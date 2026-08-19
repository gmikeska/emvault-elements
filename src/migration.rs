//! Elements/Liquid federation-migration planning — the Elements counterpart of
//! [`emvault_core::migration`].
//!
//! A migration sweeps funds from an old federation to a new one after a signer
//! rotation. This module is the **planning** layer: given each account's
//! captured UTXOs and its new-federation destination address, it produces a
//! [`ElementsMigrationPlan`] describing the *shape* of the sweep — which
//! outpoints each transaction spends, which outputs it pays (customer funds +
//! the fee account's drained change), and the ordering. It does **not** build
//! the PSET; the consumer assembles each transaction with
//! [`crate::build_migration_pset`] using the described outputs.
//!
//! ## Assets
//!
//! Elements transactions balance **per asset**, so migration is asset-aware:
//! each account's *entire per-asset balance* (L-BTC plus every issued asset)
//! moves to that account's new-federation confidential address. A confidential
//! address is asset-agnostic, so one destination receives one output per asset.
//! The mining fee is paid **only** from the fee account's L-BTC (the policy
//! asset); every non-policy asset migrates in full. Each account is **atomic**:
//! all of its assets are swept in a single transaction.
//!
//! Two multi-account strategies mirror the core Bitcoin algorithms:
//! - [`ElementsAccountForAccountSweep`] — one transaction, fees paid by a
//!   designated internal account; every customer receives its full per-asset
//!   balance.
//! - [`ElementsAccountForAccountBatchedSweep`] — one transaction per large
//!   account, small accounts bundled, fee account migrating last (with its
//!   L-BTC change chained hop-to-hop and its own assets swept in the final tx).
//!
//! Fees are `u64` sats throughout (Elements amounts are explicit sats); the
//! shared [`MigrationError`] carries [`emvault_core::bitcoin::Amount`], so the
//! sat totals are wrapped only at the error boundary.

use std::collections::BTreeMap;

use elements::hashes::Hash as _;
use elements::{Address, AssetId, OutPoint, Txid};

use emvault_core::bitcoin::Amount;
use emvault_core::error::MigrationError;

use crate::sync::CapturedUtxo;

// ---------------------------------------------------------------------------
// Plan types
// ---------------------------------------------------------------------------

/// A single account's captured UTXOs and its destination address in the new
/// federation. The UTXO type for the multi-account algorithms.
#[derive(Debug, Clone)]
pub struct ElementsAccountUtxoSet {
    /// BIP-48 account index (`m/48'/{coin}'/{account_idx}'/2'`).
    pub account_idx: u32,
    /// UTXOs belonging to this account in the old federation.
    pub utxos: Vec<CapturedUtxo>,
    /// Destination confidential address in the new federation for this account.
    pub destination_address: Address,
}

impl ElementsAccountUtxoSet {
    /// Total value (sats) across all UTXOs, **regardless of asset**. Only
    /// meaningful for single-asset accounts; prefer [`Self::balances_by_asset`]
    /// or [`Self::policy_value_sat`] for asset-aware logic.
    #[must_use]
    pub fn total_value_sat(&self) -> u64 {
        self.utxos.iter().map(CapturedUtxo::value).sum()
    }

    /// Per-asset balances (sats) across this account's UTXOs, keyed by asset id
    /// (deterministic order). One migration output is emitted per entry.
    #[must_use]
    pub fn balances_by_asset(&self) -> BTreeMap<AssetId, u64> {
        let mut m = BTreeMap::new();
        for u in &self.utxos {
            *m.entry(u.asset()).or_default() += u.value();
        }
        m
    }

    /// This account's balance (sats) of the `policy` asset (L-BTC) only — the
    /// pool the mining fee is drawn from.
    #[must_use]
    pub fn policy_value_sat(&self, policy: AssetId) -> u64 {
        self.utxos
            .iter()
            .filter(|u| u.asset() == policy)
            .map(CapturedUtxo::value)
            .sum()
    }
}

/// A single output within an [`ElementsSweepTransaction`].
///
/// Customer outputs carry their concrete new-federation address. Fee-account
/// outputs carry no address: the consumer resolves them to the fee account's
/// **old**-federation address for intermediate (chained) transactions and its
/// **new**-federation address for the final fee-account transaction
/// ([`ElementsSweepTransaction::is_fee_final`]). Every output carries the
/// [`AssetId`] it moves.
#[derive(Debug, Clone)]
pub enum ElementsSweepOutput {
    /// A customer account's funds for one asset, paid in full to its
    /// new-federation address.
    Customer {
        /// BIP-48 account index this output belongs to.
        account_idx: u32,
        /// The customer's destination address in the new federation.
        address: Address,
        /// The exact amount (sats) paid — the account's full balance of `asset`.
        amount_sat: u64,
        /// The asset this output moves.
        asset: AssetId,
    },
    /// A fee-account output for one asset. For the **policy** asset the amount
    /// is the drained remainder (`fee_input_value - tx_fee`); for every other
    /// asset it is the account's full balance (assets never pay the fee).
    /// Address is resolved by the consumer per
    /// [`ElementsSweepTransaction::is_fee_final`].
    FeeChange {
        /// The fee account's BIP-48 account index.
        account_idx: u32,
        /// The amount (sats) routed to the fee account for `asset`.
        amount_sat: u64,
        /// The asset this output moves.
        asset: AssetId,
    },
}

impl ElementsSweepOutput {
    /// The BIP-48 account index this output belongs to.
    #[must_use]
    pub fn account_idx(&self) -> u32 {
        match self {
            ElementsSweepOutput::Customer { account_idx, .. }
            | ElementsSweepOutput::FeeChange { account_idx, .. } => *account_idx,
        }
    }

    /// The output amount in sats.
    #[must_use]
    pub fn amount_sat(&self) -> u64 {
        match self {
            ElementsSweepOutput::Customer { amount_sat, .. }
            | ElementsSweepOutput::FeeChange { amount_sat, .. } => *amount_sat,
        }
    }

    /// The asset this output moves.
    #[must_use]
    pub fn asset(&self) -> AssetId {
        match self {
            ElementsSweepOutput::Customer { asset, .. }
            | ElementsSweepOutput::FeeChange { asset, .. } => *asset,
        }
    }
}

/// A single sweep transaction's shape.
#[derive(Debug, Clone)]
pub struct ElementsSweepTransaction {
    /// Source UTXO outpoints to spend. For the batched strategy the fee-account
    /// chain input after the first hop is a [`synthetic_change_outpoint`]
    /// placeholder (a zeroed txid with the preceding tx index as vout) — the
    /// consumer replaces it with the real preceding fee-change output.
    pub source_utxos: Vec<OutPoint>,
    /// The transaction's outputs (one per account per asset). Customer amounts
    /// are exact; the fee account's policy-asset output absorbs the mining fee.
    pub outputs: Vec<ElementsSweepOutput>,
    /// `true` for the final, fee-account-only transaction — the consumer routes
    /// its fee change to the **new** federation. Intermediate transactions route
    /// fee change to the fee account's **old**-federation address.
    pub is_fee_final: bool,
}

/// The plan produced by an [`ElementsSweepAlgorithm`].
#[derive(Debug, Clone)]
pub struct ElementsMigrationPlan {
    /// One [`ElementsSweepTransaction`] per migration tx, in execution order.
    pub sweep_transactions: Vec<ElementsSweepTransaction>,
    /// Estimated total fees (sats) across all sweep transactions.
    pub total_fees_sat: u64,
    /// Total UTXO count being migrated.
    pub utxo_count: usize,
}

/// Pluggable Elements sweep algorithm.
pub trait ElementsSweepAlgorithm: Send + Sync {
    /// Produce a migration plan for sweeping `accounts` from an old federation
    /// to a new one at `fee_rate_sat_per_vb`.
    ///
    /// # Errors
    /// [`MigrationError::NoUtxos`] if nothing is funded,
    /// [`MigrationError::InvalidConfig`] if the fee account is absent or holds
    /// no policy asset, and [`MigrationError::InsufficientFeeBalance`] if the fee
    /// account's L-BTC cannot cover the estimated fees.
    fn plan(
        &self,
        accounts: &[ElementsAccountUtxoSet],
        fee_rate_sat_per_vb: u64,
    ) -> Result<ElementsMigrationPlan, MigrationError>;
}

/// Number of distinct-asset outputs an account contributes (one per asset).
fn account_output_count(a: &ElementsAccountUtxoSet) -> usize {
    a.balances_by_asset().len()
}

// ---------------------------------------------------------------------------
// Single-transaction strategy
// ---------------------------------------------------------------------------

/// Sweeps all accounts in a single transaction. Fees paid (in the policy asset)
/// by a designated internal account; customer accounts receive their full
/// per-asset balance.
pub struct ElementsAccountForAccountSweep {
    fee_account_idx: u32,
    policy_asset: AssetId,
}

impl ElementsAccountForAccountSweep {
    /// Construct with the fee-paying account index and the chain's policy
    /// (L-BTC) asset — the asset the mining fee is drawn from.
    #[must_use]
    pub fn new(fee_account_idx: u32, policy_asset: AssetId) -> Self {
        Self {
            fee_account_idx,
            policy_asset,
        }
    }
}

impl ElementsSweepAlgorithm for ElementsAccountForAccountSweep {
    fn plan(
        &self,
        accounts: &[ElementsAccountUtxoSet],
        fee_rate_sat_per_vb: u64,
    ) -> Result<ElementsMigrationPlan, MigrationError> {
        let funded = funded_accounts(accounts)?;
        let fee_account = find_fee_account(&funded, self.fee_account_idx)?;

        let total_inputs: usize = funded.iter().map(|a| a.utxos.len()).sum();
        let total_outputs: usize = funded.iter().map(|a| account_output_count(a)).sum();
        let fee = estimate_elements_fee_sat(total_inputs, total_outputs, fee_rate_sat_per_vb);

        let fee_policy_value = fee_account.policy_value_sat(self.policy_asset);
        if fee_policy_value == 0 {
            return Err(no_policy_asset(self.fee_account_idx));
        }
        if fee_policy_value < fee {
            return Err(insufficient_fee(
                self.fee_account_idx,
                fee_policy_value,
                fee,
            ));
        }

        let source_utxos = funded
            .iter()
            .flat_map(|a| a.utxos.iter().map(|u| u.outpoint))
            .collect();

        let mut outputs = Vec::with_capacity(total_outputs);
        for a in &funded {
            let is_fee = a.account_idx == self.fee_account_idx;
            for (asset, amount) in a.balances_by_asset() {
                if is_fee {
                    // Policy asset pays the fee; other assets migrate in full.
                    let amount_sat = if asset == self.policy_asset {
                        amount - fee
                    } else {
                        amount
                    };
                    outputs.push(ElementsSweepOutput::FeeChange {
                        account_idx: a.account_idx,
                        amount_sat,
                        asset,
                    });
                } else {
                    outputs.push(ElementsSweepOutput::Customer {
                        account_idx: a.account_idx,
                        address: a.destination_address.clone(),
                        amount_sat: amount,
                        asset,
                    });
                }
            }
        }

        Ok(ElementsMigrationPlan {
            utxo_count: total_inputs,
            total_fees_sat: fee,
            // Single transaction: the fee account migrates here, so its
            // fee-change resolves to the new federation.
            sweep_transactions: vec![ElementsSweepTransaction {
                source_utxos,
                outputs,
                is_fee_final: true,
            }],
        })
    }
}

// ---------------------------------------------------------------------------
// Batched strategy
// ---------------------------------------------------------------------------

/// Sweeps each account in its own transaction. Small accounts (whose policy-asset
/// balance is below `small_account_threshold_sat`) are bundled into one. Fees
/// paid by a designated internal account that migrates last, its L-BTC change
/// chained hop-to-hop; the fee account's own assets are swept in the final tx.
pub struct ElementsAccountForAccountBatchedSweep {
    fee_account_idx: u32,
    small_account_threshold_sat: u64,
    policy_asset: AssetId,
}

impl ElementsAccountForAccountBatchedSweep {
    /// Construct with the fee account index, small-account bundling threshold
    /// (measured in the policy asset), and the chain's policy (L-BTC) asset.
    #[must_use]
    pub fn new(
        fee_account_idx: u32,
        small_account_threshold_sat: u64,
        policy_asset: AssetId,
    ) -> Self {
        Self {
            fee_account_idx,
            small_account_threshold_sat,
            policy_asset,
        }
    }
}

struct BatchedPlanState {
    sweep_transactions: Vec<ElementsSweepTransaction>,
    total_utxo_count: usize,
    cumulative_fee_sat: u64,
}

/// Customer outputs (one per asset) for an account paid in full to its dest.
fn customer_outputs(a: &ElementsAccountUtxoSet) -> Vec<ElementsSweepOutput> {
    a.balances_by_asset()
        .into_iter()
        .map(|(asset, amount)| ElementsSweepOutput::Customer {
            account_idx: a.account_idx,
            address: a.destination_address.clone(),
            amount_sat: amount,
            asset,
        })
        .collect()
}

impl ElementsAccountForAccountBatchedSweep {
    #[allow(clippy::too_many_arguments)]
    fn plan_large_accounts(
        state: &mut BatchedPlanState,
        large: &[&ElementsAccountUtxoSet],
        fee_seed_outpoint: OutPoint,
        initial_fee_utxo_value: u64,
        fee_account_idx: u32,
        policy_asset: AssetId,
        fee_rate_sat_per_vb: u64,
    ) {
        for (tx_idx, acct) in large.iter().enumerate() {
            let acct_inputs = acct.utxos.len();
            let acct_outputs = account_output_count(acct);
            // outputs = the account's per-asset outputs + the fee-change output.
            let tx_fee =
                estimate_elements_fee_sat(acct_inputs + 1, acct_outputs + 1, fee_rate_sat_per_vb);

            let mut source: Vec<OutPoint> = acct.utxos.iter().map(|u| u.outpoint).collect();
            if tx_idx == 0 {
                source.push(fee_seed_outpoint);
            } else {
                source.push(synthetic_change_outpoint(tx_idx - 1));
            }

            let fee_input_value = if tx_idx == 0 {
                initial_fee_utxo_value
            } else {
                initial_fee_utxo_value - state.cumulative_fee_sat
            };
            state.cumulative_fee_sat += tx_fee;

            let mut outputs = customer_outputs(acct);
            outputs.push(ElementsSweepOutput::FeeChange {
                account_idx: fee_account_idx,
                amount_sat: fee_input_value - tx_fee,
                asset: policy_asset,
            });

            state.total_utxo_count += acct_inputs + 1;
            state.sweep_transactions.push(ElementsSweepTransaction {
                source_utxos: source,
                outputs,
                is_fee_final: false,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn plan_small_bundle(
        state: &mut BatchedPlanState,
        small: &[&ElementsAccountUtxoSet],
        fee_seed_outpoint: OutPoint,
        initial_fee_utxo_value: u64,
        fee_account_idx: u32,
        policy_asset: AssetId,
        fee_rate_sat_per_vb: u64,
        preceding_tx_count: usize,
    ) {
        let small_inputs: usize = small.iter().map(|a| a.utxos.len()).sum();
        let small_outputs: usize = small.iter().map(|a| account_output_count(a)).sum();
        let tx_fee =
            estimate_elements_fee_sat(small_inputs + 1, small_outputs + 1, fee_rate_sat_per_vb);

        let mut source: Vec<OutPoint> = small
            .iter()
            .flat_map(|a| a.utxos.iter().map(|u| u.outpoint))
            .collect();
        if preceding_tx_count == 0 {
            source.push(fee_seed_outpoint);
        } else {
            source.push(synthetic_change_outpoint(preceding_tx_count - 1));
        }

        let fee_input_value = if preceding_tx_count == 0 {
            initial_fee_utxo_value
        } else {
            initial_fee_utxo_value - state.cumulative_fee_sat
        };
        state.cumulative_fee_sat += tx_fee;

        let mut outputs: Vec<ElementsSweepOutput> =
            small.iter().flat_map(|a| customer_outputs(a)).collect();
        outputs.push(ElementsSweepOutput::FeeChange {
            account_idx: fee_account_idx,
            amount_sat: fee_input_value - tx_fee,
            asset: policy_asset,
        });

        state.total_utxo_count += small_inputs + 1;
        state.sweep_transactions.push(ElementsSweepTransaction {
            source_utxos: source,
            outputs,
            is_fee_final: false,
        });
    }
}

impl ElementsSweepAlgorithm for ElementsAccountForAccountBatchedSweep {
    #[allow(clippy::too_many_lines)]
    fn plan(
        &self,
        accounts: &[ElementsAccountUtxoSet],
        fee_rate_sat_per_vb: u64,
    ) -> Result<ElementsMigrationPlan, MigrationError> {
        let policy = self.policy_asset;
        let funded = funded_accounts(accounts)?;
        let fee_account = find_fee_account(&funded, self.fee_account_idx)?;

        // Split the fee account's UTXOs into policy (funds the fee chain) and
        // non-policy (its own assets, swept in the final tx).
        let fee_policy_utxos: Vec<&CapturedUtxo> = fee_account
            .utxos
            .iter()
            .filter(|u| u.asset() == policy)
            .collect();
        let fee_asset_utxos: Vec<&CapturedUtxo> = fee_account
            .utxos
            .iter()
            .filter(|u| u.asset() != policy)
            .collect();
        let fee_policy_total = fee_account.policy_value_sat(policy);
        let Some(seed_utxo) = fee_policy_utxos.first() else {
            return Err(no_policy_asset(self.fee_account_idx));
        };
        let fee_seed_outpoint = seed_utxo.outpoint;
        let initial_fee_utxo_value = seed_utxo.value();

        let (large, small): (Vec<&ElementsAccountUtxoSet>, Vec<&ElementsAccountUtxoSet>) = funded
            .iter()
            .filter(|a| a.account_idx != self.fee_account_idx)
            .copied()
            .partition(|a| a.policy_value_sat(policy) >= self.small_account_threshold_sat);

        // Pre-flight: estimate total fees across all planned transactions.
        let planned_fees = batched_estimate_total_fees(
            &large,
            &small,
            &fee_asset_utxos,
            fee_policy_utxos.len(),
            fee_rate_sat_per_vb,
        );
        if fee_policy_total < planned_fees {
            return Err(insufficient_fee(
                self.fee_account_idx,
                fee_policy_total,
                planned_fees,
            ));
        }

        let mut state = BatchedPlanState {
            sweep_transactions: Vec::new(),
            total_utxo_count: 0,
            cumulative_fee_sat: 0,
        };

        Self::plan_large_accounts(
            &mut state,
            &large,
            fee_seed_outpoint,
            initial_fee_utxo_value,
            self.fee_account_idx,
            policy,
            fee_rate_sat_per_vb,
        );

        if !small.is_empty() {
            Self::plan_small_bundle(
                &mut state,
                &small,
                fee_seed_outpoint,
                initial_fee_utxo_value,
                self.fee_account_idx,
                policy,
                fee_rate_sat_per_vb,
                large.len(),
            );
        }

        // Fee account migration (always last): drains its remaining L-BTC to the
        // new federation and sweeps its own non-policy assets in full.
        let fee_asset_balances = fee_asset_balances(&fee_asset_utxos);
        let fee_final_outputs = 1 + fee_asset_balances.len();
        let fee_final_inputs = fee_policy_utxos.len() + fee_asset_utxos.len();
        let fee_migration_fee =
            estimate_elements_fee_sat(fee_final_inputs, fee_final_outputs, fee_rate_sat_per_vb);
        state.cumulative_fee_sat += fee_migration_fee;

        // Fee-account source: all its policy + asset UTXOs. If any intermediate
        // tx ran, the seed policy UTXO was already consumed there, so replace it
        // with the chained change placeholder.
        let mut fee_source: Vec<OutPoint> = fee_policy_utxos
            .iter()
            .chain(fee_asset_utxos.iter())
            .map(|u| u.outpoint)
            .collect();
        if !state.sweep_transactions.is_empty() {
            fee_source.retain(|op| *op != fee_seed_outpoint);
            fee_source.push(synthetic_change_outpoint(
                state.sweep_transactions.len() - 1,
            ));
        }

        let fee_account_remaining = fee_policy_total - state.cumulative_fee_sat;
        state.total_utxo_count += fee_source.len();

        let mut fee_outputs = vec![ElementsSweepOutput::FeeChange {
            account_idx: self.fee_account_idx,
            amount_sat: fee_account_remaining,
            asset: policy,
        }];
        for (asset, amount) in fee_asset_balances {
            fee_outputs.push(ElementsSweepOutput::FeeChange {
                account_idx: self.fee_account_idx,
                amount_sat: amount,
                asset,
            });
        }

        state.sweep_transactions.push(ElementsSweepTransaction {
            source_utxos: fee_source,
            outputs: fee_outputs,
            is_fee_final: true,
        });

        Ok(ElementsMigrationPlan {
            sweep_transactions: state.sweep_transactions,
            total_fees_sat: state.cumulative_fee_sat,
            utxo_count: state.total_utxo_count,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Per-asset balances (sats) across a set of the fee account's non-policy UTXOs.
fn fee_asset_balances(fee_asset_utxos: &[&CapturedUtxo]) -> BTreeMap<AssetId, u64> {
    let mut m = BTreeMap::new();
    for u in fee_asset_utxos {
        *m.entry(u.asset()).or_default() += u.value();
    }
    m
}

fn funded_accounts(
    accounts: &[ElementsAccountUtxoSet],
) -> Result<Vec<&ElementsAccountUtxoSet>, MigrationError> {
    let funded: Vec<&ElementsAccountUtxoSet> =
        accounts.iter().filter(|a| !a.utxos.is_empty()).collect();
    if funded.is_empty() {
        return Err(MigrationError::NoUtxos);
    }
    Ok(funded)
}

fn find_fee_account<'a>(
    funded: &[&'a ElementsAccountUtxoSet],
    fee_account_idx: u32,
) -> Result<&'a ElementsAccountUtxoSet, MigrationError> {
    funded
        .iter()
        .copied()
        .find(|a| a.account_idx == fee_account_idx)
        .ok_or_else(|| {
            MigrationError::InvalidConfig(format!(
                "fee account index {fee_account_idx} not found in input set or has no UTXOs"
            ))
        })
}

fn no_policy_asset(fee_account_idx: u32) -> MigrationError {
    MigrationError::InvalidConfig(format!(
        "fee account index {fee_account_idx} holds no L-BTC (policy asset) to pay the migration fee"
    ))
}

fn insufficient_fee(fee_account_idx: u32, available_sat: u64, required_sat: u64) -> MigrationError {
    MigrationError::InsufficientFeeBalance {
        fee_account_idx,
        available: Amount::from_sat(available_sat),
        required: Amount::from_sat(required_sat),
    }
}

fn batched_estimate_total_fees(
    large: &[&ElementsAccountUtxoSet],
    small: &[&ElementsAccountUtxoSet],
    fee_asset_utxos: &[&CapturedUtxo],
    fee_policy_utxo_count: usize,
    fee_rate_sat_per_vb: u64,
) -> u64 {
    let mut total = 0u64;
    for acct in large {
        total += estimate_elements_fee_sat(
            acct.utxos.len() + 1,
            account_output_count(acct) + 1,
            fee_rate_sat_per_vb,
        );
    }
    if !small.is_empty() {
        let small_input_count: usize = small.iter().map(|a| a.utxos.len()).sum::<usize>() + 1;
        let small_output_count: usize =
            small.iter().map(|a| account_output_count(a)).sum::<usize>() + 1;
        total +=
            estimate_elements_fee_sat(small_input_count, small_output_count, fee_rate_sat_per_vb);
    }
    let fee_final_outputs = 1 + fee_asset_balances(fee_asset_utxos).len();
    total += estimate_elements_fee_sat(
        fee_policy_utxo_count + fee_asset_utxos.len(),
        fee_final_outputs,
        fee_rate_sat_per_vb,
    );
    total
}

/// Planning fee estimate (sats) for an Elements P2WSH multisig tx. Real fee
/// accounting is left to PSET construction; this sizes the pre-flight check.
#[must_use]
pub fn estimate_elements_fee_sat(inputs: usize, outputs: usize, fee_rate_sat_per_vb: u64) -> u64 {
    (inputs as u64 * 1100 + outputs as u64 * 1500 + 200) * fee_rate_sat_per_vb / 10
}

/// Synthetic outpoint standing in for the change output of a preceding sweep in
/// the fee-account chain. The real outpoint is unknown at planning time; this
/// placeholder uses a zeroed txid with the preceding tx index as vout, which the
/// consumer replaces with the actual chained fee-change output.
#[must_use]
pub fn synthetic_change_outpoint(preceding_tx_index: usize) -> OutPoint {
    #[allow(clippy::cast_possible_truncation)]
    OutPoint::new(
        Txid::from_raw_hash(elements::hashes::sha256d::Hash::all_zeros()),
        preceding_tx_index as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ElementsNetwork;
    use crate::sync::WalletId;
    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    use elements::{TxOut, TxOutSecrets};

    fn lbtc() -> AssetId {
        *ElementsNetwork::ElementsRegtest.to_lwk().policy_asset()
    }

    fn some_asset() -> AssetId {
        AssetId::from_byte_array([0x11; 32])
    }

    fn dummy_addr() -> Address {
        "el1qq2v5lthcntj42w2z7uc3wx6zkxd0d37edzrwev6f6qyurcz6wqnxafp2j3zpesa7pqnq7fw7dyeujznz7xm7v05ms47sd6kxw2veyjhqrkwdx3ppmr90"
            .parse()
            .expect("valid ct address")
    }

    fn utxo_asset(vout: u32, value_sat: u64, asset: AssetId) -> CapturedUtxo {
        let mut outpoint = OutPoint::null();
        outpoint.vout = vout;
        CapturedUtxo {
            wallet_id: WalletId::from_bytes([1u8; 16]),
            outpoint,
            txout: TxOut::default(),
            secrets: TxOutSecrets::new(
                asset,
                AssetBlindingFactor::zero(),
                value_sat,
                ValueBlindingFactor::zero(),
            ),
            chain: lwk_wollet::Chain::External,
            wildcard_index: vout,
            height: 1,
            is_spent: false,
        }
    }

    fn utxo(vout: u32, value_sat: u64) -> CapturedUtxo {
        utxo_asset(vout, value_sat, lbtc())
    }

    fn acct(idx: u32, values: &[u64]) -> ElementsAccountUtxoSet {
        ElementsAccountUtxoSet {
            account_idx: idx,
            utxos: values
                .iter()
                .enumerate()
                .map(|(i, v)| utxo(u32::try_from(i).expect("utxo index fits u32"), *v))
                .collect(),
            destination_address: dummy_addr(),
        }
    }

    /// An account holding both L-BTC and one issued asset.
    fn acct_with_asset(idx: u32, lbtc_sat: u64, asset_sat: u64) -> ElementsAccountUtxoSet {
        ElementsAccountUtxoSet {
            account_idx: idx,
            utxos: vec![utxo(0, lbtc_sat), utxo_asset(1, asset_sat, some_asset())],
            destination_address: dummy_addr(),
        }
    }

    #[test]
    fn account_for_account_single_tx_fee_account_pays() {
        let accounts = vec![
            acct(0, &[200_000]),
            acct(1, &[300_000]),
            acct(99, &[100_000]),
        ];
        let plan = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 1)
            .unwrap();
        assert_eq!(plan.sweep_transactions.len(), 1);
        let tx = &plan.sweep_transactions[0];
        assert!(tx.is_fee_final);
        assert_eq!(tx.source_utxos.len(), 3);
        let c0 = tx
            .outputs
            .iter()
            .find(|o| o.account_idx() == 0)
            .unwrap()
            .amount_sat();
        assert_eq!(c0, 200_000);
        let fee_change = tx
            .outputs
            .iter()
            .find(|o| matches!(o, ElementsSweepOutput::FeeChange { .. }))
            .unwrap()
            .amount_sat();
        assert_eq!(fee_change + plan.total_fees_sat, 100_000);
    }

    #[test]
    fn single_tx_migrates_customer_asset_and_lbtc_separately() {
        // Customer 0 holds L-BTC + an asset; fee account 99 holds L-BTC.
        let accounts = vec![acct_with_asset(0, 200_000, 5_000), acct(99, &[100_000])];
        let plan = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 1)
            .unwrap();
        let tx = &plan.sweep_transactions[0];
        // Customer 0 gets two outputs: full L-BTC + full asset.
        let c0_lbtc = tx
            .outputs
            .iter()
            .find(|o| o.account_idx() == 0 && o.asset() == lbtc())
            .unwrap()
            .amount_sat();
        let c0_asset = tx
            .outputs
            .iter()
            .find(|o| o.account_idx() == 0 && o.asset() == some_asset())
            .unwrap()
            .amount_sat();
        assert_eq!(c0_lbtc, 200_000, "customer L-BTC migrates in full");
        assert_eq!(c0_asset, 5_000, "customer asset migrates in full");
    }

    #[test]
    fn single_tx_migrates_fee_account_asset_in_full() {
        // Fee account 99 holds L-BTC (pays fee) + an asset (migrates in full).
        let accounts = vec![acct(0, &[200_000]), acct_with_asset(99, 100_000, 7_000)];
        let plan = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 1)
            .unwrap();
        let tx = &plan.sweep_transactions[0];
        // Fee account's asset output is full; its L-BTC output is balance - fee.
        let fee_asset = tx
            .outputs
            .iter()
            .find(|o| o.account_idx() == 99 && o.asset() == some_asset())
            .unwrap()
            .amount_sat();
        assert_eq!(
            fee_asset, 7_000,
            "fee account's asset is not touched by the fee"
        );
        let fee_lbtc = tx
            .outputs
            .iter()
            .find(|o| o.account_idx() == 99 && o.asset() == lbtc())
            .unwrap()
            .amount_sat();
        assert_eq!(fee_lbtc + plan.total_fees_sat, 100_000);
    }

    #[test]
    fn rejects_no_funded_accounts() {
        let accounts = vec![acct(0, &[]), acct(99, &[])];
        let err = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 1)
            .unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    #[test]
    fn rejects_missing_fee_account() {
        let accounts = vec![acct(0, &[200_000])];
        let err = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 1)
            .unwrap_err();
        assert!(matches!(err, MigrationError::InvalidConfig(_)));
    }

    #[test]
    fn rejects_fee_account_without_policy_asset() {
        // Fee account holds only an asset, no L-BTC → cannot pay the fee.
        let fee_only_asset = ElementsAccountUtxoSet {
            account_idx: 99,
            utxos: vec![utxo_asset(0, 10_000, some_asset())],
            destination_address: dummy_addr(),
        };
        let accounts = vec![acct(0, &[200_000]), fee_only_asset];
        let err = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 1)
            .unwrap_err();
        assert!(matches!(err, MigrationError::InvalidConfig(_)));
    }

    #[test]
    fn rejects_insufficient_fee_balance() {
        let accounts = vec![acct(0, &[200_000]), acct(99, &[1])];
        let err = ElementsAccountForAccountSweep::new(99, lbtc())
            .plan(&accounts, 100)
            .unwrap_err();
        assert!(matches!(err, MigrationError::InsufficientFeeBalance { .. }));
    }

    #[test]
    fn estimate_fee_matches_formula() {
        let got = estimate_elements_fee_sat(3, 2, 5);
        let expected: u64 = (3 * 1100 + 2 * 1500 + 200) * 5 / 10;
        assert_eq!(got, expected);
        assert_eq!(expected, 3250);
    }

    #[test]
    fn estimate_fee_zero_rate_is_zero() {
        assert_eq!(estimate_elements_fee_sat(10, 4, 0), 0);
    }

    #[test]
    fn estimate_fee_monotonic_in_inputs() {
        assert!(estimate_elements_fee_sat(5, 2, 10) > estimate_elements_fee_sat(3, 2, 10));
    }

    #[test]
    fn estimate_fee_monotonic_in_outputs() {
        assert!(estimate_elements_fee_sat(3, 4, 10) > estimate_elements_fee_sat(3, 2, 10));
    }

    #[test]
    fn estimate_fee_monotonic_in_rate() {
        assert!(estimate_elements_fee_sat(3, 2, 20) > estimate_elements_fee_sat(3, 2, 10));
    }

    #[test]
    fn synthetic_outpoint_is_deterministic() {
        assert_eq!(synthetic_change_outpoint(7), synthetic_change_outpoint(7));
    }

    #[test]
    fn synthetic_outpoint_has_zeroed_txid_and_index_vout() {
        let op = synthetic_change_outpoint(42);
        assert_eq!(
            op.txid.to_string(),
            "0".repeat(64),
            "txid must be all zeros"
        );
        assert_eq!(op.vout, 42, "vout carries the preceding tx index");
    }

    #[test]
    fn synthetic_outpoint_distinct_across_inputs() {
        let a = synthetic_change_outpoint(0);
        let b = synthetic_change_outpoint(1);
        assert_ne!(a, b);
        assert_eq!(a.txid, b.txid, "same zeroed txid");
        assert_ne!(a.vout, b.vout, "distinguished by vout");
    }

    #[test]
    fn batched_orders_large_then_small_then_fee_last() {
        let accounts = vec![acct(0, &[500_000]), acct(1, &[1_000]), acct(99, &[200_000])];
        let plan = ElementsAccountForAccountBatchedSweep::new(99, 10_000, lbtc())
            .plan(&accounts, 1)
            .unwrap();
        assert_eq!(plan.sweep_transactions.len(), 3);
        assert!(!plan.sweep_transactions[0].is_fee_final);
        assert!(plan.sweep_transactions.last().unwrap().is_fee_final);
        assert!(
            plan.sweep_transactions
                .last()
                .unwrap()
                .outputs
                .iter()
                .all(|o| matches!(o, ElementsSweepOutput::FeeChange { .. }))
        );
    }

    #[test]
    fn batched_fee_account_sweeps_its_own_asset_in_final_tx() {
        // Large customer 0 (L-BTC + asset); fee account 99 (L-BTC + asset).
        let accounts = vec![
            acct_with_asset(0, 500_000, 3_000),
            acct_with_asset(99, 400_000, 9_000),
        ];
        let plan = ElementsAccountForAccountBatchedSweep::new(99, 10_000, lbtc())
            .plan(&accounts, 1)
            .unwrap();
        let final_tx = plan.sweep_transactions.last().unwrap();
        assert!(final_tx.is_fee_final);
        // Fee account's asset is swept full in the final tx.
        let fee_asset = final_tx
            .outputs
            .iter()
            .find(|o| o.asset() == some_asset())
            .expect("fee account asset output present in final tx")
            .amount_sat();
        assert_eq!(fee_asset, 9_000);
        // The large customer's asset went out in its own (earlier) tx.
        let cust_asset_tx = plan.sweep_transactions.iter().find(|t| {
            t.outputs
                .iter()
                .any(|o| o.account_idx() == 0 && o.asset() == some_asset())
        });
        assert!(
            cust_asset_tx.is_some(),
            "customer asset migrated in an earlier tx"
        );
    }
}
