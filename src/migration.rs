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
//! [`crate::build_migration_pset`] / [`crate::build_spend_pset`] using the
//! described outputs, exactly as the Bitcoin planner leaves PSBT construction to
//! the consumer.
//!
//! Two multi-account strategies mirror the core Bitcoin algorithms:
//! - [`ElementsAccountForAccountSweep`] — one transaction, fees paid by a
//!   designated internal account; every customer receives its full balance.
//! - [`ElementsAccountForAccountBatchedSweep`] — one transaction per large
//!   account, small accounts bundled, fee account migrating last with its
//!   change chained hop-to-hop.
//!
//! Fees are `u64` sats throughout (Elements amounts are explicit sats); the
//! shared [`MigrationError`] carries [`emvault_core::bitcoin::Amount`], so the
//! sat totals are wrapped only at the error boundary. Roster arithmetic is
//! chain-agnostic and reused directly from [`emvault_core::roster`] — see the
//! `roster` re-export in [`crate`].

use elements::hashes::Hash as _;
use elements::{Address, OutPoint, Txid};

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
    /// Total value (sats) across all UTXOs in this account.
    #[must_use]
    pub fn total_value_sat(&self) -> u64 {
        self.utxos.iter().map(CapturedUtxo::value).sum()
    }
}

/// A single output within an [`ElementsSweepTransaction`].
///
/// Customer outputs carry their concrete new-federation address. The
/// **fee-change** output carries no address: the consumer resolves it to the
/// fee account's **old**-federation address for intermediate (chained)
/// transactions and its **new**-federation address for the final fee-account
/// transaction ([`ElementsSweepTransaction::is_fee_final`]).
#[derive(Debug, Clone)]
pub enum ElementsSweepOutput {
    /// A customer account's funds, paid in full to its new-federation address.
    Customer {
        /// BIP-48 account index this output belongs to.
        account_idx: u32,
        /// The customer's destination address in the new federation.
        address: Address,
        /// The exact amount (sats) paid — the account's full balance.
        amount_sat: u64,
    },
    /// The fee account's drained change (`fee_input_value - tx_fee`). Address is
    /// resolved by the consumer per [`ElementsSweepTransaction::is_fee_final`].
    FeeChange {
        /// The fee account's BIP-48 account index.
        account_idx: u32,
        /// The drained remainder (sats) routed to the fee account.
        amount_sat: u64,
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
}

/// A single sweep transaction's shape.
#[derive(Debug, Clone)]
pub struct ElementsSweepTransaction {
    /// Source UTXO outpoints to spend. For the batched strategy the fee-account
    /// chain input after the first hop is a [`synthetic_change_outpoint`]
    /// placeholder (a zeroed txid with the preceding tx index as vout) — the
    /// consumer replaces it with the real preceding fee-change output.
    pub source_utxos: Vec<OutPoint>,
    /// The transaction's outputs. Customer amounts are exact; the fee-change
    /// output absorbs the mining fee.
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
    /// [`MigrationError::InvalidConfig`] if the fee account is absent, and
    /// [`MigrationError::InsufficientFeeBalance`] if the fee account cannot cover
    /// the estimated fees.
    fn plan(
        &self,
        accounts: &[ElementsAccountUtxoSet],
        fee_rate_sat_per_vb: u64,
    ) -> Result<ElementsMigrationPlan, MigrationError>;
}

// ---------------------------------------------------------------------------
// Single-transaction strategy
// ---------------------------------------------------------------------------

/// Sweeps all accounts in a single transaction. Fees paid by a designated
/// internal account; customer accounts receive their full balance.
pub struct ElementsAccountForAccountSweep {
    fee_account_idx: u32,
}

impl ElementsAccountForAccountSweep {
    /// Construct with the fee-paying account index.
    #[must_use]
    pub fn new(fee_account_idx: u32) -> Self {
        Self { fee_account_idx }
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
        let fee = estimate_elements_fee_sat(total_inputs, funded.len(), fee_rate_sat_per_vb);

        let fee_account_value = fee_account.total_value_sat();
        if fee_account_value < fee {
            return Err(insufficient_fee(
                self.fee_account_idx,
                fee_account_value,
                fee,
            ));
        }

        let source_utxos = funded
            .iter()
            .flat_map(|a| a.utxos.iter().map(|u| u.outpoint))
            .collect();

        let outputs = funded
            .iter()
            .map(|a| {
                if a.account_idx == self.fee_account_idx {
                    ElementsSweepOutput::FeeChange {
                        account_idx: a.account_idx,
                        amount_sat: a.total_value_sat() - fee,
                    }
                } else {
                    ElementsSweepOutput::Customer {
                        account_idx: a.account_idx,
                        address: a.destination_address.clone(),
                        amount_sat: a.total_value_sat(),
                    }
                }
            })
            .collect();

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

/// Sweeps each account in its own transaction. Small accounts (below
/// `small_account_threshold_sat`) are bundled into one. Fees paid by a
/// designated internal account that migrates last, its change chained
/// hop-to-hop.
pub struct ElementsAccountForAccountBatchedSweep {
    fee_account_idx: u32,
    small_account_threshold_sat: u64,
}

impl ElementsAccountForAccountBatchedSweep {
    /// Construct with the fee account index and small-account bundling threshold.
    #[must_use]
    pub fn new(fee_account_idx: u32, small_account_threshold_sat: u64) -> Self {
        Self {
            fee_account_idx,
            small_account_threshold_sat,
        }
    }
}

struct BatchedPlanState {
    sweep_transactions: Vec<ElementsSweepTransaction>,
    total_utxo_count: usize,
    cumulative_fee_sat: u64,
}

impl ElementsAccountForAccountBatchedSweep {
    fn plan_large_accounts(
        state: &mut BatchedPlanState,
        large: &[&ElementsAccountUtxoSet],
        fee_utxos: &[OutPoint],
        initial_fee_utxo_value: u64,
        fee_account_idx: u32,
        fee_rate_sat_per_vb: u64,
    ) {
        for (tx_idx, acct) in large.iter().enumerate() {
            let acct_inputs = acct.utxos.len();
            let tx_fee = estimate_elements_fee_sat(acct_inputs + 1, 2, fee_rate_sat_per_vb);

            let mut source: Vec<OutPoint> = acct.utxos.iter().map(|u| u.outpoint).collect();
            if tx_idx == 0 {
                source.push(fee_utxos[0]);
            } else {
                source.push(synthetic_change_outpoint(tx_idx - 1));
            }

            let fee_input_value = if tx_idx == 0 {
                initial_fee_utxo_value
            } else {
                initial_fee_utxo_value - state.cumulative_fee_sat
            };
            state.cumulative_fee_sat += tx_fee;

            let outputs = vec![
                ElementsSweepOutput::Customer {
                    account_idx: acct.account_idx,
                    address: acct.destination_address.clone(),
                    amount_sat: acct.total_value_sat(),
                },
                ElementsSweepOutput::FeeChange {
                    account_idx: fee_account_idx,
                    amount_sat: fee_input_value - tx_fee,
                },
            ];

            state.total_utxo_count += acct_inputs + 1;
            state.sweep_transactions.push(ElementsSweepTransaction {
                source_utxos: source,
                outputs,
                is_fee_final: false,
            });
        }
    }

    fn plan_small_bundle(
        state: &mut BatchedPlanState,
        small: &[&ElementsAccountUtxoSet],
        fee_utxos: &[OutPoint],
        initial_fee_utxo_value: u64,
        fee_account_idx: u32,
        fee_rate_sat_per_vb: u64,
        preceding_tx_count: usize,
    ) {
        let small_inputs: usize = small.iter().map(|a| a.utxos.len()).sum();
        let tx_fee =
            estimate_elements_fee_sat(small_inputs + 1, small.len() + 1, fee_rate_sat_per_vb);

        let mut source: Vec<OutPoint> = small
            .iter()
            .flat_map(|a| a.utxos.iter().map(|u| u.outpoint))
            .collect();
        if preceding_tx_count == 0 {
            source.push(fee_utxos[0]);
        } else {
            source.push(synthetic_change_outpoint(preceding_tx_count - 1));
        }

        let fee_input_value = if preceding_tx_count == 0 {
            initial_fee_utxo_value
        } else {
            initial_fee_utxo_value - state.cumulative_fee_sat
        };
        state.cumulative_fee_sat += tx_fee;

        let mut outputs: Vec<ElementsSweepOutput> = small
            .iter()
            .map(|a| ElementsSweepOutput::Customer {
                account_idx: a.account_idx,
                address: a.destination_address.clone(),
                amount_sat: a.total_value_sat(),
            })
            .collect();
        outputs.push(ElementsSweepOutput::FeeChange {
            account_idx: fee_account_idx,
            amount_sat: fee_input_value - tx_fee,
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
    fn plan(
        &self,
        accounts: &[ElementsAccountUtxoSet],
        fee_rate_sat_per_vb: u64,
    ) -> Result<ElementsMigrationPlan, MigrationError> {
        let funded = funded_accounts(accounts)?;
        let fee_account = find_fee_account(&funded, self.fee_account_idx)?;
        let fee_account_total = fee_account.total_value_sat();
        let initial_fee_utxo_value = fee_account.utxos[0].value();

        let (large, small): (Vec<&ElementsAccountUtxoSet>, Vec<&ElementsAccountUtxoSet>) = funded
            .iter()
            .filter(|a| a.account_idx != self.fee_account_idx)
            .copied()
            .partition(|a| a.total_value_sat() >= self.small_account_threshold_sat);

        // Pre-flight: estimate total fees across all planned transactions.
        let planned_fees = batched_estimate_total_fees(
            &large,
            &small,
            fee_account.utxos.len(),
            fee_rate_sat_per_vb,
        );
        if fee_account_total < planned_fees {
            return Err(insufficient_fee(
                self.fee_account_idx,
                fee_account_total,
                planned_fees,
            ));
        }

        let fee_utxos: Vec<OutPoint> = fee_account.utxos.iter().map(|u| u.outpoint).collect();

        let mut state = BatchedPlanState {
            sweep_transactions: Vec::new(),
            total_utxo_count: 0,
            cumulative_fee_sat: 0,
        };

        Self::plan_large_accounts(
            &mut state,
            &large,
            &fee_utxos,
            initial_fee_utxo_value,
            self.fee_account_idx,
            fee_rate_sat_per_vb,
        );

        if !small.is_empty() {
            Self::plan_small_bundle(
                &mut state,
                &small,
                &fee_utxos,
                initial_fee_utxo_value,
                self.fee_account_idx,
                fee_rate_sat_per_vb,
                large.len(),
            );
        }

        // Fee account migration (always last): drains its remaining balance to
        // the new federation.
        let fee_migration_fee =
            estimate_elements_fee_sat(fee_account.utxos.len(), 1, fee_rate_sat_per_vb);
        state.cumulative_fee_sat += fee_migration_fee;

        let mut fee_source: Vec<OutPoint> = fee_utxos;
        if !state.sweep_transactions.is_empty() {
            fee_source.remove(0);
            fee_source.push(synthetic_change_outpoint(
                state.sweep_transactions.len() - 1,
            ));
        }

        let fee_account_remaining = fee_account_total - state.cumulative_fee_sat;
        state.total_utxo_count += fee_source.len();

        state.sweep_transactions.push(ElementsSweepTransaction {
            source_utxos: fee_source,
            outputs: vec![ElementsSweepOutput::FeeChange {
                account_idx: self.fee_account_idx,
                amount_sat: fee_account_remaining,
            }],
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
    fee_account_utxo_count: usize,
    fee_rate_sat_per_vb: u64,
) -> u64 {
    let mut total = 0u64;
    for acct in large {
        total += estimate_elements_fee_sat(acct.utxos.len() + 1, 2, fee_rate_sat_per_vb);
    }
    if !small.is_empty() {
        let small_input_count: usize = small.iter().map(|a| a.utxos.len()).sum::<usize>() + 1;
        total += estimate_elements_fee_sat(small_input_count, small.len() + 1, fee_rate_sat_per_vb);
    }
    total += estimate_elements_fee_sat(fee_account_utxo_count, 1, fee_rate_sat_per_vb);
    total
}

/// Planning fee estimate (sats) for an Elements P2WSH multisig tx. Matches the
/// heuristic used by the migration example's display/plan helpers. Real fee
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
    use elements::{AssetId, TxOut, TxOutSecrets};

    fn lbtc() -> AssetId {
        *ElementsNetwork::ElementsRegtest.to_lwk().policy_asset()
    }

    fn dummy_addr() -> Address {
        // Planning never parses the destination; a known-good ct address string
        // is enough to populate the field.
        "el1qq2v5lthcntj42w2z7uc3wx6zkxd0d37edzrwev6f6qyurcz6wqnxafp2j3zpesa7pqnq7fw7dyeujznz7xm7v05ms47sd6kxw2veyjhqrkwdx3ppmr90"
            .parse()
            .expect("valid ct address")
    }

    fn utxo(vout: u32, value_sat: u64) -> CapturedUtxo {
        let mut outpoint = OutPoint::null();
        outpoint.vout = vout;
        CapturedUtxo {
            wallet_id: WalletId::from_bytes([1u8; 16]),
            outpoint,
            txout: TxOut::default(),
            secrets: TxOutSecrets::new(
                lbtc(),
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

    #[test]
    fn account_for_account_single_tx_fee_account_pays() {
        // customers 0,1 + fee account 99; single tx, fee account drains change.
        let accounts = vec![
            acct(0, &[200_000]),
            acct(1, &[300_000]),
            acct(99, &[100_000]),
        ];
        let plan = ElementsAccountForAccountSweep::new(99)
            .plan(&accounts, 1)
            .unwrap();
        assert_eq!(plan.sweep_transactions.len(), 1);
        let tx = &plan.sweep_transactions[0];
        assert!(tx.is_fee_final);
        assert_eq!(tx.source_utxos.len(), 3);
        // customers get exact; fee account gets its balance minus the fee.
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
    fn rejects_no_funded_accounts() {
        let accounts = vec![acct(0, &[]), acct(99, &[])];
        let err = ElementsAccountForAccountSweep::new(99)
            .plan(&accounts, 1)
            .unwrap_err();
        assert!(matches!(err, MigrationError::NoUtxos));
    }

    #[test]
    fn rejects_missing_fee_account() {
        let accounts = vec![acct(0, &[200_000])];
        let err = ElementsAccountForAccountSweep::new(99)
            .plan(&accounts, 1)
            .unwrap_err();
        assert!(matches!(err, MigrationError::InvalidConfig(_)));
    }

    #[test]
    fn rejects_insufficient_fee_balance() {
        let accounts = vec![acct(0, &[200_000]), acct(99, &[1])];
        let err = ElementsAccountForAccountSweep::new(99)
            .plan(&accounts, 100)
            .unwrap_err();
        assert!(matches!(err, MigrationError::InsufficientFeeBalance { .. }));
    }

    // --- estimate_elements_fee_sat / synthetic_change_outpoint --------------

    #[test]
    fn estimate_fee_matches_formula() {
        // (inputs*1100 + outputs*1500 + 200) * rate / 10
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
        // large: acct 0 (big); small: acct 1 (tiny); fee: 99.
        let accounts = vec![acct(0, &[500_000]), acct(1, &[1_000]), acct(99, &[200_000])];
        let plan = ElementsAccountForAccountBatchedSweep::new(99, 10_000)
            .plan(&accounts, 1)
            .unwrap();
        // one large tx + one small-bundle tx + one fee-final tx.
        assert_eq!(plan.sweep_transactions.len(), 3);
        assert!(!plan.sweep_transactions[0].is_fee_final);
        assert!(plan.sweep_transactions.last().unwrap().is_fee_final);
        // last tx is fee-account only.
        assert!(
            plan.sweep_transactions
                .last()
                .unwrap()
                .outputs
                .iter()
                .all(|o| matches!(o, ElementsSweepOutput::FeeChange { .. }))
        );
    }
}
