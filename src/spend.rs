//! Spend-path construction: turn captured UTXOs into a blinded, signable PSET.
//!
//! Construction and blinding are delegated to LWK's [`TxBuilder`], fed our
//! [`CapturedUtxo`]s as `ExternalUtxo`s (the wallet itself holds no scanned
//! state). LWK does coin assembly + confidential blinding; we then **enrich**
//! each of our inputs with the `witness_script` and `bip32_derivation` that the
//! multisig signing path needs (LWK treats external inputs as foreign and omits
//! these), and hand the result to the existing
//! [`ElementsSigningCoordinator`](crate::pset::ElementsSigningCoordinator)
//! → finalize pipeline.

use std::collections::HashMap;

use elements::{Address, OutPoint, Txid};
use elements_miniscript::psbt::PsbtExt;
use lwk_wollet::{ExternalUtxo, TxBuilder};

use crate::error::SpendError;
use crate::pset::BlindedPset;
use crate::sync::{CapturedUtxo, WalletId};
use crate::wollet::ElementsWollet;

/// Build a blinded, signable PSET spending `utxos` to pay `amount_sat` L-BTC to
/// `recipient`, with change returning to `wollet`'s internal chain.
///
/// All provided `utxos` are added as inputs (coarse selection — the caller
/// chooses which to pass). LWK blinds the result; we enrich our inputs with the
/// multisig `witness_script` + `bip32_derivation` before returning.
///
/// # Errors
///
/// - [`SpendError::Build`] from LWK (e.g. insufficient funds for amount + fee).
/// - [`SpendError::Descriptor`] / [`SpendError::Enrich`] if input metadata
///   cannot be derived.
/// - [`SpendError::Pset`] if the result is not a valid blinded PSET.
pub fn build_spend_pset(
    wollet: &ElementsWollet,
    utxos: &[CapturedUtxo],
    recipient: &Address,
    amount_sat: u64,
    fee_rate_sat_per_kvb: f32,
) -> Result<BlindedPset, SpendError> {
    let singles = singles_of(wollet)?;
    let (external, enrich) = prepare_inputs(utxos, &singles)?;
    let pset = TxBuilder::new(wollet.lwk_network())
        .add_external_utxos(external)
        .map_err(|e| SpendError::Build(e.to_string()))?
        .add_lbtc_recipient(recipient, amount_sat)
        .map_err(|e| SpendError::Build(e.to_string()))?
        .fee_rate(Some(fee_rate_sat_per_kvb))
        .finish(wollet.inner())
        .map_err(|e| SpendError::Build(e.to_string()))?;
    finish_blinded(pset, &enrich)
}

/// Like [`build_spend_pset`] but **sweeps** all provided UTXOs to `recipient`
/// (drains L-BTC; no change output). Used for consolidation / migration sweeps.
///
/// # Errors
///
/// Same as [`build_spend_pset`].
pub fn build_sweep_pset(
    wollet: &ElementsWollet,
    utxos: &[CapturedUtxo],
    recipient: &Address,
    fee_rate_sat_per_kvb: f32,
) -> Result<BlindedPset, SpendError> {
    let singles = singles_of(wollet)?;
    let (external, enrich) = prepare_inputs(utxos, &singles)?;
    let pset = TxBuilder::new(wollet.lwk_network())
        .add_external_utxos(external)
        .map_err(|e| SpendError::Build(e.to_string()))?
        .drain_lbtc_wallet()
        .drain_lbtc_to(recipient.clone())
        .fee_rate(Some(fee_rate_sat_per_kvb))
        .finish(wollet.inner())
        .map_err(|e| SpendError::Build(e.to_string()))?;
    finish_blinded(pset, &enrich)
}

/// Build a blinded **migration** PSET: many accounts' UTXOs in, each customer
/// paid their exact amount, and the **fee account pays the mining fee** by
/// absorbing the remainder via an L-BTC drain output.
///
/// `inputs` pairs each captured UTXO with the [`ElementsWollet`] that owns it
/// (so its inputs are enriched with the correct multisig metadata).
/// `customer_recipients` are exact `(address, amount)` pairs;
/// `fee_account_dest` receives `sum(inputs) - sum(customers) - fee`.
///
/// # Errors
///
/// Same as [`build_spend_pset`]; also if an input's owning descriptor cannot be
/// derived.
pub fn build_migration_pset(
    fee_wollet: &ElementsWollet,
    inputs: &[(CapturedUtxo, &ElementsWollet)],
    customer_recipients: &[(Address, u64)],
    fee_account_dest: &Address,
    fee_rate_sat_per_kvb: f32,
) -> Result<BlindedPset, SpendError> {
    // Cache each distinct owning descriptor's single-path forms.
    let mut singles_cache: HashMap<String, SingleDescriptors> = HashMap::new();
    let mut external = Vec::with_capacity(inputs.len());
    let mut enrich: HashMap<OutPoint, DefiniteDesc> = HashMap::new();

    for (utxo, owner) in inputs {
        let key = owner.descriptor().to_string();
        if !singles_cache.contains_key(&key) {
            singles_cache.insert(key.clone(), singles_of(owner)?);
        }
        let singles = &singles_cache[&key];
        external.push(external_utxo(utxo, max_weight_of(singles)?));
        enrich.insert(
            utxo.outpoint,
            definite_at(singles, utxo.chain as usize, utxo.wildcard_index)?,
        );
    }

    let mut builder = TxBuilder::new(fee_wollet.lwk_network())
        .add_external_utxos(external)
        .map_err(|e| SpendError::Build(e.to_string()))?;
    for (addr, amount) in customer_recipients {
        builder = builder
            .add_lbtc_recipient(addr, *amount)
            .map_err(|e| SpendError::Build(e.to_string()))?;
    }
    let pset = builder
        .drain_lbtc_wallet()
        .drain_lbtc_to(fee_account_dest.clone())
        .fee_rate(Some(fee_rate_sat_per_kvb))
        .finish(fee_wollet.inner())
        .map_err(|e| SpendError::Build(e.to_string()))?;
    finish_blinded(pset, &enrich)
}

/// Build a [`CapturedUtxo`] from a freshly-broadcast (still-unconfirmed)
/// confidential output that `wollet` controls — used to **chain** the fee
/// account's change from one batched-migration transaction into the next
/// without waiting for a confirmation or a re-scan.
///
/// `wollet` must own the output's script (so it can recover the blinding
/// secrets); for the batched migration this is the fee account's wollet, and
/// the chained change is routed back to its own address each hop.
///
/// `wildcard_index` is the derivation index of the destination address the
/// change was paid to (the batched flow uses the external chain at index 0).
/// `height` is recorded as `0` (unconfirmed); the value is informational here
/// since the UTXO is consumed immediately as an `ExternalUtxo`.
///
/// # Errors
///
/// [`SpendError::Unblind`] if the output does not belong to `wollet` or its
/// confidential commitments cannot be opened.
pub fn captured_from_output(
    wollet: &ElementsWollet,
    txid: Txid,
    vout: u32,
    txout: &elements::TxOut,
    wallet_id: WalletId,
    wildcard_index: u32,
) -> Result<CapturedUtxo, SpendError> {
    let secrets = wollet
        .unblind(txout)
        .map_err(|e| SpendError::Unblind(e.to_string()))?;
    Ok(CapturedUtxo {
        wallet_id,
        outpoint: OutPoint::new(txid, vout),
        txout: txout.clone(),
        secrets,
        chain: lwk_wollet::Chain::External,
        wildcard_index,
        height: 0,
        is_spent: false,
    })
}

type SingleDescriptors = Vec<
    elements_miniscript::descriptor::Descriptor<
        elements_miniscript::descriptor::DescriptorPublicKey,
    >,
>;

type DefiniteDesc = elements_miniscript::descriptor::Descriptor<
    elements_miniscript::descriptor::DefiniteDescriptorKey,
>;

/// Split a wollet's multipath descriptor into its `[external, internal]`
/// single-path forms.
fn singles_of(wollet: &ElementsWollet) -> Result<SingleDescriptors, SpendError> {
    wollet
        .descriptor()
        .descriptor()
        .map_err(|e| SpendError::Descriptor(e.to_string()))?
        .clone()
        .into_single_descriptors()
        .map_err(|e| SpendError::Descriptor(e.to_string()))
}

/// Max satisfaction weight, identical across indices for our multisig.
fn max_weight_of(singles: &SingleDescriptors) -> Result<usize, SpendError> {
    singles
        .first()
        .ok_or_else(|| SpendError::Descriptor("descriptor has no chains".into()))?
        .at_derivation_index(0)
        .map_err(|e| SpendError::Descriptor(e.to_string()))?
        .max_weight_to_satisfy()
        .map_err(|e| SpendError::Descriptor(e.to_string()))
}

fn external_utxo(u: &CapturedUtxo, max_weight: usize) -> ExternalUtxo {
    ExternalUtxo {
        outpoint: u.outpoint,
        txout: u.txout.clone(),
        tx: None,
        unblinded: u.secrets,
        max_weight_to_satisfy: max_weight,
    }
}

/// The definite (concrete-index) descriptor for `chain`/`index`.
fn definite_at(
    singles: &SingleDescriptors,
    chain: usize,
    index: u32,
) -> Result<DefiniteDesc, SpendError> {
    singles
        .get(chain)
        .ok_or_else(|| SpendError::Descriptor("missing chain descriptor".into()))?
        .at_derivation_index(index)
        .map_err(|e| SpendError::Descriptor(e.to_string()))
}

/// Single-wallet input prep: external UTXOs + a per-outpoint enrichment map.
fn prepare_inputs(
    utxos: &[CapturedUtxo],
    singles: &SingleDescriptors,
) -> Result<(Vec<ExternalUtxo>, HashMap<OutPoint, DefiniteDesc>), SpendError> {
    let max_weight = max_weight_of(singles)?;
    let mut external = Vec::with_capacity(utxos.len());
    let mut enrich = HashMap::with_capacity(utxos.len());
    for u in utxos {
        external.push(external_utxo(u, max_weight));
        enrich.insert(
            u.outpoint,
            definite_at(singles, u.chain as usize, u.wildcard_index)?,
        );
    }
    Ok((external, enrich))
}

/// Enrich each of our inputs with `witness_script` + `bip32_derivation` (from
/// its owning descriptor), then wrap as a [`BlindedPset`].
fn finish_blinded(
    mut pset: elements::pset::PartiallySignedTransaction,
    enrich: &HashMap<OutPoint, DefiniteDesc>,
) -> Result<BlindedPset, SpendError> {
    for idx in 0..pset.inputs().len() {
        let input = &pset.inputs()[idx];
        let prevout = OutPoint::new(input.previous_txid, input.previous_output_index);
        let Some(definite) = enrich.get(&prevout) else {
            continue;
        };
        pset.update_input_with_descriptor(idx, definite)
            .map_err(|e| SpendError::Enrich(e.to_string()))?;
    }
    Ok(BlindedPset::new(pset)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ElementsWalletHandle;
    use crate::descriptor::{CtDescriptorBuilder, CtKeyMode};
    use crate::network::ElementsNetwork;
    use crate::pset::ElementsSigningCoordinator;
    use crate::sync::WalletId;

    use crate::testkit::SoftwareSigner as SoftSigner;

    use crate::signer::ElementsSigner;

    use asterism_core::federation::Federation;
    use asterism_core::network::{ElementsNetworkId, NetworkType};
    use asterism_core::signer::Signer;
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::{AssetId, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness};

    fn soft(seed: u8) -> SoftSigner {
        SoftSigner::new(seed, ElementsNetwork::ElementsRegtest)
    }

    fn lbtc() -> AssetId {
        *ElementsNetwork::ElementsRegtest.to_lwk().policy_asset()
    }

    fn explicit_txout(spk: Script, value: u64) -> TxOut {
        TxOut {
            asset: Asset::Explicit(lbtc()),
            value: Value::Explicit(value),
            nonce: Nonce::Null,
            script_pubkey: spk,
            witness: TxOutWitness::default(),
        }
    }

    /// 2-of-3 federation + wollet from three `SoftSigner`s.
    fn federation_and_wollet(
        seeds: [u8; 3],
        blinding: u8,
    ) -> (Federation<SoftSigner>, ElementsWollet, Vec<SoftSigner>) {
        let signers: Vec<SoftSigner> = seeds.iter().map(|&s| soft(s)).collect();
        let mut builder = CtDescriptorBuilder::new(2, &[blinding; 32])
            .unwrap()
            .key_mode(CtKeyMode::Ranged);
        for s in &signers {
            builder.add_signer(s as &dyn Signer).unwrap();
        }
        let desc = builder.build().unwrap();
        let handle = ElementsWalletHandle::new(desc.clone(), [blinding; 32]);
        let wollet =
            ElementsWollet::from_handle(&handle, ElementsNetwork::ElementsRegtest).unwrap();
        let fed = Federation::new(
            2,
            signers.clone(),
            NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
        )
        .unwrap();
        (fed, wollet, signers)
    }

    fn captured_lbtc(wallet: WalletId, index: u32, value: u64, txid_seed: u8) -> CapturedUtxo {
        // A confidential-looking but explicit funding output to our addr `index`.
        let mut outpoint = OutPoint::null();
        outpoint.vout = u32::from(txid_seed);
        CapturedUtxo {
            wallet_id: wallet,
            outpoint,
            txout: explicit_txout(Script::new(), value),
            secrets: TxOutSecrets::new(
                lbtc(),
                AssetBlindingFactor::zero(),
                value,
                ValueBlindingFactor::zero(),
            ),
            chain: lwk_wollet::Chain::External,
            wildcard_index: index,
            height: 1,
            is_spent: false,
        }
    }

    /// Build a `CapturedUtxo` whose txout actually pays our derived address at
    /// `index`, so LWK + our enrichment see a consistent script.
    fn funding_utxo(
        wollet: &ElementsWollet,
        index: u32,
        value: u64,
        txid_seed: u8,
    ) -> CapturedUtxo {
        let addr = wollet.address(lwk_wollet::Chain::External, index).unwrap();
        let mut u = captured_lbtc(WalletId::from_bytes([1; 16]), index, value, txid_seed);
        u.txout = explicit_txout(addr.script_pubkey(), value);
        u
    }

    /// Multi-account, fee-account-pays migration PSET: customers receive exact
    /// amounts, the fee account absorbs the mining fee via the drain, and each
    /// account signs only its own inputs.
    #[test]
    fn migration_fee_account_pays_and_multi_account_signs() {
        // Fee account F + two customers C1, C2 (distinct keys → distinct scripts).
        let (_fed_f, w_f, sg_f) = federation_and_wollet([1, 2, 3], 0xaa);
        let (_fed_c1, w_c1, sg_c1) = federation_and_wollet([4, 5, 6], 0xbb);
        let (_fed_c2, w_c2, sg_c2) = federation_and_wollet([7, 8, 9], 0xcc);

        // F holds 100k (to pay the fee); customers hold their balances.
        let f_utxo = funding_utxo(&w_f, 0, 100_000, 1);
        let c1_utxo = funding_utxo(&w_c1, 0, 200_000, 2);
        let c2_utxo = funding_utxo(&w_c2, 0, 300_000, 3);

        // New-federation destinations (each wallet's own index-5 addr so we can
        // unblind and verify exact amounts).
        let c1_dest = w_c1.address(lwk_wollet::Chain::External, 5).unwrap();
        let c2_dest = w_c2.address(lwk_wollet::Chain::External, 5).unwrap();
        let f_dest = w_f.address(lwk_wollet::Chain::External, 5).unwrap();

        let inputs = vec![(f_utxo, &w_f), (c1_utxo, &w_c1), (c2_utxo, &w_c2)];
        let blinded = build_migration_pset(
            &w_f,
            &inputs,
            &[(c1_dest.clone(), 200_000), (c2_dest.clone(), 300_000)],
            &f_dest,
            2000.0,
        )
        .unwrap();

        // Structural: 3 inputs enriched, outputs blinded.
        {
            let pset = blinded.as_pset();
            assert_eq!(pset.inputs().len(), 3);
            for inp in pset.inputs() {
                assert!(inp.witness_script.is_some());
                assert_eq!(inp.bip32_derivation.len(), 3);
            }
            assert!(pset.outputs().iter().any(|o| o.value_rangeproof.is_some()));
        }

        // Fee-account-pays: customers get exact; fee account drains the rest.
        let tx = blinded.as_pset().extract_tx().unwrap();
        let unblind_at = |w: &ElementsWollet, dest: &Address| -> u64 {
            let spk = dest.script_pubkey();
            let txout = tx
                .output
                .iter()
                .find(|o| o.script_pubkey == spk)
                .expect("destination output present");
            w.unblind(txout).unwrap().value
        };
        assert_eq!(unblind_at(&w_c1, &c1_dest), 200_000, "customer 1 exact");
        assert_eq!(unblind_at(&w_c2, &c2_dest), 300_000, "customer 2 exact");
        let fee_change = unblind_at(&w_f, &f_dest);
        let fee_sat = tx
            .output
            .iter()
            .find(|o| o.script_pubkey.is_empty())
            .and_then(|o| o.value.explicit())
            .unwrap();
        assert!(fee_sat > 0, "non-zero fee");
        assert_eq!(
            fee_change + fee_sat,
            100_000,
            "fee account paid: its 100k = drain change + fee, customers untouched"
        );

        // Multi-account signing: each account's 2-of-3 signs only its inputs.
        let mut pset = blinded.into_pset();
        for s in [
            &sg_f[0], &sg_f[1], &sg_c1[0], &sg_c1[1], &sg_c2[0], &sg_c2[1],
        ] {
            s.sign_pset(&mut pset).unwrap();
        }
        crate::finalize_p2wsh_pset(&mut pset).unwrap();
        let final_tx = pset.extract_tx().unwrap();
        assert_eq!(final_tx.input.len(), 3);
        for inp in &final_tx.input {
            assert!(
                inp.witness.script_witness.len() >= 4,
                "each input finalized with a witness"
            );
        }
    }

    /// Batched migration with **chained confidential fee-change** (decision
    /// (b)): the fee account's change is routed back to its OWN old-fed address
    /// each hop, captured via [`captured_from_output`], and fed into the next
    /// tx. The final fee-only tx (empty customer set) drains to the new-fed
    /// address. Asserts customers get exact amounts, value is conserved across
    /// the chain (only mining fees leak), and every input signs+finalizes.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn batched_migration_chains_fee_change_offline() {
        const INITIAL_FEE: u64 = 1_000_000;
        const C1_BAL: u64 = 200_000;
        const C2_BAL: u64 = 300_000;
        const RATE_KVB: f32 = 1000.0; // 1 sat/vB

        let (_f_fed, w_f, sg_f) = federation_and_wollet([1, 2, 3], 0xaa);
        let (_c1_fed, w_c1, sg_c1) = federation_and_wollet([4, 5, 6], 0xbb);
        let (_c2_fed, w_c2, sg_c2) = federation_and_wollet([7, 8, 9], 0xcc);

        let f_utxo = funding_utxo(&w_f, 0, INITIAL_FEE, 1);
        let c1_utxo = funding_utxo(&w_c1, 0, C1_BAL, 2);
        let c2_utxo = funding_utxo(&w_c2, 0, C2_BAL, 3);

        // Customer new-fed destinations (own index-5 addr so we can unblind).
        let c1_dest = w_c1.address(lwk_wollet::Chain::External, 5).unwrap();
        let c2_dest = w_c2.address(lwk_wollet::Chain::External, 5).unwrap();
        // Fee account: OLD-fed change sink (External/0) for intermediate hops;
        // a distinct NEW-fed address (index 6) only for the final tx.
        let f_old = w_f.address(lwk_wollet::Chain::External, 0).unwrap();
        let f_new = w_f.address(lwk_wollet::Chain::External, 6).unwrap();

        let wallet_id = WalletId::from_bytes([1; 16]);

        // Build one batch tx, sign with `signers`, finalize, extract.
        let run = |inputs: &[(CapturedUtxo, &ElementsWollet)],
                   customers: &[(Address, u64)],
                   fee_dest: &Address,
                   signers: &[&SoftSigner]|
         -> elements::Transaction {
            let blinded =
                build_migration_pset(&w_f, inputs, customers, fee_dest, RATE_KVB).unwrap();
            let mut pset = blinded.into_pset();
            for s in signers {
                s.sign_pset(&mut pset).unwrap();
            }
            crate::finalize_p2wsh_pset(&mut pset).unwrap();
            let tx = pset.extract_tx().unwrap();
            for inp in &tx.input {
                assert!(
                    inp.witness.script_witness.len() >= 4,
                    "each input finalized with a witness"
                );
            }
            tx
        };

        let fee_of = |tx: &elements::Transaction| -> u64 {
            tx.output
                .iter()
                .find(|o| o.script_pubkey.is_empty())
                .and_then(|o| o.value.explicit())
                .expect("explicit fee output")
        };
        // Capture the fee account's change output (at `f_old`) as a chained UTXO.
        let chain_change = |tx: &elements::Transaction| -> CapturedUtxo {
            let spk = f_old.script_pubkey();
            let (vout, txout) = tx
                .output
                .iter()
                .enumerate()
                .find(|(_, o)| o.script_pubkey == spk)
                .map(|(i, o)| (u32::try_from(i).unwrap(), o.clone()))
                .expect("fee change output present");
            captured_from_output(&w_f, tx.txid(), vout, &txout, wallet_id, 0).unwrap()
        };
        let unblind_at = |w: &ElementsWollet, tx: &elements::Transaction, dest: &Address| -> u64 {
            let spk = dest.script_pubkey();
            let txout = tx
                .output
                .iter()
                .find(|o| o.script_pubkey == spk)
                .expect("destination output present");
            w.unblind(txout).unwrap().value
        };

        // --- tx0: C1 + real fee utxo → C1 exact, change back to F old. ------
        let tx0 = run(
            &[(c1_utxo, &w_c1), (f_utxo, &w_f)],
            &[(c1_dest.clone(), C1_BAL)],
            &f_old,
            &[&sg_c1[0], &sg_c1[1], &sg_f[0], &sg_f[1]],
        );
        assert_eq!(unblind_at(&w_c1, &tx0, &c1_dest), C1_BAL, "C1 exact");
        let fee0 = fee_of(&tx0);
        let change0 = chain_change(&tx0);
        assert_eq!(
            change0.value(),
            INITIAL_FEE - fee0,
            "after tx0 the fee account holds its balance minus fee0 (C1 untouched)"
        );

        // --- tx1: C2 + chained change → C2 exact, change back to F old. -----
        let tx1 = run(
            &[(c2_utxo, &w_c2), (change0, &w_f)],
            &[(c2_dest.clone(), C2_BAL)],
            &f_old,
            &[&sg_c2[0], &sg_c2[1], &sg_f[0], &sg_f[1]],
        );
        assert_eq!(unblind_at(&w_c2, &tx1, &c2_dest), C2_BAL, "C2 exact");
        let fee1 = fee_of(&tx1);
        let change1 = chain_change(&tx1);
        assert_eq!(
            change1.value(),
            INITIAL_FEE - fee0 - fee1,
            "after tx1 the fee account holds its balance minus fees so far"
        );

        // --- tx2: fee-only final tx (empty customers) → drain to F new. -----
        let tx2 = run(&[(change1, &w_f)], &[], &f_new, &[&sg_f[0], &sg_f[1]]);
        // Empty-customer drain (risk #2): exactly one recipient output + fee.
        assert_eq!(tx2.output.len(), 2, "final fee-only tx: drain output + fee");
        let fee2 = fee_of(&tx2);
        let final_value = unblind_at(&w_f, &tx2, &f_new);

        // Value conservation across the whole chain: the fee account's initial
        // balance ends up at the new federation, less the cumulative mining fee.
        assert_eq!(
            final_value + fee0 + fee1 + fee2,
            INITIAL_FEE,
            "fee account paid exactly the cumulative fee; customers got full balances"
        );
    }

    #[test]
    fn assembles_blinds_and_enriches() {
        let (_fed, wollet, _) = federation_and_wollet([1, 2, 3], 0xaa);
        let recipient = ElementsWollet::from_handle(
            &ElementsWalletHandle::new(
                {
                    let mut b = CtDescriptorBuilder::new(2, &[0xcc; 32])
                        .unwrap()
                        .key_mode(CtKeyMode::Ranged);
                    for s in [10u8, 11, 12].map(soft) {
                        b.add_signer(&s as &dyn Signer).unwrap();
                    }
                    b.build().unwrap()
                },
                [0xcc; 32],
            ),
            ElementsNetwork::ElementsRegtest,
        )
        .unwrap()
        .address(lwk_wollet::Chain::External, 0)
        .unwrap();

        let utxos = vec![funding_utxo(&wollet, 0, 100_000, 1)];
        let blinded = build_spend_pset(&wollet, &utxos, &recipient, 40_000, 100.0).unwrap();
        let pset = blinded.as_pset();

        assert_eq!(pset.inputs().len(), 1, "our single utxo is the input");
        // every input enriched with the multisig metadata
        for inp in pset.inputs() {
            assert!(inp.witness_script.is_some(), "witness_script populated");
            assert_eq!(
                inp.bip32_derivation.len(),
                3,
                "all three federation keys present for signing"
            );
        }
        // outputs: recipient + change + fee, at least one blinded
        assert!(pset.outputs().len() >= 3, "recipient + change + fee");
        assert!(
            pset.outputs().iter().any(|o| o.value_rangeproof.is_some()),
            "LWK blinded the outputs"
        );
    }

    #[test]
    fn full_round_trip_sign_and_finalize() {
        let (fed, wollet, signers) = federation_and_wollet([1, 2, 3], 0xaa);
        let recipient = {
            let (_f, w2, _s) = federation_and_wollet([7, 8, 9], 0xdd);
            w2.address(lwk_wollet::Chain::External, 0).unwrap()
        };

        let utxos = vec![funding_utxo(&wollet, 0, 200_000, 1)];
        let blinded = build_spend_pset(&wollet, &utxos, &recipient, 50_000, 100.0).unwrap();

        let mut coordinator = ElementsSigningCoordinator::new(&fed, blinded).unwrap();
        // sign with two of three signers (threshold 2-of-3)
        let signed0 = coordinator
            .sign_with(&signers[0], &signers[0].id())
            .unwrap();
        assert!(signed0 >= 1, "signer 0 signed at least one input");
        coordinator
            .sign_with(&signers[1], &signers[1].id())
            .unwrap();
        assert!(coordinator.is_complete(), "2-of-3 threshold met");

        let finalized = coordinator.finalize().unwrap();
        let tx = finalized.transaction();
        assert_eq!(tx.input.len(), 1);
        // a real P2WSH witness was assembled (OP_0 + 2 sigs + witnessScript)
        assert!(
            tx.input[0].witness.script_witness.len() >= 4,
            "finalized witness stack present"
        );
        assert!(!finalized.serialize_hex().is_empty());
    }

    /// A confidential output sitting at one of our watched scripts but blinded
    /// with a key we don't hold must fail to unblind — this is the precondition
    /// the block-scan engine relies on to *skip* (not abort on) legacy/foreign
    /// change outputs.
    #[test]
    fn unblind_fails_for_foreign_blinded_output_at_our_script() {
        use elements::confidential::Value;

        let (_fed, wollet_a, _) = federation_and_wollet([1, 2, 3], 0xaa);
        let (_f, wollet_b, _) = federation_and_wollet([7, 8, 9], 0xdd);
        let recipient_b = wollet_b.address(lwk_wollet::Chain::External, 0).unwrap();

        let utxos = vec![funding_utxo(&wollet_a, 0, 200_000, 1)];
        let blinded = build_spend_pset(&wollet_a, &utxos, &recipient_b, 50_000, 2000.0).unwrap();
        let tx = blinded.as_pset().extract_tx().unwrap();

        // Take a genuinely-blinded output (recipient/change) and move it onto
        // wallet A's external script #0 — a script A watches but for which the
        // output was blinded with a different key.
        let mut foreign = tx
            .output
            .iter()
            .find(|o| matches!(o.value, Value::Confidential(_)))
            .expect("a blinded output exists")
            .clone();
        foreign.script_pubkey = wollet_a
            .address(lwk_wollet::Chain::External, 0)
            .unwrap()
            .script_pubkey();

        assert!(
            wollet_a.unblind(&foreign).is_err(),
            "foreign-blinded output at our script must fail to unblind"
        );
    }

    #[test]
    fn insufficient_funds_errors() {
        let (_fed, wollet, _) = federation_and_wollet([1, 2, 3], 0xaa);
        let recipient = {
            let (_f, w2, _s) = federation_and_wollet([7, 8, 9], 0xdd);
            w2.address(lwk_wollet::Chain::External, 0).unwrap()
        };
        // only 10k available, asking to send 50k
        let utxos = vec![funding_utxo(&wollet, 0, 10_000, 1)];
        let err = build_spend_pset(&wollet, &utxos, &recipient, 50_000, 100.0).unwrap_err();
        assert!(matches!(err, SpendError::Build(_)), "got {err:?}");
    }
}
