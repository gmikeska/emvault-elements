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

use elements::{Address, OutPoint};
use elements_miniscript::psbt::PsbtExt;
use lwk_wollet::{ExternalUtxo, TxBuilder};

use crate::error::SpendError;
use crate::pset::BlindedPset;
use crate::sync::CapturedUtxo;
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
    let (external, singles) = prepare_inputs(wollet, utxos)?;
    let pset = TxBuilder::new(wollet.lwk_network())
        .add_external_utxos(external)
        .map_err(|e| SpendError::Build(e.to_string()))?
        .add_lbtc_recipient(recipient, amount_sat)
        .map_err(|e| SpendError::Build(e.to_string()))?
        .fee_rate(Some(fee_rate_sat_per_kvb))
        .finish(wollet.inner())
        .map_err(|e| SpendError::Build(e.to_string()))?;
    finish_blinded(pset, utxos, &singles)
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
    let (external, singles) = prepare_inputs(wollet, utxos)?;
    let pset = TxBuilder::new(wollet.lwk_network())
        .add_external_utxos(external)
        .map_err(|e| SpendError::Build(e.to_string()))?
        .drain_lbtc_wallet()
        .drain_lbtc_to(recipient.clone())
        .fee_rate(Some(fee_rate_sat_per_kvb))
        .finish(wollet.inner())
        .map_err(|e| SpendError::Build(e.to_string()))?;
    finish_blinded(pset, utxos, &singles)
}

type SingleDescriptors = Vec<
    elements_miniscript::descriptor::Descriptor<
        elements_miniscript::descriptor::DescriptorPublicKey,
    >,
>;

/// Map captured UTXOs to LWK `ExternalUtxo`s and split the descriptor into its
/// [external, internal] single-path forms.
fn prepare_inputs(
    wollet: &ElementsWollet,
    utxos: &[CapturedUtxo],
) -> Result<(Vec<ExternalUtxo>, SingleDescriptors), SpendError> {
    let multi = wollet
        .descriptor()
        .descriptor()
        .map_err(|e| SpendError::Descriptor(e.to_string()))?
        .clone();
    let singles = multi
        .into_single_descriptors()
        .map_err(|e| SpendError::Descriptor(e.to_string()))?;

    let max_weight = singles
        .first()
        .ok_or_else(|| SpendError::Descriptor("descriptor has no chains".into()))?
        .at_derivation_index(0)
        .map_err(|e| SpendError::Descriptor(e.to_string()))?
        .max_weight_to_satisfy()
        .map_err(|e| SpendError::Descriptor(e.to_string()))?;

    let external = utxos
        .iter()
        .map(|u| ExternalUtxo {
            outpoint: u.outpoint,
            txout: u.txout.clone(),
            tx: None,
            unblinded: u.secrets,
            max_weight_to_satisfy: max_weight,
        })
        .collect();
    Ok((external, singles))
}

/// Enrich each of our inputs with `witness_script` + `bip32_derivation`, then
/// wrap as a [`BlindedPset`].
fn finish_blinded(
    mut pset: elements::pset::PartiallySignedTransaction,
    utxos: &[CapturedUtxo],
    singles: &SingleDescriptors,
) -> Result<BlindedPset, SpendError> {
    let by_outpoint: HashMap<OutPoint, (usize, u32)> = utxos
        .iter()
        .map(|u| (u.outpoint, (u.chain as usize, u.wildcard_index)))
        .collect();

    for idx in 0..pset.inputs().len() {
        let input = &pset.inputs()[idx];
        let prevout = OutPoint::new(input.previous_txid, input.previous_output_index);
        let Some((chain_idx, index)) = by_outpoint.get(&prevout).copied() else {
            continue;
        };
        let definite = singles
            .get(chain_idx)
            .ok_or_else(|| SpendError::Descriptor("missing chain descriptor".into()))?
            .at_derivation_index(index)
            .map_err(|e| SpendError::Descriptor(e.to_string()))?;
        pset.update_input_with_descriptor(idx, &definite)
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

    /// 2-of-3 federation + wollet from three SoftSigners.
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

    /// Build a CapturedUtxo whose txout actually pays our derived address at
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
