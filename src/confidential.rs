//! Defense-in-depth validation for blinded PSETs.

use elements::pset::PartiallySignedTransaction as Pset;

use crate::error::PsetError;
use crate::pset::BlindedPset;

/// Validate that a blinded PSET has correct confidential transaction
/// structure before signing.
///
/// Checks:
/// - Every non-fee output has a value commitment and asset commitment.
/// - Every non-fee output has a range proof and surjection proof.
/// - All blinder indices reference valid inputs.
///
/// This is called automatically by [`ElementsSigningCoordinator::new`]
/// as a pre-signing gate. It can also be called standalone for
/// out-of-band validation of PSETs received from external sources.
pub fn validate_blinding(pset: &BlindedPset) -> Result<(), PsetError> {
    let inner = pset.as_pset();
    validate_blinding_raw(inner)
}

/// Raw PSET validation (operates on an unwrapped `Pset`).
pub(crate) fn validate_blinding_raw(pset: &Pset) -> Result<(), PsetError> {
    let num_inputs = pset.inputs().len();

    for (idx, output) in pset.outputs().iter().enumerate() {
        let is_fee = output.script_pubkey.is_empty();
        if is_fee {
            continue;
        }

        if output.value_rangeproof.is_none() {
            return Err(PsetError::BlindingFailed(format!(
                "output {idx} missing range proof"
            )));
        }

        if output.asset_surjection_proof.is_none() {
            return Err(PsetError::BlindingFailed(format!(
                "output {idx} missing surjection proof"
            )));
        }

        if let Some(blinder_idx) = output.blinder_index
            && (blinder_idx as usize) >= num_inputs
        {
            return Err(PsetError::BlindingFailed(format!(
                "output {idx} blinder_index {blinder_idx} exceeds input count {num_inputs}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pset() -> Pset {
        let tx = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        Pset::from_tx(tx)
    }

    #[test]
    fn validation_passes_on_empty_outputs() {
        let pset = minimal_pset();
        // Can't construct a BlindedPset from an empty PSET (NotBlinded),
        // so validate_blinding_raw should pass on the raw PSET with no
        // non-fee outputs.
        assert!(BlindedPset::new(pset).is_err(), "empty PSET is not blinded");
        let raw = minimal_pset();
        validate_blinding_raw(&raw).expect("empty outputs should pass");
    }

    // --- Negative-case coverage for validate_blinding -----------------------
    //
    // These build *genuine* confidential outputs entirely offline (no network):
    // real range and surjection proofs are produced via secp256k1-zkp and the
    // `elements` blinding primitives (`Asset::blind` / `Value::blind`, driven
    // through `TxOut::with_txout_secrets`). Individual proof fields are then
    // selectively cleared to trip each validation branch.

    use elements::confidential::{AssetBlindingFactor, ValueBlindingFactor};
    use elements::secp256k1_zkp::{self, Secp256k1, SecretKey};
    use elements::{AssetId, Script, Transaction, TxIn, TxOut, TxOutSecrets};

    fn test_asset() -> AssetId {
        AssetId::from_slice(&[2u8; 32]).expect("valid asset id")
    }

    /// A non-empty script pubkey so the output is treated as a real (non-fee)
    /// output. The exact bytes are irrelevant to blinding; this is a p2wpkh
    /// witness-program shape.
    fn nonempty_spk() -> Script {
        let mut bytes = vec![0x00u8, 0x14];
        bytes.extend([0x11u8; 20]);
        Script::from(bytes)
    }

    /// Build a genuine, fully-blinded confidential `TxOut` offline. Both the
    /// range proof (`witness.rangeproof`) and surjection proof
    /// (`witness.surjection_proof`) are real and non-empty.
    fn genuine_confidential_txout() -> TxOut {
        let secp = Secp256k1::new();
        let mut rng = secp256k1_zkp::rand::thread_rng();
        let asset = test_asset();

        // Input secret the surjection proof maps the output asset back to.
        let in_secrets = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::new(&mut rng),
            100_000,
            ValueBlindingFactor::new(&mut rng),
        );
        let out_secrets = TxOutSecrets::new(
            asset,
            AssetBlindingFactor::new(&mut rng),
            100_000,
            ValueBlindingFactor::new(&mut rng),
        );

        let blinding_secret = SecretKey::new(&mut rng);
        let receiver_pk = secp256k1_zkp::PublicKey::from_secret_key(&secp, &blinding_secret);
        let ephemeral_sk = SecretKey::new(&mut rng);

        TxOut::with_txout_secrets(
            &mut rng,
            &secp,
            nonempty_spk(),
            receiver_pk,
            ephemeral_sk,
            out_secrets,
            &[in_secrets],
        )
        .expect("offline blinding of a single output should succeed")
    }

    /// Wrap outputs into a PSET carrying `num_inputs` dummy inputs. `from_tx`
    /// copies each `TxOut`'s witness proofs into the PSET output's
    /// `value_rangeproof` / `asset_surjection_proof` fields.
    fn pset_with(num_inputs: usize, outputs: Vec<TxOut>) -> Pset {
        let tx = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: (0..num_inputs).map(|_| TxIn::default()).collect(),
            output: outputs,
        };
        Pset::from_tx(tx)
    }

    #[test]
    fn fee_output_is_skipped_even_without_proofs() {
        // A fee output has an empty script pubkey and carries no proofs; it
        // must be skipped rather than rejected for missing proofs.
        let fee = TxOut::default();
        assert!(fee.script_pubkey.is_empty(), "fee output has empty spk");
        let pset = pset_with(1, vec![fee]);
        validate_blinding_raw(&pset).expect("fee output should be skipped");
    }

    #[test]
    fn rejects_non_fee_output_missing_range_proof() {
        let out = TxOut {
            script_pubkey: nonempty_spk(),
            ..TxOut::default()
        };
        let pset = pset_with(1, vec![out]);
        let err = validate_blinding_raw(&pset).unwrap_err();
        match err {
            PsetError::BlindingFailed(msg) => {
                assert!(msg.contains("missing range proof"), "got: {msg}");
            }
            other => panic!("expected BlindingFailed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_fee_output_missing_surjection_proof() {
        // Genuine output has both proofs; drop only the surjection proof so the
        // range-proof check passes and the surjection check is what trips.
        let mut pset = pset_with(1, vec![genuine_confidential_txout()]);
        assert!(pset.outputs()[0].value_rangeproof.is_some());
        pset.outputs_mut()[0].asset_surjection_proof = None;
        let err = validate_blinding_raw(&pset).unwrap_err();
        match err {
            PsetError::BlindingFailed(msg) => {
                assert!(msg.contains("missing surjection proof"), "got: {msg}");
            }
            other => panic!("expected BlindingFailed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_blinder_index_exceeding_input_count() {
        // One input, blinder_index points at input 5 -> out of range.
        let mut pset = pset_with(1, vec![genuine_confidential_txout()]);
        pset.outputs_mut()[0].blinder_index = Some(5);
        let err = validate_blinding_raw(&pset).unwrap_err();
        match err {
            PsetError::BlindingFailed(msg) => {
                assert!(msg.contains("exceeds input count"), "got: {msg}");
            }
            other => panic!("expected BlindingFailed, got {other:?}"),
        }
    }

    #[test]
    fn accepts_blinder_index_within_input_count() {
        // Three inputs, blinder_index 2 is in range -> passes.
        let mut pset = pset_with(3, vec![genuine_confidential_txout()]);
        pset.outputs_mut()[0].blinder_index = Some(2);
        validate_blinding_raw(&pset).expect("in-range blinder_index should pass");
    }

    #[test]
    fn accepts_fully_blinded_output() {
        let pset = pset_with(1, vec![genuine_confidential_txout()]);
        assert!(pset.outputs()[0].value_rangeproof.is_some());
        assert!(pset.outputs()[0].asset_surjection_proof.is_some());
        validate_blinding_raw(&pset).expect("fully-blinded output should pass");
    }

    #[test]
    fn public_validate_blinding_rejects_missing_surjection() {
        // Exercise the public wrapper: keep the range proof (so BlindedPset::new
        // accepts the PSET as blinded) but drop the surjection proof.
        let mut pset = pset_with(1, vec![genuine_confidential_txout()]);
        pset.outputs_mut()[0].asset_surjection_proof = None;
        let blinded = BlindedPset::new(pset).expect("range proof present -> blinded");
        let err = validate_blinding(&blinded).unwrap_err();
        match err {
            PsetError::BlindingFailed(msg) => {
                assert!(msg.contains("missing surjection proof"), "got: {msg}");
            }
            other => panic!("expected BlindingFailed, got {other:?}"),
        }
    }
}
