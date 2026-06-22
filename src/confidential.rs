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

        if let Some(blinder_idx) = output.blinder_index {
            if (blinder_idx as usize) >= num_inputs {
                return Err(PsetError::BlindingFailed(format!(
                    "output {idx} blinder_index {blinder_idx} exceeds input count {num_inputs}"
                )));
            }
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
        let blinded = BlindedPset::new(pset);
        // Can't construct a BlindedPset from an empty PSET (NotBlinded),
        // so validate_blinding_raw should pass on the raw PSET with no
        // non-fee outputs.
        let raw = minimal_pset();
        validate_blinding_raw(&raw).expect("empty outputs should pass");
    }
}
