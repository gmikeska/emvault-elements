use elements::pset::PartiallySignedTransaction as Pset;

use crate::error::PsetError;

/// Trait for signers that can produce ECDSA partial signatures over Elements
/// PSET inputs.
///
/// This mirrors `bdk_wallet::signer::TransactionSigner` for the Elements
/// pipeline. The HSM doesn't see confidential transaction data — blinding,
/// range proofs, and surjection proofs stay software-side via LWK. The HSM
/// only computes ECDSA on a sighash, identical to the Bitcoin path.
pub trait ElementsSigner: Send + Sync {
    /// Sign all inputs in `pset` that belong to this signer.
    ///
    /// Returns the number of inputs that were signed. The implementation
    /// must insert partial signatures into the PSET's `partial_sigs` map
    /// for each input it signs.
    ///
    /// # Errors
    ///
    /// Returns [`PsetError`] if the signer backend fails or the PSET
    /// structure is invalid.
    fn sign_pset(&self, pset: &mut Pset) -> Result<usize, PsetError>;
}
