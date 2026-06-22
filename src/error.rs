use thiserror::Error;

use asterism_core::signer::SignerId;

/// Errors from PSET pipeline operations (signing, blinding, finalization).
#[derive(Debug, Error)]
pub enum PsetError {
    /// The signer backend (HSM, software wallet, etc.) returned an error.
    #[error("signer backend error: {0}")]
    SignerBackend(String),

    /// An Elements-specific error (PSET structure, sighash computation, etc.).
    #[error("elements error: {0}")]
    Elements(String),

    /// A PSET that was expected to have zero partial signatures had some.
    #[error("expected unsigned PSET but found {found} partial signatures")]
    UnexpectedSignatures {
        /// Number of partial signatures found.
        found: usize,
    },

    /// Attempted to sign a PSET that has not been blinded.
    #[error("PSET has not been blinded — blind before signing")]
    NotBlinded,

    /// Finalization attempted before the signature threshold was met.
    #[error("insufficient signatures: have {have}, need {need}")]
    InsufficientSignatures {
        /// Signatures collected so far.
        have: usize,
        /// Threshold required.
        need: usize,
    },

    /// PSET finalization failed.
    #[error("finalization failed: {0}")]
    FinalizationFailed(String),

    /// PSET blinding failed.
    #[error("blinding failed: {0}")]
    BlindingFailed(String),

    /// A signer referenced in a signing operation is not a member of the
    /// federation.
    #[error("unknown signer: {0}")]
    UnknownSigner(SignerId),

    /// A signed PSET was returned but contained no new partial signature
    /// attributable to the claimed signer.
    #[error("invalid signature from signer {0}: {1}")]
    InvalidSignature(SignerId, String),
}

/// Errors from confidential descriptor construction.
#[derive(Debug, Error)]
pub enum CtDescriptorError {
    /// The master blinding key is the wrong length (must be exactly 32 bytes).
    #[error("master blinding key must be exactly 32 bytes (got {0})")]
    BadBlindingKeyLength(usize),

    /// A signer with the same id was already added.
    #[error("duplicate signer key: {0}")]
    DuplicateKey(String),

    /// No signers were added before calling `build()`.
    #[error("descriptor builder has no signers")]
    NoSigners,

    /// The underlying miniscript or descriptor library rejected the inputs.
    #[error("descriptor error: {0}")]
    Descriptor(String),

    /// Network mismatch between signer xpub and the builder's target.
    #[error("network mismatch: expected {expected}, got {actual}")]
    NetworkMismatch {
        /// Expected network kind.
        expected: String,
        /// Actual network kind from the xpub.
        actual: String,
    },
}
