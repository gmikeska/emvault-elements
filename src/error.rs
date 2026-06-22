use thiserror::Error;

/// Errors from PSET signing operations.
#[derive(Debug, Error)]
pub enum PsetError {
    /// The signer backend (HSM, software wallet, etc.) returned an error.
    #[error("signer backend error: {0}")]
    SignerBackend(String),

    /// An Elements-specific error (PSET structure, sighash computation, etc.).
    #[error("elements error: {0}")]
    Elements(String),
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
