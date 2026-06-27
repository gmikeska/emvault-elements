use thiserror::Error;

use emvault_core::signer::SignerId;

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

/// Errors from [`crate::wollet::ElementsWollet`] construction and operations.
#[derive(Debug, Error)]
pub enum WolletError {
    /// The confidential descriptor could not be parsed into a
    /// `lwk_wollet::WolletDescriptor`.
    #[error("failed to parse wollet descriptor: {0}")]
    Descriptor(String),

    /// `lwk_wollet::WolletBuilder::build` failed.
    #[error("failed to build wollet: {0}")]
    Build(String),

    /// Address derivation failed for a given index/chain.
    #[error("failed to derive address: {0}")]
    AddressDerivation(String),

    /// Unblinding a confidential output failed (wrong key, malformed
    /// commitments, or an unexpected explicit/null field).
    #[error("failed to unblind output: {0}")]
    Unblind(String),
}

/// Errors from spend construction ([`crate::spend`]).
#[derive(Debug, Error)]
pub enum SpendError {
    /// LWK's `TxBuilder` failed to construct/blind the transaction (e.g.
    /// insufficient funds).
    #[error("transaction build failed: {0}")]
    Build(String),

    /// Deriving the spending descriptor for an input failed.
    #[error("descriptor derivation failed: {0}")]
    Descriptor(String),

    /// Populating an input's `witness_script` / `bip32_derivation` failed.
    #[error("input enrichment failed: {0}")]
    Enrich(String),

    /// Unblinding a confidential output (e.g. a chained fee-change output)
    /// failed.
    #[error("output unblind failed: {0}")]
    Unblind(String),

    /// The constructed PSET was rejected by the pipeline newtype.
    #[error(transparent)]
    Pset(#[from] PsetError),
}

/// Errors from the shared block-scan pipeline ([`crate::sync`]).
#[derive(Debug, Error)]
pub enum SyncError {
    /// A storage backend ([`crate::sync::BlockStore`] /
    /// [`crate::sync::WalletUtxoStore`]) returned an error.
    #[error("store error: {0}")]
    Store(String),

    /// The chain source ([`crate::sync::ElementsChainSource`]) returned an
    /// error.
    #[error("chain source error: {0}")]
    ChainSource(String),

    /// Consensus (de)serialization of a block or transaction failed.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Wallet-level error (descriptor derivation or unblinding) while scanning.
    #[error(transparent)]
    Wollet(#[from] WolletError),
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
