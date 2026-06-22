//! # asterism-elements
//!
//! Elements/Liquid support for the Emerald multi-signature custody platform.
//!
//! This companion crate to [`asterism-core`] provides:
//!
//! - [`ElementsNetwork`] — network enum with LWK and address parameters.
//! - [`CtDescriptorBuilder`] — builds `ct(slip77(...), elwsh(sortedmulti(...)))`
//!   confidential descriptors from [`asterism_core::Signer`] instances.
//! - [`ElementsSigner`] — trait for signers that can produce ECDSA partial
//!   signatures over Elements PSET inputs.
//! - [`pset`] — PSET pipeline: blinding, signing coordination, and
//!   finalization (mirrors [`asterism_core::psbt`] with an Elements-specific
//!   blinding stage).
//! - [`error`] — error types for PSET signing and descriptor construction.
//!
//! The crate does not perform wallet management, chain sync, or transaction
//! broadcast — those responsibilities belong to the consuming application.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// Defense-in-depth validation for blinded PSETs.
pub mod confidential;
/// Confidential descriptor construction.
pub mod descriptor;
/// Error types for PSET signing and descriptor construction.
pub mod error;
/// Elements/Liquid network types.
pub mod network;
/// PSET pipeline: blinding, signing coordination, finalization.
pub mod pset;
/// The [`ElementsSigner`] trait for PSET signing.
pub mod signer;

pub use descriptor::{CtDescriptorBuilder, CtKeyMode};
pub use error::{CtDescriptorError, PsetError};
pub use confidential::validate_blinding;
pub use pset::{
    BlindedPset, ElementsSigningCoordinator, FinalizedPset, UnsignedPset, blind_pset,
    derive_input_secrets, explicit_txout_secrets, finalize_p2wsh_pset, slip77_blinding_key,
    unblind_input,
};
pub use network::ElementsNetwork;
pub use signer::ElementsSigner;

/// Re-export of [`elements_miniscript`] for downstream crates that need
/// access to the confidential descriptor types or `secp256k1_zkp`.
pub use elements_miniscript;
