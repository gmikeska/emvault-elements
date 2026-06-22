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
//! - [`error`] — error types for PSET signing and descriptor construction.
//!
//! The crate does not perform wallet management, chain sync, or transaction
//! broadcast — those responsibilities belong to the consuming application
//! (typically via `lwk_wollet`).

#![warn(missing_docs)]
#![forbid(unsafe_code)]

/// Confidential descriptor construction.
pub mod descriptor;
/// Error types for PSET signing and descriptor construction.
pub mod error;
/// Elements/Liquid network types.
pub mod network;
/// The [`ElementsSigner`] trait for PSET signing.
pub mod signer;

pub use descriptor::{CtDescriptorBuilder, CtKeyMode};
pub use error::{CtDescriptorError, PsetError};
pub use network::ElementsNetwork;
pub use signer::ElementsSigner;

/// Re-export of [`elements_miniscript`] for downstream crates that need
/// access to the confidential descriptor types or `secp256k1_zkp`.
pub use elements_miniscript;
