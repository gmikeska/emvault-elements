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
//! - [`wollet`] — [`ElementsWollet`], a client-side wallet wrapping
//!   `lwk_wollet::Wollet` for address derivation and unblinding.
//!
//! Unlike `asterism-core`, this crate is intentionally "thicker": because the
//! Elements daemon-wallet model does not scale, Elements UTXO capture is done
//! client-side here. The [`wollet`] module owns descriptor-driven derivation
//! and unblinding; the shared block-scan pipeline (forthcoming [`sync`]) drives
//! capture across all wallets. Persistence and the RPC transport remain the
//! consuming application's responsibility.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

/// Defense-in-depth validation for blinded PSETs.
pub mod confidential;
/// Confidential descriptor construction.
pub mod descriptor;
/// Error types for PSET signing and descriptor construction.
pub mod error;
/// [`ElementsFederatedWallet`] — Elements implementation of the federated wallet.
pub mod federated_wallet;
/// Elements/Liquid network types.
pub mod network;
/// PSET pipeline: blinding, signing coordination, finalization.
pub mod pset;
/// The [`ElementsSigner`] trait for PSET signing.
pub mod signer;
/// Spend-path construction: captured UTXOs → blinded, signable PSET.
pub mod spend;
/// Reusable test helpers ([`testkit::SoftwareSigner`]).
#[cfg(any(test, feature = "test-utils"))]
pub mod testkit;
/// Shared block-scan pipeline: DB-agnostic stores, chain-source transport, and
/// the [`sync::BlockScanEngine`].
pub mod sync;
/// [`ElementsWollet`] — client-side wallet (address derivation, unblinding).
pub mod wollet;

pub use confidential::validate_blinding;
pub use descriptor::{CtDescriptorBuilder, CtKeyMode};
pub use error::{CtDescriptorError, PsetError, SpendError, SyncError, WolletError};
pub use spend::{build_spend_pset, build_sweep_pset};
pub use federated_wallet::{ElementsFederatedWallet, ElementsWalletHandle};
pub use network::ElementsNetwork;
pub use sync::{
    BlockScanEngine, BlockStore, CapturedUtxo, ElementsChainSource, SyncedTip, WalletId,
    WalletUtxoStore,
};
pub use wollet::ElementsWollet;
pub use pset::{
    BlindedPset, ElementsSigningCoordinator, FinalizedPset, UnsignedPset, blind_pset,
    derive_input_secrets, explicit_txout_secrets, finalize_p2wsh_pset, slip77_blinding_key,
    unblind_input,
};
pub use signer::ElementsSigner;

/// Re-export of [`elements_miniscript`] for downstream crates that need
/// access to the confidential descriptor types or `secp256k1_zkp`.
pub use elements_miniscript;

/// Re-export of LWK's `Network` type, returned by [`ElementsNetwork::to_lwk`]
/// and [`ElementsNetwork::custom_regtest`].
pub use lwk_wollet::Network as LwkNetwork;
