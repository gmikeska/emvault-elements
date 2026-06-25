//! Shared block-scan pipeline for Elements UTXO capture.
//!
//! The daemon-wallet model does not scale: one Elements node cannot host
//! hundreds of watch-only wallets, and per-wallet `scantxoutset` sweeps the
//! whole UTXO set on every call. Instead we fetch each block **once** and match
//! its outputs against the **union** of every wallet's watched scripts — one
//! scan serves all wallets.
//!
//! This module defines the **database-agnostic surface**:
//!
//! - [`CapturedUtxo`] — an unblinded, owned UTXO record.
//! - [`WalletUtxoStore`] — per-wallet UTXO persistence.
//! - [`BlockStore`] — raw block + sync-cursor persistence.
//! - [`ElementsChainSource`] — block/tx fetch + broadcast transport.
//! - [`BlockScanEngine`] — the scan/match/unblind engine (see [`scan`]).
//!
//! All traits use `&self` (mutations go through interior mutability or a shared
//! pool) so a Postgres implementation backed by a connection pool is natural.
//! Concrete persistence — e.g. the Postgres schema that stores blocks — lives
//! in the consuming application (`test-app-pkcs11`).

use elements::{
    AssetId, Block, BlockHash, OutPoint, Script, Transaction, TxOut, TxOutSecrets, Txid,
};
use lwk_wollet::Chain;

use crate::error::SyncError;

/// Re-export of LWK's keychain enum (external / internal), used by
/// [`CapturedUtxo`] so downstream crates need not depend on `lwk_wollet`.
pub use lwk_wollet::Chain as KeychainKind;

pub mod scan;

#[cfg(any(test, feature = "test-utils"))]
pub mod fakes;

#[cfg(test)]
mod tests;

pub use scan::BlockScanEngine;

/// Opaque 16-byte wallet identifier (e.g. a UUID's bytes). Keeps the library
/// free of any specific id/database crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WalletId([u8; 16]);

impl WalletId {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for WalletId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for WalletId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletId(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// An unblinded UTXO captured for a wallet by the block-scan pipeline.
///
/// Carries everything needed to spend the output later: the on-chain
/// confidential [`TxOut`] (used as `witness_utxo`) and the unblinded
/// [`TxOutSecrets`] (asset, value, and blinding factors).
#[derive(Clone, Debug, PartialEq)]
pub struct CapturedUtxo {
    /// The wallet that owns this output.
    pub wallet_id: WalletId,
    /// The outpoint (txid + vout).
    pub outpoint: OutPoint,
    /// The on-chain confidential output (serves as the PSET `witness_utxo`).
    pub txout: TxOut,
    /// The unblinded secrets (asset, value, blinding factors).
    pub secrets: TxOutSecrets,
    /// Which descriptor chain (external/receive or internal/change) matched.
    pub chain: Chain,
    /// The wildcard derivation index of the matching script.
    pub wildcard_index: u32,
    /// Block height at which this output was confirmed.
    pub height: u32,
    /// Whether the output has since been spent.
    pub is_spent: bool,
}

impl CapturedUtxo {
    /// The unblinded value in satoshis.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.secrets.value
    }

    /// The unblinded asset id.
    #[must_use]
    pub fn asset(&self) -> AssetId {
        self.secrets.asset
    }

    /// The output's script pubkey.
    #[must_use]
    pub fn script_pubkey(&self) -> &Script {
        &self.txout.script_pubkey
    }
}

/// The last block the pipeline has fully scanned and persisted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncedTip {
    /// Height of the synced tip.
    pub height: u32,
    /// Block hash at that height (used for reorg detection).
    pub hash: BlockHash,
}

/// Per-wallet UTXO persistence. Implementations must be idempotent: re-`upsert`
/// of the same outpoint updates rather than duplicates.
pub trait WalletUtxoStore {
    /// Insert or update captured UTXOs.
    fn upsert_utxos(&self, utxos: &[CapturedUtxo]) -> Result<(), SyncError>;

    /// Mark the given outpoints as spent at `spent_height` (the height of the
    /// block containing the spending transaction). The height is recorded so
    /// [`rollback_above`](Self::rollback_above) can un-spend outputs whose
    /// spend lands in an orphaned block.
    fn mark_spent(&self, outpoints: &[OutPoint], spent_height: u32) -> Result<(), SyncError>;

    /// List unspent UTXOs for one wallet.
    fn list_unspent(&self, wallet: WalletId) -> Result<Vec<CapturedUtxo>, SyncError>;

    /// All unspent outpoints across every wallet, with their owner — used by
    /// the engine to build its spend-detection index.
    fn unspent_outpoints(&self) -> Result<Vec<(OutPoint, WalletId)>, SyncError>;

    /// Reorg rollback: drop all UTXOs *captured* strictly above `height`, and
    /// un-spend any UTXO whose recorded spend height is strictly above
    /// `height`.
    fn rollback_above(&self, height: u32) -> Result<(), SyncError>;
}

/// Raw block + sync-cursor persistence. Storing blocks lets the pipeline fetch
/// each block from the node exactly once and reuse it across all wallets.
pub trait BlockStore {
    /// Persist a raw (consensus-encoded) block at the given height.
    fn store_block(&self, height: u32, hash: BlockHash, raw: &[u8]) -> Result<(), SyncError>;

    /// The last fully-scanned tip, if any.
    fn synced_tip(&self) -> Result<Option<SyncedTip>, SyncError>;

    /// Update the synced tip cursor.
    fn set_synced_tip(&self, tip: SyncedTip) -> Result<(), SyncError>;

    /// The stored block hash at `height`, if we have it.
    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SyncError>;

    /// Drop stored blocks strictly above `height` (reorg rollback).
    fn rollback_above(&self, height: u32) -> Result<(), SyncError>;
}

/// Block/transaction fetch and broadcast transport (the RPC seam). The
/// canonical implementation wraps an Elements node's JSON-RPC
/// (`ElementsRpcClient`); a mock implementation drives the engine tests.
pub trait ElementsChainSource {
    /// Current best block height.
    fn tip_height(&self) -> Result<u32, SyncError>;

    /// Block hash at the given height.
    fn block_hash(&self, height: u32) -> Result<BlockHash, SyncError>;

    /// Fetch a full block by hash.
    fn block(&self, hash: &BlockHash) -> Result<Block, SyncError>;

    /// Broadcast a finalized transaction, returning its txid.
    fn broadcast(&self, tx: &Transaction) -> Result<Txid, SyncError>;
}
