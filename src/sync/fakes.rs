//! In-memory implementations of the [`sync`](crate::sync) traits, plus a
//! scripted [`MockChainSource`].
//!
//! These back the block-scan engine's unit tests (no node, no database) and
//! serve as the behavioral reference the Postgres implementations in
//! `test-app-pkcs11` must match. Gated behind `cfg(test)` or the `test-utils`
//! feature.

use std::collections::HashMap;
use std::sync::Mutex;

use elements::{Block, BlockHash, OutPoint, Transaction, Txid};

use crate::error::SyncError;

use super::{BlockStore, CapturedUtxo, ElementsChainSource, SyncedTip, WalletId, WalletUtxoStore};

/// In-memory [`WalletUtxoStore`]. Keyed by outpoint; tracks spend height for
/// reorg-correct rollback.
#[derive(Default)]
pub struct MemUtxoStore {
    inner: Mutex<HashMap<OutPoint, Entry>>,
}

struct Entry {
    utxo: CapturedUtxo,
    spent_height: Option<u32>,
}

impl MemUtxoStore {
    /// A fresh empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of records (spent and unspent) — test convenience.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Whether the store holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl WalletUtxoStore for MemUtxoStore {
    fn upsert_utxos(&self, utxos: &[CapturedUtxo]) -> Result<(), SyncError> {
        let mut map = self.inner.lock().unwrap();
        for u in utxos {
            map.entry(u.outpoint)
                .and_modify(|e| {
                    // preserve spend state on re-capture
                    e.utxo = u.clone();
                })
                .or_insert_with(|| Entry {
                    utxo: u.clone(),
                    spent_height: None,
                });
        }
        Ok(())
    }

    fn mark_spent(&self, outpoints: &[OutPoint], spent_height: u32) -> Result<(), SyncError> {
        let mut map = self.inner.lock().unwrap();
        for op in outpoints {
            if let Some(e) = map.get_mut(op) {
                e.utxo.is_spent = true;
                e.spent_height = Some(spent_height);
            }
        }
        Ok(())
    }

    fn list_unspent(&self, wallet: WalletId) -> Result<Vec<CapturedUtxo>, SyncError> {
        let map = self.inner.lock().unwrap();
        Ok(map
            .values()
            .filter(|e| !e.utxo.is_spent && e.utxo.wallet_id == wallet)
            .map(|e| e.utxo.clone())
            .collect())
    }

    fn unspent_outpoints(&self) -> Result<Vec<(OutPoint, WalletId)>, SyncError> {
        let map = self.inner.lock().unwrap();
        Ok(map
            .values()
            .filter(|e| !e.utxo.is_spent)
            .map(|e| (e.utxo.outpoint, e.utxo.wallet_id))
            .collect())
    }

    fn rollback_above(&self, height: u32) -> Result<(), SyncError> {
        let mut map = self.inner.lock().unwrap();
        // Drop UTXOs captured above the rollback height.
        map.retain(|_, e| e.utxo.height <= height);
        // Un-spend UTXOs whose spend landed in an orphaned block.
        for e in map.values_mut() {
            if e.spent_height.is_some_and(|h| h > height) {
                e.utxo.is_spent = false;
                e.spent_height = None;
            }
        }
        Ok(())
    }
}

/// In-memory [`BlockStore`].
#[derive(Default)]
pub struct MemBlockStore {
    blocks: Mutex<HashMap<u32, (BlockHash, Vec<u8>)>>,
    tip: Mutex<Option<SyncedTip>>,
}

impl MemBlockStore {
    /// A fresh empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored blocks — test convenience.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.lock().unwrap().len()
    }
}

impl BlockStore for MemBlockStore {
    fn store_block(&self, height: u32, hash: BlockHash, raw: &[u8]) -> Result<(), SyncError> {
        self.blocks
            .lock()
            .unwrap()
            .insert(height, (hash, raw.to_vec()));
        Ok(())
    }

    fn synced_tip(&self) -> Result<Option<SyncedTip>, SyncError> {
        Ok(*self.tip.lock().unwrap())
    }

    fn set_synced_tip(&self, tip: SyncedTip) -> Result<(), SyncError> {
        *self.tip.lock().unwrap() = Some(tip);
        Ok(())
    }

    fn block_hash_at(&self, height: u32) -> Result<Option<BlockHash>, SyncError> {
        Ok(self.blocks.lock().unwrap().get(&height).map(|(h, _)| *h))
    }

    fn rollback_above(&self, height: u32) -> Result<(), SyncError> {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.retain(|h, _| *h <= height);
        let mut tip = self.tip.lock().unwrap();
        if tip.is_some_and(|t| t.height > height) {
            *tip = blocks
                .iter()
                .max_by_key(|(h, _)| **h)
                .map(|(h, (hash, _))| SyncedTip {
                    height: *h,
                    hash: *hash,
                });
        }
        Ok(())
    }
}

/// A scripted [`ElementsChainSource`] backed by an in-memory chain of blocks.
///
/// Build a chain with [`MockChainSource::push_block`]; reorg by truncating with
/// [`MockChainSource::reorg_to`] and pushing a divergent suffix.
#[derive(Default)]
pub struct MockChainSource {
    /// Active chain, index = height (height 0 = genesis placeholder).
    chain: Mutex<Vec<Block>>,
    broadcast: Mutex<Vec<Transaction>>,
}

impl MockChainSource {
    /// A fresh empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a block as the new tip. Its `header.height` is expected to equal
    /// the resulting index.
    pub fn push_block(&self, block: Block) {
        self.chain.lock().unwrap().push(block);
    }

    /// Truncate the active chain so the new tip is at `height` (drops every
    /// block above it), simulating a reorg's rollback before a new suffix is
    /// pushed.
    pub fn reorg_to(&self, height: u32) {
        self.chain.lock().unwrap().truncate(height as usize + 1);
    }

    /// Transactions submitted via [`ElementsChainSource::broadcast`].
    #[must_use]
    pub fn broadcasted(&self) -> Vec<Transaction> {
        self.broadcast.lock().unwrap().clone()
    }
}

impl ElementsChainSource for MockChainSource {
    fn tip_height(&self) -> Result<u32, SyncError> {
        let chain = self.chain.lock().unwrap();
        if chain.is_empty() {
            return Err(SyncError::ChainSource("empty chain".into()));
        }
        Ok((chain.len() - 1) as u32)
    }

    fn block_hash(&self, height: u32) -> Result<BlockHash, SyncError> {
        let chain = self.chain.lock().unwrap();
        chain
            .get(height as usize)
            .map(Block::block_hash)
            .ok_or_else(|| SyncError::ChainSource(format!("no block at height {height}")))
    }

    fn block(&self, hash: &BlockHash) -> Result<Block, SyncError> {
        let chain = self.chain.lock().unwrap();
        chain
            .iter()
            .find(|b| b.block_hash() == *hash)
            .cloned()
            .ok_or_else(|| SyncError::ChainSource(format!("no block with hash {hash}")))
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, SyncError> {
        let txid = tx.txid();
        self.broadcast.lock().unwrap().push(tx.clone());
        Ok(txid)
    }
}
