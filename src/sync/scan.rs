//! [`BlockScanEngine`] — the scalable core of Elements UTXO capture.
//!
//! Registers every wallet's watched scripts into a single index, then walks the
//! chain **once**, matching each block's outputs against that index. One scan
//! serves all wallets, which is what makes hundreds of wallets viable.

use std::collections::HashMap;

use elements::{OutPoint, Script};
use lwk_wollet::Chain;

use crate::error::SyncError;
use crate::wollet::ElementsWollet;

use super::{BlockStore, CapturedUtxo, ElementsChainSource, SyncedTip, WalletId, WalletUtxoStore};

/// Summary of one [`BlockScanEngine::sync`] pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// Number of blocks scanned (and stored) this pass.
    pub blocks_scanned: u32,
    /// Number of UTXOs captured this pass.
    pub utxos_captured: usize,
    /// Number of UTXOs marked spent this pass.
    pub utxos_spent: usize,
    /// Outputs that matched a watched script but could not be unblinded (e.g.
    /// confidential outputs blinded with a key we don't hold — legacy/foreign).
    /// These are skipped, not captured.
    pub skipped_unblindable: usize,
    /// The height of the common ancestor a reorg rolled back to, if any.
    pub reorg_to: Option<u32>,
}

/// Scans blocks for outputs belonging to a set of registered wallets.
///
/// Borrows the [`ElementsWollet`]s for the lifetime `'w` so it can unblind
/// matched outputs; build it fresh each sync pass (cheap) so newly-revealed
/// addresses are picked up via an extended gap.
pub struct BlockScanEngine<'w> {
    /// `script_pubkey` -> the wallet/chain/index + which registered wollet owns
    /// it (so the right blinding key is used to unblind).
    index: HashMap<Script, ScriptEntry>,
    /// Registered wollets, indexed by [`ScriptEntry::wollet_idx`]. A single
    /// `WalletId` may register multiple wollets (one per federation version,
    /// each with its own descriptor and possibly its own blinding key).
    wollets: Vec<&'w ElementsWollet>,
}

#[derive(Clone, Copy)]
struct ScriptEntry {
    wallet_id: WalletId,
    chain: Chain,
    wildcard_index: u32,
    wollet_idx: usize,
}

impl<'w> BlockScanEngine<'w> {
    /// A fresh engine with no registered wallets.
    #[must_use]
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            wollets: Vec::new(),
        }
    }

    /// Register a wallet (or one federation version of it) under `id` and index
    /// its external + internal scripts for indices `0..gap`. May be called
    /// multiple times with the same `id` to watch several federation versions.
    ///
    /// # Errors
    ///
    /// Propagates [`SyncError::Wollet`] if address derivation fails.
    pub fn register_wallet(
        &mut self,
        id: WalletId,
        wollet: &'w ElementsWollet,
        gap: u32,
    ) -> Result<(), SyncError> {
        let wollet_idx = self.wollets.len();
        self.wollets.push(wollet);
        for (spk, chain, widx) in wollet.watched_scripts(gap)? {
            self.index.insert(
                spk,
                ScriptEntry {
                    wallet_id: id,
                    chain,
                    wildcard_index: widx,
                    wollet_idx,
                },
            );
        }
        Ok(())
    }

    /// Number of indexed scripts across all wallets (test/diagnostic).
    #[must_use]
    pub fn indexed_script_count(&self) -> usize {
        self.index.len()
    }

    /// Run one sync pass: detect reorgs, then scan, store, and attribute every
    /// block from the last synced tip up to the chain tip.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError`] from the chain source, stores, or unblinding.
    pub fn sync<CS, BS, US>(
        &self,
        chain: &CS,
        blocks: &BS,
        utxos: &US,
    ) -> Result<SyncSummary, SyncError>
    where
        CS: ElementsChainSource,
        BS: BlockStore,
        US: WalletUtxoStore,
    {
        let tip = chain.tip_height()?;
        let mut summary = SyncSummary::default();

        // --- determine the start height, handling reorgs --------------------
        let mut start = match blocks.synced_tip()? {
            None => 0,
            Some(t) => {
                if chain.block_hash(t.height)? == t.hash {
                    t.height + 1
                } else {
                    let ancestor = Self::find_common_ancestor(chain, blocks, t.height)?;
                    blocks.rollback_above(ancestor)?;
                    utxos.rollback_above(ancestor)?;
                    summary.reorg_to = Some(ancestor);
                    ancestor + 1
                }
            }
        };
        if start > tip + 1 {
            // Stored tip is ahead of the node (deep reorg already rolled back
            // to genesis is impossible here); clamp defensively.
            start = tip + 1;
        }

        // --- build the spend-detection index from current unspent set -------
        let mut spend_index: HashMap<OutPoint, WalletId> =
            utxos.unspent_outpoints()?.into_iter().collect();

        // --- scan each new block --------------------------------------------
        for h in start..=tip {
            let hash = chain.block_hash(h)?;
            let block = chain.block(&hash)?;
            let raw = elements::encode::serialize(&block);
            blocks.store_block(h, hash, &raw)?;

            let mut captured: Vec<CapturedUtxo> = Vec::new();
            let mut spent: Vec<OutPoint> = Vec::new();

            for tx in &block.txdata {
                let txid = tx.txid();

                // inputs: detect spends of our known outputs
                for input in &tx.input {
                    let prevout = input.previous_output;
                    if spend_index.remove(&prevout).is_some() {
                        spent.push(prevout);
                    }
                }

                // outputs: match against the script index
                for (vout, txout) in tx.output.iter().enumerate() {
                    let spk = &txout.script_pubkey;
                    if let Some(entry) = self.index.get(spk).copied() {
                        let wollet = self.wollets[entry.wollet_idx];
                        // An output may match a watched script yet be blinded
                        // with a key we don't hold (legacy/foreign change). We
                        // can't spend it, so skip rather than aborting the scan.
                        let Ok(secrets) = wollet.unblind(txout) else {
                            summary.skipped_unblindable += 1;
                            continue;
                        };
                        let vout = u32::try_from(vout).expect("vout fits in u32");
                        let outpoint = OutPoint::new(txid, vout);
                        captured.push(CapturedUtxo {
                            wallet_id: entry.wallet_id,
                            outpoint,
                            txout: txout.clone(),
                            secrets,
                            chain: entry.chain,
                            wildcard_index: entry.wildcard_index,
                            height: h,
                            is_spent: false,
                        });
                        // a later tx in this same block may spend it
                        spend_index.insert(outpoint, entry.wallet_id);
                    }
                }
            }

            if !captured.is_empty() {
                summary.utxos_captured += captured.len();
                utxos.upsert_utxos(&captured)?;
            }
            if !spent.is_empty() {
                summary.utxos_spent += spent.len();
                utxos.mark_spent(&spent, h)?;
            }
            summary.blocks_scanned += 1;
        }

        // --- advance the cursor ---------------------------------------------
        if tip + 1 >= start {
            let tip_hash = chain.block_hash(tip)?;
            blocks.set_synced_tip(SyncedTip {
                height: tip,
                hash: tip_hash,
            })?;
        }

        Ok(summary)
    }

    /// Walk back from `from` to the highest height where the node's block hash
    /// matches the one we stored — the common ancestor of the reorg.
    fn find_common_ancestor<CS, BS>(chain: &CS, blocks: &BS, from: u32) -> Result<u32, SyncError>
    where
        CS: ElementsChainSource,
        BS: BlockStore,
    {
        let mut h = from;
        loop {
            match blocks.block_hash_at(h)? {
                Some(stored) if stored == chain.block_hash(h)? => return Ok(h),
                _ => {
                    if h == 0 {
                        return Ok(0);
                    }
                    h -= 1;
                }
            }
        }
    }
}

impl Default for BlockScanEngine<'_> {
    fn default() -> Self {
        Self::new()
    }
}
