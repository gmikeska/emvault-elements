//! Nodeless (descriptor-private) Elements chain backends.
//!
//! A peer to the block-scan pipeline ([`crate::sync`]): instead of pulling every
//! block from an Elements node and matching it against the union of watched
//! scripts, this drives LWK's address/scripthash **blockchain clients**
//! ([`lwk_wollet::ElectrumClient`], [`lwk_wollet::blocking::EsploraClient`],
//! and the Esplora *Waterfalls* descriptor endpoint). LWK performs the
//! scripthash scan, the confidential **unblinding**, and the internal reorg
//! reconciliation against the wallet's [`lwk_wollet::Wollet`]; this module
//! projects LWK's authoritative post-scan UTXO set back into the crate's own
//! [`CapturedUtxo`] / [`WalletUtxoStore`] currency so the spend, PSET, and
//! migration paths are byte-for-byte identical regardless of backend.
//!
//! # Reorg handling
//!
//! LWK reconciles reorgs *inside* `apply_update`, but it exposes only a single
//! tip. To emit an explicit rollback height — parity with the RPC path's
//! `SyncResult.reorg_to` and the Bitcoin `emvault-electrum` crate's
//! checkpoint-hash comparison — this module keeps a **thin sparse checkpoint
//! map** ([`CheckpointStore`]) of `(height, hash)` synced tips. Each sync walks
//! the stored checkpoints from the highest down and re-queries the backend's
//! header at each height; the highest checkpoint whose hash still matches the
//! chain is the common ancestor. Anything above it was reorged out, so the
//! caller's [`WalletUtxoStore::rollback_above`] is invoked before the
//! authoritative upsert.
//!
//! # Blinding-key note
//!
//! All emvault Elements descriptors are `ct(slip77(..), ..)` (see
//! [`crate::descriptor::CtDescriptorBuilder`]). LWK only refuses Waterfalls for
//! `elip151` deterministic blinding (which would reveal the blinding key to the
//! server); because emvault never emits `elip151`, Waterfalls is always
//! compatible here and no runtime guard is required.

use std::collections::HashMap;
use std::str::FromStr;

use elements::{BlockHash, OutPoint, Transaction, Txid};
use lwk_wollet::blocking::BlockchainBackend;

use crate::error::SyncError;
use crate::sync::{CapturedUtxo, SyncedTip, WalletId, WalletUtxoStore};
use crate::wollet::ElementsWollet;

/// Persistence for the sparse reorg-detection checkpoint map.
///
/// Implementations store a small set of `(height, hash)` synced-tip
/// checkpoints. The set may be pruned aggressively — only enough depth to cover
/// the deepest reorg worth detecting is needed (Liquid's federated chain barely
/// reorgs; regtest reorgs in tests are shallow).
pub trait CheckpointStore {
    /// All stored checkpoints, in any order.
    fn load(&self) -> Result<Vec<SyncedTip>, SyncError>;

    /// Persist (insert or replace) a checkpoint for its height.
    fn save(&self, tip: SyncedTip) -> Result<(), SyncError>;

    /// Drop checkpoints strictly above `height` (reorg rollback).
    fn rollback_above(&self, height: u32) -> Result<(), SyncError>;
}

/// Outcome of a nodeless [`NodelessSync::sync`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodelessSyncOutcome {
    /// The wallet's chain tip after applying the scan update.
    pub tip: SyncedTip,
    /// Number of unspent UTXOs upserted (the authoritative current set).
    pub upserted: usize,
    /// Number of outpoints that left the unspent set this sync (spent).
    pub spent: usize,
    /// Common-ancestor height a reorg was reconciled down to, if any. `None` on
    /// a normal forward sync. Mirrors the RPC path's `SyncResult.reorg_to`.
    pub reorg_to: Option<u32>,
}

/// A nodeless chain backend over any LWK [`BlockchainBackend`] (Electrum,
/// Esplora, or Waterfalls). Construct via [`NodelessSync::new_electrum`],
/// [`NodelessSync::new_esplora`], or [`NodelessSync::new_waterfalls`].
pub struct NodelessSync<B: BlockchainBackend> {
    client: B,
    wallet_id: WalletId,
}

impl<B: BlockchainBackend> NodelessSync<B> {
    /// Wrap an already-constructed LWK client.
    pub fn from_client(client: B, wallet_id: WalletId) -> Self {
        Self { client, wallet_id }
    }

    /// Scan, reconcile reorgs, and project LWK's authoritative UTXO set into the
    /// caller's stores.
    ///
    /// Steps: (1) `full_scan` + `apply_update` (LWK unblinds and reconciles
    /// internally); (2) read the new tip; (3) checkpoint-compare to find any
    /// reorg common ancestor; (4) on reorg, `rollback_above` both stores; (5)
    /// upsert the authoritative unspent set; (6) mark outpoints that left the
    /// unspent set as spent; (7) persist the new checkpoint.
    ///
    /// # Errors
    ///
    /// [`SyncError::Backend`] on client/LWK failures, or the store's error on
    /// persistence failures.
    pub fn sync(
        &mut self,
        wollet: &mut ElementsWollet,
        utxos: &dyn WalletUtxoStore,
        checkpoints: &dyn CheckpointStore,
    ) -> Result<NodelessSyncOutcome, SyncError> {
        // 1. Scan + apply. LWK reconciles reorgs into the wollet's own state.
        if let Some(update) = self
            .client
            .full_scan(wollet.inner())
            .map_err(|e| SyncError::Backend(e.to_string()))?
        {
            wollet
                .inner_mut()
                .apply_update(update)
                .map_err(|e| SyncError::Backend(e.to_string()))?;
        }

        // 2. New tip.
        let tip = wollet.inner().tip();
        let new_tip = SyncedTip {
            height: tip.height(),
            hash: tip.hash(),
        };

        // 3. Reorg detection via checkpoint-compare.
        let stored = checkpoints.load()?;
        let reorg_to = self.resolve_reorg(&stored, new_tip.height)?;

        // 4. On reorg, purge above the common ancestor so the authoritative
        //    upsert below reflects post-reorg truth.
        if let Some(h) = reorg_to {
            utxos.rollback_above(h)?;
            checkpoints.rollback_above(h)?;
        }

        // 5. Project LWK's authoritative unspent set and upsert.
        let prev_unspent: std::collections::HashSet<OutPoint> = utxos
            .list_unspent(self.wallet_id)?
            .into_iter()
            .map(|u| u.outpoint)
            .collect();
        let current = self.project_unspent(wollet)?;
        let current_set: std::collections::HashSet<OutPoint> =
            current.iter().map(|u| u.outpoint).collect();
        utxos.upsert_utxos(&current)?;

        // 6. Anything that left the unspent set (and was not already purged as
        //    reorged-out in step 4) has been spent.
        let disappeared: Vec<OutPoint> = prev_unspent.difference(&current_set).copied().collect();
        if !disappeared.is_empty() {
            utxos.mark_spent(&disappeared, new_tip.height)?;
        }

        // 7. Persist the new checkpoint.
        checkpoints.save(new_tip)?;

        Ok(NodelessSyncOutcome {
            tip: new_tip,
            upserted: current.len(),
            spent: disappeared.len(),
            reorg_to,
        })
    }

    /// Broadcast a finalized transaction.
    ///
    /// # Errors
    ///
    /// [`SyncError::Backend`] if the client rejects the broadcast.
    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, SyncError> {
        self.client
            .broadcast(tx)
            .map_err(|e| SyncError::Backend(e.to_string()))
    }

    /// Project LWK's unspent [`WalletTxOut`](lwk_wollet::WalletTxOut) set into
    /// [`CapturedUtxo`]. The confidential `TxOut` (PSET `witness_utxo`) is
    /// recovered from the wallet's cached transaction; unconfirmed outputs
    /// (mempool) are recorded at height `0`, matching LWK's height convention.
    fn project_unspent(&self, wollet: &ElementsWollet) -> Result<Vec<CapturedUtxo>, SyncError> {
        let w = wollet.inner();
        let unspent = w.utxos().map_err(|e| SyncError::Backend(e.to_string()))?;
        let mut out = Vec::with_capacity(unspent.len());
        for u in unspent {
            let wtx = w
                .transaction(&u.outpoint.txid)
                .map_err(|e| SyncError::Backend(e.to_string()))?
                .ok_or_else(|| {
                    SyncError::Backend(format!("cached tx {} missing for utxo", u.outpoint.txid))
                })?;
            let txout = wtx
                .tx
                .output
                .get(u.outpoint.vout as usize)
                .ok_or_else(|| {
                    SyncError::Backend(format!(
                        "vout {} out of range for tx {}",
                        u.outpoint.vout, u.outpoint.txid
                    ))
                })?
                .clone();
            out.push(CapturedUtxo {
                wallet_id: self.wallet_id,
                outpoint: u.outpoint,
                txout,
                secrets: u.unblinded,
                chain: u.ext_int,
                wildcard_index: u.wildcard_index,
                height: u.height.unwrap_or(0),
                is_spent: false,
            });
        }
        Ok(out)
    }

    /// Checkpoint-compare reorg detection: walk stored checkpoints highest-first
    /// and re-query the backend header at each height. The highest checkpoint
    /// whose hash still matches the chain is the common ancestor; a reorg is
    /// signalled iff some checkpoint at or below the new tip no longer matches
    /// (or lies above the new tip because the chain shrank).
    fn resolve_reorg(
        &self,
        stored: &[SyncedTip],
        new_height: u32,
    ) -> Result<Option<u32>, SyncError> {
        resolve_reorg_with(stored, new_height, |h| self.header_hash_at(h))
    }

    fn header_hash_at(&self, height: u32) -> Result<BlockHash, SyncError> {
        let headers = self
            .client
            .get_headers(&[height], &HashMap::new())
            .map_err(|e| SyncError::Backend(e.to_string()))?;
        headers
            .first()
            .map(elements::BlockHeader::block_hash)
            .ok_or_else(|| SyncError::Backend(format!("no header at height {height}")))
    }
}

/// Pure core of [`NodelessSync::resolve_reorg`], factored out so it can be unit
/// tested without a live backend. `chain_hash_at(height)` returns the chain's
/// current block hash at `height`.
///
/// Returns `Some(common_ancestor_height)` when a reorg is detected (roll back
/// everything strictly above it), or `None` on a clean forward extension.
fn resolve_reorg_with(
    stored: &[SyncedTip],
    new_height: u32,
    mut chain_hash_at: impl FnMut(u32) -> Result<BlockHash, SyncError>,
) -> Result<Option<u32>, SyncError> {
    if stored.is_empty() {
        return Ok(None);
    }
    // Highest height first.
    let mut cps: Vec<&SyncedTip> = stored.iter().collect();
    cps.sort_by_key(|c| std::cmp::Reverse(c.height));

    let mut saw_mismatch = false;
    for cp in &cps {
        if cp.height > new_height {
            // Chain no longer reaches this checkpoint — it was reorged out.
            saw_mismatch = true;
            continue;
        }
        let chain_hash = chain_hash_at(cp.height)?;
        if chain_hash == cp.hash {
            // Common ancestor. If nothing above it mismatched, it's a clean
            // extension; otherwise roll back to exactly this height.
            return Ok(if saw_mismatch { Some(cp.height) } else { None });
        }
        saw_mismatch = true;
    }

    // No stored checkpoint still matches: the reorg is deeper than our oldest
    // checkpoint. Roll back conservatively to just below the oldest one.
    let oldest = cps.last().map_or(0, |c| c.height.saturating_sub(1));
    Ok(Some(oldest))
}

#[cfg(feature = "electrum")]
impl NodelessSync<lwk_wollet::ElectrumClient> {
    /// Connect to an Electrum server (`tcp://host:port` or `ssl://host:port`).
    ///
    /// # Errors
    ///
    /// [`SyncError::Backend`] if the URL is malformed or the connection fails.
    pub fn new_electrum(url: &str, wallet_id: WalletId) -> Result<Self, SyncError> {
        let electrum_url = lwk_wollet::ElectrumUrl::from_str(url)
            .map_err(|e| SyncError::Backend(format!("invalid electrum url `{url}`: {e}")))?;
        let client = lwk_wollet::ElectrumClient::new(&electrum_url)
            .map_err(|e| SyncError::Backend(e.to_string()))?;
        Ok(Self::from_client(client, wallet_id))
    }
}

#[cfg(feature = "esplora")]
impl NodelessSync<lwk_wollet::blocking::EsploraClient> {
    /// Connect to an Esplora REST endpoint (plain address-scan mode).
    ///
    /// # Errors
    ///
    /// [`SyncError::Backend`] if the client cannot be constructed.
    pub fn new_esplora(
        url: &str,
        network: lwk_wollet::Network,
        wallet_id: WalletId,
    ) -> Result<Self, SyncError> {
        let client = lwk_wollet::blocking::EsploraClient::new(url, network)
            .map_err(|e| SyncError::Backend(e.to_string()))?;
        Ok(Self::from_client(client, wallet_id))
    }

    /// Connect to an Esplora endpoint that supports the **Waterfalls**
    /// descriptor route (one query per descriptor). Always compatible with
    /// emvault's `slip77` confidential descriptors.
    ///
    /// # Errors
    ///
    /// [`SyncError::Backend`] if the client cannot be constructed.
    pub fn new_waterfalls(
        url: &str,
        network: lwk_wollet::Network,
        wallet_id: WalletId,
    ) -> Result<Self, SyncError> {
        let client = lwk_wollet::blocking::EsploraClient::new_waterfalls(url, network)
            .map_err(|e| SyncError::Backend(e.to_string()))?;
        Ok(Self::from_client(client, wallet_id))
    }
}

/// In-memory [`CheckpointStore`] for tests and small single-process consumers.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Default)]
pub struct MemCheckpointStore {
    inner: std::sync::Mutex<std::collections::BTreeMap<u32, BlockHash>>,
}

#[cfg(any(test, feature = "test-utils"))]
impl CheckpointStore for MemCheckpointStore {
    fn load(&self) -> Result<Vec<SyncedTip>, SyncError> {
        let map = self.inner.lock().expect("checkpoint mutex");
        Ok(map
            .iter()
            .map(|(&height, &hash)| SyncedTip { height, hash })
            .collect())
    }

    fn save(&self, tip: SyncedTip) -> Result<(), SyncError> {
        self.inner
            .lock()
            .expect("checkpoint mutex")
            .insert(tip.height, tip.hash);
        Ok(())
    }

    fn rollback_above(&self, height: u32) -> Result<(), SyncError> {
        self.inner
            .lock()
            .expect("checkpoint mutex")
            .retain(|&h, _| h <= height);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::hashes::Hash;

    fn hash(byte: u8) -> BlockHash {
        BlockHash::from_byte_array([byte; 32])
    }

    fn tip(height: u32, byte: u8) -> SyncedTip {
        SyncedTip {
            height,
            hash: hash(byte),
        }
    }

    #[test]
    fn no_checkpoints_is_not_a_reorg() {
        let got = resolve_reorg_with(&[], 100, |_| unreachable!()).unwrap();
        assert_eq!(got, None);
    }

    #[test]
    fn matching_tip_is_clean_extension() {
        let stored = vec![tip(90, 0x90), tip(100, 0xaa)];
        // Chain still has our hashes at those heights; tip advanced to 110.
        let got = resolve_reorg_with(&stored, 110, |h| {
            Ok(match h {
                100 => hash(0xaa),
                90 => hash(0x90),
                _ => hash(0xff),
            })
        })
        .unwrap();
        assert_eq!(got, None, "no hash changed -> no reorg");
    }

    #[test]
    fn changed_tip_hash_reorgs_to_lower_matching_checkpoint() {
        let stored = vec![tip(90, 0x90), tip(100, 0xaa)];
        // Height 100's hash changed; height 90 still matches -> ancestor = 90.
        let got = resolve_reorg_with(&stored, 100, |h| {
            Ok(match h {
                100 => hash(0xbb), // reorged
                90 => hash(0x90),  // intact
                _ => hash(0xff),
            })
        })
        .unwrap();
        assert_eq!(got, Some(90));
    }

    #[test]
    fn chain_shrank_below_checkpoint_is_a_reorg() {
        let stored = vec![tip(90, 0x90), tip(100, 0xaa)];
        // New tip is 95: checkpoint 100 is above it (gone); 90 still matches.
        let got = resolve_reorg_with(&stored, 95, |h| {
            Ok(match h {
                90 => hash(0x90),
                _ => hash(0xff),
            })
        })
        .unwrap();
        assert_eq!(got, Some(90));
    }

    #[test]
    fn reorg_deeper_than_all_checkpoints_rolls_back_below_oldest() {
        let stored = vec![tip(90, 0x90), tip(100, 0xaa)];
        // Nothing matches -> roll back to oldest_height - 1 = 89.
        let got = resolve_reorg_with(&stored, 100, |_| Ok(hash(0xff))).unwrap();
        assert_eq!(got, Some(89));
    }
}
