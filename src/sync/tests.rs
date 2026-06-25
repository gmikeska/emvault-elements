//! P3 (store-contract) and P4 (engine) tests for the block-scan pipeline.
//!
//! All tests run against the in-memory [`fakes`](super::fakes) — no node, no
//! database. Outputs are **explicit** (unconfidential) so `unblind` exercises
//! the explicit branch without constructing rangeproofs; the confidential
//! blinding-key path is covered separately by the `wollet` module tests.

use std::str::FromStr;

use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash;
use elements::{
    AssetId, AssetIssuance, Block, BlockExtData as ExtData, BlockHash, BlockHeader, LockTime,
    OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness, TxMerkleNode, TxOut, TxOutSecrets,
    TxOutWitness,
};

use crate::ElementsWalletHandle;
use crate::descriptor::{CtDescriptorBuilder, CtKeyMode};
use crate::network::ElementsNetwork;
use crate::wollet::ElementsWollet;
use asterism_core::signer::Signer;
use asterism_core::test_utils::MockSigner;
use bitcoin::Network;
use lwk_wollet::Chain;

use super::fakes::{MemBlockStore, MemUtxoStore, MockChainSource};
use super::{
    BlockScanEngine, BlockStore, CapturedUtxo, ElementsChainSource, SyncedTip, WalletId,
    WalletUtxoStore,
};

// ---------------------------------------------------------------------------
// testkit
// ---------------------------------------------------------------------------

fn test_asset() -> AssetId {
    AssetId::from_str("0202020202020202020202020202020202020202020202020202020202020202").unwrap()
}

fn wid(n: u8) -> WalletId {
    let mut b = [0u8; 16];
    b[0] = n;
    WalletId::from_bytes(b)
}

/// A 2-of-3 ranged wallet seeded deterministically.
fn make_wollet(signer_seeds: [u8; 3], blinding: u8) -> ElementsWollet {
    let mut builder = CtDescriptorBuilder::new(2, &[blinding; 32])
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in signer_seeds
        .iter()
        .map(|&s| MockSigner::with_seed(u64::from(s), Network::Regtest))
    {
        builder.add_signer(&s as &dyn Signer).unwrap();
    }
    let desc = builder.build().unwrap();
    let handle = ElementsWalletHandle::new(desc, [blinding; 32]);
    ElementsWollet::from_handle(&handle, ElementsNetwork::ElementsRegtest).unwrap()
}

/// An explicit (unconfidential) output to `spk`.
fn explicit_txout(spk: Script, value: u64) -> TxOut {
    TxOut {
        asset: Asset::Explicit(test_asset()),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey: spk,
        witness: TxOutWitness::default(),
    }
}

/// A transaction with a unique input (so its txid varies by `nonce`) paying the
/// given `(script, value)` outputs.
fn tx_paying(nonce: u8, outs: Vec<(Script, u64)>) -> Transaction {
    let mut prevout = OutPoint::null();
    prevout.vout = u32::from(nonce); // make the input (and thus txid) unique
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            is_pegin: false,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            asset_issuance: AssetIssuance::default(),
            witness: TxInWitness::default(),
        }],
        output: outs
            .into_iter()
            .map(|(s, v)| explicit_txout(s, v))
            .collect(),
    }
}

/// A transaction spending `inputs`, paying `outs`.
fn tx_spending(inputs: Vec<OutPoint>, outs: Vec<(Script, u64)>) -> Transaction {
    Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: inputs
            .into_iter()
            .map(|op| TxIn {
                previous_output: op,
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: AssetIssuance::default(),
                witness: TxInWitness::default(),
            })
            .collect(),
        output: outs
            .into_iter()
            .map(|(s, v)| explicit_txout(s, v))
            .collect(),
    }
}

/// Build a block at `height`; `salt` perturbs the header so divergent blocks at
/// the same height get distinct hashes (for reorg tests).
fn block_at(height: u32, prev: BlockHash, txs: Vec<Transaction>, salt: u32) -> Block {
    Block {
        header: BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_700_000_000 + salt,
            height,
            ext: ExtData::Proof {
                challenge: Script::new(),
                solution: Script::new(),
            },
        },
        txdata: txs,
    }
}

/// Push a linear chain of blocks onto `chain`, returning the tip hash. `genesis`
/// is height 0 with no relevant txs.
fn build_chain(chain: &MockChainSource, blocks: Vec<Vec<Transaction>>) -> Vec<BlockHash> {
    let mut prev = BlockHash::all_zeros();
    let mut hashes = vec![];
    for (height, txs) in blocks.into_iter().enumerate() {
        let b = block_at(u32::try_from(height).expect("height fits u32"), prev, txs, 0);
        prev = b.block_hash();
        hashes.push(prev);
        chain.push_block(b);
    }
    hashes
}

fn captured(wallet: WalletId, height: u32, value: u64, salt: u8) -> CapturedUtxo {
    let mut outpoint = OutPoint::null();
    outpoint.vout = u32::from(salt);
    CapturedUtxo {
        wallet_id: wallet,
        outpoint,
        txout: explicit_txout(Script::new(), value),
        secrets: TxOutSecrets::new(
            test_asset(),
            AssetBlindingFactor::zero(),
            value,
            ValueBlindingFactor::zero(),
        ),
        chain: Chain::External,
        wildcard_index: 0,
        height,
        is_spent: false,
    }
}

// ---------------------------------------------------------------------------
// P3 — store contract tests (the fakes honor the trait contracts)
// ---------------------------------------------------------------------------

#[test]
fn mem_utxo_store_upsert_then_list() {
    let store = MemUtxoStore::new();
    let w = wid(1);
    store
        .upsert_utxos(&[captured(w, 1, 100, 0), captured(w, 1, 200, 1)])
        .unwrap();
    // idempotent: re-upsert same outpoints doesn't duplicate
    store.upsert_utxos(&[captured(w, 1, 100, 0)]).unwrap();

    let mut vals: Vec<u64> = store
        .list_unspent(w)
        .unwrap()
        .iter()
        .map(CapturedUtxo::value)
        .collect();
    vals.sort_unstable();
    assert_eq!(vals, vec![100, 200]);
    assert_eq!(store.len(), 2);
}

#[test]
fn mem_utxo_store_mark_spent_excludes() {
    let store = MemUtxoStore::new();
    let w = wid(1);
    let u = captured(w, 1, 100, 0);
    let op = u.outpoint;
    store.upsert_utxos(&[u]).unwrap();
    store.mark_spent(&[op], 2).unwrap();
    assert!(store.list_unspent(w).unwrap().is_empty());
    assert!(store.unspent_outpoints().unwrap().is_empty());
}

#[test]
fn mem_utxo_store_unspent_outpoints_across_wallets() {
    let store = MemUtxoStore::new();
    store.upsert_utxos(&[captured(wid(1), 1, 10, 0)]).unwrap();
    store.upsert_utxos(&[captured(wid(2), 1, 20, 1)]).unwrap();
    let ops = store.unspent_outpoints().unwrap();
    assert_eq!(ops.len(), 2);
    let owners: std::collections::HashSet<_> = ops.iter().map(|(_, w)| *w).collect();
    assert_eq!(owners.len(), 2);
}

#[test]
fn mem_utxo_store_rollback_drops_and_unspends() {
    let store = MemUtxoStore::new();
    let w = wid(1);
    let low = captured(w, 5, 100, 0); // captured at height 5
    let low_op = low.outpoint;
    let high = captured(w, 9, 200, 1); // captured at height 9
    store.upsert_utxos(&[low, high]).unwrap();
    store.mark_spent(&[low_op], 8).unwrap(); // spent at height 8

    // rollback above 7: drops the height-9 utxo, un-spends the height-8 spend
    store.rollback_above(7).unwrap();

    let unspent = store.list_unspent(w).unwrap();
    assert_eq!(unspent.len(), 1, "height-9 dropped, height-5 un-spent");
    assert_eq!(unspent[0].value(), 100);
}

#[test]
fn mem_block_store_cursor_and_hash_roundtrip() {
    let store = MemBlockStore::new();
    assert!(store.synced_tip().unwrap().is_none());
    let h = BlockHash::all_zeros();
    store.store_block(3, h, b"rawblockbytes").unwrap();
    store
        .set_synced_tip(SyncedTip { height: 3, hash: h })
        .unwrap();
    assert_eq!(
        store.synced_tip().unwrap(),
        Some(SyncedTip { height: 3, hash: h })
    );
    assert_eq!(store.block_hash_at(3).unwrap(), Some(h));
    assert_eq!(store.block_hash_at(4).unwrap(), None);
}

#[test]
fn mem_block_store_rollback_above() {
    let store = MemBlockStore::new();
    for height in 0..=5u32 {
        let mut bytes = [0u8; 32];
        bytes[0] = u8::try_from(height).unwrap();
        let h = BlockHash::from_byte_array(bytes);
        store.store_block(height, h, b"x").unwrap();
        store.set_synced_tip(SyncedTip { height, hash: h }).unwrap();
    }
    store.rollback_above(3).unwrap();
    assert_eq!(store.block_count(), 4, "heights 0..=3 remain");
    assert_eq!(store.synced_tip().unwrap().map(|t| t.height), Some(3));
    assert!(store.block_hash_at(4).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// P4 — engine tests (capture, spend, attribution, reorg, idempotence)
// ---------------------------------------------------------------------------

fn engine_with<'w>(wallets: &[(WalletId, &'w ElementsWollet)]) -> BlockScanEngine<'w> {
    let mut e = BlockScanEngine::new();
    for (id, w) in wallets {
        e.register_wallet(*id, w, 20).unwrap();
    }
    e
}

#[test]
fn single_deposit_captured() {
    let w = make_wollet([1, 2, 3], 0xaa);
    let id = wid(1);
    let engine = engine_with(&[(id, &w)]);

    let spk = w.address(Chain::External, 0).unwrap().script_pubkey();
    let chain = MockChainSource::new();
    build_chain(
        &chain,
        vec![vec![], vec![tx_paying(1, vec![(spk, 50_000)])]],
    );
    let blocks = MemBlockStore::new();
    let utxos = MemUtxoStore::new();

    let summary = engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(summary.utxos_captured, 1);
    assert_eq!(summary.blocks_scanned, 2);

    let unspent = utxos.list_unspent(id).unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(
        unspent[0].value(),
        50_000,
        "explicit value recovered via unblind"
    );
    assert_eq!(blocks.block_count(), 2, "each block stored once");
    assert_eq!(blocks.synced_tip().unwrap().map(|t| t.height), Some(1));
}

#[test]
fn spend_marks_utxo_spent() {
    let w = make_wollet([1, 2, 3], 0xaa);
    let id = wid(1);
    let engine = engine_with(&[(id, &w)]);
    let spk = w.address(Chain::External, 0).unwrap().script_pubkey();

    let chain = MockChainSource::new();
    build_chain(
        &chain,
        vec![vec![], vec![tx_paying(1, vec![(spk.clone(), 50_000)])]],
    );
    let blocks = MemBlockStore::new();
    let utxos = MemUtxoStore::new();
    engine.sync(&chain, &blocks, &utxos).unwrap();

    let deposit = utxos.list_unspent(id).unwrap()[0].outpoint;
    // a new block spends it
    let other = w.address(Chain::External, 5).unwrap().script_pubkey();
    let spend = tx_spending(vec![deposit], vec![(other, 40_000)]);
    let prev = chain.block_hash(1).unwrap();
    chain.push_block(block_at(2, prev, vec![spend], 0));

    let summary = engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(summary.utxos_spent, 1);
    // deposit spent; change output (index 5) captured
    let unspent = utxos.list_unspent(id).unwrap();
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].value(), 40_000);
}

#[test]
fn unwatched_output_ignored() {
    let w = make_wollet([1, 2, 3], 0xaa);
    let foreign = make_wollet([4, 5, 6], 0xbb);
    let id = wid(1);
    let engine = engine_with(&[(id, &w)]);

    let foreign_spk = foreign.address(Chain::External, 0).unwrap().script_pubkey();
    let chain = MockChainSource::new();
    build_chain(
        &chain,
        vec![vec![], vec![tx_paying(1, vec![(foreign_spk, 99_000)])]],
    );
    let blocks = MemBlockStore::new();
    let utxos = MemUtxoStore::new();

    let summary = engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(summary.utxos_captured, 0);
    assert!(utxos.list_unspent(id).unwrap().is_empty());
}

#[test]
fn multi_wallet_attribution() {
    let w1 = make_wollet([1, 2, 3], 0xaa);
    let w2 = make_wollet([4, 5, 6], 0xbb);
    let (id1, id2) = (wid(1), wid(2));
    let engine = engine_with(&[(id1, &w1), (id2, &w2)]);

    let spk1 = w1.address(Chain::External, 0).unwrap().script_pubkey();
    let spk2 = w2.address(Chain::External, 0).unwrap().script_pubkey();
    let chain = MockChainSource::new();
    // ONE block pays both wallets
    build_chain(
        &chain,
        vec![
            vec![],
            vec![tx_paying(1, vec![(spk1, 11_000), (spk2, 22_000)])],
        ],
    );
    let blocks = MemBlockStore::new();
    let utxos = MemUtxoStore::new();

    let summary = engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(summary.utxos_captured, 2);
    assert_eq!(utxos.list_unspent(id1).unwrap()[0].value(), 11_000);
    assert_eq!(utxos.list_unspent(id2).unwrap()[0].value(), 22_000);
}

#[test]
fn reorg_rolls_back_and_recaptures() {
    let w = make_wollet([1, 2, 3], 0xaa);
    let id = wid(1);
    let engine = engine_with(&[(id, &w)]);
    let spk0 = w.address(Chain::External, 0).unwrap().script_pubkey();
    let spk1 = w.address(Chain::External, 1).unwrap().script_pubkey();

    let chain = MockChainSource::new();
    // genesis, then height-1 deposits 70k to addr0
    build_chain(
        &chain,
        vec![vec![], vec![tx_paying(1, vec![(spk0, 70_000)])]],
    );
    let blocks = MemBlockStore::new();
    let utxos = MemUtxoStore::new();
    engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(utxos.list_unspent(id).unwrap()[0].value(), 70_000);

    // reorg: drop height 1, replace with a divergent block depositing 88k to addr1
    chain.reorg_to(0);
    let genesis = chain.block_hash(0).unwrap();
    chain.push_block(block_at(
        1,
        genesis,
        vec![tx_paying(2, vec![(spk1, 88_000)])],
        999,
    ));

    let summary = engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(summary.reorg_to, Some(0), "rolled back to common ancestor");
    let unspent = utxos.list_unspent(id).unwrap();
    assert_eq!(unspent.len(), 1, "old deposit dropped, new one captured");
    assert_eq!(unspent[0].value(), 88_000);
}

#[test]
fn idempotent_resync() {
    let w = make_wollet([1, 2, 3], 0xaa);
    let id = wid(1);
    let engine = engine_with(&[(id, &w)]);
    let spk = w.address(Chain::External, 0).unwrap().script_pubkey();

    let chain = MockChainSource::new();
    build_chain(
        &chain,
        vec![vec![], vec![tx_paying(1, vec![(spk, 50_000)])]],
    );
    let blocks = MemBlockStore::new();
    let utxos = MemUtxoStore::new();

    engine.sync(&chain, &blocks, &utxos).unwrap();
    // second pass with no new blocks: nothing scanned, nothing duplicated
    let summary = engine.sync(&chain, &blocks, &utxos).unwrap();
    assert_eq!(summary.blocks_scanned, 0);
    assert_eq!(summary.utxos_captured, 0);
    assert_eq!(utxos.list_unspent(id).unwrap().len(), 1);
}
