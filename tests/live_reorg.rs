//! Live regtest reorg test for the **nodeless** Elements chain backend.
//!
//! Proves that [`emvault_elements::nodeless::NodelessSync`] (over LWK's Electrum
//! client) survives a **reorg-below-the-persisted-tip**: it detects the reorg
//! via the checkpoint-hash comparison, rolls the affected UTXOs back, and
//! reconciles the store to LWK's post-reorg authoritative set — the Elements
//! analog of `emvault-electrum/tests/live_reorg.rs`.
//!
//! ## Harness
//! - An **Elements regtest** node (JSON-RPC) with a funded wallet, e.g. the
//!   `liquid-regtest` compose stack. Genesis hash + policy asset are read from
//!   the node so the LWK network matches a custom regtest.
//! - An **electrs-liquid** (Blockstream electrs, `--features liquid`) Electrum
//!   server pointed at that node.
//!
//! ## Run
//! ```text
//! ELEMENTS_LIVE=1 \
//!   ELEMENTS_ELECTRUM_URL=tcp://host.docker.internal:60101 \
//!   ELEMENTS_RPC=http://host.docker.internal:7041 \
//!   ELEMENTS_RPC_AUTH=user:pass \
//!   cargo test -p emvault-elements --features "electrum test-utils" \
//!     --test live_reorg -- --nocapture
//! ```
//! Skipped (returns immediately) unless `ELEMENTS_LIVE=1`. Compiles only with the
//! `electrum` + `test-utils` features (else the file is empty).
//!
//! ## Recipe
//! Fund a wallet address, confirm it in `B0`, bury it, then sync (persisting a
//! checkpoint above `B0`). `invalidateblock B0` and mine a strictly longer
//! competing branch: the funding tx is re-mined from the mempool at a new hash,
//! so every checkpoint at/below the old tip flips. Re-sync and assert the reorg
//! was detected (`reorg_to` set) and the store matches LWK's live UTXO set.
//!
//! To also assert *eviction* (balance → 0), extend the reorg step with a
//! funding-input double-spend before mining the competing branch (see the
//! Bitcoin test's §6.2 recipe); that requires building a blinded Elements
//! double-spend through the node wallet and is left as a manual extension.

#![cfg(all(feature = "electrum", feature = "test-utils"))]
// Live integration harness: a few pedantic lints are noise for a linear,
// scripted regtest scenario driven through `curl` RPC helpers.
#![allow(
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::duration_suboptimal_units
)]

use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant};

use emvault_core::signer::Signer;
use emvault_elements::descriptor::{CtDescriptorBuilder, CtKeyMode};
use emvault_elements::elements::{AssetId, BlockHash};
use emvault_elements::nodeless::{MemCheckpointStore, NodelessSync};
use emvault_elements::sync::fakes::MemUtxoStore;
use emvault_elements::sync::{KeychainKind, WalletId, WalletUtxoStore};
use emvault_elements::testkit::SoftwareSigner;
use emvault_elements::{ElementsNetwork, ElementsWalletHandle, ElementsWollet};
use serde_json::{Value, json};

const FUND_SATS: u64 = 5_000_000;
const BLINDING_KEY: [u8; 32] = [0x11; 32];

fn skip() -> bool {
    match std::env::var("ELEMENTS_LIVE") {
        Ok(v) if !v.trim().is_empty() => false,
        _ => {
            eprintln!("SKIP: set ELEMENTS_LIVE=1 to run the live regtest nodeless reorg test");
            true
        }
    }
}

fn electrum_url() -> String {
    std::env::var("ELEMENTS_ELECTRUM_URL")
        .unwrap_or_else(|_| "tcp://host.docker.internal:60101".to_string())
}
fn rpc_base() -> String {
    std::env::var("ELEMENTS_RPC").unwrap_or_else(|_| "http://host.docker.internal:7041".to_string())
}
fn rpc_auth() -> String {
    std::env::var("ELEMENTS_RPC_AUTH").unwrap_or_else(|_| "user:pass".to_string())
}

/// Minimal Elements JSON-RPC over `curl` (mirrors the Bitcoin test; no HTTP
/// crate dependency). `wallet` appends `/wallet/<name>` for wallet RPCs.
fn rpc(method: &str, params: Value, wallet: Option<&str>) -> Value {
    let url = match wallet {
        Some(w) => format!("{}/wallet/{w}", rpc_base()),
        None => rpc_base(),
    };
    let body = json!({"jsonrpc": "1.0", "id": "reorg-test", "method": method, "params": params});
    let out = Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "60",
            "--user",
            &rpc_auth(),
            "--data-binary",
            &body.to_string(),
            "-H",
            "content-type: text/plain;",
            &url,
        ])
        .output()
        .expect("spawn curl");
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rpc {method}: bad JSON: {e}: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert!(
        v.get("error").is_none_or(Value::is_null),
        "rpc {method} error: {}",
        v["error"]
    );
    v["result"].clone()
}

fn block_count() -> u64 {
    rpc("getblockcount", json!([]), None).as_u64().unwrap()
}
fn block_hash(height: u64) -> String {
    rpc("getblockhash", json!([height]), None)
        .as_str()
        .unwrap()
        .to_string()
}
/// Mine `n` blocks to a fresh node address; returns the new tip height.
fn mine(wallet: &str, n: u32) -> u64 {
    let addr = rpc("getnewaddress", json!([]), Some(wallet));
    let addr = addr.as_str().expect("getnewaddress");
    rpc("generatetoaddress", json!([n, addr]), None);
    block_count()
}
fn btc(sats: u64) -> f64 {
    sats as f64 / 100_000_000.0
}

/// Derive the custom-regtest LWK network from the node (policy asset + genesis),
/// matching `test-app`'s `node_lwk_network`.
fn node_lwk() -> lwk_wollet_network::Network {
    let genesis = BlockHash::from_str(&block_hash(0)).expect("genesis hash");
    let pegged = rpc("getsidechaininfo", json!([]), None)["pegged_asset"]
        .as_str()
        .expect("pegged_asset")
        .to_string();
    let policy = AssetId::from_str(&pegged).expect("policy asset");
    ElementsNetwork::custom_regtest(policy, genesis)
}

mod lwk_wollet_network {
    pub use emvault_elements::lwk_wollet::Network;
}

/// Build a 2-of-3 ranged CT wallet from deterministic software signers.
fn build_wollet(lwk: lwk_wollet_network::Network) -> ElementsWollet {
    let mut builder = CtDescriptorBuilder::new(2, &BLINDING_KEY)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for seed in 1..=3u8 {
        let s = SoftwareSigner::new_with_lwk(seed, lwk);
        builder.add_signer(&s as &dyn Signer).unwrap();
    }
    let desc = builder.build().unwrap();
    let handle = ElementsWalletHandle::new(desc, BLINDING_KEY);
    ElementsWollet::from_handle_with_lwk(&handle, ElementsNetwork::ElementsRegtest, lwk).unwrap()
}

fn total_unspent(store: &MemUtxoStore, wid: WalletId) -> u64 {
    store
        .list_unspent(wid)
        .expect("list_unspent")
        .iter()
        .map(emvault_elements::sync::CapturedUtxo::value)
        .sum()
}

/// Sync repeatedly until the wallet tip reaches `target` (doubles as the
/// electrs-catch-up wait). Returns whether any pass reported a reorg.
fn sync_until(
    client: &mut NodelessSync<emvault_elements::lwk_wollet::ElectrumClient>,
    wid: WalletId,
    wollets: &mut [ElementsWollet],
    utxos: &MemUtxoStore,
    checkpoints: &MemCheckpointStore,
    target: u64,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut saw_reorg = false;
    loop {
        match client.sync(wid, wollets, utxos, checkpoints) {
            Ok(o) => {
                saw_reorg |= o.reorg_to.is_some();
                if u64::from(o.tip.height) >= target {
                    return saw_reorg;
                }
            }
            Err(e) => eprintln!("sync error (will retry): {e}"),
        }
        assert!(
            Instant::now() < deadline,
            "electrs did not reach height {target} within 120s"
        );
        std::thread::sleep(Duration::from_millis(750));
    }
}

#[test]
fn reorg_below_persisted_tip_nodeless() {
    if skip() {
        return;
    }

    let wallet = std::env::var("MINER_WALLET").unwrap_or_else(|_| "miner".to_string());
    let lwk = node_lwk();
    let wid = WalletId::from_bytes([7u8; 16]);
    let mut wollets = vec![build_wollet(lwk)];
    let utxos = MemUtxoStore::new();
    let checkpoints = MemCheckpointStore::default();
    let mut client = NodelessSync::new_electrum(&electrum_url()).expect("connect electrs-liquid");

    // --- Phase 1: fund a wallet address, confirm it, bury it below the tip. ---
    let addr = wollets[0]
        .address(KeychainKind::External, 0)
        .expect("derive CT address");
    eprintln!("funding CT address: {addr}");
    let d_txid = rpc(
        "sendtoaddress",
        json!([addr.to_string(), btc(FUND_SATS)]),
        Some(&wallet),
    );
    eprintln!("funding txid: {d_txid}");

    let h0 = mine(&wallet, 1); // confirm the funding tx in B0
    let b0 = block_hash(h0);
    eprintln!("funded at height={h0} hash={b0}");
    let h_pre = mine(&wallet, 2); // bury B0 two deep

    let saw = sync_until(&mut client, wid, &mut wollets, &utxos, &checkpoints, h_pre);
    let bal1 = total_unspent(&utxos, wid);
    eprintln!("sync #1: tip>={h_pre} balance={bal1} sats reorg_seen={saw}");
    assert_eq!(bal1, FUND_SATS, "wallet should capture the funding UTXO");

    // --- Phase 2: reorg below the persisted tip. ---
    // Invalidate B0 (rolls back to h0-1; the funding tx returns to the mempool),
    // then mine a strictly longer competing branch. Every checkpoint at/below the
    // old tip flips, so the nodeless sync must detect the reorg and reconcile.
    rpc("invalidateblock", json!([b0]), None);
    let h_post = mine(&wallet, 3);
    eprintln!("post-reorg tip height={h_post}");

    let saw_reorg = sync_until(&mut client, wid, &mut wollets, &utxos, &checkpoints, h_post);
    assert!(
        saw_reorg,
        "the nodeless sync must detect the reorg-below-tip (reorg_to set)"
    );

    // Reconcile invariant: the store's unspent set equals LWK's live unspent set.
    let mut store_ops: Vec<_> = utxos
        .list_unspent(wid)
        .unwrap()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    let mut live_ops: Vec<_> = wollets[0]
        .inner()
        .utxos()
        .expect("wollet utxos")
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    store_ops.sort();
    live_ops.sort();
    assert_eq!(
        store_ops, live_ops,
        "after the reorg the store must match LWK's authoritative UTXO set"
    );
    eprintln!(
        "post-reorg reconcile OK: {} unspent outpoint(s)",
        store_ops.len()
    );
}
