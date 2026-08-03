//! GATED-LIVE smoke tests for the **nodeless** chain backends across all three
//! LWK blockchain clients (Electrum, Esplora, Waterfalls).
//!
//! Each test builds a real 2-of-3 confidential wollet (identical construction
//! to `tests/live_reorg.rs`), drives one backend's [`NodelessSync`] against a
//! live regtest, and asserts the backend reports a positive chain tip that
//! roughly matches the Elements node's block count.
//!
//! ## Run
//! ```text
//! ELEMENTS_LIVE=1 \
//!   ELEMENTS_ELECTRUM_URL=tcp://host.docker.internal:60101 \
//!   ELEMENTS_ESPLORA_URL=http://host.docker.internal:3002 \
//!   ELEMENTS_WATERFALLS_URL=http://host.docker.internal:3002 \
//!   ELEMENTS_RPC=http://host.docker.internal:7041 \
//!   ELEMENTS_RPC_AUTH=user:pass \
//!   cargo test -p emvault-elements --features "nodeless test-utils" \
//!     --test nodeless_live -- --nocapture
//! ```
//! Skipped (returns immediately) unless `ELEMENTS_LIVE=1`. Compiles only with
//! `test-utils` plus at least one of `electrum` / `esplora` (else the file is
//! empty). The node RPC (`ELEMENTS_RPC` / `ELEMENTS_RPC_AUTH`) is used to derive
//! the custom-regtest LWK network and to read the reference block count.

#![cfg(all(feature = "test-utils", any(feature = "electrum", feature = "esplora")))]
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
use emvault_elements::sync::WalletId;
use emvault_elements::sync::fakes::MemUtxoStore;
use emvault_elements::testkit::SoftwareSigner;
use emvault_elements::{ElementsNetwork, ElementsWalletHandle, ElementsWollet};
use serde_json::{Value, json};

const BLINDING_KEY: [u8; 32] = [0x22; 32];

fn skip() -> bool {
    match std::env::var("ELEMENTS_LIVE") {
        Ok(v) if !v.trim().is_empty() => false,
        _ => {
            eprintln!("SKIP: set ELEMENTS_LIVE=1 to run the live nodeless smoke tests");
            true
        }
    }
}

#[cfg(feature = "electrum")]
fn electrum_url() -> String {
    std::env::var("ELEMENTS_ELECTRUM_URL")
        .unwrap_or_else(|_| "tcp://host.docker.internal:60101".to_string())
}

#[cfg(feature = "esplora")]
fn esplora_url() -> String {
    std::env::var("ELEMENTS_ESPLORA_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3002".to_string())
}

#[cfg(feature = "esplora")]
fn waterfalls_url() -> String {
    std::env::var("ELEMENTS_WATERFALLS_URL")
        .unwrap_or_else(|_| "http://host.docker.internal:3002".to_string())
}

fn rpc_base() -> String {
    std::env::var("ELEMENTS_RPC").unwrap_or_else(|_| "http://host.docker.internal:7041".to_string())
}
fn rpc_auth() -> String {
    std::env::var("ELEMENTS_RPC_AUTH").unwrap_or_else(|_| "user:pass".to_string())
}

/// Minimal Elements JSON-RPC over `curl` (mirrors `tests/live_reorg.rs`; no HTTP
/// crate dependency).
fn rpc(method: &str, params: Value) -> Value {
    let body =
        json!({"jsonrpc": "1.0", "id": "nodeless-smoke", "method": method, "params": params});
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
            &rpc_base(),
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
    rpc("getblockcount", json!([])).as_u64().unwrap()
}
fn block_hash(height: u64) -> String {
    rpc("getblockhash", json!([height]))
        .as_str()
        .unwrap()
        .to_string()
}

mod lwk_wollet_network {
    pub use emvault_elements::lwk_wollet::Network;
}

/// Derive the custom-regtest LWK network from the node (policy asset + genesis),
/// matching `tests/live_reorg.rs::node_lwk`.
fn node_lwk() -> lwk_wollet_network::Network {
    let genesis = BlockHash::from_str(&block_hash(0)).expect("genesis hash");
    let pegged = rpc("getsidechaininfo", json!([]))["pegged_asset"]
        .as_str()
        .expect("pegged_asset")
        .to_string();
    let policy = AssetId::from_str(&pegged).expect("policy asset");
    ElementsNetwork::custom_regtest(policy, genesis)
}

/// Build a 2-of-3 ranged CT wallet from deterministic software signers
/// (identical construction to `tests/live_reorg.rs::build_wollet`).
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

/// Sync repeatedly until the wallet tip reaches `target` (doubles as the
/// backend-catch-up wait), bounded by a deadline. Generic over the LWK client so
/// the same loop serves Electrum, Esplora, and Waterfalls.
fn sync_until<B: emvault_elements::lwk_wollet::blocking::BlockchainBackend>(
    client: &mut NodelessSync<B>,
    wid: WalletId,
    wollets: &mut [ElementsWollet],
    utxos: &MemUtxoStore,
    checkpoints: &MemCheckpointStore,
    target: u64,
) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match client.sync(wid, wollets, utxos, checkpoints) {
            Ok(o) => {
                if u64::from(o.tip.height) >= target {
                    return;
                }
            }
            Err(e) => eprintln!("sync error (will retry): {e}"),
        }
        assert!(
            Instant::now() < deadline,
            "backend did not reach height {target} within 120s"
        );
        std::thread::sleep(Duration::from_millis(750));
    }
}

/// Shared body: sync an empty-but-real wollet against `client`, then assert the
/// backend reports a positive tip that roughly matches the node's block count.
fn smoke_sync_and_tip<B: emvault_elements::lwk_wollet::blocking::BlockchainBackend>(
    mut client: NodelessSync<B>,
    label: &str,
) {
    let lwk = node_lwk();
    let wid = WalletId::from_bytes([9u8; 16]);
    let mut wollets = vec![build_wollet(lwk)];
    let utxos = MemUtxoStore::new();
    let checkpoints = MemCheckpointStore::default();

    let node_tip = block_count();
    assert!(
        node_tip > 0,
        "{label}: node must have a live chain (height > 0)"
    );

    sync_until(
        &mut client,
        wid,
        &mut wollets,
        &utxos,
        &checkpoints,
        node_tip,
    );

    let tip = client.tip_height().expect("backend tip_height");
    assert!(tip > 0, "{label}: backend tip height must be > 0");

    // Roughly matches the node; allow a small lag either way for propagation
    // between the node and the indexer/electrum server.
    let node_tip2 = block_count();
    let diff = node_tip2.abs_diff(u64::from(tip));
    assert!(
        diff <= 2,
        "{label}: backend tip {tip} should ~match node {node_tip2} (diff {diff})"
    );
    eprintln!("{label}: OK tip={tip} node={node_tip2}");
}

#[cfg(feature = "electrum")]
#[test]
fn nodeless_electrum_sync_and_tip() {
    if skip() {
        return;
    }
    let client = NodelessSync::new_electrum(&electrum_url()).expect("connect electrs-liquid");
    smoke_sync_and_tip(client, "electrum");
    // TODO(live): a broadcast round-trip needs a fully built + blinded + signed
    // Elements tx (spend::build_spend_pset -> blind_pset -> sign -> finalize),
    // which is already exercised end-to-end by the pset/spend unit suites and
    // the RPC migration harness. This smoke test asserts sync + tip only and
    // does not construct/re-broadcast a tx here.
}

#[cfg(feature = "esplora")]
#[test]
fn nodeless_esplora_sync_and_tip() {
    if skip() {
        return;
    }
    let lwk = node_lwk();
    let client = NodelessSync::new_esplora(&esplora_url(), lwk).expect("connect esplora");
    smoke_sync_and_tip(client, "esplora");
}

#[cfg(feature = "esplora")]
#[test]
fn nodeless_waterfalls_sync_and_tip() {
    if skip() {
        return;
    }
    let lwk = node_lwk();
    let client = NodelessSync::new_waterfalls(&waterfalls_url(), lwk).expect("connect waterfalls");
    smoke_sync_and_tip(client, "waterfalls");
}
