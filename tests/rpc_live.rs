//! GATED-LIVE tests for [`ElementsRpc`] against a live `elementsd`.
//!
//! Exercises the safe read surface (block count / tip, wallet info, descriptor
//! introspection, blinding-key read) and, when a funded wallet is available, a
//! create + process (blind) PSET path. Nothing is broadcast.
//!
//! ## Run
//! ```text
//! ELEMENTS_LIVE=1 \
//!   ELEMENTS_RPC=http://host.docker.internal:7041 \
//!   ELEMENTS_RPC_AUTH=user:pass \
//!   MINER_WALLET=miner \
//!   cargo test -p emvault-elements --test rpc_live -- --nocapture
//! ```
//! Skipped (returns immediately) unless `ELEMENTS_LIVE=1`. Compiles with the
//! default feature set (the `rpc` module is always built).

// Live integration harness: pedantic float/precision lints are noise for a
// linear, node-driven smoke scenario.
#![allow(clippy::doc_markdown, clippy::missing_panics_doc, clippy::float_cmp)]

use emvault_elements::rpc::ElementsRpc;
use serde_json::json;

fn skip() -> bool {
    match std::env::var("ELEMENTS_LIVE") {
        Ok(v) if !v.trim().is_empty() => false,
        _ => {
            eprintln!("SKIP: set ELEMENTS_LIVE=1 to run the live ElementsRpc tests");
            true
        }
    }
}

fn rpc_base() -> String {
    std::env::var("ELEMENTS_RPC").unwrap_or_else(|_| "http://host.docker.internal:7041".to_string())
}

/// Split `ELEMENTS_RPC_AUTH` (`user:pass`) into its parts.
fn rpc_auth() -> (String, String) {
    let raw = std::env::var("ELEMENTS_RPC_AUTH").unwrap_or_else(|_| "user:pass".to_string());
    match raw.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (raw, String::new()),
    }
}

fn miner_wallet() -> String {
    std::env::var("MINER_WALLET").unwrap_or_else(|_| "miner".to_string())
}

fn client() -> ElementsRpc {
    let (user, pass) = rpc_auth();
    ElementsRpc::new(&rpc_base(), &user, &pass)
}

#[test]
fn rpc_getblockcount_and_tip() {
    if skip() {
        return;
    }
    let rpc = client();
    let height = rpc.get_block_count().expect("getblockcount");
    assert!(height > 0, "block count should be > 0 on a live chain");
    eprintln!("getblockcount: {height}");
}

#[test]
fn rpc_descriptor_info() {
    if skip() {
        return;
    }
    let rpc = client();
    // A fixed, key-only descriptor: getdescriptorinfo is a pure read that
    // canonicalizes it and appends a checksum. No wallet context required.
    let info = rpc
        .get_descriptor_info(
            "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
        )
        .expect("getdescriptorinfo");
    assert!(!info.descriptor.is_empty(), "descriptor echoed back");
    assert!(!info.checksum.is_empty(), "checksum computed");
    eprintln!(
        "getdescriptorinfo: checksum={} range={} solvable={}",
        info.checksum, info.is_range, info.is_solvable
    );
}

#[test]
fn rpc_wallet_info_and_blinding_key() {
    if skip() {
        return;
    }
    let rpc = client();
    let wallet = miner_wallet();

    rpc.ensure_wallet_loaded(&wallet)
        .expect("ensure wallet loaded");
    assert!(
        rpc.list_wallets()
            .expect("listwallets")
            .iter()
            .any(|w| w == &wallet),
        "wallet {wallet} should be loaded after ensure_wallet_loaded"
    );

    let balances = rpc.get_balances(&wallet).expect("getbalances");
    assert!(
        balances.trusted >= 0.0,
        "trusted balance should be a valid (non-negative) amount"
    );
    eprintln!(
        "balances: trusted={} pending={} immature={}",
        balances.trusted, balances.untrusted_pending, balances.immature
    );

    let utxos = rpc.list_unspent(&wallet).expect("listunspent");
    // listtransactions is a read-only smoke; assert it deserializes.
    let _txs = rpc.list_transactions(&wallet).expect("listtransactions");
    eprintln!("listunspent: {} utxo(s)", utxos.len());

    // Blinding-key read: dump the blinding key for the first UTXO address we
    // have, if any. On an empty wallet there is no address to read; skip the
    // assertion rather than failing.
    if let Some(addr) = utxos.iter().find_map(|u| u.address.clone()) {
        match rpc.dump_blinding_key(&wallet, &addr) {
            Ok(key) => {
                assert!(!key.is_empty(), "dumpblindingkey should return a hex key");
                eprintln!("dumpblindingkey({addr}): {} hex chars", key.len());
            }
            // Non-fatal: watch-only / imported addresses may lack a private
            // blinding key on this wallet.
            Err(e) => eprintln!("dumpblindingkey (non-fatal): {e}"),
        }
    } else {
        eprintln!("no wallet address available; skipping blinding-key read");
    }
}

#[test]
fn rpc_create_and_process_psbt() {
    if skip() {
        return;
    }
    let rpc = client();
    let wallet = miner_wallet();
    rpc.ensure_wallet_loaded(&wallet)
        .expect("ensure wallet loaded");

    let utxos = rpc.list_unspent(&wallet).expect("listunspent");
    let Some(dest) = utxos.iter().find_map(|u| u.address.clone()) else {
        eprintln!("no wallet address available; skipping create-funded-psbt path");
        return;
    };
    let has_spendable = utxos
        .iter()
        .any(|u| u.spendable && u.amount.unwrap_or(0.0) > 0.0);
    if !has_spendable {
        eprintln!("wallet has no spendable funds; skipping create-funded-psbt path");
        return;
    }

    // Send a dust-ish amount back to one of our own addresses. The wallet funds
    // and (via walletcreatefundedpsbt) blinds the change internally.
    let outputs = vec![json!({ dest.clone(): 0.0001 })];
    let funded = rpc
        .wallet_create_funded_psbt(&wallet, &outputs, 0.00001)
        .expect("walletcreatefundedpsbt");
    assert!(!funded.psbt.is_empty(), "funded PSET should be non-empty");
    eprintln!(
        "walletcreatefundedpsbt: fee={} changepos={}",
        funded.fee, funded.changepos
    );

    // Update/blind (no signing, no broadcast): walletprocesspsbt with sign=false.
    let processed = rpc
        .wallet_update_psbt(&wallet, &funded.psbt)
        .expect("walletprocesspsbt");
    assert!(!processed.is_empty(), "processed PSET should be non-empty");
    eprintln!("walletprocesspsbt: processed PSET len={}", processed.len());
}
