//! GATED-LIVE end-to-end: issue a regtest asset, fund a 2-of-3 confidential
//! federation with it (plus L-BTC for the fee), then spend the asset via
//! [`build_asset_spend_pset`], sign with the software federation, and **broadcast
//! the result to a live `elementsd`** — proving the asset-spend path is
//! consensus-valid on-chain, not just in the offline unit test.
//!
//! ## Run
//! ```text
//! ELEMENTS_LIVE=1 \
//!   ELEMENTS_RPC=http://host.docker.internal:18884 \
//!   ELEMENTS_RPC_AUTH=elements:PASS \
//!   ELEMENTS_WALLET=default \
//!   cargo test -p emvault-elements --features test-utils --test asset_spend_live -- --nocapture
//! ```
//! Skipped unless `ELEMENTS_LIVE=1`.

// Needs the `testkit` software signers (behind `test-utils`); compiles to an
// empty crate otherwise so the default-feature `cargo test --all-targets` gate
// (which doesn't enable `test-utils`) stays green.
#![cfg(feature = "test-utils")]
#![allow(clippy::doc_markdown, clippy::missing_panics_doc, clippy::float_cmp)]

use std::str::FromStr;

use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};

use emvault_core::signer::Signer;
use emvault_elements::sync::WalletId;
use emvault_elements::testkit::SoftwareSigner;
use emvault_elements::{
    CtDescriptorBuilder, CtKeyMode, ElementsNetwork, ElementsSigner, ElementsWalletHandle,
    ElementsWollet, build_asset_spend_pset, build_migration_pset, captured_from_output, elements,
    finalize_p2wsh_pset, lwk_wollet,
};

fn skip() -> bool {
    match std::env::var("ELEMENTS_LIVE") {
        Ok(v) if !v.trim().is_empty() => false,
        _ => {
            eprintln!("SKIP: set ELEMENTS_LIVE=1 to run asset_spend_live");
            true
        }
    }
}

fn wallet_client() -> Client {
    let base = std::env::var("ELEMENTS_RPC")
        .unwrap_or_else(|_| "http://host.docker.internal:18884".into());
    let wallet = std::env::var("ELEMENTS_WALLET").unwrap_or_else(|_| "default".into());
    let (user, pass) = std::env::var("ELEMENTS_RPC_AUTH")
        .unwrap_or_else(|_| "elements:pass".into())
        .split_once(':')
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .expect("ELEMENTS_RPC_AUTH must be user:pass");
    Client::new(
        &format!("{}/wallet/{wallet}", base.trim_end_matches('/')),
        Auth::UserPass(user, pass),
    )
    .expect("elements rpc client")
}

fn call(rpc: &Client, method: &str, params: &[Value]) -> Value {
    rpc.call::<Value>(method, params)
        .unwrap_or_else(|e| panic!("rpc {method} failed: {e}"))
}

/// Mine one block so the preceding wallet tx confirms.
fn mine(rpc: &Client) {
    let addr = call(rpc, "getnewaddress", &[]);
    let _ = call(rpc, "generatetoaddress", &[json!(1), addr]);
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Fetch a confirmed tx and return the `elements::TxOut` at the output paying
/// `spk`, plus its vout index.
fn find_output(rpc: &Client, txid: &str, spk: &elements::Script) -> (u32, elements::TxOut) {
    // Use the wallet's gettransaction (node has txindex=0, so a confirmed tx
    // isn't queryable via getrawtransaction without a block hash).
    let gt = call(rpc, "gettransaction", &[json!(txid)]);
    let raw = unhex(gt["hex"].as_str().expect("tx hex"));
    let tx: elements::Transaction = elements::encode::deserialize(&raw).expect("decode tx");
    for (i, o) in tx.output.iter().enumerate() {
        if &o.script_pubkey == spk {
            return (u32::try_from(i).unwrap(), o.clone());
        }
    }
    panic!("no output paying our script in {txid}");
}

/// Build a 2-of-3 confidential federation wallet from three seeds + a blinding
/// byte, on the given network.
fn fed_wollet(
    seeds: [u8; 3],
    blinding: u8,
    net: ElementsNetwork,
    lwk_net: lwk_wollet::Network,
) -> (Vec<SoftwareSigner>, ElementsWollet) {
    let signers: Vec<SoftwareSigner> = seeds
        .map(|s| SoftwareSigner::new_with_lwk(s, lwk_net))
        .to_vec();
    let mbk = [blinding; 32];
    let mut b = CtDescriptorBuilder::new(2, &mbk)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        b.add_signer(s as &dyn Signer).unwrap();
    }
    let desc = b.build().unwrap();
    let handle = ElementsWalletHandle::new(desc, mbk);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk_net).unwrap();
    (signers, wollet)
}

/// Send `units` whole units of `asset_hex` to a confidential address, returning
/// the funding txid.
fn send_asset(rpc: &Client, addr: &str, units: u64, asset_hex: &str) -> String {
    call(
        rpc,
        "sendtoaddress",
        &[
            json!(addr),
            json!(units),
            json!(""),
            json!(""),
            json!(false),
            json!(false),
            json!(1),
            json!("unset"),
            json!(false),
            json!(asset_hex),
        ],
    )
    .as_str()
    .unwrap()
    .to_string()
}

#[test]
#[allow(clippy::too_many_lines)]
fn asset_receive_and_spend_live() {
    if skip() {
        return;
    }
    let rpc = wallet_client();
    let net = ElementsNetwork::ElementsRegtest;

    // 1. Issue a fresh regtest asset (1000 units, no reissuance token) + confirm.
    let issue = call(&rpc, "issueasset", &[json!(1000), json!(0)]);
    let asset_hex = issue["asset"].as_str().expect("asset id").to_string();
    let asset = elements::AssetId::from_str(&asset_hex).expect("asset id parse");
    mine(&rpc);
    eprintln!("issued asset {asset_hex}");

    // 2. This regtest node's policy asset + genesis differ from LWK's defaults,
    //    so build a custom-regtest network from the node's own values (else LWK
    //    prices the fee in the wrong policy asset).
    let genesis_hex = call(&rpc, "getblockhash", &[json!(0)]);
    let genesis = elements::BlockHash::from_str(genesis_hex.as_str().unwrap()).unwrap();
    let side = call(&rpc, "getsidechaininfo", &[]);
    let policy =
        elements::AssetId::from_str(side["pegged_asset"].as_str().expect("pegged_asset")).unwrap();
    let lwk_net = ElementsNetwork::custom_regtest(policy, genesis);
    eprintln!("node policy asset {policy}");

    // 3. Build a 2-of-3 confidential federation (software signers) + wollet on
    //    the node's actual network.
    let signers: Vec<SoftwareSigner> = [1u8, 2, 3]
        .map(|s| SoftwareSigner::new_with_lwk(s, lwk_net))
        .to_vec();
    let mbk = [0x42u8; 32];
    let mut builder = CtDescriptorBuilder::new(2, &mbk)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let desc = builder.build().unwrap();
    let handle = ElementsWalletHandle::new(desc, mbk);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk_net).unwrap();
    let asset_addr = wollet.address(lwk_wollet::Chain::External, 0).unwrap();
    let fee_addr = wollet.address(lwk_wollet::Chain::External, 1).unwrap();

    // 3. Fund the federation: 100 units of the asset to addr0, 0.01 L-BTC to
    //    addr1 (fee source), then confirm.
    let asset_txid = call(
        &rpc,
        "sendtoaddress",
        &[
            json!(asset_addr.to_string()),
            json!(100),
            json!(""),
            json!(""),
            json!(false),
            json!(false),
            json!(1),
            json!("unset"),
            json!(false),
            json!(asset_hex),
        ],
    )
    .as_str()
    .unwrap()
    .to_string();
    let lbtc_txid = call(
        &rpc,
        "sendtoaddress",
        &[json!(fee_addr.to_string()), json!(1.0)],
    )
    .as_str()
    .unwrap()
    .to_string();
    mine(&rpc);
    eprintln!("funded: asset tx {asset_txid}, lbtc tx {lbtc_txid}");

    // 4. Capture the two federation UTXOs (unblind the confidential outputs).
    let wid = WalletId::from_bytes([7; 16]);
    let (a_vout, a_txout) = find_output(&rpc, &asset_txid, &asset_addr.script_pubkey());
    let (f_vout, f_txout) = find_output(&rpc, &lbtc_txid, &fee_addr.script_pubkey());
    let asset_utxo = captured_from_output(
        &wollet,
        elements::Txid::from_str(&asset_txid).unwrap(),
        a_vout,
        &a_txout,
        wid,
        0,
    )
    .expect("capture asset utxo");
    let fee_utxo = captured_from_output(
        &wollet,
        elements::Txid::from_str(&lbtc_txid).unwrap(),
        f_vout,
        &f_txout,
        wid,
        1,
    )
    .expect("capture fee utxo");
    assert_eq!(asset_utxo.asset(), asset, "captured the issued asset");
    eprintln!(
        "captured asset={} ({} u) + fee-utxo asset={} value={} sat",
        asset_utxo.asset(),
        asset_utxo.value(),
        fee_utxo.asset(),
        fee_utxo.value()
    );

    // 5. Spend 50 units of the asset to a fresh node address; L-BTC pays the fee.
    let recipient_str = call(&rpc, "getnewaddress", &[])
        .as_str()
        .unwrap()
        .to_string();
    let recipient = elements::Address::from_str(&recipient_str).unwrap();
    let send_units: u64 = 50 * 100_000_000;
    let blinded = build_asset_spend_pset(
        &wollet,
        &[asset_utxo, fee_utxo],
        &recipient,
        asset,
        send_units,
        1000.0,
    )
    .expect("build asset spend pset");

    // 6. Federation signs 2-of-3, finalize, extract.
    let mut pset = blinded.into_pset();
    let mut total = 0usize;
    for s in signers.iter().take(2) {
        total += s.sign_pset(&mut pset).expect("sign");
    }
    eprintln!("federation produced {total} signatures");
    finalize_p2wsh_pset(&mut pset).expect("finalize");
    let tx = pset.extract_tx().expect("extract");
    let raw_hex = elements::encode::serialize_hex(&tx);

    // 7. Broadcast to the live node — the real consensus check — and confirm.
    let txid = call(&rpc, "sendrawtransaction", &[json!(raw_hex)]);
    let txid = txid.as_str().expect("broadcast txid").to_string();
    mine(&rpc);
    let got = call(&rpc, "gettransaction", &[json!(txid.clone())]);
    let confs = got["confirmations"].as_i64().unwrap_or(0);
    assert!(
        confs >= 1,
        "spend tx {txid} should be confirmed, got {confs}"
    );
    eprintln!("SPEND CONFIRMED: {txid} ({confs} conf) — asset {asset_hex}");
}

/// Full-asset **Max**: fund a fresh federation, then drain its *entire* asset
/// balance to a node address (the L-BTC fee is paid separately, so nothing is
/// subtracted from the asset). Verifies on-chain that the node's asset balance
/// returns in full — i.e. no asset change was created.
#[test]
#[allow(clippy::too_many_lines)]
fn asset_max_drain_live() {
    if skip() {
        return;
    }
    let rpc = wallet_client();
    let net = ElementsNetwork::ElementsRegtest;

    // Issue 500 units + confirm.
    let issue = call(&rpc, "issueasset", &[json!(500), json!(0)]);
    let asset_hex = issue["asset"].as_str().expect("asset id").to_string();
    let asset = elements::AssetId::from_str(&asset_hex).unwrap();
    mine(&rpc);

    // Node's real regtest params.
    let genesis_hex = call(&rpc, "getblockhash", &[json!(0)]);
    let genesis = elements::BlockHash::from_str(genesis_hex.as_str().unwrap()).unwrap();
    let side = call(&rpc, "getsidechaininfo", &[]);
    let policy =
        elements::AssetId::from_str(side["pegged_asset"].as_str().expect("pegged_asset")).unwrap();
    let lwk_net = ElementsNetwork::custom_regtest(policy, genesis);

    // Fresh 2-of-3 federation (distinct seeds → distinct wallet).
    let signers: Vec<SoftwareSigner> = [11u8, 12, 13]
        .map(|s| SoftwareSigner::new_with_lwk(s, lwk_net))
        .to_vec();
    let mbk = [0x77u8; 32];
    let mut builder = CtDescriptorBuilder::new(2, &mbk)
        .unwrap()
        .key_mode(CtKeyMode::Ranged);
    for s in &signers {
        builder.add_signer(s as &dyn Signer).unwrap();
    }
    let desc = builder.build().unwrap();
    let handle = ElementsWalletHandle::new(desc, mbk);
    let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk_net).unwrap();
    let asset_addr = wollet.address(lwk_wollet::Chain::External, 0).unwrap();
    let fee_addr = wollet.address(lwk_wollet::Chain::External, 1).unwrap();

    // Fund: 250 units of the asset + 1.0 L-BTC, then confirm.
    let asset_txid = call(
        &rpc,
        "sendtoaddress",
        &[
            json!(asset_addr.to_string()),
            json!(250),
            json!(""),
            json!(""),
            json!(false),
            json!(false),
            json!(1),
            json!("unset"),
            json!(false),
            json!(asset_hex),
        ],
    )
    .as_str()
    .unwrap()
    .to_string();
    let lbtc_txid = call(
        &rpc,
        "sendtoaddress",
        &[json!(fee_addr.to_string()), json!(1.0)],
    )
    .as_str()
    .unwrap()
    .to_string();
    mine(&rpc);

    // Node's asset balance now (after sending 250 to the federation).
    let node_asset = |r: &Client| -> f64 {
        call(r, "getbalances", &[])["mine"]["trusted"][asset_hex.as_str()]
            .as_f64()
            .unwrap_or(0.0)
    };
    let before = node_asset(&rpc);

    // Capture both federation UTXOs.
    let wid = WalletId::from_bytes([9; 16]);
    let (a_vout, a_txout) = find_output(&rpc, &asset_txid, &asset_addr.script_pubkey());
    let (f_vout, f_txout) = find_output(&rpc, &lbtc_txid, &fee_addr.script_pubkey());
    let asset_utxo = captured_from_output(
        &wollet,
        elements::Txid::from_str(&asset_txid).unwrap(),
        a_vout,
        &a_txout,
        wid,
        0,
    )
    .expect("capture asset utxo");
    let fee_utxo = captured_from_output(
        &wollet,
        elements::Txid::from_str(&lbtc_txid).unwrap(),
        f_vout,
        &f_txout,
        wid,
        1,
    )
    .expect("capture fee utxo");

    // MAX: spend the ENTIRE asset balance back to a node address.
    let drain = asset_utxo.value();
    let recipient_str = call(&rpc, "getnewaddress", &[])
        .as_str()
        .unwrap()
        .to_string();
    let recipient = elements::Address::from_str(&recipient_str).unwrap();
    let blinded = build_asset_spend_pset(
        &wollet,
        &[asset_utxo, fee_utxo],
        &recipient,
        asset,
        drain,
        1000.0,
    )
    .expect("build asset drain pset");

    let mut pset = blinded.into_pset();
    for s in signers.iter().take(2) {
        s.sign_pset(&mut pset).expect("sign");
    }
    finalize_p2wsh_pset(&mut pset).expect("finalize");
    let tx = pset.extract_tx().expect("extract");
    let raw_hex = elements::encode::serialize_hex(&tx);

    let txid = call(&rpc, "sendrawtransaction", &[json!(raw_hex)]);
    let txid = txid.as_str().expect("broadcast txid").to_string();
    mine(&rpc);
    let got = call(&rpc, "gettransaction", &[json!(txid.clone())]);
    assert!(
        got["confirmations"].as_i64().unwrap_or(0) >= 1,
        "drain tx {txid} should be confirmed"
    );

    // The node's asset balance returned in full → the whole 250 units came back
    // (no asset change stranded in the federation).
    let after = node_asset(&rpc);
    assert!(
        (after - before - 250.0).abs() < 1e-8,
        "node asset balance should rise by the full 250 units: before={before} after={after}"
    );
    eprintln!("MAX DRAIN CONFIRMED: {txid} — node asset {before} → {after} (+250)");
}

/// Live regtest **asset migration** (account-for-account): an old-federation
/// customer holding L-BTC + an issued asset is migrated to a new federation; the
/// old fee account pays the L-BTC fee. Verifies on-chain that the new federation
/// receives the customer's **full L-BTC and full asset** — i.e. assets migrate.
#[test]
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn asset_migration_moves_asset_live() {
    if skip() {
        return;
    }
    let rpc = wallet_client();
    let net = ElementsNetwork::ElementsRegtest;

    let issue = call(&rpc, "issueasset", &[json!(500), json!(0)]);
    let asset_hex = issue["asset"].as_str().expect("asset id").to_string();
    let asset = elements::AssetId::from_str(&asset_hex).unwrap();
    mine(&rpc);

    let genesis_hex = call(&rpc, "getblockhash", &[json!(0)]);
    let genesis = elements::BlockHash::from_str(genesis_hex.as_str().unwrap()).unwrap();
    let side = call(&rpc, "getsidechaininfo", &[]);
    let policy =
        elements::AssetId::from_str(side["pegged_asset"].as_str().expect("pegged_asset")).unwrap();
    let lwk_net = ElementsNetwork::custom_regtest(policy, genesis);

    // Build a 2-of-3 confidential federation wallet from three seeds + blinding.
    let build = |seeds: [u8; 3], blinding: u8| -> (Vec<SoftwareSigner>, ElementsWollet) {
        let signers: Vec<SoftwareSigner> = seeds
            .map(|s| SoftwareSigner::new_with_lwk(s, lwk_net))
            .to_vec();
        let mbk = [blinding; 32];
        let mut b = CtDescriptorBuilder::new(2, &mbk)
            .unwrap()
            .key_mode(CtKeyMode::Ranged);
        for s in &signers {
            b.add_signer(s as &dyn Signer).unwrap();
        }
        let desc = b.build().unwrap();
        let handle = ElementsWalletHandle::new(desc, mbk);
        let wollet = ElementsWollet::from_handle_with_lwk(&handle, net, lwk_net).unwrap();
        (signers, wollet)
    };

    // OLD federation: fee account + a customer. NEW federation: rotated dests.
    let (fee_sgn, fee_w) = build([1, 2, 3], 0xa1);
    let (cust_sgn, cust_w) = build([4, 5, 6], 0xb2);
    let (_newc_sgn, newc_w) = build([7, 8, 9], 0xc3);
    let (_newf_sgn, newf_w) = build([10, 11, 12], 0xd4);

    let fee_addr = fee_w.address(lwk_wollet::Chain::External, 0).unwrap();
    let cust_lbtc_addr = cust_w.address(lwk_wollet::Chain::External, 0).unwrap();
    let cust_asset_addr = cust_w.address(lwk_wollet::Chain::External, 1).unwrap();
    let new_cust_dest = newc_w.address(lwk_wollet::Chain::External, 0).unwrap();
    let new_fee_dest = newf_w.address(lwk_wollet::Chain::External, 0).unwrap();

    // Fund: old fee 1.0 L-BTC; old customer 0.5 L-BTC + 250 asset units.
    let fee_txid = call(
        &rpc,
        "sendtoaddress",
        &[json!(fee_addr.to_string()), json!(1.0)],
    )
    .as_str()
    .unwrap()
    .to_string();
    let cust_lbtc_txid = call(
        &rpc,
        "sendtoaddress",
        &[json!(cust_lbtc_addr.to_string()), json!(0.5)],
    )
    .as_str()
    .unwrap()
    .to_string();
    let cust_asset_txid = call(
        &rpc,
        "sendtoaddress",
        &[
            json!(cust_asset_addr.to_string()),
            json!(250),
            json!(""),
            json!(""),
            json!(false),
            json!(false),
            json!(1),
            json!("unset"),
            json!(false),
            json!(asset_hex),
        ],
    )
    .as_str()
    .unwrap()
    .to_string();
    mine(&rpc);

    // Capture the three old-fed UTXOs.
    let wid = WalletId::from_bytes([5; 16]);
    let cap = |w: &ElementsWollet, txid: &str, addr: &elements::Address, idx: u32| {
        let (vout, txout) = find_output(&rpc, txid, &addr.script_pubkey());
        captured_from_output(
            w,
            elements::Txid::from_str(txid).unwrap(),
            vout,
            &txout,
            wid,
            idx,
        )
        .expect("capture")
    };
    let fee_utxo = cap(&fee_w, &fee_txid, &fee_addr, 0);
    let cust_lbtc_utxo = cap(&cust_w, &cust_lbtc_txid, &cust_lbtc_addr, 0);
    let cust_asset_utxo = cap(&cust_w, &cust_asset_txid, &cust_asset_addr, 1);
    let cust_lbtc_val = cust_lbtc_utxo.value();
    let cust_asset_val = cust_asset_utxo.value();

    // Migrate account-for-account: the customer's full L-BTC + full asset go to
    // the new-fed customer address; the old fee account drains its L-BTC to the
    // new fee address (paying the mining fee).
    let inputs = vec![
        (fee_utxo, &fee_w),
        (cust_lbtc_utxo, &cust_w),
        (cust_asset_utxo, &cust_w),
    ];
    let recipients = vec![
        (new_cust_dest.clone(), cust_lbtc_val, policy),
        (new_cust_dest.clone(), cust_asset_val, asset),
    ];
    let blinded =
        build_migration_pset(&fee_w, &inputs, &recipients, &new_fee_dest, 1000.0).unwrap();

    // Each account's 2-of-3 signs (distinct feds → a signer only signs its own
    // inputs), then finalize + broadcast.
    let mut pset = blinded.into_pset();
    for s in fee_sgn.iter().take(2).chain(cust_sgn.iter().take(2)) {
        s.sign_pset(&mut pset).unwrap();
    }
    finalize_p2wsh_pset(&mut pset).unwrap();
    let tx = pset.extract_tx().unwrap();
    let raw_hex = elements::encode::serialize_hex(&tx);

    let txid = call(&rpc, "sendrawtransaction", &[json!(raw_hex)]);
    let txid = txid.as_str().expect("broadcast txid").to_string();
    // Confirm in a block. The migration tx is federation-signed (not a wallet
    // tx), so query it by block hash rather than gettransaction.
    let mine_addr = call(&rpc, "getnewaddress", &[]);
    let blocks = call(&rpc, "generatetoaddress", &[json!(1), mine_addr]);
    let blockhash = blocks[0].as_str().expect("block hash");
    let mined = call(
        &rpc,
        "getrawtransaction",
        &[json!(txid), json!(true), json!(blockhash)],
    );
    assert_eq!(
        mined["txid"].as_str(),
        Some(txid.as_str()),
        "migration tx {txid} mined in block"
    );

    // The NEW federation receives the customer's full L-BTC + full asset.
    let spk = new_cust_dest.script_pubkey();
    let mut got_lbtc = 0u64;
    let mut got_asset = 0u64;
    for o in tx.output.iter().filter(|o| o.script_pubkey == spk) {
        let s = newc_w.unblind(o).unwrap();
        if s.asset == policy {
            got_lbtc = s.value;
        } else if s.asset == asset {
            got_asset = s.value;
        }
    }
    assert_eq!(got_asset, cust_asset_val, "customer asset migrated in full");
    assert_eq!(got_lbtc, cust_lbtc_val, "customer L-BTC migrated in full");
    eprintln!(
        "ASSET MIGRATION CONFIRMED: {txid} — new fed got {got_lbtc} sat L-BTC + {got_asset} asset units"
    );
}

/// Live regtest **multi-customer asset migration**: two customers holding
/// *different* amounts of the same asset are migrated in one account-for-account
/// transaction (fee account pays). Verifies each customer's new-federation
/// address receives **exactly its own amount** — i.e. per-customer counts are
/// preserved, not crossed or merged.
#[test]
#[allow(clippy::too_many_lines, clippy::similar_names)]
fn asset_migration_preserves_per_customer_amounts_live() {
    if skip() {
        return;
    }
    let rpc = wallet_client();
    let net = ElementsNetwork::ElementsRegtest;

    let issue = call(&rpc, "issueasset", &[json!(1000), json!(0)]);
    let asset_hex = issue["asset"].as_str().expect("asset id").to_string();
    let asset = elements::AssetId::from_str(&asset_hex).unwrap();
    mine(&rpc);

    let genesis =
        elements::BlockHash::from_str(call(&rpc, "getblockhash", &[json!(0)]).as_str().unwrap())
            .unwrap();
    let side = call(&rpc, "getsidechaininfo", &[]);
    let policy = elements::AssetId::from_str(side["pegged_asset"].as_str().unwrap()).unwrap();
    let lwk_net = ElementsNetwork::custom_regtest(policy, genesis);

    // Old fed: fee account + two asset-only customers. New fed: rotated dests.
    let (fee_sgn, fee_w) = fed_wollet([1, 2, 3], 0xa1, net, lwk_net);
    let (a_sgn, a_w) = fed_wollet([4, 5, 6], 0xb2, net, lwk_net);
    let (b_sgn, b_w) = fed_wollet([7, 8, 9], 0xc3, net, lwk_net);
    let (_na_sgn, na_w) = fed_wollet([10, 11, 12], 0xd4, net, lwk_net);
    let (_nb_sgn, nb_w) = fed_wollet([13, 14, 15], 0xe5, net, lwk_net);
    let (_nf_sgn, nf_w) = fed_wollet([16, 17, 18], 0xf6, net, lwk_net);

    let ext = lwk_wollet::Chain::External;
    let fee_addr = fee_w.address(ext, 0).unwrap();
    let a_addr = a_w.address(ext, 0).unwrap();
    let b_addr = b_w.address(ext, 0).unwrap();
    let a_dest = na_w.address(ext, 0).unwrap();
    let b_dest = nb_w.address(ext, 0).unwrap();
    let fee_dest = nf_w.address(ext, 0).unwrap();

    // Fund: fee 1.0 L-BTC; customer A 120 units; customer B 305 units (distinct).
    let fee_txid = call(
        &rpc,
        "sendtoaddress",
        &[json!(fee_addr.to_string()), json!(1.0)],
    )
    .as_str()
    .unwrap()
    .to_string();
    let a_txid = send_asset(&rpc, &a_addr.to_string(), 120, &asset_hex);
    let b_txid = send_asset(&rpc, &b_addr.to_string(), 305, &asset_hex);
    mine(&rpc);

    let wid = WalletId::from_bytes([6; 16]);
    let cap = |w: &ElementsWollet, txid: &str, addr: &elements::Address, idx: u32| {
        let (vout, txout) = find_output(&rpc, txid, &addr.script_pubkey());
        captured_from_output(
            w,
            elements::Txid::from_str(txid).unwrap(),
            vout,
            &txout,
            wid,
            idx,
        )
        .expect("capture")
    };
    let fee_utxo = cap(&fee_w, &fee_txid, &fee_addr, 0);
    let a_utxo = cap(&a_w, &a_txid, &a_addr, 0);
    let b_utxo = cap(&b_w, &b_txid, &b_addr, 0);
    let a_val = a_utxo.value();
    let b_val = b_utxo.value();
    assert_ne!(a_val, b_val, "the two customers hold different amounts");

    let inputs = vec![(fee_utxo, &fee_w), (a_utxo, &a_w), (b_utxo, &b_w)];
    let recipients = vec![
        (a_dest.clone(), a_val, asset),
        (b_dest.clone(), b_val, asset),
    ];
    let blinded = build_migration_pset(&fee_w, &inputs, &recipients, &fee_dest, 1000.0).unwrap();

    let mut pset = blinded.into_pset();
    for s in fee_sgn
        .iter()
        .take(2)
        .chain(a_sgn.iter().take(2))
        .chain(b_sgn.iter().take(2))
    {
        s.sign_pset(&mut pset).unwrap();
    }
    finalize_p2wsh_pset(&mut pset).unwrap();
    let tx = pset.extract_tx().unwrap();
    let raw_hex = elements::encode::serialize_hex(&tx);

    let txid = call(&rpc, "sendrawtransaction", &[json!(raw_hex)])
        .as_str()
        .unwrap()
        .to_string();
    let mine_addr = call(&rpc, "getnewaddress", &[]);
    let blocks = call(&rpc, "generatetoaddress", &[json!(1), mine_addr]);
    let blockhash = blocks[0].as_str().unwrap();
    let mined = call(
        &rpc,
        "getrawtransaction",
        &[json!(txid), json!(true), json!(blockhash)],
    );
    assert_eq!(
        mined["txid"].as_str(),
        Some(txid.as_str()),
        "migration mined"
    );

    // Each customer's new-fed address receives EXACTLY its own amount.
    let got = |w: &ElementsWollet, dest: &elements::Address| -> u64 {
        let spk = dest.script_pubkey();
        tx.output
            .iter()
            .filter(|o| o.script_pubkey == spk)
            .filter_map(|o| w.unblind(o).ok())
            .find(|s| s.asset == asset)
            .map_or(0, |s| s.value)
    };
    let a_got = got(&na_w, &a_dest);
    let b_got = got(&nb_w, &b_dest);
    assert_eq!(a_got, a_val, "customer A amount preserved");
    assert_eq!(b_got, b_val, "customer B amount preserved");
    assert_ne!(a_got, b_got, "amounts stayed distinct (not crossed/merged)");
    eprintln!(
        "MULTI-CUSTOMER MIGRATION CONFIRMED: {txid} — A={a_got}, B={b_got} (distinct, preserved)"
    );
}
