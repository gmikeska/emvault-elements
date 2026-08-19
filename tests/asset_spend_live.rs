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
    ElementsWollet, build_asset_spend_pset, captured_from_output, elements, finalize_p2wsh_pset,
    lwk_wollet,
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
