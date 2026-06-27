//! Thin wrapper around `bitcoincore_rpc::Client` for Elements-specific RPC
//! calls. Elements extends Bitcoin Core's JSON-RPC interface; basic calls
//! (`sendrawtransaction`, `getblockcount`) are byte-compatible, but wallet
//! calls return CT-specific fields that `bitcoincore-rpc`'s types don't
//! cover. We use `RpcApi::call` with custom deserialize targets.
//!
//! Any Elements consumer that talks to a node daemon needs these calls; the
//! types below are deserialize targets mirroring the daemon's JSON-RPC results.

// This module is a 1:1 transport binding over the Elements daemon's JSON-RPC
// surface: methods map to named RPC calls and the structs are deserialize
// targets for their responses. Per-method / per-field doc comments would
// restate the RPC names without adding insight, so `missing_docs` is allowed
// here (the crate warns it elsewhere).
#![allow(missing_docs)]

use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum ElementsRpcError {
    #[error("RPC error: {0}")]
    Rpc(#[from] bitcoincore_rpc::Error),
    #[error("unexpected RPC response: {0}")]
    BadResponse(String),
}

pub struct ElementsRpc {
    base_url: String,
    user: String,
    password: String,
}

impl ElementsRpc {
    #[must_use]
    pub fn new(base_url: &str, user: &str, password: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        }
    }

    fn client_for_wallet(&self, wallet: &str) -> Result<RpcClient, ElementsRpcError> {
        let url = format!("{}/wallet/{wallet}", self.base_url);
        let auth = Auth::UserPass(self.user.clone(), self.password.clone());
        Ok(RpcClient::new(&url, auth)?)
    }

    fn base_client(&self) -> Result<RpcClient, ElementsRpcError> {
        let auth = Auth::UserPass(self.user.clone(), self.password.clone());
        Ok(RpcClient::new(&self.base_url, auth)?)
    }

    pub fn get_block_count(&self) -> Result<u64, ElementsRpcError> {
        let client = self.base_client()?;
        Ok(client.get_block_count()?)
    }

    pub fn create_wallet(&self, name: &str) -> Result<(), ElementsRpcError> {
        let client = self.base_client()?;
        let _: Value = client.call(
            "createwallet",
            &[
                json!(name),
                json!(true),  // disable_private_keys
                json!(true),  // blank
                json!(""),    // passphrase
                json!(false), // avoid_reuse
                json!(true),  // descriptors
            ],
        )?;
        Ok(())
    }

    pub fn load_wallet(&self, name: &str) -> Result<(), ElementsRpcError> {
        let client = self.base_client()?;
        let _: Value = client.call("loadwallet", &[json!(name)])?;
        Ok(())
    }

    pub fn list_wallets(&self) -> Result<Vec<String>, ElementsRpcError> {
        let client = self.base_client()?;
        Ok(client.call("listwallets", &[])?)
    }

    pub fn list_wallet_dir(&self) -> Result<Vec<String>, ElementsRpcError> {
        let client = self.base_client()?;
        let raw: Value = client.call("listwalletdir", &[])?;
        let names = raw
            .get("wallets")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(names)
    }

    pub fn ensure_wallet_loaded(&self, name: &str) -> Result<(), ElementsRpcError> {
        let loaded = self.list_wallets()?;
        if loaded.iter().any(|w| w == name) {
            return Ok(());
        }

        let on_disk = self.list_wallet_dir()?;
        if on_disk.iter().any(|w| w == name) {
            return self.load_wallet(name);
        }

        self.create_wallet(name)
    }

    pub fn get_descriptor_info(
        &self,
        descriptor: &str,
    ) -> Result<DescriptorInfo, ElementsRpcError> {
        let client = self.base_client()?;
        Ok(client.call("getdescriptorinfo", &[json!(descriptor)])?)
    }

    pub fn import_descriptors(
        &self,
        wallet: &str,
        descriptors: &[ImportDescriptorRequest],
    ) -> Result<Vec<ImportDescriptorResult>, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let descs_json: Vec<Value> = descriptors
            .iter()
            .map(|d| {
                json!({
                    "desc": d.descriptor,
                    "timestamp": "now",
                    "active": d.active,
                    "internal": d.internal,
                })
            })
            .collect();
        let results: Vec<ImportDescriptorResult> =
            client.call("importdescriptors", &[json!(descs_json)])?;
        Ok(results)
    }

    pub fn import_blinding_key(
        &self,
        wallet: &str,
        address: &str,
        blinding_key_hex: &str,
    ) -> Result<(), ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let _: Value = client.call(
            "importblindingkey",
            &[json!(address), json!(blinding_key_hex)],
        )?;
        Ok(())
    }

    pub fn dump_blinding_key(
        &self,
        wallet: &str,
        address: &str,
    ) -> Result<String, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let key: String = client.call("dumpblindingkey", &[json!(address)])?;
        Ok(key)
    }

    pub fn get_balances(&self, wallet: &str) -> Result<ElementsBalances, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let raw: Value = client.call("getbalances", &[])?;
        let mine = raw.get("mine").ok_or_else(|| {
            ElementsRpcError::BadResponse("getbalances missing 'mine' field".into())
        })?;
        let trusted = extract_btc_balance(mine.get("trusted"));
        let untrusted_pending = extract_btc_balance(mine.get("untrusted_pending"));
        let immature = extract_btc_balance(mine.get("immature"));
        Ok(ElementsBalances {
            trusted,
            untrusted_pending,
            immature,
        })
    }

    pub fn list_unspent(&self, wallet: &str) -> Result<Vec<ElementsUtxo>, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let utxos: Vec<ElementsUtxo> = client.call("listunspent", &[json!(0), json!(9_999_999)])?;
        Ok(utxos)
    }

    pub fn wallet_create_funded_psbt(
        &self,
        wallet: &str,
        outputs: &[Value],
        fee_rate_btc_per_kb: f64,
    ) -> Result<FundedPsbt, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let result: FundedPsbt = client.call(
            "walletcreatefundedpsbt",
            &[
                json!([]), // inputs (auto-select)
                json!(outputs),
                json!(0), // locktime
                json!({
                    "feeRate": fee_rate_btc_per_kb,
                }),
                json!(true), // bip32derivs
            ],
        )?;
        Ok(result)
    }

    pub fn wallet_create_funded_psbt_drain(
        &self,
        wallet: &str,
        outputs: &[Value],
        fee_rate_btc_per_kb: f64,
    ) -> Result<FundedPsbt, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let output_count = u32::try_from(outputs.len()).unwrap_or(u32::MAX);
        let output_indices: Vec<u32> = (0..output_count).collect();
        let result: FundedPsbt = client.call(
            "walletcreatefundedpsbt",
            &[
                json!([]),
                json!(outputs),
                json!(0),
                json!({
                    "feeRate": fee_rate_btc_per_kb,
                    "subtractFeeFromOutputs": output_indices,
                }),
                json!(true),
            ],
        )?;
        Ok(result)
    }

    pub fn list_transactions(
        &self,
        wallet: &str,
    ) -> Result<Vec<WalletTransaction>, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let txs: Vec<WalletTransaction> = client.call(
            "listtransactions",
            &[json!("*"), json!(9999), json!(0), json!(true)],
        )?;
        Ok(txs)
    }

    pub fn get_wallet_transaction_hex(
        &self,
        wallet: &str,
        txid: &str,
    ) -> Result<String, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let result: serde_json::Value = client.call("gettransaction", &[json!(txid)])?;
        result["hex"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| ElementsRpcError::BadResponse("gettransaction returned no hex".into()))
    }

    /// Create a funded PSET using the fee account's daemon wallet with
    /// explicit inputs (from multiple wallets) and fee subtracted only
    /// from the specified output index.
    pub fn wallet_create_funded_psbt_with_inputs(
        &self,
        wallet: &str,
        inputs: &[Value],
        outputs: &[Value],
        fee_subtract_output_index: usize,
        fee_rate_btc_per_kb: f64,
    ) -> Result<FundedPsbt, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let result: FundedPsbt = client.call(
            "walletcreatefundedpsbt",
            &[
                json!(inputs),
                json!(outputs),
                json!(0),
                json!({
                    "feeRate": fee_rate_btc_per_kb,
                    "subtractFeeFromOutputs": [fee_subtract_output_index],
                    "add_inputs": false,
                }),
                json!(true),
            ],
        )?;
        Ok(result)
    }

    /// Create a raw PSET with explicit inputs and outputs (no wallet context).
    pub fn create_psbt(
        &self,
        inputs: &[Value],
        outputs: &[Value],
    ) -> Result<String, ElementsRpcError> {
        let client = self.base_client()?;
        let result: String = client.call("createpsbt", &[json!(inputs), json!(outputs)])?;
        Ok(result)
    }

    /// Update a PSET with metadata from a specific daemon wallet (witness
    /// data, bip32 derivations) WITHOUT signing.
    pub fn wallet_update_psbt(
        &self,
        wallet: &str,
        psbt_base64: &str,
    ) -> Result<String, ElementsRpcError> {
        let client = self.client_for_wallet(wallet)?;
        let result: serde_json::Value = client.call(
            "walletprocesspsbt",
            &[json!(psbt_base64), json!(false), json!("ALL"), json!(true)],
        )?;
        result["psbt"].as_str().map(str::to_string).ok_or_else(|| {
            ElementsRpcError::BadResponse("walletprocesspsbt returned no psbt".into())
        })
    }

    pub fn send_raw_transaction(&self, hex: &str) -> Result<String, ElementsRpcError> {
        let client = self.base_client()?;
        let txid: Value = client.call("sendrawtransaction", &[json!(hex)])?;
        txid.as_str().map(str::to_string).ok_or_else(|| {
            ElementsRpcError::BadResponse("sendrawtransaction returned non-string".into())
        })
    }
}

fn extract_btc_balance(v: Option<&Value>) -> f64 {
    v.and_then(|obj| obj.get("bitcoin").and_then(Value::as_f64))
        .unwrap_or(0.0)
}

#[derive(Debug, Deserialize)]
pub struct DescriptorInfo {
    pub descriptor: String,
    pub checksum: String,
    #[serde(rename = "isrange")]
    pub is_range: bool,
    #[serde(rename = "issolvable")]
    pub is_solvable: bool,
    #[serde(rename = "hasprivatekeys")]
    pub has_private_keys: bool,
}

#[derive(Debug)]
pub struct ImportDescriptorRequest {
    pub descriptor: String,
    pub active: bool,
    pub internal: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportDescriptorResult {
    pub success: bool,
    #[serde(default)]
    pub error: Option<ImportDescriptorError>,
}

#[derive(Debug, Deserialize)]
pub struct ImportDescriptorError {
    pub code: i32,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ElementsBalances {
    pub trusted: f64,
    pub untrusted_pending: f64,
    pub immature: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ElementsUtxo {
    pub txid: String,
    pub vout: u32,
    pub address: Option<String>,
    pub amount: Option<f64>,
    pub asset: Option<String>,
    pub confirmations: u32,
    #[serde(default)]
    pub spendable: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletTransaction {
    pub txid: String,
    pub address: Option<String>,
    pub category: String,
    pub amount: Option<f64>,
    pub confirmations: Option<i64>,
    pub vout: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct FundedPsbt {
    pub psbt: String,
    pub fee: f64,
    pub changepos: i32,
}
