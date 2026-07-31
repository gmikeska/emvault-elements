# Plan: Nodeless (Electrum + Esplora + Waterfalls) chain backends for `emvault-elements`

Status: **approved — decisions locked 2026-07-31** · Scope: **chain-backend layer only** (no GroupVault) · Author: Maggie

## 0. Locked decisions (Greg, 2026-07-31)

1. **One single `emvault-elements` crate** — the nodeless backends live inside it behind
   cargo features; no sibling crates.
2. **App coverage:** `test-app-electrum` = **electrum only**; `test-app-pkcs11` = **both**
   (electrum + esplora, incl. waterfalls).
3. **Implement waterfalls** — via lwk's `EsploraClient::new_waterfalls` (a constructor mode
   of the esplora backend, not a separate backend).
4. **Reorg = checkpoint-compare** (matches `emvault-electrum`).
5. **RPC block-scan stays the default** — nodeless strictly opt-in via feature.
6. **Lean hard on `lwk_wollet`** — it provides the scan + unblind + reorg; we take full
   advantage rather than hand-rolling.

## 1. Goal & scope

Add **two nodeless chain backends — Esplora (incl. Waterfalls) and Electrum — to the
Elements side of the emvault crate system**, both **reorg-correct**, as peers to the
existing elementsd **RPC block-scan**. Exercise and prove them through two reference apps:

- **`test-app-electrum`** → **electrum only** (mirrors its Bitcoin path, which already uses
  `emvault-electrum`). After this, the app is electrum on *both* chains.
- **`test-app-pkcs11`** → **both nodeless backends** — electrum **and** esplora/waterfalls
  (mirrors its Bitcoin path, which already has `APP_CHAIN_BACKEND = rpc|esplora|waterfalls`),
  so it's the full-coverage proving ground for the whole nodeless Elements layer.

**Out of scope for this plan:** GroupVault wiring, UI, deploy. This is purely the
`emvault-elements` chain layer + the two test apps that validate it.

## 2. Where we are today (grounded)

Elements sync in the crate is **block-oriented**:

- `sync::ElementsChainSource` — `tip_height()`, `block_hash(height)`, `block(hash)->Block`,
  `broadcast(tx)`; whole-block download.
- `sync::scan::BlockScanEngine` — walks last-synced→tip, matches `ElementsWollet::watched_scripts()`,
  unblinds, upserts `CapturedUtxo` into `WalletUtxoStore`, records hashes in `BlockStore`,
  and rolls back on reorg → `SyncResult.reorg_to: Option<u32>` (common-ancestor walk).
- `rpc::ElementsRpc` is the only `ElementsChainSource` impl.

Both apps already carry the full Elements plumbing and are **RPC-only** for Liquid:

- `elements_sync.rs`: `PgBlockStore` (`BlockStore`), `PgWalletUtxoStore` (`WalletUtxoStore`),
  `RpcChainSource` (`ElementsChainSource`). **Identical between the two apps.**
- `test-app-electrum/elements_ingest.rs` already logs `reorg_to` from `SyncResult` — the
  reorg signal is already surfaced end-to-end; the RPC path acts on it, the new backends
  must produce the same signal.
- `test-app-pkcs11/config.rs`: `ChainBackend { Rpc, Esplora, Waterfalls }` from
  `APP_CHAIN_BACKEND` — but **only the Bitcoin path honors it; Elements is hard-wired to RPC.**

## 3. The crux — and why esplora+electrum are ONE piece of work

Electrum (`scripthash.get_history`) and Esplora (`GET /address/:h/txs`) are both
**address/scripthash-oriented**, not block-oriented. Neither maps onto the block-based
`ElementsChainSource`/`BlockScanEngine` — same reason `emvault-electrum`/`emvault-esplora`
are *separate* paths from Bitcoin Core on the BTC side, not adapters over it.

The decisive fact: **`lwk_wollet` is already a dependency and re-export** (`Cargo.toml:20`,
`lib.rs:92`), and it ships **both** Liquid clients — `ElectrumClient` (feature `electrum`,
`lib.rs:161`) and `EsploraClient` (feature `esplora`, `lib.rs:168`) — and **both implement
the same `BlockchainBackend::full_scan()` trait**, which does the scripthash scan **plus
confidential unblinding plus reorg reconciliation** against an `lwk_wollet::Wollet`. That
`Wollet` is exactly what `ElementsWollet` already holds (`wollet.rs:29 inner: Wollet`,
doc: *"held for future use"*).

**Waterfalls rides the same client.** lwk exposes `EsploraClient::new_waterfalls(url,
network)` (`clients/blocking/esplora.rs:47`) and a `.waterfalls(true)` builder
(`clients/mod.rs:102`) — the Blockstream one-query-per-descriptor endpoint — as a
*constructor mode* of the very same `EsploraClient`, with the same `full_scan` and reorg
path. So waterfalls is a URL/flag choice, not a third code path.

So the work is **one nodeless scan engine generic over lwk's `BlockchainBackend`**, with thin
client constructors (electrum URL / esplora URL / waterfalls URL) behind cargo features.
Electrum, esplora, and waterfalls share the scan, the UTXO projection, and the reorg logic —
they differ only in which lwk client is constructed. Unblinding and reorg are solved once, by
lwk, for all three.

> **Security constraint (waterfalls only):** lwk refuses waterfalls when the CT descriptor
> uses **elip151** deterministic blinding (`error.rs:217 UsingWaterfallsWithElip151`) — the
> descriptor endpoint would reveal the blinding key to the server. Waterfalls therefore
> requires an explicit / SLIP77 blinding-key mode. We must check `CtKeyMode` on the wallet's
> descriptor before allowing waterfalls, and surface a clear error otherwise. Plain esplora
> and electrum are unaffected.

## 4. Approach (chosen) + rejected alternatives

**Chosen — wrap lwk's `BlockchainBackend` (both clients) against `ElementsWollet::inner`,
one generic engine, two features:**

```rust
// new: src/nodeless/mod.rs   (shared engine + projection + checkpoints)
//      src/nodeless/electrum.rs  (feature "electrum": constructs lwk ElectrumClient)
//      src/nodeless/esplora.rs   (feature "esplora":  constructs lwk EsploraClient)

pub struct NodelessSync<B: lwk_wollet::BlockchainBackend> { client: B, checkpoints: ... }

impl<B: lwk_wollet::BlockchainBackend> NodelessSync<B> {
    /// full_scan the wollet, project unspent -> CapturedUtxo, drive the store,
    /// emit reorg_to for the caller. Identical for electrum & esplora.
    pub fn sync(
        &mut self,
        wollet: &mut ElementsWollet,
        store: &mut dyn WalletUtxoStore,
    ) -> Result<SyncResult, SyncError>;

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, SyncError>;
}

// constructors
ElementsElectrumSync::new(url, network)          -> NodelessSync<ElectrumClient>  // feature electrum
ElementsEsploraSync::new(base_url, network)      -> NodelessSync<EsploraClient>   // feature esplora
ElementsEsploraSync::new_waterfalls(url, network)-> NodelessSync<EsploraClient>   // feature esplora (waterfalls mode)
```

| | Alternative | Verdict |
|---|---|---|
| B | Separate sibling crates `emvault-elements-esplora` / `-electrum` (mirror the Bitcoin crate split) | **Rejected (decision #1).** lwk unifies all three Liquid clients, so a split duplicates the same glue. Single crate + features. |
| C | Hand-roll scripthash/esplora clients + our own `confidential.rs` unblind | Rejected. Re-implements lwk's Liquid unblind/gap-limit/reorg we already ship (decision #6: lean on lwk). |
| D | Implement `ElementsChainSource::block()` over electrs/esplora REST, reuse `BlockScanEngine` | Rejected. Whole-block pulls kill the privacy/nodeless win. |

## 5. The real work: UTXO-model reconciliation (shared by both backends)

lwk keeps state inside its `Wollet` and exposes UTXOs as `lwk_wollet::WalletTxOut` after a
scan; our whole downstream (`spend.rs`, `pset.rs`, `federated_wallet.rs`, both apps' PSET
pipelines) speaks `CapturedUtxo` + `WalletUtxoStore`. So after each `full_scan` we **project
lwk's unspent set into `CapturedUtxo` and drive the existing store** — keeping `CapturedUtxo`
the single internal currency so **spend/PSET/migration/sweep code needs zero changes**.

Per unspent `WalletTxOut`:
- `outpoint` ← `WalletTxOut.outpoint`
- `witness_utxo` ← confidential `TxOut`
- `secrets: TxOutSecrets` ← `WalletTxOut.unblinded` (lwk already unblinded)
- `height` ← `WalletTxOut.height` (`None` = mempool)

`PgWalletUtxoStore` is reused **unchanged** in both apps. `PgBlockStore` (block-hash chain)
is only needed by the block-scan engine; the nodeless path instead needs a **thin checkpoint
store** (§6) — a few height→hash rows, either a new small table or reuse of the existing
block-hash rows.

## 6. Reorg support (parity with RPC + `emvault-electrum`)

The RPC path emits `SyncResult.reorg_to`; the Bitcoin `emvault-electrum` crate has
`ElectrumSyncResult` reorg detection with a `tests/live_reorg.rs`. The nodeless Elements
path must emit the **same `reorg_to`** so both apps' ingest (which already logs it) can act
identically.

lwk's `full_scan` reconciles reorgs internally (rewrites txs whose height changed). To
surface an explicit `reorg_to` we keep a **thin height→blockhash checkpoint map** and compare
each sync (the model `emvault-electrum` already uses), rather than inferring from UTXO deltas
— gives an explicit rollback height and drives `WalletUtxoStore` rollback when a confirmed
outpoint regresses. This checkpoint compare is the one genuinely new bit of logic; it is
written **once** and serves both electrum and esplora.

## 7. `emvault-elements` API + features

```toml
[features]
default = []                          # RPC block-scan stays the only default path (decision #5)
electrum = ["lwk_wollet/electrum"]    # pulls lwk's electrum-client transitively
esplora  = ["lwk_wollet/esplora"]     # plain esplora AND waterfalls (same client, new_waterfalls ctor)
nodeless = ["electrum", "esplora"]
```

(No separate `waterfalls` feature — it's a constructor on the esplora client, decision #3.)

Re-export `NodelessSync`, `ElementsElectrumSync`, `ElementsEsploraSync`, reusing the existing
`SyncResult`, `CapturedUtxo`, `WalletUtxoStore`, `SyncError`. **Existing consumers are
untouched unless they opt into a feature.**

## 8. Test-app wiring (the acceptance vehicles)

**Shared prerequisite — give the Elements path a backend selector** (it currently has none).
Add `ELEMENTS_CHAIN_BACKEND` (or extend the app's existing `ChainBackend`) so the Elements
sync picks `rpc | electrum | esplora | waterfalls`, exactly like the Bitcoin path already does.
Both apps keep `PgWalletUtxoStore` as-is.

- **`test-app-electrum`** → **electrum only.** Wire `ElementsElectrumSync` against the
  electrs-liquid electrum endpoint `10.44.0.1:60101` (liquidtestnet). Its `elements_ingest.rs`
  already surfaces `reorg_to`; extend it to drive store rollback on reorg. Selector accepts
  `rpc | electrum`. After this, the app is electrum on *both* chains.
- **`test-app-pkcs11`** → **both nodeless backends + waterfalls.** Wire `ElementsElectrumSync`
  **and** `ElementsEsploraSync` (plain + `new_waterfalls`), selector `rpc | electrum | esplora
  | waterfalls`, mirroring its Bitcoin `APP_CHAIN_BACKEND`. This is the full-coverage app.
  Esplora/waterfalls target: the **same electrs-liquid box also serves an esplora-compatible
  REST API on `127.0.0.1:3102`** (expose over the WG tunnel) — Blockstream electrs supports
  the waterfalls descriptor endpoint — so **one electrs-liquid serves electrum + esplora +
  waterfalls**. Public `…/liquidtestnet/api` is the fallback. Waterfalls requires a non-elip151
  descriptor (see §3 constraint) — assert the app's CT key mode is compatible before offering it.

Cross-backend equivalence is the headline assertion: for the same wallet, the
electrum / esplora / waterfalls `CapturedUtxo` set must match the RPC path's capture.

## 9. Phased work

1. **Features + engine skeleton** — add `electrum`/`esplora` features (flip lwk's), add the
   `inner` accessor on `ElementsWollet`, stand up `NodelessSync<B>` generic over
   `BlockchainBackend`. Confirm it builds with each lwk client.
2. **UTXO projection** (§5) — `WalletTxOut → CapturedUtxo`, drive `WalletUtxoStore`.
   Unit-test the projection against a known unblinded output.
3. **Reorg checkpoints** (§6) — checkpoint store + compare → populate `reorg_to`, trigger
   store rollback. Unit-test with a simulated header-hash change.
4. **Broadcast** — via each lwk client.
   Add `new_waterfalls` constructor + the §3 elip151 guard.
5. **test-app-electrum (electrum only)** — Elements backend selector (`rpc | electrum`) +
   `ElementsElectrumSync` wired to `10.44.0.1:60101`; ingest acts on `reorg_to`. Live test on
   liquidtestnet: fund a CT address, sync, assert capture == RPC path, spend, and a
   reorg-parity check (deterministic reorg on the elementsregtest / gv-regtest elements stack).
6. **test-app-pkcs11 (both + waterfalls)** — Elements backend selector
   (`rpc | electrum | esplora | waterfalls`) + `ElementsElectrumSync` **and**
   `ElementsEsploraSync` (plain + waterfalls) wired to the electrs-liquid box; run the full
   acceptance battery (capture-equivalence, spend, reorg) across **all three** nodeless modes.
7. **Crate reorg tests** — mirror `emvault-electrum/tests/live_reorg.rs` for the Elements
   nodeless path (electrum + esplora + waterfalls), plus a checkpoint-compare unit test.

Testkit note: `emvault-elements/testkit.rs` + the elementsregtest harness can host steps 2–4
and the deterministic reorg without the VPS; the VPS electrs-liquid (electrum `:60101` + REST
`:3102`) is the liquidtestnet acceptance target for steps 5–6.

## 10. Resolved (was: open questions)

All six original open questions were answered by Greg on 2026-07-31 — see **§0 Locked
decisions**. Summary: single crate + features; electrum-app = electrum only, pkcs11-app =
both + waterfalls; implement waterfalls via lwk's `new_waterfalls`; checkpoint-compare reorg;
RPC stays default; lean on lwk.

**Remaining small verifications (not blockers — resolve during Phase 1):**

- **`BlockchainBackend` generics** — confirm lwk 0.18.1 lets us write one generic
  `NodelessSync<B: BlockchainBackend>` cleanly (blocking clients); if the trait isn't
  object-safe / uniformly bounded, fall back to two thin wrappers sharing a projection fn.
  Same end result, marginally more code.
- **CT key mode in the apps** — verify `test-app-pkcs11`'s Elements descriptors use a
  SLIP77/explicit blinding mode (not elip151) so waterfalls is actually usable there; if they
  default to elip151, waterfalls is offered only for compatible wallets (plain esplora +
  electrum remain universal).
- **electrs-liquid waterfalls endpoint** — confirm the Blockstream electrs build we shipped
  exposes the `/descriptor` waterfalls route on `:3102`; if not, plain esplora still works and
  waterfalls points at Blockstream's hosted enterprise endpoint.
```