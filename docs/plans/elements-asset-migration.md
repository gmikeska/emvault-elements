# Plan: Asset-aware Elements federation migration (pkcs11 app)

## Problem / assessment

Federation migration on the Elements side is **L-BTC-only**. A federation holding any
non-L-BTC Liquid asset cannot migrate it to the new federation. Three layers are affected:

1. **Model** — `migration.rs`: `ElementsAccountUtxoSet::total_value_sat()` sums *every*
   UTXO's value regardless of asset (mixes asset units with L-BTC sats).
   `ElementsSweepOutput::Customer { account_idx, address, amount_sat }` carries no asset.
2. **Builder** — `spend.rs::build_migration_pset`: emits only `add_lbtc_recipient(addr, amt)`
   per account + `drain_lbtc_wallet()/drain_lbtc_to(fee_dest)` for the fee account.
3. **Executor** — `test-app-pkcs11/examples/federation_migration.rs`: feeds each account's
   full UTXO set (all assets) into the L-BTC-only builder, one `(dest, amount)` per account.

**Consequence:** Elements txs must balance per-asset. An account holding asset X puts asset-X
inputs into a tx with no asset-X output ⇒ the migration **fails to build**; if only L-BTC UTXOs
were selected, the assets are **stranded on the old federation** after rotation.

## Design

**Invariant (account-for-account):** each account's *entire per-asset balance* — L-BTC plus
every asset it holds — moves to that account's **new-federation confidential address**. A
confidential address is asset-agnostic, so one dest address receives multiple outputs (one per
asset). The fee account pays the L-BTC mining fee **and** migrates its own assets.

**Fee rule:** the mining fee is subtracted only from the fee account's **L-BTC** (policy asset).
Every non-policy asset migrates in full — identical to the asset "Max" we just shipped.

### Change 1 — model (`emvault-elements/src/migration.rs`)
- `ElementsAccountUtxoSet`: add `balances_by_asset() -> BTreeMap<AssetId, u64>`; add
  `policy_value_sat(policy: AssetId)` (L-BTC only). Keep `total_value_sat` for callers that
  truly mean "policy asset," or deprecate it.
- `ElementsSweepOutput::Customer` gains `asset: AssetId`. Plans now emit **one Customer output
  per (account, asset)**.
- `ElementsAccountForAccountSweep` / `ElementsAccountForAccountBatchedSweep::plan`:
  - per account, one output per asset (amount = that asset's account total);
  - fee subtracted **only** from the fee account's policy-asset output;
  - batch sizing becomes output-count aware (each asset = one more blinded output + rangeproof,
    so accounts-per-batch shrinks as assets multiply). Keep each account **atomic** — never
    split one account's assets across two batch txs.

### Change 2 — builder (`emvault-elements/src/spend.rs`)
- `build_migration_pset` becomes asset-aware: `customer_recipients: &[(Address, u64, AssetId)]`
  (one entry per account×asset). For each, `add_recipient(addr, amount, asset)` (policy asset can
  still go through `add_lbtc_recipient`; `add_recipient` with the policy id works uniformly).
- Fee account: keep `drain_lbtc_wallet()/drain_lbtc_to(fee_dest)` for its L-BTC (change − fee).
  Its **non-policy** assets are passed in `customer_recipients` with `addr = fee_dest` so they
  migrate too (otherwise unbalanced/stranded).
- L-BTC-only migration is just the special case where every per-asset list is `[policy]`.

### Change 3 — executor (`test-app-pkcs11/examples/federation_migration.rs`)
- When assembling recipients, compute each account's per-asset balances (group its UTXOs by
  `CapturedUtxo::asset()`) and push `(dest, amount, asset)` per asset.
- Fee account: push its non-policy assets as `(fee_dest, amount, asset)`; L-BTC via the drain.
- Batched mode: only the fee account's **L-BTC** change is chained across batches
  (`captured_from_output`); assets are fully moved within the tx where they appear. Ensure an
  account's asset outputs all land in the same batch (atomicity).

### Change 4 — verification (`examples/migration_verify.rs`)
- Verify **per-asset** balances migrated: each account's assets present on the new fed, zero on
  the old; L-BTC reconciles minus cumulative fee.

### Change 5 — tests
- Extend `tests/elements_migration_hsm_signing.rs` + `elements_migration_hsm_e2e.rs`: an account
  holding a non-L-BTC asset migrates it (asset output present, fee still L-BTC), multi-account
  signs scoped.
- New live regtest e2e (mirrors `tests/asset_spend_live.rs`): issue asset, fund old-fed accounts
  with asset + L-BTC, run the migration, assert assets land on the new fed and old fed is empty.

## Phasing
1. Model + planner (Change 1) with unit tests on the per-asset plan math.
2. Builder (Change 2) with an offline multi-asset migration unit test (extend
   `spend.rs::migration_*` tests to carry an asset).
3. Executor (Change 3) + verify (Change 4).
4. Live regtest asset-migration e2e (Change 5).
5. fmt + clippy-pedantic gate; hand Greg staged diffs (crate = Greg commits/republishes).

## Progress (2026-08-19)
- ✅ **Phase 1 — model + planners** (`migration.rs`): `balances_by_asset`/`policy_value_sat`;
  `Customer`/`FeeChange` carry `asset`; both sweep algorithms take a `policy_asset` and emit one
  output per (account, asset); fee subtracted only from the fee account's policy asset; fee
  account's own assets swept in the final batched tx; output-count-aware fee sizing. 17 unit tests
  (incl. 4 new asset cases) pass; clippy-pedantic clean.
- ✅ **Phase 2 — builder** (`spend.rs`): `build_migration_pset` now takes
  `&[(Address, u64, AssetId)]` and uses `add_recipient(addr, amt, asset)` (breaking → **0.9.0**).
  New offline test `migration_moves_asset_and_lbtc` (asset + L-BTC migrate together, 2-of-3
  finalize); existing migration tests updated to the 3-tuple API. clippy-pedantic clean (default
  + `test-utils`).
- ⏳ **Phase 3 — executor** (`examples/federation_migration.rs`) + the two migration HSM test
  files (`tests/elements_migration_hsm_signing.rs`, `elements_migration_hsm_e2e.rs`). The app does
  **not compile** against the new crate API until this lands. Executor work: pass `policy_asset`
  (`lwk_net.policy_asset()`) to the sweep constructors; dedup each account's inputs (now multiple outputs
  per account); build per-asset `(dest, amount, asset)` recipients; add the fee account's
  non-policy `FeeChange` outputs as recipients to the fee dest in the final tx.
- ⏳ **Phase 4 — verify** (`migration_verify.rs`): per-asset checks.
- ⏳ **Phase 5 — live regtest asset-migration e2e**.

## Republish note
This changes `emvault-elements` **public API** (migration builder signature + `Customer` variant).
Bundle with the pending **0.8.1** (or **0.9.0** if we treat the signature change as breaking).

## Open questions (for Greg)
1. **Builder API:** extend `build_migration_pset` (one builder, per-asset recipients) vs. add a
   parallel `build_asset_migration_pset`? (Rec: extend.)
2. **Fee-account assets** migrate in the same run? (Rec: yes — else stranded.)
3. **Batch granularity:** keep each account atomic; shrink accounts-per-batch as asset count
   grows. Any hard per-tx output/size cap to respect?
4. **Fee subtraction** only from the fee account's L-BTC; assets always migrate in full — confirm.
5. **Scope:** Elements-only (Bitcoin untouched), via the `federation_migration` tool (no new app
   UI) — confirm.
6. **Asset set:** data-driven from the accounts' UTXOs (no allow/deny list) — confirm.
7. **Republish:** OK to bundle the API change into 0.8.1 (or bump 0.9.0 if breaking)?
