# Changelog

All notable changes to `emvault-elements` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

## [0.12.0] - 2026-11-24

Supersedes **0.11.0, which is yanked**. The source is identical to 0.11.0; the version moves so
every inter-crate requirement in the suite resolves at one *resolvable* version (see
`emvault-pkcs11` 0.12.0 for this round's change).

## [0.11.0] - 2026-11-24

Released in lockstep with the suite. No functional change in this crate; the version
moves so every inter-crate requirement in the suite resolves at one version (see
`emvault-pkcs11` 0.11.0 for this round's change).

## [0.10.0] - 2026-08-28

### Changed
- Released in lockstep with the suite-wide **0.10.0** (`emvault-core` F1/F4/F2 Taproot signing/verification + config-auth security hardening). No functional changes to this crate; rebuilt against `emvault-core` 0.10.0.

## [0.9.0] - 2026-08-21

### Added
- `build_asset_spend_pset` — build a PSET spending a **non-L-BTC Liquid asset**
  to a recipient (L-BTC still pays the network fee), with an offline unit test
  and a gated live-regtest e2e.

### Changed
- **BREAKING:** federation migration is now **asset-aware**. The sweep planner
  emits one recipient per held asset and `build_migration_pset` (and the
  per-asset sweep API) take `(Address, u64, AssetId)` recipients, so a migration
  carries L-BTC **and** every issued asset to the successor in a single
  transaction. Callers building migration sweeps must now supply the asset id.

### Tested
- Live regtest e2e: asset send, full-balance asset drain (asset "Max", no change
  output), and single- + multi-customer asset migration with per-customer amount
  preservation.

## [0.8.0] - 2026-08-16

### Changed
- Released in lockstep with the suite-wide v0.8.0; no functional changes to
  `emvault-elements`. Confidential Taproot (`ct(slip77(...), eltr(NUMS,
  multi_a(...)))`) is planned but gated on upstream Liquid Wallet Kit
  taproot-multisig support.

## [0.7.0] - 2026-08-03

### Added
- Nodeless sync backends (new `nodeless` module): drive Elements/Liquid wallet
  sync over LWK's blockchain clients with no local `elementsd` — Electrum,
  Esplora, and Waterfalls — behind the `electrum` / `esplora` / `nodeless`
  features. Brings the Liquid side to chain-backend parity with Bitcoin.
- Authenticated Esplora/Waterfalls constructors (`TokenProvider`) for
  Blockstream enterprise endpoints (OAuth), so the served liquidtestnet
  enterprise tier can be used directly without a proxy or fork.
- Nodeless `tip_height()` on the wollet — read the chain tip from the active
  backend without an RPC node.
- Elements roster-reuse + migration-planning layer (`SweepAlgorithm` /
  `MigrationPlan`), mirroring the Bitcoin side, for federation migrations.

### Changed
- Documentation updates.
- Released in lockstep with the suite-wide v0.7.0 update.

## [0.6.0] - 2026-07-29

### Changed
- Released in lockstep with the suite-wide reorg-reconciliation update (v0.6.0).
- Documentation updates.

## [0.5.0] - 2026-07-27

### Changed
- Dependency and lockfile refresh; version realigned across the emvault suite.

## [0.4.0] - 2026-07-22

### Changed
- Release-metadata bump only (no functional changes).

## [0.3.0] - 2026-07-13

### Changed
- Documentation and release-metadata updates only.
