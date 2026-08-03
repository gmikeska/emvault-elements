# Changelog

All notable changes to `emvault-elements` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

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
