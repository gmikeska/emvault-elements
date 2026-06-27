# asterism-elements

Elements/Liquid support for the Emerald multi-signature custody platform.

`asterism-elements` is the confidential-transaction (CT) companion to
[`asterism-core`](https://github.com/gmikeska/asterism-core). Where
`asterism-core` covers Bitcoin federations, this crate adds the Elements/Liquid
surface: confidential descriptors, the PSET signing pipeline, a client-side
wallet, and the daemon RPC transport.

Unlike `asterism-core`, this crate is intentionally **"thicker"**: because the
Elements daemon-wallet model does not scale, UTXO capture is done client-side
here, via a descriptor-driven wollet plus a shared block-scan pipeline.
Persistence (the database) remains the consuming application's responsibility.

## What's in the box

| Module | Purpose |
| ------ | ------- |
| [`network`](src/network.rs) | `ElementsNetwork` — network enum with LWK + address parameters. |
| [`descriptor`](src/descriptor.rs) | `CtDescriptorBuilder` — builds `ct(slip77(...), elwsh(sortedmulti(...)))` confidential descriptors from [`asterism_core::Signer`] instances. |
| [`signer`](src/signer.rs) | `ElementsSigner` — trait for producing ECDSA partial signatures over PSET inputs. |
| [`pset`](src/pset.rs) | PSET pipeline: blinding, signing coordination, finalization (mirrors `asterism_core::psbt` with an Elements blinding stage). |
| [`confidential`](src/confidential.rs) | Defense-in-depth validation for blinded PSETs (range/surjection-proof + blinder-index checks). |
| [`spend`](src/spend.rs) | Spend-path construction: captured UTXOs → blinded, signable PSET (spend / sweep / migration). |
| [`wollet`](src/wollet.rs) | `ElementsWollet` — client-side wallet wrapping `lwk_wollet::Wollet` for address derivation + unblinding. |
| [`sync`](src/sync.rs) | Shared block-scan pipeline: DB-agnostic stores, chain-source transport, and `BlockScanEngine`. |
| [`federated_wallet`](src/federated_wallet.rs) | `ElementsFederatedWallet` — version-aware federated wallet. |
| [`rpc`](src/rpc.rs) | `ElementsRpc` — thin `bitcoincore_rpc` wrapper for the Elements daemon's CT-aware JSON-RPC calls. |
| [`error`](src/error.rs) | `thiserror`-derived error types (`PsetError`, `CtDescriptorError`, `SpendError`, `SyncError`, `WolletError`). |

## Relationship to the rest of the family

```
asterism-core ──(Signer, Federation, descriptor traits)──► asterism-elements
                                                               │
                                          ct(slip77, elwsh(sortedmulti)))
                                          PSET blind → sign → finalize
                                          client-side wollet + block-scan
```

Signers come from the backend crates and implement `asterism_core::Signer`:
[`asterism-pkcs11`](https://github.com/gmikeska/asterism-pkcs11) for HSMs and
[`asterism-xpub`](https://github.com/gmikeska/asterism-xpub) for consumer
hardware wallets. The Elements signing path (`ElementsSigner`) is wired into the
HSM backend when `asterism-pkcs11` is built with its `elements` feature.

## Cargo features

| Feature | Default | Effect |
| ------- | ------- | ------ |
| `test-utils` | off | Exposes the in-memory sync fakes (`MemBlockStore`, `MemUtxoStore`, `MockChainSource`) for downstream test suites. |

## Build and test

```sh
cargo build
cargo test
cargo test --features test-utils
cargo clippy --all-targets -- -D warnings -W clippy::pedantic
cargo doc --no-deps
```

## License

MIT OR Apache-2.0.
