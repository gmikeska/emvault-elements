//! [`ElementsWollet`] — a client-side Elements wallet wrapping a
//! [`lwk_wollet::Wollet`] built from an [`ElementsWalletHandle`].
//!
//! This is the Elements analog of the Bitcoin side's `bdk_wallet::Wallet`. It
//! owns descriptor-driven **address/script derivation** and **unblinding**;
//! UTXO capture is performed by the shared block-scan pipeline (see
//! [`crate::sync`]) which feeds matched outputs back through
//! [`ElementsWollet::unblind`]. The `Wollet` instance is held for future use by
//! the spend path; persistence is owned by the consuming application, so the
//! wallet is built with LWK's default in-memory (`NoPersist`) store.

use std::str::FromStr;

use elements::{Address, Script, TxOut, TxOutSecrets};
use elements_miniscript::slip77::MasterBlindingKey;
use lwk_wollet::clients::try_unblind;
use lwk_wollet::{Chain, Wollet, WolletBuilder, WolletDescriptor};

use crate::descriptor::to_multipath_string;
use crate::error::WolletError;
use crate::federated_wallet::ElementsWalletHandle;
use crate::network::ElementsNetwork;

/// A client-side Elements wallet for a single federation version.
///
/// Construct one per [`ElementsWalletHandle`]. Cheap to query for scripts and
/// addresses; unblinding requires only the descriptor's embedded SLIP-77 key.
pub struct ElementsWollet {
    inner: Wollet,
    descriptor: WolletDescriptor,
    master_blinding_key: MasterBlindingKey,
    network: ElementsNetwork,
    lwk_network: lwk_wollet::Network,
}

impl std::fmt::Debug for ElementsWollet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElementsWollet")
            .field("network", &self.network)
            .field("descriptor", &self.descriptor.to_string())
            .finish_non_exhaustive()
    }
}

impl ElementsWollet {
    /// Build an `ElementsWollet` from a handle's confidential descriptor and
    /// blinding key.
    ///
    /// The handle's `ct_descriptor` is converted to a BIP-389 multipath
    /// (`/<0;1>/*`) descriptor so the wollet exposes both external (receive)
    /// and internal (change) chains.
    ///
    /// # Errors
    ///
    /// - [`WolletError::Descriptor`] if the descriptor cannot be parsed by LWK.
    /// - [`WolletError::Build`] if `WolletBuilder::build` fails.
    pub fn from_handle(
        handle: &ElementsWalletHandle,
        network: ElementsNetwork,
    ) -> Result<Self, WolletError> {
        let lwk_network = network.to_lwk();
        Self::from_handle_with_lwk(handle, network, lwk_network)
    }

    /// Like [`from_handle`](Self::from_handle) but with an explicit
    /// [`lwk_wollet::Network`] — required for a custom Elements regtest whose
    /// policy asset / genesis differ from LWK's defaults (see
    /// [`ElementsNetwork::custom_regtest`]).
    ///
    /// # Errors
    ///
    /// Same as [`from_handle`](Self::from_handle).
    pub fn from_handle_with_lwk(
        handle: &ElementsWalletHandle,
        network: ElementsNetwork,
        lwk_network: lwk_wollet::Network,
    ) -> Result<Self, WolletError> {
        let desc_str = to_multipath_string(&handle.ct_descriptor);
        Self::from_descriptor_str(&desc_str, handle.blinding_key, network, lwk_network)
    }

    /// Build directly from a stored BIP-389 multipath confidential descriptor
    /// string (`ct(slip77(..),elwsh(sortedmulti(..)))/<0;1>/*`) and its 32-byte
    /// SLIP-77 master blinding key. This is the reconstruction path used by the
    /// consuming application when loading a wallet from persistence.
    ///
    /// # Errors
    ///
    /// - [`WolletError::Descriptor`] if the string or blinding key is invalid.
    /// - [`WolletError::Build`] if `WolletBuilder::build` fails.
    pub fn from_descriptor_str(
        descriptor_str: &str,
        blinding_key: [u8; 32],
        network: ElementsNetwork,
        lwk_network: lwk_wollet::Network,
    ) -> Result<Self, WolletError> {
        let descriptor = WolletDescriptor::from_str(descriptor_str)
            .map_err(|e| WolletError::Descriptor(e.to_string()))?;

        let inner = WolletBuilder::new(lwk_network, descriptor.clone())
            .build()
            .map_err(|e| WolletError::Build(e.to_string()))?;

        let master_blinding_key = MasterBlindingKey::from_str(&hex32(&blinding_key))
            .map_err(|e| WolletError::Descriptor(format!("invalid blinding key: {e}")))?;

        Ok(Self {
            inner,
            descriptor,
            master_blinding_key,
            network,
            lwk_network,
        })
    }

    /// The watched script pubkeys for this wallet: external + internal chains,
    /// indices `0..gap`. This is what the block-scan engine indexes to match
    /// outputs. Returned as `(script_pubkey, chain, index)`.
    ///
    /// # Errors
    ///
    /// [`WolletError::AddressDerivation`] if any index fails to derive.
    pub fn watched_scripts(&self, gap: u32) -> Result<Vec<(Script, Chain, u32)>, WolletError> {
        let params = self.network.address_params();
        let mut out = Vec::with_capacity(gap as usize * 2);
        for i in 0..gap {
            let ext = self
                .descriptor
                .address(i, params)
                .map_err(|e| WolletError::AddressDerivation(e.to_string()))?;
            out.push((ext.script_pubkey(), Chain::External, i));

            let int = self
                .descriptor
                .change(i, params)
                .map_err(|e| WolletError::AddressDerivation(e.to_string()))?;
            out.push((int.script_pubkey(), Chain::Internal, i));
        }
        Ok(out)
    }

    /// Derive a confidential address for the given chain and index.
    ///
    /// # Errors
    ///
    /// [`WolletError::AddressDerivation`] on derivation failure.
    pub fn address(&self, chain: Chain, index: u32) -> Result<Address, WolletError> {
        let params = self.network.address_params();
        let res = match chain {
            Chain::External => self.descriptor.address(index, params),
            Chain::Internal => self.descriptor.change(index, params),
        };
        res.map_err(|e| WolletError::AddressDerivation(e.to_string()))
    }

    /// Unblind a confidential output belonging to this wallet, recovering its
    /// asset, value, and blinding factors.
    ///
    /// # Errors
    ///
    /// [`WolletError::Unblind`] if the output is not ours or is malformed.
    pub fn unblind(&self, txout: &TxOut) -> Result<TxOutSecrets, WolletError> {
        try_unblind(txout, &self.descriptor).map_err(|e| WolletError::Unblind(e.to_string()))
    }

    /// The underlying LWK descriptor.
    #[must_use]
    pub fn descriptor(&self) -> &WolletDescriptor {
        &self.descriptor
    }

    /// The SLIP-77 master blinding key (for deriving per-script secrets in the
    /// spend path).
    #[must_use]
    pub fn master_blinding_key(&self) -> &MasterBlindingKey {
        &self.master_blinding_key
    }

    /// The Elements network this wallet operates on.
    #[must_use]
    pub fn network(&self) -> ElementsNetwork {
        self.network
    }

    /// The concrete [`lwk_wollet::Network`] (policy asset + genesis) this wallet
    /// was built with — used by the spend path for fee/blinding accounting.
    #[must_use]
    pub fn lwk_network(&self) -> lwk_wollet::Network {
        self.lwk_network
    }

    /// Access to the wrapped `lwk_wollet::Wollet`.
    #[must_use]
    pub fn inner(&self) -> &Wollet {
        &self.inner
    }
}

/// Lowercase-hex encode a 32-byte array (no external dependency).
fn hex32(b: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &byte in b {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::CtDescriptorBuilder;
    use crate::slip77_blinding_key;
    use emvault_core::network::ElementsNetworkId;
    use emvault_core::signer::Signer;
    use emvault_core::test_utils::MockSigner;
    use bitcoin::Network;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1};

    /// Build a 2-of-3 ranged handle from deterministic mock signers.
    fn make_handle(blinding_key: [u8; 32]) -> ElementsWalletHandle {
        let mut builder = CtDescriptorBuilder::new(2, &blinding_key)
            .unwrap()
            .key_mode(crate::descriptor::CtKeyMode::Ranged);
        for s in (1..=3).map(|s| MockSigner::with_seed(s, Network::Regtest)) {
            builder.add_signer(&s as &dyn Signer).unwrap();
        }
        let desc = builder.build().unwrap();
        ElementsWalletHandle::new(desc, blinding_key)
    }

    #[test]
    fn from_handle_builds_wollet() {
        let handle = make_handle([0x11; 32]);
        let w = ElementsWollet::from_handle(&handle, ElementsNetwork::ElementsRegtest).unwrap();
        assert_eq!(w.network(), ElementsNetwork::ElementsRegtest);
        assert!(matches!(
            emvault_core::network::NetworkType::from(w.network()),
            emvault_core::network::NetworkType::Elements(ElementsNetworkId::ElementsRegtest)
        ));
    }

    #[test]
    fn watched_scripts_are_deterministic_and_distinct() {
        let handle = make_handle([0x22; 32]);
        let w = ElementsWollet::from_handle(&handle, ElementsNetwork::ElementsRegtest).unwrap();

        let a = w.watched_scripts(5).unwrap();
        let b = w.watched_scripts(5).unwrap();
        assert_eq!(a, b, "derivation must be deterministic");
        assert_eq!(a.len(), 10, "5 external + 5 internal");

        // external and internal index 0 must differ
        let ext0 = w.address(Chain::External, 0).unwrap().script_pubkey();
        let int0 = w.address(Chain::Internal, 0).unwrap().script_pubkey();
        assert_ne!(ext0, int0);

        // all 10 scripts distinct
        let set: std::collections::HashSet<_> = a.iter().map(|(s, _, _)| s.clone()).collect();
        assert_eq!(set.len(), 10);

        // chain/index labelling is correct
        assert_eq!(a[0], (ext0, Chain::External, 0));
        assert_eq!(a[1].1, Chain::Internal);
        assert_eq!(a[1].2, 0);
    }

    /// Promotes the P0 interop spike: the address LWK derives for a watched
    /// script carries a blinding pubkey equal to the SLIP-77 key we derive
    /// independently — so `unblind` and the spend path use the same key.
    #[test]
    fn ct_descriptor_blinding_key_matches_slip77() {
        let mbk = [0x33; 32];
        let handle = make_handle(mbk);
        let w = ElementsWollet::from_handle(&handle, ElementsNetwork::ElementsRegtest).unwrap();

        let addr = w.address(Chain::External, 0).unwrap();
        let spk = addr.script_pubkey();
        let secret = slip77_blinding_key(w.master_blinding_key(), &spk);
        let derived_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &secret);

        assert_eq!(
            addr.blinding_pubkey,
            Some(derived_pubkey),
            "LWK address blinding pubkey must equal our slip77-derived key"
        );
    }
}
