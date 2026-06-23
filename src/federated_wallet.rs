//! [`ElementsFederatedWallet`] — Elements implementation of [`FederatedWallet`].
//!
//! Each federation version is paired with an [`ElementsWalletHandle`], a
//! lightweight reference to a named watch-only wallet on the Elements daemon.
//! The application creates the daemon wallets and passes handles in; this
//! module is a container with no RPC, persistence, or sync logic.

use std::collections::HashSet;

use elements_miniscript::confidential::Descriptor as ConfidentialDescriptor;
use elements_miniscript::descriptor::DescriptorPublicKey;

use asterism_core::error::FederatedWalletError;
use asterism_core::federated_wallet::{FederatedWallet, FederationWallet};
use asterism_core::network::NetworkType;
use asterism_core::signer::{Signer, SignerId};

use crate::network::ElementsNetwork;

// ---------------------------------------------------------------------------
// ElementsWalletHandle
// ---------------------------------------------------------------------------

/// A lightweight handle to a named watch-only wallet on the Elements daemon.
///
/// Each handle stores its own SLIP-77 blinding key. Federation changes offer
/// the opportunity to rotate the blinding key (to prevent old signers from
/// obtaining newer transaction history via backup bundles), but rotation is
/// not mandatory — organizations may keep the same key for accounting reasons.
#[derive(Clone, Debug)]
pub struct ElementsWalletHandle {
    /// The wallet name on the Elements daemon (used in RPC calls).
    pub wallet_name: String,
    /// The confidential descriptor for this federation version.
    pub ct_descriptor: ConfidentialDescriptor<DescriptorPublicKey>,
    /// The 32-byte SLIP-77 master blinding key for this federation version.
    pub blinding_key: [u8; 32],
}

impl ElementsWalletHandle {
    /// Create a new handle.
    pub fn new(
        wallet_name: String,
        ct_descriptor: ConfidentialDescriptor<DescriptorPublicKey>,
        blinding_key: [u8; 32],
    ) -> Self {
        Self {
            wallet_name,
            ct_descriptor,
            blinding_key,
        }
    }
}

// ---------------------------------------------------------------------------
// ElementsFederatedWallet
// ---------------------------------------------------------------------------

/// Elements implementation of [`FederatedWallet`], backed by per-federation
/// [`ElementsWalletHandle`] instances referencing named daemon wallets.
///
/// Like [`BtcFederatedWallet`](asterism_core::BtcFederatedWallet), this type
/// is **immutable** — [`with_federation`](Self::with_federation) returns a
/// new instance; the original is unchanged.
pub struct ElementsFederatedWallet<S: Signer = Box<dyn Signer>> {
    federation_wallets: Vec<FederationWallet<S, ElementsWalletHandle>>,
    network: ElementsNetwork,
}

impl<S: Signer> std::fmt::Debug for ElementsFederatedWallet<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElementsFederatedWallet")
            .field("federation_count", &self.federation_wallets.len())
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl<S: Signer> ElementsFederatedWallet<S> {
    /// Create a new `ElementsFederatedWallet` with the initial federation and
    /// its pre-created wallet handle.
    ///
    /// # Errors
    ///
    /// Returns [`FederatedWalletError::NonElementsNetwork`] if the federation's
    /// network is not an Elements network.
    pub fn new(
        federation: asterism_core::federation::Federation<S>,
        handle: ElementsWalletHandle,
        network: ElementsNetwork,
    ) -> Result<Self, FederatedWalletError> {
        if !federation.network().is_elements() {
            return Err(FederatedWalletError::NonElementsNetwork);
        }
        let fw = FederationWallet {
            federation,
            wallet: handle,
            index: 0,
        };
        Ok(Self {
            federation_wallets: vec![fw],
            network,
        })
    }

    /// Return a **new** `ElementsFederatedWallet` containing all existing
    /// federation-wallet pairs plus the new one. The original is unchanged.
    ///
    /// # Errors
    ///
    /// - [`FederatedWalletError::NetworkMismatch`] if the new federation's
    ///   network differs from the existing federations.
    /// - [`FederatedWalletError::NonElementsNetwork`] if the federation is not
    ///   Elements.
    pub fn with_federation(
        &self,
        federation: asterism_core::federation::Federation<S>,
        handle: ElementsWalletHandle,
    ) -> Result<Self, FederatedWalletError>
    where
        S: Clone,
    {
        if !federation.network().is_elements() {
            return Err(FederatedWalletError::NonElementsNetwork);
        }
        let incoming_network: NetworkType = self.network.into();
        if federation.network() != incoming_network {
            return Err(FederatedWalletError::NetworkMismatch {
                existing: incoming_network,
                incoming: federation.network(),
            });
        }
        let new_index = self.federation_wallets.len();
        let mut new_wallets: Vec<FederationWallet<S, ElementsWalletHandle>> =
            Vec::with_capacity(new_index + 1);
        for fw in &self.federation_wallets {
            new_wallets.push(FederationWallet {
                federation: fw.federation.clone(),
                wallet: fw.wallet.clone(),
                index: fw.index,
            });
        }
        new_wallets.push(FederationWallet {
            federation,
            wallet: handle,
            index: new_index,
        });
        Ok(Self {
            federation_wallets: new_wallets,
            network: self.network,
        })
    }

    /// The Elements network this wallet operates on.
    #[must_use]
    pub fn elements_network(&self) -> ElementsNetwork {
        self.network
    }

    /// All confidential descriptors across the wallet stack.
    #[must_use]
    pub fn ct_descriptors(&self) -> Vec<&ConfidentialDescriptor<DescriptorPublicKey>> {
        self.federation_wallets
            .iter()
            .map(|fw| &fw.wallet.ct_descriptor)
            .collect()
    }

    /// Iterate all wallet handles (for RPC-based sync fan-out by the
    /// application).
    pub fn wallet_handles(&self) -> impl Iterator<Item = &ElementsWalletHandle> {
        self.federation_wallets.iter().map(|fw| &fw.wallet)
    }

    /// Direct access to a wallet handle by federation index.
    #[must_use]
    pub fn handle_at(&self, index: usize) -> Option<&ElementsWalletHandle> {
        self.federation_wallets.get(index).map(|fw| &fw.wallet)
    }
}

// ---------------------------------------------------------------------------
// FederatedWallet trait impl
// ---------------------------------------------------------------------------

impl<S: Signer> FederatedWallet<S, ElementsWalletHandle> for ElementsFederatedWallet<S> {
    fn federation_wallets(&self) -> &[FederationWallet<S, ElementsWalletHandle>] {
        &self.federation_wallets
    }

    fn current(&self) -> &FederationWallet<S, ElementsWalletHandle> {
        self.federation_wallets
            .last()
            .expect("ElementsFederatedWallet always has at least one federation")
    }

    fn at(&self, index: usize) -> Option<&FederationWallet<S, ElementsWalletHandle>> {
        self.federation_wallets.get(index)
    }

    fn federation_count(&self) -> usize {
        self.federation_wallets.len()
    }

    fn network(&self) -> NetworkType {
        self.network.into()
    }

    fn threshold(&self) -> u32 {
        self.current().federation.threshold()
    }

    fn find_by_signer(&self, id: &SignerId) -> Vec<&FederationWallet<S, ElementsWalletHandle>> {
        self.federation_wallets
            .iter()
            .filter(|fw| fw.federation.contains(id))
            .collect()
    }

    fn signer_is_current(&self, id: &SignerId) -> bool {
        self.current().federation.contains(id)
    }

    fn all_signer_ids(&self) -> HashSet<SignerId> {
        self.federation_wallets
            .iter()
            .flat_map(|fw| fw.federation.signers().iter().map(asterism_core::Signer::id))
            .collect()
    }

    fn current_signer_ids(&self) -> HashSet<SignerId> {
        self.current()
            .federation
            .signers()
            .iter()
            .map(asterism_core::Signer::id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterism_core::federation::Federation;
    use asterism_core::network::ElementsNetworkId;
    use asterism_core::signer::{SignerCapabilities, SignerHealth, SignerType, TransportType};
    use bitcoin::Network;
    use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
    use std::str::FromStr;

    #[derive(Clone)]
    struct FakeSigner {
        xpub: Xpub,
        fingerprint: Fingerprint,
        path: DerivationPath,
        id: SignerId,
    }

    impl FakeSigner {
        fn new(seed: u8) -> Self {
            use bitcoin::bip32::Xpriv;
            use bitcoin::secp256k1::Secp256k1;
            let secp = Secp256k1::new();
            let mut seed_bytes = [0u8; 32];
            seed_bytes[0] = seed;
            let xpriv = Xpriv::new_master(Network::Testnet, &seed_bytes).unwrap();
            let path = DerivationPath::from_str("m/48'/1'/0'/2'").unwrap();
            let derived = xpriv.derive_priv(&secp, &path).unwrap();
            let xpub = Xpub::from_priv(&secp, &derived);
            let fingerprint = xpriv.fingerprint(&secp);
            let id = SignerId::from_fingerprint(fingerprint);
            Self {
                xpub,
                fingerprint,
                path,
                id,
            }
        }
    }

    impl Signer for FakeSigner {
        fn id(&self) -> SignerId {
            self.id.clone()
        }
        fn label(&self) -> Option<&str> {
            None
        }
        fn xpub(&self) -> &Xpub {
            &self.xpub
        }
        fn fingerprint(&self) -> Fingerprint {
            self.fingerprint
        }
        fn derivation_path(&self) -> &DerivationPath {
            &self.path
        }
        fn signer_type(&self) -> SignerType {
            SignerType::External
        }
        fn supported_networks(&self) -> Vec<NetworkType> {
            vec![NetworkType::Elements(ElementsNetworkId::ElementsRegtest)]
        }
        fn capabilities(&self) -> SignerCapabilities {
            SignerCapabilities::p2wsh_only(vec![TransportType::Usb])
        }
        fn health_check(&self) -> Result<SignerHealth, asterism_core::error::SignerError> {
            Ok(SignerHealth {
                reachable: true,
                firmware_version: None,
                last_seen: None,
            })
        }
    }

    fn make_federation(seeds: &[u8], threshold: u32) -> Federation<FakeSigner> {
        let signers: Vec<FakeSigner> = seeds.iter().map(|&s| FakeSigner::new(s)).collect();
        Federation::new(
            threshold,
            signers,
            NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
        )
        .unwrap()
    }

    fn make_handle(
        name: &str,
        fed: &Federation<FakeSigner>,
        blinding_key: [u8; 32],
    ) -> ElementsWalletHandle {
        use crate::descriptor::CtDescriptorBuilder;
        let mut builder = CtDescriptorBuilder::new(fed.threshold(), &blinding_key).unwrap();
        for signer in fed.signers() {
            builder.add_signer(signer).unwrap();
        }
        let desc = builder.build().unwrap();
        ElementsWalletHandle::new(name.to_string(), desc, blinding_key)
    }

    #[test]
    fn construct_with_initial_federation() {
        let fed = make_federation(&[1, 2, 3], 2);
        let handle = make_handle("test-wallet-0", &fed, [0xaa; 32]);
        let fw =
            ElementsFederatedWallet::new(fed, handle, ElementsNetwork::ElementsRegtest).unwrap();
        assert_eq!(fw.federation_count(), 1);
        assert_eq!(fw.current().index, 0);
        assert_eq!(fw.threshold(), 2);
        assert_eq!(fw.elements_network(), ElementsNetwork::ElementsRegtest);
    }

    #[test]
    fn with_federation_adds_and_preserves_original() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let h1 = make_handle("wallet-v1", &fed1, [0xaa; 32]);
        let fw1 = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let h2 = make_handle("wallet-v2", &fed2, [0xbb; 32]);
        let fw2 = fw1.with_federation(fed2, h2).unwrap();

        assert_eq!(fw1.federation_count(), 1, "original unchanged");
        assert_eq!(fw2.federation_count(), 2, "new has both");
        assert_eq!(fw2.current().index, 1);
    }

    #[test]
    fn distinct_blinding_keys_per_handle() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let key1 = [0xaa; 32];
        let h1 = make_handle("wallet-v1", &fed1, key1);
        let fw = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let key2 = [0xbb; 32];
        let h2 = make_handle("wallet-v2", &fed2, key2);
        let fw = fw.with_federation(fed2, h2).unwrap();

        assert_eq!(fw.handle_at(0).unwrap().blinding_key, key1);
        assert_eq!(fw.handle_at(1).unwrap().blinding_key, key2);
    }

    #[test]
    fn ct_descriptors_returns_all() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let h1 = make_handle("wallet-v1", &fed1, [0xaa; 32]);
        let fw = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let h2 = make_handle("wallet-v2", &fed2, [0xbb; 32]);
        let fw = fw.with_federation(fed2, h2).unwrap();

        assert_eq!(fw.ct_descriptors().len(), 2);
    }

    #[test]
    fn wallet_handles_iterates_all() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let h1 = make_handle("wallet-v1", &fed1, [0xaa; 32]);
        let fw = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let fed2 = make_federation(&[1, 3, 4], 2);
        let h2 = make_handle("wallet-v2", &fed2, [0xbb; 32]);
        let fw = fw.with_federation(fed2, h2).unwrap();

        let names: Vec<&str> = fw
            .wallet_handles()
            .map(|h| h.wallet_name.as_str())
            .collect();
        assert_eq!(names, vec!["wallet-v1", "wallet-v2"]);
    }

    #[test]
    fn find_by_signer_returns_correct_federations() {
        let s1 = FakeSigner::new(1);
        let s2 = FakeSigner::new(2);
        let s3 = FakeSigner::new(3);
        let s4 = FakeSigner::new(4);
        let id2 = s2.id();

        let fed1 = Federation::new(
            2,
            vec![s1.clone(), s2, s3.clone()],
            NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
        )
        .unwrap();
        let h1 = make_handle("wallet-v1", &fed1, [0xaa; 32]);
        let fw = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let fed2 = Federation::new(
            2,
            vec![s1, s3, s4],
            NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
        )
        .unwrap();
        let h2 = make_handle("wallet-v2", &fed2, [0xbb; 32]);
        let fw = fw.with_federation(fed2, h2).unwrap();

        let matches = fw.find_by_signer(&id2);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].index, 0);
    }

    #[test]
    fn removed_signer_in_all_but_not_current() {
        let s1 = FakeSigner::new(1);
        let s2 = FakeSigner::new(2);
        let s3 = FakeSigner::new(3);
        let s4 = FakeSigner::new(4);
        let id2 = s2.id();

        let fed1 = Federation::new(
            2,
            vec![s1.clone(), s2, s3.clone()],
            NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
        )
        .unwrap();
        let h1 = make_handle("wallet-v1", &fed1, [0xaa; 32]);
        let fw = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let fed2 = Federation::new(
            2,
            vec![s1, s3, s4],
            NetworkType::Elements(ElementsNetworkId::ElementsRegtest),
        )
        .unwrap();
        let h2 = make_handle("wallet-v2", &fed2, [0xbb; 32]);
        let fw = fw.with_federation(fed2, h2).unwrap();

        assert!(fw.all_signer_ids().contains(&id2));
        assert!(!fw.current_signer_ids().contains(&id2));
        assert!(!fw.signer_is_current(&id2));
    }

    #[test]
    fn immutability_original_unchanged() {
        let fed1 = make_federation(&[1, 2, 3], 2);
        let h1 = make_handle("wallet-v1", &fed1, [0xaa; 32]);
        let fw1 = ElementsFederatedWallet::new(fed1, h1, ElementsNetwork::ElementsRegtest).unwrap();

        let original_count = fw1.federation_count();
        let original_threshold = fw1.threshold();

        let fed2 = make_federation(&[1, 3, 4], 3);
        let h2 = make_handle("wallet-v2", &fed2, [0xbb; 32]);
        let _fw2 = fw1.with_federation(fed2, h2).unwrap();

        assert_eq!(fw1.federation_count(), original_count);
        assert_eq!(fw1.threshold(), original_threshold);
    }

    #[test]
    fn non_elements_network_rejected() {
        use asterism_core::test_utils::MockSigner;
        let signers: Vec<MockSigner> = (1..=3)
            .map(|s| MockSigner::with_seed(s, Network::Regtest))
            .collect();
        let fed = Federation::new(2, signers, Network::Regtest.into()).unwrap();
        let handle = ElementsWalletHandle::new(
            "test".to_string(),
            // Use a dummy descriptor — we expect the network check to fire first
            {
                use crate::descriptor::CtDescriptorBuilder;
                let mut builder = CtDescriptorBuilder::new(2, &[0xaa; 32]).unwrap();
                let dummy_signers = make_federation(&[1, 2, 3], 2);
                for s in dummy_signers.signers() {
                    builder.add_signer(s).unwrap();
                }
                builder.build().unwrap()
            },
            [0xaa; 32],
        );
        let err = ElementsFederatedWallet::new(fed, handle, ElementsNetwork::ElementsRegtest)
            .unwrap_err();
        assert!(matches!(err, FederatedWalletError::NonElementsNetwork));
    }
}
