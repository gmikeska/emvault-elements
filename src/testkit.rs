//! Reusable test helpers, gated behind `cfg(test)` or the `test-utils` feature.
//!
//! [`SoftwareSigner`] is a self-contained in-process signer that owns its
//! master key: it implements both [`emvault_core::signer::Signer`] (so it can
//! build federations/descriptors) and [`crate::signer::ElementsSigner`] (so it
//! can produce real ECDSA signatures over the Elements segwit-v0 sighash). This
//! is exactly what a production HSM does, made available for offline and
//! node-backed tests without depending on `emvault-pkcs11`.

use std::str::FromStr;

use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;

use elements::EcdsaSighashType;
use elements::pset::PartiallySignedTransaction as Pset;
use elements::sighash::SighashCache;
use elements_miniscript::psbt::{PsbtExt, PsbtSighashMsg};

use emvault_core::network::{ElementsNetworkId, NetworkType};
use emvault_core::signer::{
    Signer, SignerCapabilities, SignerHealth, SignerId, SignerType, TransportType,
};

use crate::error::PsetError;
use crate::network::ElementsNetwork;
use crate::signer::ElementsSigner;

/// A deterministic in-process software signer for tests.
#[derive(Clone)]
pub struct SoftwareSigner {
    master: Xpriv,
    path: DerivationPath,
    xpub: Xpub,
    fingerprint: Fingerprint,
    id: SignerId,
    genesis: elements::BlockHash,
}

impl SoftwareSigner {
    /// Build a signer from a deterministic seed for the given Elements network.
    /// Two calls with the same seed produce the same keys.
    #[must_use]
    pub fn new(seed: u8, network: ElementsNetwork) -> Self {
        Self::new_with_lwk(seed, network.to_lwk())
    }

    /// Like [`new`](Self::new) but with an explicit [`lwk_wollet::Network`], so
    /// the signing genesis hash matches a custom regtest node (see
    /// [`ElementsNetwork::custom_regtest`]). The genesis hash is mixed into the
    /// Elements segwit-v0 sighash, so it must match the node or signatures will
    /// be invalid.
    #[must_use]
    pub fn new_with_lwk(seed: u8, lwk_network: lwk_wollet::Network) -> Self {
        let mut seed_bytes = [0u8; 32];
        seed_bytes[0] = seed;
        seed_bytes[1] = 0x5a;
        Self::new_with_seed_bytes(seed_bytes, lwk_network)
    }

    /// Like [`new_with_lwk`](Self::new_with_lwk) but with full 32-byte seed
    /// entropy — useful when tests need keys (and thus the multisig script)
    /// that are unique per run.
    #[must_use]
    pub fn new_with_seed_bytes(seed_bytes: [u8; 32], lwk_network: lwk_wollet::Network) -> Self {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Regtest, &seed_bytes).expect("valid master");
        let path = DerivationPath::from_str("m/48'/1'/0'/2'").expect("valid path");
        let derived = master.derive_priv(&secp, &path).expect("derive");
        let xpub = Xpub::from_priv(&secp, &derived);
        let fingerprint = master.fingerprint(&secp);
        let id = SignerId::from_fingerprint(fingerprint);
        Self {
            master,
            path,
            xpub,
            fingerprint,
            id,
            genesis: lwk_network.genesis_hash(),
        }
    }
}

impl Signer for SoftwareSigner {
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
    fn health_check(&self) -> Result<SignerHealth, emvault_core::error::SignerError> {
        Ok(SignerHealth {
            reachable: true,
            firmware_version: None,
            last_seen: None,
        })
    }
}

impl ElementsSigner for SoftwareSigner {
    fn sign_pset(&self, pset: &mut Pset) -> Result<usize, PsetError> {
        let secp = Secp256k1::new();
        let tx = pset
            .extract_tx()
            .map_err(|e| PsetError::Elements(e.to_string()))?;
        let mut cache = SighashCache::new(&tx);
        let mut signed = 0usize;

        let n = pset.inputs().len();
        for idx in 0..n {
            let msg = pset
                .sighash_msg(idx, &mut cache, None, self.genesis)
                .map_err(|e| PsetError::Elements(e.to_string()))?;
            let message = match msg {
                PsbtSighashMsg::EcdsaSighash(_) => msg.to_secp_msg(),
                PsbtSighashMsg::TapSighash(_) => continue,
            };

            let mine: Vec<(bitcoin::PublicKey, DerivationPath)> = pset.inputs()[idx]
                .bip32_derivation
                .iter()
                .filter(|(_, (fp, _))| *fp == self.fingerprint)
                .map(|(pk, (_, path))| (*pk, path.clone()))
                .collect();

            for (pk, full_path) in mine {
                let child = self
                    .master
                    .derive_priv(&secp, &full_path)
                    .map_err(|e| PsetError::SignerBackend(e.to_string()))?;
                let sig = secp.sign_ecdsa(&message, &child.private_key);
                let mut ser = sig.serialize_der().to_vec();
                ser.push(EcdsaSighashType::All as u8);
                pset.inputs_mut()[idx].partial_sigs.insert(pk, ser);
                signed += 1;
            }
        }
        Ok(signed)
    }
}
