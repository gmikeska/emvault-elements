use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use elements_miniscript::confidential::Descriptor as ConfidentialDescriptor;
use elements_miniscript::descriptor::DescriptorPublicKey;

use emvault_core::signer::{Signer, SignerId};

use crate::error::CtDescriptorError;

/// How descriptor keys are encoded in the CT descriptor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CtKeyMode {
    /// Each signer contributes a single public key. The descriptor produces
    /// one address.
    #[default]
    Fixed,
    /// Each signer contributes an xpub with BIP-389-style wildcards for
    /// receive/change derivation.
    Ranged,
}

/// Builder for `ct(slip77(...), elwsh(sortedmulti(m, ...)))` confidential
/// descriptors.
#[derive(Debug)]
pub struct CtDescriptorBuilder {
    threshold: u32,
    mode: CtKeyMode,
    master_blinding_key: [u8; 32],
    entries: BTreeMap<SignerId, KeyEntry>,
}

#[derive(Clone, Debug)]
struct KeyEntry {
    fingerprint: Fingerprint,
    derivation_path: DerivationPath,
    xpub: Xpub,
}

impl CtDescriptorBuilder {
    /// Create a new builder with the given threshold and 32-byte SLIP-77
    /// master blinding key.
    ///
    /// # Errors
    ///
    /// Returns [`CtDescriptorError::BadBlindingKeyLength`] if `mbk` is not
    /// exactly 32 bytes.
    pub fn new(threshold: u32, mbk: &[u8]) -> Result<Self, CtDescriptorError> {
        if mbk.len() != 32 {
            return Err(CtDescriptorError::BadBlindingKeyLength(mbk.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(mbk);
        Ok(Self {
            threshold,
            mode: CtKeyMode::default(),
            master_blinding_key: key,
            entries: BTreeMap::new(),
        })
    }

    /// Override the [`CtKeyMode`].
    #[must_use]
    pub fn key_mode(mut self, mode: CtKeyMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add a signer's contribution.
    ///
    /// # Errors
    ///
    /// Returns [`CtDescriptorError::DuplicateKey`] if a signer with the same
    /// [`SignerId`] has already been added.
    pub fn add_signer(&mut self, signer: &dyn Signer) -> Result<&mut Self, CtDescriptorError> {
        let id = signer.id();
        let entry = KeyEntry {
            fingerprint: signer.fingerprint(),
            derivation_path: signer.derivation_path().clone(),
            xpub: *signer.xpub(),
        };
        if self.entries.insert(id.clone(), entry).is_some() {
            return Err(CtDescriptorError::DuplicateKey(id.to_string()));
        }
        Ok(self)
    }

    /// Build the confidential descriptor.
    ///
    /// Produces a `ct(slip77(<mbk_hex>), elwsh(sortedmulti(m, ...)))`
    /// descriptor string and parses it into the typed
    /// `ConfidentialDescriptor`.
    ///
    /// # Errors
    ///
    /// Returns [`CtDescriptorError::NoSigners`] if no signers were added,
    /// [`CtDescriptorError::Descriptor`] if the descriptor string fails to
    /// parse.
    pub fn build(self) -> Result<ConfidentialDescriptor<DescriptorPublicKey>, CtDescriptorError> {
        if self.entries.is_empty() {
            return Err(CtDescriptorError::NoSigners);
        }

        let keys: Vec<String> = self
            .entries
            .values()
            .map(|e| format_key(self.mode, e))
            .collect();

        let mbk_hex = hex::encode(self.master_blinding_key);

        let keys_csv = keys.join(",");
        let desc_str = format!(
            "ct(slip77({mbk_hex}),elwsh(sortedmulti({},{keys_csv})))",
            self.threshold
        );

        ConfidentialDescriptor::<DescriptorPublicKey>::from_str(&desc_str)
            .map_err(|e| CtDescriptorError::Descriptor(e.to_string()))
    }
}

fn format_key(mode: CtKeyMode, entry: &KeyEntry) -> String {
    let origin = format_origin(entry.fingerprint, &entry.derivation_path);
    match mode {
        CtKeyMode::Fixed => {
            let pk = bitcoin::PublicKey::new(entry.xpub.public_key);
            format!("[{origin}]{pk}")
        }
        CtKeyMode::Ranged => {
            let xpub_str = entry.xpub.to_string();
            format!("[{origin}]{xpub_str}/0/*")
        }
    }
}

fn format_origin(fp: Fingerprint, path: &DerivationPath) -> String {
    let fp_hex = fp.to_string();
    if path.is_empty() {
        return fp_hex;
    }
    let segments: Vec<String> = path
        .into_iter()
        .map(|cn| match cn {
            ChildNumber::Normal { index } => format!("{index}"),
            ChildNumber::Hardened { index } => format!("{index}h"),
        })
        .collect();
    format!("{fp_hex}/{}", segments.join("/"))
}

fn hex_encode_byte(b: u8) -> [u8; 2] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]]
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let [hi, lo] = super::hex_encode_byte(*b);
            s.push(hi as char);
            s.push(lo as char);
        }
        s
    }
}

/// Convert a confidential descriptor into a BIP-389-style multipath string
/// by replacing `/0/*` with `/<0;1>/*`, analogous to
/// [`emvault_core::descriptor::to_multipath_string`].
///
/// Strips the `#checksum` suffix (if present) before substitution so
/// downstream parsers compute a fresh checksum over the multipath body.
pub fn to_multipath_string(desc: &ConfidentialDescriptor<DescriptorPublicKey>) -> String {
    let s = desc.to_string();
    let body = s.split_once('#').map_or(s.as_str(), |(b, _)| b);
    body.replace("/0/*", "/<0;1>/*")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::bip32::Xpub;

    use emvault_core::network::NetworkType;
    use emvault_core::signer::{
        SignerCapabilities, SignerHealth, SignerId, SignerType, TransportType,
    };

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
            vec![NetworkType::Bitcoin(Network::Testnet)]
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

    #[test]
    fn build_ct_descriptor_fixed_mode() {
        let mbk = [0xab; 32];
        let mut builder = CtDescriptorBuilder::new(2, &mbk).unwrap();
        for seed in 1..=3u8 {
            builder.add_signer(&FakeSigner::new(seed)).unwrap();
        }
        let desc = builder.build().unwrap();
        let s = desc.to_string();
        assert!(s.starts_with("ct(slip77("), "got: {s}");
        assert!(s.contains("sortedmulti(2,"), "got: {s}");
    }

    #[test]
    fn build_ct_descriptor_ranged_mode() {
        let mbk = [0xcd; 32];
        let mut builder = CtDescriptorBuilder::new(2, &mbk)
            .unwrap()
            .key_mode(CtKeyMode::Ranged);
        for seed in 1..=3u8 {
            builder.add_signer(&FakeSigner::new(seed)).unwrap();
        }
        let desc = builder.build().unwrap();
        let s = desc.to_string();
        assert!(
            s.contains("/0/*"),
            "ranged mode should have wildcard, got: {s}"
        );
    }

    #[test]
    fn multipath_string_replaces_wildcard() {
        let mbk = [0xef; 32];
        let mut builder = CtDescriptorBuilder::new(2, &mbk)
            .unwrap()
            .key_mode(CtKeyMode::Ranged);
        for seed in 1..=3u8 {
            builder.add_signer(&FakeSigner::new(seed)).unwrap();
        }
        let desc = builder.build().unwrap();
        let mp = to_multipath_string(&desc);
        assert!(mp.contains("/<0;1>/*"), "got: {mp}");
        assert!(!mp.contains('#'), "should strip checksum, got: {mp}");
    }

    #[test]
    fn bad_blinding_key_length() {
        let err = CtDescriptorBuilder::new(2, &[0u8; 16]).unwrap_err();
        assert!(matches!(err, CtDescriptorError::BadBlindingKeyLength(16)));
    }

    #[test]
    fn duplicate_signer_rejected() {
        let mbk = [0xaa; 32];
        let s1 = FakeSigner::new(1);
        let mut builder = CtDescriptorBuilder::new(2, &mbk).unwrap();
        builder.add_signer(&s1).unwrap();
        let err = builder.add_signer(&s1).unwrap_err();
        assert!(matches!(err, CtDescriptorError::DuplicateKey(_)));
    }

    #[test]
    fn no_signers_rejected() {
        let mbk = [0xbb; 32];
        let builder = CtDescriptorBuilder::new(2, &mbk).unwrap();
        let err = builder.build().unwrap_err();
        assert!(matches!(err, CtDescriptorError::NoSigners));
    }

    #[test]
    fn at_derivation_index_works() {
        let mbk = [0xab; 32];
        let mut builder = CtDescriptorBuilder::new(2, &mbk)
            .unwrap()
            .key_mode(CtKeyMode::Ranged);
        for seed in 1..=3u8 {
            builder.add_signer(&FakeSigner::new(seed)).unwrap();
        }
        let desc = builder.build().unwrap();
        let definite = desc.at_derivation_index(0).expect("definite descriptor");
        let secp = elements_miniscript::elements::secp256k1_zkp::Secp256k1::new();
        let addr = definite
            .address(&secp, &AddressParams::LIQUID_TESTNET)
            .expect("address derivation");
        assert!(addr.blinding_pubkey.is_some());
    }

    use elements::AddressParams;
}
