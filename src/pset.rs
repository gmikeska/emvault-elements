//! PSET pipeline: blinding, signing coordination, finalization.
//!
//! The Elements PSET pipeline mirrors [`asterism_core::psbt`] but adds an
//! Elements-specific blinding stage between construction and signing:
//!
//! 1. **Construction** — done outside this crate (e.g., via Elements RPC
//!    `walletcreatefundedpsbt` or LWK's `TxBuilder`). The resulting PSET
//!    is wrapped in [`UnsignedPset`].
//! 2. **Blinding** — [`blind_pset`] applies Pedersen commitments, range
//!    proofs, and surjection proofs to all non-fee outputs using the
//!    SLIP-77 master blinding key. Produces a [`BlindedPset`].
//! 3. **Signing** — coordinated by [`ElementsSigningCoordinator`].
//!    Iterates [`ElementsSigner`] instances and collects partial
//!    signatures into the PSET.
//! 4. **Finalization** — assembles P2WSH witness stacks from partial
//!    signatures and extracts the broadcast-ready
//!    [`elements::Transaction`].
//!
//! The `Unsigned` → `Blinded` → `Finalized` newtype progression makes
//! invalid states unrepresentable.

use std::collections::{HashMap, HashSet};

use elements::confidential;
use elements::encode::serialize as consensus_serialize;
use elements::pset::PartiallySignedTransaction as Pset;
use elements::secp256k1_zkp::{self, Secp256k1};
use elements::{Script, TxOutSecrets};

use asterism_core::federation::Federation;
use asterism_core::signer::{Signer, SignerId};

use crate::error::PsetError;
use crate::signer::ElementsSigner;

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// A PSET with zero partial signatures, before blinding.
#[derive(Clone, Debug)]
pub struct UnsignedPset(Pset);

impl UnsignedPset {
    /// Wrap a raw PSET. Fails if any input already has partial signatures.
    pub fn new(pset: Pset) -> Result<Self, PsetError> {
        let total_sigs: usize = pset.inputs().iter().map(|i| i.partial_sigs.len()).sum();
        if total_sigs != 0 {
            return Err(PsetError::UnexpectedSignatures { found: total_sigs });
        }
        Ok(Self(pset))
    }

    /// Borrow the inner PSET.
    #[must_use]
    pub fn as_pset(&self) -> &Pset {
        &self.0
    }

    /// Take ownership of the inner PSET.
    #[must_use]
    pub fn into_pset(self) -> Pset {
        self.0
    }
}

/// A PSET whose outputs have been blinded (range proofs and surjection
/// proofs are present). Ready for signing.
#[derive(Clone, Debug)]
pub struct BlindedPset(Pset);

impl BlindedPset {
    /// Wrap a PSET that has already been blinded. Validates that at least
    /// one non-fee output carries a range proof.
    pub fn new(pset: Pset) -> Result<Self, PsetError> {
        let has_blinded_output = pset.outputs().iter().any(|o| o.value_rangeproof.is_some());
        if !has_blinded_output {
            return Err(PsetError::NotBlinded);
        }
        Ok(Self(pset))
    }

    /// Borrow the inner PSET.
    #[must_use]
    pub fn as_pset(&self) -> &Pset {
        &self.0
    }

    /// Take ownership of the inner PSET.
    #[must_use]
    pub fn into_pset(self) -> Pset {
        self.0
    }
}

/// A fully-signed, finalized PSET, ready for broadcast.
#[derive(Clone, Debug)]
pub struct FinalizedPset {
    pset: Pset,
    transaction: elements::Transaction,
}

impl FinalizedPset {
    /// The fully-signed transaction.
    #[must_use]
    pub fn transaction(&self) -> &elements::Transaction {
        &self.transaction
    }

    /// The transaction id.
    #[must_use]
    pub fn txid(&self) -> elements::Txid {
        self.transaction.txid()
    }

    /// The consensus-serialized transaction bytes.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        consensus_serialize(&self.transaction)
    }

    /// The consensus-serialized transaction as hex.
    #[must_use]
    pub fn serialize_hex(&self) -> String {
        let bytes = self.serialize();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in &bytes {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        hex
    }

    /// The original PSET (retained for audit).
    #[must_use]
    pub fn as_pset(&self) -> &Pset {
        &self.pset
    }
}

// ---------------------------------------------------------------------------
// Blinding
// ---------------------------------------------------------------------------

/// Blind an unsigned PSET using the SLIP-77 master blinding key.
///
/// For each non-fee output that carries a `blinding_key` and a
/// `blinder_index`, this function:
/// 1. Unblind the corresponding input (using the SLIP-77-derived
///    per-script blinding key) to recover [`TxOutSecrets`].
/// 2. Call `Pset::blind_last` to apply Pedersen commitments, range
///    proofs, and surjection proofs.
///
/// The resulting [`BlindedPset`] is ready for signing.
///
/// # Parameters
///
/// * `pset` — The unsigned, unblinded PSET (from `walletcreatefundedpsbt`
///   or similar).
/// * `master_blinding_key` — The 32-byte SLIP-77 master blinding key
///   used to derive per-script blinding private keys.
/// * `inp_txout_secrets` — Pre-computed [`TxOutSecrets`] for each input,
///   keyed by input index. For inputs whose witness UTXO is unblinded
///   (explicit values), pass the explicit secrets. For confidential
///   inputs, the caller must unblind them first (using the SLIP-77
///   derived key for that input's script).
#[allow(clippy::implicit_hasher)]
pub fn blind_pset(
    pset: UnsignedPset,
    inp_txout_secrets: &HashMap<usize, TxOutSecrets>,
) -> Result<BlindedPset, PsetError> {
    let secp = Secp256k1::new();
    let mut rng = secp256k1_zkp::rand::thread_rng();
    let mut inner = pset.into_pset();

    inner
        .blind_last(&mut rng, &secp, inp_txout_secrets)
        .map_err(|e| PsetError::BlindingFailed(e.to_string()))?;

    BlindedPset::new(inner)
}

/// Build [`TxOutSecrets`] for an input whose witness UTXO has explicit
/// (unblinded) asset and value. This is common on regtest where
/// coinbase outputs and non-CT transactions produce unblinded UTXOs.
#[must_use]
pub fn explicit_txout_secrets(asset: elements::AssetId, value: u64) -> TxOutSecrets {
    TxOutSecrets::new(
        asset,
        elements::confidential::AssetBlindingFactor::zero(),
        value,
        elements::confidential::ValueBlindingFactor::zero(),
    )
}

/// Unblind a confidential witness UTXO using a SLIP-77 derived blinding
/// key, returning the [`TxOutSecrets`] needed for PSET blinding.
pub fn unblind_input(
    witness_utxo: &elements::TxOut,
    blinding_key: secp256k1_zkp::SecretKey,
) -> Result<TxOutSecrets, PsetError> {
    let secp = Secp256k1::new();
    witness_utxo
        .unblind(&secp, blinding_key)
        .map_err(|e| PsetError::BlindingFailed(format!("unblind failed: {e}")))
}

/// Derive the SLIP-77 blinding private key for a given script pubkey.
#[must_use]
pub fn slip77_blinding_key(
    master_blinding_key: &elements_miniscript::slip77::MasterBlindingKey,
    script_pubkey: &Script,
) -> secp256k1_zkp::SecretKey {
    master_blinding_key.blinding_private_key(script_pubkey)
}

/// Build the complete `inp_txout_secrets` map for a PSET by inspecting
/// each input's `witness_utxo` and unblinding as needed.
///
/// For explicit (unblinded) inputs, constructs secrets with zero blinding
/// factors. For confidential inputs, derives the SLIP-77 blinding key
/// and unblinds.
pub fn derive_input_secrets(
    pset: &Pset,
    master_blinding_key: &elements_miniscript::slip77::MasterBlindingKey,
) -> Result<HashMap<usize, TxOutSecrets>, PsetError> {
    let mut secrets = HashMap::new();
    for (i, input) in pset.inputs().iter().enumerate() {
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| PsetError::Elements(format!("input {i} missing witness_utxo")))?;

        let txout_secrets = if let (confidential::Value::Explicit(value), confidential::Asset::Explicit(asset)) = (utxo.value, utxo.asset) {
            explicit_txout_secrets(asset, value)
        } else {
            let blinding_key = slip77_blinding_key(master_blinding_key, &utxo.script_pubkey);
            unblind_input(utxo, blinding_key)?
        };
        secrets.insert(i, txout_secrets);
    }
    Ok(secrets)
}

// ---------------------------------------------------------------------------
// Signing coordinator
// ---------------------------------------------------------------------------

/// Coordinates signature collection across `ElementsSigner` instances
/// for a blinded PSET.
pub struct ElementsSigningCoordinator<'a, S: Signer = Box<dyn Signer>> {
    federation: &'a Federation<S>,
    pset: Pset,
    signed: HashSet<SignerId>,
}

impl<'a, S: Signer> ElementsSigningCoordinator<'a, S> {
    /// Create a new coordinator from a federation and a blinded PSET.
    ///
    /// Runs [`validate_blinding`](crate::confidential::validate_blinding)
    /// as a defense-in-depth check before accepting the PSET for signing.
    pub fn new(federation: &'a Federation<S>, pset: BlindedPset) -> Result<Self, PsetError> {
        crate::confidential::validate_blinding(&pset)?;
        Ok(Self {
            federation,
            pset: pset.into_pset(),
            signed: HashSet::new(),
        })
    }

    /// Borrow the current PSET.
    #[must_use]
    pub fn pset(&self) -> &Pset {
        &self.pset
    }

    /// How many distinct signers have contributed signatures so far.
    #[must_use]
    pub fn signatures_collected(&self) -> usize {
        self.signed.len()
    }

    /// Whether the signing threshold has been met.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        let collected =
            u32::try_from(self.signatures_collected()).expect("signature count fits u32");
        collected >= self.federation.threshold()
    }

    /// Sign the PSET with a single `ElementsSigner`. Returns the number
    /// of inputs that were signed. The signer must be a member of the
    /// federation.
    pub fn sign_with<ES: ElementsSigner>(
        &mut self,
        signer: &ES,
        signer_id: &SignerId,
    ) -> Result<usize, PsetError> {
        if !self.federation.contains(signer_id) {
            return Err(PsetError::UnknownSigner(signer_id.clone()));
        }
        let n = signer.sign_pset(&mut self.pset)?;
        if n > 0 {
            self.signed.insert(signer_id.clone());
        }
        Ok(n)
    }

    /// Ingest a signed PSET returned by an external signer (e.g., a
    /// hardware wallet connected to a browser). Merges new partial
    /// signatures into the coordinator's PSET.
    pub fn receive_signature(
        &mut self,
        signer_id: &SignerId,
        signed_pset: &Pset,
    ) -> Result<(), PsetError> {
        if !self.federation.contains(signer_id) {
            return Err(PsetError::UnknownSigner(signer_id.clone()));
        }
        let signer = self
            .federation
            .find(signer_id)
            .ok_or_else(|| PsetError::UnknownSigner(signer_id.clone()))?;
        let fp = signer.fingerprint();

        let mut found_new = false;
        for (input_idx, signed_input) in signed_pset.inputs().iter().enumerate() {
            // Collect new sigs to insert (avoids borrow conflict).
            let new_sigs: Vec<_> = signed_input
                .partial_sigs
                .iter()
                .filter(|(pk, _)| {
                    let fp_matches = signed_input
                        .bip32_derivation
                        .iter()
                        .any(|(k, (f, _))| *f == fp && k == *pk);
                    fp_matches && !self.pset.inputs()[input_idx].partial_sigs.contains_key(*pk)
                })
                .map(|(pk, sig)| (*pk, sig.clone()))
                .collect();

            for (pk, sig) in new_sigs {
                self.pset.inputs_mut()[input_idx]
                    .partial_sigs
                    .insert(pk, sig);
                found_new = true;
            }
        }

        if !found_new {
            return Err(PsetError::InvalidSignature(
                signer_id.clone(),
                "no new partial signature attributable to this signer".into(),
            ));
        }
        self.signed.insert(signer_id.clone());
        Ok(())
    }

    /// Finalize the PSET once the threshold has been met.
    ///
    /// Assembles P2WSH witness stacks (`OP_0` + sorted DER sigs +
    /// `witness_script`) for each input and extracts the broadcast-ready
    /// transaction.
    pub fn finalize(mut self) -> Result<FinalizedPset, PsetError> {
        if !self.is_complete() {
            return Err(PsetError::InsufficientSignatures {
                have: self.signatures_collected(),
                need: self.federation.threshold() as usize,
            });
        }

        finalize_p2wsh_pset(&mut self.pset)?;

        let transaction = self
            .pset
            .extract_tx()
            .map_err(|e| PsetError::FinalizationFailed(e.to_string()))?;

        Ok(FinalizedPset {
            pset: self.pset,
            transaction,
        })
    }
}

// ---------------------------------------------------------------------------
// P2WSH finalization
// ---------------------------------------------------------------------------

/// Assemble P2WSH witness stacks from partial signatures.
///
/// For each input with a `witness_script`, collects partial signatures
/// in the order the corresponding public keys appear in the witness
/// script (required for `OP_CHECKMULTISIG`), prepends `OP_0` (the
/// dummy element consumed by the multisig opcode bug), and appends the
/// witness script.
pub fn finalize_p2wsh_pset(pset: &mut Pset) -> Result<(), PsetError> {
    for (idx, input) in pset.inputs_mut().iter_mut().enumerate() {
        let witness_script = match input.witness_script.as_ref() {
            Some(ws) => ws.clone(),
            None => {
                return Err(PsetError::FinalizationFailed(format!(
                    "input {idx} missing witness_script"
                )));
            }
        };

        // Extract the public keys from the witness script in their
        // script-order. For `sortedmulti`, keys appear sorted by their
        // compressed encoding. We need signatures in the same order.
        let pubkeys_in_script = extract_pubkeys_from_witness_script(&witness_script);

        // Collect signatures ordered by script position.
        let mut ordered_sigs: Vec<Vec<u8>> = Vec::new();
        for pk in &pubkeys_in_script {
            if let Some(sig) = input.partial_sigs.get(pk) {
                ordered_sigs.push(sig.clone());
            }
        }

        // Build the witness: OP_0 (multisig bug) + sigs + witness_script
        let mut witness = vec![vec![]]; // OP_0
        witness.extend(ordered_sigs);
        witness.push(witness_script.to_bytes());

        input.final_script_witness = Some(witness);

        // Clear fields that are no longer needed after finalization
        // (standard PSBT/PSET practice).
        input.partial_sigs.clear();
        input.witness_script = None;
        input.bip32_derivation.clear();
        input.redeem_script = None;
        input.sighash_type = None;
    }

    Ok(())
}

/// Extract compressed public keys from a P2WSH multisig witness script.
///
/// Handles `OP_n <pk1> <pk2> ... <pkN> OP_m OP_CHECKMULTISIG` format.
fn extract_pubkeys_from_witness_script(script: &Script) -> Vec<bitcoin::PublicKey> {
    let mut pubkeys = Vec::new();
    for instruction in script.instructions() {
        if let Ok(elements::script::Instruction::PushBytes(data)) = instruction
            && data.len() == 33
            && let Ok(pk) = bitcoin::PublicKey::from_slice(data)
        {
            pubkeys.push(pk);
        }
    }
    pubkeys
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::pset::PartiallySignedTransaction;

    fn minimal_pset() -> PartiallySignedTransaction {
        // A minimal valid PSET with no inputs/outputs for newtype tests.
        let tx = elements::Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        PartiallySignedTransaction::from_tx(tx)
    }

    #[test]
    fn unsigned_pset_accepts_zero_sigs() {
        let pset = minimal_pset();
        UnsignedPset::new(pset).expect("should accept zero-sig PSET");
    }

    #[test]
    fn blinded_pset_rejects_unblinded() {
        let pset = minimal_pset();
        let err = BlindedPset::new(pset).unwrap_err();
        assert!(matches!(err, PsetError::NotBlinded));
    }
}
