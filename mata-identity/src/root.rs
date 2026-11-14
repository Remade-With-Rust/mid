//! Derived personal root identity — `#root` and the DID as a pure function of
//! the vault key (DID-logins plan v2, ADR 0011).
//!
//! Until 2026-09-30 the personal root was the one key on the platform that was
//! **not** derived from the vault key. Milestone 1 (2026-04-22) minted it from OS
//! randomness on whichever device found `registered_public_key` empty and stored
//! it AES-GCM under the vault key, deferring derivation "to a later milestone" to
//! keep the first test users' signatures valid. Every other identity — the
//! `#encryption` key, every company key ([`crate::entity`]) — derives from the
//! vault key and is therefore identical on every device with no handshake. The
//! random root forked three ways on one account (three DIDs, one vault; see
//! `docs/plans/did-logins.md` §2). This module closes that exception.
//!
//! ## Contract — frozen; the vector file is the test of record
//!
//! - `scalar = HKDF-SHA256(salt = "MATA-PKI-v1", ikm = vault_key,
//!   info = "MATA-PKI-v1/root/signing")` via [`derive_subordinate_key`]. The
//!   scalar is the P-256 private key.
//! - `did = "did:mata:" + base58btc(compressed SEC1 public key)` — byte for byte
//!   the encoding `mid_verify::keys::did_from_pubkey` uses, and the one entity
//!   DIDs use (ADR 0010).
//! - `publicKeyMultibase = "z" + base58btc(compressed SEC1)` — byte for byte
//!   `mid_verify::keys::multibase_from_pubkey`.
//! - The genesis roster is version 1 with one verification method
//!   `<did>#device-0` and `signed_at = MID_DERIVED_GENESIS_EPOCH`. With those
//!   inputs the genesis canonical bytes, and so the hash every relying party
//!   anchors on, are a pure function of the vault key. The hash ignores the
//!   signature field, so signature randomness cannot make two devices differ.
//!
//! `tests/vectors/derived_identity_v1.json` records all of the above for one
//! fixed vault key. It is read by this crate, by `mid-issuer` (which produces the
//! genesis hash) and by `mid-verify` (which verifies a JWT minted on it). Any
//! surface that derives differently fails a vector.
//!
//! ## Threat model
//!
//! Unchanged. Whoever holds the vault key could already decrypt the stored random
//! root; derivation makes the coupling explicit and identical everywhere. The
//! derived scalar is still stored on the credential, encrypted under the vault
//! key, so a future vault-key **rotation** can carry the DID forward by
//! re-wrapping it. Derive when absent; never mint randomly again.

use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::{derive_subordinate_key, IdentityError};

/// HKDF purpose label of the personal root. Versioned by the `MATA-PKI-v1/`
/// prefix inside [`derive_subordinate_key`]; domain-separated from
/// [`crate::PURPOSE_ENCRYPTION`] and from every `entity/{id}` label.
pub const PURPOSE_ROOT_SIGNING: &str = "root/signing";

/// The `signed_at` every derived genesis roster carries: 2025-09-30T00:00:00Z,
/// the day the design was locked. **Frozen.** Changing it changes every
/// derived genesis hash and therefore every relying party's anchor.
pub const MID_DERIVED_GENESIS_EPOCH: u64 = 1_759_190_400;

/// The kid of the genesis verification method, `<did>#device-0`. The same
/// literal the v1 wallets used; kept so pre-derivation chains stay readable.
pub const MID_GENESIS_DEVICE_KID: &str = "device-0";

// A change to the epoch must be a deliberate, reviewed act: it also has to
// change this pin and regenerate the vector file.
const _: () = assert!(
    MID_DERIVED_GENESIS_EPOCH == 1_759_190_400,
    "MID_DERIVED_GENESIS_EPOCH is frozen; see docs/plans/did-logins.md D2"
);

/// The person's derived root identity. The scalar is sensitive — hold it only
/// as long as a signature needs it. `did`, `public_key_sec1` and
/// `public_key_multibase` are public.
pub struct RootIdentity {
    /// `did:mata:<base58btc(compressed pubkey)>`.
    pub did: String,
    /// Raw 32-byte P-256 private scalar. **Sensitive.**
    pub private_scalar: [u8; 32],
    /// SEC1 uncompressed public key (65 bytes, `0x04 || X || Y`), the form
    /// `RegisteredCredential::registered_public_key` stores.
    pub public_key_sec1: Vec<u8>,
    /// `z<base58btc(compressed pubkey)>`, the form the genesis verification
    /// method carries.
    pub public_key_multibase: String,
}

/// Derive the personal root identity from the vault key. Deterministic: the
/// same vault key yields the same DID on every device, with no transport and
/// no sync. Errors only on an empty vault key or a scalar outside the curve
/// order (probability 2^-128, but the check is real).
pub fn derive_root_identity(vault_key: &[u8]) -> Result<RootIdentity, IdentityError> {
    if vault_key.is_empty() {
        return Err(IdentityError::KeyGenFailed(
            "cannot derive a root identity from an empty vault key".to_string(),
        ));
    }
    let scalar = derive_subordinate_key(vault_key, PURPOSE_ROOT_SIGNING);
    let sk =
        SigningKey::from_bytes((&scalar).into()).map_err(|_| IdentityError::InvalidPrivateKey)?;
    let vk = sk.verifying_key();
    Ok(RootIdentity {
        did: did_from_verifying_key(vk),
        private_scalar: scalar,
        public_key_sec1: vk.to_encoded_point(false).as_bytes().to_vec(),
        public_key_multibase: multibase_from_verifying_key(vk),
    })
}

/// The DID a SEC1 public key (compressed or uncompressed) names. This is the
/// one encoding shared by persons, devices and companies; a wallet that
/// computes a DID any other way is wrong.
pub fn did_from_public_key_sec1(public_key_sec1: &[u8]) -> Result<String, IdentityError> {
    let vk = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|e| IdentityError::InvalidSec1(e.to_string()))?;
    Ok(did_from_verifying_key(&vk))
}

/// The `publicKeyMultibase` form of a SEC1 public key, as the genesis
/// verification method carries it.
pub fn multibase_from_public_key_sec1(public_key_sec1: &[u8]) -> Result<String, IdentityError> {
    let vk = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|e| IdentityError::InvalidSec1(e.to_string()))?;
    Ok(multibase_from_verifying_key(&vk))
}

fn did_from_verifying_key(vk: &VerifyingKey) -> String {
    let compressed = vk.to_encoded_point(true);
    debug_assert_eq!(compressed.as_bytes().len(), 33);
    format!(
        "did:mata:{}",
        bs58::encode(compressed.as_bytes()).into_string()
    )
}

fn multibase_from_verifying_key(vk: &VerifyingKey) -> String {
    let compressed = vk.to_encoded_point(true);
    format!("z{}", bs58::encode(compressed.as_bytes()).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_entity_identity, keypair_from_scalar_bytes, PURPOSE_ENCRYPTION};

    const VAULT: &[u8; 32] = &[0x42u8; 32];

    #[test]
    fn same_vault_key_same_identity() {
        let a = derive_root_identity(VAULT).unwrap();
        let b = derive_root_identity(VAULT).unwrap();
        assert_eq!(a.did, b.did);
        assert_eq!(a.private_scalar, b.private_scalar);
        assert_eq!(a.public_key_sec1, b.public_key_sec1);
        assert_eq!(a.public_key_multibase, b.public_key_multibase);
    }

    #[test]
    fn different_vault_keys_are_different_people() {
        let a = derive_root_identity(&[1u8; 32]).unwrap();
        let b = derive_root_identity(&[2u8; 32]).unwrap();
        assert_ne!(a.did, b.did);
    }

    #[test]
    fn root_is_domain_separated_from_encryption_and_entity_keys() {
        let root = derive_root_identity(VAULT).unwrap();
        let enc_scalar = derive_subordinate_key(VAULT, PURPOSE_ENCRYPTION);
        assert_ne!(
            root.private_scalar, enc_scalar,
            "root/signing must not equal encryption"
        );
        let entity = derive_entity_identity(VAULT, "holding-1").unwrap();
        assert_ne!(
            root.did, entity.entity_did,
            "a person and a company must never collide"
        );
        assert_ne!(root.private_scalar, entity.private_scalar);
    }

    #[test]
    fn did_encoding_is_base58_of_the_compressed_key() {
        let root = derive_root_identity(VAULT).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(&root.public_key_sec1).unwrap();
        let expected = format!(
            "did:mata:{}",
            bs58::encode(vk.to_encoded_point(true).as_bytes()).into_string()
        );
        assert_eq!(root.did, expected);
        assert!(root.public_key_multibase.starts_with('z'));
        assert_eq!(
            &root.public_key_multibase[1..],
            &root.did["did:mata:".len()..]
        );
    }

    #[test]
    fn sec1_helpers_agree_with_the_derivation_for_both_point_encodings() {
        let root = derive_root_identity(VAULT).unwrap();
        assert_eq!(
            did_from_public_key_sec1(&root.public_key_sec1).unwrap(),
            root.did
        );
        assert_eq!(
            multibase_from_public_key_sec1(&root.public_key_sec1).unwrap(),
            root.public_key_multibase
        );
        let vk = VerifyingKey::from_sec1_bytes(&root.public_key_sec1).unwrap();
        let compressed = vk.to_encoded_point(true);
        assert_eq!(
            did_from_public_key_sec1(compressed.as_bytes()).unwrap(),
            root.did
        );
    }

    #[test]
    fn empty_vault_key_is_refused() {
        assert!(derive_root_identity(&[]).is_err());
    }

    #[test]
    fn scalar_round_trips_through_keypair_from_scalar_bytes() {
        // The credential stores the scalar; loading it back must yield the
        // same public key the derivation produced.
        let root = derive_root_identity(VAULT).unwrap();
        let (_, pub_sec1) = keypair_from_scalar_bytes(&root.private_scalar).unwrap();
        assert_eq!(pub_sec1, root.public_key_sec1);
    }

    // ─── The vector of record ───────────────────────────────────────────────

    const VECTOR: &str = include_str!("../tests/vectors/derived_identity_v1.json");

    fn vector() -> serde_json::Value {
        serde_json::from_str(VECTOR).expect("derived_identity_v1.json parses")
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).expect("vector hex field decodes")
    }

    #[test]
    fn matches_derived_identity_vector_v1() {
        let v = vector();
        assert_eq!(v["version"].as_u64(), Some(1));
        assert_eq!(v["purpose"].as_str(), Some(PURPOSE_ROOT_SIGNING));
        assert_eq!(v["hkdf_salt"].as_str(), Some("MATA-PKI-v1"));
        assert_eq!(
            v["genesis"]["signed_at"].as_u64(),
            Some(MID_DERIVED_GENESIS_EPOCH)
        );
        assert_eq!(
            v["genesis"]["device_kid"].as_str(),
            Some(MID_GENESIS_DEVICE_KID)
        );
        assert_eq!(v["genesis"]["version"].as_u64(), Some(1));

        let vault = hex_decode(v["vault_key_hex"].as_str().unwrap());
        let root = derive_root_identity(&vault).unwrap();

        assert_eq!(
            hex::encode(root.private_scalar),
            v["root_private_scalar_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(&root.public_key_sec1),
            v["root_public_key_sec1_hex"].as_str().unwrap()
        );
        assert_eq!(root.did, v["did"].as_str().unwrap());
        assert_eq!(
            root.public_key_multibase,
            v["public_key_multibase"].as_str().unwrap()
        );

        // The encryption key is pinned beside the root so a change to the HKDF
        // salt or info prefix — which would move BOTH — cannot be mistaken for a
        // root-only defect.
        let enc_scalar = derive_subordinate_key(&vault, PURPOSE_ENCRYPTION);
        let (_, enc_pub) = keypair_from_scalar_bytes(&enc_scalar).unwrap();
        assert_eq!(
            hex::encode(enc_pub),
            v["encryption_public_key_sec1_hex"].as_str().unwrap()
        );
    }

    /// One-shot generator for the vector file. Run with
    /// `cargo test -p mata-identity --target <host> print_vector_material -- --ignored --nocapture`
    /// and paste the fields into `tests/vectors/derived_identity_v1.json`; the
    /// genesis hash is produced by mid-issuer's vector test.
    #[test]
    #[ignore]
    fn print_vector_material() {
        let v = vector();
        let vault = hex_decode(v["vault_key_hex"].as_str().unwrap());
        let root = derive_root_identity(&vault).unwrap();
        let enc_scalar = derive_subordinate_key(&vault, PURPOSE_ENCRYPTION);
        let (_, enc_pub) = keypair_from_scalar_bytes(&enc_scalar).unwrap();
        println!(
            "VECTOR root_private_scalar_hex {}",
            hex::encode(root.private_scalar)
        );
        println!(
            "VECTOR root_public_key_sec1_hex {}",
            hex::encode(&root.public_key_sec1)
        );
        println!("VECTOR did {}", root.did);
        println!("VECTOR public_key_multibase {}", root.public_key_multibase);
        println!(
            "VECTOR encryption_public_key_sec1_hex {}",
            hex::encode(enc_pub)
        );
    }
}
