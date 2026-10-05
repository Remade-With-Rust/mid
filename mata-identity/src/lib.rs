//! MATA user-owned identity keypairs.
//!
//! Phase 1 of the MATA KMS / sovereign identity platform.
//!
//! # Design
//!
//! Each user has a single P-256 ECDSA keypair generated locally at signup.
//! - **Public key**: stored plaintext in the user's `RegisteredCredential` and
//!   uploaded to Supabase `user_identity_keys` so third parties can verify
//!   signatures without any MATA round-trip.
//! - **Private key**: encrypted at rest with the user's vault key and stored
//!   in the same `RegisteredCredential` alongside other sensitive material.
//!
//! Uses the pure-Rust `p256` crate — no WebCrypto dependency. Works identically
//! on native, mobile, and WASM. The same crate is already used throughout
//! `dioxus-webauthn` for the software biometric fallback, so this builds on
//! infrastructure MATA already trusts.
//!
//! ## What this crate provides
//!
//! - [`generate_identity_keypair`] — produces a fresh P-256 keypair using OS
//!   randomness via `getrandom`.
//! - [`public_key_to_jwk`] / [`public_key_from_jwk`] — JWK round-trip for
//!   storing / retrieving the public key as JSON (Supabase, wire format).
//! - [`public_key_to_sec1_bytes`] / [`public_key_from_sec1_bytes`] — SEC1
//!   uncompressed bytes (65 bytes, starting with 0x04) for local storage.
//! - [`sign_with_private_key`] / [`verify_signature`] — sign a challenge with
//!   the raw private key bytes, verify with a JWK public key.
//!
//! ## What this crate does NOT do
//!
//! - No encryption of the private key at rest — that's the caller's job using
//!   MATA's existing `encrypt_with_vault_key` helper.
//! - No network calls — uploading the pubkey to Supabase happens in
//!   `dioxus-supabase-auth`.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub use p256;

// M2: HKDF subordinate-key derivation, DID document types, RFC 8785 canon.
pub mod canonicalize;
pub mod did;
pub mod hkdf;
// M4 (SMB): controlled-entity identity — per-holding entity DID + control proof.
pub mod entity;
// DID-logins v2 (ADR 0011): the personal root derived from the vault key.
pub mod root;

pub use canonicalize::{canonicalize_for_signing_unsigned, CanonicalizeError};
pub use did::{did_for_user, DidDocument, DidProof, MataAttestation, ServiceEndpoint, VerificationMethod};
pub use entity::{
    build_control_proof, derive_entity_identity, verify_control_proof, EntityControlProof,
    EntityIdentity, ENTITY_PROOF_VERSION,
};
pub use hkdf::{derive_subordinate_key, PURPOSE_ENCRYPTION};
pub use root::{
    derive_root_identity, did_from_public_key_sec1, multibase_from_public_key_sec1, RootIdentity,
    MID_DERIVED_GENESIS_EPOCH, MID_GENESIS_DEVICE_KID, PURPOSE_ROOT_SIGNING,
};

/// A P-256 public key serialized as a JWK (JSON Web Key).
///
/// Shape: `{ "kty": "EC", "crv": "P-256", "x": "<base64url>", "y": "<base64url>" }`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JwkPublicKey {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// Errors returned by this crate.
#[derive(Debug)]
pub enum IdentityError {
    /// Key generation failed (OS randomness unavailable).
    KeyGenFailed(String),
    /// The bytes could not be parsed as a P-256 signing key.
    InvalidPrivateKey,
    /// JWK shape is invalid (missing field, wrong curve, etc.).
    InvalidJwk(String),
    /// SEC1 point bytes were malformed.
    InvalidSec1(String),
    /// Signature could not be parsed as DER-encoded ECDSA.
    InvalidSignature,
    /// Signature verification returned NOT_OK.
    VerificationFailed,
    /// base64 decode failed.
    Base64(base64::DecodeError),
    /// RFC 8785 (JCS) canonicalization failed (M4 control proofs).
    Canonicalize(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGenFailed(e) => write!(f, "key generation failed: {e}"),
            Self::InvalidPrivateKey => write!(f, "invalid P-256 private key bytes"),
            Self::InvalidJwk(why) => write!(f, "invalid JWK: {why}"),
            Self::InvalidSec1(why) => write!(f, "invalid SEC1 point: {why}"),
            Self::InvalidSignature => write!(f, "invalid signature format"),
            Self::VerificationFailed => write!(f, "signature verification failed"),
            Self::Base64(e) => write!(f, "base64 decode: {e}"),
            Self::Canonicalize(why) => write!(f, "canonicalization failed: {why}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<base64::DecodeError> for IdentityError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(e)
    }
}

// ─── Key generation ──────────────────────────────────────────────────────────

/// Generate a fresh P-256 identity keypair using OS randomness.
///
/// Returns `(private_key_bytes, public_key_sec1_bytes)`:
/// - `private_key_bytes` — 32 raw scalar bytes. The caller MUST encrypt this
///   with the vault key before storing it anywhere persistent.
/// - `public_key_sec1_bytes` — 65 bytes of SEC1 uncompressed encoding
///   (`0x04 || X || Y`). Safe to store plaintext.
pub fn generate_identity_keypair() -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| IdentityError::KeyGenFailed(e.to_string()))?;

    let signing_key = SigningKey::from_bytes((&raw).into())
        .map_err(|_| IdentityError::InvalidPrivateKey)?;
    let private_key_bytes = signing_key.to_bytes().to_vec();
    let public_key_bytes = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    Ok((private_key_bytes, public_key_bytes))
}

/// Generate a fresh P-256 ECDSA keypair for **device-scoped signing** (M5).
///
/// Distinct from [`generate_identity_keypair`] only in intent — at the byte
/// level both produce a 32-byte scalar + 65-byte SEC1 pubkey via OS
/// randomness. Kept as a named generator so M5 sender / receiver call sites
/// read cleanly (`generate_device_signing_keypair()` says "this is the
/// per-device authenticator, not the user-level `#root`").
///
/// The user-level `#root` from M1 is shared across paired devices via the
/// vault export. The device-level signing key is *unique per device* and
/// never shared — that's what gives M5's roster its compromise-containment
/// property. A stolen device's signing key only matters as long as siblings
/// trust it in their roster.
///
/// Returns `(private_key_bytes, public_key_sec1_bytes)`. Caller MUST encrypt
/// `private_key_bytes` under the vault key before persisting (same scheme as
/// `registered_private_key`).
pub fn generate_device_signing_keypair() -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
    generate_identity_keypair()
}

/// Generate a fresh P-256 ECDH keypair for **device-scoped encryption** (M5).
///
/// Used as the recipient half of HPKE-sealed [`RotationEnvelope`]s in M5's
/// passphrase-rotation flow. At the byte level identical to
/// [`generate_device_signing_keypair`] (both are P-256 scalars), but the
/// keypair is consumed by HPKE's `DHKEM(P-256, HKDF-SHA256)` rather than
/// ECDSA — separate keys for separate purposes is the cryptographic
/// hygiene M5 commits to (one stolen signing key cannot decrypt sibling
/// rotation envelopes).
///
/// Returns `(private_key_bytes, public_key_sec1_bytes)`. Caller MUST encrypt
/// `private_key_bytes` under the vault key before persisting.
pub fn generate_device_encryption_keypair() -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).map_err(|e| IdentityError::KeyGenFailed(e.to_string()))?;

    let secret = p256::SecretKey::from_bytes((&raw).into())
        .map_err(|_| IdentityError::InvalidPrivateKey)?;
    let private_key_bytes = secret.to_bytes().to_vec();
    let public_key_bytes = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    Ok((private_key_bytes, public_key_bytes))
}

/// Construct a P-256 keypair from a fixed 32-byte scalar.
///
/// Used by M2's HKDF-derived `#encryption` key — feed
/// [`derive_subordinate_key`] output through here to get the SEC1 public
/// half plus the same scalar normalized as a private key.
///
/// Returns `(private_key_bytes, public_key_sec1_bytes)` matching
/// [`generate_identity_keypair`]'s shape so callers can reuse the same
/// downstream encrypt-and-store code paths.
///
/// Errors:
/// - [`IdentityError::InvalidPrivateKey`] if the scalar is zero or not in
///   the curve's order. With HKDF-SHA256 output the probability is
///   negligible (≈ 2⁻¹²⁸) but the check is still performed defensively.
pub fn keypair_from_scalar_bytes(
    scalar_bytes: &[u8; 32],
) -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let signing_key = SigningKey::from_bytes(scalar_bytes.into())
        .map_err(|_| IdentityError::InvalidPrivateKey)?;
    let private_key_bytes = signing_key.to_bytes().to_vec();
    let public_key_bytes = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    Ok((private_key_bytes, public_key_bytes))
}

// ─── Signing / verification ──────────────────────────────────────────────────

/// Sign an arbitrary byte slice with the raw private key bytes.
///
/// Returns a DER-encoded ECDSA-P256-SHA256 signature. Compatible with standard
/// verifiers including WebCrypto's `ECDSA` algorithm.
pub fn sign_with_private_key(
    private_key_bytes: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>, IdentityError> {
    let signing_key = SigningKey::from_bytes(private_key_bytes.into())
        .map_err(|_| IdentityError::InvalidPrivateKey)?;
    let signature: Signature = signing_key.sign(challenge);
    let der: DerSignature = signature.to_der();
    Ok(der.as_bytes().to_vec())
}

/// Verify a signature using a JWK public key.
///
/// This is the function third-party services import to verify MATA users:
/// they fetch the user's `public_key_jwk` from Supabase, then call this with
/// the challenge they issued and the signature the user returned. No MATA
/// server round-trip required.
pub fn verify_signature(
    public_key_jwk: &JwkPublicKey,
    challenge: &[u8],
    signature_der: &[u8],
) -> Result<(), IdentityError> {
    let verifying_key = public_key_from_jwk(public_key_jwk)?;
    let signature =
        Signature::from_der(signature_der).map_err(|_| IdentityError::InvalidSignature)?;
    verifying_key
        .verify(challenge, &signature)
        .map_err(|_| IdentityError::VerificationFailed)
}

/// Verify a DER-encoded ECDSA-P256-SHA256 signature against an SEC1
/// uncompressed public key (65 bytes, prefix `0x04`).
///
/// Sibling of [`verify_signature`] for callers that hold the public key as
/// raw SEC1 bytes rather than JWK — e.g. M5's `device_roster::RosterEntry`
/// stores `signing_pubkey: Vec<u8>` directly so the rotation-envelope
/// receive path doesn't need to round-trip through JWK on every verify.
pub fn verify_signature_sec1(
    public_key_sec1: &[u8],
    challenge: &[u8],
    signature_der: &[u8],
) -> Result<(), IdentityError> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| IdentityError::InvalidSec1("malformed SEC1 P-256 point".into()))?;
    let signature =
        Signature::from_der(signature_der).map_err(|_| IdentityError::InvalidSignature)?;
    verifying_key
        .verify(challenge, &signature)
        .map_err(|_| IdentityError::VerificationFailed)
}

// ─── JWK round-trip ──────────────────────────────────────────────────────────

/// Convert SEC1-encoded public key bytes to JWK representation.
pub fn public_key_to_jwk(public_key_sec1: &[u8]) -> Result<JwkPublicKey, IdentityError> {
    if public_key_sec1.len() != 65 || public_key_sec1[0] != 0x04 {
        return Err(IdentityError::InvalidSec1(format!(
            "expected 65 bytes starting with 0x04, got {} bytes",
            public_key_sec1.len()
        )));
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let x = &public_key_sec1[1..33];
    let y = &public_key_sec1[33..65];

    Ok(JwkPublicKey {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
    })
}

/// Parse a P-256 `VerifyingKey` from its JWK representation.
pub fn public_key_from_jwk(jwk: &JwkPublicKey) -> Result<VerifyingKey, IdentityError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    if jwk.kty != "EC" {
        return Err(IdentityError::InvalidJwk(format!(
            "kty must be EC, got {}",
            jwk.kty
        )));
    }
    if jwk.crv != "P-256" {
        return Err(IdentityError::InvalidJwk(format!(
            "crv must be P-256, got {}",
            jwk.crv
        )));
    }

    let x = URL_SAFE_NO_PAD.decode(&jwk.x)?;
    let y = URL_SAFE_NO_PAD.decode(&jwk.y)?;

    if x.len() != 32 || y.len() != 32 {
        return Err(IdentityError::InvalidJwk(format!(
            "x and y must each be 32 bytes, got x={} y={}",
            x.len(),
            y.len()
        )));
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);

    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| IdentityError::InvalidJwk("invalid P-256 point".to_string()))
}

/// Convert JWK to SEC1 bytes (inverse of [`public_key_to_jwk`]).
pub fn public_key_from_jwk_to_sec1(jwk: &JwkPublicKey) -> Result<Vec<u8>, IdentityError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let vk = public_key_from_jwk(jwk)?;
    Ok(vk.to_encoded_point(false).as_bytes().to_vec())
}

// ─── M3-Structural: ECDH shared-secret primitive ─────────────────────────────

/// Compute the raw ECDH shared secret for P-256.
///
/// Inputs:
/// - `our_priv`: the local 32-byte P-256 scalar (e.g. the user's `#encryption`
///   private key after [`derive_subordinate_key`] + [`keypair_from_scalar_bytes`]).
/// - `peer_pub_sec1`: the peer's public key as SEC1 uncompressed bytes
///   (`0x04 || X || Y`, 65 bytes — same format as
///   [`public_key_from_jwk_to_sec1`] returns).
///
/// Output: 32 raw bytes — the X-coordinate of the shared point. **This is not
/// suitable as an AEAD key directly.** Callers MUST run it through a KDF (HKDF
/// is the canonical choice; HPKE wraps this for you in `mata-messaging`).
///
/// The output is **commutative**: if Alice computes
/// `ecdh_shared_secret(alice_priv, bob_pub)` and Bob computes
/// `ecdh_shared_secret(bob_priv, alice_pub)`, both return the same 32 bytes.
/// This is the property that lets two parties derive the same symmetric key
/// without ever exchanging it.
///
/// # Cross-platform contract
///
/// Pure-Rust via `p256::ecdh::diffie_hellman`. Output is byte-identical on
/// native, WASM, iOS, and Android — verified by RFC 5903 known-answer vectors.
/// No platform divergence; no SubtleCrypto fallback needed.
///
/// # Errors
/// - [`IdentityError::InvalidPrivateKey`] if `our_priv` isn't a valid scalar.
/// - [`IdentityError::InvalidSec1`] if `peer_pub_sec1` isn't a valid P-256
///   point (wrong length, point at infinity, not on the curve).
pub fn ecdh_shared_secret(
    our_priv: &[u8; 32],
    peer_pub_sec1: &[u8],
) -> Result<[u8; 32], IdentityError> {
    use p256::{NonZeroScalar, PublicKey};

    let scalar = NonZeroScalar::try_from(&our_priv[..])
        .map_err(|_| IdentityError::InvalidPrivateKey)?;

    // SEC1 uncompressed → PublicKey. `from_sec1_bytes` validates length, the
    // 0x04 header, and that the point is on the curve and not the identity.
    let peer_pub = PublicKey::from_sec1_bytes(peer_pub_sec1)
        .map_err(|e| IdentityError::InvalidSec1(format!("not a valid P-256 point: {e}")))?;

    // Diffie-Hellman: shared = scalar * peer_point. The output's X coordinate
    // is what HPKE's KEM consumes (after KDF expansion). RFC 5903 §3.
    let shared = p256::ecdh::diffie_hellman(scalar, peer_pub.as_affine());
    let shared_bytes = shared.raw_secret_bytes();

    // raw_secret_bytes returns a generic-array of 32 bytes for P-256.
    // Copy into a plain array so the caller doesn't import generic-array.
    let mut out = [0u8; 32];
    out.copy_from_slice(&shared_bytes[..]);
    Ok(out)
}

// ─── M2: DID document build / self-sign / verify ─────────────────────────────

/// Build the unsigned skeleton of a user's first DID document.
///
/// Caller fills `proof` via [`self_sign_did_document`]. M7 fills
/// `mata_attestation` via the `issue-did-attestation` edge function.
///
/// # Arguments
///
/// - `user_uuid`: Supabase `auth.users.id`.
/// - `root_pubkey_sec1`: The user's `#root` public key (from M1's
///   `RegisteredCredential.registered_public_key`). 65 bytes, SEC1
///   uncompressed.
/// - `encryption_pubkey_sec1`: The user's `#encryption` public key, derived
///   in M2 via [`derive_subordinate_key`] then converted to SEC1.
pub fn build_initial_did_document(
    user_uuid: uuid::Uuid,
    root_pubkey_sec1: &[u8],
    encryption_pubkey_sec1: &[u8],
) -> Result<DidDocument, IdentityError> {
    let did = did::did_for_user(user_uuid);
    let root_jwk = public_key_to_jwk(root_pubkey_sec1)?;
    let enc_jwk = public_key_to_jwk(encryption_pubkey_sec1)?;

    Ok(DidDocument {
        id: did.clone(),
        controller: did,
        version: 1,
        updated: chrono::Utc::now(),
        pki_version: 1,
        verification_method: vec![
            VerificationMethod {
                id: "#root".into(),
                type_: "EcdsaSecp256r1VerificationKey2019".into(),
                public_key_jwk: root_jwk,
                purpose: vec![
                    "authentication".into(),
                    "capabilityInvocation".into(),
                ],
                scope: None,
                expires: None,
            },
            VerificationMethod {
                id: "#encryption".into(),
                type_: "EcdhEsP256".into(),
                public_key_jwk: enc_jwk,
                purpose: vec!["keyAgreement".into()],
                scope: None,
                expires: None,
            },
        ],
        service: vec![],
        proof: None,
        mata_attestation: None,
    })
}

/// Self-sign a DID document with the user's `#root` private key.
///
/// Fills `doc.proof`. Idempotent — calling twice replaces the previous
/// signature with a fresh one over the same bytes (chiefly useful when the
/// document version is bumped and the proof needs re-issuing).
///
/// # Errors
///
/// - [`IdentityError::InvalidPrivateKey`] if `root_private_key` isn't a
///   valid 32-byte P-256 scalar.
/// - JCS canonicalization failure (extremely rare with well-typed input).
pub fn self_sign_did_document(
    doc: &mut DidDocument,
    root_private_key: &[u8],
) -> Result<(), IdentityError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Strip any existing proof/attestation before computing the signing
    // bytes; canonicalize_for_signing_unsigned does this on a clone, so
    // doc itself is untouched until we write the new proof at the end.
    let canonical = canonicalize::canonicalize_for_signing_unsigned(doc)
        .map_err(|e| IdentityError::InvalidJwk(format!("canonicalize: {e}")))?;

    let signature_der = sign_with_private_key(root_private_key, &canonical)?;

    doc.proof = Some(DidProof {
        type_: "EcdsaSecp256r1Signature2019".into(),
        verification_method: "#root".into(),
        signature: URL_SAFE_NO_PAD.encode(&signature_der),
    });
    Ok(())
}

/// Verify a DID document's self-signature.
///
/// Fetches the `#root` public key from the document's
/// `verification_method` list, recomputes the canonical signing bytes,
/// and checks the signature stored in `proof`.
///
/// **Does not** verify MATA's attestation — that's M7's
/// `mata-identity-verify::verify_with_attestation`. A successful return
/// from this function only proves the holder of `#root` produced the
/// document, not that MATA has confirmed the user's identity.
pub fn verify_did_document_self_signature(doc: &DidDocument) -> Result<(), IdentityError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let proof = doc
        .proof
        .as_ref()
        .ok_or_else(|| IdentityError::InvalidJwk("document has no proof".into()))?;

    if proof.type_ != "EcdsaSecp256r1Signature2019" {
        return Err(IdentityError::InvalidJwk(format!(
            "unsupported proof type: {}",
            proof.type_
        )));
    }
    if proof.verification_method != "#root" {
        return Err(IdentityError::InvalidJwk(format!(
            "M2 only accepts proofs by #root, got {}",
            proof.verification_method
        )));
    }

    // Find the #root verification method.
    let root_method = doc
        .verification_method
        .iter()
        .find(|vm| vm.id == "#root")
        .ok_or_else(|| IdentityError::InvalidJwk("no #root verificationMethod".into()))?;

    let signature_der = URL_SAFE_NO_PAD
        .decode(proof.signature.as_bytes())
        .map_err(|_| IdentityError::InvalidSignature)?;

    let canonical = canonicalize::canonicalize_for_signing_unsigned(doc)
        .map_err(|e| IdentityError::InvalidJwk(format!("canonicalize: {e}")))?;

    verify_signature(&root_method.public_key_jwk, &canonical, &signature_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_keypair() {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        assert_eq!(private_key.len(), 32);
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        let jwk = public_key_to_jwk(&public_key).unwrap();

        let challenge = b"authentication-challenge-xyz";
        let signature = sign_with_private_key(&private_key, challenge).unwrap();

        verify_signature(&jwk, challenge, &signature).unwrap();
    }

    #[test]
    fn verify_fails_on_wrong_message() {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        let jwk = public_key_to_jwk(&public_key).unwrap();

        let signature = sign_with_private_key(&private_key, b"original").unwrap();
        let result = verify_signature(&jwk, b"tampered", &signature);
        assert!(matches!(result, Err(IdentityError::VerificationFailed)));
    }

    #[test]
    fn verify_fails_on_wrong_pubkey() {
        let (pk1, _) = generate_identity_keypair().unwrap();
        let (_, pub2) = generate_identity_keypair().unwrap();
        let wrong_jwk = public_key_to_jwk(&pub2).unwrap();

        let signature = sign_with_private_key(&pk1, b"hello").unwrap();
        let result = verify_signature(&wrong_jwk, b"hello", &signature);
        assert!(matches!(result, Err(IdentityError::VerificationFailed)));
    }

    #[test]
    fn jwk_roundtrip_preserves_pubkey() {
        let (_, public_key) = generate_identity_keypair().unwrap();
        let jwk = public_key_to_jwk(&public_key).unwrap();
        let sec1_again = public_key_from_jwk_to_sec1(&jwk).unwrap();
        assert_eq!(sec1_again, public_key);
    }

    #[test]
    fn jwk_has_expected_shape() {
        let (_, public_key) = generate_identity_keypair().unwrap();
        let jwk = public_key_to_jwk(&public_key).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let x = URL_SAFE_NO_PAD.decode(&jwk.x).unwrap();
        let y = URL_SAFE_NO_PAD.decode(&jwk.y).unwrap();
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
    }

    #[test]
    fn rejects_malformed_jwk() {
        let (_, public_key) = generate_identity_keypair().unwrap();
        let mut jwk = public_key_to_jwk(&public_key).unwrap();
        let original = jwk.clone();

        jwk.kty = "RSA".to_string();
        assert!(matches!(public_key_from_jwk(&jwk), Err(IdentityError::InvalidJwk(_))));

        jwk = original.clone();
        jwk.crv = "P-384".to_string();
        assert!(matches!(public_key_from_jwk(&jwk), Err(IdentityError::InvalidJwk(_))));

        jwk = original.clone();
        jwk.x = "not-base64-!!!".to_string();
        assert!(public_key_from_jwk(&jwk).is_err());
    }

    #[test]
    fn two_generations_produce_different_keys() {
        let (pk1, pub1) = generate_identity_keypair().unwrap();
        let (pk2, pub2) = generate_identity_keypair().unwrap();
        // Overwhelmingly likely to differ; failure would mean broken RNG.
        assert_ne!(pk1, pk2);
        assert_ne!(pub1, pub2);
    }

    // ─── M5: Device-scoped keypair generators ───────────────────────────────
    //
    // Per-device keypairs back the M5 passphrase-rotation flow. They MUST be
    // unique per device (compromise containment) — these tests assert RNG
    // sanity. Byte-shape parity with `generate_identity_keypair` is locked in
    // because Step 4's wire format reuses the same SEC1 encoding.

    #[test]
    fn device_signing_keypair_has_correct_shape() {
        let (priv_bytes, pub_bytes) = generate_device_signing_keypair().unwrap();
        assert_eq!(priv_bytes.len(), 32, "P-256 scalar is 32 bytes");
        assert_eq!(pub_bytes.len(), 65, "SEC1 uncompressed P-256 is 65 bytes");
        assert_eq!(pub_bytes[0], 0x04, "SEC1 uncompressed prefix is 0x04");
    }

    #[test]
    fn device_encryption_keypair_has_correct_shape() {
        let (priv_bytes, pub_bytes) = generate_device_encryption_keypair().unwrap();
        assert_eq!(priv_bytes.len(), 32);
        assert_eq!(pub_bytes.len(), 65);
        assert_eq!(pub_bytes[0], 0x04);
    }

    #[test]
    fn two_device_signing_keypairs_differ() {
        // RNG sanity. The compromise-containment property of M5's roster
        // depends on this — if two devices ever generate the same signing
        // key the threat model collapses.
        let (p1, pub1) = generate_device_signing_keypair().unwrap();
        let (p2, pub2) = generate_device_signing_keypair().unwrap();
        assert_ne!(p1, p2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn two_device_encryption_keypairs_differ() {
        let (p1, pub1) = generate_device_encryption_keypair().unwrap();
        let (p2, pub2) = generate_device_encryption_keypair().unwrap();
        assert_ne!(p1, p2);
        assert_ne!(pub1, pub2);
    }

    #[test]
    fn device_signing_keypair_signs_and_verifies() {
        // Proves the device signing keypair is a real, usable ECDSA-P256
        // keypair — not just bytes that happen to be the right length.
        // Step 5 (sender flow) signs RotationEnvelopes with this; Step 7
        // (receiver flow) verifies with the matching pubkey from the
        // roster. This test pins that round-trip at the unit level.
        let (priv_bytes, pub_bytes) = generate_device_signing_keypair().unwrap();
        let jwk = public_key_to_jwk(&pub_bytes).unwrap();

        let challenge = b"M5 RotationEnvelope canonical bytes";
        let sig = sign_with_private_key(&priv_bytes, challenge).unwrap();
        verify_signature(&jwk, challenge, &sig).expect("freshly minted device signing key must verify");
    }

    #[test]
    fn device_encryption_keypair_performs_ecdh() {
        // Two M5 device-encryption keypairs must derive identical shared
        // secrets when each is fed the other's pubkey — that's the
        // primitive HPKE will rely on in Step 4. If this test ever
        // breaks, M5's transport is broken before any envelope ships.
        let (alice_priv, alice_pub) = generate_device_encryption_keypair().unwrap();
        let (bob_priv, bob_pub) = generate_device_encryption_keypair().unwrap();

        let alice_priv_arr: [u8; 32] = alice_priv.try_into().unwrap();
        let bob_priv_arr: [u8; 32] = bob_priv.try_into().unwrap();
        let alice_to_bob = ecdh_shared_secret(&alice_priv_arr, &bob_pub).unwrap();
        let bob_to_alice = ecdh_shared_secret(&bob_priv_arr, &alice_pub).unwrap();
        assert_eq!(alice_to_bob, bob_to_alice);
    }

    // ─── M3-Structural: ECDH shared-secret tests ─────────────────────────────

    #[test]
    fn ecdh_rfc5903_p256_vector() {
        // RFC 5903 §8.1 — ECDH P-256 known-answer vector.
        // Initiator (Alice) and Responder (Bob) private keys; expected
        // shared X-coordinate Z. Public keys are derived deterministically
        // from the private scalars rather than transcribed (avoids the
        // class of bug where transcribed curve coordinates drift).
        let alice_priv: [u8; 32] = [
            0xc8, 0x8f, 0x01, 0xf5, 0x10, 0xd9, 0xac, 0x3f, 0x70, 0xa2, 0x92, 0xda, 0xa2, 0x31,
            0x6d, 0xe5, 0x44, 0xe9, 0xaa, 0xb8, 0xaf, 0xe8, 0x40, 0x49, 0xc6, 0x2a, 0x9c, 0x57,
            0x86, 0x2d, 0x14, 0x33,
        ];
        let bob_priv: [u8; 32] = [
            0xc6, 0xef, 0x9c, 0x5d, 0x78, 0xae, 0x01, 0x2a, 0x01, 0x11, 0x64, 0xac, 0xb3, 0x97,
            0xce, 0x20, 0x88, 0x68, 0x5d, 0x8f, 0x06, 0xbf, 0x9b, 0xe0, 0xb2, 0x83, 0xab, 0x46,
            0x47, 0x6b, 0xee, 0x53,
        ];
        // RFC 5903 §8.1 expected Z (shared X-coordinate).
        let expected_shared: [u8; 32] = [
            0xd6, 0x84, 0x0f, 0x6b, 0x42, 0xf6, 0xed, 0xaf, 0xd1, 0x31, 0x16, 0xe0, 0xe1, 0x25,
            0x65, 0x20, 0x2f, 0xef, 0x8e, 0x9e, 0xce, 0x7d, 0xce, 0x03, 0x81, 0x24, 0x64, 0xd0,
            0x4b, 0x94, 0x42, 0xde,
        ];

        let (_, bob_pub) = keypair_from_scalar_bytes(&bob_priv).unwrap();
        let shared = ecdh_shared_secret(&alice_priv, &bob_pub).unwrap();
        assert_eq!(
            shared, expected_shared,
            "ECDH did not match RFC 5903 §8.1 vector"
        );

        // Commutativity check — defining DH property.
        let (_, alice_pub) = keypair_from_scalar_bytes(&alice_priv).unwrap();
        let shared_reverse = ecdh_shared_secret(&bob_priv, &alice_pub).unwrap();
        assert_eq!(shared, shared_reverse);
    }

    #[test]
    fn ecdh_random_keypairs_commutative() {
        let (alice_priv_vec, alice_pub) = generate_identity_keypair().unwrap();
        let (bob_priv_vec, bob_pub) = generate_identity_keypair().unwrap();
        let alice_priv: [u8; 32] = alice_priv_vec.try_into().unwrap();
        let bob_priv: [u8; 32] = bob_priv_vec.try_into().unwrap();

        let alice_to_bob = ecdh_shared_secret(&alice_priv, &bob_pub).unwrap();
        let bob_to_alice = ecdh_shared_secret(&bob_priv, &alice_pub).unwrap();
        assert_eq!(alice_to_bob, bob_to_alice);
    }

    #[test]
    fn ecdh_different_peers_give_different_secrets() {
        let alice_priv: [u8; 32] = generate_identity_keypair().unwrap().0.try_into().unwrap();
        let (_, bob_pub) = generate_identity_keypair().unwrap();
        let (_, carol_pub) = generate_identity_keypair().unwrap();

        let alice_to_bob = ecdh_shared_secret(&alice_priv, &bob_pub).unwrap();
        let alice_to_carol = ecdh_shared_secret(&alice_priv, &carol_pub).unwrap();
        assert_ne!(alice_to_bob, alice_to_carol);
    }

    #[test]
    fn ecdh_rejects_malformed_peer_pubkey() {
        let our_priv: [u8; 32] = generate_identity_keypair().unwrap().0.try_into().unwrap();

        // Wrong length
        assert!(ecdh_shared_secret(&our_priv, &[0x04u8; 10]).is_err());
        // Wrong header byte (not 0x04 SEC1 uncompressed)
        let mut bogus = vec![0x03u8; 65];
        bogus[0] = 0x05;
        assert!(ecdh_shared_secret(&our_priv, &bogus).is_err());
        // 65 zeros (point at infinity / not on curve)
        assert!(ecdh_shared_secret(&our_priv, &[0u8; 65]).is_err());
    }

    // ─── M2: DID document build / self-sign / verify ─────────────────────────

    fn make_user_keypairs() -> ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>)) {
        let root = generate_identity_keypair().unwrap();
        let enc = generate_identity_keypair().unwrap();
        (root, enc)
    }

    fn fixture_uuid(b: u8) -> uuid::Uuid {
        // Tests don't need real RNG-driven UUIDs; using a deterministic
        // pattern keeps the cargo dep surface small (no `uuid/v4` feature).
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = b.wrapping_add(i as u8);
        }
        uuid::Uuid::from_bytes(bytes)
    }

    #[test]
    fn build_did_has_root_and_encryption() {
        let ((_, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xA0);
        let doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();

        assert_eq!(doc.id, format!("did:mata:{uid}"));
        assert_eq!(doc.controller, doc.id);
        assert_eq!(doc.version, 1);
        assert_eq!(doc.pki_version, 1);
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.verification_method[0].id, "#root");
        assert_eq!(doc.verification_method[1].id, "#encryption");
        assert!(doc.proof.is_none());
        assert!(doc.mata_attestation.is_none());
    }

    #[test]
    fn self_sign_then_verify_roundtrip() {
        let ((root_priv, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xB0);
        let mut doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();

        self_sign_did_document(&mut doc, &root_priv).unwrap();
        assert!(doc.proof.is_some());

        verify_did_document_self_signature(&doc).expect("self-sig must verify");
    }

    #[test]
    fn verify_fails_when_proof_missing() {
        let ((_, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xB0);
        let doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();
        // Never signed.
        assert!(verify_did_document_self_signature(&doc).is_err());
    }

    #[test]
    fn verify_fails_after_tampering_with_field() {
        let ((root_priv, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xB0);
        let mut doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();
        self_sign_did_document(&mut doc, &root_priv).unwrap();

        // Tamper: bump version after signing.
        doc.version = 2;
        let result = verify_did_document_self_signature(&doc);
        assert!(matches!(result, Err(IdentityError::VerificationFailed)));
    }

    #[test]
    fn verify_fails_with_swapped_root_pubkey() {
        let ((root_priv, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xB0);
        let mut doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();
        self_sign_did_document(&mut doc, &root_priv).unwrap();

        // Tamper: replace #root pubkey with someone else's.
        let (_, attacker_pub) = generate_identity_keypair().unwrap();
        doc.verification_method[0].public_key_jwk = public_key_to_jwk(&attacker_pub).unwrap();

        assert!(matches!(
            verify_did_document_self_signature(&doc),
            Err(IdentityError::VerificationFailed)
        ));
    }

    #[test]
    fn re_signing_replaces_old_proof() {
        let ((root_priv, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xB0);
        let mut doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();
        self_sign_did_document(&mut doc, &root_priv).unwrap();
        let first_sig = doc.proof.as_ref().unwrap().signature.clone();

        // Bump version (legitimate change), re-sign.
        doc.version = 2;
        self_sign_did_document(&mut doc, &root_priv).unwrap();
        let second_sig = doc.proof.as_ref().unwrap().signature.clone();

        // ECDSA signatures are non-deterministic by default — different `k`
        // each time. So the bytes differ, but both verify against the same
        // pubkey + canonical bytes.
        assert_ne!(first_sig, second_sig);
        verify_did_document_self_signature(&doc).expect("re-signed proof must verify");
    }

    #[test]
    fn signing_does_not_depend_on_attestation_field() {
        // M7 will populate mata_attestation; that must NOT change the bytes
        // signed by #root. Verify the user's signature is stable when the
        // attestation appears later.
        let ((root_priv, root_pub), (_, enc_pub)) = make_user_keypairs();
        let uid = fixture_uuid(0xB0);
        let mut doc = build_initial_did_document(uid, &root_pub, &enc_pub).unwrap();
        self_sign_did_document(&mut doc, &root_priv).unwrap();

        // Simulate M7 layering on a fake attestation (signature value not
        // checked here — just confirms presence doesn't break self-sig).
        doc.mata_attestation = Some(MataAttestation {
            issuer: "did:mata:authority".into(),
            issued: chrono::Utc::now(),
            expires: chrono::Utc::now() + chrono::Duration::days(7),
            kid: "mata-root-1".into(),
            signature: "fake-sig-base64".into(),
        });

        verify_did_document_self_signature(&doc)
            .expect("user self-sig must remain valid after attestation is added");
    }

    #[test]
    fn keypair_from_scalar_is_deterministic() {
        let scalar = [0x42u8; 32];
        let (priv1, pub1) = keypair_from_scalar_bytes(&scalar).unwrap();
        let (priv2, pub2) = keypair_from_scalar_bytes(&scalar).unwrap();
        assert_eq!(priv1, priv2);
        assert_eq!(pub1, pub2);
        assert_eq!(priv1.len(), 32);
        assert_eq!(pub1.len(), 65);
        assert_eq!(pub1[0], 0x04);
    }

    #[test]
    fn keypair_from_scalar_can_sign_and_verify() {
        // Sanity: HKDF output → keypair → sign → verify chain works.
        let vault = [0x11u8; 32];
        let scalar = derive_subordinate_key(&vault, PURPOSE_ENCRYPTION);
        let (priv_bytes, pub_bytes) = keypair_from_scalar_bytes(&scalar).unwrap();
        let jwk = public_key_to_jwk(&pub_bytes).unwrap();
        let sig = sign_with_private_key(&priv_bytes, b"hello").unwrap();
        verify_signature(&jwk, b"hello", &sig).unwrap();
    }

    #[test]
    fn cross_uuid_self_signs_dont_collide() {
        // Sanity: two different users' documents produce different signing
        // bytes (so their proofs aren't interchangeable).
        let ((root_priv_a, root_pub_a), (_, enc_pub_a)) = make_user_keypairs();
        let ((_, root_pub_b), (_, enc_pub_b)) = make_user_keypairs();
        let mut doc_a = build_initial_did_document(fixture_uuid(0xC0), &root_pub_a, &enc_pub_a).unwrap();
        let doc_b = build_initial_did_document(fixture_uuid(0xD0), &root_pub_b, &enc_pub_b).unwrap();

        self_sign_did_document(&mut doc_a, &root_priv_a).unwrap();

        // Try to use A's proof on B's document. Must fail.
        let mut doc_b_with_a_proof = doc_b.clone();
        doc_b_with_a_proof.proof = doc_a.proof.clone();
        assert!(matches!(
            verify_did_document_self_signature(&doc_b_with_a_proof),
            Err(IdentityError::VerificationFailed)
        ));
    }
}
