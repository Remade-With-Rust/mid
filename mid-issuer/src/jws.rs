//! JWS compact-form encoding for ES256.
//!
//! Implements the JWS spec (RFC 7515) Section 3.1 compact serialization for
//! ES256 (RFC 7518 §3.4) — the only signature algorithm mID supports in v1.
//!
//! ## Compact form
//!
//! ```text
//! base64url(header) || "." || base64url(payload) || "." || base64url(signature)
//! ```
//!
//! Where:
//! - `header` is the JWS header JSON `{"alg":"ES256","typ":"JWT"}`.
//! - `payload` is the application-supplied JSON.
//! - `signature` is 64 bytes: `r || s`, low-s canonical form, over
//!   `SHA-256(base64url(header) || "." || base64url(payload))`.
//!
//! ## Why not the `jsonwebtoken` crate
//!
//! - We already have the ECDSA signing primitive in [`DeviceSigner`]; no
//!   reason to drag in a second crypto dep.
//! - JWS compact form is tiny — implementing it directly is ~50 LOC and
//!   keeps the audit surface in this crate's repo.
//! - `jsonwebtoken` ties signing to its own internal key-handle abstraction,
//!   which can't represent a `DeviceSigner` (Secure Enclave / StrongBox /
//!   software-vault) uniformly.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kms_client::DeviceSigner;
use sha2::{Digest, Sha256};

use crate::error::MidIssuerError;

/// The JWS header. Fixed for v1 — `alg: ES256`, `typ: JWT`. Serializing
/// inline rather than as a struct keeps the header bytes deterministic
/// (no field-ordering ambiguity).
///
/// This exact JSON is committed to as the prehash input; changing it is a
/// wire-format break.
const JWS_HEADER_JSON: &str = r#"{"alg":"ES256","typ":"JWT"}"#;

/// Build a JWS compact-form ES256 token from a JSON payload.
///
/// `payload_json` MUST be a serialized JSON object. The caller is
/// responsible for canonical key ordering — `serde_json` produces a stable
/// output for `BTreeMap`-based structs, which is what
/// [`crate::types::MidJwtPayload`] uses.
///
/// The signer's [`DeviceSigner::sign_prehash`] is called with the SHA-256
/// of the `base64url(header).base64url(payload)` signing input. The
/// resulting 64-byte `r || s` is base64url-encoded and concatenated as the
/// third segment.
pub fn build_jws_compact(
    payload_json: &[u8],
    signer: &dyn DeviceSigner,
) -> Result<String, MidIssuerError> {
    let header_b64 = URL_SAFE_NO_PAD.encode(JWS_HEADER_JSON.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);

    // Signing input: header.payload (no leading or trailing chars). RFC
    // 7515 §5.1 step 7.
    let mut signing_input = String::with_capacity(header_b64.len() + 1 + payload_b64.len());
    signing_input.push_str(&header_b64);
    signing_input.push('.');
    signing_input.push_str(&payload_b64);

    // SHA-256 the signing input before passing to the device. The
    // DeviceSigner contract takes a 32-byte prehash and produces low-s
    // canonical r || s.
    let mut hasher = Sha256::new();
    hasher.update(signing_input.as_bytes());
    let prehash: [u8; 32] = hasher.finalize().into();

    let signature_bytes = signer.sign_prehash(&prehash);
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature_bytes);

    let mut out = signing_input;
    out.reserve(1 + signature_b64.len());
    out.push('.');
    out.push_str(&signature_b64);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kms_client::InMemoryDeviceSigner;
    use p256::ecdsa::SigningKey;

    /// Deterministic-from-device-id test signer. The signing key is derived
    /// by hashing the device_id, so tests are reproducible (same id → same
    /// key) and don't rely on kms-client's `generate` convenience method.
    fn make_test_signer(device_id: &str) -> InMemoryDeviceSigner {
        let mut hasher = Sha256::new();
        hasher.update(device_id.as_bytes());
        hasher.update(b"-mid-issuer-test-seed");
        let seed: [u8; 32] = hasher.finalize().into();
        let signing_key = SigningKey::from_bytes(&seed.into()).expect("non-zero test seed");
        InMemoryDeviceSigner::new(device_id, signing_key)
    }

    #[test]
    fn jws_has_three_dot_separated_segments() {
        let signer = make_test_signer("test-device");
        let payload = serde_json::to_vec(&serde_json::json!({"hello": "world"})).unwrap();
        let jws = build_jws_compact(&payload, &signer).unwrap();
        assert_eq!(jws.matches('.').count(), 2, "jws compact form is 3 segments separated by 2 dots");
    }

    #[test]
    fn jws_header_segment_decodes_to_expected_header() {
        let signer = make_test_signer("test-device");
        let payload = serde_json::to_vec(&serde_json::json!({"x": 1})).unwrap();
        let jws = build_jws_compact(&payload, &signer).unwrap();
        let header_segment = jws.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_segment).unwrap();
        let header_str = std::str::from_utf8(&header_bytes).unwrap();
        assert_eq!(header_str, r#"{"alg":"ES256","typ":"JWT"}"#);
    }

    #[test]
    fn jws_signature_segment_is_64_bytes_base64url() {
        let signer = make_test_signer("test-device");
        let payload = serde_json::to_vec(&serde_json::json!({"x": 1})).unwrap();
        let jws = build_jws_compact(&payload, &signer).unwrap();
        let sig_segment = jws.split('.').nth(2).unwrap();
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_segment).unwrap();
        assert_eq!(sig_bytes.len(), 64, "ES256 signature is 64 bytes (r || s)");
    }
}
