//! RFC 8785 JSON Canonicalization Scheme (JCS) wrappers for DID documents.
//!
//! Critical Implementation Detail #2: ECDSA signs bytes, not JSON. The same
//! document must produce the same byte stream regardless of object-key
//! ordering or whitespace, on every platform that signs or verifies it.
//!
//! We use the [`serde_jcs`] crate for the actual JCS step (don't roll our
//! own — RFC 8785's number-formatting rules are subtle and easy to get
//! wrong) and add a domain-specific helper that strips the signing
//! envelope before canonicalizing, so the document can self-sign without
//! signing its own signature.
//!
//! ## Used by
//!
//! - [`crate::self_sign_did_document`] — produces the bytes that go into
//!   [`crate::did::DidProof::signature`].
//! - [`crate::verify_did_document_self_signature`] — recomputes the same
//!   bytes from the received document for verification.
//! - M7: `issue-did-attestation` edge function — recomputes the bytes
//!   server-side before calling KMS. The user-signed bytes and the
//!   MATA-signed bytes are identical so a single canonicalization is
//!   used for both signatures.

use crate::did::DidDocument;

/// Errors specific to canonicalization. Wraps the underlying `serde_jcs`
/// failure modes (which are vanishingly rare for well-typed input).
#[derive(Debug)]
pub enum CanonicalizeError {
    Serialize(String),
}

impl std::fmt::Display for CanonicalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(s) => write!(f, "JCS canonicalization failed: {s}"),
        }
    }
}

impl std::error::Error for CanonicalizeError {}

/// Canonicalize a DID document with `proof` and `mata_attestation` stripped.
///
/// This is the byte stream that BOTH the user (via `#root`) and MATA (via
/// the corporate root key in M7) sign. Stripping the signing envelopes
/// means the document carries its own signatures without circular
/// "signing the signature" semantics.
///
/// # Use
///
/// Prefer this over [`canonicalize_full`] for any signing or verification
/// flow. `canonicalize_full` exists only for diagnostic / audit purposes.
pub fn canonicalize_for_signing_unsigned(doc: &DidDocument) -> Result<Vec<u8>, CanonicalizeError> {
    // Clone-and-strip rather than mutating the caller's value. The clone
    // is cheap (Rc-free POD types) and keeps the signing path side-effect-
    // free.
    let mut stripped = doc.clone();
    stripped.proof = None;
    stripped.mata_attestation = None;
    canonicalize_full(&stripped)
}

/// Canonicalize the full DID document, including any `proof` /
/// `mata_attestation`. Used when caching the exact byte form a verifier
/// will hash, or for audit logs. **Not for signing** — use
/// [`canonicalize_for_signing_unsigned`] instead.
pub fn canonicalize_full(doc: &DidDocument) -> Result<Vec<u8>, CanonicalizeError> {
    serde_jcs::to_string(doc)
        .map(String::into_bytes)
        .map_err(|e| CanonicalizeError::Serialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::{DidDocument, DidProof, VerificationMethod};
    use crate::JwkPublicKey;
    use chrono::{DateTime, Utc};

    fn fixture_doc(with_proof: bool) -> DidDocument {
        let updated = DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let jwk = JwkPublicKey {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA".into(),
        };
        DidDocument {
            id: "did:mata:11111111-1111-1111-1111-111111111111".into(),
            controller: "did:mata:11111111-1111-1111-1111-111111111111".into(),
            version: 1,
            updated,
            pki_version: 1,
            verification_method: vec![VerificationMethod {
                id: "#root".into(),
                type_: "EcdsaSecp256r1VerificationKey2019".into(),
                public_key_jwk: jwk,
                purpose: vec!["authentication".into(), "capabilityInvocation".into()],
                scope: None,
                expires: None,
            }],
            service: vec![],
            proof: if with_proof {
                Some(DidProof {
                    type_: "EcdsaSecp256r1Signature2019".into(),
                    verification_method: "#root".into(),
                    signature: "test-signature-base64url".into(),
                })
            } else {
                None
            },
            mata_attestation: None,
        }
    }

    #[test]
    fn signing_form_strips_proof() {
        let signed = canonicalize_for_signing_unsigned(&fixture_doc(true)).unwrap();
        let unsigned = canonicalize_for_signing_unsigned(&fixture_doc(false)).unwrap();
        assert_eq!(
            signed, unsigned,
            "presence/absence of proof must not change signing bytes"
        );
    }

    #[test]
    fn signing_form_omits_proof_field() {
        let bytes = canonicalize_for_signing_unsigned(&fixture_doc(true)).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("proof"), "proof must be stripped: {}", s);
        assert!(
            !s.contains("mataAttestation"),
            "mataAttestation must be stripped: {}",
            s
        );
    }

    #[test]
    fn canonical_output_has_sorted_keys() {
        let bytes = canonicalize_for_signing_unsigned(&fixture_doc(false)).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        // RFC 8785 sorts object keys lexicographically (UTF-16 code-unit
        // order). For our top-level fields the alphabetical order is:
        // controller, id, pkiVersion, updated, verificationMethod, version.
        // Find positions and confirm ordering.
        let pos = |needle: &str| s.find(&format!("\"{needle}\"")).expect("field present");
        let p_controller = pos("controller");
        let p_id = pos("id");
        let p_pki = pos("pkiVersion");
        let p_updated = pos("updated");
        let p_vm = pos("verificationMethod");
        let p_version = pos("version");
        assert!(
            p_controller < p_id
                && p_id < p_pki
                && p_pki < p_updated
                && p_updated < p_vm
                && p_vm < p_version,
            "JCS keys not sorted lexicographically: {}",
            s
        );
    }

    #[test]
    fn full_form_includes_proof_when_present() {
        let bytes = canonicalize_full(&fixture_doc(true)).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("proof"));
        assert!(s.contains("test-signature-base64url"));
    }

    #[test]
    fn deterministic_across_calls() {
        let a = canonicalize_for_signing_unsigned(&fixture_doc(false)).unwrap();
        let b = canonicalize_for_signing_unsigned(&fixture_doc(false)).unwrap();
        assert_eq!(a, b);
    }
}
