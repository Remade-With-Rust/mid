//! DID document types — `did:mata:<user_uuid>`.
//!
//! Shape mirrors the example in `docs/plans/phase 1 KMS implementation
//! mission.md`. Field ordering inside this file is the **canonical** order
//! the example uses; serialization order on the wire is determined by
//! [`serde_jcs`](crate::canonicalize) (RFC 8785 lexicographic key sorting),
//! not by struct field order.
//!
//! ## M2/M7 split
//!
//! `mata_attestation` is `Option` because Milestone 2 (structural) ships
//! self-signed documents only. Milestone 7 (deferred KMS infrastructure)
//! populates the field. Verifiers handed an M2-era document should treat
//! `mata_attestation: None` as "user-asserted, not MATA-attested" and
//! decide based on their trust posture whether that's sufficient.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::JwkPublicKey;

/// A user's full DID document, as published in `user_identity_keys.did_document`.
///
/// The `proof` field is the user's own signature over the canonicalized
/// representation of every other field (excluding `proof` and
/// `mata_attestation` themselves — see
/// [`crate::canonicalize::canonicalize_for_signing_unsigned`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// `did:mata:<uuid>`. Stable for the lifetime of the user.
    pub id: String,
    /// Same value as `id` for self-controlled DIDs (the universal case in M2).
    pub controller: String,
    /// Monotonically increasing version of this document — bumped every time
    /// any field changes. M2 ships v1 at signup and never bumps until M4
    /// adds key rotation.
    pub version: u32,
    /// When this document version was produced.
    pub updated: DateTime<Utc>,
    /// Protocol version for forward compatibility — Critical Implementation
    /// Detail #4. M6 introduces v2 when post-quantum signatures land.
    pub pki_version: u32,
    /// Every public key the user currently uses, with its purpose and
    /// optional scope/expiry. M2 populates `#root` and `#encryption`;
    /// M4 adds task-scoped and delegation entries here.
    pub verification_method: Vec<VerificationMethod>,
    /// Service endpoints — e.g. messaging inbox. Empty in M2; M3 adds
    /// `#messaging`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<ServiceEndpoint>,
    /// User's self-signature over the document. Present in M2 onward.
    /// `Option` so the unsigned skeleton can be passed around before
    /// [`crate::self_sign_did_document`] fills it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DidProof>,
    /// MATA's notary signature. `None` in M2-Structural; populated in M7.
    /// External verifiers MUST decide whether a document without this is
    /// acceptable for their use case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mata_attestation: Option<MataAttestation>,
}

/// A single public key in the user's `verification_method` list.
///
/// The `id` is a relative DID URL (`#root`, `#encryption`, `#signing-acme`,
/// etc.). Combine with the document's `id` to form the absolute reference
/// (`did:mata:abc...#root`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    /// `#root`, `#encryption`, `#signing-<service>`, etc.
    pub id: String,
    /// `EcdsaSecp256r1VerificationKey2019` (signing keys) or
    /// `EcdhEsP256` (key-agreement keys).
    #[serde(rename = "type")]
    pub type_: String,
    /// The public key as a JWK.
    pub public_key_jwk: JwkPublicKey,
    /// What this key is used for. Standard W3C DID Core values:
    /// `authentication`, `assertionMethod`, `keyAgreement`,
    /// `capabilityInvocation`, `capabilityDelegation`.
    pub purpose: Vec<String>,
    /// Optional service this key is scoped to (e.g. `"acme.com"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Optional expiry — Level 1 of the revocation model
    /// (Critical Implementation Detail: most "revocation" is just expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<DateTime<Utc>>,
}

/// A service endpoint listed alongside the verification methods.
///
/// Empty in M2. M3 populates `#messaging` so senders can discover where to
/// deliver an encrypted message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub service_endpoint: String,
}

/// User's self-signature, written into [`DidDocument::proof`] by
/// [`crate::self_sign_did_document`] and verified by
/// [`crate::verify_did_document_self_signature`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidProof {
    /// Always `"EcdsaSecp256r1Signature2019"` in M2.
    #[serde(rename = "type")]
    pub type_: String,
    /// Which `verification_method` produced the signature — always
    /// `"#root"` in M2 (only key with `capabilityInvocation` purpose).
    pub verification_method: String,
    /// DER-encoded ECDSA signature, base64url-encoded.
    pub signature: String,
}

/// MATA's notary signature over the document, populated in M7.
///
/// Verifiers fetch `/.well-known/mata-pki-roots.json` to learn MATA's
/// public root key, then validate `signature` against the same canonical
/// bytes the user signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MataAttestation {
    /// Always `"did:mata:authority"`.
    pub issuer: String,
    /// When MATA signed.
    pub issued: DateTime<Utc>,
    /// When the attestation expires — default 1 week from `issued`.
    /// Active users silently re-attest within 24 h of expiry.
    pub expires: DateTime<Utc>,
    /// Which root key signed — opaque ID like `"mata-root-1"`, never an
    /// AWS ARN, so MATA can migrate KMS providers without touching
    /// verifiers (see M7 plan section).
    pub kid: String,
    /// DER-encoded signature, base64url-encoded.
    pub signature: String,
}

/// Format a user UUID as a `did:mata:<uuid>` string. The UUID is
/// rendered hyphenated lowercase, matching Supabase's `auth.users.id`.
pub fn did_for_user(user_uuid: uuid::Uuid) -> String {
    format!("did:mata:{user_uuid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_format_matches_spec() {
        let uuid = uuid::Uuid::parse_str("63c58bf2-ddfe-426c-9476-2f1625bc3f12").unwrap();
        assert_eq!(
            did_for_user(uuid),
            "did:mata:63c58bf2-ddfe-426c-9476-2f1625bc3f12"
        );
    }

    #[test]
    fn empty_optionals_omitted_from_json() {
        let doc = DidDocument {
            id: "did:mata:00000000-0000-0000-0000-000000000000".into(),
            controller: "did:mata:00000000-0000-0000-0000-000000000000".into(),
            version: 1,
            updated: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            pki_version: 1,
            verification_method: vec![],
            service: vec![],
            proof: None,
            mata_attestation: None,
        };
        let json = serde_json::to_string(&doc).unwrap();
        // Empty `service` vec, missing `proof`, missing `mata_attestation`
        // should not appear in the output — keeps the canonical signing
        // bytes stable as the document grows.
        assert!(!json.contains("service"));
        assert!(!json.contains("proof"));
        assert!(!json.contains("mataAttestation"));
    }

    #[test]
    fn pki_version_serialized_as_camel_case() {
        let doc = DidDocument {
            id: "did:mata:x".into(),
            controller: "did:mata:x".into(),
            version: 1,
            updated: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
            pki_version: 1,
            verification_method: vec![],
            service: vec![],
            proof: None,
            mata_attestation: None,
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.contains("\"pkiVersion\":1"), "got: {}", json);
    }
}
