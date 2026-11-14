//! The attestation: a verified sign-up as a `mata-sign` statement.
//!
//! After [`verify`](crate::flow::verify) succeeds, the service signs
//! [`AttestationClaims`] with its own DID. The resulting token is
//! self-contained: a tenant's backend, a proxy, or any third party verifies
//! it **offline** with [`verify_attestation`] — the four `mid-verify` checks
//! on the signature, then the binding of the claims to the signed hash.
//! Nothing in it is a bearer secret: it names a user and when their address
//! was proven, under a signature only the service can make, for a few
//! minutes.
//!
//! The claims ride in the statement's `content_preview` and are bound by its
//! `content_hash` (the detached model), so the token carries everything a
//! verifier needs.

use serde::{Deserialize, Serialize};

use mata_sign::{Content, DeviceSigner, SignError, StatementInput, VerifyOptions};
use mid_issuer::IdentitySnapshot;

use crate::email::EmailIndex;
use crate::error::FlowError;
use crate::records::{TenantId, User, UserId};

/// The statement `context` every attestation carries; a verifier requires
/// it, so a document signature can never pass as an attestation.
pub const ATTESTATION_CONTEXT: &str = "mid-sovereign-signup/attest/v1";
/// The statement `content_type`.
pub const ATTESTATION_CONTENT_TYPE: &str = "application/vnd.mid-sovereign-signup.attestation+json";
/// The claims schema version.
pub const ATTESTATION_VERSION: u32 = 1;

/// What the service attests. Serialized as JSON in field order; the
/// statement's hash covers exactly these bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationClaims {
    /// Schema version ([`ATTESTATION_VERSION`]).
    pub v: u32,
    /// The tenant the user belongs to.
    pub tenant: TenantId,
    /// The user.
    pub user_id: UserId,
    /// The peppered index of the proven address — lets a holder of the pepper
    /// confirm which address this is without the token naming it.
    pub email_idx: EmailIndex,
    /// When the address was first proven, Unix seconds.
    pub email_verified_at: u64,
    /// The user's linked `did:mata`, if any — so a DID-aware consumer can
    /// treat the two proofs as one principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_did: Option<String>,
}

impl AttestationClaims {
    /// Claims for a verified user; refuses one whose address was never
    /// proven.
    pub fn for_user(user: &User) -> Result<Self, FlowError> {
        let email_verified_at = user.email_verified_at.ok_or(FlowError::NotVerified)?;
        Ok(Self {
            v: ATTESTATION_VERSION,
            tenant: user.tenant.clone(),
            user_id: user.id.clone(),
            email_idx: user.email_idx,
            email_verified_at,
            linked_did: user.linked_did.clone(),
        })
    }

    /// The exact bytes the statement hashes (compact JSON, field order).
    pub fn canonical_json(&self) -> String {
        serde_json::to_string(self).expect("claims serialize")
    }
}

fn statement_input(json: &str, iat: u64, ttl_secs: u64) -> StatementInput<'_> {
    StatementInput {
        content: Content::Bytes(json.as_bytes()),
        content_type: ATTESTATION_CONTENT_TYPE.to_string(),
        context: Some(ATTESTATION_CONTEXT.to_string()),
        nonce: None,
        exp: Some(iat.saturating_add(ttl_secs)),
        preview: Some(json.to_string()),
        platform_binding: None,
    }
}

/// Sign an attestation as the service identity in `snapshot` (a full
/// roster-carrying identity). `iat` is caller-supplied; the token expires at
/// `iat + ttl_secs`.
pub fn sign_attestation(
    claims: &AttestationClaims,
    snapshot: &IdentitySnapshot,
    signer: &dyn DeviceSigner,
    iat: u64,
    ttl_secs: u64,
) -> Result<String, SignError> {
    let json = claims.canonical_json();
    mata_sign::sign_statement(
        &statement_input(&json, iat, ttl_secs),
        snapshot,
        signer,
        iat,
    )
}

/// Sign an attestation as a **single-key service identity**: a DID that is
/// just this signer's key, with no roster on hand (see
/// [`mata_sign::sign_single_device`]). The common shape for a service.
pub fn sign_attestation_single_device(
    did: &str,
    multibase: &str,
    device_id: &str,
    claims: &AttestationClaims,
    signer: &dyn DeviceSigner,
    iat: u64,
    ttl_secs: u64,
) -> Result<String, SignError> {
    let json = claims.canonical_json();
    mata_sign::sign_single_device(
        did,
        multibase,
        device_id,
        &statement_input(&json, iat, ttl_secs),
        signer,
        iat,
    )
}

/// What a verifier requires of an attestation.
#[derive(Debug, Clone, Default)]
pub struct AttestationPolicy<'a> {
    /// If set, the signing DID must be exactly this (pin your signup
    /// service). Strongly recommended.
    pub expected_issuer: Option<&'a str>,
    /// If set, the claims' tenant must be exactly this.
    pub expected_tenant: Option<&'a TenantId>,
    /// The verifier's wall clock, Unix seconds.
    pub now_unix_secs: u64,
    /// Allowed forward skew of the signer's `iat` past `now`.
    pub max_iat_skew_secs: u64,
}

/// A verified attestation.
#[derive(Debug, Clone)]
pub struct VerifiedAttestation {
    /// The service DID that signed it.
    pub issuer: String,
    /// The claims, bound to the signature.
    pub claims: AttestationClaims,
    /// Issued-at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds.
    pub exp: u64,
}

/// Why an attestation was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestError {
    /// The statement failed (signature, roster, expiry, context, …).
    #[error("attestation statement: {0}")]
    Statement(#[from] mata_sign::VerifyError),
    /// Not an attestation content type.
    #[error("content type is not an attestation: {0}")]
    ContentType(String),
    /// Attestations must expire; this one does not.
    #[error("attestation carries no expiry")]
    NoExpiry,
    /// The token did not inline its claims.
    #[error("attestation carries no claims")]
    MissingClaims,
    /// The inlined claims do not hash to the signed content hash.
    #[error("claims do not match the signed content hash")]
    ContentMismatch,
    /// The claims are not valid JSON for this schema.
    #[error("claims: {0}")]
    Claims(#[from] serde_json::Error),
    /// A claims version this verifier does not understand.
    #[error("unsupported attestation version {0}")]
    UnsupportedVersion(u32),
    /// Signed by a DID other than the one required.
    #[error("issuer mismatch: expected {expected}, got {got}")]
    IssuerMismatch {
        /// Required.
        expected: String,
        /// Presented.
        got: String,
    },
    /// Attests a tenant other than the one required.
    #[error("tenant mismatch: expected {expected}, got {got}")]
    TenantMismatch {
        /// Required.
        expected: TenantId,
        /// Presented.
        got: TenantId,
    },
}

/// Verify an attestation token offline. Pure: no clock read, no network.
pub fn verify_attestation(
    token: &str,
    policy: &AttestationPolicy<'_>,
) -> Result<VerifiedAttestation, AttestError> {
    let v = mata_sign::verify_statement(
        token,
        &VerifyOptions {
            expected_context: Some(ATTESTATION_CONTEXT.to_string()),
            expected_nonce: None,
            now_unix_secs: policy.now_unix_secs,
            max_iat_skew_secs: policy.max_iat_skew_secs,
        },
    )?;
    if v.content_type != ATTESTATION_CONTENT_TYPE {
        return Err(AttestError::ContentType(v.content_type));
    }
    let exp = v.exp.ok_or(AttestError::NoExpiry)?;
    let json = v.preview.as_deref().ok_or(AttestError::MissingClaims)?;
    if !v.matches_content(json.as_bytes()) {
        return Err(AttestError::ContentMismatch);
    }
    let claims: AttestationClaims = serde_json::from_str(json)?;
    if claims.v != ATTESTATION_VERSION {
        return Err(AttestError::UnsupportedVersion(claims.v));
    }
    if let Some(expected) = policy.expected_issuer {
        if v.did != expected {
            return Err(AttestError::IssuerMismatch {
                expected: expected.to_string(),
                got: v.did,
            });
        }
    }
    if let Some(expected) = policy.expected_tenant {
        if claims.tenant != *expected {
            return Err(AttestError::TenantMismatch {
                expected: expected.clone(),
                got: claims.tenant,
            });
        }
    }
    Ok(VerifiedAttestation {
        issuer: v.did,
        claims,
        iat: v.iat,
        exp,
    })
}
