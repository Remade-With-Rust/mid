//! Spec-frozen error taxonomy per [envelope_spec.md §"Error taxonomy"](../../../docs/kms/envelope_spec.md).
//!
//! `kms-types::validate()` returns the shape-only variants (everything except
//! the verifier-state variants — `NonceExpired`, `NonceAlreadyConsumed`,
//! `NonceNotFound`, `DidNotFound`, `DeviceNotInRoster`, `SignatureInvalid`,
//! `StorageError`). The verifier crate adds those.
//!
//! Per spec, all of these map to a single opaque `"invalid assertion"` response
//! when surfaced to a client — no DID-existence oracle, no information about
//! which specific check failed. The granular variants exist for server-side
//! logging and tests.

use thiserror::Error;

/// Verification failure modes. See module docs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// Envelope JSON couldn't be parsed, or a required field was missing.
    #[error("malformed envelope")]
    MalformedEnvelope,

    /// `envelope_version` is a value this verifier doesn't recognize.
    #[error("unknown envelope version")]
    UnknownEnvelopeVersion,

    /// `envelope_type` doesn't match the envelope being decoded
    /// (e.g., a `RosterUpdate` arrived where a `NonceEnvelope` was expected).
    #[error("wrong envelope type")]
    WrongEnvelopeType,

    /// `audience` is not in this verifier's allow-list.
    #[error("unknown audience")]
    UnknownAudience,

    /// `purpose` is not in the allow-list for this audience.
    #[error("unknown purpose")]
    UnknownPurpose,

    /// `nonce` field is not exactly 32 bytes.
    #[error("malformed nonce")]
    MalformedNonce,

    /// `did` doesn't match the `did:mata:<base58>` shape.
    #[error("malformed did")]
    MalformedDid,

    /// `expires_at <= issued_at`, or TTL > 300 seconds.
    #[error("invalid timestamps")]
    InvalidTimestamps,

    /// Roster update's `new_version != prior_version + 1`.
    #[error("non-monotonic roster version")]
    NonMonotonicVersion,

    /// Roster update's `new_roster` is empty (would unreach the DID).
    #[error("empty roster")]
    EmptyRoster,

    /// Roster update's `signed_at` is more than 300s away from now.
    #[error("roster update timestamp out of range")]
    RosterTimestampOutOfRange,

    /// Roster update's `prior_version` doesn't match the current
    /// `roster_version` in `kms_did_documents` — another device beat
    /// this update to the punch. The client should re-resolve the DID
    /// document and retry with the fresh prior_version.
    #[error("stale roster version")]
    StaleRosterVersion,

    /// Nonce TTL exceeded before the assertion arrived.
    #[error("nonce expired")]
    NonceExpired,

    /// Nonce was already consumed by an earlier verify.
    #[error("nonce already consumed")]
    NonceAlreadyConsumed,

    /// Nonce ID isn't in the nonce store.
    #[error("nonce not found")]
    NonceNotFound,

    /// No `kms_did_documents` row for the claimed DID.
    #[error("did not found")]
    DidNotFound,

    /// `device_id` isn't present in the resolved roster.
    #[error("device not in roster")]
    DeviceNotInRoster,

    /// Ed25519 signature failed to verify against the device's pubkey.
    #[error("signature invalid")]
    SignatureInvalid,

    /// `audience` in the signed nonce doesn't match the verifier's expected
    /// audience (defense against cross-audience replay).
    #[error("audience mismatch")]
    AudienceMismatch,

    /// `purpose` in the signed nonce doesn't match the endpoint's expected
    /// purpose.
    #[error("purpose mismatch")]
    PurposeMismatch,

    /// `issuer` in the signed nonce doesn't match this verifier's configured
    /// issuer ID.
    #[error("issuer mismatch")]
    IssuerMismatch,

    /// Underlying storage (nonce store, DID resolver, etc.) reported an error.
    #[error("storage error: {0}")]
    StorageError(String),
}
