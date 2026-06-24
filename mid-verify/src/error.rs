//! Typed error variants for the mID verifier.
//!
//! Every variant maps to a specific failure mode so the RP backend can
//! react distinctly (log it, return 401 with a specific code, alert a
//! security team). Generic catch-alls like `Other` are deliberately
//! avoided — production code reading `match err { ... }` should never
//! hit a fallback.

use thiserror::Error;

/// The single error type returned by [`crate::verify_mid_response`].
#[derive(Debug, Error)]
pub enum VerifyError {
    // ─── JWS shape / encoding ──────────────────────────────────────────────
    /// The JWT string did not have exactly 3 dot-separated segments.
    #[error("invalid JWS compact form: expected 3 segments, got {0}")]
    InvalidJwsShape(usize),

    /// One of the base64url segments failed to decode.
    #[error("base64url decoding failed for {segment} segment: {source}")]
    Base64Decode {
        /// Which segment failed: "header", "payload", or "signature".
        segment: &'static str,
        /// The underlying base64 error.
        source: base64::DecodeError,
    },

    /// The JWS header was not valid JSON or did not declare `alg: ES256`.
    #[error("invalid or unsupported JWS header (alg must be ES256, typ must be JWT)")]
    InvalidJwsHeader,

    /// The JWT payload JSON was not parseable into a [`mid_issuer::MidJwtPayload`].
    #[error("JWT payload JSON malformed: {0}")]
    PayloadJson(#[from] serde_json::Error),

    // ─── Metadata checks ───────────────────────────────────────────────────
    /// The `aud` claim did not match the verifier's expected audience.
    #[error("audience mismatch: expected `{expected}`, got `{actual}`")]
    AudienceMismatch {
        /// What the RP configured.
        expected: String,
        /// What the JWT carried.
        actual: String,
    },

    /// The `nonce` claim did not match the nonce the RP issued for this
    /// session — possible replay attempt or stale tab.
    #[error("nonce mismatch — possible replay or stale request")]
    NonceMismatch,

    /// The JWT's `exp` is in the past relative to the verifier's clock.
    #[error("token expired: exp={exp}, now={now}")]
    Expired {
        /// JWT's expiry claim.
        exp: u64,
        /// Verifier's wall clock.
        now: u64,
    },

    /// The JWT's `iat` is too far in the future for the verifier's clock
    /// skew tolerance — possible attacker producing forward-dated tokens
    /// or genuine clock skew.
    #[error("token issued too far in the future: iat={iat}, now={now}, max skew {max_skew_secs}s")]
    NotYetValid {
        /// JWT's issued-at claim.
        iat: u64,
        /// Verifier's wall clock.
        now: u64,
        /// Verifier's configured skew tolerance.
        max_skew_secs: u64,
    },

    // ─── Key decoding ──────────────────────────────────────────────────────
    /// The DID's base58 suffix did not decode to a valid P-256 public key.
    /// Either the DID is malformed or it's from a non-mID identity system.
    #[error("DID `{did}` does not encode a valid P-256 public key")]
    MalformedDid {
        /// The DID that failed to decode.
        did: String,
    },

    /// A verification method's `publicKeyMultibase` did not decode to a
    /// valid P-256 public key.
    #[error("verification method `{vm_id}` has an invalid public_key_multibase")]
    MalformedVmPubkey {
        /// The VM ID whose pubkey failed to decode.
        vm_id: String,
    },

    /// A base64url-encoded signature was not 64 bytes (the expected
    /// `r || s` form for ES256).
    #[error("signature has wrong length: expected 64 bytes, got {actual}")]
    SignatureWrongLength {
        /// The length actually decoded.
        actual: usize,
    },

    // ─── Cryptographic checks ──────────────────────────────────────────────
    /// The genesis roster's self-signature did not verify against the key
    /// recoverable from the DID. Either the genesis roster was tampered
    /// with or the signature is from a different key — the user does not
    /// hold the genesis key.
    #[error("genesis roster self-signature is invalid (does not verify against key encoded in DID)")]
    GenesisSignatureInvalid,

    /// A roster chain entry was signed by a verification method that is
    /// not present in the prior entry's roster — the chain is broken.
    #[error(
        "chain entry version {entry_version} signed by `{signer_kid}`, which is not in the prior roster"
    )]
    ChainSignerNotInPriorRoster {
        /// The version of the chain entry whose signer is unknown.
        entry_version: u64,
        /// The signer_kid that doesn't appear in the prior roster.
        signer_kid: String,
    },

    /// A roster chain entry's signature did not verify against the
    /// claimed signer's public key. Either the entry was tampered with
    /// or the signature is from a different key.
    #[error("chain entry version {entry_version} has an invalid signature")]
    ChainSignatureInvalid {
        /// The chain entry version that failed signature verification.
        entry_version: u64,
    },

    /// Chain versions did not strictly increase. Indicates a stolen
    /// device trying to bundle an older roster envelope as the head, or
    /// a malformed chain.
    #[error(
        "chain version not strictly monotonic: entry version {entry_version} <= prior version {prior_version}"
    )]
    ChainVersionNotMonotonic {
        /// The non-monotonic entry's version.
        entry_version: u64,
        /// The prior entry's version (must be < entry_version).
        prior_version: u64,
    },

    /// The verification method that signed the JWT is not present in the
    /// head roster — the signing device has been revoked.
    #[error(
        "current verification method `{vm_id}` is not in the head roster — device has been revoked"
    )]
    CurrentVmNotInHeadRoster {
        /// The VM ID that's not in the head roster.
        vm_id: String,
    },

    /// The JWS outer signature did not verify against the embedded
    /// verification method's public key.
    #[error("JWS outer signature did not verify against the embedded verification method")]
    JwtSignatureInvalid,

    // ─── Optional rollback detection ───────────────────────────────────────
    /// The current roster version is less than the highest the RP has
    /// seen for this DID — possible stolen-device replay of an old
    /// (pre-revocation) roster envelope.
    ///
    /// This variant is NEVER produced by [`crate::verify_mid_response`]
    /// directly; the RP uses [`crate::VerifiedMid::check_rollback`] after
    /// looking up `last_seen_version` from its own per-DID store.
    #[error("rollback detected: current version {current} < last seen {last_seen}")]
    RollbackDetected {
        /// The current head roster version from the verified JWT.
        current: u64,
        /// The highest version this RP has seen for this DID.
        last_seen: u64,
    },
}
