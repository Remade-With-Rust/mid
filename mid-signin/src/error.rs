use mid_verify::VerifyError;

/// Errors from the relying-party authentication flow: a failed cryptographic
/// verification, or a failure of one of the stateful RP duties the verifier
/// leaves open (single-use nonces, genesis anchoring, rollback detection).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RpError {
    /// The mID token failed cryptographic verification (signature, audience,
    /// nonce equality, expiry, roster chain, …). Wraps the underlying
    /// `mid-verify` error.
    #[error("mID verification failed: {0}")]
    Verify(#[from] VerifyError),

    /// The token could not even be decomposed far enough to read its echoed
    /// nonce (not three JWS segments / bad base64url / payload not JSON).
    #[error("malformed mID token: could not read the echoed nonce")]
    MalformedToken,

    /// The expected nonce was never issued, has expired, or was already
    /// consumed — a possible replay.
    #[error("nonce was not issued, expired, or already used (possible replay)")]
    NonceRejected,

    /// The nonce store is at capacity and holds no expired entries to evict —
    /// nonce issuance is being flooded.
    #[error("nonce store at capacity ({max_live} live nonces)")]
    NonceCapacity {
        /// The store's configured live-nonce ceiling.
        max_live: usize,
    },

    /// A known DID presented a different genesis roster than first recorded —
    /// possible identity spoofing.
    #[error("genesis roster mismatch for DID {did}: possible identity spoofing")]
    GenesisMismatch {
        /// The DID whose presented genesis hash diverged from its anchor.
        did: String,
    },

    /// The presented head-roster version is lower than the last seen —
    /// possible stolen-device rollback.
    #[error(
        "rollback detected for DID {did}: presented version {presented} < last seen {last_seen}"
    )]
    Rollback {
        /// The DID that presented the regressed roster.
        did: String,
        /// The head-roster version in the presented token.
        presented: u64,
        /// The highest version this RP has previously accepted for the DID.
        last_seen: u64,
    },

    /// The session has passed its expiry.
    /// The token's roster history does not contain the roster this RP saw
    /// last at `version`: a history branched off an older roster (for example
    /// by a device removed later, which was listed in an earlier version).
    #[error("roster fork for DID {did}: this history differs from the one seen at version {version}")]
    Fork {
        /// The DID whose history forked.
        did: String,
        /// The recorded version whose roster this token does not carry.
        version: u64,
    },
    #[error("session expired: exp={exp}, now={now}")]
    SessionExpired {
        /// The session's `exp`, Unix seconds.
        exp: u64,
        /// The caller's current time, Unix seconds.
        now: u64,
    },

    /// A persistent store failed (I/O, corruption). Carries the backend's
    /// message; never carries token material.
    #[error("auth store failure: {0}")]
    Store(String),
}

impl RpError {
    /// A stable machine-readable code for HTTP responses and logs. Codes are
    /// append-only: existing values never change meaning.
    pub fn code(&self) -> &'static str {
        match self {
            RpError::Verify(_) => "verify_failed",
            RpError::MalformedToken => "malformed_token",
            RpError::NonceRejected => "nonce_rejected",
            RpError::NonceCapacity { .. } => "nonce_capacity",
            RpError::GenesisMismatch { .. } => "genesis_mismatch",
            RpError::Rollback { .. } => "rollback_detected",
            RpError::Fork { .. } => "roster_fork",
            RpError::SessionExpired { .. } => "session_expired",
            RpError::Store(_) => "store_failure",
        }
    }
}
