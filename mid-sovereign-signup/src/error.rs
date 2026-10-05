use crate::code::CodeError;
use crate::email::EmailError;
use crate::policy::{PolicyError, RateLimited};
use crate::seams::EntropyError;

/// Errors from the sign-up / sign-in flow. Every variant is safe to show to
/// the end user: none carries the code, the address, or store internals.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FlowError {
    /// The address failed normalization (see [`crate::NormalizedEmail`]).
    #[error("invalid email address: {0}")]
    InvalidEmail(#[from] EmailError),

    /// The presented code is not six digits. Malformed input never counts as
    /// an attempt — it cannot be a guess.
    #[error("invalid code: {0}")]
    InvalidCode(#[from] CodeError),

    /// A code was sent to this address within
    /// [`Policy::resend_cooldown_secs`](crate::Policy::resend_cooldown_secs).
    #[error("a code was sent recently; retry after {retry_after_secs}s")]
    ResendTooSoon {
        /// Seconds until a resend is allowed.
        retry_after_secs: u64,
    },

    /// A [`RateWindow`](crate::RateWindow) refused the request.
    #[error("rate limited; retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds until the window admits another request.
        retry_after_secs: u64,
    },

    /// No live challenge exists for this address — nothing was started, or it
    /// was already finished. The user must start again.
    #[error("no live code for this address; start again")]
    NoLiveChallenge,

    /// The challenge passed its TTL. The user must start again.
    #[error("the code has expired; start again")]
    Expired,

    /// The code did not match. The attempt has been counted.
    #[error("wrong code ({attempts_left} attempts left)")]
    WrongCode {
        /// Guesses remaining before the challenge is exhausted.
        attempts_left: u32,
    },

    /// Too many wrong codes; the challenge is consumed. The user must start
    /// again.
    #[error("too many wrong codes; start again")]
    AttemptsExhausted,

    /// The challenge was already consumed (verified, exhausted, or
    /// superseded by a resend). The user must start again.
    #[error("this code was already used; start again")]
    AlreadyConsumed,

    /// The code was correct but no account exists and the challenge was
    /// started in sign-in-only mode (`create_user: false`).
    #[error("no account for this address and the request did not allow creating one")]
    UnknownUser,

    /// The challenge the store loaded is not the one for this tenant and
    /// address — a store bug, not user error.
    #[error("the loaded challenge does not belong to this tenant/address (store returned the wrong record)")]
    ChallengeMismatch,

    /// The user the store loaded is not the one for this tenant and address —
    /// a store bug, not user error.
    #[error(
        "the loaded user does not belong to this tenant/address (store returned the wrong record)"
    )]
    UserMismatch,

    /// An attestation was requested for a user whose address was never
    /// verified.
    #[error("the user's address has not been verified")]
    NotVerified,

    /// A different DID is already linked to this user; unlink first.
    #[error("a DID is already linked to this user: {did}")]
    DidAlreadyLinked {
        /// The DID currently linked.
        did: String,
    },

    /// The value is not a `did:mata:…` identifier.
    #[error("not a did:mata identifier")]
    InvalidDid,

    /// A username must be 3–32 of `a-z 0-9 _ . -`, starting and ending with a
    /// letter or digit.
    #[error("usernames are 3-32 letters, digits, '_', '.', '-', starting and ending with a letter or digit")]
    InvalidUsername,

    /// The entropy source failed (OS RNG unavailable, fixed entropy
    /// exhausted).
    #[error(transparent)]
    Entropy(#[from] EntropyError),

    /// The [`Policy`](crate::Policy) is internally inconsistent.
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

impl FlowError {
    /// A stable machine-readable code for HTTP responses and logs. Codes are
    /// append-only: existing values never change meaning.
    pub fn code(&self) -> &'static str {
        match self {
            FlowError::InvalidEmail(_) => "invalid_email",
            FlowError::InvalidCode(_) => "invalid_code",
            FlowError::ResendTooSoon { .. } => "resend_too_soon",
            FlowError::RateLimited { .. } => "rate_limited",
            FlowError::NoLiveChallenge => "no_live_challenge",
            FlowError::Expired => "code_expired",
            FlowError::WrongCode { .. } => "wrong_code",
            FlowError::AttemptsExhausted => "attempts_exhausted",
            FlowError::AlreadyConsumed => "code_consumed",
            FlowError::UnknownUser => "unknown_user",
            FlowError::ChallengeMismatch => "challenge_mismatch",
            FlowError::UserMismatch => "user_mismatch",
            FlowError::NotVerified => "not_verified",
            FlowError::DidAlreadyLinked { .. } => "did_already_linked",
            FlowError::InvalidDid => "invalid_did",
            FlowError::InvalidUsername => "invalid_username",
            FlowError::Entropy(_) => "entropy_failure",
            FlowError::Policy(_) => "policy_invalid",
        }
    }

    /// `true` when the only way forward is to start a new challenge (the
    /// current one is gone, expired, or exhausted). A client uses this to
    /// swap "try again" for "send a new code".
    pub fn needs_new_code(&self) -> bool {
        matches!(
            self,
            FlowError::NoLiveChallenge
                | FlowError::Expired
                | FlowError::AttemptsExhausted
                | FlowError::AlreadyConsumed
        )
    }

    /// `true` when the fault is in the caller's wiring (the store handed the
    /// core a record for a different tenant/address, or the policy is
    /// inconsistent) rather than in anything the end user did.
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            FlowError::ChallengeMismatch
                | FlowError::UserMismatch
                | FlowError::Entropy(_)
                | FlowError::Policy(_)
        )
    }
}

impl From<RateLimited> for FlowError {
    fn from(r: RateLimited) -> Self {
        FlowError::RateLimited {
            retry_after_secs: r.retry_after_secs,
        }
    }
}
