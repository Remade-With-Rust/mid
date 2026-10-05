use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// The knobs of the flow. Frozen into each [`Challenge`](crate::Challenge)
/// at issue time, so changing the policy never retroactively loosens a live
/// challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// How long a code stays valid after it is issued.
    pub code_ttl_secs: u64,
    /// Wrong guesses allowed before the challenge is exhausted. With a 10⁶
    /// code space the default (5) bounds a brute force at 5 × 10⁻⁶ per
    /// challenge.
    pub max_attempts: u32,
    /// Minimum gap between two codes to the same address. A resend inside
    /// the gap is refused with
    /// [`FlowError::ResendTooSoon`](crate::FlowError::ResendTooSoon); a
    /// resend outside it supersedes the live challenge.
    pub resend_cooldown_secs: u64,
    /// Lifetime of a signed attestation. Short by design: an attestation is a
    /// proof-of-verification handed to a backend right after verify, not a
    /// session.
    pub attestation_ttl_secs: u64,
}

impl Policy {
    /// 10-minute codes, 5 attempts, 60-second resend gap, 5-minute
    /// attestations.
    pub const DEFAULT: Policy = Policy {
        code_ttl_secs: 600,
        max_attempts: 5,
        resend_cooldown_secs: 60,
        attestation_ttl_secs: 300,
    };

    /// Reject a policy that cannot work (zero TTL, zero attempts, a cooldown
    /// longer than the code lives).
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.code_ttl_secs == 0 {
            return Err(PolicyError::ZeroTtl);
        }
        if self.max_attempts == 0 {
            return Err(PolicyError::ZeroAttempts);
        }
        if self.resend_cooldown_secs > self.code_ttl_secs {
            return Err(PolicyError::CooldownExceedsTtl {
                cooldown: self.resend_cooldown_secs,
                ttl: self.code_ttl_secs,
            });
        }
        if self.attestation_ttl_secs == 0 {
            return Err(PolicyError::ZeroAttestationTtl);
        }
        Ok(())
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An inconsistent [`Policy`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// `code_ttl_secs` is zero.
    #[error("code_ttl_secs must be > 0")]
    ZeroTtl,
    /// `max_attempts` is zero.
    #[error("max_attempts must be >= 1")]
    ZeroAttempts,
    /// `resend_cooldown_secs` exceeds `code_ttl_secs`.
    #[error("resend_cooldown_secs ({cooldown}) must not exceed code_ttl_secs ({ttl})")]
    CooldownExceedsTtl {
        /// The configured cooldown.
        cooldown: u64,
        /// The configured TTL.
        ttl: u64,
    },
    /// `attestation_ttl_secs` is zero.
    #[error("attestation_ttl_secs must be > 0")]
    ZeroAttestationTtl,
}

/// A sliding-window counter: at most `limit` events in any `window_secs`
/// span. Pure — `now` is a parameter — so a store can persist it per key
/// (address index, client address, tenant) and the server applies it before
/// `start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateWindow {
    window_secs: u64,
    limit: u32,
    /// Event times, oldest first.
    events: VecDeque<u64>,
}

impl RateWindow {
    /// A window admitting `limit` events per `window_secs`.
    pub fn new(window_secs: u64, limit: u32) -> Self {
        Self {
            window_secs,
            limit,
            events: VecDeque::new(),
        }
    }

    /// The window length, seconds.
    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    /// Events admitted per window.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Change the window and limit, keeping the recorded events — so tightening
    /// a limit takes effect immediately and loosening it never forgets history.
    pub fn reconfigure(&mut self, window_secs: u64, limit: u32) {
        self.window_secs = window_secs;
        self.limit = limit;
    }

    /// Events still inside the window at `now`.
    pub fn count(&self, now: u64) -> u32 {
        self.events
            .iter()
            .filter(|&&t| t.saturating_add(self.window_secs) > now)
            .count() as u32
    }

    /// Drop events that have left the window.
    pub fn prune(&mut self, now: u64) {
        while let Some(&oldest) = self.events.front() {
            if oldest.saturating_add(self.window_secs) <= now {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }

    /// Admit and record an event at `now`, or refuse with the wait until the
    /// oldest in-window event leaves.
    pub fn check_and_record(&mut self, now: u64) -> Result<(), RateLimited> {
        self.prune(now);
        if self.events.len() as u32 >= self.limit {
            let oldest = self.events.front().copied().unwrap_or(now);
            let retry_after_secs = oldest
                .saturating_add(self.window_secs)
                .saturating_sub(now)
                .max(1);
            return Err(RateLimited { retry_after_secs });
        }
        self.events.push_back(now);
        Ok(())
    }
}

/// A [`RateWindow`] refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("rate limited; retry after {retry_after_secs}s")]
pub struct RateLimited {
    /// Seconds until the window admits another event.
    pub retry_after_secs: u64,
}
