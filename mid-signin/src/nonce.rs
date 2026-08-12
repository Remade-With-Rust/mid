use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::RpError;

/// Default time-to-live for an issued, unconsumed nonce: 10 minutes — ample
/// for a human to complete the consent screen, short enough that abandoned
/// nonces don't accumulate.
pub const DEFAULT_NONCE_TTL_SECS: u64 = 600;

/// Default ceiling on simultaneously-live nonces. Bounds memory/disk under a
/// nonce-issuance flood; at 32-byte nonces this is ~6 MB of hex strings.
pub const DEFAULT_MAX_LIVE_NONCES: usize = 100_000;

/// A single-use nonce store. The RP issues a nonce per sign-in (embedded in
/// the mID request, echoed in the returned JWT) and consumes it when the
/// token verifies; a second presentation of the same nonce fails, defeating
/// token replay. The verifier only checks nonce *equality* — proving the
/// nonce was ours and enforcing single use is this store's job.
///
/// `now_unix_secs` is a parameter (never read from a clock inside the store)
/// so implementations stay pure and deterministic under test.
pub trait NonceStore: Send + Sync {
    /// Issue and record a fresh single-use nonce.
    ///
    /// Errors with [`RpError::NonceCapacity`] when the live set is full and
    /// holds nothing expired to evict, or [`RpError::Store`] on backend
    /// failure.
    fn issue(&self, now_unix_secs: u64) -> Result<String, RpError>;

    /// Consume a nonce. Returns `true` iff it had been issued, had not
    /// expired, and had not yet been used. Expired or unknown nonces return
    /// `false` — indistinguishable by design (both are rejections).
    fn consume(&self, nonce: &str, now_unix_secs: u64) -> Result<bool, RpError>;
}

/// Process-local [`NonceStore`] with TTL expiry and a live-set ceiling.
/// For persistence across restarts use `RedbStore` (feature `redb-store`)
/// or implement the trait over your own database.
pub struct InMemoryNonceStore {
    ttl_secs: u64,
    max_live: usize,
    /// nonce → issued_at (Unix seconds)
    live: Mutex<HashMap<String, u64>>,
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryNonceStore {
    /// A store with the default TTL ([`DEFAULT_NONCE_TTL_SECS`]) and ceiling
    /// ([`DEFAULT_MAX_LIVE_NONCES`]).
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_NONCE_TTL_SECS, DEFAULT_MAX_LIVE_NONCES)
    }

    /// A store with explicit TTL and live-set ceiling.
    pub fn with_limits(ttl_secs: u64, max_live: usize) -> Self {
        Self {
            ttl_secs,
            max_live,
            live: Mutex::new(HashMap::new()),
        }
    }
}

impl NonceStore for InMemoryNonceStore {
    fn issue(&self, now_unix_secs: u64) -> Result<String, RpError> {
        let mut live = self.live.lock().expect("nonce mutex poisoned");
        if live.len() >= self.max_live {
            // Sweep expired entries before declaring capacity.
            let ttl = self.ttl_secs;
            live.retain(|_, issued_at| now_unix_secs < issued_at.saturating_add(ttl));
            if live.len() >= self.max_live {
                return Err(RpError::NonceCapacity {
                    max_live: self.max_live,
                });
            }
        }
        let nonce = fresh_nonce()?;
        live.insert(nonce.clone(), now_unix_secs);
        Ok(nonce)
    }

    fn consume(&self, nonce: &str, now_unix_secs: u64) -> Result<bool, RpError> {
        let mut live = self.live.lock().expect("nonce mutex poisoned");
        match live.remove(nonce) {
            Some(issued_at) => Ok(now_unix_secs < issued_at.saturating_add(self.ttl_secs)),
            None => Ok(false),
        }
    }
}

/// 32 bytes of OS randomness, hex-encoded (64 chars). ~256 bits of entropy —
/// unguessable, collision-free at any realistic issuance volume.
pub(crate) fn fresh_nonce() -> Result<String, RpError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| RpError::Store(format!("OS RNG unavailable for nonce issuance: {e}")))?;
    Ok(to_hex(&bytes))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
