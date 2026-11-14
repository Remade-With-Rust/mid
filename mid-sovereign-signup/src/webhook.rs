//! Webhook signatures — pure, so a tenant's receiver can verify deliveries
//! with this crate's default build.
//!
//! Every delivery carries
//!
//! ```text
//! x-signup-signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>
//! ```
//!
//! The timestamp is inside the MAC, so a captured delivery cannot be replayed
//! later than the receiver's tolerance; receivers also deduplicate on the
//! event id in the body (`x-signup-event-id` carries it too).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The signature header.
pub const SIGNATURE_HEADER: &str = "x-signup-signature";
/// The event-id header (the body's `id`).
pub const EVENT_ID_HEADER: &str = "x-signup-event-id";
/// The event-type header (the body's `type`).
pub const EVENT_TYPE_HEADER: &str = "x-signup-event";
/// A sensible receiver tolerance: five minutes either way.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

fn mac(secret: &str, timestamp: u64, body: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC takes any key");
    m.update(timestamp.to_string().as_bytes());
    m.update(b".");
    m.update(body);
    m.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The header value for a delivery of `body` at `timestamp`.
pub fn sign(secret: &str, timestamp: u64, body: &[u8]) -> String {
    format!("t={timestamp},v1={}", hex(&mac(secret, timestamp, body)))
}

/// Why a delivery's signature was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// The header is not `t=<n>,v1=<hex>`.
    #[error("malformed signature header")]
    Malformed,
    /// The timestamp is outside the tolerance.
    #[error("signature timestamp outside tolerance")]
    Stale,
    /// The MAC does not match.
    #[error("signature mismatch")]
    Mismatch,
}

/// Verify a delivery: the header must parse, its timestamp be within
/// `tolerance_secs` of `now`, and some `v1` MAC match (constant-time).
pub fn verify(
    secret: &str,
    header: &str,
    body: &[u8],
    now: u64,
    tolerance_secs: u64,
) -> Result<(), SignatureError> {
    let mut ts = None;
    let mut sigs = Vec::new();
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => ts = v.parse::<u64>().ok(),
            Some(("v1", v)) => sigs.push(v.to_string()),
            _ => {}
        }
    }
    let ts = ts.ok_or(SignatureError::Malformed)?;
    if sigs.is_empty() {
        return Err(SignatureError::Malformed);
    }
    if ts.abs_diff(now) > tolerance_secs {
        return Err(SignatureError::Stale);
    }
    let want = hex(&mac(secret, ts, body));
    let ok = sigs
        .iter()
        .any(|s| s.len() == want.len() && bool::from(s.as_bytes().ct_eq(want.as_bytes())));
    if ok {
        Ok(())
    } else {
        Err(SignatureError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_and_every_refusal() {
        let body = br#"{"id":"evt_1","type":"user.created"}"#;
        let h = sign("whsec", 1_000, body);
        assert!(h.starts_with("t=1000,v1="));
        assert_eq!(verify("whsec", &h, body, 1_100, 300), Ok(()));
        assert_eq!(
            verify("whsec", &h, body, 1_301, 300),
            Err(SignatureError::Stale)
        );
        assert_eq!(
            verify("other", &h, body, 1_000, 300),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            verify("whsec", &h, b"{}", 1_000, 300),
            Err(SignatureError::Mismatch)
        );
        let moved = h.replace("t=1000", "t=1001");
        assert_eq!(
            verify("whsec", &moved, body, 1_000, 300),
            Err(SignatureError::Mismatch),
            "the timestamp is inside the MAC"
        );
        assert_eq!(
            verify("whsec", "garbage", body, 1_000, 300),
            Err(SignatureError::Malformed)
        );
        // Rotation: a header may carry several v1 values; any match passes.
        let two = format!("{h},v1=00");
        assert_eq!(verify("whsec", &two, body, 1_000, 300), Ok(()));
    }
}
