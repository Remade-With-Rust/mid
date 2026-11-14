//! Referrals: who brought whom, counted from the records rather than a counter.
//!
//! A referral code is the referrer's **username**. At sign-up the client sends
//! it as the metadata key [`REFERRAL_CODE`]; the first time a new user's own
//! metadata carries one (within [`REFERRAL_WINDOW_SECS`] of the account's
//! creation, and not their own name) the service records it, once, as
//! [`REFERRED_BY`]. A referrer's count is the number of users whose
//! `referred_by` matches their username, case-insensitively — derived on read,
//! so it cannot drift the way an incremented counter can.
//!
//! [`REFERRED_BY`] and [`REFERRAL_PERCENT`] (an operator-set profit share,
//! default [`DEFAULT_REFERRAL_PERCENT`]) are **protected**: a user's own
//! metadata update can never set or change them; only the rule above and an
//! operator can.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Metadata key the client sends at sign-up: the referrer's username.
pub const REFERRAL_CODE: &str = "referral_code";
/// Protected metadata key: the referrer's username, recorded once.
pub const REFERRED_BY: &str = "referred_by";
/// Protected metadata key: the operator-set profit share, in percent.
pub const REFERRAL_PERCENT: &str = "referral_percent";
/// The share a referrer has until an operator sets one.
pub const DEFAULT_REFERRAL_PERCENT: f64 = 10.0;
/// How long after an account's creation its referral can still be recorded
/// (the client applies sign-up data right after the first verify).
pub const REFERRAL_WINDOW_SECS: u64 = 86_400;

/// A user's own view of their referrals.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferralStats {
    /// Who referred this user, if anyone.
    pub referred_by: Option<String>,
    /// How many users this user has referred (0 without a username).
    pub referral_count: u64,
    /// This user's profit share, in percent.
    pub referral_percent: f64,
}

/// One referrer in an operator's report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReferrerRow {
    /// The referrer's user id.
    pub user_id: String,
    /// The referrer's username (the code people sign up with).
    pub username: String,
    /// Users who signed up with it.
    pub referral_count: u64,
    /// The referrer's profit share, in percent.
    pub referral_percent: f64,
}

/// The `referred_by` recorded in `metadata`, trimmed, if any.
pub fn referred_by(metadata: &BTreeMap<String, Value>) -> Option<String> {
    metadata
        .get(REFERRED_BY)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The profit share recorded in `metadata` (a number or a numeric string, as
/// Postgres `NUMERIC` exports either way), or the default.
pub fn referral_percent(metadata: &BTreeMap<String, Value>) -> f64 {
    match metadata.get(REFERRAL_PERCENT) {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|p: &f64| p.is_finite())
    .unwrap_or(DEFAULT_REFERRAL_PERCENT)
}

/// The metadata to store when a user replaces their own: `incoming` with the
/// protected keys taken from `existing`, plus `referred_by` recorded from
/// `referral_code` when this is the first one, inside the window, and not the
/// user's own name.
pub fn apply_own_metadata(
    existing: &BTreeMap<String, Value>,
    mut incoming: BTreeMap<String, Value>,
    own_username: Option<&str>,
    created_at: u64,
    now: u64,
) -> BTreeMap<String, Value> {
    incoming.remove(REFERRED_BY);
    incoming.remove(REFERRAL_PERCENT);
    if let Some(p) = existing.get(REFERRAL_PERCENT) {
        incoming.insert(REFERRAL_PERCENT.to_string(), p.clone());
    }
    if let Some(prev) = existing.get(REFERRED_BY) {
        incoming.insert(REFERRED_BY.to_string(), prev.clone());
        return incoming;
    }
    let in_window = now.saturating_sub(created_at) <= REFERRAL_WINDOW_SECS;
    let code = incoming
        .get(REFERRAL_CODE)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|c| !c.is_empty() && c.len() <= 64)
        .map(str::to_string);
    if let (true, Some(code)) = (in_window, code) {
        let own = own_username.map(str::to_lowercase);
        if own.as_deref() != Some(code.to_lowercase().as_str()) {
            incoming.insert(REFERRED_BY.to_string(), Value::String(code));
        }
    }
    incoming
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn m(v: Value) -> BTreeMap<String, Value> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn the_first_code_in_the_window_is_recorded_once() {
        let got = apply_own_metadata(&m(json!({})), m(json!({"referral_code": " Alice "})), Some("bob"), 100, 200);
        assert_eq!(referred_by(&got).as_deref(), Some("Alice"));
        // Later attempts to change it, directly or by a new code, keep the first.
        let again = apply_own_metadata(&got, m(json!({"referral_code": "eve", "referred_by": "eve"})), Some("bob"), 100, 300);
        assert_eq!(referred_by(&again).as_deref(), Some("Alice"));
    }

    #[test]
    fn no_self_referral_no_late_referral_no_forged_keys() {
        let own = apply_own_metadata(&m(json!({})), m(json!({"referral_code": "BOB"})), Some("bob"), 0, 1);
        assert_eq!(referred_by(&own), None, "your own name");
        let late = apply_own_metadata(&m(json!({})), m(json!({"referral_code": "alice"})), Some("bob"), 0, REFERRAL_WINDOW_SECS + 1);
        assert_eq!(referred_by(&late), None, "outside the sign-up window");
        let forged = apply_own_metadata(&m(json!({})), m(json!({"referred_by": "alice", "referral_percent": 99})), Some("bob"), 0, 1);
        assert_eq!(referred_by(&forged), None);
        assert_eq!(referral_percent(&forged), DEFAULT_REFERRAL_PERCENT, "a user cannot raise their own share");
        let kept = apply_own_metadata(&m(json!({"referral_percent": 25.5})), m(json!({"referral_percent": 99})), Some("bob"), 0, 1);
        assert_eq!(referral_percent(&kept), 25.5, "the operator's value survives the user's update");
    }

    #[test]
    fn percent_reads_numbers_and_numeric_strings() {
        assert_eq!(referral_percent(&m(json!({"referral_percent": 12.5}))), 12.5);
        assert_eq!(referral_percent(&m(json!({"referral_percent": "7.00"}))), 7.0);
        assert_eq!(referral_percent(&m(json!({"referral_percent": "x"}))), DEFAULT_REFERRAL_PERCENT);
        assert_eq!(referral_percent(&m(json!({}))), DEFAULT_REFERRAL_PERCENT);
    }
}
