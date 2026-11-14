//! Migrating a user base in (feature `client`): pure parsing, filtering and
//! reporting. `signupctl` does the I/O.
//!
//! Two input shapes, one JSON object per line:
//!
//! - **native** — [`ImportRecord`] as-is (what any system can produce);
//! - **supabase** — rows of GoTrue's `auth.users` as `row_to_json` writes
//!   them ([`SUPABASE_EXPORT_SQL`]): `id`, `email`, `email_confirmed_at`,
//!   `created_at`, `last_sign_in_at`, `raw_user_meta_data`. The username is
//!   read from one metadata key (default `username`); every other key rides
//!   into the user's metadata, minus GoTrue's own bookkeeping keys.
//!
//! Ids are kept: a migrated user is the same user, under the same id. The
//! report carries ids and counts, never an address.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The export query for a Supabase project (run with the service role, e.g.
/// through `psql "$DATABASE_URL"`): one JSON object per line, deleted users
/// excluded, oldest first.
pub const SUPABASE_EXPORT_SQL: &str = r#"\copy (select row_to_json(u) from (select id, email, email_confirmed_at, created_at, last_sign_in_at, raw_user_meta_data from auth.users where deleted_at is null order by created_at) u) to 'auth_users.jsonl'"#;

/// Keys GoTrue writes into `raw_user_meta_data` for itself.
const GOTRUE_INTERNAL_KEYS: &[&str] = &["email", "email_verified", "phone_verified", "sub"];

/// One user, as the import door takes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportRecord {
    /// The user's id (a UUID) — kept.
    pub id: String,
    /// The address.
    pub email: String,
    /// When the address was proven, Unix seconds; `None` = never.
    #[serde(default)]
    pub email_verified_at: Option<u64>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    #[serde(default)]
    pub last_sign_in_at: Option<u64>,
    /// A username to claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// A linked `did:mata`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_did: Option<String>,
    /// Everything else.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

/// The input shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// [`ImportRecord`] lines.
    Native,
    /// `auth.users` rows; the username is read from this metadata key.
    Supabase {
        /// Usually `username`.
        username_key: String,
    },
}

/// Parse one input line.
pub fn parse_line(source: &Source, line: &str) -> Result<ImportRecord, String> {
    match source {
        Source::Native => serde_json::from_str(line).map_err(|e| e.to_string()),
        Source::Supabase { username_key } => {
            let v: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
            let id = v["id"].as_str().ok_or("no `id`")?.to_string();
            let email = v["email"]
                .as_str()
                .filter(|e| !e.trim().is_empty())
                .ok_or("no `email` (phone-only users cannot be migrated to email sign-in)")?
                .to_string();
            let created_at = parse_timestamp(&v["created_at"])?.ok_or("no `created_at`")?;
            let mut metadata = BTreeMap::new();
            let mut username = None;
            if let Some(meta) = v["raw_user_meta_data"].as_object() {
                for (k, val) in meta {
                    if k == username_key {
                        username = val
                            .as_str()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string);
                    } else if !GOTRUE_INTERNAL_KEYS.contains(&k.as_str()) && !val.is_null() {
                        metadata.insert(k.clone(), val.clone());
                    }
                }
            }
            Ok(ImportRecord {
                id,
                email,
                email_verified_at: parse_timestamp(&v["email_confirmed_at"])?,
                created_at,
                last_sign_in_at: parse_timestamp(&v["last_sign_in_at"])?,
                username,
                linked_did: None,
                metadata,
            })
        }
    }
}

/// Unix seconds from `null`, a number, or an ISO 8601 / Postgres timestamp
/// (`2025-10-01T12:34:56.789+00:00`, `2025-10-01 12:34:56+00`, `…Z`, no zone
/// = UTC). Fractions are dropped.
pub fn parse_timestamp(v: &Value) -> Result<Option<u64>, String> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("bad timestamp {n}")),
        Value::String(s) => parse_iso(s).map(Some),
        other => Err(format!("bad timestamp {other}")),
    }
}

fn parse_iso(s: &str) -> Result<u64, String> {
    let bad = || format!("bad timestamp {s:?}");
    let s = s.trim();
    let (date, rest) = s.split_at(s.find(['T', ' ']).ok_or_else(bad)?);
    let rest = &rest[1..];
    let mut d = date.split('-');
    let (y, m, day): (i64, i64, i64) = (
        d.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?,
        d.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?,
        d.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?,
    );
    // Split the clock from the zone: Z, +hh[:mm], -hh[:mm], or nothing.
    let zpos = rest.find(['Z', '+', '-']);
    let (clock, zone) = match zpos {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let clock = clock.split('.').next().unwrap_or("");
    let mut c = clock.split(':');
    let (hh, mm, ss): (i64, i64, i64) = (
        c.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?,
        c.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?,
        c.next().and_then(|x| x.parse().ok()).unwrap_or(0),
    );
    let offset = match zone {
        "" | "Z" => 0,
        z => {
            let sign = if z.starts_with('-') { -1 } else { 1 };
            let body = z[1..].replace(':', "");
            let (oh, om) = match body.len() {
                2 => (body.parse::<i64>().map_err(|_| bad())?, 0),
                4 => (
                    body[..2].parse::<i64>().map_err(|_| bad())?,
                    body[2..].parse::<i64>().map_err(|_| bad())?,
                ),
                _ => return Err(bad()),
            };
            sign * (oh * 3_600 + om * 60)
        }
    };
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || hh > 23 || mm > 59 || ss > 60 {
        return Err(bad());
    }
    // Days from civil (H. Hinnant).
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hh * 3_600 + mm * 60 + ss - offset;
    u64::try_from(secs).map_err(|_| bad())
}

/// Which unverified rows to carry.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Carry every unverified row.
    pub include_unverified: bool,
    /// Carry these unverified ids anyway (e.g. ids an identity registry
    /// already knows: those users have an identity even if the old system
    /// never recorded the confirmation).
    pub keep_ids: BTreeSet<String>,
}

impl Filter {
    /// Send this record?
    pub fn wants(&self, r: &ImportRecord) -> bool {
        r.email_verified_at.is_some()
            || self.include_unverified
            || self.keep_ids.contains(&r.id.to_lowercase())
    }
}

/// Read ids from text: one per line, as a bare UUID or `did:mata:<uuid>`.
/// Blank lines and `#` comments are ignored; any other DID (a key-derived
/// one names a device or service, not an account) is counted, not returned.
pub fn read_ids(text: &str) -> (Vec<String>, usize) {
    let mut ids = BTreeSet::new();
    let mut not_accounts = 0;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let candidate = l.strip_prefix("did:mata:").unwrap_or(l);
        match uuid::Uuid::parse_str(candidate) {
            Ok(u) => {
                ids.insert(u.hyphenated().to_string());
            }
            Err(_) => not_accounts += 1,
        }
    }
    (ids.into_iter().collect(), not_accounts)
}

/// A line that did not parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineError {
    /// 1-based line number.
    pub line: usize,
    /// Why.
    pub error: String,
}

/// A refused or adjusted user, by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdNote {
    /// The user id.
    pub id: String,
    /// The server's code (`email_taken`, `username_taken`, …).
    pub reason: String,
}

/// What an import did. Ids and counts only — never an address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// Lines read (non-blank).
    pub source_rows: usize,
    /// Lines that did not parse.
    pub parse_errors: Vec<LineError>,
    /// Unverified rows left behind by the filter.
    pub skipped_unverified: usize,
    /// Rows sent to the door.
    pub sent: usize,
    /// Written now.
    pub imported: usize,
    /// Already there (a re-run).
    pub already_present: usize,
    /// Imported without their username.
    pub username_dropped: Vec<IdNote>,
    /// Refused.
    pub refused: Vec<IdNote>,
    /// Ids that were sent (the list `verify` checks).
    #[serde(skip)]
    pub sent_ids: Vec<String>,
}

impl Report {
    /// Fold one door result (`{id, ok, status|error, username_dropped?}`).
    pub fn absorb(&mut self, r: &Value) {
        let id = r["id"].as_str().unwrap_or("?").to_string();
        if r["ok"] == true {
            match r["status"].as_str() {
                Some("already_present") => self.already_present += 1,
                _ => self.imported += 1,
            }
            if let Some(reason) = r["username_dropped"].as_str() {
                self.username_dropped.push(IdNote {
                    id,
                    reason: reason.to_string(),
                });
            }
        } else {
            let reason = r["error"].as_str().unwrap_or("unknown").to_string();
            self.refused.push(IdNote { id, reason });
        }
    }

    /// Clean = every line parsed and every sent user is present.
    pub fn is_clean(&self) -> bool {
        self.parse_errors.is_empty()
            && self.refused.is_empty()
            && self.imported + self.already_present == self.sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timestamps_from_every_shape_supabase_writes() {
        let t = |s: &str| parse_timestamp(&json!(s)).unwrap().unwrap();
        assert_eq!(t("2025-09-30T00:00:00Z"), 1_759_190_400);
        assert_eq!(t("2025-09-30T00:00:00.123456+00:00"), 1_759_190_400);
        assert_eq!(t("2025-09-30 00:00:00+00"), 1_759_190_400);
        assert_eq!(t("2025-09-30T02:00:00+02:00"), 1_759_190_400);
        assert_eq!(t("2025-09-29T19:00:00-05:00"), 1_759_190_400);
        assert_eq!(t("2025-09-30T00:00:00"), 1_759_190_400, "no zone = UTC");
        assert_eq!(t("2000-02-29T00:00:00Z"), 951_782_400);
        assert_eq!(parse_timestamp(&Value::Null).unwrap(), None);
        assert_eq!(
            parse_timestamp(&json!(1_759_190_400u64)).unwrap(),
            Some(1_759_190_400)
        );
        assert!(parse_timestamp(&json!("yesterday")).is_err());
        assert!(parse_timestamp(&json!("2025-13-01T00:00:00Z")).is_err());
    }

    #[test]
    fn a_supabase_row_maps_and_drops_gotrue_bookkeeping() {
        let src = Source::Supabase {
            username_key: "username".into(),
        };
        let line = json!({
            "id": "11111111-2222-4333-8444-555555555555",
            "email": "Tim@Example.com",
            "email_confirmed_at": "2025-09-30T00:00:00+00:00",
            "created_at": "2025-09-29T00:00:00+00:00",
            "last_sign_in_at": null,
            "raw_user_meta_data": {
                "username": " tim ", "referral_code": "abc", "webauthn_credential_id": "cred",
                "email": "Tim@Example.com", "email_verified": true, "sub": "1111", "phone_verified": false,
                "empty": null
            }
        })
        .to_string();
        let r = parse_line(&src, &line).unwrap();
        assert_eq!(r.username.as_deref(), Some("tim"));
        assert_eq!(r.email_verified_at, Some(1_759_190_400));
        assert_eq!(r.created_at, 1_759_104_000);
        assert_eq!(
            r.metadata.keys().map(String::as_str).collect::<Vec<_>>(),
            ["referral_code", "webauthn_credential_id"]
        );
        // A native line round-trips.
        let native = serde_json::to_string(&r).unwrap();
        assert_eq!(parse_line(&Source::Native, &native).unwrap(), r);
        // Phone-only users have no address to sign in with.
        let phone =
            json!({ "id": "x", "email": null, "created_at": "2025-01-01T00:00:00Z" }).to_string();
        assert!(parse_line(&src, &phone).unwrap_err().contains("phone-only"));
    }

    #[test]
    fn the_filter_keeps_verified_and_named_unverified_rows() {
        let mut r = parse_line(
            &Source::Native,
            r#"{"id":"AAAAAAAA-2222-4333-8444-555555555555","email":"a@b.co","created_at":1}"#,
        )
        .unwrap();
        let f = Filter::default();
        assert!(!f.wants(&r), "unverified is skipped by default");
        let keep = Filter {
            keep_ids: ["aaaaaaaa-2222-4333-8444-555555555555".to_string()].into(),
            ..Default::default()
        };
        assert!(
            keep.wants(&r),
            "unless its id must be kept (case-insensitive)"
        );
        assert!(Filter {
            include_unverified: true,
            ..Default::default()
        }
        .wants(&r));
        r.email_verified_at = Some(1);
        assert!(f.wants(&r));
    }

    #[test]
    fn ids_read_from_uuids_and_account_dids_only() {
        let text = "# registry export\n11111111-2222-4333-8444-555555555555\ndid:mata:AAAAAAAA-2222-4333-8444-555555555555\n\ndid:mata:xPoFoPWHEJWJFQXHLCXhTgyx6nvCKeEiXpGyprbqUYjw\n11111111-2222-4333-8444-555555555555\n";
        let (ids, other) = read_ids(text);
        assert_eq!(
            ids,
            vec![
                "11111111-2222-4333-8444-555555555555",
                "aaaaaaaa-2222-4333-8444-555555555555"
            ]
        );
        assert_eq!(other, 1, "a key-derived DID is not an account");
    }

    #[test]
    fn the_report_folds_results_and_never_holds_an_address() {
        let mut rep = Report {
            sent: 4,
            ..Default::default()
        };
        rep.absorb(&json!({"id": "a", "ok": true, "status": "imported"}));
        rep.absorb(&json!({"id": "b", "ok": true, "status": "imported", "username_dropped": "username_taken"}));
        rep.absorb(&json!({"id": "c", "ok": true, "status": "already_present"}));
        rep.absorb(
            &json!({"id": "d", "ok": false, "error": "email_taken", "message": "x@y.co is taken"}),
        );
        assert_eq!(
            (rep.imported, rep.already_present, rep.refused.len()),
            (2, 1, 1)
        );
        assert_eq!(rep.username_dropped[0].reason, "username_taken");
        assert!(!rep.is_clean());
        assert!(
            !serde_json::to_string(&rep).unwrap().contains('@'),
            "the message (which may name an address) is not kept"
        );
    }
}
