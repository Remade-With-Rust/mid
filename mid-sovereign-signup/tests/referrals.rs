//! Referrals end to end through the store: the sign-up rule records
//! `referred_by` once, counts are derived from the records (migrated and new
//! alike), the operator report and share, and the protected keys.

use std::collections::BTreeMap;

use mid_sovereign_signup::referrals::{DEFAULT_REFERRAL_PERCENT, REFERRAL_WINDOW_SECS};
use mid_sovereign_signup::{
    EmailIndex, NormalizedEmail, OsEntropy, Pepper, SignupStore, Tenant, TenantId, User, UserId,
};
use serde_json::{json, Value};

const NOW: u64 = 1_790_000_000;

fn t() -> TenantId {
    TenantId::parse("mata").unwrap()
}

fn store() -> SignupStore<mid_sovereign_signup::store::MemEngine> {
    let s = SignupStore::in_memory(Pepper::from_bytes([3u8; 32])).unwrap();
    s.create_tenant(&Tenant::new(t(), "MATA", vec![], NOW, &mut OsEntropy).unwrap()).unwrap();
    s
}

fn user(n: u8, name: &str, created_at: u64, metadata: Value) -> User {
    User {
        id: UserId::from_random_bytes([n; 16]),
        tenant: t(),
        email: NormalizedEmail::parse(&format!("u{n}@example.com")).unwrap(),
        email_idx: EmailIndex::from_bytes([0; 32]),
        email_verified_at: Some(created_at),
        created_at,
        last_sign_in_at: None,
        linked_did: None,
        username: Some(name.to_string()),
        metadata: serde_json::from_value::<BTreeMap<String, Value>>(metadata).unwrap(),
    }
}

fn md(v: Value) -> BTreeMap<String, Value> {
    serde_json::from_value(v).unwrap()
}

#[test]
fn referrals_are_recorded_once_counted_from_records_and_reported() {
    let s = store();
    // Migrated from Supabase: alice referred carol long ago; alice has a set share.
    let alice = s.import_user(&user(1, "alice", NOW - 90 * 86_400, json!({"referral_percent": "15.00"})), NOW).unwrap();
    s.import_user(&user(2, "carol", NOW - 80 * 86_400, json!({"referred_by": "Alice", "referral_count": 0})), NOW).unwrap();
    // New sign-ups: the client applies `referral_code` right after the first verify.
    let bob = s.import_user(&user(3, "bob", NOW, json!({})), NOW).unwrap();
    s.set_own_metadata(&t(), &bob.id, md(json!({"referral_code": "ALICE", "full_name": "Bob"})), NOW + 5).unwrap();
    let dave = s.import_user(&user(4, "dave", NOW, json!({})), NOW).unwrap();
    s.set_own_metadata(&t(), &dave.id, md(json!({"referral_code": "bob"})), NOW + 5).unwrap();
    // Gaming attempts: self-referral, forging the key, a late code, re-pointing.
    let eve = s.import_user(&user(5, "eve", NOW, json!({})), NOW).unwrap();
    s.set_own_metadata(&t(), &eve.id, md(json!({"referral_code": "eve"})), NOW + 5).unwrap();
    s.set_own_metadata(&t(), &eve.id, md(json!({"referred_by": "alice", "referral_percent": 90})), NOW + 6).unwrap();
    let old = s.import_user(&user(6, "frank", NOW - 10 * 86_400, json!({})), NOW).unwrap();
    s.set_own_metadata(&t(), &old.id, md(json!({"referral_code": "alice"})), NOW).unwrap();
    s.set_own_metadata(&t(), &bob.id, md(json!({"referral_code": "dave"})), NOW + REFERRAL_WINDOW_SECS / 2).unwrap();

    let a = s.referral_stats(&t(), &alice.id).unwrap();
    assert_eq!(a.referral_count, 2, "carol (migrated) + bob (new)");
    assert_eq!(a.referral_percent, 15.0);
    assert_eq!(a.referred_by, None);
    let b = s.referral_stats(&t(), &bob.id).unwrap();
    assert_eq!((b.referred_by.as_deref(), b.referral_count), (Some("ALICE"), 1), "first code kept; dave counted");
    assert_eq!(b.referral_percent, DEFAULT_REFERRAL_PERCENT);
    let e = s.referral_stats(&t(), &eve.id).unwrap();
    assert_eq!((e.referred_by, e.referral_percent), (None, DEFAULT_REFERRAL_PERCENT), "no self-referral, no forged keys");
    assert_eq!(s.referral_stats(&t(), &old.id).unwrap().referred_by, None, "outside the sign-up window");
    // The user's own metadata otherwise lands as sent.
    assert_eq!(s.user(&t(), &bob.id).unwrap().unwrap().metadata.get("referral_code"), Some(&json!("dave")));

    let report = s.referral_report(&t()).unwrap();
    let names: Vec<(&str, u64)> = report.iter().map(|r| (r.username.as_str(), r.referral_count)).collect();
    assert_eq!(names, vec![("alice", 2), ("bob", 1)]);

    // The operator sets a share; the user's next update keeps it.
    s.set_referral_percent(&t(), &bob.id, 20.0, NOW + 10).unwrap();
    s.set_own_metadata(&t(), &bob.id, md(json!({"referral_percent": 99})), NOW + 11).unwrap();
    assert_eq!(s.referral_stats(&t(), &bob.id).unwrap().referral_percent, 20.0);
    assert!(s.set_referral_percent(&t(), &bob.id, 101.0, NOW).is_err());
}
