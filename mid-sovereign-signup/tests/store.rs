//! M1 gates for the `store` feature, exercised through the public API only.
//!
//! The topologies that matter are tested as they deploy: one process, many
//! threads sharing one store (the server); a store dropped and reopened (a
//! restart); a **separate OS process** writing the directory and this one
//! reading it after (two independent connections, not a shared in-process
//! handle); and a second opener refused while the first holds the store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Barrier};

use mid_sovereign_signup::flow::{StartRequest, VerifyRequest};
use mid_sovereign_signup::records::AuditKind;
use mid_sovereign_signup::store::{MemEngine, RedbEngine, StoreEngine};
use mid_sovereign_signup::{
    FlowError, Limits, OsEntropy, Pepper, Policy, RateRule, SignupStore, StoreError, Tenant,
    TenantId, User, UserId,
};

const NOW: u64 = 1_759_190_400;

fn pepper() -> Pepper {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    Pepper::from_bytes(b)
}

fn acme() -> TenantId {
    TenantId::parse("acme").unwrap()
}

fn tenant_record(id: &TenantId) -> Tenant {
    Tenant::new(
        id.clone(),
        "Acme Corp",
        vec!["https://app.acme.com".into()],
        NOW,
        &mut OsEntropy,
    )
    .unwrap()
}

fn mem_store() -> SignupStore<MemEngine> {
    let s = SignupStore::in_memory(pepper()).unwrap();
    s.create_tenant(&tenant_record(&acme())).unwrap();
    s
}

fn tmpdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mss-store-")
        .tempdir()
        .unwrap()
}

fn disk_store(dir: &Path) -> SignupStore<RedbEngine> {
    SignupStore::open_dir(dir, pepper()).unwrap()
}

fn start<E: StoreEngine>(s: &SignupStore<E>, email: &str, now: u64) -> Result<String, StoreError> {
    let t = acme();
    s.start(
        &StartRequest {
            tenant: &t,
            email,
            create_user: true,
            now,
        },
        Some("203.0.113.7"),
        &mut OsEntropy,
    )
    .map(|o| o.code.as_str().to_string())
}

fn verify<E: StoreEngine>(
    s: &SignupStore<E>,
    email: &str,
    code: &str,
    now: u64,
) -> Result<mid_sovereign_signup::Verified, StoreError> {
    let t = acme();
    s.verify(
        &VerifyRequest {
            tenant: &t,
            email,
            code,
            now,
        },
        &mut OsEntropy,
    )
}

/// A six-digit code guaranteed not to be `code`.
fn wrong(code: &str, salt: u32) -> String {
    let n: u32 = code.parse().unwrap();
    format!("{:06}", (n + 1 + salt) % 1_000_000)
}

fn assert_clean<E: StoreEngine>(s: &SignupStore<E>) {
    let r = s.check_integrity().unwrap();
    assert!(r.is_clean(), "integrity problems: {:#?}", r.problems);
}

// ─── the flow, persisted ─────────────────────────────────────────────────────

#[test]
fn sign_up_then_sign_in_through_the_store() {
    let s = mem_store();
    let t = acme();
    let code = start(&s, " Alice@Example.com", NOW).unwrap();
    let live = s.live_challenge(&t, "alice@example.com").unwrap().unwrap();
    assert_eq!(live.attempts, 0);

    let v = verify(&s, "alice@example.com", &code, NOW + 10).unwrap();
    assert!(v.user_created);
    assert!(
        s.live_challenge(&t, "alice@example.com").unwrap().is_none(),
        "consumed → unlisted"
    );
    let stored = s.user_by_email(&t, "ALICE@example.com").unwrap().unwrap();
    assert_eq!(stored, v.user);
    assert_eq!(s.user(&t, &v.user.id).unwrap().unwrap(), v.user);
    assert_eq!(s.count_users(&t).unwrap(), 1);

    // Sign in a day later: same user, no second record.
    let code2 = start(&s, "alice@example.com", NOW + 86_400).unwrap();
    let v2 = verify(&s, "alice@example.com", &code2, NOW + 86_401).unwrap();
    assert!(!v2.user_created);
    assert_eq!(v2.user.id, v.user.id);
    assert_eq!(v2.user.email_verified_at, Some(NOW + 10));
    assert_eq!(v2.user.last_sign_in_at, Some(NOW + 86_401));
    assert_eq!(s.count_users(&t).unwrap(), 1);

    // The audit trail tells the story, gap-free, and never names the address.
    let kinds: Vec<AuditKind> = s
        .audit(Some(&t), 0, 100)
        .unwrap()
        .into_iter()
        .map(|r| r.event.kind)
        .collect();
    assert_eq!(
        kinds,
        vec![
            AuditKind::TenantCreated,
            AuditKind::ChallengeIssued,
            AuditKind::CodeAccepted,
            AuditKind::UserCreated,
            AuditKind::ChallengeIssued,
            AuditKind::CodeAccepted,
        ]
    );
    assert_eq!(s.height().unwrap(), 6);
    let audit_json = serde_json::to_string(&s.audit(None, 0, 100).unwrap()).unwrap();
    assert!(
        !audit_json.contains("alice"),
        "audit must not carry the address"
    );
    assert_clean(&s);
}

#[test]
fn unknown_tenant_and_malformed_input_write_nothing() {
    let s = mem_store();
    let other = TenantId::parse("other").unwrap();
    let e = s
        .start(
            &StartRequest {
                tenant: &other,
                email: "a@b.co",
                create_user: true,
                now: NOW,
            },
            None,
            &mut OsEntropy,
        )
        .unwrap_err();
    assert_eq!(e.code(), "unknown_tenant");
    assert_eq!(
        start(&s, "not-an-email", NOW).unwrap_err().code(),
        "invalid_email"
    );
    assert_eq!(
        verify(&s, "a@b.co", "12a456", NOW).unwrap_err().code(),
        "invalid_code"
    );
    assert_eq!(
        verify(&s, "a@b.co", "123456", NOW).unwrap_err().code(),
        "no_live_challenge"
    );
    // Only the tenant creation and the one refused-verify audit row exist.
    assert_eq!(s.height().unwrap(), 2);
    assert_clean(&s);
}

#[test]
fn wrong_guesses_persist_and_exhaust() {
    let s = mem_store()
        .with_policy(Policy {
            max_attempts: 3,
            ..Policy::DEFAULT
        })
        .unwrap();
    let t = acme();
    let code = start(&s, "bob@example.com", NOW).unwrap();
    for i in 0..2 {
        let e = verify(&s, "bob@example.com", &wrong(&code, i), NOW + 1).unwrap_err();
        assert!(
            matches!(e.as_flow(), Some(FlowError::WrongCode { .. })),
            "{e:?}"
        );
    }
    assert_eq!(
        s.live_challenge(&t, "bob@example.com")
            .unwrap()
            .unwrap()
            .attempts,
        2
    );
    let e = verify(&s, "bob@example.com", &wrong(&code, 7), NOW + 1).unwrap_err();
    assert!(matches!(e.as_flow(), Some(FlowError::AttemptsExhausted)));
    // The right code is now dead: the challenge left the live index.
    let e = verify(&s, "bob@example.com", &code, NOW + 2).unwrap_err();
    assert!(matches!(e.as_flow(), Some(FlowError::NoLiveChallenge)));
    assert!(e.as_flow().unwrap().needs_new_code());
    assert_eq!(s.count_users(&t).unwrap(), 0);
    assert_clean(&s);
}

// ─── races: one process, many threads, one store ─────────────────────────────

#[test]
fn concurrent_right_codes_admit_exactly_one() {
    let s = Arc::new(mem_store());
    let code = start(&s, "race@example.com", NOW).unwrap();
    let n = 16;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (s, b, code) = (s.clone(), barrier.clone(), code.clone());
            std::thread::spawn(move || {
                b.wait();
                verify(&s, "race@example.com", &code, NOW + 1)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let ok = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(ok, 1, "{results:?}");
    for r in results.iter().filter(|r| r.is_err()) {
        assert!(r.as_ref().unwrap_err().as_flow().unwrap().needs_new_code());
    }
    assert_eq!(s.count_users(&acme()).unwrap(), 1);
    assert_clean(&s);
}

#[test]
fn concurrent_wrong_guesses_are_all_counted() {
    let s = Arc::new(mem_store());
    let code = start(&s, "brute@example.com", NOW).unwrap();
    let n = 32;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n as u32)
        .map(|i| {
            let (s, b, guess) = (s.clone(), barrier.clone(), wrong(&code, i));
            std::thread::spawn(move || {
                b.wait();
                verify(&s, "brute@example.com", &guess, NOW + 1)
            })
        })
        .collect();
    let errs: Vec<StoreError> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap_err())
        .collect();
    let count =
        |f: fn(&FlowError) -> bool| errs.iter().filter(|e| e.as_flow().is_some_and(f)).count();
    let wrong_n = count(|f| matches!(f, FlowError::WrongCode { .. }));
    let exhausted = count(|f| matches!(f, FlowError::AttemptsExhausted));
    let gone = count(|f| matches!(f, FlowError::NoLiveChallenge));
    assert_eq!(
        (wrong_n, exhausted, gone),
        (4, 1, 27),
        "no lost updates: exactly 5 guesses land"
    );
    // The challenge record holds exactly the policy's 5 attempts.
    let rows = s.audit(Some(&acme()), 0, 1_000).unwrap();
    let ch_id = rows.iter().find_map(|r| r.event.challenge).unwrap();
    assert_eq!(s.challenge(&acme(), &ch_id).unwrap().unwrap().attempts, 5);
    assert_clean(&s);
}

#[test]
fn concurrent_starts_for_one_address_issue_one_code() {
    let s = Arc::new(mem_store());
    let n = 16;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (s, b) = (s.clone(), barrier.clone());
            std::thread::spawn(move || {
                b.wait();
                start(&s, "dup@example.com", NOW)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert!(results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| e.code() == "resend_too_soon"));
    assert_clean(&s);
}

#[test]
fn concurrent_distinct_sign_ups_all_land() {
    let s = Arc::new(mem_store().with_limits(Limits::NONE));
    let n = 40;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let (s, b) = (s.clone(), barrier.clone());
            std::thread::spawn(move || {
                let email = format!("user{i}@example.com");
                b.wait();
                let code = start(&s, &email, NOW).unwrap();
                verify(&s, &email, &code, NOW + 1).unwrap().user.id
            })
        })
        .collect();
    let mut ids: Vec<UserId> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n);
    assert_eq!(s.count_users(&acme()).unwrap(), n);
    // Tenant + n × (issued, accepted, created): gap-free.
    assert_eq!(s.height().unwrap(), 1 + 3 * n as u64);
    assert_clean(&s);
}

// ─── rate limits ─────────────────────────────────────────────────────────────

#[test]
fn per_address_window_refuses_and_refusal_writes_nothing() {
    let s = mem_store()
        .with_policy(Policy {
            resend_cooldown_secs: 0,
            ..Policy::DEFAULT
        })
        .unwrap()
        .with_limits(Limits {
            per_address: Some(RateRule::new(3_600, 3)),
            per_client: None,
            per_tenant: None,
        });
    let t = acme();
    for i in 0..3 {
        start(&s, "rl@example.com", NOW + i).unwrap();
    }
    let before = s.live_challenge(&t, "rl@example.com").unwrap().unwrap();
    let height = s.height().unwrap();
    let e = start(&s, "rl@example.com", NOW + 10).unwrap_err();
    assert!(matches!(
        e.as_flow(),
        Some(FlowError::RateLimited {
            retry_after_secs: 3_590
        })
    ));
    assert_eq!(
        s.height().unwrap(),
        height,
        "a refused start writes no audit row"
    );
    assert_eq!(
        s.live_challenge(&t, "rl@example.com").unwrap().unwrap().id,
        before.id
    );
    // Another address is unaffected; the window reopens after an hour.
    start(&s, "other@example.com", NOW + 10).unwrap();
    start(&s, "rl@example.com", NOW + 3_600).unwrap();
    assert_clean(&s);
}

#[test]
fn per_client_and_per_tenant_windows() {
    let s = mem_store().with_limits(Limits {
        per_address: None,
        per_client: Some(RateRule::new(60, 2)),
        per_tenant: Some(RateRule::new(60, 3)),
    });
    let t = acme();
    let go = |email: &str, client: &str| {
        s.start(
            &StartRequest {
                tenant: &t,
                email,
                create_user: true,
                now: NOW,
            },
            Some(client),
            &mut OsEntropy,
        )
    };
    go("a@example.com", "10.0.0.1").unwrap();
    go("b@example.com", "10.0.0.1").unwrap();
    assert_eq!(
        go("c@example.com", "10.0.0.1").unwrap_err().code(),
        "rate_limited"
    );
    go("c@example.com", "10.0.0.2").unwrap();
    assert_eq!(
        go("d@example.com", "10.0.0.3").unwrap_err().code(),
        "rate_limited",
        "tenant cap"
    );
    // Client addresses never appear in the store, only their peppered index.
    let dump = s.dump().unwrap();
    assert!(
        dump.rates.iter().all(|(k, _)| !k.contains("10.0.0")),
        "{:?}",
        dump.rates
    );
}

// ─── tenants, users, uniqueness ──────────────────────────────────────────────

#[test]
fn tenant_uniqueness_and_updates() {
    let s = mem_store();
    let t = acme();
    let existing = s.tenant(&t).unwrap().unwrap();
    assert_eq!(
        s.create_tenant(&tenant_record(&t)).unwrap_err().code(),
        "tenant_exists"
    );
    let mut clash = tenant_record(&TenantId::parse("beta").unwrap());
    clash.public_id = existing.public_id.clone();
    assert_eq!(
        s.create_tenant(&clash).unwrap_err().code(),
        "public_id_taken"
    );
    assert_eq!(
        s.tenant_by_public_id(&existing.public_id)
            .unwrap()
            .unwrap()
            .id,
        t
    );
    assert!(s.tenant_by_public_id("pub_nope").unwrap().is_none());

    let u = s
        .update_tenant(&t, "Acme 2", vec!["HTTPS://New.acme.com/".into()], NOW + 5)
        .unwrap();
    assert!(u.allows_origin("https://new.acme.com"));
    assert!(!u.allows_origin("https://app.acme.com"));
    assert_eq!(u.public_id, existing.public_id);
    assert_eq!(s.tenants().unwrap().len(), 1);
    assert_clean(&s);
}

fn imported(email: &str, id_byte: u8) -> User {
    let e = mid_sovereign_signup::NormalizedEmail::parse(email).unwrap();
    User {
        id: UserId::from_random_bytes([id_byte; 16]),
        tenant: acme(),
        email: e,
        // Deliberately wrong: import recomputes it under the store's pepper.
        email_idx: mid_sovereign_signup::EmailIndex::from_bytes([0; 32]),
        email_verified_at: Some(NOW - 1_000),
        created_at: NOW - 2_000,
        last_sign_in_at: None,
        linked_did: None,
        username: None,
        metadata: BTreeMap::new(),
    }
}

#[test]
fn import_keeps_ids_and_enforces_uniqueness() {
    let s = mem_store();
    let t = acme();
    let u = s.import_user(&imported("Imp@Example.com", 1), NOW).unwrap();
    assert_eq!(u.id, UserId::from_random_bytes([1; 16]));
    assert_eq!(
        s.user_by_email(&t, "imp@example.com").unwrap().unwrap().id,
        u.id
    );
    assert_eq!(
        s.import_user(&imported("other@example.com", 1), NOW)
            .unwrap_err()
            .code(),
        "user_id_taken"
    );
    assert_eq!(
        s.import_user(&imported("imp@example.com", 2), NOW)
            .unwrap_err()
            .code(),
        "email_taken"
    );

    // An imported user signs in with a code like anyone else — no duplicate.
    let code = start(&s, "imp@example.com", NOW).unwrap();
    let v = verify(&s, "imp@example.com", &code, NOW + 1).unwrap();
    assert!(!v.user_created);
    assert_eq!(v.user.id, u.id);
    assert_eq!(s.count_users(&t).unwrap(), 1);
    assert_clean(&s);
}

#[test]
fn did_links_are_unique_and_reversible() {
    let s = mem_store();
    let t = acme();
    let a = s.import_user(&imported("a@example.com", 1), NOW).unwrap();
    let b = s.import_user(&imported("b@example.com", 2), NOW).unwrap();
    let did = "did:mata:xPoFoPWHEJWJFQXHLCXhTgyx6nvCKeEiXpGyprbqUYjw";

    s.link_did(&t, &a.id, did, NOW).unwrap();
    s.link_did(&t, &a.id, did, NOW).unwrap(); // idempotent, no second audit row
    assert_eq!(s.user_by_did(&t, did).unwrap().unwrap().id, a.id);
    assert_eq!(
        s.link_did(&t, &b.id, did, NOW).unwrap_err().code(),
        "did_taken"
    );
    assert_eq!(
        s.link_did(&t, &a.id, "did:mata:other", NOW)
            .unwrap_err()
            .code(),
        "did_already_linked"
    );
    assert_eq!(
        s.link_did(&t, &a.id, "nope", NOW).unwrap_err().code(),
        "invalid_did"
    );
    let links = s
        .audit(Some(&t), 0, 100)
        .unwrap()
        .into_iter()
        .filter(|r| r.event.kind == AuditKind::DidLinked)
        .count();
    assert_eq!(links, 1);

    assert_eq!(s.unlink_did(&t, &a.id, NOW).unwrap().as_deref(), Some(did));
    assert!(s.user_by_did(&t, did).unwrap().is_none());
    s.link_did(&t, &b.id, did, NOW).unwrap();
    assert_eq!(s.user_by_did(&t, did).unwrap().unwrap().id, b.id);
    assert_eq!(
        s.link_did(&t, &UserId::from_random_bytes([9; 16]), did, NOW)
            .unwrap_err()
            .code(),
        "user_not_found"
    );
    assert_clean(&s);
}

#[test]
fn delete_frees_the_address_and_the_did() {
    let s = mem_store();
    let t = acme();
    let code = start(&s, "gone@example.com", NOW).unwrap();
    let v = verify(&s, "gone@example.com", &code, NOW + 1).unwrap();
    s.link_did(&t, &v.user.id, "did:mata:abc", NOW + 2).unwrap();
    assert!(s.delete_user(&t, &v.user.id, NOW + 3).unwrap());
    assert!(!s.delete_user(&t, &v.user.id, NOW + 3).unwrap());
    assert!(s.user_by_email(&t, "gone@example.com").unwrap().is_none());
    assert!(s.user_by_did(&t, "did:mata:abc").unwrap().is_none());
    // The address signs up again as a NEW user.
    let code = start(&s, "gone@example.com", NOW + 100).unwrap();
    let v2 = verify(&s, "gone@example.com", &code, NOW + 101).unwrap();
    assert!(v2.user_created);
    assert_ne!(v2.user.id, v.user.id);
    assert_clean(&s);
}

#[test]
fn metadata_and_paging() {
    let s = mem_store();
    let t = acme();
    for i in 0..5u8 {
        s.import_user(&imported(&format!("p{i}@example.com"), i + 1), NOW)
            .unwrap();
    }
    let page1 = s.users(&t, None, 2).unwrap();
    let page2 = s.users(&t, Some(&page1[1].id), 2).unwrap();
    let page3 = s.users(&t, Some(&page2[1].id), 2).unwrap();
    assert_eq!((page1.len(), page2.len(), page3.len()), (2, 2, 1));
    let mut all: Vec<_> = [page1, page2, page3]
        .concat()
        .into_iter()
        .map(|u| u.id)
        .collect();
    all.dedup();
    assert_eq!(all.len(), 5);

    let mut md = BTreeMap::new();
    md.insert("display_name".to_string(), serde_json::json!("Pat"));
    let u = s.set_user_metadata(&t, &all[0], md.clone(), NOW).unwrap();
    assert_eq!(s.user(&t, &u.id).unwrap().unwrap().metadata, md);
}

// ─── housekeeping ────────────────────────────────────────────────────────────

#[test]
fn purge_removes_only_old_ended_challenges() {
    let s = mem_store().with_limits(Limits::NONE);
    let t = acme();
    let code = start(&s, "done@example.com", NOW).unwrap();
    verify(&s, "done@example.com", &code, NOW + 1).unwrap();
    start(&s, "stale@example.com", NOW).unwrap(); // expires at NOW+600
    start(&s, "fresh@example.com", NOW + 5_000).unwrap(); // live

    assert_eq!(
        s.purge_challenges(NOW + 700, 3_600).unwrap(),
        0,
        "inside retention"
    );
    assert_eq!(s.purge_challenges(NOW + 5_000, 3_600).unwrap(), 2);
    assert!(s.live_challenge(&t, "stale@example.com").unwrap().is_none());
    assert!(s.live_challenge(&t, "fresh@example.com").unwrap().is_some());
    assert_eq!(s.dump().unwrap().challenges.len(), 1);
    assert_clean(&s);
}

// ─── dump / restore ──────────────────────────────────────────────────────────

fn populated() -> SignupStore<MemEngine> {
    let s = mem_store().with_limits(Limits::NONE);
    let t = acme();
    for i in 0..4 {
        let e = format!("d{i}@example.com");
        let code = start(&s, &e, NOW).unwrap();
        verify(&s, &e, &code, NOW + 1).unwrap();
    }
    let u = s.user_by_email(&t, "d0@example.com").unwrap().unwrap();
    s.link_did(&t, &u.id, "did:mata:linked", NOW + 2).unwrap();
    s.create_tenant(&tenant_record(&TenantId::parse("beta").unwrap()))
        .unwrap();
    s
}

#[test]
fn dump_restore_round_trips_and_keeps_pending_codes_alive() {
    let s = populated();
    let t = acme();
    let pending = start(&s, "pending@example.com", NOW + 10).unwrap();
    let dump = s.dump().unwrap();
    assert!(
        !format!("{dump:?}").contains("example.com"),
        "Debug never prints records"
    );

    let dir = tmpdir();
    {
        let r = disk_store(dir.path());
        r.restore(&dump).unwrap();
        assert_clean(&r);
        assert_eq!(r.dump().unwrap(), dump, "byte-for-byte the same store");
        assert_eq!(
            r.user_by_did(&t, "did:mata:linked")
                .unwrap()
                .unwrap()
                .email
                .as_str(),
            "d0@example.com"
        );
        assert_eq!(
            r.restore(&dump).unwrap_err().code(),
            "restore_refused",
            "never over data"
        );
    }
    // Reopen from disk: still all there, and the pending code still verifies.
    let r = disk_store(dir.path());
    assert_eq!(r.count_users(&t).unwrap(), 4);
    let v = verify(&r, "pending@example.com", &pending, NOW + 20).unwrap();
    assert!(v.user_created);
    assert_eq!(r.height().unwrap(), dump.audit_seq + 2);
    assert_clean(&r);
}

#[test]
fn restore_refuses_a_dump_from_another_pepper() {
    let dump = populated().dump().unwrap();
    let r = SignupStore::in_memory(Pepper::from_bytes([42; 32])).unwrap();
    assert_eq!(r.restore(&dump).unwrap_err().code(), "pepper_mismatch");
    assert!(r.tenants().unwrap().is_empty(), "nothing half-restored");
}

// ─── disk: durability, sealing, exclusivity, two processes ──────────────────

#[test]
fn attempts_survive_a_restart() {
    let dir = tmpdir();
    let t = acme();
    let code = {
        let s = disk_store(dir.path())
            .with_policy(Policy {
                max_attempts: 3,
                ..Policy::DEFAULT
            })
            .unwrap();
        s.create_tenant(&tenant_record(&t)).unwrap();
        let code = start(&s, "crash@example.com", NOW).unwrap();
        verify(&s, "crash@example.com", &wrong(&code, 0), NOW + 1).unwrap_err();
        verify(&s, "crash@example.com", &wrong(&code, 1), NOW + 1).unwrap_err();
        code
    }; // dropped: the "restart"
    let s = disk_store(dir.path())
        .with_policy(Policy {
            max_attempts: 3,
            ..Policy::DEFAULT
        })
        .unwrap();
    assert_eq!(
        s.live_challenge(&t, "crash@example.com")
            .unwrap()
            .unwrap()
            .attempts,
        2
    );
    let e = verify(&s, "crash@example.com", &wrong(&code, 2), NOW + 2).unwrap_err();
    assert!(
        matches!(e.as_flow(), Some(FlowError::AttemptsExhausted)),
        "a restart buys no guesses"
    );
    assert_clean(&s);
}

#[test]
fn rows_are_sealed_at_rest() {
    let dir = tmpdir();
    {
        let s = disk_store(dir.path());
        s.create_tenant(&tenant_record(&acme())).unwrap();
        let code = start(&s, "secret.person@example.com", NOW).unwrap();
        let v = verify(&s, "secret.person@example.com", &code, NOW + 1).unwrap();
        s.link_did(&acme(), &v.user.id, "did:mata:SealedDidValue123", NOW + 2)
            .unwrap();
    }
    let raw = std::fs::read(dir.path().join("signup.redb")).unwrap();
    let has = |needle: &str| raw.windows(needle.len()).any(|w| w == needle.as_bytes());
    // Positive control: keys are plaintext by design (ids and peppered indexes),
    // so the scan must find one — or it proves nothing about the values.
    assert!(has("user-email/acme/"), "the byte scan itself works");
    assert!(
        !has("secret.person"),
        "the address is never in the file in clear"
    );
    assert!(!has("SealedDidValue123"), "nor the DID");
    assert!(!has("Acme Corp"), "nor the tenant's name");
    assert!(!has("203.0.113.7"), "nor the client address");
    let kek = std::fs::read(dir.path().join("signup.key")).unwrap();
    assert_eq!(kek.len(), 32);
}

#[test]
fn a_wrong_key_encryption_key_reads_nothing() {
    let dir = tmpdir();
    {
        let s = disk_store(dir.path());
        s.create_tenant(&tenant_record(&acme())).unwrap();
    }
    std::fs::write(dir.path().join("signup.key"), [7u8; 32]).unwrap();
    let s = disk_store(dir.path());
    assert_eq!(s.tenant(&acme()).unwrap_err().code(), "storage_failure");

    std::fs::write(dir.path().join("signup.key"), [7u8; 31]).unwrap();
    let e = SignupStore::open_dir(dir.path(), pepper()).unwrap_err();
    assert_eq!(e.code(), "key_file");
}

#[test]
fn a_second_opener_is_refused() {
    let dir = tmpdir();
    let _held = disk_store(dir.path());
    let e = SignupStore::open_dir(dir.path(), pepper()).unwrap_err();
    assert_eq!(e.code(), "storage_failure", "{e}");
}

const CHILD_DIR: &str = "MSS_STORE_CHILD_DIR";
const CHILD_MODE: &str = "MSS_STORE_CHILD_MODE";

fn run_child(dir: &Path, mode: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "child_process_entry",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DIR, dir)
        .env(CHILD_MODE, mode)
        .status()
        .unwrap()
}

/// Not a test of its own: the body a child process runs for the two
/// cross-process tests below.
#[test]
#[ignore]
fn child_process_entry() {
    let Some(dir) = std::env::var_os(CHILD_DIR).map(PathBuf::from) else {
        return;
    };
    match std::env::var(CHILD_MODE).as_deref() {
        Ok("sign-up") => {
            let s = disk_store(&dir);
            let code = start(&s, "child@example.com", NOW).unwrap();
            verify(&s, "child@example.com", &code, NOW + 1).unwrap();
        }
        Ok("open-must-fail") => {
            let e = SignupStore::open_dir(&dir, pepper()).unwrap_err();
            assert_eq!(e.code(), "storage_failure");
        }
        other => panic!("unknown child mode {other:?}"),
    }
}

#[test]
fn a_separate_process_writes_and_this_one_reads() {
    let dir = tmpdir();
    {
        let s = disk_store(dir.path());
        s.create_tenant(&tenant_record(&acme())).unwrap();
    }
    assert!(
        run_child(dir.path(), "sign-up").success(),
        "child sign-up failed"
    );
    let s = disk_store(dir.path());
    let u = s
        .user_by_email(&acme(), "child@example.com")
        .unwrap()
        .unwrap();
    assert_eq!(u.email_verified_at, Some(NOW + 1));
    assert_eq!(s.height().unwrap(), 4);
    assert_clean(&s);
}

#[test]
fn a_separate_process_cannot_open_a_held_store() {
    let dir = tmpdir();
    let s = disk_store(dir.path());
    s.create_tenant(&tenant_record(&acme())).unwrap();
    assert!(
        run_child(dir.path(), "open-must-fail").success(),
        "the child opened a held store"
    );
    // The holder is unaffected.
    assert!(s.tenant(&acme()).unwrap().is_some());
}

// ─── M2 store additions: sessions, usernames, members, webhook outbox ───────

use mid_sovereign_signup::{SessionTokens, SessionTtl, TenantMember, Verified};

fn signed_in(s: &SignupStore<MemEngine>, email: &str, now: u64) -> (Verified, SessionTokens) {
    let code = start(s, email, now).unwrap();
    s.verify_and_open_session(
        &VerifyRequest {
            tenant: &acme(),
            email,
            code: &code,
            now: now + 1,
        },
        SessionTtl {
            access_secs: 600,
            refresh_secs: 3_600,
        },
        &mut OsEntropy,
    )
    .unwrap()
}

#[test]
fn verify_opens_a_session_in_the_same_transaction() {
    let s = mem_store();
    let (v, tok) = signed_in(&s, "sess@example.com", NOW);
    assert!(tok.token.starts_with("sess_") && tok.refresh.starts_with("ref_"));
    assert!(
        !format!("{tok:?}").contains(&tok.token),
        "Debug hides the tokens"
    );
    let rec = s.session(&tok.token, NOW + 2).unwrap().unwrap();
    assert_eq!(rec.user, v.user.id);
    assert!(
        s.session(&tok.token, NOW + 1 + 600).unwrap().is_none(),
        "access expiry is exact"
    );
    assert!(s.session("sess_forged", NOW).unwrap().is_none());
    // The store never holds a usable token.
    let dump = serde_json::to_string(&s.dump().unwrap()).unwrap();
    assert!(!dump.contains(&tok.token) && !dump.contains(&tok.refresh));
    // A failed verify opens nothing.
    let code = start(&s, "nope@example.com", NOW).unwrap();
    let e = s
        .verify_and_open_session(
            &VerifyRequest {
                tenant: &acme(),
                email: "nope@example.com",
                code: &wrong(&code, 0),
                now: NOW + 1,
            },
            SessionTtl::DEFAULT,
            &mut OsEntropy,
        )
        .unwrap_err();
    assert_eq!(e.code(), "wrong_code");
    assert_eq!(s.dump().unwrap().sessions.len(), 1);
    assert_clean(&s);
}

#[test]
fn refresh_rotates_and_a_replay_revokes() {
    let s = mem_store();
    let ttl = SessionTtl {
        access_secs: 600,
        refresh_secs: 3_600,
    };
    let (_, t1) = signed_in(&s, "rot@example.com", NOW);
    let t2 = s
        .refresh_session(&t1.refresh, ttl, NOW + 100, &mut OsEntropy)
        .unwrap();
    assert!(
        s.session(&t1.token, NOW + 101).unwrap().is_none(),
        "old access token dies"
    );
    assert!(s.session(&t2.token, NOW + 101).unwrap().is_some());
    assert_clean(&s);
    // The spent refresh token comes back: theft. The live successor dies too.
    let e = s
        .refresh_session(&t1.refresh, ttl, NOW + 200, &mut OsEntropy)
        .unwrap_err();
    assert_eq!(e.code(), "session_invalid");
    assert!(
        s.session(&t2.token, NOW + 201).unwrap().is_none(),
        "replay revokes the family"
    );
    assert_eq!(
        s.refresh_session(&t2.refresh, ttl, NOW + 202, &mut OsEntropy)
            .unwrap_err()
            .code(),
        "session_invalid"
    );
    let revoked = s
        .audit(Some(&acme()), 0, 100)
        .unwrap()
        .iter()
        .filter(|r| r.event.kind == AuditKind::SessionsRevoked)
        .count();
    assert_eq!(revoked, 1);
    // Refresh expiry is exact.
    let (_, t3) = signed_in(&s, "late@example.com", NOW);
    assert_eq!(
        s.refresh_session(&t3.refresh, ttl, NOW + 1 + 3_600, &mut OsEntropy)
            .unwrap_err()
            .code(),
        "session_invalid"
    );
    assert_clean(&s);
}

#[test]
fn concurrent_refreshes_of_one_token_yield_at_most_one_live_pair() {
    let s = Arc::new(mem_store());
    let (_, t) = signed_in(&s, "multi@example.com", NOW);
    let n = 12;
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let (s, b, r) = (s.clone(), barrier.clone(), t.refresh.clone());
            std::thread::spawn(move || {
                b.wait();
                s.refresh_session(&r, SessionTtl::DEFAULT, NOW + 10, &mut OsEntropy)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // The first wins; the next is a replay and revokes the winner's pair.
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let winner = results.iter().find_map(|r| r.as_ref().ok()).unwrap();
    assert!(
        s.session(&winner.token, NOW + 11).unwrap().is_none(),
        "racing a refresh is treated as theft"
    );
    assert_clean(&s);
}

#[test]
fn sign_out_and_sign_out_everywhere() {
    let s = mem_store();
    let (v, a) = signed_in(&s, "out@example.com", NOW);
    let b = s
        .open_session(
            &acme(),
            &v.user.id,
            SessionTtl::DEFAULT,
            NOW + 5,
            &mut OsEntropy,
        )
        .unwrap();
    assert!(s.revoke_session(&a.token).unwrap());
    assert!(!s.revoke_session(&a.token).unwrap());
    assert!(s.session(&b.token, NOW + 6).unwrap().is_some());
    assert_eq!(
        s.revoke_user_sessions(&acme(), &v.user.id, NOW + 7)
            .unwrap(),
        1
    );
    assert!(s.session(&b.token, NOW + 8).unwrap().is_none());
    // Deleting a user ends their sessions.
    let c = s
        .open_session(
            &acme(),
            &v.user.id,
            SessionTtl::DEFAULT,
            NOW + 9,
            &mut OsEntropy,
        )
        .unwrap();
    s.delete_user(&acme(), &v.user.id, NOW + 10).unwrap();
    assert!(s.session(&c.token, NOW + 11).unwrap().is_none());
    assert_clean(&s);
}

#[test]
fn purge_sessions_drops_expired_and_dangling() {
    let s = mem_store();
    let ttl = SessionTtl {
        access_secs: 60,
        refresh_secs: 120,
    };
    let (v, t1) = signed_in(&s, "p@example.com", NOW);
    let _t2 = s
        .refresh_session(&t1.refresh, ttl, NOW + 2, &mut OsEntropy)
        .unwrap();
    let fresh = s
        .open_session(
            &acme(),
            &v.user.id,
            SessionTtl::DEFAULT,
            NOW + 3,
            &mut OsEntropy,
        )
        .unwrap();
    assert_eq!(
        s.purge_sessions(NOW + 1_000).unwrap(),
        1,
        "the 120 s family expired"
    );
    assert!(s.session(&fresh.token, NOW + 1_000).unwrap().is_some());
    assert_eq!(s.dump().unwrap().sessions.len(), 1);
    assert_clean(&s);
}

#[test]
fn usernames_are_unique_normalized_and_released() {
    let s = mem_store();
    let a = s.import_user(&imported("ua@example.com", 1), NOW).unwrap();
    let b = s.import_user(&imported("ub@example.com", 2), NOW).unwrap();
    assert!(s.username_available(&acme(), "Tim.A").unwrap());
    assert_eq!(
        s.username_available(&acme(), "x").unwrap_err().code(),
        "invalid_username"
    );
    assert_eq!(
        s.username_available(&acme(), "-bad").unwrap_err().code(),
        "invalid_username"
    );
    let u = s
        .set_username(&acme(), &a.id, Some("  Tim.A "), NOW)
        .unwrap();
    assert_eq!(u.username.as_deref(), Some("tim.a"));
    assert!(!s.username_available(&acme(), "TIM.A").unwrap());
    assert_eq!(
        s.set_username(&acme(), &b.id, Some("tim.a"), NOW)
            .unwrap_err()
            .code(),
        "username_taken"
    );
    s.set_username(&acme(), &a.id, Some("tim_b"), NOW).unwrap();
    assert!(
        s.username_available(&acme(), "tim.a").unwrap(),
        "rename frees the old name"
    );
    s.set_username(&acme(), &b.id, Some("tim.a"), NOW).unwrap();
    s.set_username(&acme(), &a.id, None, NOW).unwrap();
    assert!(s.username_available(&acme(), "tim_b").unwrap());
    // Another tenant has its own namespace.
    let beta = TenantId::parse("beta").unwrap();
    s.create_tenant(&tenant_record(&beta)).unwrap();
    assert!(s.username_available(&beta, "tim.a").unwrap());
    // Restore rebuilds the claim; deletion frees it.
    let dump = s.dump().unwrap();
    let r = SignupStore::in_memory(pepper()).unwrap();
    r.restore(&dump).unwrap();
    assert!(!r.username_available(&acme(), "tim.a").unwrap());
    assert_clean(&r);
    s.delete_user(&acme(), &b.id, NOW).unwrap();
    assert!(s.username_available(&acme(), "tim.a").unwrap());
    assert_clean(&s);
}

#[test]
fn members_and_webhooks_are_validated_and_secrets_redacted() {
    let s = mem_store();
    let t = acme();
    let bad = vec![TenantMember {
        did: "nope".into(),
        grants: vec![],
    }];
    assert_eq!(
        s.set_members(&t, bad, NOW).unwrap_err().code(),
        "invalid_config"
    );
    let ok = vec![TenantMember {
        did: "did:mata:abc".into(),
        grants: vec!["users.read".into()],
    }];
    assert_eq!(s.set_members(&t, ok, NOW).unwrap().members.len(), 1);
    let created = vec!["user.created".to_string()];
    assert_eq!(
        s.add_webhook(&t, "ftp://x", created.clone(), NOW, &mut OsEntropy)
            .unwrap_err()
            .code(),
        "invalid_config"
    );
    assert_eq!(
        s.add_webhook(
            &t,
            "https://x.test/h",
            vec!["user.exploded".into()],
            NOW,
            &mut OsEntropy
        )
        .unwrap_err()
        .code(),
        "invalid_config"
    );
    let hook = s
        .add_webhook(&t, "https://x.test/h", created, NOW, &mut OsEntropy)
        .unwrap();
    assert!(hook.id.starts_with("wh_") && hook.secret.len() == 43);
    let shown = format!("{:?}", s.tenant(&t).unwrap().unwrap());
    assert!(
        !shown.contains(&hook.secret),
        "Debug of a tenant never prints a webhook secret"
    );
    assert_eq!(
        s.remove_webhook(&t, "wh_nope", NOW).unwrap_err().code(),
        "webhook_not_found"
    );
    s.remove_webhook(&t, &hook.id, NOW).unwrap();
    assert!(s.tenant(&t).unwrap().unwrap().webhooks.is_empty());
}

#[test]
fn events_enter_the_outbox_with_the_write_and_back_off() {
    let s = mem_store();
    let t = acme();
    let every: Vec<String> = mid_sovereign_signup::WEBHOOK_EVENTS
        .iter()
        .map(|e| e.to_string())
        .collect();
    let all = s
        .add_webhook(&t, "https://hooks.test/all", every, NOW, &mut OsEntropy)
        .unwrap();
    let created_only = s
        .add_webhook(
            &t,
            "https://hooks.test/created",
            vec!["user.created".into()],
            NOW,
            &mut OsEntropy,
        )
        .unwrap();
    // Sending a code queues `signup.code_sent`, to `all` only.
    let code = start(&s, "ev@example.com", NOW).unwrap();
    let sent = s.due_deliveries(NOW, 100).unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].endpoint.id.as_str(), sent[0].item.event_type.as_str()),
        (all.id.as_str(), "signup.code_sent")
    );
    s.delivery_succeeded(&sent[0].item.id, NOW).unwrap();
    // A failed verify queues nothing.
    verify(&s, "ev@example.com", &wrong(&code, 0), NOW + 1).unwrap_err();
    assert_eq!(s.outbox_len().unwrap(), 0);
    // Sign-up: created + verified + signed_in to `all`, created to `created_only`.
    let v = verify(&s, "ev@example.com", &code, NOW + 2).unwrap();
    let due = s.due_deliveries(NOW + 2, 100).unwrap();
    let mut got: Vec<(String, String)> = due
        .iter()
        .map(|d| (d.endpoint.id.clone(), d.item.event_type.clone()))
        .collect();
    got.sort();
    let mut want = vec![
        (all.id.clone(), "user.created".to_string()),
        (all.id.clone(), "user.signed_in".to_string()),
        (all.id.clone(), "user.verified".to_string()),
        (created_only.id.clone(), "user.created".to_string()),
    ];
    want.sort();
    assert_eq!(got, want);
    let created: Vec<_> = due
        .iter()
        .filter(|d| d.item.event_type == "user.created")
        .collect();
    assert_eq!(
        created[0].item.event_id, created[1].item.event_id,
        "one event id across endpoints"
    );
    let body: serde_json::Value = serde_json::from_str(&created[0].item.payload).unwrap();
    assert_eq!(body["data"]["user"]["email"], "ev@example.com");
    assert_eq!(body["data"]["user"]["id"], v.user.id.as_str());

    // Success dequeues and audits; failure backs off 60 s, then doubles.
    s.delivery_succeeded(&due[0].item.id, NOW + 3).unwrap();
    let second = due[1].item.id.clone();
    assert!(!s.delivery_failed(&second, NOW + 3, "503").unwrap());
    assert!(s
        .due_deliveries(NOW + 3, 100)
        .unwrap()
        .iter()
        .all(|d| d.item.id != second));
    assert!(s
        .due_deliveries(NOW + 3 + 60, 100)
        .unwrap()
        .iter()
        .any(|d| d.item.id == second));
    let max = mid_sovereign_signup::store::MAX_DELIVERY_ATTEMPTS;
    for i in 1..max {
        let gave_up = s
            .delivery_failed(&second, NOW + 10 + u64::from(i), "503")
            .unwrap();
        assert_eq!(gave_up, i + 1 == max);
    }
    let kinds: Vec<_> = s
        .audit(Some(&t), 0, 1_000)
        .unwrap()
        .into_iter()
        .map(|r| r.event.kind)
        .collect();
    assert!(kinds.contains(&AuditKind::WebhookDelivered));
    assert!(kinds.contains(&AuditKind::WebhookAbandoned));
    assert_eq!(s.outbox_len().unwrap(), 2);

    // Removing an endpoint drops its queue; deletion emits user.deleted.
    s.remove_webhook(&t, &created_only.id, NOW + 20).unwrap();
    s.delete_user(&t, &v.user.id, NOW + 21).unwrap();
    let left = s.due_deliveries(NOW + 21, 100).unwrap();
    assert!(left.iter().any(|d| d.item.event_type == "user.deleted"));
    assert!(left.iter().all(|d| d.endpoint.id == all.id));
    // The outbox survives dump/restore.
    let dump = s.dump().unwrap();
    let r = SignupStore::in_memory(pepper()).unwrap();
    r.restore(&dump).unwrap();
    assert_eq!(r.outbox_len().unwrap(), s.outbox_len().unwrap());
    assert_clean(&r);
}
