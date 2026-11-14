//! Unit tests for the pure core. Every test is deterministic: fixed entropy,
//! fixed clocks, a fixed pepper.

use crate::attest::{
    sign_attestation_single_device, verify_attestation, AttestError, AttestationClaims,
    AttestationPolicy, ATTESTATION_CONTEXT,
};
use crate::flow::{start, verify, StartRequest, VerifyRequest};
use crate::records::{AuditKind, ConsumedReason, RejectReason, Tenant, TenantId, User, UserId};
use crate::seams::{FixedEntropy, Mailer, StubMailer};
use crate::{
    Code, CodeError, CodeMac, EmailError, EmailIndex, FlowError, NormalizedEmail, Pepper, Policy,
    PolicyError, RateWindow,
};

use kms_client::InMemoryDeviceSigner;
use mid_verify::keys::{did_from_pubkey, multibase_from_pubkey};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

const NOW: u64 = 1_759_190_400; // 2025-09-30T00:00:00Z

fn pepper() -> Pepper {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8 + 1;
    }
    Pepper::from_bytes(b)
}

fn tenant() -> TenantId {
    TenantId::parse("acme").unwrap()
}

/// Enough fixed bytes for one start (16 id + 4 code) and one verify-create
/// (16 user id), repeated so a test can run several rounds.
fn entropy() -> FixedEntropy {
    let mut v = Vec::new();
    for round in 0u8..8 {
        v.extend(std::iter::repeat_n(0xA0 + round, 16)); // challenge id
        v.extend([0x00, 0x01, 0xE2, 0x40 + round]); // code 123456 + round
        v.extend(std::iter::repeat_n(0x50 + round, 16)); // user id
    }
    FixedEntropy::new(v)
}

fn make_signing_key(seed: &str) -> SigningKey {
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    h.update(b"-mid-sovereign-signup-test-seed");
    let bytes: [u8; 32] = h.finalize().into();
    SigningKey::from_bytes(&bytes.into()).unwrap()
}

// ─── email ───────────────────────────────────────────────────────────────────

#[test]
fn email_normalizes_case_and_whitespace() {
    let e = NormalizedEmail::parse("  Alice.Smith+Tag@Example.COM \n").unwrap();
    assert_eq!(e.as_str(), "alice.smith+tag@example.com");
    assert_eq!(e.local(), "alice.smith+tag");
    assert_eq!(e.domain(), "example.com");
    assert_eq!(format!("{e:?}"), "NormalizedEmail(a***@example.com)");
    // Round-trips through serde with validation on the way in.
    let json = serde_json::to_string(&e).unwrap();
    assert_eq!(json, "\"alice.smith+tag@example.com\"");
    let back: NormalizedEmail = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
    assert!(serde_json::from_str::<NormalizedEmail>("\"nope\"").is_err());
}

#[test]
fn email_rejections() {
    use EmailError::*;
    let cases: &[(&str, EmailError)] = &[
        ("", Empty),
        ("   ", Empty),
        ("alice", MissingAt),
        ("a@b@c.com", MultipleAt),
        ("@example.com", EmptyLocal),
        ("alice@", EmptyDomain),
        ("alice@localhost", DomainNeedsDot),
        ("alice@-bad.com", BadDomainLabel),
        ("alice@bad-.com", BadDomainLabel),
        ("alice@exa mple.com", BadDomainLabel),
        ("alice@example..com", BadDomainLabel),
        ("alice@exämple.com", BadDomainLabel),
        ("al ice@example.com", BadLocalChar),
        ("\"alice\"@example.com", BadLocalChar),
        ("alice<x>@example.com", BadLocalChar),
    ];
    for (input, want) in cases {
        assert_eq!(
            NormalizedEmail::parse(input).unwrap_err(),
            *want,
            "{input:?}"
        );
    }
    let long_local = format!("{}@example.com", "a".repeat(65));
    assert_eq!(
        NormalizedEmail::parse(&long_local).unwrap_err(),
        LocalTooLong { len: 65 }
    );
    let long_total = format!("a@{}.com", "b".repeat(260));
    assert!(matches!(
        NormalizedEmail::parse(&long_total).unwrap_err(),
        TooLong { .. }
    ));
}

#[test]
fn email_index_is_tenant_scoped_and_pepper_bound() {
    let e = NormalizedEmail::parse("alice@example.com").unwrap();
    let p = pepper();
    let a = EmailIndex::derive(&p, &tenant(), &e);
    let b = EmailIndex::derive(&p, &TenantId::parse("other").unwrap(), &e);
    assert_ne!(a, b, "same address, different tenant → different index");
    let other_pepper = Pepper::from_bytes([9u8; 32]);
    let c = EmailIndex::derive(&other_pepper, &tenant(), &e);
    assert_ne!(
        a, c,
        "same address+tenant, different pepper → different index"
    );
    // Deterministic + serde round trip.
    assert_eq!(a, EmailIndex::derive(&p, &tenant(), &e));
    let json = serde_json::to_string(&a).unwrap();
    let back: EmailIndex = serde_json::from_str(&json).unwrap();
    assert_eq!(back, a);
    assert_eq!(a.to_base64url().len(), 43);
}

// ─── code ────────────────────────────────────────────────────────────────────

#[test]
fn code_generation_is_uniform_and_zero_padded() {
    // 0x00000000 → "000000"
    let mut e = FixedEntropy::new([0u8; 4]);
    assert_eq!(Code::generate(&mut e).unwrap().as_str(), "000000");
    // 0x0001E240 = 123456
    let mut e = FixedEntropy::new([0x00, 0x01, 0xE2, 0x40]);
    assert_eq!(Code::generate(&mut e).unwrap().as_str(), "123456");
    // The rejection band: u32::MAX is rejected, the next draw is used.
    let mut e = FixedEntropy::new([0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x07]);
    assert_eq!(Code::generate(&mut e).unwrap().as_str(), "000007");
    assert_eq!(e.remaining(), 0);
    // Largest accepted draw maps without bias: 4_293_999_999 % 1e6 = 999_999.
    let mut e = FixedEntropy::new(4_293_999_999u32.to_be_bytes());
    assert_eq!(Code::generate(&mut e).unwrap().as_str(), "999999");
    // Exhausted entropy is an error, never a fixed code.
    let mut e = FixedEntropy::new([0u8; 3]);
    assert!(Code::generate(&mut e).is_err());
    // Debug never prints the digits.
    assert_eq!(
        format!("{:?}", Code::parse("123456").unwrap()),
        "Code(******)"
    );
}

#[test]
fn code_parse_tolerates_separators_only() {
    assert_eq!(Code::parse("123456").unwrap().as_str(), "123456");
    assert_eq!(Code::parse(" 123 456 ").unwrap().as_str(), "123456");
    assert_eq!(Code::parse("123-456").unwrap().as_str(), "123456");
    assert_eq!(Code::parse("12345").unwrap_err(), CodeError::WrongLength);
    assert_eq!(Code::parse("1234567").unwrap_err(), CodeError::WrongLength);
    assert_eq!(Code::parse("12345a").unwrap_err(), CodeError::NotDigits);
    assert_eq!(Code::parse("").unwrap_err(), CodeError::WrongLength);
    assert_eq!(
        Code::parse("１２３４５６").unwrap_err(),
        CodeError::NotDigits
    );
}

#[test]
fn code_mac_binds_every_input() {
    let p = pepper();
    let t = tenant();
    let e = NormalizedEmail::parse("alice@example.com").unwrap();
    let idx = EmailIndex::derive(&p, &t, &e);
    let mut ent = entropy();
    let id = crate::ChallengeId::generate(&mut ent).unwrap();
    let code = Code::parse("123456").unwrap();
    let mac = CodeMac::commit(&p, &t, &idx, &id, &code);

    assert!(mac.verify(&p, &t, &idx, &id, &code));
    assert!(!mac.verify(&p, &t, &idx, &id, &Code::parse("123457").unwrap()));
    let other_id = crate::ChallengeId::generate(&mut ent).unwrap();
    assert!(
        !mac.verify(&p, &t, &idx, &other_id, &code),
        "bound to the challenge"
    );
    let other_t = TenantId::parse("other").unwrap();
    assert!(
        !mac.verify(&p, &other_t, &idx, &id, &code),
        "bound to the tenant"
    );
    let other_idx = EmailIndex::derive(&p, &t, &NormalizedEmail::parse("bob@example.com").unwrap());
    assert!(
        !mac.verify(&p, &t, &other_idx, &id, &code),
        "bound to the address"
    );
    let other_p = Pepper::from_bytes([7u8; 32]);
    assert!(
        !mac.verify(&other_p, &t, &idx, &id, &code),
        "bound to the pepper"
    );

    let json = serde_json::to_string(&mac).unwrap();
    let back: CodeMac = serde_json::from_str(&json).unwrap();
    assert!(back.verify(&p, &t, &idx, &id, &code));
    assert_eq!(format!("{mac:?}"), "CodeMac(<redacted>)");
}

// ─── policy ──────────────────────────────────────────────────────────────────

#[test]
fn policy_validation() {
    assert!(Policy::DEFAULT.validate().is_ok());
    assert_eq!(
        Policy {
            code_ttl_secs: 0,
            ..Policy::DEFAULT
        }
        .validate()
        .unwrap_err(),
        PolicyError::ZeroTtl
    );
    assert_eq!(
        Policy {
            max_attempts: 0,
            ..Policy::DEFAULT
        }
        .validate()
        .unwrap_err(),
        PolicyError::ZeroAttempts
    );
    assert_eq!(
        Policy {
            resend_cooldown_secs: 601,
            ..Policy::DEFAULT
        }
        .validate()
        .unwrap_err(),
        PolicyError::CooldownExceedsTtl {
            cooldown: 601,
            ttl: 600
        }
    );
    assert_eq!(
        Policy {
            attestation_ttl_secs: 0,
            ..Policy::DEFAULT
        }
        .validate()
        .unwrap_err(),
        PolicyError::ZeroAttestationTtl
    );
}

#[test]
fn rate_window_slides() {
    let mut w = RateWindow::new(60, 3);
    assert!(w.check_and_record(100).is_ok());
    assert!(w.check_and_record(110).is_ok());
    assert!(w.check_and_record(120).is_ok());
    let err = w.check_and_record(130).unwrap_err();
    assert_eq!(err.retry_after_secs, 30, "oldest (100) leaves at 160");
    assert_eq!(w.count(130), 3);
    // At 160 the first event has left the window.
    assert_eq!(w.count(160), 2);
    assert!(w.check_and_record(160).is_ok());
    assert!(w.check_and_record(161).is_err());
    // Persisted and restored, it keeps counting.
    let json = serde_json::to_string(&w).unwrap();
    let mut back: RateWindow = serde_json::from_str(&json).unwrap();
    assert!(back.check_and_record(161).is_err());
    let f: FlowError = back.check_and_record(161).unwrap_err().into();
    assert_eq!(f.code(), "rate_limited");
}

// ─── records ─────────────────────────────────────────────────────────────────

#[test]
fn tenant_id_rules() {
    assert!(TenantId::parse("acme").is_ok());
    assert!(TenantId::parse("my-app-2").is_ok());
    assert!(TenantId::parse("").is_err());
    assert!(TenantId::parse("Acme").is_err());
    assert!(TenantId::parse("-acme").is_err());
    assert!(TenantId::parse("acme-").is_err());
    assert!(TenantId::parse("ac me").is_err());
    assert!(TenantId::parse("a/b").is_err());
    assert!(TenantId::parse(&"a".repeat(65)).is_err());
}

#[test]
fn user_id_is_a_v4_uuid() {
    let id = UserId::from_random_bytes([0x5A; 16]);
    assert_eq!(id.as_str(), "5a5a5a5a-5a5a-4a5a-9a5a-5a5a5a5a5a5a");
    assert_eq!(
        UserId::parse("5A5A5A5A-5A5A-4A5A-9A5A-5A5A5A5A5A5A").unwrap(),
        id
    );
    assert!(UserId::parse("not-a-uuid").is_err());
}

#[test]
fn tenant_origins_and_public_id() {
    let mut ent = FixedEntropy::new([0x11; 16]);
    let t = Tenant::new(
        tenant(),
        "Acme",
        vec!["https://App.Acme.com/".into()],
        NOW,
        &mut ent,
    )
    .unwrap();
    assert!(t.public_id.starts_with("pub_"));
    assert_eq!(t.public_id.len(), 4 + 22);
    assert!(t.allows_origin("https://app.acme.com"));
    assert!(t.allows_origin(" HTTPS://app.acme.com/ "));
    assert!(!t.allows_origin("https://evil.com"));
    assert!(
        !t.allows_origin("http://app.acme.com"),
        "scheme is part of the origin"
    );
    assert_eq!(Tenant::key(&t.id), "tenant/acme");
    assert_eq!(
        Tenant::public_key(&t.public_id),
        format!("tenant-public/{}", t.public_id)
    );
}

#[test]
fn link_did_is_idempotent_and_exclusive() {
    let p = pepper();
    let e = NormalizedEmail::parse("alice@example.com").unwrap();
    let mut u = User {
        id: UserId::from_random_bytes([1; 16]),
        tenant: tenant(),
        email: e.clone(),
        email_idx: EmailIndex::derive(&p, &tenant(), &e),
        email_verified_at: Some(NOW),
        created_at: NOW,
        last_sign_in_at: None,
        linked_did: None,
        username: None,
        metadata: Default::default(),
    };
    assert_eq!(u.link_did("nope").unwrap_err().code(), "invalid_did");
    assert_eq!(u.link_did("did:mata:").unwrap_err().code(), "invalid_did");
    u.link_did("did:mata:abc").unwrap();
    u.link_did(" did:mata:abc ").unwrap();
    assert_eq!(
        u.link_did("did:mata:xyz").unwrap_err().code(),
        "did_already_linked"
    );
    assert_eq!(u.unlink_did().as_deref(), Some("did:mata:abc"));
    u.link_did("did:mata:xyz").unwrap();
    // The optional field is absent from JSON when unset.
    u.unlink_did();
    let json = serde_json::to_string(&u).unwrap();
    assert!(!json.contains("linked_did"));
    assert!(!json.contains("metadata"));
}

// ─── flow ────────────────────────────────────────────────────────────────────

#[test]
fn sign_up_then_sign_in() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let policy = Policy::DEFAULT;

    // Round 1: sign up.
    let s = start(
        &StartRequest {
            tenant: &t,
            email: " Alice@Example.com ",
            create_user: true,
            now: NOW,
        },
        None,
        &policy,
        &p,
        &mut ent,
    )
    .unwrap();
    assert_eq!(s.challenge.email.as_str(), "alice@example.com");
    assert_eq!(s.challenge.expires_at, NOW + 600);
    assert_eq!(s.challenge.max_attempts, 5);
    assert!(s.superseded.is_none());
    assert_eq!(s.audit.len(), 1);
    assert_eq!(s.audit[0].kind, AuditKind::ChallengeIssued);
    assert_eq!(s.code.as_str(), "123456");
    let msg = s.message("Acme");
    assert_eq!(msg.subject(), "123456 is your Acme code");
    assert!(msg.text_body().contains("123456"));
    assert!(msg.text_body().contains("10 minutes"));

    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123 456",
            now: NOW + 30,
        },
        Some(s.challenge.clone()),
        None,
        &p,
        &mut ent,
    );
    let v = r.outcome.unwrap();
    assert!(v.user_created);
    assert!(v.first_verification);
    assert_eq!(v.user.email_verified_at, Some(NOW + 30));
    assert_eq!(v.user.last_sign_in_at, Some(NOW + 30));
    assert_eq!(v.user.id.as_str(), "50505050-5050-4050-9050-505050505050");
    let ch = r.challenge.unwrap();
    assert_eq!(ch.attempts, 1);
    assert_eq!(ch.consumed_reason, Some(ConsumedReason::Verified));
    assert_eq!(ch.consumed_at, Some(NOW + 30));
    let kinds: Vec<_> = r.audit.iter().map(|a| a.kind).collect();
    assert_eq!(kinds, vec![AuditKind::CodeAccepted, AuditKind::UserCreated]);
    assert!(r.audit.iter().all(|a| a.user.as_ref() == Some(&v.user.id)));

    // Round 2: sign in to the existing account, a day later.
    let later = NOW + 86_400;
    let s2 = start(
        &StartRequest {
            tenant: &t,
            email: "ALICE@example.com",
            create_user: true,
            now: later,
        },
        Some(ch),
        &policy,
        &p,
        &mut ent,
    )
    .unwrap();
    assert!(
        s2.superseded.is_none(),
        "a consumed challenge is not superseded"
    );
    assert_eq!(s2.code.as_str(), "123457");
    let r2 = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123457",
            now: later + 5,
        },
        Some(s2.challenge),
        Some(v.user.clone()),
        &p,
        &mut ent,
    );
    let v2 = r2.outcome.unwrap();
    assert!(!v2.user_created);
    assert!(!v2.first_verification);
    assert_eq!(v2.user.id, v.user.id);
    assert_eq!(
        v2.user.email_verified_at,
        Some(NOW + 30),
        "first proof is kept"
    );
    assert_eq!(v2.user.last_sign_in_at, Some(later + 5));
    assert_eq!(r2.audit.len(), 1);
    assert_eq!(r2.audit[0].kind, AuditKind::CodeAccepted);
}

#[test]
fn wrong_codes_count_and_exhaust() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let s = start(
        &StartRequest {
            tenant: &t,
            email: "alice@example.com",
            create_user: true,
            now: NOW,
        },
        None,
        &Policy {
            max_attempts: 3,
            ..Policy::DEFAULT
        },
        &p,
        &mut ent,
    )
    .unwrap();
    let mut ch = Some(s.challenge);
    let req = |code: &'static str| VerifyRequest {
        tenant: &t,
        email: "alice@example.com",
        code,
        now: NOW + 1,
    };

    // Malformed input: refused, not counted.
    let r = verify(&req("12345"), ch.take(), None, &p, &mut ent);
    assert_eq!(r.outcome.unwrap_err().code(), "invalid_code");
    ch = r.challenge;
    assert_eq!(ch.as_ref().unwrap().attempts, 0);
    assert!(r.audit.is_empty());

    let r = verify(&req("000000"), ch.take(), None, &p, &mut ent);
    assert!(matches!(
        r.outcome.unwrap_err(),
        FlowError::WrongCode { attempts_left: 2 }
    ));
    assert_eq!(
        r.audit[0].kind,
        AuditKind::CodeRejected {
            reason: RejectReason::Wrong
        }
    );
    ch = r.challenge;
    assert_eq!(ch.as_ref().unwrap().attempts, 1);

    let r = verify(&req("000001"), ch.take(), None, &p, &mut ent);
    assert!(matches!(
        r.outcome.unwrap_err(),
        FlowError::WrongCode { attempts_left: 1 }
    ));
    ch = r.challenge;

    // Third wrong guess exhausts and consumes.
    let r = verify(&req("000002"), ch.take(), None, &p, &mut ent);
    let e = r.outcome.unwrap_err();
    assert!(matches!(e, FlowError::AttemptsExhausted));
    assert!(e.needs_new_code());
    assert_eq!(
        r.audit[0].kind,
        AuditKind::CodeRejected {
            reason: RejectReason::Exhausted
        }
    );
    ch = r.challenge;
    let c = ch.as_ref().unwrap();
    assert_eq!(c.attempts, 3);
    assert_eq!(c.consumed_reason, Some(ConsumedReason::Exhausted));

    // The right code is now useless: the challenge is consumed.
    let r = verify(&req("123456"), ch.take(), None, &p, &mut ent);
    assert!(matches!(r.outcome.unwrap_err(), FlowError::AlreadyConsumed));
    assert_eq!(
        r.audit[0].kind,
        AuditKind::CodeRejected {
            reason: RejectReason::Consumed
        }
    );
}

#[test]
fn right_code_consumes_so_it_cannot_be_replayed() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let s = start(
        &StartRequest {
            tenant: &t,
            email: "alice@example.com",
            create_user: true,
            now: NOW,
        },
        None,
        &Policy::DEFAULT,
        &p,
        &mut ent,
    )
    .unwrap();
    let req = VerifyRequest {
        tenant: &t,
        email: "alice@example.com",
        code: "123456",
        now: NOW + 1,
    };
    let r = verify(&req, Some(s.challenge), None, &p, &mut ent);
    let v = r.outcome.unwrap();
    let r2 = verify(&req, r.challenge, Some(v.user), &p, &mut ent);
    assert!(matches!(
        r2.outcome.unwrap_err(),
        FlowError::AlreadyConsumed
    ));
}

#[test]
fn expiry_is_exact() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let s = start(
        &StartRequest {
            tenant: &t,
            email: "alice@example.com",
            create_user: true,
            now: NOW,
        },
        None,
        &Policy::DEFAULT,
        &p,
        &mut ent,
    )
    .unwrap();
    let at = |now| VerifyRequest {
        tenant: &t,
        email: "alice@example.com",
        code: "123456",
        now,
    };
    // One second before expiry: fine.
    let r = verify(
        &at(NOW + 599),
        Some(s.challenge.clone()),
        None,
        &p,
        &mut ent,
    );
    assert!(r.outcome.is_ok());
    // At expiry: refused, no attempt counted.
    let r = verify(
        &at(NOW + 600),
        Some(s.challenge.clone()),
        None,
        &p,
        &mut ent,
    );
    assert!(matches!(r.outcome.unwrap_err(), FlowError::Expired));
    assert_eq!(r.challenge.unwrap().attempts, 0);
    assert_eq!(
        r.audit[0].kind,
        AuditKind::CodeRejected {
            reason: RejectReason::Expired
        }
    );
}

#[test]
fn no_challenge_is_a_clean_refusal() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123456",
            now: NOW,
        },
        None,
        None,
        &p,
        &mut ent,
    );
    assert!(matches!(r.outcome.unwrap_err(), FlowError::NoLiveChallenge));
    assert!(r.challenge.is_none());
    assert_eq!(
        r.audit[0].kind,
        AuditKind::CodeRejected {
            reason: RejectReason::Missing
        }
    );
}

#[test]
fn resend_cooldown_then_supersede() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let policy = Policy::DEFAULT;
    let req = |now| StartRequest {
        tenant: &t,
        email: "alice@example.com",
        create_user: true,
        now,
    };
    let s1 = start(&req(NOW), None, &policy, &p, &mut ent).unwrap();

    // Inside the cooldown: refused, nothing drawn.
    let before = ent.remaining();
    let e = start(
        &req(NOW + 59),
        Some(s1.challenge.clone()),
        &policy,
        &p,
        &mut ent,
    )
    .unwrap_err();
    assert!(matches!(
        e,
        FlowError::ResendTooSoon {
            retry_after_secs: 1
        }
    ));
    assert_eq!(ent.remaining(), before);

    // At the cooldown: the old challenge is superseded, the new one is live.
    let s2 = start(
        &req(NOW + 60),
        Some(s1.challenge.clone()),
        &policy,
        &p,
        &mut ent,
    )
    .unwrap();
    let old = s2.superseded.unwrap();
    assert_eq!(old.id, s1.challenge.id);
    assert_eq!(old.consumed_reason, Some(ConsumedReason::Superseded));
    assert_eq!(old.consumed_at, Some(NOW + 60));
    assert_ne!(s2.challenge.id, s1.challenge.id);
    // The new code verifies against the new challenge only.
    let new_code = Code::parse(s2.code.as_str()).unwrap();
    assert!(s2.challenge.code_mac.verify(
        &p,
        &t,
        &s2.challenge.email_idx,
        &s2.challenge.id,
        &new_code
    ));
    assert!(!s1.challenge.code_mac.verify(
        &p,
        &t,
        &s1.challenge.email_idx,
        &s1.challenge.id,
        &new_code
    ));
    let kinds: Vec<_> = s2.audit.iter().map(|a| a.kind).collect();
    assert_eq!(
        kinds,
        vec![AuditKind::ChallengeSuperseded, AuditKind::ChallengeIssued]
    );

    // The old code no longer verifies against the old (superseded) record…
    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123456",
            now: NOW + 61,
        },
        Some(old),
        None,
        &p,
        &mut ent,
    );
    assert!(matches!(r.outcome.unwrap_err(), FlowError::AlreadyConsumed));
    // …nor against the new one (the MAC is bound to the challenge id).
    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123456",
            now: NOW + 61,
        },
        Some(s2.challenge.clone()),
        None,
        &p,
        &mut ent,
    );
    assert!(matches!(
        r.outcome.unwrap_err(),
        FlowError::WrongCode { .. }
    ));

    // An expired live record is simply ignored on start.
    let s3 = start(
        &req(NOW + 60 + 600),
        Some(s2.challenge),
        &policy,
        &p,
        &mut ent,
    )
    .unwrap();
    assert!(s3.superseded.is_none());
}

#[test]
fn sign_in_only_refuses_unknown_user_after_a_correct_code() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let s = start(
        &StartRequest {
            tenant: &t,
            email: "alice@example.com",
            create_user: false,
            now: NOW,
        },
        None,
        &Policy::DEFAULT,
        &p,
        &mut ent,
    )
    .unwrap();
    // Start looks identical to the sign-up case: a code is issued either way.
    assert_eq!(s.code.as_str(), "123456");
    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123456",
            now: NOW + 1,
        },
        Some(s.challenge),
        None,
        &p,
        &mut ent,
    );
    assert!(matches!(r.outcome.unwrap_err(), FlowError::UnknownUser));
    // The correct code was spent regardless.
    let ch = r.challenge.unwrap();
    assert_eq!(ch.consumed_reason, Some(ConsumedReason::Verified));
    assert_eq!(
        r.audit[0].kind,
        AuditKind::CodeRejected {
            reason: RejectReason::UnknownUser
        }
    );
}

#[test]
fn store_handing_over_the_wrong_rows_is_caught() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let s = start(
        &StartRequest {
            tenant: &t,
            email: "alice@example.com",
            create_user: true,
            now: NOW,
        },
        None,
        &Policy::DEFAULT,
        &p,
        &mut ent,
    )
    .unwrap();
    // Bob's verify handed Alice's challenge.
    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "bob@example.com",
            code: "123456",
            now: NOW + 1,
        },
        Some(s.challenge.clone()),
        None,
        &p,
        &mut ent,
    );
    let e = r.outcome.unwrap_err();
    assert!(matches!(e, FlowError::ChallengeMismatch));
    assert!(e.is_internal());
    assert_eq!(r.challenge.unwrap().attempts, 0, "nothing counted");

    // Alice's start handed Bob's live challenge.
    let e = start(
        &StartRequest {
            tenant: &t,
            email: "bob@example.com",
            create_user: true,
            now: NOW + 1,
        },
        Some(s.challenge.clone()),
        &Policy::DEFAULT,
        &p,
        &mut ent,
    )
    .unwrap_err();
    assert!(matches!(e, FlowError::ChallengeMismatch));

    // Alice's verify handed Bob's user.
    let bob = NormalizedEmail::parse("bob@example.com").unwrap();
    let bob_user = User {
        id: UserId::from_random_bytes([2; 16]),
        tenant: t.clone(),
        email: bob.clone(),
        email_idx: EmailIndex::derive(&p, &t, &bob),
        email_verified_at: Some(NOW),
        created_at: NOW,
        last_sign_in_at: None,
        linked_did: None,
        username: None,
        metadata: Default::default(),
    };
    let r = verify(
        &VerifyRequest {
            tenant: &t,
            email: "alice@example.com",
            code: "123456",
            now: NOW + 1,
        },
        Some(s.challenge),
        Some(bob_user),
        &p,
        &mut ent,
    );
    assert!(matches!(r.outcome.unwrap_err(), FlowError::UserMismatch));
}

#[test]
fn stub_mailer_records_messages() {
    let p = pepper();
    let t = tenant();
    let mut ent = entropy();
    let s = start(
        &StartRequest {
            tenant: &t,
            email: "alice@example.com",
            create_user: true,
            now: NOW,
        },
        None,
        &Policy::DEFAULT,
        &p,
        &mut ent,
    )
    .unwrap();
    let mailer = StubMailer::new();
    let mut fut = mailer.send_code(s.message("Acme"));
    // The stub completes immediately; poll it once.
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(r) => r.unwrap(),
        std::task::Poll::Pending => panic!("stub mailer should be ready"),
    }
    assert_eq!(mailer.len(), 1);
    let sent = mailer.take();
    assert_eq!(sent[0].to.as_str(), "alice@example.com");
    assert_eq!(sent[0].code.as_str(), "123456");
    assert!(mailer.is_empty());
}

// ─── attestation ─────────────────────────────────────────────────────────────

fn verified_user() -> User {
    let p = pepper();
    let e = NormalizedEmail::parse("alice@example.com").unwrap();
    User {
        id: UserId::from_random_bytes([0x5A; 16]),
        tenant: tenant(),
        email: e.clone(),
        email_idx: EmailIndex::derive(&p, &tenant(), &e),
        email_verified_at: Some(NOW),
        created_at: NOW,
        last_sign_in_at: Some(NOW),
        linked_did: None,
        username: None,
        metadata: Default::default(),
    }
}

#[test]
fn attestation_round_trips_offline() {
    let key = make_signing_key("signup-service");
    let did = did_from_pubkey(key.verifying_key());
    let multibase = multibase_from_pubkey(key.verifying_key());
    let signer = InMemoryDeviceSigner::new("signupd-1", key);

    let claims = AttestationClaims::for_user(&verified_user()).unwrap();
    let token = sign_attestation_single_device(
        &did,
        &multibase,
        "signupd-1",
        &claims,
        &signer,
        NOW + 10,
        300,
    )
    .unwrap();

    let t = tenant();
    let v = verify_attestation(
        &token,
        &AttestationPolicy {
            expected_issuer: Some(&did),
            expected_tenant: Some(&t),
            now_unix_secs: NOW + 20,
            max_iat_skew_secs: 60,
        },
    )
    .unwrap();
    assert_eq!(v.issuer, did);
    assert_eq!(v.claims, claims);
    assert_eq!(v.iat, NOW + 10);
    assert_eq!(v.exp, NOW + 310);

    // Pinned issuer / tenant / expiry are enforced.
    let other_key = make_signing_key("impostor");
    let other_did = did_from_pubkey(other_key.verifying_key());
    let e = verify_attestation(
        &token,
        &AttestationPolicy {
            expected_issuer: Some(&other_did),
            now_unix_secs: NOW + 20,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, AttestError::IssuerMismatch { .. }));
    let other_t = TenantId::parse("other").unwrap();
    let e = verify_attestation(
        &token,
        &AttestationPolicy {
            expected_tenant: Some(&other_t),
            now_unix_secs: NOW + 20,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, AttestError::TenantMismatch { .. }));
    let e = verify_attestation(
        &token,
        &AttestationPolicy {
            now_unix_secs: NOW + 310,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        e,
        AttestError::Statement(mata_sign::VerifyError::Expired { .. })
    ));

    // An unverified user cannot be attested.
    let mut unverified = verified_user();
    unverified.email_verified_at = None;
    assert_eq!(
        AttestationClaims::for_user(&unverified).unwrap_err().code(),
        "not_verified"
    );
}

#[test]
fn attestation_rejects_a_plain_statement_and_a_tampered_preview() {
    let key = make_signing_key("signup-service");
    let did = did_from_pubkey(key.verifying_key());
    let multibase = multibase_from_pubkey(key.verifying_key());
    let signer = InMemoryDeviceSigner::new("signupd-1", key);
    let claims = AttestationClaims::for_user(&verified_user()).unwrap();
    let json = claims.canonical_json();

    // A document signature with the wrong context is not an attestation.
    let plain = mata_sign::sign_single_device(
        &did,
        &multibase,
        "signupd-1",
        &mata_sign::StatementInput {
            content: mata_sign::Content::Bytes(json.as_bytes()),
            content_type: "application/json".into(),
            context: Some("mata-doc".into()),
            nonce: None,
            exp: Some(NOW + 300),
            preview: Some(json.clone()),
            platform_binding: None,
        },
        &signer,
        NOW,
    )
    .unwrap();
    let e = verify_attestation(
        &plain,
        &AttestationPolicy {
            now_unix_secs: NOW + 1,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        e,
        AttestError::Statement(mata_sign::VerifyError::ContextMismatch { .. })
    ));

    // Right context, right hash, but no expiry: refused.
    let no_exp = mata_sign::sign_single_device(
        &did,
        &multibase,
        "signupd-1",
        &mata_sign::StatementInput {
            content: mata_sign::Content::Bytes(json.as_bytes()),
            content_type: crate::attest::ATTESTATION_CONTENT_TYPE.into(),
            context: Some(ATTESTATION_CONTEXT.into()),
            nonce: None,
            exp: None,
            preview: Some(json.clone()),
            platform_binding: None,
        },
        &signer,
        NOW,
    )
    .unwrap();
    let e = verify_attestation(
        &no_exp,
        &AttestationPolicy {
            now_unix_secs: NOW + 1,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, AttestError::NoExpiry));

    // Claims inlined that do not hash to the signed content: refused.
    let mut forged = claims.clone();
    forged.user_id = UserId::from_random_bytes([0xEE; 16]);
    let forged_json = forged.canonical_json();
    let tampered = mata_sign::sign_single_device(
        &did,
        &multibase,
        "signupd-1",
        &mata_sign::StatementInput {
            content: mata_sign::Content::Bytes(json.as_bytes()),
            content_type: crate::attest::ATTESTATION_CONTENT_TYPE.into(),
            context: Some(ATTESTATION_CONTEXT.into()),
            nonce: None,
            exp: Some(NOW + 300),
            preview: Some(forged_json),
            platform_binding: None,
        },
        &signer,
        NOW,
    )
    .unwrap();
    let e = verify_attestation(
        &tampered,
        &AttestationPolicy {
            now_unix_secs: NOW + 1,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(matches!(e, AttestError::ContentMismatch));
}
