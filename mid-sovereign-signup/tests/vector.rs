//! Test vector `tests/vector_v1.json`: pins the wire-relevant derivations so
//! a port (another language, a future refactor) can prove it computes the
//! same bytes.
//!
//! Pinned: the email normalization, the `EmailIndex` for a known pepper and
//! tenant, the `CodeMac` for a known challenge id and code, the user id
//! minted from known random bytes, and the attestation claims' canonical
//! JSON + SHA-256 content hash. Signature bytes are **not** pinned (an
//! implementation may use any valid ECDSA nonce scheme); the round trip is
//! covered by the unit tests.
//!
//! Regenerate with `cargo test -p mid-sovereign-signup --test vector -- --ignored print_vector --nocapture`
//! and review the diff: a change here is a wire change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mid_sovereign_signup::attest::AttestationClaims;
use mid_sovereign_signup::flow::{start, verify, StartRequest, VerifyRequest};
use mid_sovereign_signup::{
    ChallengeId, Code, CodeMac, EmailIndex, FixedEntropy, NormalizedEmail, Pepper, Policy,
    TenantId, UserId,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Vector {
    v: u32,
    pepper_b64u: String,
    tenant: String,
    email_raw: String,
    email: String,
    email_idx_b64u: String,
    challenge_id_b64u: String,
    code: String,
    code_mac_b64u: String,
    now: u64,
    user_random_b64u: String,
    user_id: String,
    claims_json: String,
    claims_sha256_b64u: String,
}

const NOW: u64 = 1_759_190_400;

fn fixed_pepper() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8 + 1;
    }
    b
}

/// Compute the vector from first principles, through the public API.
fn compute() -> Vector {
    let pepper_bytes = fixed_pepper();
    let pepper = Pepper::from_bytes(pepper_bytes);
    let tenant = TenantId::parse("acme").unwrap();
    let email_raw = "  Alice.Smith@Example.COM ".to_string();
    let email = NormalizedEmail::parse(&email_raw).unwrap();
    let email_idx = EmailIndex::derive(&pepper, &tenant, &email);

    // The flow draws: 16 bytes challenge id, 4 bytes code, then (on verify)
    // 16 bytes user id. Pin the draw order through the flow itself.
    let challenge_random = [0xA5u8; 16];
    let code_random = [0x00u8, 0x01, 0xE2, 0x40]; // 123456
    let user_random = [0x5Au8; 16];
    let mut bytes = Vec::new();
    bytes.extend(challenge_random);
    bytes.extend(code_random);
    bytes.extend(user_random);
    let mut entropy = FixedEntropy::new(bytes);

    let s = start(
        &StartRequest {
            tenant: &tenant,
            email: &email_raw,
            create_user: true,
            now: NOW,
        },
        None,
        &Policy::DEFAULT,
        &pepper,
        &mut entropy,
    )
    .unwrap();
    assert_eq!(s.challenge.id, ChallengeId::from_bytes(challenge_random));
    assert_eq!(s.challenge.email, email);
    assert_eq!(s.challenge.email_idx, email_idx);

    // The MAC is reproducible from its inputs alone.
    let direct = CodeMac::commit(&pepper, &tenant, &email_idx, &s.challenge.id, &s.code);
    assert_eq!(direct.to_base64url(), s.challenge.code_mac.to_base64url());
    assert!(s.challenge.code_mac.verify(
        &pepper,
        &tenant,
        &email_idx,
        &s.challenge.id,
        &Code::parse(s.code.as_str()).unwrap()
    ));

    let r = verify(
        &VerifyRequest {
            tenant: &tenant,
            email: &email_raw,
            code: s.code.as_str(),
            now: NOW + 30,
        },
        Some(s.challenge.clone()),
        None,
        &pepper,
        &mut entropy,
    );
    let v = r.outcome.unwrap();
    assert_eq!(v.user.id, UserId::from_random_bytes(user_random));
    assert_eq!(
        entropy.remaining(),
        0,
        "the flow drew exactly the pinned bytes"
    );

    let claims = AttestationClaims::for_user(&v.user).unwrap();
    let claims_json = claims.canonical_json();
    let digest: [u8; 32] = Sha256::digest(claims_json.as_bytes()).into();

    Vector {
        v: 1,
        pepper_b64u: URL_SAFE_NO_PAD.encode(pepper_bytes),
        tenant: tenant.to_string(),
        email_raw,
        email: email.to_string(),
        email_idx_b64u: email_idx.to_base64url(),
        challenge_id_b64u: s.challenge.id.to_base64url(),
        code: s.code.as_str().to_string(),
        code_mac_b64u: s.challenge.code_mac.to_base64url(),
        now: NOW,
        user_random_b64u: URL_SAFE_NO_PAD.encode(user_random),
        user_id: v.user.id.to_string(),
        claims_json,
        claims_sha256_b64u: URL_SAFE_NO_PAD.encode(digest),
    }
}

fn load() -> Vector {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vector_v1.json");
    let text = std::fs::read_to_string(path).expect("tests/vector_v1.json present");
    serde_json::from_str(&text).expect("vector parses")
}

#[test]
fn vector_v1_matches() {
    let computed = compute();
    let pinned = load();
    assert_eq!(
        computed,
        pinned,
        "\n\ncomputed vector differs from tests/vector_v1.json — a WIRE change.\n\
         Computed:\n{}\n",
        serde_json::to_string_pretty(&computed).unwrap()
    );
}

/// `cargo test -p mid-sovereign-signup --test vector -- --ignored print_vector --nocapture`
#[test]
#[ignore]
fn print_vector() {
    println!("{}", serde_json::to_string_pretty(&compute()).unwrap());
}
