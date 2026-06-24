//! End-to-end tests for [`kms_verifier::Verifier`].
//!
//! These tests use real ECDSA P-256 keypairs and the in-memory [`NonceStore`] /
//! [`DidResolver`] impls. They cover every assumed-adversary scenario from
//! [docs/kms/threat_model.md](../../../docs/kms/threat_model.md):
//!
//! - happy path
//! - audience binding (A3 — captured assertion can't be redirected)
//! - replay defense (A3 — captured assertion can't be reused)
//! - tamper detection (A3 — embedded envelope must equal stored envelope)
//! - device revocation (A2 — stolen key stops working once removed from roster)
//! - expired nonce (defends against capture-and-wait)
//! - unknown DID (no DID-existence oracle: same error class as the rest)
//! - wrong purpose / wrong audience / wrong issuer

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kms_verifier::{
    Clock, DidDocumentV2, InMemoryDidResolver, InMemoryNonceStore, NonceEnvelope, NonceGenerator,
    RosterEntry, RosterUpdate, SignedAssertion, Verifier, VerifyError,
};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;

// ── Test fixtures ───────────────────────────────────────────────────────────

const ISSUER: &str = "kms-banking-proxy";
const AUDIENCE: &str = "kms-banking";
const PURPOSE: &str = "get_accounts";
const TEST_DID: &str = "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXY";

/// Manual clock that the test advances explicitly. Default starts at 1_700_000_000.
struct FakeClock {
    now: AtomicU64,
}

impl FakeClock {
    fn new(start: u64) -> Arc<Self> {
        Arc::new(Self {
            now: AtomicU64::new(start),
        })
    }
    fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Deterministic-but-varying nonce generator. Each call returns
/// [counter:8][zeros:24]. Test code only relies on uniqueness, not entropy.
struct CountingNonceGen {
    counter: AtomicU64,
}

impl CountingNonceGen {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicU64::new(0),
        })
    }
}

impl NonceGenerator for CountingNonceGen {
    fn random_32(&self) -> [u8; 32] {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out
    }
}

struct Harness {
    verifier: Verifier,
    resolver: Arc<InMemoryDidResolver>,
    clock: Arc<FakeClock>,
    device_id: String,
    signing_key: SigningKey,
}

async fn make_harness() -> Harness {
    make_harness_with_purposes([PURPOSE.to_string()]).await
}

async fn make_harness_with_purposes(
    purposes: impl IntoIterator<Item = String>,
) -> Harness {
    let resolver = Arc::new(InMemoryDidResolver::new());
    let store = Arc::new(InMemoryNonceStore::new());
    let clock = FakeClock::new(1_700_000_000);
    let rng = CountingNonceGen::new();

    let signing_key = SigningKey::random(&mut OsRng);
    let device_id = "dev-laptop".to_string();
    let entry = RosterEntry {
        device_id: device_id.clone(),
        // SEC1 uncompressed: 0x04 || x[32] || y[32] = 65 bytes.
        pubkey: signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
        added_at: 1_699_000_000,
        label: "Test laptop".into(),
    };
    resolver
        .upsert(DidDocumentV2 {
            did: TEST_DID.into(),
            roster_version: 1,
            roster: vec![entry],
            updated_at: 1_699_000_000,
        })
        .await;

    let verifier = Verifier::new(
        ISSUER,
        AUDIENCE,
        purposes,
        store.clone(),
        resolver.clone(),
    )
    .with_clock(clock.clone())
    .with_nonce_generator(rng.clone());

    Harness {
        verifier,
        resolver,
        clock,
        device_id,
        signing_key,
    }
}

fn sign(envelope: &NonceEnvelope, key: &SigningKey, device_id: &str) -> SignedAssertion {
    // Prehash signing: canonical_bytes() is already a SHA-256 digest, so we
    // use sign_prehash directly rather than letting ECDSA hash the input.
    // The p256 crate's sign_prehash uses RFC 6979 deterministic ECDSA but
    // does NOT normalize `s` to the low form by default — we must do it
    // explicitly here so the signature matches the canonical form the
    // verifier requires. (kms-client does the same in production.)
    let canonical = envelope.canonical_bytes();
    let raw: Signature = key.sign_prehash(&canonical).expect("sign_prehash");
    let normalized = raw.normalize_s().unwrap_or(raw);
    SignedAssertion {
        envelope_version: SignedAssertion::CURRENT_VERSION,
        envelope_type: SignedAssertion::TYPE.into(),
        nonce_envelope: envelope.clone(),
        device_id: device_id.into(),
        signature: normalized.to_bytes().to_vec(),
    }
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn happy_path_issue_then_verify() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    let verified = h.verifier.verify(&assertion, PURPOSE).await.unwrap();
    assert_eq!(verified.did, TEST_DID);
    assert_eq!(verified.device_id, h.device_id);
    assert_eq!(verified.purpose, PURPOSE);
    assert_eq!(verified.roster_version, 1);
}

#[tokio::test]
async fn issued_nonce_has_correct_audience_and_issuer() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    assert_eq!(nonce.audience, AUDIENCE);
    assert_eq!(nonce.issuer, ISSUER);
    assert_eq!(nonce.purpose, PURPOSE);
    assert_eq!(nonce.did, TEST_DID);
}

// ── Issuance failure modes ──────────────────────────────────────────────────

#[tokio::test]
async fn issue_rejects_malformed_did() {
    let h = make_harness().await;
    let err = h.verifier.issue_nonce("not-a-did", PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::MalformedDid);
}

#[tokio::test]
async fn issue_rejects_unknown_purpose() {
    let h = make_harness().await;
    let err = h
        .verifier
        .issue_nonce(TEST_DID, "admin_override")
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::UnknownPurpose);
}

// ── Replay defense ──────────────────────────────────────────────────────────

#[tokio::test]
async fn replay_of_consumed_nonce_fails() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    h.verifier.verify(&assertion, PURPOSE).await.unwrap();

    // Second call with the same assertion: nonce is gone.
    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::NonceNotFound);
}

// ── Audience binding ────────────────────────────────────────────────────────

#[tokio::test]
async fn assertion_for_different_audience_fails() {
    // Two verifiers sharing the same DID resolver but configured for different
    // audiences. A nonce minted by the banking verifier, signed by the user,
    // must not validate at the OIDC verifier — even though the signature
    // verifies and the DID resolves.
    let resolver = Arc::new(InMemoryDidResolver::new());
    let banking_store = Arc::new(InMemoryNonceStore::new());
    let oidc_store = Arc::new(InMemoryNonceStore::new());
    let clock = FakeClock::new(1_700_000_000);

    let signing_key = SigningKey::random(&mut OsRng);
    let device_id = "dev-laptop";
    resolver
        .upsert(DidDocumentV2 {
            did: TEST_DID.into(),
            roster_version: 1,
            roster: vec![RosterEntry {
                device_id: device_id.into(),
                pubkey: signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
                added_at: 1_699_000_000,
                label: "Test".into(),
            }],
            updated_at: 1_699_000_000,
        })
        .await;

    let banking_verifier = Verifier::new(
        "kms-banking-proxy",
        "kms-banking",
        ["get_accounts".to_string()],
        banking_store,
        resolver.clone(),
    )
    .with_clock(clock.clone())
    .with_nonce_generator(CountingNonceGen::new());

    let oidc_verifier = Verifier::new(
        "kms-oidc-adapter",
        "kms-oidc",
        ["sign_in".to_string()],
        oidc_store,
        resolver.clone(),
    )
    .with_clock(clock.clone())
    .with_nonce_generator(CountingNonceGen::new());

    let banking_nonce = banking_verifier
        .issue_nonce(TEST_DID, "get_accounts")
        .await
        .unwrap();
    let assertion = sign(&banking_nonce, &signing_key, device_id);

    // The OIDC verifier sees a signed assertion with audience="kms-banking".
    // Its allow-list is configured for "kms-oidc" only.
    let err = oidc_verifier.verify(&assertion, "sign_in").await.unwrap_err();
    assert_eq!(err, VerifyError::AudienceMismatch);
}

#[tokio::test]
async fn assertion_for_different_issuer_fails() {
    // Same audience, different issuer ID. The verifier rejects.
    let h = make_harness().await;
    let mut nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    nonce.issuer = "different-issuer".into();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::IssuerMismatch);
}

#[tokio::test]
async fn assertion_for_different_purpose_fails() {
    let h = make_harness_with_purposes([
        "get_accounts".into(),
        "get_transactions".into(),
    ])
    .await;
    let nonce = h.verifier.issue_nonce(TEST_DID, "get_accounts").await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    // Endpoint expected get_transactions; assertion is for get_accounts.
    let err = h
        .verifier
        .verify(&assertion, "get_transactions")
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::PurposeMismatch);
}

// ── Tamper detection ────────────────────────────────────────────────────────

#[tokio::test]
async fn tampered_envelope_with_valid_signature_fails() {
    // Privilege-escalation attempt: client receives a nonce for
    // purpose="get_accounts", then signs a forged envelope with the same
    // random bytes but purpose="exchange_public_token". The signature
    // verifies (the client re-signed the tampered bytes), but the stored
    // envelope says get_accounts.
    let h = make_harness_with_purposes([
        "get_accounts".into(),
        "exchange_public_token".into(),
    ])
    .await;
    let issued = h.verifier.issue_nonce(TEST_DID, "get_accounts").await.unwrap();

    let mut tampered = issued.clone();
    tampered.purpose = "exchange_public_token".into();
    let assertion = sign(&tampered, &h.signing_key, &h.device_id);

    // The endpoint expects exchange_public_token (matching the tampered
    // envelope), so the purpose-match check passes. The signature verifies
    // against the tampered canonical bytes. The store comparison catches it.
    let err = h
        .verifier
        .verify(&assertion, "exchange_public_token")
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::MalformedEnvelope);
}

// ── Signature failure modes ─────────────────────────────────────────────────

#[tokio::test]
async fn wrong_key_signature_fails() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();

    // Attacker signs with their own key, claims to be `dev-laptop`.
    let attacker_key = SigningKey::random(&mut OsRng);
    let assertion = sign(&nonce, &attacker_key, &h.device_id);

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

#[tokio::test]
async fn corrupted_signature_fails() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let mut assertion = sign(&nonce, &h.signing_key, &h.device_id);
    assertion.signature[0] ^= 0xFF;

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

#[tokio::test]
async fn nonce_not_consumed_on_signature_failure() {
    // Defensive property: a corrupted-network-packet failure should NOT
    // burn the user's nonce. They can retry with a corrected packet.
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let mut bad = sign(&nonce, &h.signing_key, &h.device_id);
    bad.signature.fill(0);

    let _ = h.verifier.verify(&bad, PURPOSE).await.unwrap_err();

    // Now retry with a correct signature. Should succeed.
    let good = sign(&nonce, &h.signing_key, &h.device_id);
    h.verifier.verify(&good, PURPOSE).await.unwrap();
}

// ── Roster checks (A2 — compromised device containment) ────────────────────

#[tokio::test]
async fn device_not_in_roster_fails() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let mut assertion = sign(&nonce, &h.signing_key, &h.device_id);
    assertion.device_id = "dev-not-in-roster".into();

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::DeviceNotInRoster);
}

#[tokio::test]
async fn revoked_device_cannot_sign_after_revocation() {
    // A2: device was on the roster, signed a nonce, then was revoked.
    // The captured assertion must not validate after revocation.
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    // Revoke the device by replacing the roster with a different one.
    let other_key = SigningKey::random(&mut OsRng);
    h.resolver
        .upsert(DidDocumentV2 {
            did: TEST_DID.into(),
            roster_version: 2,
            roster: vec![RosterEntry {
                device_id: "dev-phone".into(),
                pubkey: other_key
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .to_vec(),
                added_at: 1_699_500_000,
                label: "Phone".into(),
            }],
            updated_at: 1_700_000_500,
        })
        .await;

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::DeviceNotInRoster);
}

// ── Time-bound checks ──────────────────────────────────────────────────────

#[tokio::test]
async fn expired_nonce_fails() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    // Advance well past the default 30s TTL.
    h.clock.advance(60);

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::NonceExpired);
}

#[tokio::test]
async fn nonce_just_before_expiry_succeeds() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    // Push clock to exactly `expires_at` — still valid (the consume check is
    // `expires_at < now`, so equality passes).
    let elapsed = nonce.expires_at - nonce.issued_at;
    h.clock.advance(elapsed);

    h.verifier.verify(&assertion, PURPOSE).await.unwrap();
}

// ── DID resolution failure modes ───────────────────────────────────────────

#[tokio::test]
async fn unknown_did_fails() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign(&nonce, &h.signing_key, &h.device_id);

    // Wipe the DID from the resolver between issuance and verify.
    h.resolver.remove(TEST_DID).await;

    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::DidNotFound);
}

// ── Property: every issued nonce is single-use ─────────────────────────────

#[tokio::test]
async fn many_issued_nonces_each_single_use() {
    let h = make_harness().await;
    let mut assertions = Vec::new();
    for _ in 0..16 {
        let n = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
        assertions.push(sign(&n, &h.signing_key, &h.device_id));
    }
    for a in &assertions {
        h.verifier.verify(a, PURPOSE).await.unwrap();
    }
    for a in &assertions {
        let err = h.verifier.verify(a, PURPOSE).await.unwrap_err();
        assert_eq!(err, VerifyError::NonceNotFound);
    }
}

// ── ECDSA malleability defense ─────────────────────────────────────────────

#[tokio::test]
async fn high_s_signature_is_rejected() {
    // ECDSA malleability: for any valid (r, s), (r, n - s) is also valid.
    // The verifier MUST reject the high-s form to kill this attack vector.
    // We construct both forms from the same signing operation and confirm
    // the verifier accepts the canonical (low-s) form and rejects the
    // malleated (high-s) form.
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();

    let canonical = nonce.canonical_bytes();
    let raw: Signature = h
        .signing_key
        .sign_prehash(&canonical)
        .expect("sign_prehash");
    let low_s = raw.normalize_s().unwrap_or(raw);
    let high_s = {
        // Construct the malleated counterpart: flip s -> -s mod n by
        // re-constructing from (r, -s). The simplest path: if low_s differs
        // from raw, raw is the high form; otherwise we need to manually
        // build the high form via (r, -s).
        use p256::ecdsa::Signature as P256Signature;
        let r = low_s.r();
        let s = low_s.s();
        let neg_s = -s;
        P256Signature::from_scalars(r, neg_s).expect("from_scalars")
    };

    // Sanity: low and high differ in their s bytes.
    assert_ne!(low_s.to_bytes(), high_s.to_bytes());

    // Build a signed assertion with the high-s form and confirm the verifier
    // rejects it.
    let assertion = SignedAssertion {
        envelope_version: SignedAssertion::CURRENT_VERSION,
        envelope_type: SignedAssertion::TYPE.into(),
        nonce_envelope: nonce,
        device_id: h.device_id.clone(),
        signature: high_s.to_bytes().to_vec(),
    };
    let err = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

// ── Property: shape errors short-circuit before any state mutation ─────────

#[tokio::test]
async fn shape_invalid_assertion_does_not_consume_anything() {
    let h = make_harness().await;
    let nonce = h.verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let mut assertion = sign(&nonce, &h.signing_key, &h.device_id);

    // Break shape: empty device_id.
    assertion.device_id = String::new();

    let _ = h.verifier.verify(&assertion, PURPOSE).await.unwrap_err();

    // The valid signed copy should still verify cleanly.
    let good = sign(&nonce, &h.signing_key, &h.device_id);
    h.verifier.verify(&good, PURPOSE).await.unwrap();
}

// ── RosterUpdate verification ──────────────────────────────────────────────

/// Builds a `RosterUpdate` signed by `key` against the harness's current
/// roster (laptop entry only). `new_roster` is what the update tries to
/// install. Returns the canonical low-s signed envelope.
fn sign_roster_update(
    key: &SigningKey,
    signer_device_id: &str,
    did: &str,
    prior_version: u64,
    new_roster: Vec<RosterEntry>,
    signed_at: u64,
) -> RosterUpdate {
    let mut update = RosterUpdate {
        envelope_version: RosterUpdate::CURRENT_VERSION,
        envelope_type: RosterUpdate::TYPE.into(),
        did: did.into(),
        prior_version,
        new_version: prior_version + 1,
        new_roster,
        signed_at,
        signer_device_id: signer_device_id.into(),
        signature: vec![0u8; RosterUpdate::SIGNATURE_LEN],
    };
    let canonical = update.canonical_bytes();
    let raw: Signature = key.sign_prehash(&canonical).expect("sign_prehash");
    let normalized = raw.normalize_s().unwrap_or(raw);
    update.signature = normalized.to_bytes().to_vec();
    update
}

/// Construct a fresh `RosterEntry` for `device_id` with the given key's pubkey.
fn entry_for(device_id: &str, key: &SigningKey, added_at: u64, label: &str) -> RosterEntry {
    RosterEntry {
        device_id: device_id.into(),
        pubkey: key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        added_at,
        label: label.into(),
    }
}

/// Happy path: web (in the bootstrap roster) signs a RosterUpdate adding
/// desktop's M5 pubkey. Verifier accepts, returns the new version + the
/// signer device_id for the audit log.
#[tokio::test]
async fn roster_update_happy_path_adds_second_device() {
    let h = make_harness().await;
    let now = h.clock.now_secs();

    let desktop_key = SigningKey::random(&mut OsRng);
    let new_roster = vec![
        entry_for(&h.device_id, &h.signing_key, 1_699_000_000, "Test laptop"),
        entry_for("dev-desktop", &desktop_key, now, "MacBook"),
    ];
    let update = sign_roster_update(
        &h.signing_key,
        &h.device_id,
        TEST_DID,
        1,
        new_roster,
        now,
    );

    let verified = h.verifier.verify_roster_update(&update).await.unwrap();
    assert_eq!(verified.did, TEST_DID);
    assert_eq!(verified.signer_device_id, h.device_id);
    assert_eq!(verified.new_roster_version, 2);
}

/// Stale prior_version (someone else updated the roster first). Verifier
/// must reject without burning state — caller re-resolves + retries.
#[tokio::test]
async fn roster_update_stale_prior_version_rejected() {
    let h = make_harness().await;
    let now = h.clock.now_secs();

    // Harness boots with roster_version=1. Sign an update that claims
    // prior_version=2 — mismatched.
    let other_key = SigningKey::random(&mut OsRng);
    let new_roster = vec![
        entry_for(&h.device_id, &h.signing_key, 1_699_000_000, "Test laptop"),
        entry_for("dev-other", &other_key, now, "Other"),
    ];
    let update = sign_roster_update(
        &h.signing_key,
        &h.device_id,
        TEST_DID,
        2,
        new_roster,
        now,
    );

    let err = h.verifier.verify_roster_update(&update).await.unwrap_err();
    assert_eq!(err, VerifyError::StaleRosterVersion);
}

/// Signer device must be in the PRIOR roster. A device that's not in the
/// roster trying to add itself (or anyone else) is rejected.
#[tokio::test]
async fn roster_update_signer_not_in_prior_roster_rejected() {
    let h = make_harness().await;
    let now = h.clock.now_secs();

    // Build an update signed by a desktop key that ISN'T in the prior
    // roster — desktop tries to add itself without a sibling's blessing.
    let desktop_key = SigningKey::random(&mut OsRng);
    let new_roster = vec![
        entry_for(&h.device_id, &h.signing_key, 1_699_000_000, "Test laptop"),
        entry_for("dev-desktop", &desktop_key, now, "MacBook"),
    ];
    let update = sign_roster_update(
        &desktop_key,
        "dev-desktop",
        TEST_DID,
        1,
        new_roster,
        now,
    );

    let err = h.verifier.verify_roster_update(&update).await.unwrap_err();
    assert_eq!(err, VerifyError::DeviceNotInRoster);
}

/// Signature tampered (forged with a different key but claiming the
/// signer is the legitimate laptop). Verifier rejects under the
/// laptop's prior-roster pubkey.
#[tokio::test]
async fn roster_update_bad_signature_rejected() {
    let h = make_harness().await;
    let now = h.clock.now_secs();

    let attacker_key = SigningKey::random(&mut OsRng);
    let desktop_key = SigningKey::random(&mut OsRng);
    let new_roster = vec![
        entry_for(&h.device_id, &h.signing_key, 1_699_000_000, "Test laptop"),
        entry_for("dev-evil", &desktop_key, now, "Evil"),
    ];
    // Sign with attacker_key but claim signer_device_id is the legitimate
    // laptop. Verifier looks up the laptop's pubkey, signature won't verify.
    let update = sign_roster_update(
        &attacker_key,
        &h.device_id,
        TEST_DID,
        1,
        new_roster,
        now,
    );

    let err = h.verifier.verify_roster_update(&update).await.unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

/// `signed_at` outside the ±300s tolerance window. Defense against
/// long-tail-replay (e.g., a signed update captured and held for hours).
#[tokio::test]
async fn roster_update_signed_at_outside_window_rejected() {
    let h = make_harness().await;
    let now = h.clock.now_secs();

    let desktop_key = SigningKey::random(&mut OsRng);
    let new_roster = vec![
        entry_for(&h.device_id, &h.signing_key, 1_699_000_000, "Test laptop"),
        entry_for("dev-desktop", &desktop_key, now, "MacBook"),
    ];
    // Stamp 10 minutes in the past — well past the ±300s window.
    let update = sign_roster_update(
        &h.signing_key,
        &h.device_id,
        TEST_DID,
        1,
        new_roster,
        now - 600,
    );

    let err = h.verifier.verify_roster_update(&update).await.unwrap_err();
    assert_eq!(err, VerifyError::RosterTimestampOutOfRange);
}

/// `new_version != prior_version + 1` — shape-level check via
/// `RosterUpdate::validate()`. Returns `NonMonotonicVersion`.
#[tokio::test]
async fn roster_update_non_monotonic_version_rejected() {
    let h = make_harness().await;
    let now = h.clock.now_secs();
    let desktop_key = SigningKey::random(&mut OsRng);

    let mut update = sign_roster_update(
        &h.signing_key,
        &h.device_id,
        TEST_DID,
        1,
        vec![entry_for("dev-desktop", &desktop_key, now, "MacBook")],
        now,
    );
    // Skip a version — claims new_version=5 instead of 2.
    update.new_version = 5;

    let err = h.verifier.verify_roster_update(&update).await.unwrap_err();
    assert_eq!(err, VerifyError::NonMonotonicVersion);
}

/// Unknown DID — never bootstrapped. Same response taxonomy as a
/// SignedAssertion against an unknown DID (no existence oracle).
#[tokio::test]
async fn roster_update_unknown_did_rejected() {
    let h = make_harness().await;
    let now = h.clock.now_secs();
    let desktop_key = SigningKey::random(&mut OsRng);

    // Properly-formed DID, just not in the resolver. Differs from
    // TEST_DID by one character so it definitively misses.
    let update = sign_roster_update(
        &h.signing_key,
        &h.device_id,
        "did:mata:ZZZZZ6789ABCDEFGHJKLMNPQRSTUVWXY",
        1,
        vec![entry_for("dev-desktop", &desktop_key, now, "MacBook")],
        now,
    );

    let err = h.verifier.verify_roster_update(&update).await.unwrap_err();
    assert_eq!(err, VerifyError::DidNotFound);
}
