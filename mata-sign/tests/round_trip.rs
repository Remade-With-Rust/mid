//! End-to-end tests for `mata-sign`: build a real identity (self-signed genesis
//! roster, optional device-add chain), sign content, and verify it through the
//! reused mID checks. The fixture mirrors `mid-verify`'s test pattern — a real
//! P-256 genesis key derives the DID and self-signs the genesis roster, so the
//! four cryptographic checks run against genuine signatures, not stubs.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kms_client::InMemoryDeviceSigner;
use mid_issuer::{
    EmbeddedGenesisRoster, EmbeddedRosterChainEntry, EmbeddedVerificationMethod, IdentitySnapshot,
    VerificationMethod,
};
use mid_verify::keys::{did_from_pubkey, multibase_from_pubkey};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use mata_sign::{
    sign_statement, verify_statement, Content, StatementInput, VerifyError, VerifyOptions,
};

// ─── Fixture builders (mirror mid-verify/src/lib.rs tests) ───────────────────

fn make_signing_key(seed: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(b"-mata-sign-test-seed");
    let bytes: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&bytes.into()).unwrap()
}

fn sign_genesis(roster: &EmbeddedGenesisRoster, signing_key: &SigningKey) -> String {
    let canonical = mid_issuer::canonical::genesis_canonical_bytes(roster);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    let sig: Signature = signing_key.sign_prehash(&prehash).unwrap();
    let normalized = sig.normalize_s().unwrap_or(sig);
    URL_SAFE_NO_PAD.encode(normalized.to_bytes())
}

fn sign_chain_entry(entry: &EmbeddedRosterChainEntry, signing_key: &SigningKey) -> String {
    let canonical = mid_issuer::canonical::chain_entry_canonical_bytes(entry);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    let sig: Signature = signing_key.sign_prehash(&prehash).unwrap();
    let normalized = sig.normalize_s().unwrap_or(sig);
    URL_SAFE_NO_PAD.encode(normalized.to_bytes())
}

/// A genesis-only identity: the DID is derived from the genesis key, the
/// genesis roster is genuinely self-signed, and the returned signer holds the
/// genesis key. `(snapshot, signer, did)`.
fn genesis_identity(seed: &str, device_id: &str) -> (IdentitySnapshot, InMemoryDeviceSigner, String) {
    let key = make_signing_key(seed);
    let did = did_from_pubkey(key.verifying_key());
    let vm_id = format!("{did}#{device_id}");
    let vm = VerificationMethod {
        id: vm_id.clone(),
        vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
        controller: did.clone(),
        public_key_multibase: multibase_from_pubkey(key.verifying_key()),
    };
    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did: did.clone(),
        verification_methods: vec![vm.clone()],
        signed_at: 1_700_000_000,
        self_signed_by_genesis_key: String::new(),
    };
    genesis.self_signed_by_genesis_key = sign_genesis(&genesis, &key);

    let snapshot = IdentitySnapshot {
        did: did.clone(),
        genesis_roster: genesis,
        roster_chain: vec![],
        current_verification_method: EmbeddedVerificationMethod {
            id: vm_id,
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did.clone(),
            public_key_multibase: multibase_from_pubkey(key.verifying_key()),
        },
        approved_claims: BTreeMap::new(),
    };
    let signer = InMemoryDeviceSigner::new(device_id, key);
    (snapshot, signer, did)
}

fn opts(now: u64) -> VerifyOptions {
    VerifyOptions { now_unix_secs: now, max_iat_skew_secs: 120, ..Default::default() }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn sign_then_verify_then_match_content() {
    let (snapshot, signer, did) = genesis_identity("alice", "laptop");
    let content = b"the quick brown fox";

    let token = sign_statement(
        &StatementInput::bytes(content, "text/plain"),
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap();

    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    assert_eq!(v.did, did);
    assert_eq!(v.content_type, "text/plain");
    assert_eq!(v.current_version, 1);
    assert!(v.matches_content(content), "the signed bytes must match");
}

#[test]
fn tampered_content_is_rejected_by_match() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let token = sign_statement(
        &StatementInput::bytes(b"original", "text/plain"),
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap();

    // The token verifies cryptographically (the signer IS who they say)...
    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    // ...but a different document does NOT match the committed hash.
    assert!(!v.matches_content(b"tampered"), "altered content must not match");
    assert!(v.matches_content(b"original"));
}

#[test]
fn tampered_token_payload_fails_signature_check() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let token = sign_statement(
        &StatementInput::bytes(b"hello", "text/plain"),
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap();

    // Flip a byte in the payload segment → JWS signature must fail.
    let mut segs: Vec<String> = token.split('.').map(String::from).collect();
    let mut payload = URL_SAFE_NO_PAD.decode(&segs[1]).unwrap();
    payload[0] ^= 0xff;
    segs[1] = URL_SAFE_NO_PAD.encode(&payload);
    let forged = segs.join(".");

    let err = verify_statement(&forged, &opts(1_716_700_100)).unwrap_err();
    matches!(err, VerifyError::Crypto(_) | VerifyError::Malformed(_));
}

#[test]
fn wrong_signer_is_rejected() {
    // Build a valid snapshot for alice, but sign with bob's key. The embedded
    // VM (alice's pubkey) won't verify bob's JWS signature.
    let (snapshot, _alice_signer, _) = genesis_identity("alice", "laptop");
    let bob = InMemoryDeviceSigner::new("laptop", make_signing_key("bob"));

    let token = sign_statement(
        &StatementInput::bytes(b"hi", "text/plain"),
        &snapshot,
        &bob,
        1_716_700_000,
    )
    .unwrap();

    let err = verify_statement(&token, &opts(1_716_700_100)).unwrap_err();
    assert!(matches!(err, VerifyError::Crypto(_)), "got {err:?}");
}

#[test]
fn expired_statement_is_rejected() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let input = StatementInput {
        content: Content::Bytes(b"expires"),
        content_type: "text/plain".into(),
        context: None,
        nonce: None,
        exp: Some(1_716_700_500),
        preview: None,
        platform_binding: None,
    };
    let token = sign_statement(&input, &snapshot, &signer, 1_716_700_000).unwrap();

    // now > exp → Expired.
    let err = verify_statement(&token, &opts(1_716_701_000)).unwrap_err();
    assert!(matches!(err, VerifyError::Expired { .. }), "got {err:?}");
    // before exp → ok.
    assert!(verify_statement(&token, &opts(1_716_700_200)).is_ok());
}

#[test]
fn future_dated_statement_is_rejected() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let token = sign_statement(
        &StatementInput::bytes(b"future", "text/plain"),
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap();

    // Verifier clock is well before iat, beyond the 120s skew → NotYetValid.
    let err = verify_statement(&token, &opts(1_716_600_000)).unwrap_err();
    assert!(matches!(err, VerifyError::NotYetValid { .. }), "got {err:?}");
}

#[test]
fn context_binding_is_enforced() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let input = StatementInput {
        content: Content::Bytes(b"post body"),
        content_type: "text/plain".into(),
        context: Some("iamhuman".into()),
        nonce: None,
        exp: None,
        preview: Some("post body".into()),
        platform_binding: None,
    };
    let token = sign_statement(&input, &snapshot, &signer, 1_716_700_000).unwrap();

    // Matching context → ok, preview round-trips.
    let mut o = opts(1_716_700_100);
    o.expected_context = Some("iamhuman".into());
    let v = verify_statement(&token, &o).unwrap();
    assert_eq!(v.context.as_deref(), Some("iamhuman"));
    assert_eq!(v.preview.as_deref(), Some("post body"));

    // A verifier expecting a different context rejects it (no cross-use replay).
    let mut o2 = opts(1_716_700_100);
    o2.expected_context = Some("mata-doc".into());
    let err = verify_statement(&token, &o2).unwrap_err();
    assert!(matches!(err, VerifyError::ContextMismatch { .. }), "got {err:?}");
}

#[test]
fn nonce_binding_is_enforced() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let input = StatementInput {
        content: Content::Bytes(b"x"),
        content_type: "text/plain".into(),
        context: None,
        nonce: Some("nonce-123".into()),
        exp: None,
        preview: None,
        platform_binding: None,
    };
    let token = sign_statement(&input, &snapshot, &signer, 1_716_700_000).unwrap();

    let mut o = opts(1_716_700_100);
    o.expected_nonce = Some("nonce-999".into());
    let err = verify_statement(&token, &o).unwrap_err();
    assert!(matches!(err, VerifyError::NonceMismatch), "got {err:?}");

    o.expected_nonce = Some("nonce-123".into());
    assert!(verify_statement(&token, &o).is_ok());
}

#[test]
fn precomputed_hash_matches_bytes_hash() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let content = b"a large document's bytes";
    let digest: [u8; 32] = Sha256::digest(content).into();

    let token = sign_statement(
        &StatementInput {
            content: Content::PrecomputedSha256(digest),
            content_type: "application/pdf".into(),
            context: None,
            nonce: None,
            exp: None,
            preview: None,
            platform_binding: None,
        },
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap();

    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    assert_eq!(v.content_hash, digest);
    assert!(v.matches_content(content), "precomputed-hash sign verifies against the raw bytes");
}

#[test]
fn device_add_chain_bumps_version_and_verifies() {
    // Genesis device "laptop" adds a second device "phone"; "phone" signs.
    let genesis_key = make_signing_key("alice");
    let did = did_from_pubkey(genesis_key.verifying_key());
    let phone_key = make_signing_key("alice-phone");

    let laptop_vm = VerificationMethod {
        id: format!("{did}#laptop"),
        vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
        controller: did.clone(),
        public_key_multibase: multibase_from_pubkey(genesis_key.verifying_key()),
    };
    let phone_vm = VerificationMethod {
        id: format!("{did}#phone"),
        vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
        controller: did.clone(),
        public_key_multibase: multibase_from_pubkey(phone_key.verifying_key()),
    };

    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did: did.clone(),
        verification_methods: vec![laptop_vm.clone()],
        signed_at: 1_700_000_000,
        self_signed_by_genesis_key: String::new(),
    };
    genesis.self_signed_by_genesis_key = sign_genesis(&genesis, &genesis_key);

    // Chain entry v2: laptop (in prior/genesis roster) signs the new roster
    // {laptop, phone}.
    let mut entry = EmbeddedRosterChainEntry {
        version: 2,
        did: did.clone(),
        verification_methods: vec![laptop_vm, phone_vm.clone()],
        signed_at: 1_700_000_100,
        signed_by_signer_in_prior_roster: String::new(),
        signer_kid: "laptop".into(),
    };
    entry.signed_by_signer_in_prior_roster = sign_chain_entry(&entry, &genesis_key);

    let snapshot = IdentitySnapshot {
        did: did.clone(),
        genesis_roster: genesis,
        roster_chain: vec![entry],
        current_verification_method: EmbeddedVerificationMethod {
            id: phone_vm.id.clone(),
            vm_type: phone_vm.vm_type.clone(),
            controller: did,
            public_key_multibase: phone_vm.public_key_multibase.clone(),
        },
        approved_claims: BTreeMap::new(),
    };
    let phone_signer = InMemoryDeviceSigner::new("phone", phone_key);

    let token = sign_statement(
        &StatementInput::bytes(b"signed from my phone", "text/plain"),
        &snapshot,
        &phone_signer,
        1_716_700_000,
    )
    .unwrap();

    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    assert_eq!(v.current_version, 2, "head roster version reflects the device add");
    assert!(v.matches_content(b"signed from my phone"));
}

#[test]
fn sign_single_device_round_trips_without_a_prebuilt_snapshot() {
    // The derived/service-identity path: only a key + its DID, no roster on
    // hand. `sign_single_device` builds + self-signs the genesis internally.
    let key = make_signing_key("acme-business");
    let did = did_from_pubkey(key.verifying_key());
    let multibase = multibase_from_pubkey(key.verifying_key());
    let signer = InMemoryDeviceSigner::new("biz-holding-1", key);

    let content = b"OFFER LETTER\nPosition: Engineer\nSalary: ...";
    let token = mata_sign::sign_single_device(
        &did,
        &multibase,
        "biz-holding-1",
        &StatementInput {
            content: Content::Bytes(content),
            content_type: "application/vnd.mata.hiring-document".into(),
            context: Some("mata-doc".into()),
            nonce: None,
            exp: None,
            preview: None,
            platform_binding: None,
        },
        &signer,
        1_716_700_000,
    )
    .unwrap();

    // Verifies through the exact same checks as any other statement.
    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    assert_eq!(v.did, did);
    assert_eq!(v.context.as_deref(), Some("mata-doc"));
    assert_eq!(v.current_version, 1);
    assert!(v.matches_content(content));
    assert!(!v.matches_content(b"a forged offer letter"));
}

#[test]
fn signer_not_in_head_roster_fails_at_sign_time() {
    let (mut snapshot, signer, did) = genesis_identity("alice", "laptop");
    // Claim a device that isn't in the roster.
    snapshot.current_verification_method.id = format!("{did}#ghost");

    let err = sign_statement(
        &StatementInput::bytes(b"x", "text/plain"),
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap_err();
    assert!(matches!(err, mata_sign::SignError::InconsistentSnapshot(_)), "got {err:?}");
}

// ─── S1 platform binding (docs/iamhuman/s1-platform-binding.md) ──────────────

#[test]
fn platform_binding_round_trips() {
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let input = StatementInput {
        content: Content::Bytes(b"hello from a bound post"),
        content_type: "text/plain".into(),
        context: Some("iamhuman".into()),
        nonce: None,
        exp: None,
        preview: None,
        platform_binding: Some(mata_sign::PlatformBinding {
            platform: "x.com".into(),
            author_handle: Some("farmer_timmm".into()),
            author_id: Some("1234567890".into()),
        }),
    };
    let token = sign_statement(&input, &snapshot, &signer, 1_716_700_000).unwrap();

    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    let b = v.platform_binding.expect("binding survives sign→verify");
    assert_eq!(b.platform, "x.com");
    assert_eq!(b.author_handle.as_deref(), Some("farmer_timmm"));
    assert_eq!(b.author_id.as_deref(), Some("1234567890"));
    // The binding is covered by the signature: flip the platform in the payload
    // and the JWS check must fail.
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let payload = URL_SAFE_NO_PAD.decode(&parts[1]).unwrap();
    let tampered = String::from_utf8(payload).unwrap().replace("x.com", "evil.example");
    parts[1] = URL_SAFE_NO_PAD.encode(tampered.as_bytes());
    let forged = parts.join(".");
    let err = verify_statement(&forged, &opts(1_716_700_100)).unwrap_err();
    assert!(matches!(err, VerifyError::Crypto(_)), "got {err:?}");
}

#[test]
fn absent_platform_binding_is_wire_identical() {
    // Backward-compat guarantee: a bindingless statement serializes with NO
    // `platform_binding` key at all — byte-identical envelope shape to pre-S1
    // tokens, so document/claim/blob signatures and old verifiers never see
    // the field.
    let (snapshot, signer, _) = genesis_identity("alice", "laptop");
    let token = sign_statement(
        &StatementInput::bytes(b"plain statement", "text/plain"),
        &snapshot,
        &signer,
        1_716_700_000,
    )
    .unwrap();

    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
    assert!(
        !payload.contains("platform_binding"),
        "bindingless payload must not carry the key: {payload}"
    );
    let v = verify_statement(&token, &opts(1_716_700_100)).unwrap();
    assert!(v.platform_binding.is_none());
}
