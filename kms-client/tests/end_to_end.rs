//! End-to-end proof that `kms-client` signs assertions the `kms-verifier`
//! accepts. Both crates must agree on:
//! - envelope canonical form (SHA-256 prefix + length prefixes)
//! - ECDSA P-256 prehash signing
//! - low-s canonical signature form
//! - SEC1-uncompressed pubkey shape
//!
//! These tests don't exercise the HTTP layer — that's covered by
//! `kms-banking-proxy` integration tests in Phase 5. Here we prove the
//! in-process round-trip.

use std::sync::Arc;

use kms_client::{sign_assertion, DeviceSigner, InMemoryDeviceSigner};
use kms_verifier::{
    DidDocumentV2, InMemoryDidResolver, InMemoryNonceStore, RosterEntry, Verifier, VerifyError,
};

const ISSUER: &str = "kms-banking-proxy";
const AUDIENCE: &str = "kms-banking";
const PURPOSE: &str = "get_accounts";
const TEST_DID: &str = "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXY";

async fn setup() -> (Verifier, Arc<InMemoryDidResolver>, InMemoryDeviceSigner) {
    let resolver = Arc::new(InMemoryDidResolver::new());
    let nonce_store = Arc::new(InMemoryNonceStore::new());

    let signer = InMemoryDeviceSigner::generate("dev-laptop");

    // Publish the device's pubkey in the user's DID document.
    resolver
        .upsert(DidDocumentV2 {
            did: TEST_DID.into(),
            roster_version: 1,
            roster: vec![RosterEntry {
                device_id: signer.device_id().to_string(),
                pubkey: signer.pubkey_sec1(),
                added_at: 1_699_000_000,
                label: "Test laptop".into(),
            }],
            updated_at: 1_699_000_000,
        })
        .await;

    let verifier = Verifier::new(
        ISSUER,
        AUDIENCE,
        [PURPOSE.to_string()],
        nonce_store,
        resolver.clone(),
    );

    (verifier, resolver, signer)
}

#[tokio::test]
async fn client_signs_then_verifier_accepts() {
    let (verifier, _resolver, signer) = setup().await;

    // Verifier issues nonce.
    let nonce = verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();

    // Client signs.
    let assertion = sign_assertion(&signer, nonce).unwrap();

    // Verifier accepts.
    let verified = verifier.verify(&assertion, PURPOSE).await.unwrap();
    assert_eq!(verified.did, TEST_DID);
    assert_eq!(verified.device_id, "dev-laptop");
    assert_eq!(verified.purpose, PURPOSE);
    assert_eq!(verified.roster_version, 1);
}

#[tokio::test]
async fn signed_assertion_is_low_s_canonical() {
    // The verifier rejects high-s signatures. Confirm that whatever
    // sign_assertion produces, it survives the verifier's malleability check.
    // Run many signatures (each a fresh nonce) — if any produce high-s, this
    // would catch it. RFC 6979 + normalize_s should make this stable.
    let (verifier, _resolver, signer) = setup().await;
    for _ in 0..32 {
        let nonce = verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
        let assertion = sign_assertion(&signer, nonce).unwrap();
        verifier.verify(&assertion, PURPOSE).await.unwrap();
    }
}

#[tokio::test]
async fn client_envelope_shape_validation_blocks_bad_server() {
    // A hostile or buggy server returns a malformed envelope; the client
    // refuses to sign it.
    let signer = InMemoryDeviceSigner::generate("dev-laptop");

    // Pretend the server sent us this — bad version.
    let bad_envelope = kms_client::NonceEnvelope {
        envelope_version: 99,
        envelope_type: kms_client::NonceEnvelope::TYPE.into(),
        nonce: vec![0xAB; 32],
        did: TEST_DID.into(),
        audience: AUDIENCE.into(),
        purpose: PURPOSE.into(),
        issued_at: 1_716_583_200,
        expires_at: 1_716_583_230,
        issuer: ISSUER.into(),
    };

    let err = sign_assertion(&signer, bad_envelope).unwrap_err();
    assert_eq!(err, VerifyError::UnknownEnvelopeVersion);
}

#[tokio::test]
async fn different_devices_produce_distinguishable_assertions() {
    // Two devices on the same roster, both sign the same nonce. Verifier
    // accepts both. VerifiedIdentity.device_id differs.
    let resolver = Arc::new(InMemoryDidResolver::new());
    let nonce_store = Arc::new(InMemoryNonceStore::new());

    let laptop = InMemoryDeviceSigner::generate("dev-laptop");
    let phone = InMemoryDeviceSigner::generate("dev-phone");

    resolver
        .upsert(DidDocumentV2 {
            did: TEST_DID.into(),
            roster_version: 1,
            roster: vec![
                RosterEntry {
                    device_id: laptop.device_id().to_string(),
                    pubkey: laptop.pubkey_sec1(),
                    added_at: 1_699_000_000,
                    label: "Laptop".into(),
                },
                RosterEntry {
                    device_id: phone.device_id().to_string(),
                    pubkey: phone.pubkey_sec1(),
                    added_at: 1_699_000_000,
                    label: "Phone".into(),
                },
            ],
            updated_at: 1_699_000_000,
        })
        .await;

    let verifier = Verifier::new(
        ISSUER,
        AUDIENCE,
        [PURPOSE.to_string()],
        nonce_store,
        resolver,
    );

    let nonce_a = verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion_a = sign_assertion(&laptop, nonce_a).unwrap();
    let verified_a = verifier.verify(&assertion_a, PURPOSE).await.unwrap();
    assert_eq!(verified_a.device_id, "dev-laptop");

    let nonce_b = verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion_b = sign_assertion(&phone, nonce_b).unwrap();
    let verified_b = verifier.verify(&assertion_b, PURPOSE).await.unwrap();
    assert_eq!(verified_b.device_id, "dev-phone");
}

#[tokio::test]
async fn attacker_off_roster_cannot_forge() {
    // Attacker holds a perfectly valid P-256 keypair, but it's not on the
    // user's roster. The verifier rejects.
    let (verifier, _resolver, _legit) = setup().await;
    let attacker = InMemoryDeviceSigner::generate("dev-laptop"); // claim laptop's id!
    let nonce = verifier.issue_nonce(TEST_DID, PURPOSE).await.unwrap();
    let assertion = sign_assertion(&attacker, nonce).unwrap();
    let err = verifier.verify(&assertion, PURPOSE).await.unwrap_err();
    // The signature won't verify under the legit device's roster pubkey.
    assert_eq!(err, VerifyError::SignatureInvalid);
}
