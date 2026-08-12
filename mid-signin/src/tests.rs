use std::sync::Arc;

use kms_client::InMemoryDeviceSigner;

use crate::test_fixtures::{
    fresh_identity, make_signing_key, mint_jwt, two_device_identity, DeviceKey, IdentityFixture,
};
use crate::{
    peek_nonce, AnchorStore, Authenticator, InMemoryAnchorStore, InMemoryNonceStore, NonceStore,
    RpError, VerifyParams,
};

const RP: &str = "https://acme.com";
const NOW: u64 = 1_716_700_010;
const IAT: u64 = 1_716_700_000;

fn single_device_setup() -> (IdentityFixture, InMemoryDeviceSigner) {
    let identity = IdentityFixture::new("device-A", "dev-laptop");
    let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
    (identity, signer)
}

// ─── Authenticator: full flow ───────────────────────────────────────────────

#[test]
fn authenticate_happy_path() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);

    let session = auth
        .authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
        .expect("happy path");
    assert_eq!(session.did, identity.did());
    assert_eq!(session.current_version, 1);
    assert_eq!(session.claim_str("did"), Some(identity.did().as_str()));
    assert!(!session.is_expired(NOW));
}

#[test]
fn replayed_token_rejected() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);
    let params = VerifyParams::new(RP, &nonce, NOW);

    auth.authenticate(&jwt, &params).expect("first use");
    let replay = auth.authenticate(&jwt, &params).unwrap_err();
    assert!(matches!(replay, RpError::NonceRejected));
}

#[test]
fn unissued_nonce_rejected() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    // Cryptographically valid token whose nonce we never issued.
    let jwt = mint_jwt(&snapshot, &signer, RP, "attacker-chosen-nonce", IAT);
    let err = auth
        .authenticate(&jwt, &VerifyParams::new(RP, "attacker-chosen-nonce", NOW))
        .unwrap_err();
    assert!(matches!(err, RpError::NonceRejected));
}

#[test]
fn failed_verification_does_not_burn_the_nonce() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    let nonce = auth.issue_nonce(NOW).unwrap();
    // Token minted for a DIFFERENT audience — verification fails before
    // nonce consumption.
    let wrong_aud = mint_jwt(&snapshot, &signer, "https://evil.example", &nonce, IAT);
    let err = auth
        .authenticate(&wrong_aud, &VerifyParams::new(RP, &nonce, NOW))
        .unwrap_err();
    assert!(matches!(err, RpError::Verify(_)));

    // The legitimate retry with the same nonce still succeeds.
    let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);
    auth.authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
        .expect("nonce survived the failed attempt");
}

#[test]
fn rollback_across_sign_ins_detected() {
    // Same DID: a two-device (version 2) sign-in, then a genesis-only
    // (version 1) sign-in — the stolen-device rollback shape.
    let identity = IdentityFixture::new("genesis", "dev-laptop");
    let phone = DeviceKey::new("new-phone", "dev-phone");
    let auth = Authenticator::in_memory();

    let v2 = two_device_identity(&identity, &phone);
    let phone_signer = InMemoryDeviceSigner::new("dev-phone", make_signing_key("new-phone"));
    let nonce1 = auth.issue_nonce(NOW).unwrap();
    let jwt_v2 = mint_jwt(&v2, &phone_signer, RP, &nonce1, IAT);
    auth.authenticate(&jwt_v2, &VerifyParams::new(RP, &nonce1, NOW))
        .expect("version 2 accepted");

    let v1 = fresh_identity(&identity);
    let laptop_signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("genesis"));
    let nonce2 = auth.issue_nonce(NOW).unwrap();
    let jwt_v1 = mint_jwt(&v1, &laptop_signer, RP, &nonce2, IAT);
    let err = auth
        .authenticate(&jwt_v1, &VerifyParams::new(RP, &nonce2, NOW))
        .unwrap_err();
    match err {
        RpError::Rollback {
            presented,
            last_seen,
            ..
        } => {
            assert_eq!(presented, 1);
            assert_eq!(last_seen, 2);
        }
        other => panic!("expected Rollback, got {other:?}"),
    }
}

#[test]
fn version_reuse_is_not_rollback() {
    // Presenting the SAME version again (normal repeat sign-in) is fine.
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    for _ in 0..2 {
        let nonce = auth.issue_nonce(NOW).unwrap();
        let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);
        auth.authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
            .expect("repeat sign-in at same version");
    }
}

// ─── Embedded-nonce path (the HTTP-route flow) ──────────────────────────────

#[test]
fn embedded_nonce_happy_path() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);

    let session = auth
        .authenticate_with_embedded_nonce(&jwt, RP, NOW, 120)
        .expect("embedded-nonce flow");
    assert_eq!(session.did, identity.did());
}

#[test]
fn embedded_nonce_forged_value_rejected() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();

    // Nonce never issued by this RP: peek succeeds, consumption fails.
    let jwt = mint_jwt(&snapshot, &signer, RP, "forged-nonce", IAT);
    let err = auth
        .authenticate_with_embedded_nonce(&jwt, RP, NOW, 120)
        .unwrap_err();
    assert!(matches!(err, RpError::NonceRejected));
}

#[test]
fn peek_nonce_reads_the_echoed_value() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let jwt = mint_jwt(&snapshot, &signer, RP, "nonce-xyz", IAT);
    assert_eq!(peek_nonce(&jwt).unwrap(), "nonce-xyz");
}

#[test]
fn peek_nonce_rejects_garbage() {
    assert!(matches!(
        peek_nonce("not-a-jwt").unwrap_err(),
        RpError::MalformedToken
    ));
    assert!(matches!(
        peek_nonce("a.b").unwrap_err(),
        RpError::MalformedToken
    ));
    assert!(matches!(
        peek_nonce("a.!!!notb64!!!.c").unwrap_err(),
        RpError::MalformedToken
    ));
}

// ─── Nonce store: TTL + capacity ────────────────────────────────────────────

#[test]
fn expired_nonce_rejected() {
    let store = InMemoryNonceStore::with_limits(60, 10);
    let nonce = store.issue(1_000).unwrap();
    // 61 seconds later: past TTL.
    assert!(!store.consume(&nonce, 1_061).unwrap());
}

#[test]
fn nonce_capacity_enforced_and_sweep_recovers() {
    let store = InMemoryNonceStore::with_limits(60, 2);
    store.issue(1_000).unwrap();
    store.issue(1_000).unwrap();
    // Full, nothing expired → capacity error.
    let err = store.issue(1_010).unwrap_err();
    assert!(matches!(err, RpError::NonceCapacity { max_live: 2 }));
    // Past TTL the sweep evicts both and issuance recovers.
    store.issue(1_100).expect("sweep frees capacity");
}

// ─── Anchor store invariants (unit level) ───────────────────────────────────

#[test]
fn genesis_mismatch_detected() {
    let anchors = InMemoryAnchorStore::new();
    anchors.check_and_update("did:mata:x", &[1u8; 32], 1).unwrap();
    let err = anchors
        .check_and_update("did:mata:x", &[2u8; 32], 2)
        .unwrap_err();
    assert!(matches!(err, RpError::GenesisMismatch { .. }));
}

#[test]
fn anchor_first_sight_records() {
    let anchors = InMemoryAnchorStore::new();
    anchors.check_and_update("did:mata:x", &[1u8; 32], 3).unwrap();
    // Higher version fine; lower rejected.
    anchors.check_and_update("did:mata:x", &[1u8; 32], 4).unwrap();
    let err = anchors
        .check_and_update("did:mata:x", &[1u8; 32], 3)
        .unwrap_err();
    assert!(matches!(err, RpError::Rollback { .. }));
}

// ─── Session expiry helpers ─────────────────────────────────────────────────

#[test]
fn session_expiry_helpers() {
    let (identity, signer) = single_device_setup();
    let snapshot = fresh_identity(&identity);
    let auth = Authenticator::in_memory();
    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);
    let session = auth
        .authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
        .unwrap();

    assert!(session.ensure_valid(NOW).is_ok());
    let past_exp = session.exp + 1;
    assert!(session.is_expired(past_exp));
    assert!(matches!(
        session.ensure_valid(past_exp).unwrap_err(),
        RpError::SessionExpired { .. }
    ));
}

// ─── RedbStore (feature-gated) ──────────────────────────────────────────────

#[cfg(feature = "redb-store")]
mod redb_store {
    use super::*;
    use crate::RedbStore;

    #[test]
    fn nonce_survives_reopen_and_single_use_holds_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.redb");

        let nonce = {
            let store = RedbStore::open(&path).unwrap();
            store.issue(NOW).unwrap()
        };
        // Reopen: the issued nonce is still live exactly once.
        let store = RedbStore::open(&path).unwrap();
        assert!(store.consume(&nonce, NOW).unwrap());
        drop(store);
        let store = RedbStore::open(&path).unwrap();
        assert!(!store.consume(&nonce, NOW).unwrap(), "replay across reopen");
    }

    #[test]
    fn rollback_detected_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.redb");

        {
            let store = RedbStore::open(&path).unwrap();
            store.check_and_update("did:mata:x", &[7u8; 32], 5).unwrap();
        }
        let store = RedbStore::open(&path).unwrap();
        let err = store
            .check_and_update("did:mata:x", &[7u8; 32], 4)
            .unwrap_err();
        assert!(matches!(
            err,
            RpError::Rollback {
                presented: 4,
                last_seen: 5,
                ..
            }
        ));
        // Genesis mismatch also persists.
        let err = store
            .check_and_update("did:mata:x", &[8u8; 32], 6)
            .unwrap_err();
        assert!(matches!(err, RpError::GenesisMismatch { .. }));
    }

    #[test]
    fn end_to_end_through_persistent_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth.redb");
        let store = Arc::new(RedbStore::open(&path).unwrap());
        let auth = Authenticator::new(store.clone(), store);

        let (identity, signer) = single_device_setup();
        let snapshot = fresh_identity(&identity);
        let nonce = auth.issue_nonce(NOW).unwrap();
        let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);
        let session = auth
            .authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
            .expect("end-to-end over redb");
        assert_eq!(session.did, identity.did());
        // Replay still rejected through the persistent store.
        assert!(matches!(
            auth.authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
                .unwrap_err(),
            RpError::NonceRejected
        ));
    }
}

// ─── Drop-in routes (feature-gated) ─────────────────────────────────────────

#[cfg(feature = "routes")]
mod routes {
    use super::*;
    use crate::routes::{router, router_with, MidRp, MidRpConfig, OnVerified};
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn rp() -> Arc<MidRp> {
        Arc::new(MidRp::new(MidRpConfig::new(RP), Authenticator::in_memory()))
    }

    fn post_json(uri: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn nonce_then_verify_round_trip() {
        let rp = rp();
        let app = router(rp);

        // 1. Mint a nonce over HTTP.
        let response = app
            .clone()
            .oneshot(post_json("/auth/mid/nonce", "{}".into()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let nonce = body_json(response).await["nonce"].as_str().unwrap().to_owned();

        // 2. Wallet-side: mint a real JWT echoing that nonce.
        let (identity, signer) = single_device_setup();
        let snapshot = fresh_identity(&identity);
        // iat must be near the real wall clock — the route reads SystemTime.
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, iat);

        // 3. Verify over HTTP.
        let body = serde_json::json!({ "jwt": jwt }).to_string();
        let response = app
            .clone()
            .oneshot(post_json("/auth/mid/verify", body.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let verified = body_json(response).await;
        assert_eq!(verified["did"].as_str().unwrap(), identity.did());
        assert_eq!(verified["roster_version"].as_u64().unwrap(), 1);

        // 4. Replay over HTTP → 401 nonce_rejected.
        let response = app
            .oneshot(post_json("/auth/mid/verify", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_json(response).await["error"].as_str().unwrap(),
            "nonce_rejected"
        );
    }

    #[tokio::test]
    async fn malformed_token_is_bad_request() {
        let app = router(rp());
        let body = serde_json::json!({ "jwt": "garbage" }).to_string();
        let response = app
            .oneshot(post_json("/auth/mid/verify", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_json(response).await["error"].as_str().unwrap(),
            "malformed_token"
        );
    }

    #[tokio::test]
    async fn on_verified_hook_takes_over_the_response() {
        let rp = rp();
        let hook: OnVerified = Arc::new(|session| {
            Some(
                (
                    StatusCode::OK,
                    [(header::SET_COOKIE, format!("sid={}", session.did))],
                    "signed-in",
                )
                    .into_response(),
            )
        });
        let app = router_with(rp.clone(), hook);

        let nonce = rp.issue_nonce().unwrap();
        let (identity, signer) = single_device_setup();
        let snapshot = fresh_identity(&identity);
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, iat);

        let body = serde_json::json!({ "jwt": jwt }).to_string();
        let response = app
            .oneshot(post_json("/auth/mid/verify", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie.starts_with("sid=did:mata:"));
    }
}
