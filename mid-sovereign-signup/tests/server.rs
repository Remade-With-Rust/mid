//! M2 gates for the `server` feature: everything runs against a REAL bound
//! socket (an in-process server on 127.0.0.1:0, and — last test — the actual
//! `signupd` binary in its own process), driven over HTTP.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kms_client::InMemoryDeviceSigner;
use mid_sovereign_signup::attest::{verify_attestation, AttestationPolicy};
use mid_sovereign_signup::server::{
    serve, Clock, KeyDidResolver, Need, Server, ServerConfig, ServiceIdentity, SnapshotTier,
    SystemClock, OPS,
};
use mid_sovereign_signup::store::MemEngine;
use mid_sovereign_signup::{webhook, OsEntropy, Pepper, SignupStore, StubMailer, Tenant, TenantId};
use p256::ecdsa::SigningKey;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

const ORIGIN: &str = "https://app.acme.com";
const IMPORT_TOKEN: &str = "import-token-0123456789abcdef0123456789";

struct CountingTier(AtomicU64);
impl SnapshotTier for CountingTier {
    fn posture(&self) -> String {
        "test-tier".into()
    }
    fn height(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
    fn failures(&self) -> u64 {
        0
    }
    fn land(&self, _now: u64) -> Result<Option<u64>, String> {
        Ok(Some(self.0.fetch_add(1, Ordering::SeqCst) + 1))
    }
}

struct Harness {
    base: String,
    public_id: String,
    http: Client,
    mail: Arc<StubMailer>,
    tier: Arc<CountingTier>,
    server: Arc<Server<MemEngine>>,
    operator: InMemoryDeviceSigner,
    operator_did: String,
    _stop: tokio::sync::oneshot::Sender<()>,
}

fn key(seed: u8) -> SigningKey {
    let mut b = [seed; 32];
    b[0] = 1;
    SigningKey::from_bytes(&b.into()).unwrap()
}

fn signer(seed: u8) -> (InMemoryDeviceSigner, String) {
    let s = InMemoryDeviceSigner::new(mid_sovereign_signup::server::KEY_DID_DEVICE_ID, key(seed));
    let did = kms_verifier::did_from_pubkey_sec1(&s.pubkey_sec1()).unwrap();
    (s, did)
}

async fn harness_with(cfg: impl FnOnce(&mut ServerConfig)) -> Harness {
    let (operator, operator_did) = signer(9);
    let store = SignupStore::in_memory(Pepper::from_bytes([3; 32]))
        .unwrap()
        .with_limits(mid_sovereign_signup::Limits::NONE);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let mut t = Tenant::new(
        TenantId::parse("acme").unwrap(),
        "Acme",
        vec![ORIGIN.into()],
        clock.now_secs(),
        &mut OsEntropy,
    )
    .unwrap();
    t.members.clear();
    store.create_tenant(&t).unwrap();
    let mail = Arc::new(StubMailer::new());
    let tier = Arc::new(CountingTier(AtomicU64::new(0)));
    let mut config = ServerConfig {
        operators: vec![operator_did.clone()],
        import_token: Some(IMPORT_TOKEN.into()),
        ..ServerConfig::default()
    };
    cfg(&mut config);
    let server = Arc::new(Server::new(
        Arc::new(store),
        mail.clone(),
        Arc::new(ServiceIdentity::from_secret([5; 32]).unwrap()),
        Arc::new(KeyDidResolver),
        tier.clone(),
        clock,
        config,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = server.clone();
    tokio::spawn(async move {
        serve(srv, listener, async move {
            let _ = rx.await;
        })
        .await
        .unwrap();
    });
    Harness {
        base,
        public_id: t.public_id,
        http: Client::new(),
        mail,
        tier,
        server,
        operator,
        operator_did,
        _stop: tx,
    }
}

async fn harness() -> Harness {
    harness_with(|_| {}).await
}

impl Harness {
    fn p(&self, path: &str) -> String {
        format!("{}/v1/p/{}{}", self.base, self.public_id, path)
    }

    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        let r = self
            .http
            .post(self.p(path))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    fn last_code(&self) -> String {
        self.mail
            .take()
            .last()
            .expect("a code was mailed")
            .code
            .as_str()
            .to_string()
    }

    async fn sign_up(&self, email: &str) -> Value {
        let (s, _) = self.post("/signup/start", json!({ "email": email })).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let code = self.last_code();
        let (s, body) = self
            .post("/signup/verify", json!({ "email": email, "code": code }))
            .await;
        assert_eq!(s, StatusCode::OK, "{body}");
        body
    }

    /// `Authorization` value for one backend call: nonce → sign → header.
    async fn assertion(&self, who: &InMemoryDeviceSigner, did: &str, purpose: &str) -> String {
        let env: kms_types::NonceEnvelope = self
            .http
            .post(format!("{}/v1/nonce", self.base))
            .json(&json!({ "did": did, "purpose": purpose }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let a = kms_client::sign_assertion(who, env).unwrap();
        format!(
            "Signup-Assertion {}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&a).unwrap())
        )
    }

    async fn admin(
        &self,
        who: &InMemoryDeviceSigner,
        did: &str,
        purpose: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let auth = self.assertion(who, did, purpose).await;
        let mut rb = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .header("authorization", auth);
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let r = rb.send().await.unwrap();
        let status = r.status();
        (status, r.json().await.unwrap_or(Value::Null))
    }
}

// ─── the end-user journey ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn sign_up_end_to_end_with_session_and_offline_attestation() {
    let h = harness().await;
    let body = h.sign_up(" Alice@Example.com ").await;
    assert_eq!(body["user"]["email"], "alice@example.com");
    assert_eq!(body["user_created"], true);
    let token = body["session"]["token"].as_str().unwrap().to_string();
    let refresh = body["session"]["refresh"].as_str().unwrap().to_string();
    assert!(
        h.tier.height() >= 1,
        "the verify landed a snapshot before answering"
    );

    // The attestation verifies OFFLINE, pinned to the service DID it names.
    let issuer = body["attestation_issuer"].as_str().unwrap();
    assert_eq!(issuer, h.server.identity().did());
    let acme = TenantId::parse("acme").unwrap();
    let v = verify_attestation(
        body["attestation"].as_str().unwrap(),
        &AttestationPolicy {
            expected_issuer: Some(issuer),
            expected_tenant: Some(&acme),
            now_unix_secs: h.server.now(),
            max_iat_skew_secs: 60,
        },
    )
    .unwrap();
    assert_eq!(
        v.claims.user_id.as_str(),
        body["user"]["id"].as_str().unwrap()
    );

    // The session reads the user's own record.
    let me: Value = h
        .http
        .get(h.p("/users/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["id"], body["user"]["id"]);
    // A fresh attestation on demand.
    let a: Value = h
        .http
        .get(h.p("/attestation"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(a["attestation"].as_str().unwrap().split('.').count() == 3);

    // Refresh rotates; the old access token dies; logout ends the new one.
    let (s, pair) = h
        .post("/session/refresh", json!({ "refresh": refresh }))
        .await;
    assert_eq!(s, StatusCode::OK);
    let token2 = pair["token"].as_str().unwrap();
    assert_eq!(
        h.http
            .get(h.p("/users/me"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.http
            .post(h.p("/session/logout"))
            .bearer_auth(token2)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.http
            .get(h.p("/users/me"))
            .bearer_auth(token2)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Replaying the spent refresh token is refused.
    let (s, e) = h
        .post("/session/refresh", json!({ "refresh": refresh }))
        .await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("session_invalid"))
    );

    // Signing in again is the same user.
    let again = h.sign_up("alice@example.com").await;
    assert_eq!(again["user"]["id"], body["user"]["id"]);
    assert_eq!(again["user_created"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_profile_routes_set_username_and_metadata() {
    let h = harness().await;
    let a = h.sign_up("a@example.com").await;
    let b = h.sign_up("b@example.com").await;
    let ta = a["session"]["token"].as_str().unwrap();
    let tb = b["session"]["token"].as_str().unwrap();
    let (s, v) = h
        .post("/username/check", json!({ "username": "Tim" }))
        .await;
    assert_eq!((s, v["available"].as_bool()), (StatusCode::OK, Some(true)));
    let r = h
        .http
        .patch(h.p("/users/me"))
        .bearer_auth(ta)
        .json(&json!({ "username": "Tim", "metadata": { "plan": "pro" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let me: Value = r.json().await.unwrap();
    assert_eq!(
        (me["username"].as_str(), me["metadata"]["plan"].as_str()),
        (Some("tim"), Some("pro"))
    );
    let (_, v) = h
        .post("/username/check", json!({ "username": "TIM" }))
        .await;
    assert_eq!(v["available"], false);
    let r = h
        .http
        .patch(h.p("/users/me"))
        .bearer_auth(tb)
        .json(&json!({ "username": "tim" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = h
        .http
        .patch(h.p("/users/me"))
        .bearer_auth(tb)
        .json(&json!({ "email": "x@y.z" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "the address is not editable here"
    );
    let r = h
        .http
        .patch(h.p("/users/me"))
        .bearer_auth(ta)
        .json(&json!({ "username": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["username"], Value::Null);
    let (s, _) = h.post("/username/check", json!({ "username": "x" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Sign out everywhere.
    let r = h
        .http
        .post(h.p("/session/logout-all"))
        .bearer_auth(ta)
        .send()
        .await
        .unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["revoked"], 1);
}

// ─── the gate ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn cors_and_the_tenant_gate() {
    let h = harness().await;
    let pre = h
        .http
        .request(reqwest::Method::OPTIONS, h.p("/signup/start"))
        .header("origin", ORIGIN)
        .header("access-control-request-method", "POST")
        .send()
        .await
        .unwrap();
    assert_eq!(pre.status(), StatusCode::NO_CONTENT);
    assert_eq!(pre.headers()["access-control-allow-origin"], ORIGIN);
    assert!(pre.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .contains("authorization"));

    let evil = h
        .http
        .request(reqwest::Method::OPTIONS, h.p("/signup/start"))
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(evil.status(), StatusCode::FORBIDDEN);
    let evil = h
        .http
        .post(h.p("/signup/start"))
        .header("origin", "https://evil.example")
        .json(&json!({ "email": "x@y.co" }))
        .send()
        .await
        .unwrap();
    assert_eq!(evil.status(), StatusCode::FORBIDDEN);
    assert!(h.mail.is_empty(), "a refused origin sends nothing");

    let ok = h
        .http
        .post(h.p("/signup/start"))
        .header("origin", ORIGIN)
        .json(&json!({ "email": "x@y.co" }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::ACCEPTED);
    assert_eq!(ok.headers()["access-control-allow-origin"], ORIGIN);

    let r = h
        .http
        .post(format!("{}/v1/p/pub_nope/signup/start", h.base))
        .json(&json!({ "email": "x@y.co" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn flow_errors_map_to_statuses() {
    let h = harness_with(|_| {}).await;
    let (s, e) = h
        .post("/signup/start", json!({ "email": "not-an-email" }))
        .await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_email"))
    );
    h.post("/signup/start", json!({ "email": "w@example.com" }))
        .await;
    let code = h.last_code();
    let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
    let (s, e) = h
        .post(
            "/signup/verify",
            json!({ "email": "w@example.com", "code": wrong }),
        )
        .await;
    assert_eq!(
        (s, e["error"].as_str(), e["attempts_left"].as_u64()),
        (StatusCode::UNAUTHORIZED, Some("wrong_code"), Some(4))
    );
    for _ in 0..4 {
        h.post(
            "/signup/verify",
            json!({ "email": "w@example.com", "code": wrong }),
        )
        .await;
    }
    let (s, e) = h
        .post(
            "/signup/verify",
            json!({ "email": "w@example.com", "code": code }),
        )
        .await;
    assert_eq!(
        (s, e["needs_new_code"].as_bool()),
        (StatusCode::GONE, Some(true)),
        "{e}"
    );
    let (s, _) = h
        .post(
            "/signup/verify",
            json!({ "email": "w@example.com", "code": "12" }),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn cooldown_and_resend_answer_alike_and_limits_say_retry_after() {
    let h = harness().await;
    let (s1, b1) = h
        .post("/signup/start", json!({ "email": "c@example.com" }))
        .await;
    let (s2, b2) = h
        .post("/signup/start", json!({ "email": "c@example.com" }))
        .await;
    assert_eq!((s1, s2), (StatusCode::ACCEPTED, StatusCode::ACCEPTED));
    assert_eq!(b1["status"], b2["status"]);
    assert_eq!(
        h.mail.take().len(),
        1,
        "inside the cooldown nothing is re-sent"
    );
    let (s, _) = h
        .post("/signup/resend", json!({ "email": "nobody@example.com" }))
        .await;
    assert_eq!(
        s,
        StatusCode::ACCEPTED,
        "no live code: the same answer, nothing sent"
    );
    assert!(h.mail.is_empty());

    // Per-address send limit: Retry-After on the wire.
    let tight = mid_sovereign_signup::Limits {
        per_address: Some(mid_sovereign_signup::RateRule::new(3_600, 1)),
        per_client: None,
        per_tenant: None,
    };
    let store = SignupStore::in_memory(Pepper::from_bytes([3; 32]))
        .unwrap()
        .with_policy(mid_sovereign_signup::Policy {
            resend_cooldown_secs: 0,
            ..Default::default()
        })
        .unwrap()
        .with_limits(tight);
    let now = SystemClock.now_secs();
    let t = Tenant::new(
        TenantId::parse("acme").unwrap(),
        "Acme",
        vec![],
        now,
        &mut OsEntropy,
    )
    .unwrap();
    store.create_tenant(&t).unwrap();
    let server = Arc::new(Server::new(
        Arc::new(store),
        Arc::new(StubMailer::new()),
        Arc::new(ServiceIdentity::from_secret([5; 32]).unwrap()),
        Arc::new(KeyDidResolver),
        Arc::new(mid_sovereign_signup::server::VolumeOnly),
        Arc::new(SystemClock),
        ServerConfig::default(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "http://{}/v1/p/{}",
        listener.local_addr().unwrap(),
        t.public_id
    );
    tokio::spawn(serve(server, listener, std::future::pending()));
    let c = Client::new();
    let go = || {
        c.post(format!("{base}/signup/start"))
            .json(&json!({ "email": "rl@example.com" }))
            .send()
    };
    assert_eq!(go().await.unwrap().status(), StatusCode::ACCEPTED);
    let r = go().await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        r.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 3_000
    );
}

// ─── backends and operators ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn backend_calls_need_a_fresh_assertion_for_that_exact_operation() {
    let h = harness().await;
    let (reader, reader_did) = signer(21);
    let (stranger, stranger_did) = signer(22);
    let op = h.operator_did.clone();
    let get = reqwest::Method::GET;
    let post = reqwest::Method::POST;
    let delete = reqwest::Method::DELETE;

    // The operator creates a tenant with a read-only member.
    let (s, t) = h
        .admin(
            &h.operator,
            &op,
            "signup.tenants.create",
            post.clone(),
            "/v1/admin/tenants",
            Some(json!({
                "id": "beta", "name": "Beta", "origins": ["https://beta.test"],
                "members": [{ "did": reader_did, "grants": ["users.read"] }]
            })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    assert!(t["public_id"].as_str().unwrap().starts_with("pub_"));
    let (s, _) = h
        .admin(
            &h.operator,
            &op,
            "signup.members.set",
            reqwest::Method::PUT,
            "/v1/admin/tenants/beta/members",
            Some(json!({
                "members": [{ "did": reader_did, "grants": ["users.fly"] }]
            })),
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "unknown grants are refused");

    // Users exist in acme; the reader is a member of beta only.
    h.sign_up("u1@example.com").await;
    let (s, list) = h
        .admin(
            &h.operator,
            &op,
            "signup.users.list",
            get.clone(),
            "/v1/admin/tenants/acme/users",
            None,
        )
        .await;
    assert_eq!(
        (s, list["users"].as_array().unwrap().len()),
        (StatusCode::OK, 1)
    );
    let uid = list["users"][0]["id"].as_str().unwrap().to_string();
    let (s, _) = h
        .admin(
            &reader,
            &reader_did,
            "signup.users.list",
            get.clone(),
            "/v1/admin/tenants/acme/users",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "membership is per tenant");
    let (s, l) = h
        .admin(
            &reader,
            &reader_did,
            "signup.users.list",
            get.clone(),
            "/v1/admin/tenants/beta/users",
            None,
        )
        .await;
    assert_eq!(
        (s, l["users"].as_array().unwrap().len()),
        (StatusCode::OK, 0)
    );
    let (s, _) = h
        .admin(
            &reader,
            &reader_did,
            "signup.users.delete",
            delete.clone(),
            "/v1/admin/tenants/beta/users/5a5a5a5a-5a5a-4a5a-9a5a-5a5a5a5a5a5a",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "read grant cannot delete");
    let (s, _) = h
        .admin(
            &stranger,
            &stranger_did,
            "signup.tenants.get",
            get.clone(),
            "/v1/admin/tenants/beta",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = h
        .admin(
            &reader,
            &reader_did,
            "signup.tenants.get",
            get.clone(),
            "/v1/admin/tenants/beta",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // An assertion minted for one operation cannot perform another.
    let list_auth = h.assertion(&h.operator, &op, "signup.users.list").await;
    let r = h
        .http
        .delete(format!("{}/v1/admin/tenants/acme/users/{uid}", h.base))
        .header("authorization", &list_auth)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // An assertion is single-use.
    let auth = h.assertion(&h.operator, &op, "signup.users.list").await;
    let first = h
        .http
        .get(format!("{}/v1/admin/tenants/acme/users", h.base))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    let replay = h
        .http
        .get(format!("{}/v1/admin/tenants/acme/users", h.base))
        .header("authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(
        (first.status(), replay.status()),
        (StatusCode::OK, StatusCode::UNAUTHORIZED)
    );
    // A signature by the wrong key for the DID is refused.
    let (s, _) = h
        .admin(
            &stranger,
            &op,
            "signup.users.list",
            get.clone(),
            "/v1/admin/tenants/acme/users",
            None,
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // The operator deletes; usage and audit read back.
    let (s, _) = h
        .admin(
            &h.operator,
            &op,
            "signup.users.delete",
            delete,
            &format!("/v1/admin/tenants/acme/users/{uid}"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, usage) = h
        .admin(
            &h.operator,
            &op,
            "signup.usage.read",
            get.clone(),
            "/v1/admin/tenants/acme/usage",
            None,
        )
        .await;
    assert_eq!(
        (
            usage["users"].as_u64(),
            usage["sign_ups"].as_u64(),
            usage["codes_sent"].as_u64()
        ),
        (Some(0), Some(1), Some(1))
    );
    let (_, audit) = h
        .admin(
            &h.operator,
            &op,
            "signup.audit.read",
            get,
            "/v1/admin/tenants/acme/audit",
            None,
        )
        .await;
    let kinds: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["event"]["kind"]["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"user_deleted"), "{kinds:?}");
    // Unknown purposes cannot even get a nonce.
    let r = h
        .http
        .post(format!("{}/v1/nonce", h.base))
        .json(&json!({ "did": op, "purpose": "signup.everything" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_declared_operation_is_routed() {
    let h = harness().await;
    for op in OPS {
        let path = op
            .path
            .replace(":tenant", "acme")
            .replace(":user", "5a5a5a5a-5a5a-4a5a-9a5a-5a5a5a5a5a5a")
            .replace(":webhook", "wh_x");
        let method = reqwest::Method::from_bytes(op.method.as_bytes()).unwrap();
        let r = h
            .http
            .request(method, format!("{}{}", h.base, path))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "{} {} ({}) must exist and demand an assertion",
            op.method,
            op.path,
            op.id
        );
        assert!(matches!(
            op.need,
            Need::Operator | Need::Member | Need::Grant(_)
        ));
    }
}

// ─── webhooks ────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn webhooks_arrive_signed_and_failures_retry() {
    use axum::routing::post;
    let h = harness().await;
    let got: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let receiver = {
        let (got, fail) = (got.clone(), fail.clone());
        axum::Router::new().route(
            "/hook",
            post(move |headers: axum::http::HeaderMap, body: String| {
                let (got, fail) = (got.clone(), fail.clone());
                async move {
                    if fail.load(Ordering::SeqCst) {
                        return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                    }
                    let sig = headers[webhook::SIGNATURE_HEADER]
                        .to_str()
                        .unwrap()
                        .to_string();
                    got.lock().unwrap().push((sig, body));
                    axum::http::StatusCode::OK
                }
            }),
        )
    };
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, receiver).await.unwrap() });

    let op = h.operator_did.clone();
    let (s, hook) = h
        .admin(
            &h.operator,
            &op,
            "signup.webhooks.add",
            reqwest::Method::POST,
            "/v1/admin/tenants/acme/webhooks",
            Some(json!({
                "url": url, "events": ["user.created", "user.verified"]
            })),
        )
        .await;
    assert_eq!(s, StatusCode::CREATED, "{hook}");
    let secret = hook["secret"].as_str().unwrap().to_string();
    let (_, t) = h
        .admin(
            &h.operator,
            &op,
            "signup.tenants.get",
            reqwest::Method::GET,
            "/v1/admin/tenants/acme",
            None,
        )
        .await;
    assert!(
        !t.to_string().contains(&secret),
        "the secret is shown once, never read back"
    );

    let user = h.sign_up("hooked@example.com").await;
    // The delivery loop is woken by the verify; give it a moment, then drain.
    for _ in 0..50 {
        if got.lock().unwrap().len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let received = got.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "user.created + user.verified");
    let now = h.server.now();
    for (sig, body) in &received {
        webhook::verify(&secret, sig, body.as_bytes(), now, 300)
            .expect("signed with the endpoint's secret");
        let v: Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["data"]["user"]["id"], user["user"]["id"]);
        assert_eq!(v["data"]["user"]["email"], "hooked@example.com");
    }
    assert!(webhook::verify("wrong", &received[0].0, received[0].1.as_bytes(), now, 300).is_err());

    // A failing endpoint keeps the event queued with a backoff.
    fail.store(true, Ordering::SeqCst);
    h.sign_up("second@example.com").await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(h.server.deliver_due().await, 0);
    assert_eq!(
        h.server.store().outbox_len().unwrap(),
        2,
        "queued, not lost"
    );
    assert_eq!(got.lock().unwrap().len(), 2);
}

// ─── the import door ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn the_import_door_keeps_ids_and_is_closed_without_a_token() {
    let closed = harness_with(|c| c.import_token = None).await;
    let r = closed
        .http
        .post(format!("{}/v1/import", closed.base))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND, "no token, no door");

    let h = harness().await;
    let body = json!({ "tenant": "acme", "users": [
        { "id": "11111111-1111-4111-8111-111111111111", "email": "Legacy@Example.com", "email_verified_at": 1700000000u64, "created_at": 1690000000u64, "username": "legacy" },
        { "id": "22222222-2222-4222-8222-222222222222", "email": "nope", "email_verified_at": null, "created_at": 1 },
    ]});
    let r = h
        .http
        .post(format!("{}/v1/import", h.base))
        .bearer_auth("wrong-token-wrong-token-wrong-token!!")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r: Value = h
        .http
        .post(format!("{}/v1/import", h.base))
        .bearer_auth(IMPORT_TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r["imported"], 1);
    assert_eq!(r["results"][1]["ok"], false);
    let again: Value = h
        .http
        .post(format!("{}/v1/import", h.base))
        .bearer_auth(IMPORT_TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        again["results"][0]["status"], "already_present",
        "re-running is safe"
    );
    assert_eq!(again["already_present"], 1);

    let signed = h.sign_up("legacy@example.com").await;
    assert_eq!(
        signed["user"]["id"], "11111111-1111-4111-8111-111111111111",
        "the uuid survives the migration"
    );
    assert_eq!(signed["user"]["username"], "legacy");
    assert_eq!(signed["user_created"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_reports_the_posture() {
    let h = harness().await;
    h.sign_up("h@example.com").await;
    let v: Value = h
        .http
        .get(format!("{}/healthz", h.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["durability"], "test-tier");
    assert_eq!(
        (v["tenants"].as_u64(), v["users"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(v["import_enabled"], true);
    assert_eq!(v["mail"], "stub");
    assert_eq!(v["attestation_issuer"], h.server.identity().did());
    assert!(v["height"].as_u64().unwrap() >= 4);
}

// ─── the shipped binary ──────────────────────────────────────────────────────

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn field(line: &str, key: &str) -> Option<String> {
    let start = line.find(&format!("{key}="))? + key.len() + 1;
    Some(
        line[start..]
            .split_whitespace()
            .next()?
            .trim_matches('"')
            .to_string(),
    )
}

async fn wait_for(rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>, needle: &str) -> String {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let l = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out waiting for the daemon")
            .expect("daemon exited");
        if l.contains(needle) {
            return l;
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_signupd_binary_signs_a_user_up_over_tcp() {
    use tokio::io::AsyncBufReadExt;
    let dir = tempfile::tempdir().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_signupd"))
        .env("SIGNUP_BIND", format!("127.0.0.1:{port}"))
        .env("SIGNUP_DB", dir.path())
        .env("SIGNUP_PEPPER", "11".repeat(32))
        .env("SIGNUP_BOOTSTRAP_TENANTS", format!("acme|Acme|{ORIGIN}"))
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .env_remove("SES_FROM_ADDRESS")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let (lines_tx, mut lines_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Ok(Some(l)) = lines.next_line().await {
            let _ = lines_tx.send(strip_ansi(&l));
        }
    });
    let ready = wait_for(&mut lines_rx, "tenant ready").await;
    let public_id = field(&ready, "public_id").expect("the public id is logged");
    wait_for(&mut lines_rx, "listening").await;

    let base = format!("http://127.0.0.1:{port}");
    let c = Client::new();
    let r = c
        .post(format!("{base}/v1/p/{public_id}/signup/start"))
        .header("origin", ORIGIN)
        .json(&json!({ "email": "bin@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let stub = wait_for(&mut lines_rx, "[Email STUB]").await;
    let code = field(&stub, "code").expect("the stub logs the code");
    let v: Value = c
        .post(format!("{base}/v1/p/{public_id}/signup/verify"))
        .json(&json!({ "email": "bin@example.com", "code": code }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["user"]["email"], "bin@example.com", "{v}");
    let health: Value = c
        .get(format!("{base}/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        (
            health["users"].as_u64(),
            health["durability"].as_str(),
            health["mail"].as_str()
        ),
        (Some(1), Some("volume-only"), Some("log-stub"))
    );
    assert!(dir.path().join("identity.key").exists() && dir.path().join("signup.key").exists());
    child.kill().await.unwrap();

    // Refusal: no pepper → exit 2 with a sentence.
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_signupd"))
        .env("SIGNUP_DB", dir.path().join("other"))
        .env_remove("SIGNUP_PEPPER")
        .output()
        .await
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("SIGNUP_PEPPER"));
}

#[allow(dead_code)]
fn _unused(_: BTreeMap<String, String>) {}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_sign_up_gets_one_welcome_and_a_sign_in_none() {
    let h = harness_with(|c| c.welcome_delay_secs = 0).await;
    h.sign_up("welcome@example.com").await;
    for _ in 0..100 {
        if !h.mail.welcomes().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let w = h.mail.welcomes();
    assert_eq!(w.len(), 1, "one welcome after the first sign-up");
    assert_eq!(w[0].to.as_str(), "welcome@example.com");
    // Signing in again: no second welcome.
    h.sign_up("welcome@example.com").await;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(h.mail.welcomes().len(), 1);
}
