//! The headless client (feature `client`) — wasm32 and native.
//!
//! Typed calls to a sign-up server, typed errors, and a session seam. No UI:
//! an app draws its own screens and calls these. One [`SignupClient`] talks
//! to one tenant: its base URL is the tenant's public path,
//! `https://signup.example.com/v1/p/<public_id>`.
//!
//! ```ignore
//! let c = SignupClient::new("https://signup.example.com/v1/p/pub_…");
//! c.start("alice@example.com", true).await?;
//! let v = c.verify("alice@example.com", "123456").await?;   // user + session + attestation
//! store.save(&v.session)?;                                   // a SessionStore of your choice
//! let me = c.me(&v.session.token).await?;
//! ```
//!
//! The transport is a seam ([`Transport`]): [`HttpTransport`] (reqwest —
//! `fetch` on wasm32, rustls natively) for real use, [`MockTransport`] for
//! tests that should not touch a socket.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::seams::BoxFuture;

// ─── wire types ──────────────────────────────────────────────────────────────

/// A user, as the server shows them to themselves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    /// The user id (UUID).
    pub id: String,
    /// The verified address.
    pub email: String,
    /// When the address was first proven, Unix seconds.
    pub email_verified_at: Option<u64>,
    /// The username, if set.
    #[serde(default)]
    pub username: Option<String>,
    /// A linked `did:mata`, if any.
    #[serde(default)]
    pub linked_did: Option<String>,
    /// Tenant-defined metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds.
    #[serde(default)]
    pub last_sign_in_at: Option<u64>,
}

/// An opaque session pair. `Debug` prints neither token.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSession {
    /// `sess_…` — `Authorization: Bearer`.
    pub token: String,
    /// `ref_…` — exchanged once for a new pair.
    pub refresh: String,
    /// Access expiry, Unix seconds.
    pub expires_at: u64,
    /// Refresh expiry, Unix seconds.
    pub refresh_expires_at: u64,
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession")
            .field("expires_at", &self.expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// The access token expires within `slack_secs` of `now`.
    pub fn expiring(&self, now: u64, slack_secs: u64) -> bool {
        self.expires_at <= now.saturating_add(slack_secs)
    }
}

/// A successful verify.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifiedSignup {
    /// The user.
    pub user: UserInfo,
    /// The session the verify opened.
    pub session: ClientSession,
    /// A `mata-sign` attestation of the verified address (minutes-long;
    /// fetch a fresh one with [`SignupClient::attestation`]).
    pub attestation: String,
    /// The service DID that signed it — pin it where you verify.
    pub attestation_issuer: String,
    /// The verify created the user.
    pub user_created: bool,
    /// The verify was the address's first proof.
    pub first_verification: bool,
}

/// A fresh attestation.
#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    /// The token.
    pub attestation: String,
    /// Its issuer.
    pub attestation_issuer: String,
}

/// A `PATCH /users/me` body: `None` leaves a field alone; `username:
/// Some(None)` clears it.
#[derive(Debug, Clone, Default)]
pub struct UserPatch {
    /// Replace the metadata.
    pub metadata: Option<BTreeMap<String, Value>>,
    /// Set (`Some(Some(name))`) or clear (`Some(None)`) the username.
    pub username: Option<Option<String>>,
}

// ─── errors ──────────────────────────────────────────────────────────────────

/// What a call can fail with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The server could not be reached.
    #[error("network: {0}")]
    Network(String),
    /// The server answered with an error.
    #[error("{code}: {message}")]
    Api {
        /// HTTP status.
        status: u16,
        /// The server's stable error code (`wrong_code`, `rate_limited`, …).
        code: String,
        /// The server's message.
        message: String,
        /// Guesses left, on `wrong_code`.
        attempts_left: Option<u32>,
        /// Seconds to wait, on `rate_limited`.
        retry_after_secs: Option<u64>,
        /// The only way forward is a new code.
        needs_new_code: bool,
    },
    /// The server's answer did not parse.
    #[error("unexpected response: {0}")]
    Decode(String),
}

impl ClientError {
    /// The server's error code, or `network` / `decode`.
    pub fn code(&self) -> &str {
        match self {
            ClientError::Network(_) => "network",
            ClientError::Decode(_) => "decode",
            ClientError::Api { code, .. } => code,
        }
    }

    /// The session is gone; sign in again.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, ClientError::Api { status: 401, code, .. } if code != "wrong_code")
    }
}

// ─── transport ───────────────────────────────────────────────────────────────

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
    /// PATCH
    Patch,
}

/// One request.
#[derive(Debug, Clone)]
pub struct ApiRequest {
    /// Method.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// `Authorization: Bearer` value.
    pub bearer: Option<String>,
    /// JSON body.
    pub body: Option<Value>,
}

/// One response.
#[derive(Debug, Clone)]
pub struct ApiResponse {
    /// HTTP status.
    pub status: u16,
    /// JSON body (`Null` when empty).
    pub body: Value,
}

/// Moves a request and its response. Implement over anything that speaks
/// HTTP; [`HttpTransport`] is reqwest.
pub trait Transport {
    /// Send one request.
    fn send(&self, req: ApiRequest) -> BoxFuture<'_, Result<ApiResponse, String>>;
}

/// reqwest: `fetch` on wasm32, rustls natively.
#[derive(Debug, Clone, Default)]
pub struct HttpTransport {
    http: reqwest::Client,
}

impl HttpTransport {
    /// Wrap a configured client (timeouts, user agent, …).
    pub fn with_client(http: reqwest::Client) -> Self {
        Self { http }
    }
}

impl Transport for HttpTransport {
    fn send(&self, req: ApiRequest) -> BoxFuture<'_, Result<ApiResponse, String>> {
        Box::pin(async move {
            let mut rb = match req.method {
                Method::Get => self.http.get(&req.url),
                Method::Post => self.http.post(&req.url),
                Method::Patch => self.http.patch(&req.url),
            };
            if let Some(t) = &req.bearer {
                rb = rb.bearer_auth(t);
            }
            if let Some(b) = &req.body {
                rb = rb.json(b);
            }
            let resp = rb.send().await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let text = resp.text().await.map_err(|e| e.to_string())?;
            let body = if text.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&text).unwrap_or(Value::String(text))
            };
            Ok(ApiResponse { status, body })
        })
    }
}

type Handler = Box<dyn Fn(&ApiRequest) -> ApiResponse + Send + Sync>;

/// A scripted transport for tests: a handler answers every request, and
/// every request is recorded.
pub struct MockTransport {
    handler: Handler,
    seen: Mutex<Vec<ApiRequest>>,
}

impl MockTransport {
    /// Answer every request with `handler`.
    pub fn new(handler: impl Fn(&ApiRequest) -> ApiResponse + Send + Sync + 'static) -> Self {
        Self {
            handler: Box::new(handler),
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Requests sent so far.
    pub fn requests(&self) -> Vec<ApiRequest> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Transport for MockTransport {
    fn send(&self, req: ApiRequest) -> BoxFuture<'_, Result<ApiResponse, String>> {
        let resp = (self.handler)(&req);
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(req);
        Box::pin(async move { Ok(resp) })
    }
}

// ─── the client ──────────────────────────────────────────────────────────────

/// Calls for one tenant. See the module docs.
#[derive(Debug, Clone)]
pub struct SignupClient<T: Transport = HttpTransport> {
    base: String,
    transport: T,
}

impl SignupClient<HttpTransport> {
    /// A client for the tenant at `base` (`…/v1/p/<public_id>`).
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_transport(base, HttpTransport::default())
    }
}

impl<T: Transport> SignupClient<T> {
    /// A client over any transport.
    pub fn with_transport(base: impl Into<String>, transport: T) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            transport,
        }
    }

    /// The tenant base URL.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The transport (e.g. a [`MockTransport`] to inspect).
    pub fn transport(&self) -> &T {
        &self.transport
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> Result<Value, ClientError> {
        let req = ApiRequest {
            method,
            url: format!("{}{}", self.base, path),
            bearer: bearer.map(str::to_string),
            body,
        };
        let resp = self
            .transport
            .send(req)
            .await
            .map_err(ClientError::Network)?;
        if (200..300).contains(&resp.status) {
            return Ok(resp.body);
        }
        let b = &resp.body;
        Err(ClientError::Api {
            status: resp.status,
            code: b["error"].as_str().unwrap_or("http_error").to_string(),
            message: b["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("HTTP {}", resp.status)),
            attempts_left: b["attempts_left"].as_u64().map(|n| n as u32),
            retry_after_secs: b["retry_after_secs"].as_u64(),
            needs_new_code: b["needs_new_code"].as_bool().unwrap_or(false),
        })
    }

    fn decode<V: serde::de::DeserializeOwned>(v: Value) -> Result<V, ClientError> {
        serde_json::from_value(v).map_err(|e| ClientError::Decode(e.to_string()))
    }

    /// Send a code. Answers alike whether a code went out or the address is
    /// in its resend cooldown; returns the seconds until a resend can go.
    pub async fn start(&self, email: &str, create_user: bool) -> Result<u64, ClientError> {
        let v = self
            .call(
                Method::Post,
                "/signup/start",
                None,
                Some(json!({ "email": email, "create_user": create_user })),
            )
            .await?;
        Ok(v["resend_after_secs"].as_u64().unwrap_or(0))
    }

    /// Re-send to an address with a live code.
    pub async fn resend(&self, email: &str) -> Result<u64, ClientError> {
        let v = self
            .call(
                Method::Post,
                "/signup/resend",
                None,
                Some(json!({ "email": email })),
            )
            .await?;
        Ok(v["resend_after_secs"].as_u64().unwrap_or(0))
    }

    /// Check a code: the user, a session, and an attestation.
    pub async fn verify(&self, email: &str, code: &str) -> Result<VerifiedSignup, ClientError> {
        let v = self
            .call(
                Method::Post,
                "/signup/verify",
                None,
                Some(json!({ "email": email, "code": code })),
            )
            .await?;
        Self::decode(v)
    }

    /// Is the username free in this tenant?
    pub async fn username_available(&self, username: &str) -> Result<bool, ClientError> {
        let v = self
            .call(
                Method::Post,
                "/username/check",
                None,
                Some(json!({ "username": username })),
            )
            .await?;
        v["available"]
            .as_bool()
            .ok_or_else(|| ClientError::Decode("no `available`".into()))
    }

    /// The signed-in user.
    pub async fn me(&self, token: &str) -> Result<UserInfo, ClientError> {
        Self::decode(
            self.call(Method::Get, "/users/me", Some(token), None)
                .await?,
        )
    }

    /// Who referred me, how many I referred, my share (`GET /users/me/referrals`).
    pub async fn referrals(&self, token: &str) -> Result<crate::referrals::ReferralStats, ClientError> {
        Self::decode(
            self.call(Method::Get, "/users/me/referrals", Some(token), None)
                .await?,
        )
    }

    /// Change metadata and/or username.
    pub async fn update_me(&self, token: &str, patch: &UserPatch) -> Result<UserInfo, ClientError> {
        let mut body = serde_json::Map::new();
        if let Some(m) = &patch.metadata {
            body.insert("metadata".into(), json!(m));
        }
        if let Some(u) = &patch.username {
            body.insert("username".into(), json!(u));
        }
        Self::decode(
            self.call(
                Method::Patch,
                "/users/me",
                Some(token),
                Some(Value::Object(body)),
            )
            .await?,
        )
    }

    /// Exchange a refresh token for a new pair (the old pair dies).
    pub async fn refresh(&self, refresh: &str) -> Result<ClientSession, ClientError> {
        Self::decode(
            self.call(
                Method::Post,
                "/session/refresh",
                None,
                Some(json!({ "refresh": refresh })),
            )
            .await?,
        )
    }

    /// End this session.
    pub async fn logout(&self, token: &str) -> Result<(), ClientError> {
        self.call(Method::Post, "/session/logout", Some(token), None)
            .await
            .map(|_| ())
    }

    /// End every session of this user; returns how many.
    pub async fn logout_all(&self, token: &str) -> Result<u64, ClientError> {
        let v = self
            .call(Method::Post, "/session/logout-all", Some(token), None)
            .await?;
        Ok(v["revoked"].as_u64().unwrap_or(0))
    }

    /// A fresh attestation for the signed-in user.
    pub async fn attestation(&self, token: &str) -> Result<Attestation, ClientError> {
        Self::decode(
            self.call(Method::Get, "/attestation", Some(token), None)
                .await?,
        )
    }
}

// ─── sessions at rest ────────────────────────────────────────────────────────

/// Where a session lives between runs.
pub trait SessionStore {
    /// The saved session, if any.
    fn load(&self) -> Result<Option<ClientSession>, String>;
    /// Save (replace) the session.
    fn save(&self, session: &ClientSession) -> Result<(), String>;
    /// Forget it.
    fn clear(&self) -> Result<(), String>;
}

/// A session that lives only as long as the process.
#[derive(Debug, Default)]
pub struct MemorySessionStore(Mutex<Option<ClientSession>>);

impl SessionStore for MemorySessionStore {
    fn load(&self) -> Result<Option<ClientSession>, String> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }
    fn save(&self, session: &ClientSession) -> Result<(), String> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(session.clone());
        Ok(())
    }
    fn clear(&self) -> Result<(), String> {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use sealed::SealedFileSessionStore;
pub use sealed::{key_from_passphrase, open, seal, SealError, SEALED_VERSION};

mod sealed {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    use argon2::{Algorithm, Argon2, Params, Version};

    /// Envelope version byte.
    pub const SEALED_VERSION: u8 = 1;
    const AAD: &[u8] = b"mid-sovereign-signup/session/v1";
    const NONCE_LEN: usize = 12;
    // The wallet's Argon2id parameters (m = 64 MiB, t = 4, p = 4): a
    // passphrase-derived key costs an attacker what a vault passphrase does.
    const ARGON_M_KIB: u32 = 65_536;
    const ARGON_T: u32 = 4;
    const ARGON_P: u32 = 4;

    /// Why sealed bytes would not open.
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum SealError {
        /// Too short, or an unknown version.
        #[error("not a sealed session (or an unsupported version)")]
        Malformed,
        /// Wrong key, or the bytes were changed.
        #[error("wrong key, or the sealed session was altered")]
        Rejected,
        /// No randomness for the nonce.
        #[error("no randomness available")]
        Random,
    }

    /// `version ‖ nonce ‖ AES-256-GCM(plaintext)`, with a fixed domain tag as
    /// associated data.
    pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|_| SealError::Random)?;
        let cipher = Aes256Gcm::new(key.into());
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| SealError::Rejected)?;
        let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
        out.push(SEALED_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open what [`seal`] produced.
    pub fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
        if sealed.len() < 1 + NONCE_LEN + 16 || sealed[0] != SEALED_VERSION {
            return Err(SealError::Malformed);
        }
        let (nonce, ct) = sealed[1..].split_at(NONCE_LEN);
        Aes256Gcm::new(key.into())
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: AAD })
            .map_err(|_| SealError::Rejected)
    }

    /// A 32-byte key from a passphrase (Argon2id, the wallet's parameters).
    /// Slow on purpose; derive once and keep the key in memory.
    pub fn key_from_passphrase(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
        let params =
            Params::new(ARGON_M_KIB, ARGON_T, ARGON_P, Some(32)).map_err(|e| e.to_string())?;
        let mut out = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }

    /// A session sealed in one file. Writes go to a temporary file first and
    /// are renamed into place, so a crash never leaves half a session.
    #[cfg(not(target_arch = "wasm32"))]
    pub struct SealedFileSessionStore {
        path: std::path::PathBuf,
        key: [u8; 32],
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl SealedFileSessionStore {
        /// Seal at `path` under `key`.
        pub fn new(path: impl Into<std::path::PathBuf>, key: [u8; 32]) -> Self {
            Self {
                path: path.into(),
                key,
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl std::fmt::Debug for SealedFileSessionStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SealedFileSessionStore")
                .field("path", &self.path)
                .finish_non_exhaustive()
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl super::SessionStore for SealedFileSessionStore {
        fn load(&self) -> Result<Option<super::ClientSession>, String> {
            let bytes = match std::fs::read(&self.path) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.to_string()),
            };
            let plain = open(&self.key, &bytes).map_err(|e| e.to_string())?;
            serde_json::from_slice(&plain)
                .map(Some)
                .map_err(|e| e.to_string())
        }

        fn save(&self, session: &super::ClientSession) -> Result<(), String> {
            let plain = serde_json::to_vec(session).map_err(|e| e.to_string())?;
            let sealed = seal(&self.key, &plain).map_err(|e| e.to_string())?;
            if let Some(dir) = self.path.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            let tmp = self.path.with_extension("tmp");
            std::fs::write(&tmp, &sealed).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
        }

        fn clear(&self) -> Result<(), String> {
            match std::fs::remove_file(&self.path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(body: Value) -> ApiResponse {
        ApiResponse { status: 200, body }
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = std::pin::pin!(f);
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn requests_are_shaped_as_the_server_expects() {
        let c = SignupClient::with_transport(
            "https://s.test/v1/p/pub_x/",
            MockTransport::new(|r| match r.url.rsplit('/').next().unwrap() {
                "start" => ApiResponse {
                    status: 202,
                    body: json!({ "status": "accepted", "resend_after_secs": 60 }),
                },
                "check" => ok(json!({ "available": false })),
                "me" => ok(
                    json!({ "id": "u", "email": "a@b.co", "email_verified_at": 1, "created_at": 1, "username": "al" }),
                ),
                _ => ok(Value::Null),
            }),
        );
        assert_eq!(block(c.start("a@b.co", true)).unwrap(), 60);
        assert!(!block(c.username_available("al")).unwrap());
        let me = block(c.update_me(
            "sess_t",
            &UserPatch {
                username: Some(None),
                ..Default::default()
            },
        ))
        .unwrap();
        assert_eq!(me.username.as_deref(), Some("al"));
        let seen = c.transport().requests();
        assert_eq!(seen[0].url, "https://s.test/v1/p/pub_x/signup/start");
        assert_eq!(seen[0].body.as_ref().unwrap()["create_user"], true);
        assert_eq!(seen[2].method, Method::Patch);
        assert_eq!(seen[2].bearer.as_deref(), Some("sess_t"));
        assert_eq!(
            seen[2].body.as_ref().unwrap(),
            &json!({ "username": null }),
            "only the named fields are sent"
        );
    }

    #[test]
    fn server_errors_become_typed_errors() {
        let c = SignupClient::with_transport(
            "https://s.test/v1/p/pub_x",
            MockTransport::new(|r| {
                if r.url.ends_with("/verify") {
                    ApiResponse {
                        status: 401,
                        body: json!({ "error": "wrong_code", "message": "wrong code (3 attempts left)", "attempts_left": 3 }),
                    }
                } else if r.url.ends_with("/me") {
                    ApiResponse {
                        status: 401,
                        body: json!({ "error": "unauthorized", "message": "no" }),
                    }
                } else {
                    ApiResponse {
                        status: 429,
                        body: json!({ "error": "rate_limited", "message": "slow down", "retry_after_secs": 30 }),
                    }
                }
            }),
        );
        let e = block(c.verify("a@b.co", "000000")).unwrap_err();
        assert_eq!(e.code(), "wrong_code");
        assert!(matches!(
            e,
            ClientError::Api {
                attempts_left: Some(3),
                ..
            }
        ));
        assert!(!e.is_unauthorized(), "a wrong code is not a lost session");
        assert!(block(c.me("sess_x")).unwrap_err().is_unauthorized());
        assert!(matches!(
            block(c.start("a@b.co", true)).unwrap_err(),
            ClientError::Api {
                retry_after_secs: Some(30),
                ..
            }
        ));
    }

    #[test]
    fn sealing_round_trips_and_refuses_tampering() {
        let key = [7u8; 32];
        let s = seal(&key, b"hello").unwrap();
        assert_eq!(open(&key, &s).unwrap(), b"hello");
        assert_ne!(seal(&key, b"hello").unwrap(), s, "fresh nonce every time");
        assert_eq!(open(&[8u8; 32], &s).unwrap_err(), SealError::Rejected);
        let mut bad = s.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, &bad).unwrap_err(), SealError::Rejected);
        assert_eq!(open(&key, &s[..5]).unwrap_err(), SealError::Malformed);
        let k1 = key_from_passphrase("correct horse", &[1; 16]).unwrap();
        assert_eq!(k1, key_from_passphrase("correct horse", &[1; 16]).unwrap());
        assert_ne!(k1, key_from_passphrase("correct horse", &[2; 16]).unwrap());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn the_sealed_file_store_never_writes_a_token_in_clear() {
        let dir = std::env::temp_dir().join(format!("mss-client-{}", std::process::id()));
        let path = dir.join("session.sealed");
        let store = SealedFileSessionStore::new(&path, [9u8; 32]);
        assert!(store.load().unwrap().is_none());
        let s = ClientSession {
            token: "sess_SECRETTOKEN".into(),
            refresh: "ref_SECRETREFRESH".into(),
            expires_at: 10,
            refresh_expires_at: 20,
        };
        store.save(&s).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(6).any(|w| w == b"SECRET"));
        assert_eq!(store.load().unwrap().unwrap(), s);
        assert!(
            SealedFileSessionStore::new(&path, [1u8; 32])
                .load()
                .is_err(),
            "another key reads nothing"
        );
        assert!(!format!("{s:?}").contains("SECRET"));
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
