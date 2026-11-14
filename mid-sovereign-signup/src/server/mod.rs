//! The HTTP service (feature `server`): the store behind an API.
//!
//! Three kinds of caller, three kinds of proof, and no API keys:
//!
//! | Caller | Proves itself with | Routes |
//! |---|---|---|
//! | A page or app on the tenant's site | the tenant's **public id** in the path, the tenant's **origin allow-list**, and the send limits | `/v1/p/:public_id/signup/{start,resend,verify}`, `/username/check` |
//! | A signed-in end user | an opaque **session** (`Authorization: Bearer sess_…`), rotated by refresh, revocable | `/v1/p/:public_id/users/me`, `/session/*`, `/attestation` |
//! | The tenant's backend, or the operator | a **signed assertion** per request (`Authorization: Signup-Assertion <base64url JSON>`) over a server-minted single-use nonce whose *purpose is the operation*, by a `did:mata` the tenant lists as a member with the needed grant (or an operator DID) | `/v1/nonce`, `/v1/admin/…` |
//!
//! Plus a migration door (`POST /v1/import`, a bearer token that exists only
//! while importing; closed = 404) and `GET /healthz`.
//!
//! The browser routes carry the public id **in the path** so a CORS preflight
//! — which carries neither body nor credentials — can still be answered for
//! the right tenant.
//!
//! Every store call runs on the blocking pool (redb fsyncs). A verify that
//! creates or signs in a user returns only after the snapshot tier was asked
//! to land the new state (a tier failure is logged and counted, never fatal —
//! the volume already holds the fsync'd write).

mod admin;
pub mod env;
mod identity;
mod public;
mod resolve;
mod worker;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::seams::{BoxFuture, CodeMessage, MailError, Mailer};
use crate::store::{SessionTtl, SignupStore, StoreEngine, StoreError};
use crate::FlowError;

pub use admin::{Need, Op, ADMIN_GRANTS, OPS};
pub use identity::ServiceIdentity;
pub use kms_verifier::{Clock, DidResolver, SystemClock};
pub use resolve::{ChainResolver, KeyDidResolver, KEY_DID_DEVICE_ID};

/// The header carrying a backend's signed assertion scheme.
pub const ASSERTION_SCHEME: &str = "Signup-Assertion";

// ─── the snapshot seam ───────────────────────────────────────────────────────

/// Off-box durability. The open server ships [`VolumeOnly`]; an operator
/// plugs in a tier that seals and ships [`SignupStore::dump`] (MATA's lands
/// erasure-coded, encrypted snapshots in R2).
pub trait SnapshotTier: Send + Sync {
    /// For `/healthz`: `"volume-only"`, `"r2:<bucket>"`, …
    fn posture(&self) -> String;
    /// The last height landed off-box (0 = none).
    fn height(&self) -> u64;
    /// Landings that failed since boot.
    fn failures(&self) -> u64;
    /// Land the current state if it changed. Blocking; called off the async
    /// workers. `Ok(None)` = nothing to land.
    fn land(&self, now_unix: u64) -> Result<Option<u64>, String>;
}

/// No off-box copy: the volume is the only durability. Fine for a local
/// shape; say so in `/healthz`.
#[derive(Debug, Default, Clone, Copy)]
pub struct VolumeOnly;

impl SnapshotTier for VolumeOnly {
    fn posture(&self) -> String {
        "volume-only".into()
    }
    fn height(&self) -> u64 {
        0
    }
    fn failures(&self) -> u64 {
        0
    }
    fn land(&self, _now_unix: u64) -> Result<Option<u64>, String> {
        Ok(None)
    }
}

// ─── a mailer for operators with no mail provider ────────────────────────────

/// Logs each code (`[Email STUB]`) instead of sending it — how a local or
/// pre-launch operator reads codes. **Never** run it where the log is not
/// yours alone: the log line carries a live code.
#[derive(Debug, Default, Clone, Copy)]
pub struct LogMailer;

impl Mailer for LogMailer {
    fn send_code(&self, msg: CodeMessage) -> BoxFuture<'_, Result<(), MailError>> {
        tracing::warn!(
            target: "mid_sovereign_signup::mail",
            to = ?msg.to,
            tenant = %msg.tenant,
            code = %msg.code,
            "[Email STUB] would send a sign-in code (no mail provider configured)"
        );
        Box::pin(async { Ok(()) })
    }
    fn kind(&self) -> &'static str {
        "log-stub"
    }
}

// ─── configuration and state ─────────────────────────────────────────────────

/// What the server needs beyond its parts.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Session lifetimes.
    pub session_ttl: SessionTtl,
    /// DIDs holding `signup:operator` (create tenants, set members, read
    /// anything).
    pub operators: Vec<String>,
    /// Opens `POST /v1/import` while set (≥ 32 characters). `None` = the door
    /// does not exist.
    pub import_token: Option<String>,
    /// A trusted proxy header carrying the client address (e.g.
    /// `fly-client-ip`); `None` = the socket peer.
    pub client_ip_header: Option<String>,
    /// The assertion audience (what a backend's nonce is minted for).
    pub assertion_audience: String,
    /// The assertion issuer (this server's name in its nonces).
    pub assertion_issuer: String,
    /// Land a snapshot before answering a successful verify.
    pub land_on_verify: bool,
    /// Seconds after a first sign-up before the welcome email is sent (the
    /// client sets the username right after verify; the welcome greets it).
    pub welcome_delay_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            session_ttl: SessionTtl::DEFAULT,
            operators: Vec::new(),
            import_token: None,
            client_ip_header: None,
            assertion_audience: "mid-sovereign-signup".into(),
            assertion_issuer: "mid-sovereign-signup".into(),
            land_on_verify: true,
            welcome_delay_secs: 20,
        }
    }
}

/// The running service: the store and every seam around it.
pub struct Server<E: StoreEngine + 'static> {
    pub(crate) store: Arc<SignupStore<E>>,
    pub(crate) mailer: Arc<dyn Mailer + Send + Sync>,
    pub(crate) identity: Arc<ServiceIdentity>,
    pub(crate) verifier: kms_verifier::Verifier,
    pub(crate) tier: Arc<dyn SnapshotTier>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) cfg: ServerConfig,
    pub(crate) mail_sent: AtomicU64,
    pub(crate) mail_failures: AtomicU64,
    pub(crate) wake: tokio::sync::Notify,
    pub(crate) http: reqwest::Client,
}

impl<E: StoreEngine + 'static> Server<E> {
    /// Assemble a server. `resolver` resolves the DIDs that sign backend
    /// assertions ([`KeyDidResolver`] needs no network).
    pub fn new(
        store: Arc<SignupStore<E>>,
        mailer: Arc<dyn Mailer + Send + Sync>,
        identity: Arc<ServiceIdentity>,
        resolver: Arc<dyn DidResolver>,
        tier: Arc<dyn SnapshotTier>,
        clock: Arc<dyn Clock>,
        cfg: ServerConfig,
    ) -> Self {
        let purposes = OPS.iter().map(|op| op.id.to_string());
        let verifier = kms_verifier::Verifier::new(
            cfg.assertion_issuer.clone(),
            cfg.assertion_audience.clone(),
            purposes,
            Arc::new(kms_verifier::InMemoryNonceStore::new()),
            resolver,
        )
        .with_clock(clock.clone())
        .with_nonce_ttl_secs(60);
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("an HTTP client with no custom TLS always builds");
        Self {
            store,
            mailer,
            identity,
            verifier,
            tier,
            clock,
            cfg,
            mail_sent: AtomicU64::new(0),
            mail_failures: AtomicU64::new(0),
            wake: tokio::sync::Notify::new(),
            http,
        }
    }

    /// The store.
    pub fn store(&self) -> &Arc<SignupStore<E>> {
        &self.store
    }

    /// The service identity that signs attestations.
    pub fn identity(&self) -> &ServiceIdentity {
        &self.identity
    }

    /// The server's clock, Unix seconds.
    pub fn now(&self) -> u64 {
        self.clock.now_secs()
    }

    /// Ask the snapshot tier to land the current state (blocking pool).
    /// Failures are logged and counted by the tier, never returned.
    pub async fn land_snapshot(self: &Arc<Self>) {
        let s = self.clone();
        let now = self.now();
        match blocking(move || s.tier.land(now)).await {
            Ok(Some(h)) => tracing::info!(height = h, "snapshot landed"),
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "snapshot landing failed (the volume still holds the write)")
            }
        }
    }
}

/// Run a store call on the blocking pool.
pub(crate) async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| std::panic::resume_unwind(e.into_panic()))
}

// ─── errors on the wire ──────────────────────────────────────────────────────

/// An error response: `{ "error": <stable code>, "message": …, …extra }`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after: Option<u64>,
    extra: Option<serde_json::Value>,
}

impl ApiError {
    pub(crate) fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
            extra: None,
        }
    }

    pub(crate) fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing or invalid credentials",
        )
    }

    pub(crate) fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this identity may not do that here",
        )
    }

    pub(crate) fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub(crate) fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "internal error");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
        )
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        let code = e.code();
        if let StoreError::Flow(f) = &e {
            return flow_error(f, code);
        }
        let status = match &e {
            StoreError::UnknownTenant(_)
            | StoreError::UserNotFound
            | StoreError::WebhookNotFound => StatusCode::NOT_FOUND,
            StoreError::TenantExists(_)
            | StoreError::PublicIdTaken
            | StoreError::UserIdTaken
            | StoreError::EmailTaken
            | StoreError::DidTaken
            | StoreError::UsernameTaken => StatusCode::CONFLICT,
            StoreError::SessionInvalid => StatusCode::UNAUTHORIZED,
            StoreError::InvalidConfig(_) | StoreError::Immutable(_) => StatusCode::BAD_REQUEST,
            _ => return ApiError::internal(&e),
        };
        ApiError::new(status, code, e.to_string())
    }
}

fn flow_error(f: &FlowError, code: &'static str) -> ApiError {
    let status = match f {
        FlowError::InvalidEmail(_)
        | FlowError::InvalidCode(_)
        | FlowError::InvalidDid
        | FlowError::InvalidUsername => StatusCode::BAD_REQUEST,
        FlowError::ResendTooSoon { .. } | FlowError::RateLimited { .. } => {
            StatusCode::TOO_MANY_REQUESTS
        }
        FlowError::WrongCode { .. } => StatusCode::UNAUTHORIZED,
        FlowError::NoLiveChallenge
        | FlowError::Expired
        | FlowError::AttemptsExhausted
        | FlowError::AlreadyConsumed => StatusCode::GONE,
        FlowError::UnknownUser => StatusCode::FORBIDDEN,
        FlowError::DidAlreadyLinked { .. } => StatusCode::CONFLICT,
        FlowError::NotVerified => StatusCode::FORBIDDEN,
        _ => return ApiError::internal(f),
    };
    let mut err = ApiError::new(status, code, f.to_string());
    match f {
        FlowError::ResendTooSoon { retry_after_secs }
        | FlowError::RateLimited { retry_after_secs } => {
            err.retry_after = Some(*retry_after_secs);
        }
        FlowError::WrongCode { attempts_left } => {
            err.extra = Some(json!({ "attempts_left": attempts_left }));
        }
        _ => {}
    }
    if f.needs_new_code() {
        err.extra = Some(json!({ "needs_new_code": true }));
    }
    err
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code, "message": self.message });
        if let (Some(extra), Some(obj)) = (self.extra, body.as_object_mut()) {
            if let Some(e) = extra.as_object() {
                for (k, v) in e {
                    obj.insert(k.clone(), v.clone());
                }
            }
        }
        if let (Some(r), Some(obj)) = (self.retry_after, body.as_object_mut()) {
            obj.insert("retry_after_secs".into(), json!(r));
        }
        let mut resp = (self.status, Json(body)).into_response();
        if let Some(r) = self.retry_after {
            if let Ok(v) = HeaderValue::from_str(&r.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
        }
        resp
    }
}

// ─── the router ──────────────────────────────────────────────────────────────

/// Every route, with the per-tenant CORS gate in front of the browser routes.
pub fn router<E: StoreEngine + 'static>(server: Arc<Server<E>>) -> Router {
    Router::new()
        .route("/healthz", get(healthz::<E>))
        .nest("/v1/p/:public_id", public::routes::<E>())
        .merge(admin::routes::<E>())
        .layer(from_fn_with_state(server.clone(), tenant_gate::<E>))
        .with_state(server)
}

/// The tenant a browser route names (inserted by the gate).
#[derive(Clone)]
pub(crate) struct GateTenant(pub crate::Tenant);

/// For `/v1/p/:public_id/…`: resolve the tenant (404 if unknown), answer the
/// CORS preflight for its origins, refuse a disallowed `Origin`, and stamp
/// the CORS headers on the response. Requests with no `Origin` (native apps,
/// servers, curl) pass: the public id is public, and the send limits gate.
async fn tenant_gate<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let Some(rest) = path.strip_prefix("/v1/p/") else {
        return next.run(req).await;
    };
    let public_id = rest.split('/').next().unwrap_or("").to_string();
    let store = s.store.clone();
    let tenant = match blocking(move || store.tenant_by_public_id(&public_id)).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return ApiError::new(StatusCode::NOT_FOUND, "unknown_tenant", "no such public id")
                .into_response()
        }
        Err(e) => return ApiError::from(e).into_response(),
    };
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    if let Some(o) = &origin {
        if !tenant.allows_origin(o) {
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "origin_not_allowed",
                "this origin is not on the tenant's allow-list",
            )
            .into_response();
        }
    }
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        cors_headers(resp.headers_mut(), origin.as_deref());
        return resp;
    }
    req.extensions_mut().insert(GateTenant(tenant));
    let mut resp = next.run(req).await;
    cors_headers(resp.headers_mut(), origin.as_deref());
    resp
}

fn cors_headers(h: &mut HeaderMap, origin: Option<&str>) {
    let Some(origin) = origin.and_then(|o| HeaderValue::from_str(o).ok()) else {
        return;
    };
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PATCH, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type, authorization"),
    );
    h.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("600"),
    );
}

async fn healthz<E: StoreEngine + 'static>(State(s): State<Arc<Server<E>>>) -> Response {
    let store = s.store.clone();
    let counts = blocking(move || -> Result<(usize, usize, u64, usize), StoreError> {
        let tenants = store.tenants()?;
        let mut users = 0;
        for t in &tenants {
            users += store.count_users(&t.id)?;
        }
        Ok((tenants.len(), users, store.height()?, store.outbox_len()?))
    })
    .await;
    match counts {
        Ok((tenants, users, height, outbox)) => Json(json!({
            "status": "ok",
            "service": "mid-sovereign-signup",
            "version": env!("CARGO_PKG_VERSION"),
            "tenants": tenants,
            "users": users,
            "height": height,
            "last_snapshot_height": s.tier.height(),
            "snapshot_failures": s.tier.failures(),
            "durability": s.tier.posture(),
            "import_enabled": s.cfg.import_token.is_some(),
            "mail": s.mailer.kind(),
            "mail_sent": s.mail_sent.load(Ordering::Relaxed),
            "mail_failures": s.mail_failures.load(Ordering::Relaxed),
            "webhook_outbox": outbox,
            "attestation_issuer": s.identity.did(),
            "clock": s.now(),
        }))
        .into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

// ─── running it ──────────────────────────────────────────────────────────────

/// Start the background loops: webhook delivery (woken by every event, and
/// every 5 s), snapshot landing (every 60 s), and housekeeping (every 10 min:
/// purge challenges ended over a day ago and dead sessions).
pub fn spawn_workers<E: StoreEngine + 'static>(
    server: Arc<Server<E>>,
) -> Vec<tokio::task::JoinHandle<()>> {
    worker::spawn(server)
}

/// Serve on `listener` until `shutdown` resolves, with the workers running.
/// Peer addresses reach the handlers (the per-client send limit).
pub async fn serve<E: StoreEngine + 'static>(
    server: Arc<Server<E>>,
    listener: tokio::net::TcpListener,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let workers = spawn_workers(server.clone());
    let app = router(server.clone());
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await;
    for w in workers {
        w.abort();
    }
    // One last landing so a clean shutdown leaves the tier current.
    server.land_snapshot().await;
    result
}
