//! Drop-in axum routes pairing with the `@matanetwork/sovereign-id` frontend
//! SDK — the impure boundary of this crate (SystemTime + HTTP live here and
//! only here).
//!
//! - `POST /auth/mid/nonce` → `200 {"nonce": "<hex>"}` — mint the single-use
//!   nonce the page passes to `signIn({ nonce, … })`.
//! - `POST /auth/mid/verify` with `{"jwt": "<jws>"}` → `200 {"did", "claims",
//!   "roster_version"}` on success, `401 {"error": "<code>"}` on any
//!   authentication failure (`400` for tokens too malformed to parse, `503`
//!   when nonce issuance is at capacity).
//!
//! The verify route resolves the expected nonce from the token's own echoed
//! `nonce` field and requires it live in the store (see
//! [`Authenticator::authenticate_with_embedded_nonce`]) — no server-side
//! session is needed before sign-in.
//!
//! Applications that mint their own session cookie pass an `on_verified`
//! responder to [`router_with`]; ones with richer needs (async session
//! stores) skip the router and call [`MidRp::verify_jwt`] from their own
//! handler — it is the whole flow in one call.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::Authenticator;
use crate::error::RpError;
use crate::session::RpSession;

/// Configuration for the drop-in RP endpoint.
#[derive(Debug, Clone)]
pub struct MidRpConfig {
    /// This RP's origin — the exact string the frontend passes as
    /// `rpOrigin` and the wallet mints into the token's `aud`.
    pub rp_origin: String,
    /// Maximum allowed forward clock skew on the token's `iat`, seconds.
    pub max_iat_skew_secs: u64,
}

impl MidRpConfig {
    /// Config with the default 120 s skew allowance.
    pub fn new(rp_origin: impl Into<String>) -> Self {
        Self {
            rp_origin: rp_origin.into(),
            max_iat_skew_secs: 120,
        }
    }
}

/// The RP endpoint state: configuration + the [`Authenticator`], with the
/// wall clock attached. Share it via `Arc` between the router and any custom
/// handlers.
pub struct MidRp {
    config: MidRpConfig,
    auth: Authenticator,
}

impl MidRp {
    /// Bundle a config and an authenticator into route state.
    pub fn new(config: MidRpConfig, auth: Authenticator) -> Self {
        Self { config, auth }
    }

    /// Issue a single-use nonce (wall-clock boundary).
    pub fn issue_nonce(&self) -> Result<String, RpError> {
        self.auth.issue_nonce(now_unix())
    }

    /// The full sign-in flow for one token: peek nonce → verify → consume
    /// nonce → anchor/rollback check (wall-clock boundary).
    pub fn verify_jwt(&self, jwt: &str) -> Result<RpSession, RpError> {
        self.auth.authenticate_with_embedded_nonce(
            jwt,
            &self.config.rp_origin,
            now_unix(),
            self.config.max_iat_skew_secs,
        )
    }

    /// The underlying authenticator, for callers composing their own flow.
    pub fn authenticator(&self) -> &Authenticator {
        &self.auth
    }
}

/// Optional hook run after a successful verification. Return `Some(response)`
/// to take over the response (e.g. to set a session cookie); return `None`
/// to fall back to the default JSON body.
pub type OnVerified = Arc<dyn Fn(&RpSession) -> Option<Response> + Send + Sync>;

#[derive(Clone)]
struct RouterState {
    rp: Arc<MidRp>,
    on_verified: Option<OnVerified>,
}

/// The two drop-in routes with the default JSON responses.
pub fn router(rp: Arc<MidRp>) -> Router {
    build_router(RouterState {
        rp,
        on_verified: None,
    })
}

/// The two drop-in routes with a post-verification responder (session-cookie
/// minting, redirects, …).
pub fn router_with(rp: Arc<MidRp>, on_verified: OnVerified) -> Router {
    build_router(RouterState {
        rp,
        on_verified: Some(on_verified),
    })
}

fn build_router(state: RouterState) -> Router {
    Router::new()
        .route("/auth/mid/nonce", post(issue_nonce_handler))
        .route("/auth/mid/verify", post(verify_handler))
        .with_state(state)
}

#[derive(Serialize)]
struct NonceResponse {
    nonce: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    jwt: String,
}

#[derive(Serialize)]
struct VerifiedResponse {
    did: String,
    roster_version: u64,
    claims: std::collections::BTreeMap<String, mid_verify::ClaimValue>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

async fn issue_nonce_handler(State(state): State<RouterState>) -> Response {
    match state.rp.issue_nonce() {
        Ok(nonce) => (StatusCode::OK, Json(NonceResponse { nonce })).into_response(),
        Err(err) => error_response(&err),
    }
}

async fn verify_handler(
    State(state): State<RouterState>,
    Json(body): Json<VerifyRequest>,
) -> Response {
    match state.rp.verify_jwt(&body.jwt) {
        Ok(session) => {
            if let Some(hook) = &state.on_verified {
                if let Some(response) = hook(&session) {
                    return response;
                }
            }
            (
                StatusCode::OK,
                Json(VerifiedResponse {
                    did: session.did.clone(),
                    roster_version: session.current_version,
                    claims: session.claims,
                }),
            )
                .into_response()
        }
        Err(err) => error_response(&err),
    }
}

fn error_response(err: &RpError) -> Response {
    let status = match err {
        RpError::MalformedToken => StatusCode::BAD_REQUEST,
        RpError::NonceCapacity { .. } => StatusCode::SERVICE_UNAVAILABLE,
        RpError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::UNAUTHORIZED,
    };
    (status, Json(ErrorResponse { error: err.code() })).into_response()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}
