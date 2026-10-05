//! The browser / app routes under `/v1/p/:public_id`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{blocking, ApiError, GateTenant, Server};
use crate::flow::{StartRequest, VerifyRequest};
use crate::store::{SessionRecord, StoreEngine, StoreError};
use crate::{FlowError, OsEntropy, User};

pub(crate) fn routes<E: StoreEngine + 'static>() -> Router<Arc<Server<E>>> {
    Router::new()
        .route("/signup/start", post(start::<E>))
        .route("/signup/resend", post(resend::<E>))
        .route("/signup/verify", post(verify::<E>))
        .route("/username/check", post(username_check::<E>))
        .route("/users/me", get(me::<E>).patch(update_me::<E>))
        .route("/users/me/referrals", get(my_referrals::<E>))
        .route("/session/refresh", post(refresh::<E>))
        .route("/session/logout", post(logout::<E>))
        .route("/session/logout-all", post(logout_all::<E>))
        .route("/attestation", get(attestation::<E>))
}

/// What a client may see of a user — their own record, for themselves.
#[derive(Debug, Serialize)]
pub(crate) struct UserView {
    id: String,
    email: String,
    email_verified_at: Option<u64>,
    username: Option<String>,
    linked_did: Option<String>,
    metadata: BTreeMap<String, serde_json::Value>,
    created_at: u64,
    last_sign_in_at: Option<u64>,
}

impl From<&User> for UserView {
    fn from(u: &User) -> Self {
        Self {
            id: u.id.to_string(),
            email: u.email.to_string(),
            email_verified_at: u.email_verified_at,
            username: u.username.clone(),
            linked_did: u.linked_did.clone(),
            metadata: u.metadata.clone(),
            created_at: u.created_at,
            last_sign_in_at: u.last_sign_in_at,
        }
    }
}

pub(crate) fn user_view(u: &User) -> UserView {
    UserView::from(u)
}

fn client_key<E: StoreEngine + 'static>(
    s: &Server<E>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<String> {
    if let Some(h) = &s.cfg.client_ip_header {
        if let Some(v) = headers.get(h.as_str()).and_then(|v| v.to_str().ok()) {
            return Some(v.trim().to_string());
        }
    }
    peer.map(|p| p.ip().to_string())
}

fn accepted(resend_after: u64) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(json!({ "status": "accepted", "resend_after_secs": resend_after })),
    )
        .into_response()
}

#[derive(Deserialize)]
struct StartBody {
    email: String,
    #[serde(default = "yes")]
    create_user: bool,
}

fn yes() -> bool {
    true
}

/// Issue a code. Answers `202 accepted` whether a code was sent or the
/// address is inside its resend cooldown — the response never tells an
/// observer whether the address is enrolled or was just mailed.
async fn start<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<StartBody>,
) -> Response {
    let client = client_key(&s, &headers, connect.map(|c| c.0));
    issue(s, tenant, body.email, body.create_user, client).await
}

async fn issue<E: StoreEngine + 'static>(
    s: Arc<Server<E>>,
    tenant: crate::Tenant,
    email: String,
    create_user: bool,
    client: Option<String>,
) -> Response {
    let cooldown = s.store.policy().resend_cooldown_secs;
    let now = s.now();
    let store = s.store.clone();
    let tid = tenant.id.clone();
    let out = blocking(move || {
        store.start(
            &StartRequest {
                tenant: &tid,
                email: &email,
                create_user,
                now,
            },
            client.as_deref(),
            &mut OsEntropy,
        )
    })
    .await;
    match out {
        Ok(outcome) => {
            let msg = outcome.message(tenant.name.clone());
            match tokio::time::timeout(Duration::from_secs(10), s.mailer.send_code(msg)).await {
                Ok(Ok(())) => {
                    s.mail_sent.fetch_add(1, Ordering::Relaxed);
                }
                Ok(Err(e)) => {
                    s.mail_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(error = %e, tenant = %tenant.id, "code mail failed; the user can resend after the cooldown");
                }
                Err(_) => {
                    s.mail_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(tenant = %tenant.id, "code mail timed out");
                }
            }
            accepted(cooldown)
        }
        Err(StoreError::Flow(FlowError::ResendTooSoon { retry_after_secs })) => {
            accepted(retry_after_secs)
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct ResendBody {
    email: String,
}

/// Re-send to an address with a live code (a new code; the old one dies).
/// No live code — or inside the cooldown — is the same `202`.
async fn resend<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<ResendBody>,
) -> Response {
    let store = s.store.clone();
    let (tid, email) = (tenant.id.clone(), body.email.clone());
    let live = blocking(move || store.live_challenge(&tid, &email)).await;
    match live {
        Ok(Some(ch)) if ch.is_live(s.now()) => {
            let client = client_key(&s, &headers, connect.map(|c| c.0));
            issue(s, tenant, body.email, ch.create_user, client).await
        }
        Ok(_) => accepted(s.store.policy().resend_cooldown_secs),
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct VerifyBody {
    email: String,
    code: String,
}

/// Check a code: `200 { user, session, attestation, user_created }`.
async fn verify<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    Json(body): Json<VerifyBody>,
) -> Response {
    let now = s.now();
    let ttl = s.cfg.session_ttl;
    let store = s.store.clone();
    let tid = tenant.id.clone();
    let out = blocking(move || {
        store.verify_and_open_session(
            &VerifyRequest {
                tenant: &tid,
                email: &body.email,
                code: &body.code,
                now,
            },
            ttl,
            &mut OsEntropy,
        )
    })
    .await;
    let (v, tokens) = match out {
        Ok(ok) => ok,
        Err(e) => return ApiError::from(e).into_response(),
    };
    if s.cfg.land_on_verify {
        s.land_snapshot().await;
    }
    s.wake.notify_one();
    if v.user_created {
        // The welcome, once, off the request path; best-effort.
        let s2 = s.clone();
        let user = v.user.clone();
        let tenant_name = tenant.name.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(s2.cfg.welcome_delay_secs)).await;
            let store = s2.store.clone();
            let (tid, uid) = (user.tenant.clone(), user.id.clone());
            let username = blocking(move || store.user(&tid, &uid))
                .await
                .ok()
                .flatten()
                .and_then(|u| u.username)
                .or(user.username.clone());
            let msg = crate::seams::WelcomeMessage {
                to: user.email.clone(),
                tenant: user.tenant.clone(),
                tenant_name,
                username,
            };
            match tokio::time::timeout(Duration::from_secs(10), s2.mailer.send_welcome(msg)).await {
                Ok(Ok(())) => tracing::info!(user = %user.id, "welcome email sent"),
                Ok(Err(e)) => tracing::warn!(user = %user.id, error = %e, "welcome email failed"),
                Err(_) => tracing::warn!(user = %user.id, "welcome email timed out"),
            }
        });
    }
    let attestation = match s
        .identity
        .attest(&v.user, now, s.store.policy().attestation_ttl_secs)
    {
        Ok(a) => a,
        Err(e) => return ApiError::internal(e).into_response(),
    };
    Json(json!({
        "user": user_view(&v.user),
        "user_created": v.user_created,
        "first_verification": v.first_verification,
        "session": tokens,
        "attestation": attestation,
        "attestation_issuer": s.identity.did(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct UsernameBody {
    username: String,
}

async fn username_check<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    Json(body): Json<UsernameBody>,
) -> Response {
    let store = s.store.clone();
    match blocking(move || store.username_available(&tenant.id, &body.username)).await {
        Ok(available) => Json(json!({ "available": available })).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
}

/// The session the request carries, which must belong to this tenant.
async fn session_of<E: StoreEngine + 'static>(
    s: &Arc<Server<E>>,
    tenant: &crate::Tenant,
    headers: &HeaderMap,
) -> Result<(String, SessionRecord), ApiError> {
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    let store = s.store.clone();
    let now = s.now();
    let t = token.clone();
    let rec = blocking(move || store.session(&t, now))
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    if rec.tenant != tenant.id {
        return Err(ApiError::unauthorized());
    }
    Ok((token, rec))
}

async fn current_user<E: StoreEngine + 'static>(
    s: &Arc<Server<E>>,
    tenant: &crate::Tenant,
    headers: &HeaderMap,
) -> Result<(String, User), ApiError> {
    let (token, rec) = session_of(s, tenant, headers).await?;
    let store = s.store.clone();
    let user = blocking(move || store.user(&rec.tenant, &rec.user))
        .await?
        .ok_or_else(ApiError::unauthorized)?;
    Ok((token, user))
}

async fn me<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    headers: HeaderMap,
) -> Response {
    match current_user(&s, &tenant, &headers).await {
        Ok((_, u)) => Json(user_view(&u)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `PATCH /users/me` — `{ "metadata": {…} }` replaces the metadata;
/// `{ "username": "name" | null }` sets or clears the username.
async fn update_me<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let (_, user) = match current_user(&s, &tenant, &headers).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let Some(obj) = body.as_object() else {
        return ApiError::bad_request("expected a JSON object").into_response();
    };
    if obj.keys().any(|k| k != "metadata" && k != "username") {
        return ApiError::bad_request("only `metadata` and `username` can be changed here")
            .into_response();
    }
    let metadata = match obj.get("metadata") {
        None => None,
        Some(v) => match serde_json::from_value::<BTreeMap<String, serde_json::Value>>(v.clone()) {
            Ok(m)
                if serde_json::to_vec(&m)
                    .map(|b| b.len())
                    .unwrap_or(usize::MAX)
                    <= 16 * 1024 =>
            {
                Some(m)
            }
            Ok(_) => return ApiError::bad_request("metadata is limited to 16 KiB").into_response(),
            Err(_) => return ApiError::bad_request("metadata must be an object").into_response(),
        },
    };
    let username = match obj.get("username") {
        None => None,
        Some(serde_json::Value::Null) => Some(None),
        Some(serde_json::Value::String(n)) => Some(Some(n.clone())),
        Some(_) => {
            return ApiError::bad_request("username must be a string or null").into_response()
        }
    };
    let store = s.store.clone();
    let now = s.now();
    let out = blocking(move || -> Result<User, StoreError> {
        let mut u = user;
        if let Some(name) = username {
            u = store.set_username(&u.tenant, &u.id, name.as_deref(), now)?;
        }
        if let Some(m) = metadata {
            u = store.set_own_metadata(&u.tenant, &u.id, m, now)?;
        }
        Ok(u)
    })
    .await;
    match out {
        Ok(u) => Json(user_view(&u)).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

/// `GET /users/me/referrals` — who referred me, how many I referred, my share.
async fn my_referrals<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    headers: HeaderMap,
) -> Response {
    let (_, user) = match current_user(&s, &tenant, &headers).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let store = s.store.clone();
    match blocking(move || store.referral_stats(&user.tenant, &user.id)).await {
        Ok(stats) => Json(stats).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct RefreshBody {
    refresh: String,
}

async fn refresh<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    Json(body): Json<RefreshBody>,
) -> Response {
    let store = s.store.clone();
    let now = s.now();
    let ttl = s.cfg.session_ttl;
    let tid = tenant.id.clone();
    let out = blocking(move || -> Result<_, StoreError> {
        let tokens = store.refresh_session(&body.refresh, ttl, now, &mut OsEntropy)?;
        // A refresh token from another tenant must not mint a session here.
        match store.session(&tokens.token, now)? {
            Some(rec) if rec.tenant == tid => Ok(tokens),
            _ => {
                store.revoke_session(&tokens.token)?;
                Err(StoreError::SessionInvalid)
            }
        }
    })
    .await;
    match out {
        Ok(tokens) => Json(tokens).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn logout<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    headers: HeaderMap,
) -> Response {
    let (token, _) = match session_of(&s, &tenant, &headers).await {
        Ok(x) => x,
        Err(e) => return e.into_response(),
    };
    let store = s.store.clone();
    match blocking(move || store.revoke_session(&token)).await {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn logout_all<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    headers: HeaderMap,
) -> Response {
    let (_, rec) = match session_of(&s, &tenant, &headers).await {
        Ok(x) => x,
        Err(e) => return e.into_response(),
    };
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.revoke_user_sessions(&rec.tenant, &rec.user, now)).await {
        Ok(n) => Json(json!({ "revoked": n })).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

/// A fresh attestation for the signed-in user — so a client can prove the
/// verified address to a third party at any time, not only at verify.
async fn attestation<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Extension(GateTenant(tenant)): Extension<GateTenant>,
    headers: HeaderMap,
) -> Response {
    let (_, user) = match current_user(&s, &tenant, &headers).await {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    match s
        .identity
        .attest(&user, s.now(), s.store.policy().attestation_ttl_secs)
    {
        Ok(a) => Json(json!({ "attestation": a, "attestation_issuer": s.identity.did() }))
            .into_response(),
        Err(e) => ApiError::from(StoreError::Flow(e)).into_response(),
    }
}
