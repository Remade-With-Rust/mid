//! Backend and operator routes: every call proves a `did:mata` with a signed
//! assertion over a single-use nonce whose **purpose is the operation**, so
//! an assertion minted to list users cannot delete one. Plus the import door.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use kms_types::SignedAssertion;
use mata_cap::{Caller, Capability};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;

use super::public::user_view;
use super::{blocking, ApiError, Server, ASSERTION_SCHEME};
use crate::store::{StoreEngine, StoreError};
use crate::{NormalizedEmail, OsEntropy, Tenant, TenantId, TenantMember, User, UserId};

/// What an operation requires of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// `signup:operator`.
    Operator,
    /// `signup:<action>@<tenant>` (members of the tenant named in the path,
    /// or an operator).
    Grant(&'static str),
    /// Any member of the tenant, or an operator.
    Member,
}

/// One backend operation: its id (= the assertion purpose), its route, and
/// the grant it needs. The router and this table are tested against each
/// other so a declared operation can never 404.
#[derive(Debug, Clone, Copy)]
pub struct Op {
    /// The operation id and assertion purpose, e.g. `signup.users.list`.
    pub id: &'static str,
    /// HTTP method.
    pub method: &'static str,
    /// Route pattern (axum syntax).
    pub path: &'static str,
    /// What the caller must hold.
    pub need: Need,
}

/// Grants a tenant member may hold.
pub const ADMIN_GRANTS: &[&str] = &[
    "users.read",
    "users.write",
    "tenant.write",
    "webhooks",
    "audit.read",
];

/// Every backend operation.
pub const OPS: &[Op] = &[
    Op {
        id: "signup.tenants.create",
        method: "POST",
        path: "/v1/admin/tenants",
        need: Need::Operator,
    },
    Op {
        id: "signup.tenants.list",
        method: "GET",
        path: "/v1/admin/tenants",
        need: Need::Operator,
    },
    Op {
        id: "signup.tenants.get",
        method: "GET",
        path: "/v1/admin/tenants/:tenant",
        need: Need::Member,
    },
    Op {
        id: "signup.tenants.update",
        method: "PATCH",
        path: "/v1/admin/tenants/:tenant",
        need: Need::Grant("tenant.write"),
    },
    Op {
        id: "signup.members.set",
        method: "PUT",
        path: "/v1/admin/tenants/:tenant/members",
        need: Need::Operator,
    },
    Op {
        id: "signup.webhooks.add",
        method: "POST",
        path: "/v1/admin/tenants/:tenant/webhooks",
        need: Need::Grant("webhooks"),
    },
    Op {
        id: "signup.webhooks.remove",
        method: "DELETE",
        path: "/v1/admin/tenants/:tenant/webhooks/:webhook",
        need: Need::Grant("webhooks"),
    },
    Op {
        id: "signup.users.list",
        method: "GET",
        path: "/v1/admin/tenants/:tenant/users",
        need: Need::Grant("users.read"),
    },
    Op {
        id: "signup.users.get",
        method: "GET",
        path: "/v1/admin/tenants/:tenant/users/:user",
        need: Need::Grant("users.read"),
    },
    Op {
        id: "signup.users.delete",
        method: "DELETE",
        path: "/v1/admin/tenants/:tenant/users/:user",
        need: Need::Grant("users.write"),
    },
    Op {
        id: "signup.audit.read",
        method: "GET",
        path: "/v1/admin/tenants/:tenant/audit",
        need: Need::Grant("audit.read"),
    },
    Op {
        id: "signup.referrals.list",
        method: "GET",
        path: "/v1/admin/tenants/:tenant/referrals",
        need: Need::Grant("users.read"),
    },
    Op {
        id: "signup.referrals.set_percent",
        method: "PUT",
        path: "/v1/admin/tenants/:tenant/users/:user/referral-percent",
        need: Need::Grant("users.write"),
    },
    Op {
        id: "signup.usage.read",
        method: "GET",
        path: "/v1/admin/tenants/:tenant/usage",
        need: Need::Grant("users.read"),
    },
];

fn op(id: &str) -> &'static Op {
    OPS.iter()
        .find(|o| o.id == id)
        .expect("every handler names a declared op")
}

pub(crate) fn routes<E: StoreEngine + 'static>() -> Router<Arc<Server<E>>> {
    Router::new()
        .route("/v1/nonce", post(nonce::<E>))
        .route("/v1/import", post(import::<E>))
        .route("/v1/import/check", post(import_check::<E>))
        .route(
            "/v1/admin/tenants",
            post(tenants_create::<E>).get(tenants_list::<E>),
        )
        .route(
            "/v1/admin/tenants/:tenant",
            get(tenants_get::<E>).patch(tenants_update::<E>),
        )
        .route("/v1/admin/tenants/:tenant/members", put(members_set::<E>))
        .route(
            "/v1/admin/tenants/:tenant/webhooks",
            post(webhooks_add::<E>),
        )
        .route(
            "/v1/admin/tenants/:tenant/webhooks/:webhook",
            delete(webhooks_remove::<E>),
        )
        .route("/v1/admin/tenants/:tenant/users", get(users_list::<E>))
        .route(
            "/v1/admin/tenants/:tenant/users/:user",
            get(users_get::<E>).delete(users_delete::<E>),
        )
        .route("/v1/admin/tenants/:tenant/audit", get(audit_read::<E>))
        .route("/v1/admin/tenants/:tenant/usage", get(usage_read::<E>))
        .route("/v1/admin/tenants/:tenant/referrals", get(referrals_list::<E>))
        .route(
            "/v1/admin/tenants/:tenant/users/:user/referral-percent",
            put(referral_percent_set::<E>),
        )
}

// ─── nonce + assertion ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct NonceBody {
    did: String,
    purpose: String,
}

/// `POST /v1/nonce {did, purpose}` → the envelope to sign. The purpose must
/// be an operation id from [`OPS`].
async fn nonce<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    Json(b): Json<NonceBody>,
) -> Response {
    match s.verifier.issue_nonce(&b.did, &b.purpose).await {
        Ok(env) => Json(env).into_response(),
        Err(e) => ApiError::bad_request(format!("cannot issue a nonce: {e}")).into_response(),
    }
}

/// Verify the request's assertion for `op_id` and check the caller may
/// perform it (in `tenant`, when the op is tenant-scoped). Returns the DID.
async fn authorize<E: StoreEngine + 'static>(
    s: &Arc<Server<E>>,
    headers: &HeaderMap,
    op_id: &str,
    tenant: Option<&TenantId>,
) -> Result<String, ApiError> {
    let op = op(op_id);
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix(ASSERTION_SCHEME))
        .map(str::trim)
        .ok_or_else(ApiError::unauthorized)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw.trim_end_matches('='))
        .or_else(|_| STANDARD.decode(raw))
        .map_err(|_| ApiError::unauthorized())?;
    let assertion: SignedAssertion =
        serde_json::from_slice(&bytes).map_err(|_| ApiError::unauthorized())?;
    let who = s.verifier.verify(&assertion, op.id).await.map_err(|e| {
        tracing::info!(op = op.id, error = ?e, "assertion refused");
        ApiError::unauthorized()
    })?;

    let operator_cap = Capability::new("signup", "operator");
    let mut grants = Vec::new();
    if s.cfg.operators.contains(&who.did) {
        grants.push(operator_cap.clone());
    }
    let mut member = false;
    if let Some(t) = tenant {
        let store = s.store.clone();
        let tid = t.clone();
        if let Some(rec) = blocking(move || store.tenant(&tid)).await? {
            if let Some(m) = rec.members.iter().find(|m| m.did == who.did) {
                member = true;
                grants.extend(
                    m.grants
                        .iter()
                        .map(|g| Capability::scoped("signup", g.as_str(), t.as_str())),
                );
            }
        }
    }
    let caller = Caller::new(who.did.clone(), grants);
    let allowed = caller.can(&operator_cap)
        || match op.need {
            Need::Operator => false,
            Need::Member => member,
            Need::Grant(action) => tenant
                .is_some_and(|t| caller.can(&Capability::scoped("signup", action, t.as_str()))),
        };
    if !allowed {
        tracing::info!(op = op.id, did = %who.did, "assertion valid but not permitted");
        return Err(ApiError::forbidden());
    }
    tracing::info!(op = op.id, did = %who.did, device = %who.device_id, "backend call authorized");
    Ok(who.did)
}

/// Parse a JSON body — only ever after the caller is authorized, so an
/// unauthenticated client learns nothing about the request schema.
fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request(format!("body: {e}")))
}

fn tenant_id(raw: &str) -> Result<TenantId, ApiError> {
    TenantId::parse(raw).map_err(|e| ApiError::bad_request(format!("tenant id: {e}")))
}

// ─── views ───────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct WebhookView {
    id: String,
    url: String,
    events: Vec<String>,
    created_at: u64,
    format: &'static str,
}

#[derive(Serialize)]
struct TenantView {
    id: String,
    name: String,
    public_id: String,
    origins: Vec<String>,
    created_at: u64,
    members: Vec<TenantMember>,
    webhooks: Vec<WebhookView>,
}

fn tenant_view(t: &Tenant) -> TenantView {
    TenantView {
        id: t.id.to_string(),
        name: t.name.clone(),
        public_id: t.public_id.clone(),
        origins: t.origins.clone(),
        created_at: t.created_at,
        members: t.members.clone(),
        webhooks: t
            .webhooks
            .iter()
            .map(|w| WebhookView {
                id: w.id.clone(),
                url: w.url.clone(),
                events: w.events.clone(),
                created_at: w.created_at,
                format: w.format.as_str(),
            })
            .collect(),
    }
}

fn check_grants(members: &[TenantMember]) -> Result<(), ApiError> {
    for m in members {
        if let Some(g) = m
            .grants
            .iter()
            .find(|g| !ADMIN_GRANTS.contains(&g.as_str()))
        {
            return Err(ApiError::bad_request(format!(
                "unknown grant {g:?}; grants are {ADMIN_GRANTS:?}"
            )));
        }
    }
    Ok(())
}

// ─── tenants ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateTenant {
    id: String,
    name: String,
    #[serde(default)]
    origins: Vec<String>,
    #[serde(default)]
    members: Vec<TenantMember>,
}

async fn tenants_create<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(e) = authorize(&s, &headers, "signup.tenants.create", None).await {
        return e.into_response();
    }
    let b: CreateTenant = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let id = match tenant_id(&b.id) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = check_grants(&b.members) {
        return e.into_response();
    }
    let store = s.store.clone();
    let now = s.now();
    let out = blocking(move || -> Result<Tenant, StoreError> {
        let t = Tenant::new(id.clone(), b.name, b.origins, now, &mut OsEntropy)
            .map_err(crate::FlowError::from)?;
        store.create_tenant(&t)?;
        if b.members.is_empty() {
            Ok(t)
        } else {
            store.set_members(&id, b.members, now)
        }
    })
    .await;
    match out {
        Ok(t) => (StatusCode::CREATED, Json(tenant_view(&t))).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn tenants_list<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = authorize(&s, &headers, "signup.tenants.list", None).await {
        return e.into_response();
    }
    let store = s.store.clone();
    match blocking(move || store.tenants()).await {
        Ok(ts) => Json(ts.iter().map(tenant_view).collect::<Vec<_>>()).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn tenants_get<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.tenants.get", Some(&tid)).await {
        return e.into_response();
    }
    let store = s.store.clone();
    match blocking(move || store.tenant(&tid)).await {
        Ok(Some(t)) => Json(tenant_view(&t)).into_response(),
        Ok(None) => {
            ApiError::new(StatusCode::NOT_FOUND, "unknown_tenant", "no such tenant").into_response()
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateTenant {
    name: String,
    origins: Vec<String>,
}

async fn tenants_update<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Bytes,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.tenants.update", Some(&tid)).await {
        return e.into_response();
    }
    let b: UpdateTenant = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.update_tenant(&tid, b.name, b.origins, now)).await {
        Ok(t) => Json(tenant_view(&t)).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct SetMembers {
    members: Vec<TenantMember>,
}

async fn members_set<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Bytes,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.members.set", Some(&tid)).await {
        return e.into_response();
    }
    let b: SetMembers = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = check_grants(&b.members) {
        return e.into_response();
    }
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.set_members(&tid, b.members, now)).await {
        Ok(t) => Json(tenant_view(&t)).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

// ─── webhooks ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddWebhook {
    url: String,
    events: Vec<String>,
    /// `"event"` (default) or `"slack"`.
    #[serde(default)]
    format: Option<String>,
}

/// Returns the endpoint **with its secret** — the only time it is shown.
async fn webhooks_add<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
    body: Bytes,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.webhooks.add", Some(&tid)).await {
        return e.into_response();
    }
    let b: AddWebhook = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let Some(format) = crate::WebhookFormat::parse(b.format.as_deref().unwrap_or("")) else {
        return ApiError::bad_request("format must be \"event\" or \"slack\"").into_response();
    };
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.add_webhook_with(&tid, &b.url, b.events, format, now, &mut OsEntropy)).await {
        Ok(w) => (
            StatusCode::CREATED,
            Json(json!({ "id": w.id, "url": w.url, "events": w.events, "created_at": w.created_at, "format": w.format.as_str(), "secret": w.secret })),
        )
            .into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn webhooks_remove<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path((t, webhook)): Path<(String, String)>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.webhooks.remove", Some(&tid)).await {
        return e.into_response();
    }
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.remove_webhook(&tid, &webhook, now)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

// ─── users, audit, usage ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Page {
    after: Option<String>,
    limit: Option<usize>,
}

async fn users_list<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
    Query(p): Query<Page>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.users.list", Some(&tid)).await {
        return e.into_response();
    }
    let after = match p.after.as_deref().map(UserId::parse).transpose() {
        Ok(a) => a,
        Err(e) => return ApiError::bad_request(e.to_string()).into_response(),
    };
    let limit = p.limit.unwrap_or(100).clamp(1, 500);
    let store = s.store.clone();
    match blocking(move || store.users(&tid, after.as_ref(), limit)).await {
        Ok(users) => {
            let next = (users.len() == limit)
                .then(|| users.last().map(|u| u.id.to_string()))
                .flatten();
            Json(json!({ "users": users.iter().map(user_view).collect::<Vec<_>>(), "next": next }))
                .into_response()
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

/// Every referrer with at least one referral, most first.
async fn referrals_list<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.referrals.list", Some(&tid)).await {
        return e.into_response();
    }
    let store = s.store.clone();
    match blocking(move || store.referral_report(&tid)).await {
        Ok(rows) => Json(json!({ "referrers": rows })).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct SetPercent {
    referral_percent: f64,
}

/// Set a referrer's profit share (0–100).
async fn referral_percent_set<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path((t, u)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.referrals.set_percent", Some(&tid)).await {
        return e.into_response();
    }
    let Ok(uid) = UserId::parse(&u) else {
        return ApiError::bad_request("user id is not a UUID").into_response();
    };
    let b: SetPercent = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.set_referral_percent(&tid, &uid, b.referral_percent, now)).await {
        Ok(user) => Json(user_view(&user)).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn users_get<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path((t, u)): Path<(String, String)>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.users.get", Some(&tid)).await {
        return e.into_response();
    }
    let Ok(uid) = UserId::parse(&u) else {
        return ApiError::bad_request("user id is not a UUID").into_response();
    };
    let store = s.store.clone();
    match blocking(move || store.user(&tid, &uid)).await {
        Ok(Some(user)) => Json(user_view(&user)).into_response(),
        Ok(None) => ApiError::from(StoreError::UserNotFound).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn users_delete<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path((t, u)): Path<(String, String)>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.users.delete", Some(&tid)).await {
        return e.into_response();
    }
    let Ok(uid) = UserId::parse(&u) else {
        return ApiError::bad_request("user id is not a UUID").into_response();
    };
    let store = s.store.clone();
    let now = s.now();
    match blocking(move || store.delete_user(&tid, &uid, now)).await {
        Ok(true) => {
            s.wake.notify_one();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => ApiError::from(StoreError::UserNotFound).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct AuditPage {
    after: Option<u64>,
    limit: Option<usize>,
}

async fn audit_read<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
    Query(p): Query<AuditPage>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.audit.read", Some(&tid)).await {
        return e.into_response();
    }
    let store = s.store.clone();
    let limit = p.limit.unwrap_or(200).clamp(1, 1_000);
    match blocking(move || store.audit(Some(&tid), p.after.unwrap_or(0), limit)).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

async fn usage_read<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    Path(t): Path<String>,
) -> Response {
    let tid = match tenant_id(&t) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = authorize(&s, &headers, "signup.usage.read", Some(&tid)).await {
        return e.into_response();
    }
    let store = s.store.clone();
    let out = blocking(move || -> Result<serde_json::Value, StoreError> {
        let users = store.count_users(&tid)?;
        let mut issued = 0u64;
        let mut verified = 0u64;
        let mut created = 0u64;
        let mut after = 0;
        loop {
            let rows = store.audit(Some(&tid), after, 1_000)?;
            let Some(last) = rows.last() else { break };
            after = last.seq;
            for r in &rows {
                match r.event.kind {
                    crate::AuditKind::ChallengeIssued => issued += 1,
                    crate::AuditKind::CodeAccepted => verified += 1,
                    crate::AuditKind::UserCreated => created += 1,
                    _ => {}
                }
            }
        }
        Ok(json!({ "users": users, "codes_sent": issued, "verifications": verified, "sign_ups": created }))
    })
    .await;
    match out {
        Ok(v) => Json(v).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

// ─── the import door ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ImportUser {
    id: String,
    email: String,
    email_verified_at: Option<u64>,
    created_at: u64,
    #[serde(default)]
    last_sign_in_at: Option<u64>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    linked_did: Option<String>,
    #[serde(default)]
    metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct ImportBody {
    tenant: String,
    users: Vec<ImportUser>,
    /// `refuse` (default): a taken or malformed username refuses the user.
    /// `drop`: import the user without it, and say so in the result.
    #[serde(default)]
    username_conflict: Option<crate::store::UsernameConflict>,
}

#[derive(Deserialize)]
struct CheckBody {
    tenant: String,
    ids: Vec<String>,
}

/// `POST /v1/import` — the migration door. Exists only while an import token
/// is configured (otherwise 404); the token is compared in constant time;
/// every user lands through the store's uniqueness checks, keeping its id;
/// each batch is logged loudly. Results are per user, so a re-run after a
/// partial failure is safe (already-present ids answer `user_id_taken`).
async fn import<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(want) = &s.cfg.import_token else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if got.len() != want.len() || !bool::from(got.as_bytes().ct_eq(want.as_bytes())) {
        return ApiError::unauthorized().into_response();
    }
    let b: ImportBody = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let tid = match tenant_id(&b.tenant) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if b.users.len() > 1_000 {
        return ApiError::bad_request("at most 1000 users per batch").into_response();
    }
    tracing::warn!(tenant = %tid, count = b.users.len(), "IMPORT batch received through the migration door");
    let store = s.store.clone();
    let now = s.now();
    let policy = b
        .username_conflict
        .unwrap_or(crate::store::UsernameConflict::Refuse);
    let results = blocking(move || {
        b.users
            .into_iter()
            .map(|u| {
                let id = u.id.clone();
                let built = UserId::parse(&u.id)
                    .map_err(|e| e.to_string())
                    .and_then(|uid| {
                        NormalizedEmail::parse(&u.email)
                            .map(|email| (uid, email))
                            .map_err(|e| format!("email: {e}"))
                    });
                let outcome = match built {
                    Err(e) => Err(json!({ "error": "invalid_record", "message": e })),
                    Ok((uid, email)) => {
                        let user = User {
                            id: uid,
                            tenant: tid.clone(),
                            email,
                            email_idx: crate::EmailIndex::from_bytes([0; 32]),
                            email_verified_at: u.email_verified_at,
                            created_at: u.created_at,
                            last_sign_in_at: u.last_sign_in_at,
                            linked_did: u.linked_did,
                            username: u.username,
                            metadata: u.metadata,
                        };
                        store
                            .import_user_with(&user, now, policy)
                            .map(|o| match o {
                                crate::store::ImportOutcome::Imported {
                                    username_dropped: None,
                                    ..
                                } => {
                                    json!({ "status": "imported" })
                                }
                                crate::store::ImportOutcome::Imported {
                                    username_dropped: Some(d),
                                    ..
                                } => {
                                    json!({ "status": "imported", "username_dropped": d.reason })
                                }
                                crate::store::ImportOutcome::AlreadyPresent { .. } => {
                                    json!({ "status": "already_present" })
                                }
                            })
                            .map_err(|e| json!({ "error": e.code(), "message": e.to_string() }))
                    }
                };
                match outcome {
                    Ok(mut v) => {
                        v["id"] = json!(id);
                        v["ok"] = json!(true);
                        v
                    }
                    Err(mut e) => {
                        e["id"] = json!(id);
                        e["ok"] = json!(false);
                        e
                    }
                }
            })
            .collect::<Vec<_>>()
    })
    .await;
    let imported = results.iter().filter(|r| r["status"] == "imported").count();
    tracing::warn!(
        imported,
        refused = results.len() - imported,
        "IMPORT batch landed"
    );
    s.land_snapshot().await;
    let already = results
        .iter()
        .filter(|r| r["status"] == "already_present")
        .count();
    Json(json!({ "imported": imported, "already_present": already, "results": results }))
        .into_response()
}

/// `POST /v1/import/check {tenant, ids}` → `{checked, missing}` — the
/// migration's proof that every id it was meant to carry is here. Behind the
/// same token as the import door (404 when closed): a directory listing is
/// not a public question.
async fn import_check<E: StoreEngine + 'static>(
    State(s): State<Arc<Server<E>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(want) = &s.cfg.import_token else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if got.len() != want.len() || !bool::from(got.as_bytes().ct_eq(want.as_bytes())) {
        return ApiError::unauthorized().into_response();
    }
    let b: CheckBody = match parse(&body) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let tid = match tenant_id(&b.tenant) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };
    if b.ids.len() > 10_000 {
        return ApiError::bad_request("at most 10000 ids per check").into_response();
    }
    let mut ids = Vec::with_capacity(b.ids.len());
    for raw in &b.ids {
        match UserId::parse(raw) {
            Ok(id) => ids.push(id),
            Err(_) => {
                return ApiError::bad_request(format!("not a user id: {raw:?}")).into_response()
            }
        }
    }
    let checked = ids.len();
    let store = s.store.clone();
    match blocking(move || store.missing_users(&tid, &ids)).await {
        Ok(missing) => Json(json!({
            "checked": checked,
            "missing": missing.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}
