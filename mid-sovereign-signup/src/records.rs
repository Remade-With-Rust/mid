//! The records a store persists, and their key namespace.
//!
//! The core never touches a store; it hands these back from
//! [`start`](crate::flow::start) and [`verify`](crate::flow::verify) for the
//! caller to write in one transaction. The `key` / `live_key` / `email_key`
//! builders are the namespace a store should use, kept stable so an operator
//! can read a dump:
//!
//! | Key | Points at | Uniqueness |
//! |---|---|---|
//! | `tenant/{tenant}` | [`Tenant`] | one per id |
//! | `tenant-public/{public_id}` | the tenant's id | one per public id |
//! | `user/{tenant}/{user_id}` | [`User`] | one per id |
//! | `user-email/{tenant}/{email_idx}` | the user's id | **one address → one user** |
//! | `challenge/{tenant}/{challenge_id}` | [`Challenge`] | one per id |
//! | `challenge-live/{tenant}/{email_idx}` | the live challenge's id | **one live code per address** |
//! | `audit/{tenant}/{at}/{n}` | [`AuditEvent`] | append-only |

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::code::CodeMac;
use crate::email::{EmailIndex, NormalizedEmail};
use crate::enc;
use crate::error::FlowError;
use crate::seams::{Entropy, EntropyError};

/// Longest tenant id, in bytes.
pub const MAX_TENANT_ID_LEN: usize = 64;

// ─── Tenant ──────────────────────────────────────────────────────────────────

/// A tenant's identifier: 1–64 lowercase ASCII letters, digits and hyphens,
/// not starting or ending with a hyphen (`acme`, `my-app-2`). It is part of
/// every key, MAC and attestation, so it is validated once, here.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TenantId(String);

impl TenantId {
    /// Validate a tenant id.
    pub fn parse(raw: &str) -> Result<Self, TenantIdError> {
        if raw.is_empty() {
            return Err(TenantIdError::Empty);
        }
        if raw.len() > MAX_TENANT_ID_LEN {
            return Err(TenantIdError::TooLong { len: raw.len() });
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(TenantIdError::BadChar);
        }
        if raw.starts_with('-') || raw.ends_with('-') {
            return Err(TenantIdError::EdgeHyphen);
        }
        Ok(Self(raw.to_string()))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TenantId({})", self.0)
    }
}

impl TryFrom<String> for TenantId {
    type Error = TenantIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<TenantId> for String {
    fn from(t: TenantId) -> Self {
        t.0
    }
}

/// Why a tenant id was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenantIdError {
    /// Empty.
    #[error("empty")]
    Empty,
    /// Longer than [`MAX_TENANT_ID_LEN`].
    #[error("too long ({len} > {MAX_TENANT_ID_LEN})")]
    TooLong {
        /// Observed length.
        len: usize,
    },
    /// Something other than `a-z`, `0-9`, `-`.
    #[error("only lowercase letters, digits and hyphens are allowed")]
    BadChar,
    /// Starts or ends with a hyphen.
    #[error("must not start or end with a hyphen")]
    EdgeHyphen,
}

/// A tenant: one adopter's user base. The `public_id` is what a browser
/// page presents to name the tenant (the role an "anon key" plays
/// elsewhere): **public by design**, it carries no authority — the origin
/// allow-list and the rate limits do the gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    /// The tenant id.
    pub id: TenantId,
    /// Display name, used in the code message ("Acme" in "123456 is your Acme
    /// code").
    pub name: String,
    /// `pub_` + 16 random bytes base64url. Names the tenant on public pages.
    pub public_id: String,
    /// Browser origins allowed to start and verify under the public id
    /// (`https://app.acme.com`). Empty = no browser access.
    pub origins: Vec<String>,
    /// Unix seconds.
    pub created_at: u64,
    /// DIDs allowed to call this tenant's backend API, each with the grants
    /// it holds here (see [`TenantMember`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<TenantMember>,
    /// Endpoints that receive this tenant's events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub webhooks: Vec<WebhookEndpoint>,
}

/// A DID allowed to call a tenant's backend API, and what it may do there.
/// Grants are action names (`users.read`, `users.write`, `tenant.write`,
/// `webhooks`, `audit.read`); a server turns each into the capability
/// `signup:<action>@<tenant>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantMember {
    /// The member's `did:mata:…`.
    pub did: String,
    /// The actions it may perform in this tenant.
    pub grants: Vec<String>,
}

/// Event names a webhook can subscribe to.
pub const WEBHOOK_EVENTS: &[&str] = &[
    // A code was emailed (sign-up or sign-in); no user record yet for a new
    // address. Its data carries the address and whether a user already exists.
    "signup.code_sent",
    "user.created",
    "user.verified",
    "user.signed_in",
    "user.deleted",
];

/// Where a tenant's events are delivered. The secret signs every delivery
/// (HMAC-SHA256 over `timestamp.body`); `Debug` never prints it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// `wh_` + random id.
    pub id: String,
    /// The `https://` URL deliveries are POSTed to.
    pub url: String,
    /// Subscribed event names (a subset of [`WEBHOOK_EVENTS`]).
    pub events: Vec<String>,
    /// The signing secret, base64url. Shown to the tenant once, at creation.
    pub secret: String,
    /// Unix seconds.
    pub created_at: u64,
    /// The body's shape. [`WebhookFormat::Event`] (the default) is the signed
    /// event JSON; [`WebhookFormat::Slack`] is a Slack incoming-webhook message.
    #[serde(default, skip_serializing_if = "WebhookFormat::is_event")]
    pub format: WebhookFormat,
}

/// How a webhook delivery's body is shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookFormat {
    /// The event JSON (`{id, type, tenant, created_at, data}`), HMAC-signed.
    #[default]
    Event,
    /// `{"text": …}` for a Slack (or Slack-compatible) incoming webhook, from
    /// [`WebhookFormat::slack_text`]. The URL is the credential: keep it secret.
    Slack,
}

impl WebhookFormat {
    /// `"event"` / `"slack"`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "" | "event" => Some(Self::Event),
            "slack" => Some(Self::Slack),
            _ => None,
        }
    }

    /// The name [`Self::parse`] accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Slack => "slack",
        }
    }

    fn is_event(&self) -> bool {
        *self == Self::Event
    }

    /// The Slack line for `event` about `email`. Slack's control characters
    /// (`&`, `<`, `>`) in the address are escaped, so it cannot inject a link
    /// or a mention.
    pub fn slack_text(event: &str, email: &str) -> String {
        let email = email
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        match event {
            "signup.code_sent" => format!("New OTP Request for {email}"),
            "user.created" => format!("Welcome new user - {email}"),
            "user.verified" => format!("Address verified - {email}"),
            "user.signed_in" => format!("Signed in - {email}"),
            "user.deleted" => format!("User deleted - {email}"),
            other => format!("{other} - {email}"),
        }
    }
}

impl fmt::Debug for WebhookEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookEndpoint")
            .field("id", &self.id)
            // The path can be the credential (Slack): print the origin only.
            .field("url", &url_origin(&self.url))
            .field("events", &self.events)
            .field("secret", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("format", &self.format)
            .finish()
    }
}

/// `scheme://host` of a URL, for logs: a webhook URL's path may be its secret.
pub fn url_origin(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    format!("{scheme}://{host}/…")
}

impl WebhookEndpoint {
    /// Whether this endpoint wants `event`.
    pub fn wants(&self, event: &str) -> bool {
        self.events.iter().any(|e| e == event)
    }
}

impl Tenant {
    /// Create a tenant with a fresh public id.
    pub fn new(
        id: TenantId,
        name: impl Into<String>,
        origins: Vec<String>,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<Self, EntropyError> {
        let mut raw = [0u8; 16];
        entropy.fill(&mut raw)?;
        Ok(Self {
            id,
            name: name.into(),
            public_id: format!("pub_{}", enc::encode(&raw)),
            origins: origins.into_iter().map(|o| normalize_origin(&o)).collect(),
            created_at: now,
            members: Vec::new(),
            webhooks: Vec::new(),
        })
    }

    /// `true` iff `origin` (as a browser sends it in the `Origin` header) is
    /// on the allow-list. Compared after trimming, lowercasing and dropping a
    /// trailing slash.
    pub fn allows_origin(&self, origin: &str) -> bool {
        let wanted = normalize_origin(origin);
        self.origins.contains(&wanted)
    }

    /// Store key for a tenant.
    pub fn key(id: &TenantId) -> String {
        format!("tenant/{id}")
    }

    /// Store key mapping a public id back to the tenant.
    pub fn public_key(public_id: &str) -> String {
        format!("tenant-public/{public_id}")
    }
}

fn normalize_origin(o: &str) -> String {
    o.trim().trim_end_matches('/').to_lowercase()
}

// ─── User ────────────────────────────────────────────────────────────────────

/// A user id: an RFC 4122 v4 UUID in lowercase hyphenated form. Minted from
/// 16 caller-supplied random bytes so the core needs no RNG of its own, and
/// kept as a UUID so it can serve as the subject of a `did:mata:<uuid>`
/// account identifier where an adopter wants one.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserId(String);

impl UserId {
    /// Parse any RFC 4122 textual form; the id is stored lowercase hyphenated.
    pub fn parse(raw: &str) -> Result<Self, UserIdError> {
        let u = uuid::Uuid::parse_str(raw.trim()).map_err(|e| UserIdError(e.to_string()))?;
        Ok(Self(u.hyphenated().to_string()))
    }

    /// A v4 UUID from 16 random bytes (the version and variant bits are
    /// overwritten per RFC 4122).
    pub fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(
            uuid::Builder::from_random_bytes(bytes)
                .into_uuid()
                .hyphenated()
                .to_string(),
        )
    }

    /// Draw a fresh id from the entropy source.
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Self, EntropyError> {
        let mut raw = [0u8; 16];
        entropy.fill(&mut raw)?;
        Ok(Self::from_random_bytes(raw))
    }

    /// The id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({})", self.0)
    }
}

impl TryFrom<String> for UserId {
    type Error = UserIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<UserId> for String {
    fn from(u: UserId) -> Self {
        u.0
    }
}

/// The value is not a UUID.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("user id is not a UUID: {0}")]
pub struct UserIdError(
    /// The parser's message.
    pub String,
);

/// A user within a tenant. One address → one user ([`User::email_key`]).
///
/// `linked_did` is the bridge to the DID world: a user who signed up by email
/// may later prove a `did:mata` (through `mid-signin`) and have it recorded
/// here, after which a tenant can treat either proof as this user. It is
/// optional, forever: nothing in this crate requires a DID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// The user id.
    pub id: UserId,
    /// The owning tenant.
    pub tenant: TenantId,
    /// The canonical address (the tenant needs it to reach the user).
    pub email: NormalizedEmail,
    /// The peppered lookup index of `email` (also the uniqueness key).
    pub email_idx: EmailIndex,
    /// When the address was first proven, Unix seconds. `None` only for
    /// imported records whose proof predates this system.
    pub email_verified_at: Option<u64>,
    /// Unix seconds.
    pub created_at: u64,
    /// Last successful verify, Unix seconds.
    pub last_sign_in_at: Option<u64>,
    /// A `did:mata:…` the user has proven and linked, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_did: Option<String>,
    /// A tenant-unique handle the user chose (see [`normalize_username`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Tenant-defined attributes (display name, locale, …). Opaque to the
    /// core; never used in any key or MAC.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl User {
    /// Store key for a user.
    pub fn key(tenant: &TenantId, id: &UserId) -> String {
        format!("user/{tenant}/{id}")
    }

    /// Store key enforcing one address → one user; its value is the user id.
    pub fn email_key(tenant: &TenantId, email_idx: &EmailIndex) -> String {
        format!("user-email/{tenant}/{email_idx}")
    }

    /// Record a proven DID. Idempotent for the same DID; refuses a different
    /// one while a link exists (unlink first — an explicit, auditable step).
    /// The caller is responsible for having verified the DID (e.g. through
    /// `mid-signin`) before calling this.
    pub fn link_did(&mut self, did: &str) -> Result<(), FlowError> {
        let did = did.trim();
        if !did.starts_with("did:mata:") || did.len() <= "did:mata:".len() {
            return Err(FlowError::InvalidDid);
        }
        match &self.linked_did {
            Some(existing) if existing == did => Ok(()),
            Some(existing) => Err(FlowError::DidAlreadyLinked {
                did: existing.clone(),
            }),
            None => {
                self.linked_did = Some(did.to_string());
                Ok(())
            }
        }
    }

    /// Remove the linked DID, returning it.
    pub fn unlink_did(&mut self) -> Option<String> {
        self.linked_did.take()
    }
}

// ─── Challenge ───────────────────────────────────────────────────────────────

/// A challenge id: 16 random bytes, base64url on the wire and in keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ChallengeId([u8; 16]);

impl ChallengeId {
    /// Draw a fresh id.
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Self, EntropyError> {
        let mut raw = [0u8; 16];
        entropy.fill(&mut raw)?;
        Ok(Self(raw))
    }

    /// Wrap raw bytes read back from a store.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw 16 bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// base64url (no padding).
    pub fn to_base64url(&self) -> String {
        enc::encode(&self.0)
    }
}

impl fmt::Display for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64url())
    }
}

impl fmt::Debug for ChallengeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChallengeId({})", self.to_base64url())
    }
}

impl TryFrom<String> for ChallengeId {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        enc::decode_exact::<16>(&s).map(Self)
    }
}

impl From<ChallengeId> for String {
    fn from(c: ChallengeId) -> Self {
        c.to_base64url()
    }
}

/// How a challenge ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumedReason {
    /// The right code was presented.
    Verified,
    /// Too many wrong codes.
    Exhausted,
    /// A newer code was issued for the same address.
    Superseded,
}

/// One issued code, as the store holds it. Never contains the code — only
/// its [`CodeMac`] commitment. The policy values are frozen in at issue
/// time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The challenge id.
    pub id: ChallengeId,
    /// The owning tenant.
    pub tenant: TenantId,
    /// The address the code was sent to (needed for a resend and for the
    /// user record on first verify).
    pub email: NormalizedEmail,
    /// The peppered index of `email` (the live-key component).
    pub email_idx: EmailIndex,
    /// The commitment to the code.
    pub code_mac: CodeMac,
    /// Whether a successful verify may create the user. `false` is
    /// sign-in-only.
    pub create_user: bool,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; the code is rejected at and after this instant.
    pub expires_at: u64,
    /// Guesses allowed, frozen from the policy.
    pub max_attempts: u32,
    /// Guesses made so far (right or wrong).
    pub attempts: u32,
    /// When the challenge ended, if it has.
    pub consumed_at: Option<u64>,
    /// Why it ended.
    pub consumed_reason: Option<ConsumedReason>,
}

impl Challenge {
    /// Store key for a challenge.
    pub fn key(tenant: &TenantId, id: &ChallengeId) -> String {
        format!("challenge/{tenant}/{id}")
    }

    /// Store key enforcing one live code per address; its value is the
    /// challenge id. Written on start, cleared (or overwritten) on consume.
    pub fn live_key(tenant: &TenantId, email_idx: &EmailIndex) -> String {
        format!("challenge-live/{tenant}/{email_idx}")
    }

    /// Not consumed and not expired at `now`.
    pub fn is_live(&self, now: u64) -> bool {
        self.consumed_at.is_none() && now < self.expires_at
    }

    /// Guesses remaining.
    pub fn attempts_left(&self) -> u32 {
        self.max_attempts.saturating_sub(self.attempts)
    }

    pub(crate) fn consume(&mut self, now: u64, reason: ConsumedReason) {
        self.consumed_at = Some(now);
        self.consumed_reason = Some(reason);
    }
}

// ─── Audit ───────────────────────────────────────────────────────────────────

/// Why a verify was refused, for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// No live challenge for the address.
    Missing,
    /// The challenge had expired.
    Expired,
    /// The challenge was already consumed.
    Consumed,
    /// Wrong code; attempts remain.
    Wrong,
    /// Wrong code; no attempts remain.
    Exhausted,
    /// Right code, but no user and sign-in-only.
    UnknownUser,
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditKind {
    /// A code was issued.
    ChallengeIssued,
    /// A live challenge was replaced by a resend.
    ChallengeSuperseded,
    /// A code was accepted.
    CodeAccepted,
    /// A code was refused.
    CodeRejected {
        /// Why.
        reason: RejectReason,
    },
    /// A user record was created.
    UserCreated,
    /// A tenant was created.
    TenantCreated,
    /// A tenant's settings (origins, name) changed.
    TenantUpdated,
    /// A user record was imported from another system, keeping its id.
    UserImported,
    /// A user's tenant-defined metadata changed.
    UserUpdated,
    /// A user record was deleted.
    UserDeleted,
    /// A DID was linked to a user.
    DidLinked,
    /// A user's DID link was removed.
    DidUnlinked,
    /// A user's username was set, changed or cleared.
    UsernameChanged,
    /// A tenant's members (backend DIDs and their grants) were replaced.
    MembersChanged,
    /// A webhook endpoint was added.
    WebhookAdded,
    /// A webhook endpoint was removed.
    WebhookRemoved,
    /// A webhook delivery was acknowledged by the endpoint.
    WebhookDelivered,
    /// A webhook delivery was abandoned after its last retry.
    WebhookAbandoned,
    /// A user's sessions were revoked (sign-out everywhere, deletion, or a
    /// replayed refresh token).
    SessionsRevoked,
}

/// One audit row. Carries ids and the address **index**, never the address
/// or the code, so the trail can be retained and shipped freely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix seconds.
    pub at: u64,
    /// The tenant.
    pub tenant: TenantId,
    /// What happened.
    pub kind: AuditKind,
    /// The user involved, when known.
    pub user: Option<UserId>,
    /// The challenge involved, when any.
    pub challenge: Option<ChallengeId>,
    /// The address index involved, when any.
    pub email_idx: Option<EmailIndex>,
}

impl AuditEvent {
    /// Store key prefix for a tenant's audit rows; the caller appends a
    /// monotonic sequence to make it unique.
    pub fn key_prefix(tenant: &TenantId, at: u64) -> String {
        format!("audit/{tenant}/{at:020}/")
    }
}

// ─── Usernames ───────────────────────────────────────────────────────────────

/// Shortest username, in characters.
pub const MIN_USERNAME_LEN: usize = 3;
/// Longest username, in characters.
pub const MAX_USERNAME_LEN: usize = 32;

/// Canonical form of a username: trimmed, lowercased, 3–32 of `a-z 0-9 _ . -`,
/// starting and ending with a letter or digit. Two inputs that normalize equal
/// are the same name.
pub fn normalize_username(raw: &str) -> Result<String, FlowError> {
    let s = raw.trim().to_lowercase();
    let n = s.chars().count();
    let ok = (MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&n)
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes().last().is_some_and(|b| b.is_ascii_alphanumeric());
    if ok {
        Ok(s)
    } else {
        Err(FlowError::InvalidUsername)
    }
}
