//! The persistent store (feature `store`): the pure flow, made durable.
//!
//! [`SignupStore`] wraps the core's pure functions in transactions on
//! [`spacedb-store`](https://crates.io/crates/spacedb-store):
//!
//! * **Atomic steps.** [`SignupStore::start`] and [`SignupStore::verify`] each
//!   run in **one** single-writer transaction that reads its inputs *inside*
//!   the transaction, calls [`flow::start`] / [`flow::verify`], and writes back
//!   every row they return — plus the audit rows — before committing. Two
//!   concurrent verifies of one code serialize: exactly one succeeds, and a
//!   wrong guess is counted even when it loses a race.
//! * **Durable.** Every accepted write commits with
//!   [`Durability::Immediate`] (fsync on the redb engine). An acknowledged
//!   sign-up survives a power cut.
//! * **Sealed at rest.** Every value is AES-256-GCM under a per-collection DEK
//!   wrapped by a key-encryption key ([`KeyProvider`]), with the row's table,
//!   key and schema version as associated data, and compression **off** (rows
//!   mix secrets with attacker-chosen bytes, so a compressed length would
//!   leak). Keys hold ids and peppered indexes only — never an address, a
//!   DID, or a client address.
//! * **Unique where it matters.** One address → one user, one live code per
//!   address, one DID → one user, one public id → one tenant: each is an index
//!   row checked and written in the same transaction as the record it guards.
//! * **Rate-limited in the service.** Sends are charged against sliding
//!   windows per address, per client and per tenant ([`Limits`]) inside the
//!   start transaction; a refused start charges nothing and writes nothing.
//! * **Recoverable.** [`SignupStore::dump`] / [`SignupStore::restore`] move the
//!   whole store as one value (for a snapshot tier to seal and ship), and
//!   restore rebuilds every index from the records — refusing a dump made
//!   under a different pepper. [`SignupStore::check_integrity`] proves the
//!   indexes and records agree.
//!
//! One process owns a store directory: the redb engine takes an exclusive
//! lock, so a second opener (another process, or the same one) is refused
//! rather than allowed to fork the data.
//!
//! This layer is single-node. Replicating it — and turning the uniqueness
//! claims into quorum (Strong-tier) claims — is a SpaceDB replication concern
//! for a later milestone; the record shapes here do not change for it.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spacedb_store::{
    Collection, Compression, Durability, KeyProvider, KvEngine, Readable, StaticKeyProvider,
    WriteTx, KEY_LEN,
};

// The engine and key types this module's API takes, re-exported so an
// adopter depends on this crate only.
#[cfg(not(target_arch = "wasm32"))]
pub use spacedb_store::RedbEngine;
pub use spacedb_store::{KeyProvider as StoreKeyProvider, KvEngine as StoreEngine};
pub use spacedb_store::{MemEngine, StaticKeyProvider as StaticStoreKey};

use crate::email::{EmailIndex, NormalizedEmail};
use crate::enc;
use crate::error::FlowError;
use crate::flow::{self, StartOutcome, StartRequest, Verified, VerifyRequest};
use crate::pepper::Pepper;
use crate::policy::{Policy, RateWindow};
use crate::records::{
    normalize_username, AuditEvent, AuditKind, Challenge, ChallengeId, Tenant, TenantId,
    TenantMember, User, UserId, WebhookEndpoint, WebhookFormat, WEBHOOK_EVENTS,
};
use crate::seams::{Entropy, OsEntropy};

const SCHEMA: u32 = 1;
const C_TENANTS: &str = "signup_tenants";
const C_USERS: &str = "signup_users";
const C_CHALLENGES: &str = "signup_challenges";
const C_INDEX: &str = "signup_index";
const C_RATES: &str = "signup_rates";
const C_AUDIT: &str = "signup_audit";
const C_META: &str = "signup_meta";
const C_SESSIONS: &str = "signup_sessions";
const C_OUTBOX: &str = "signup_outbox";
const META_AUDIT_SEQ: &str = "audit_seq";
/// Above every key this store writes (all ASCII) — the open end of a prefix scan.
const KEY_MAX: char = '\u{10FFFF}';

/// Version of the [`SignupDump`] format.
pub const DUMP_VERSION: u8 = 1;
/// File name of the redb database inside a store directory.
pub const DB_FILE: &str = "signup.redb";
/// File name of the key-encryption key inside a store directory.
pub const KEK_FILE: &str = "signup.key";

const DID_INDEX_DOMAIN: &[u8] = b"mid-sovereign-signup/did-index/v1\0";
const CLIENT_INDEX_DOMAIN: &[u8] = b"mid-sovereign-signup/client-index/v1\0";
const USERNAME_INDEX_DOMAIN: &[u8] = b"mid-sovereign-signup/username-index/v1\0";

/// Deliveries abandoned after this many failed attempts (about 12 hours of
/// exponential backoff, capped at one hour between tries).
pub const MAX_DELIVERY_ATTEMPTS: u32 = 15;

// ─── errors ──────────────────────────────────────────────────────────────────

/// Errors from the store. Flow outcomes (wrong code, expired, rate limited, …)
/// arrive as [`StoreError::Flow`]; everything else is a store-level refusal or
/// failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The flow refused (see [`FlowError`]).
    #[error(transparent)]
    Flow(#[from] FlowError),
    /// No tenant with this id.
    #[error("unknown tenant: {0}")]
    UnknownTenant(TenantId),
    /// A tenant with this id already exists.
    #[error("tenant already exists: {0}")]
    TenantExists(TenantId),
    /// The public id is already assigned to another tenant.
    #[error("public id already in use")]
    PublicIdTaken,
    /// No user with this id in this tenant.
    #[error("user not found")]
    UserNotFound,
    /// A user with this id already exists in this tenant.
    #[error("a user with this id already exists")]
    UserIdTaken,
    /// A user with this address already exists in this tenant.
    #[error("a user with this address already exists")]
    EmailTaken,
    /// This DID is already linked to another user in this tenant.
    #[error("this DID is linked to another user")]
    DidTaken,
    /// The username is taken in this tenant.
    #[error("this username is taken")]
    UsernameTaken,
    /// The session or refresh token is unknown, expired, revoked, or was
    /// already used (a replayed refresh token also revokes its session).
    #[error("the session is not valid; sign in again")]
    SessionInvalid,
    /// No webhook with this id in this tenant.
    #[error("webhook not found")]
    WebhookNotFound,
    /// A webhook or member definition was refused.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// An update tried to change a field only the flow may change.
    #[error("{0} cannot be changed through this call")]
    Immutable(&'static str),
    /// A dump's records were indexed under a different pepper than this
    /// store's — restoring would make every user unreachable by address.
    #[error("the dump was made under a different pepper")]
    PepperMismatch,
    /// A restore was refused.
    #[error("restore refused: {0}")]
    Restore(String),
    /// A stored row did not decode — corruption or a schema mismatch.
    #[error("corrupt row at {key}: {msg}")]
    Corrupt {
        /// The row's key.
        key: String,
        /// What failed.
        msg: String,
    },
    /// The key-encryption key file could not be read or created.
    #[error("key file: {0}")]
    KeyFile(String),
    /// The storage engine failed (I/O, a wrong key-encryption key, a second
    /// opener of the same file).
    #[error("storage: {0}")]
    Storage(#[from] spacedb_store::StoreError),
}

impl StoreError {
    /// A stable machine-readable code. Flow refusals keep their own codes.
    pub fn code(&self) -> &'static str {
        match self {
            StoreError::Flow(f) => f.code(),
            StoreError::UnknownTenant(_) => "unknown_tenant",
            StoreError::TenantExists(_) => "tenant_exists",
            StoreError::PublicIdTaken => "public_id_taken",
            StoreError::UserNotFound => "user_not_found",
            StoreError::UserIdTaken => "user_id_taken",
            StoreError::EmailTaken => "email_taken",
            StoreError::DidTaken => "did_taken",
            StoreError::UsernameTaken => "username_taken",
            StoreError::SessionInvalid => "session_invalid",
            StoreError::WebhookNotFound => "webhook_not_found",
            StoreError::InvalidConfig(_) => "invalid_config",
            StoreError::Immutable(_) => "immutable_field",
            StoreError::PepperMismatch => "pepper_mismatch",
            StoreError::Restore(_) => "restore_refused",
            StoreError::Corrupt { .. } => "corrupt_row",
            StoreError::KeyFile(_) => "key_file",
            StoreError::Storage(_) => "storage_failure",
        }
    }

    /// The flow refusal, if this is one.
    pub fn as_flow(&self) -> Option<&FlowError> {
        match self {
            StoreError::Flow(f) => Some(f),
            _ => None,
        }
    }
}

type Result<T, E = StoreError> = std::result::Result<T, E>;

// ─── limits ──────────────────────────────────────────────────────────────────

/// One sliding-window rule: at most `limit` sends per `window_secs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateRule {
    /// Window length, seconds.
    pub window_secs: u64,
    /// Sends admitted per window.
    pub limit: u32,
}

impl RateRule {
    /// `limit` sends per `window_secs`.
    pub const fn new(window_secs: u64, limit: u32) -> Self {
        Self { window_secs, limit }
    }
}

/// Send limits applied by [`SignupStore::start`]. Every code costs an email —
/// money and sender reputation — so these live in the service, not only at
/// the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Per address (by its peppered index).
    pub per_address: Option<RateRule>,
    /// Per client (the caller passes a client key, e.g. its IP; only a
    /// peppered index of it is stored).
    pub per_client: Option<RateRule>,
    /// Per tenant, across all its addresses.
    pub per_tenant: Option<RateRule>,
}

impl Limits {
    /// 5 sends per address per hour, 30 per client per hour, no tenant cap.
    pub const DEFAULT: Limits = Limits {
        per_address: Some(RateRule::new(3_600, 5)),
        per_client: Some(RateRule::new(3_600, 30)),
        per_tenant: None,
    };
    /// No limits (tests, or an operator enforcing them elsewhere).
    pub const NONE: Limits = Limits {
        per_address: None,
        per_client: None,
        per_tenant: None,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ─── rows ────────────────────────────────────────────────────────────────────

/// One audit row: an [`AuditEvent`] and its position in the store-wide,
/// gap-free sequence. The sequence is also the store's height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRow {
    /// 1-based, contiguous, never reused.
    pub seq: u64,
    /// The event.
    pub event: AuditEvent,
}

// ─── imports ─────────────────────────────────────────────────────────────────

/// What an import does with a username it cannot claim (taken, or not a
/// valid username — systems being migrated rarely enforced either).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsernameConflict {
    /// Refuse the whole user.
    Refuse,
    /// Import the user without the username, and report it.
    Drop,
}

/// A username an import could not claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsernameDropped {
    /// The name as it arrived.
    pub username: String,
    /// `username_taken` or `invalid_username`.
    pub reason: &'static str,
}

/// How one import went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportOutcome {
    /// Written now.
    Imported {
        /// The stored user.
        user: User,
        /// Set when the username could not be claimed under
        /// [`UsernameConflict::Drop`].
        username_dropped: Option<UsernameDropped>,
    },
    /// The same id with the same address was already here (a re-run).
    AlreadyPresent {
        /// The stored user.
        user: User,
    },
}

/// The ids in `ids` that have no user in `tenant` (the migration's proof).
impl<E: KvEngine> SignupStore<E> {
    /// Which of `ids` are missing from `tenant`.
    pub fn missing_users(&self, tenant: &TenantId, ids: &[UserId]) -> Result<Vec<UserId>> {
        let tx = self.engine.begin_read()?;
        let mut missing = Vec::new();
        for id in ids {
            if self.users.get(&tx, &User::key(tenant, id))?.is_none() {
                missing.push(id.clone());
            }
        }
        Ok(missing)
    }
}

// ─── sessions ────────────────────────────────────────────────────────────────

/// Session lifetimes: a short access token, a longer refresh token that
/// rotates on every use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTtl {
    /// Access-token lifetime, seconds.
    pub access_secs: u64,
    /// Refresh-token lifetime, seconds (from the session's issue).
    pub refresh_secs: u64,
}

impl SessionTtl {
    /// One hour access, thirty days refresh.
    pub const DEFAULT: SessionTtl = SessionTtl {
        access_secs: 3_600,
        refresh_secs: 30 * 86_400,
    };
}

impl Default for SessionTtl {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A session as stored: keyed by the SHA-256 of its access token, so the
/// store never holds a usable token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// base64url SHA-256 of the access token — the row's key.
    pub token_hash: String,
    /// base64url SHA-256 of the current refresh token.
    pub refresh_hash: String,
    /// The tenant.
    pub tenant: TenantId,
    /// The user.
    pub user: UserId,
    /// Unix seconds.
    pub issued_at: u64,
    /// Access expiry, Unix seconds.
    pub expires_at: u64,
    /// Refresh expiry, Unix seconds.
    pub refresh_expires_at: u64,
}

/// What a client holds. Opaque, random, revocable; `Debug` prints neither.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTokens {
    /// `sess_…` — sent as `Authorization: Bearer`.
    pub token: String,
    /// `ref_…` — exchanged once for a new pair.
    pub refresh: String,
    /// Access expiry, Unix seconds.
    pub expires_at: u64,
    /// Refresh expiry, Unix seconds.
    pub refresh_expires_at: u64,
}

impl std::fmt::Debug for SessionTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTokens")
            .field("expires_at", &self.expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish_non_exhaustive()
    }
}

// ─── webhook outbox ──────────────────────────────────────────────────────────

/// One pending webhook delivery, written in the same transaction as the
/// event it reports — so an event is never committed without its delivery,
/// nor a delivery queued for an event that rolled back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    /// `<event_id>.<webhook_id>` — unique per delivery.
    pub id: String,
    /// `evt_<seq>_<type>` — the same for every endpoint receiving the event;
    /// receivers deduplicate on it.
    pub event_id: String,
    /// The tenant.
    pub tenant: TenantId,
    /// The endpoint.
    pub webhook_id: String,
    /// The event name.
    pub event_type: String,
    /// The user the event is about.
    pub user: Option<UserId>,
    /// The exact JSON body to POST (signed at delivery time).
    pub payload: String,
    /// Unix seconds.
    pub created_at: u64,
    /// Failed attempts so far.
    pub attempts: u32,
    /// Not before, Unix seconds.
    pub next_attempt_at: u64,
    /// The last failure, for operators.
    pub last_error: Option<String>,
}

/// A due delivery and the endpoint it goes to (with the signing secret).
#[derive(Debug, Clone)]
pub struct Delivery {
    /// The queued item.
    pub item: OutboxItem,
    /// Its endpoint, as configured now.
    pub endpoint: WebhookEndpoint,
}

/// The whole store as one value — what a snapshot tier seals and ships.
///
/// **It contains plaintext addresses and metadata.** Never write it anywhere
/// unencrypted; hand it straight to a tier that seals it (the way
/// `kms-registry` hands its dump to an encrypted, erasure-coded tier).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignupDump {
    /// [`DUMP_VERSION`].
    pub version: u8,
    /// The audit sequence at dump time (the height).
    pub audit_seq: u64,
    /// Every tenant.
    pub tenants: Vec<Tenant>,
    /// Every user.
    pub users: Vec<User>,
    /// Every stored challenge (live or ended, until purged).
    pub challenges: Vec<Challenge>,
    /// Every rate window, by its store key.
    pub rates: Vec<(String, RateWindow)>,
    /// The audit log.
    pub audit: Vec<AuditRow>,
    /// Live sessions (hashes only — no usable token is ever stored).
    #[serde(default)]
    pub sessions: Vec<SessionRecord>,
    /// Pending webhook deliveries.
    #[serde(default)]
    pub outbox: Vec<OutboxItem>,
}

impl std::fmt::Debug for SignupDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupDump")
            .field("version", &self.version)
            .field("audit_seq", &self.audit_seq)
            .field("tenants", &self.tenants.len())
            .field("users", &self.users.len())
            .field("challenges", &self.challenges.len())
            .field("rates", &self.rates.len())
            .field("audit", &self.audit.len())
            .field("sessions", &self.sessions.len())
            .field("outbox", &self.outbox.len())
            .finish()
    }
}

/// What [`SignupStore::check_integrity`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntegrityReport {
    /// Tenants.
    pub tenants: usize,
    /// Users.
    pub users: usize,
    /// Stored challenges.
    pub challenges: usize,
    /// Challenges reachable through the live index.
    pub live_challenges: usize,
    /// Audit rows.
    pub audit_rows: usize,
    /// Every inconsistency, in words. Empty = clean.
    pub problems: Vec<String>,
}

impl IntegrityReport {
    /// No problems found.
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

// ─── the store ───────────────────────────────────────────────────────────────

/// The persistent sign-up store over any [`KvEngine`]. See the module docs.
///
/// Holds the [`Pepper`] in memory (it is never written to the store it
/// protects), the [`Policy`] and the [`Limits`]. Share one instance across
/// threads (`Arc<SignupStore<_>>`); writes serialize inside the engine.
pub struct SignupStore<E: KvEngine> {
    engine: E,
    pepper: Pepper,
    policy: Policy,
    limits: Limits,
    tenants: Collection<String, String>,
    users: Collection<String, String>,
    challenges: Collection<String, String>,
    index: Collection<String, String>,
    rates: Collection<String, String>,
    audit: Collection<u64, String>,
    meta: Collection<String, u64>,
    sessions: Collection<String, String>,
    outbox: Collection<String, String>,
}

impl<E: KvEngine> std::fmt::Debug for SignupStore<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignupStore")
            .field("policy", &self.policy)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl SignupStore<RedbEngine> {
    /// Open (creating if absent) a store in `dir`: the database in
    /// [`DB_FILE`] and a 32-byte key-encryption key in [`KEK_FILE`] (created
    /// from the OS RNG on first open, mode `0600` on Unix).
    ///
    /// Refused if the database is already open — by this process or another.
    pub fn open_dir(dir: impl AsRef<Path>, pepper: Pepper) -> Result<Self> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|e| StoreError::KeyFile(e.to_string()))?;
        let kek = load_or_create_kek(&dir.join(KEK_FILE))?;
        let engine = RedbEngine::open(dir.join(DB_FILE))?;
        Self::open(engine, Arc::new(StaticKeyProvider::new(kek)), pepper)
    }
}

impl SignupStore<MemEngine> {
    /// A store in memory under a random key-encryption key. Loses everything
    /// on drop — for tests, and for wasm hosts that persist dumps themselves.
    pub fn in_memory(pepper: Pepper) -> Result<Self> {
        let mut kek = [0u8; KEY_LEN];
        OsEntropy
            .fill(&mut kek)
            .map_err(|e| StoreError::KeyFile(e.to_string()))?;
        Self::open(
            MemEngine::new(),
            Arc::new(StaticKeyProvider::new(kek)),
            pepper,
        )
    }
}

impl<E: KvEngine> SignupStore<E> {
    /// Open a store over `engine`, sealing rows under `keys`. Uses
    /// [`Policy::DEFAULT`] and [`Limits::DEFAULT`] until changed.
    pub fn open(engine: E, keys: Arc<dyn KeyProvider>, pepper: Pepper) -> Result<Self> {
        let open = |name: &str| {
            Collection::open_or_create_with(&engine, keys.clone(), name, SCHEMA, Compression::Off)
        };
        let tenants = open(C_TENANTS)?;
        let users = open(C_USERS)?;
        let challenges = open(C_CHALLENGES)?;
        let index = open(C_INDEX)?;
        let rates = open(C_RATES)?;
        let audit = Collection::open_or_create_with(
            &engine,
            keys.clone(),
            C_AUDIT,
            SCHEMA,
            Compression::Off,
        )?;
        let sessions = open(C_SESSIONS)?;
        let outbox = open(C_OUTBOX)?;
        let meta =
            Collection::open_or_create_with(&engine, keys, C_META, SCHEMA, Compression::Off)?;
        Ok(Self {
            engine,
            pepper,
            policy: Policy::DEFAULT,
            limits: Limits::DEFAULT,
            tenants,
            users,
            challenges,
            index,
            rates,
            audit,
            meta,
            sessions,
            outbox,
        })
    }

    /// Replace the policy (validated).
    pub fn with_policy(mut self, policy: Policy) -> Result<Self> {
        policy.validate().map_err(FlowError::from)?;
        self.policy = policy;
        Ok(self)
    }

    /// Replace the send limits.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The policy in force.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The send limits in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The peppered index of `email` in `tenant` (normalizing it first).
    pub fn email_index(&self, tenant: &TenantId, email: &str) -> Result<EmailIndex> {
        let email = NormalizedEmail::parse(email).map_err(FlowError::from)?;
        Ok(EmailIndex::derive(&self.pepper, tenant, &email))
    }

    // ── tenants ──────────────────────────────────────────────────────────────

    /// Create a tenant. Refused if the id or the public id is taken.
    pub fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        if self.tenant_in(&tx, &tenant.id)?.is_some() {
            return Err(StoreError::TenantExists(tenant.id.clone()));
        }
        let pkey = Tenant::public_key(&tenant.public_id);
        if self.index.get(&tx, &pkey)?.is_some() {
            return Err(StoreError::PublicIdTaken);
        }
        put_json(&self.tenants, &mut tx, &Tenant::key(&tenant.id), tenant)?;
        self.index.put(&mut tx, &pkey, &tenant.id.to_string())?;
        self.append_audit(
            &mut tx,
            &[event(
                tenant.created_at,
                &tenant.id,
                AuditKind::TenantCreated,
            )],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// A tenant by id.
    pub fn tenant(&self, id: &TenantId) -> Result<Option<Tenant>> {
        let tx = self.engine.begin_read()?;
        self.tenant_in(&tx, id)
    }

    /// A tenant by its public id (what a browser page presents).
    pub fn tenant_by_public_id(&self, public_id: &str) -> Result<Option<Tenant>> {
        let tx = self.engine.begin_read()?;
        match self.index.get(&tx, &Tenant::public_key(public_id))? {
            None => Ok(None),
            Some(id) => {
                let id =
                    TenantId::parse(&id).map_err(|e| corrupt(&Tenant::public_key(public_id), e))?;
                self.tenant_in(&tx, &id)
            }
        }
    }

    /// Every tenant, in id order.
    pub fn tenants(&self) -> Result<Vec<Tenant>> {
        let tx = self.engine.begin_read()?;
        Ok(scan_json(&self.tenants, &tx, "tenant/")?
            .into_iter()
            .map(|(_, t)| t)
            .collect())
    }

    /// Replace a tenant's display name and origin allow-list (the id, public
    /// id and creation time never change).
    pub fn update_tenant(
        &self,
        id: &TenantId,
        name: impl Into<String>,
        origins: Vec<String>,
        now: u64,
    ) -> Result<Tenant> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut tenant = self
            .tenant_in(&tx, id)?
            .ok_or_else(|| StoreError::UnknownTenant(id.clone()))?;
        // Re-run the constructor's normalization on the new origins.
        let normalized = Tenant {
            origins,
            ..tenant.clone()
        };
        tenant.name = name.into();
        tenant.origins = normalized
            .origins
            .iter()
            .map(|o| o.trim().trim_end_matches('/').to_lowercase())
            .collect();
        put_json(&self.tenants, &mut tx, &Tenant::key(id), &tenant)?;
        self.append_audit(&mut tx, &[event(now, id, AuditKind::TenantUpdated)])?;
        tx.commit()?;
        Ok(tenant)
    }

    // ── the flow ─────────────────────────────────────────────────────────────

    /// Issue a code: charge the send limits, then [`flow::start`], all in one
    /// transaction. On success the caller hands
    /// [`StartOutcome::message`] to its mailer — after this returns, so a
    /// mailed code is always a committed commitment.
    ///
    /// `client` is the caller's client key for the per-client limit (e.g. the
    /// request's IP); only its peppered index is stored. A refused start
    /// (rate limit, resend cooldown, bad address) writes nothing.
    pub fn start(
        &self,
        req: &StartRequest<'_>,
        client: Option<&str>,
        entropy: &mut dyn Entropy,
    ) -> Result<StartOutcome> {
        let email = NormalizedEmail::parse(req.email).map_err(FlowError::from)?;
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let Some(tenant) = self.tenant_in(&tx, req.tenant)? else {
            return Err(StoreError::UnknownTenant(req.tenant.clone()));
        };
        let idx = EmailIndex::derive(&self.pepper, req.tenant, &email);

        if let Some(rule) = self.limits.per_address {
            self.charge(
                &mut tx,
                &rate_key("addr", req.tenant, &idx.to_base64url()),
                rule,
                req.now,
            )?;
        }
        if let (Some(rule), Some(client)) = (self.limits.per_client, client) {
            let cidx = scoped_index(&self.pepper, CLIENT_INDEX_DOMAIN, req.tenant, client);
            self.charge(
                &mut tx,
                &rate_key("client", req.tenant, &cidx),
                rule,
                req.now,
            )?;
        }
        if let Some(rule) = self.limits.per_tenant {
            self.charge(
                &mut tx,
                &rate_key("tenant", req.tenant, "all"),
                rule,
                req.now,
            )?;
        }

        let live = self.live_challenge_in(&tx, req.tenant, &idx)?;
        let out = flow::start(req, live, &self.policy, &self.pepper, entropy)?;

        if let Some(old) = &out.superseded {
            put_json(
                &self.challenges,
                &mut tx,
                &Challenge::key(&old.tenant, &old.id),
                old,
            )?;
        }
        let ch = &out.challenge;
        put_json(
            &self.challenges,
            &mut tx,
            &Challenge::key(&ch.tenant, &ch.id),
            ch,
        )?;
        self.index.put(
            &mut tx,
            &Challenge::live_key(&ch.tenant, &ch.email_idx),
            &ch.id.to_base64url(),
        )?;
        let seq = self.append_audit(&mut tx, &out.audit)?;
        if tenant.webhooks.iter().any(|w| w.wants("signup.code_sent")) {
            let existing = self
                .index
                .get(&tx, &User::email_key(req.tenant, &idx))?
                .is_some();
            let data = serde_json::json!({
                "email": email.as_str(),
                "existing_user": existing,
            });
            let subject = EventSubject {
                user: None,
                email: email.as_str(),
            };
            self.enqueue_event_in(&mut tx, &tenant, "signup.code_sent", subject, data, seq, req.now)?;
        }
        tx.commit()?;
        Ok(out)
    }

    /// Check a code and sign the user up or in: load the live challenge and
    /// the user **inside** one transaction, run [`flow::verify`], write back
    /// everything it returns, commit. A wrong guess is committed too — that is
    /// what makes the attempt limit real.
    pub fn verify(&self, req: &VerifyRequest<'_>, entropy: &mut dyn Entropy) -> Result<Verified> {
        self.verify_inner(req, None, entropy).map(|(v, _)| v)
    }

    /// [`Self::verify`] and, on success, open a session for the user — in the
    /// **same** transaction, so a verified user always leaves with a session
    /// and a session never exists for a verify that rolled back.
    pub fn verify_and_open_session(
        &self,
        req: &VerifyRequest<'_>,
        ttl: SessionTtl,
        entropy: &mut dyn Entropy,
    ) -> Result<(Verified, SessionTokens)> {
        let (v, tokens) = self.verify_inner(req, Some(ttl), entropy)?;
        Ok((v, tokens.expect("a session was requested")))
    }

    fn verify_inner(
        &self,
        req: &VerifyRequest<'_>,
        session: Option<SessionTtl>,
        entropy: &mut dyn Entropy,
    ) -> Result<(Verified, Option<SessionTokens>)> {
        // Malformed input never opens a transaction: it cannot be a guess.
        let email = NormalizedEmail::parse(req.email).map_err(FlowError::from)?;
        crate::Code::parse(req.code).map_err(FlowError::from)?;

        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let Some(tenant) = self.tenant_in(&tx, req.tenant)? else {
            return Err(StoreError::UnknownTenant(req.tenant.clone()));
        };
        let idx = EmailIndex::derive(&self.pepper, req.tenant, &email);
        let live = self.live_challenge_in(&tx, req.tenant, &idx)?;
        let existing = self.user_by_index_in(&tx, req.tenant, &idx)?;

        let result = flow::verify(req, live, existing, &self.pepper, entropy);

        if let Some(ch) = &result.challenge {
            put_json(
                &self.challenges,
                &mut tx,
                &Challenge::key(&ch.tenant, &ch.id),
                ch,
            )?;
            if ch.consumed_at.is_some() {
                self.index
                    .delete(&mut tx, &Challenge::live_key(&ch.tenant, &ch.email_idx))?;
            }
        }
        if let Ok(v) = &result.outcome {
            let ukey = User::key(&v.user.tenant, &v.user.id);
            if v.user_created && self.users.get(&tx, &ukey)?.is_some() {
                // A 2^-122 collision. Abort the whole step rather than
                // overwrite someone; the user simply starts again.
                return Err(StoreError::UserIdTaken);
            }
            put_json(&self.users, &mut tx, &ukey, &v.user)?;
            self.index.put(
                &mut tx,
                &User::email_key(&v.user.tenant, &v.user.email_idx),
                &v.user.id.to_string(),
            )?;
        }
        let seq = self.append_audit(&mut tx, &result.audit)?;
        let mut tokens = None;
        if let Ok(v) = &result.outcome {
            if let Some(ttl) = session {
                tokens = Some(self.open_session_in(&mut tx, &v.user, ttl, req.now, entropy)?);
            }
            let mut events = Vec::new();
            if v.user_created {
                events.push("user.created");
            }
            if v.first_verification {
                events.push("user.verified");
            }
            events.push("user.signed_in");
            for ev in events {
                self.enqueue_in(&mut tx, &tenant, ev, &v.user, seq, req.now)?;
            }
        }
        tx.commit()?;
        let v = result.outcome.map_err(StoreError::from)?;
        Ok((v, tokens))
    }

    // ── users ────────────────────────────────────────────────────────────────

    /// A user by id.
    pub fn user(&self, tenant: &TenantId, id: &UserId) -> Result<Option<User>> {
        let tx = self.engine.begin_read()?;
        get_json(&self.users, &tx, &User::key(tenant, id))
    }

    /// A user by address (normalized and indexed here).
    pub fn user_by_email(&self, tenant: &TenantId, email: &str) -> Result<Option<User>> {
        let idx = self.email_index(tenant, email)?;
        let tx = self.engine.begin_read()?;
        self.user_by_index_in(&tx, tenant, &idx)
    }

    /// The user a DID is linked to.
    pub fn user_by_did(&self, tenant: &TenantId, did: &str) -> Result<Option<User>> {
        let tx = self.engine.begin_read()?;
        match self.index.get(&tx, &self.did_key(tenant, did.trim()))? {
            None => Ok(None),
            Some(id) => {
                let id = UserId::parse(&id).map_err(|e| corrupt("user-did", e))?;
                get_json(&self.users, &tx, &User::key(tenant, &id))
            }
        }
    }

    /// A page of a tenant's users in id order, strictly after `after`.
    pub fn users(
        &self,
        tenant: &TenantId,
        after: Option<&UserId>,
        limit: usize,
    ) -> Result<Vec<User>> {
        let tx = self.engine.begin_read()?;
        let prefix = format!("user/{tenant}/");
        let lo = match after {
            Some(a) => format!("{}\0", User::key(tenant, a)),
            None => prefix.clone(),
        };
        let hi = format!("{prefix}{KEY_MAX}");
        let rows = self.users.range(&tx, &lo, &hi)?;
        rows.into_iter()
            .take(limit)
            .map(|(k, json)| decode(&k, &json))
            .collect()
    }

    /// How many users a tenant has.
    pub fn count_users(&self, tenant: &TenantId) -> Result<usize> {
        let tx = self.engine.begin_read()?;
        let prefix = format!("user/{tenant}/");
        Ok(self
            .users
            .range(&tx, &prefix, &format!("{prefix}{KEY_MAX}"))?
            .len())
    }

    /// Replace a user's metadata **from the user themselves**: the referral
    /// keys are protected and `referred_by` is recorded at most once
    /// ([`crate::referrals::apply_own_metadata`]).
    pub fn set_own_metadata(
        &self,
        tenant: &TenantId,
        id: &UserId,
        incoming: std::collections::BTreeMap<String, serde_json::Value>,
        now: u64,
    ) -> Result<User> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut user = self.user_in(&tx, tenant, id)?;
        user.metadata = crate::referrals::apply_own_metadata(
            &user.metadata,
            incoming,
            user.username.as_deref(),
            user.created_at,
            now,
        );
        put_json(&self.users, &mut tx, &User::key(tenant, id), &user)?;
        self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::UserUpdated)])?;
        tx.commit()?;
        Ok(user)
    }

    /// A user's referral stats: who referred them, how many they referred
    /// (users whose `referred_by` is their username, case-insensitively),
    /// and their share.
    pub fn referral_stats(&self, tenant: &TenantId, id: &UserId) -> Result<crate::referrals::ReferralStats> {
        let user = self.user(tenant, id)?.ok_or(StoreError::UserNotFound)?;
        let count = match user.username.as_deref() {
            Some(name) => {
                let name = name.to_lowercase();
                self.users(tenant, None, usize::MAX)?
                    .iter()
                    .filter(|u| {
                        crate::referrals::referred_by(&u.metadata)
                            .map(|r| r.to_lowercase() == name)
                            .unwrap_or(false)
                    })
                    .count() as u64
            }
            None => 0,
        };
        Ok(crate::referrals::ReferralStats {
            referred_by: crate::referrals::referred_by(&user.metadata),
            referral_count: count,
            referral_percent: crate::referrals::referral_percent(&user.metadata),
        })
    }

    /// Every referrer with at least one referral, most first.
    pub fn referral_report(&self, tenant: &TenantId) -> Result<Vec<crate::referrals::ReferrerRow>> {
        let users = self.users(tenant, None, usize::MAX)?;
        let mut counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for u in &users {
            if let Some(r) = crate::referrals::referred_by(&u.metadata) {
                *counts.entry(r.to_lowercase()).or_default() += 1;
            }
        }
        let mut rows: Vec<crate::referrals::ReferrerRow> = users
            .iter()
            .filter_map(|u| {
                let name = u.username.as_ref()?;
                let n = *counts.get(&name.to_lowercase())?;
                Some(crate::referrals::ReferrerRow {
                    user_id: u.id.to_string(),
                    username: name.clone(),
                    referral_count: n,
                    referral_percent: crate::referrals::referral_percent(&u.metadata),
                })
            })
            .collect();
        rows.sort_by(|a, b| b.referral_count.cmp(&a.referral_count).then(a.username.cmp(&b.username)));
        Ok(rows)
    }

    /// Set a referrer's profit share (operator only), 0 to 100 percent.
    pub fn set_referral_percent(&self, tenant: &TenantId, id: &UserId, percent: f64, now: u64) -> Result<User> {
        if !(0.0..=100.0).contains(&percent) {
            return Err(StoreError::InvalidConfig("referral_percent must be between 0 and 100".into()));
        }
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut user = self.user_in(&tx, tenant, id)?;
        user.metadata.insert(
            crate::referrals::REFERRAL_PERCENT.to_string(),
            serde_json::json!(percent),
        );
        put_json(&self.users, &mut tx, &User::key(tenant, id), &user)?;
        self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::UserUpdated)])?;
        tx.commit()?;
        Ok(user)
    }

    /// Replace a user's tenant-defined metadata.
    pub fn set_user_metadata(
        &self,
        tenant: &TenantId,
        id: &UserId,
        metadata: std::collections::BTreeMap<String, serde_json::Value>,
        now: u64,
    ) -> Result<User> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut user = self.user_in(&tx, tenant, id)?;
        user.metadata = metadata;
        put_json(&self.users, &mut tx, &User::key(tenant, id), &user)?;
        self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::UserUpdated)])?;
        tx.commit()?;
        Ok(user)
    }

    /// Link a DID the caller has **already verified** (e.g. through
    /// `mid-signin`) to a user. Idempotent for the same DID; refused if the
    /// user has a different one or the DID is linked to someone else here.
    pub fn link_did(&self, tenant: &TenantId, id: &UserId, did: &str, now: u64) -> Result<User> {
        let did = did.trim();
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut user = self.user_in(&tx, tenant, id)?;
        let dkey = self.did_key(tenant, did);
        if let Some(owner) = self.index.get(&tx, &dkey)? {
            if owner != id.as_str() {
                return Err(StoreError::DidTaken);
            }
        }
        let already = user.linked_did.as_deref() == Some(did);
        user.link_did(did)?;
        if !already {
            put_json(&self.users, &mut tx, &User::key(tenant, id), &user)?;
            self.index.put(&mut tx, &dkey, &id.to_string())?;
            self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::DidLinked)])?;
            tx.commit()?;
        }
        Ok(user)
    }

    /// Remove a user's DID link, returning the DID it had.
    pub fn unlink_did(&self, tenant: &TenantId, id: &UserId, now: u64) -> Result<Option<String>> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut user = self.user_in(&tx, tenant, id)?;
        let Some(did) = user.unlink_did() else {
            return Ok(None);
        };
        self.index.delete(&mut tx, &self.did_key(tenant, &did))?;
        put_json(&self.users, &mut tx, &User::key(tenant, id), &user)?;
        self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::DidUnlinked)])?;
        tx.commit()?;
        Ok(Some(did))
    }

    /// Delete a user and every index pointing at them. The address is free to
    /// sign up again (as a new user id). Returns whether the user existed.
    pub fn delete_user(&self, tenant: &TenantId, id: &UserId, now: u64) -> Result<bool> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let user: Option<User> = get_json(&self.users, &tx, &User::key(tenant, id))?;
        let Some(user) = user else {
            return Ok(false);
        };
        self.users.delete(&mut tx, &User::key(tenant, id))?;
        self.index
            .delete(&mut tx, &User::email_key(tenant, &user.email_idx))?;
        if let Some(did) = &user.linked_did {
            self.index.delete(&mut tx, &self.did_key(tenant, did))?;
        }
        if let Some(name) = &user.username {
            self.index
                .delete(&mut tx, &self.username_key(tenant, name))?;
        }
        self.revoke_user_sessions_in(&mut tx, tenant, id)?;
        let seq = self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::UserDeleted)])?;
        if let Some(t) = self.tenant_in(&tx, tenant)? {
            self.enqueue_in(&mut tx, &t, "user.deleted", &user, seq, now)?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Bring in a user from another system **keeping its id** (the migration
    /// door). Refuses a username that is taken or malformed; see
    /// [`Self::import_user_with`] for the migration-friendly policy.
    pub fn import_user(&self, user: &User, now: u64) -> Result<User> {
        match self.import_user_with(user, now, UsernameConflict::Refuse)? {
            ImportOutcome::Imported { user, .. } => Ok(user),
            ImportOutcome::AlreadyPresent { .. } => Err(StoreError::UserIdTaken),
        }
    }

    /// Import with an explicit username policy. The address index is
    /// recomputed under this store's pepper; the id, the address and any DID
    /// must be free in the tenant — except that the **same id with the same
    /// address** answers [`ImportOutcome::AlreadyPresent`], so a migration
    /// can be re-run after a partial failure without a single error.
    pub fn import_user_with(
        &self,
        user: &User,
        now: u64,
        usernames: UsernameConflict,
    ) -> Result<ImportOutcome> {
        let mut user = user.clone();
        user.email_idx = EmailIndex::derive(&self.pepper, &user.tenant, &user.email);
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        if self.tenant_in(&tx, &user.tenant)?.is_none() {
            return Err(StoreError::UnknownTenant(user.tenant.clone()));
        }
        let ukey = User::key(&user.tenant, &user.id);
        if let Some(existing) = get_json::<User>(&self.users, &tx, &ukey)? {
            if existing.email_idx == user.email_idx {
                return Ok(ImportOutcome::AlreadyPresent { user: existing });
            }
            return Err(StoreError::UserIdTaken);
        }
        let ekey = User::email_key(&user.tenant, &user.email_idx);
        if self.index.get(&tx, &ekey)?.is_some() {
            return Err(StoreError::EmailTaken);
        }
        if let Some(did) = &user.linked_did {
            if !did.starts_with("did:mata:") || did.len() <= "did:mata:".len() {
                return Err(FlowError::InvalidDid.into());
            }
            let dkey = self.did_key(&user.tenant, did);
            if self.index.get(&tx, &dkey)?.is_some() {
                return Err(StoreError::DidTaken);
            }
            self.index.put(&mut tx, &dkey, &user.id.to_string())?;
        }
        let mut username_dropped = None;
        if let Some(raw) = user.username.take() {
            let claim = match normalize_username(&raw) {
                Err(e) => Err(StoreError::from(e)),
                Ok(name) => {
                    let nkey = self.username_key(&user.tenant, &name);
                    if self.index.get(&tx, &nkey)?.is_some() {
                        Err(StoreError::UsernameTaken)
                    } else {
                        Ok((name, nkey))
                    }
                }
            };
            match (claim, usernames) {
                (Ok((name, nkey)), _) => {
                    self.index.put(&mut tx, &nkey, &user.id.to_string())?;
                    user.username = Some(name);
                }
                (Err(e), UsernameConflict::Refuse) => return Err(e),
                (Err(e), UsernameConflict::Drop) => {
                    username_dropped = Some(UsernameDropped {
                        username: raw,
                        reason: e.code(),
                    });
                }
            }
        }
        put_json(&self.users, &mut tx, &ukey, &user)?;
        self.index.put(&mut tx, &ekey, &user.id.to_string())?;
        self.append_audit(&mut tx, &[user_event(now, &user, AuditKind::UserImported)])?;
        tx.commit()?;
        Ok(ImportOutcome::Imported {
            user,
            username_dropped,
        })
    }

    // ── usernames ────────────────────────────────────────────────────────────

    /// Whether `name` (normalized) is free in the tenant. Malformed names are
    /// an error, not "unavailable".
    pub fn username_available(&self, tenant: &TenantId, name: &str) -> Result<bool> {
        let name = normalize_username(name)?;
        let tx = self.engine.begin_read()?;
        Ok(self
            .index
            .get(&tx, &self.username_key(tenant, &name))?
            .is_none())
    }

    /// Set (or with `None` clear) a user's username, claiming it uniquely in
    /// the same transaction.
    pub fn set_username(
        &self,
        tenant: &TenantId,
        id: &UserId,
        name: Option<&str>,
        now: u64,
    ) -> Result<User> {
        let name = name.map(normalize_username).transpose()?;
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut user = self.user_in(&tx, tenant, id)?;
        if user.username == name {
            return Ok(user);
        }
        if let Some(n) = &name {
            let nkey = self.username_key(tenant, n);
            if self.index.get(&tx, &nkey)?.is_some() {
                return Err(StoreError::UsernameTaken);
            }
            self.index.put(&mut tx, &nkey, &id.to_string())?;
        }
        if let Some(old) = &user.username {
            self.index
                .delete(&mut tx, &self.username_key(tenant, old))?;
        }
        user.username = name;
        put_json(&self.users, &mut tx, &User::key(tenant, id), &user)?;
        self.append_audit(
            &mut tx,
            &[user_event(now, &user, AuditKind::UsernameChanged)],
        )?;
        tx.commit()?;
        Ok(user)
    }

    // ── sessions ─────────────────────────────────────────────────────────────

    /// Open a session for an existing user (e.g. after a sign-in proven some
    /// other way, such as an mID).
    pub fn open_session(
        &self,
        tenant: &TenantId,
        id: &UserId,
        ttl: SessionTtl,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<SessionTokens> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let user = self.user_in(&tx, tenant, id)?;
        let tokens = self.open_session_in(&mut tx, &user, ttl, now, entropy)?;
        tx.commit()?;
        Ok(tokens)
    }

    /// The live session an access token names, or `None` if it is unknown,
    /// expired or revoked.
    pub fn session(&self, token: &str, now: u64) -> Result<Option<SessionRecord>> {
        let tx = self.engine.begin_read()?;
        let rec: Option<SessionRecord> =
            get_json(&self.sessions, &tx, &session_key(&token_hash(token)))?;
        Ok(rec.filter(|r| now < r.expires_at))
    }

    /// Exchange a refresh token for a new pair. The old pair dies. Presenting
    /// an already-used refresh token is treated as theft: the session it was
    /// rotated into is revoked too, and the call fails.
    pub fn refresh_session(
        &self,
        refresh: &str,
        ttl: SessionTtl,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<SessionTokens> {
        let rhash = token_hash(refresh);
        let rkey = refresh_key(&rhash);
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let Some(shash) = self.index.get(&tx, &rkey)? else {
            return Err(StoreError::SessionInvalid);
        };
        let rec: Option<SessionRecord> = get_json(&self.sessions, &tx, &session_key(&shash))?;
        let Some(rec) = rec else {
            self.index.delete(&mut tx, &rkey)?;
            tx.commit()?;
            return Err(StoreError::SessionInvalid);
        };
        if rec.refresh_hash != rhash {
            // A rotated-away refresh token came back: someone holds a copy.
            self.drop_session_in(&mut tx, &rec)?;
            self.index.delete(&mut tx, &rkey)?;
            let user: Option<User> =
                get_json(&self.users, &tx, &User::key(&rec.tenant, &rec.user))?;
            if let Some(u) = user {
                self.append_audit(&mut tx, &[user_event(now, &u, AuditKind::SessionsRevoked)])?;
            }
            tx.commit()?;
            return Err(StoreError::SessionInvalid);
        }
        if now >= rec.refresh_expires_at {
            self.drop_session_in(&mut tx, &rec)?;
            tx.commit()?;
            return Err(StoreError::SessionInvalid);
        }
        let user = self.user_in(&tx, &rec.tenant, &rec.user)?;
        self.sessions
            .delete(&mut tx, &session_key(&rec.token_hash))?;
        let tokens = self.open_session_in(&mut tx, &user, ttl, now, entropy)?;
        // Keep the spent refresh token pointing at its successor, so a replay
        // is recognised (and punished) instead of merely refused.
        self.index.put(&mut tx, &rkey, &token_hash(&tokens.token))?;
        tx.commit()?;
        Ok(tokens)
    }

    /// End one session (sign out). Returns whether it existed.
    pub fn revoke_session(&self, token: &str) -> Result<bool> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let rec: Option<SessionRecord> =
            get_json(&self.sessions, &tx, &session_key(&token_hash(token)))?;
        let Some(rec) = rec else {
            return Ok(false);
        };
        self.drop_session_in(&mut tx, &rec)?;
        tx.commit()?;
        Ok(true)
    }

    /// End every session a user has (sign out everywhere). Returns how many.
    pub fn revoke_user_sessions(&self, tenant: &TenantId, id: &UserId, now: u64) -> Result<usize> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let user = self.user_in(&tx, tenant, id)?;
        let n = self.revoke_user_sessions_in(&mut tx, tenant, id)?;
        self.append_audit(
            &mut tx,
            &[user_event(now, &user, AuditKind::SessionsRevoked)],
        )?;
        tx.commit()?;
        Ok(n)
    }

    /// Delete sessions whose refresh window has closed, and refresh-index
    /// rows that point at nothing. Returns how many sessions went.
    pub fn purge_sessions(&self, now: u64) -> Result<usize> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let all: Vec<(String, SessionRecord)> = scan_json(&self.sessions, &tx, "session/")?;
        let mut purged = 0;
        for (_, rec) in &all {
            if now >= rec.refresh_expires_at {
                self.drop_session_in(&mut tx, rec)?;
                purged += 1;
            }
        }
        for (rkey, shash) in self.index.range(
            &tx,
            &"session-refresh/".to_string(),
            &format!("session-refresh/{KEY_MAX}"),
        )? {
            if self.sessions.get(&tx, &session_key(&shash))?.is_none() {
                self.index.delete(&mut tx, &rkey)?;
            }
        }
        tx.commit()?;
        Ok(purged)
    }

    // ── tenant members and webhooks ─────────────────────────────────────────

    /// Replace the DIDs allowed to call this tenant's backend API.
    pub fn set_members(
        &self,
        tenant: &TenantId,
        members: Vec<TenantMember>,
        now: u64,
    ) -> Result<Tenant> {
        for m in &members {
            if !m.did.starts_with("did:mata:") || m.did.len() <= "did:mata:".len() {
                return Err(StoreError::InvalidConfig(format!(
                    "not a did:mata: {}",
                    m.did
                )));
            }
        }
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut t = self
            .tenant_in(&tx, tenant)?
            .ok_or_else(|| StoreError::UnknownTenant(tenant.clone()))?;
        t.members = members;
        put_json(&self.tenants, &mut tx, &Tenant::key(tenant), &t)?;
        self.append_audit(&mut tx, &[event(now, tenant, AuditKind::MembersChanged)])?;
        tx.commit()?;
        Ok(t)
    }

    /// Add a webhook endpoint with a fresh signing secret. The returned
    /// endpoint carries the secret — the only time it is handed out.
    pub fn add_webhook(
        &self,
        tenant: &TenantId,
        url: &str,
        events: Vec<String>,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<WebhookEndpoint> {
        self.add_webhook_with(tenant, url, events, WebhookFormat::Event, now, entropy)
    }

    /// [`Self::add_webhook`] with a body [`WebhookFormat`].
    pub fn add_webhook_with(
        &self,
        tenant: &TenantId,
        url: &str,
        events: Vec<String>,
        format: WebhookFormat,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<WebhookEndpoint> {
        let url = url.trim();
        check_webhook(url, &events)?;
        let mut id = [0u8; 9];
        let mut secret = [0u8; 32];
        entropy.fill(&mut id).map_err(FlowError::from)?;
        entropy.fill(&mut secret).map_err(FlowError::from)?;
        let hook = WebhookEndpoint {
            id: format!("wh_{}", enc::encode(&id)),
            url: url.to_string(),
            events,
            secret: enc::encode(&secret),
            created_at: now,
            format,
        };
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut t = self
            .tenant_in(&tx, tenant)?
            .ok_or_else(|| StoreError::UnknownTenant(tenant.clone()))?;
        t.webhooks.push(hook.clone());
        put_json(&self.tenants, &mut tx, &Tenant::key(tenant), &t)?;
        self.append_audit(&mut tx, &[event(now, tenant, AuditKind::WebhookAdded)])?;
        tx.commit()?;
        Ok(hook)
    }

    /// Make the endpoint `id` exist with exactly `url`, `events` and `format`:
    /// created with a fresh secret if absent, updated in place (secret kept)
    /// if different, untouched if equal. For endpoints a deployment declares
    /// in its configuration rather than through the API. Returns whether
    /// anything changed.
    #[allow(clippy::too_many_arguments)]
    pub fn ensure_webhook(
        &self,
        tenant: &TenantId,
        id: &str,
        url: &str,
        events: Vec<String>,
        format: WebhookFormat,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<bool> {
        let url = url.trim();
        check_webhook(url, &events)?;
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut t = self
            .tenant_in(&tx, tenant)?
            .ok_or_else(|| StoreError::UnknownTenant(tenant.clone()))?;
        match t.webhooks.iter_mut().find(|w| w.id == id) {
            Some(w) if w.url == url && w.events == events && w.format == format => {
                return Ok(false)
            }
            Some(w) => {
                w.url = url.to_string();
                w.events = events;
                w.format = format;
            }
            None => {
                let mut secret = [0u8; 32];
                entropy.fill(&mut secret).map_err(FlowError::from)?;
                t.webhooks.push(WebhookEndpoint {
                    id: id.to_string(),
                    url: url.to_string(),
                    events,
                    secret: enc::encode(&secret),
                    created_at: now,
                    format,
                });
            }
        }
        put_json(&self.tenants, &mut tx, &Tenant::key(tenant), &t)?;
        self.append_audit(&mut tx, &[event(now, tenant, AuditKind::WebhookAdded)])?;
        tx.commit()?;
        Ok(true)
    }

    /// Remove a webhook endpoint; its queued deliveries are dropped.
    pub fn remove_webhook(&self, tenant: &TenantId, id: &str, now: u64) -> Result<()> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let mut t = self
            .tenant_in(&tx, tenant)?
            .ok_or_else(|| StoreError::UnknownTenant(tenant.clone()))?;
        let before = t.webhooks.len();
        t.webhooks.retain(|w| w.id != id);
        if t.webhooks.len() == before {
            return Err(StoreError::WebhookNotFound);
        }
        put_json(&self.tenants, &mut tx, &Tenant::key(tenant), &t)?;
        let queued: Vec<(String, OutboxItem)> = scan_json(&self.outbox, &tx, "outbox/")?;
        for (key, item) in queued {
            if item.tenant == *tenant && item.webhook_id == id {
                self.outbox.delete(&mut tx, &key)?;
            }
        }
        self.append_audit(&mut tx, &[event(now, tenant, AuditKind::WebhookRemoved)])?;
        tx.commit()?;
        Ok(())
    }

    // ── webhook outbox ───────────────────────────────────────────────────────

    /// Up to `limit` deliveries due at `now`, oldest first, each with its
    /// endpoint as configured now. Items whose endpoint was removed are
    /// skipped (and are deleted by [`Self::remove_webhook`]).
    pub fn due_deliveries(&self, now: u64, limit: usize) -> Result<Vec<Delivery>> {
        let tx = self.engine.begin_read()?;
        let mut items: Vec<OutboxItem> = values(scan_json(&self.outbox, &tx, "outbox/")?);
        items.retain(|i| i.next_attempt_at <= now);
        items.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        let mut out = Vec::new();
        for item in items {
            let Some(t) = self.tenant_in(&tx, &item.tenant)? else {
                continue;
            };
            if let Some(endpoint) = t.webhooks.into_iter().find(|w| w.id == item.webhook_id) {
                out.push(Delivery { item, endpoint });
                if out.len() == limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Pending deliveries.
    pub fn outbox_len(&self) -> Result<usize> {
        let tx = self.engine.begin_read()?;
        Ok(self
            .outbox
            .range(&tx, &"outbox/".to_string(), &format!("outbox/{KEY_MAX}"))?
            .len())
    }

    /// The endpoint acknowledged a delivery: dequeue and audit it.
    pub fn delivery_succeeded(&self, id: &str, now: u64) -> Result<()> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let key = outbox_key(id);
        let item: Option<OutboxItem> = get_json(&self.outbox, &tx, &key)?;
        let Some(item) = item else {
            return Ok(());
        };
        self.outbox.delete(&mut tx, &key)?;
        self.append_audit(
            &mut tx,
            &[delivery_event(now, &item, AuditKind::WebhookDelivered)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// A delivery failed: schedule the retry with exponential backoff (30 s
    /// doubling, capped at an hour), or abandon and audit it after
    /// [`MAX_DELIVERY_ATTEMPTS`]. Returns `true` if it was abandoned.
    pub fn delivery_failed(&self, id: &str, now: u64, error: &str) -> Result<bool> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let key = outbox_key(id);
        let item: Option<OutboxItem> = get_json(&self.outbox, &tx, &key)?;
        let Some(mut item) = item else {
            return Ok(false);
        };
        item.attempts += 1;
        item.last_error = Some(error.chars().take(300).collect());
        let abandoned = item.attempts >= MAX_DELIVERY_ATTEMPTS;
        if abandoned {
            self.outbox.delete(&mut tx, &key)?;
            self.append_audit(
                &mut tx,
                &[delivery_event(now, &item, AuditKind::WebhookAbandoned)],
            )?;
        } else {
            let backoff = 30u64
                .saturating_mul(1u64 << item.attempts.min(20))
                .min(3_600);
            item.next_attempt_at = now.saturating_add(backoff);
            put_json(&self.outbox, &mut tx, &key, &item)?;
        }
        tx.commit()?;
        Ok(abandoned)
    }

    // ── challenges ───────────────────────────────────────────────────────────

    /// A stored challenge by id (live or ended).
    pub fn challenge(&self, tenant: &TenantId, id: &ChallengeId) -> Result<Option<Challenge>> {
        let tx = self.engine.begin_read()?;
        get_json(&self.challenges, &tx, &Challenge::key(tenant, id))
    }

    /// The live challenge for an address, if any (it may be past its TTL —
    /// expiry is decided at verify).
    pub fn live_challenge(&self, tenant: &TenantId, email: &str) -> Result<Option<Challenge>> {
        let idx = self.email_index(tenant, email)?;
        let tx = self.engine.begin_read()?;
        self.live_challenge_in(&tx, tenant, &idx)
    }

    /// Delete challenges that ended, or expired, more than `retain_secs`
    /// before `now` — with their live-index entries. Returns how many went.
    pub fn purge_challenges(&self, now: u64, retain_secs: u64) -> Result<usize> {
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let all: Vec<(String, Challenge)> = scan_json(&self.challenges, &tx, "challenge/")?;
        let mut purged = 0;
        for (key, ch) in all {
            let ended = ch.consumed_at.unwrap_or(ch.expires_at).min(ch.expires_at);
            if ended.saturating_add(retain_secs) > now {
                continue;
            }
            self.challenges.delete(&mut tx, &key)?;
            let lkey = Challenge::live_key(&ch.tenant, &ch.email_idx);
            if self.index.get(&tx, &lkey)?.as_deref() == Some(ch.id.to_base64url().as_str()) {
                self.index.delete(&mut tx, &lkey)?;
            }
            purged += 1;
        }
        if purged > 0 {
            tx.commit()?;
        }
        Ok(purged)
    }

    // ── audit ────────────────────────────────────────────────────────────────

    /// The audit sequence of the last write — the store's height.
    pub fn height(&self) -> Result<u64> {
        let tx = self.engine.begin_read()?;
        Ok(self
            .meta
            .get(&tx, &META_AUDIT_SEQ.to_string())?
            .unwrap_or(0))
    }

    /// Up to `limit` audit rows after `after_seq`, optionally for one tenant.
    pub fn audit(
        &self,
        tenant: Option<&TenantId>,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditRow>> {
        let tx = self.engine.begin_read()?;
        let mut out = Vec::new();
        for (seq, json) in self
            .audit
            .range(&tx, &after_seq.saturating_add(1), &u64::MAX)?
        {
            let row: AuditRow = decode(&format!("audit/{seq}"), &json)?;
            if tenant.is_none_or(|t| *t == row.event.tenant) {
                out.push(row);
                if out.len() == limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    // ── dump / restore / integrity ───────────────────────────────────────────

    /// Everything, as one value. See [`SignupDump`] — it is plaintext.
    pub fn dump(&self) -> Result<SignupDump> {
        let tx = self.engine.begin_read()?;
        let audit_seq = self
            .meta
            .get(&tx, &META_AUDIT_SEQ.to_string())?
            .unwrap_or(0);
        let audit = self
            .audit
            .range(&tx, &0, &u64::MAX)?
            .into_iter()
            .map(|(seq, json)| decode(&format!("audit/{seq}"), &json))
            .collect::<Result<Vec<AuditRow>>>()?;
        Ok(SignupDump {
            version: DUMP_VERSION,
            audit_seq,
            tenants: values(scan_json(&self.tenants, &tx, "tenant/")?),
            users: values(scan_json(&self.users, &tx, "user/")?),
            challenges: values(scan_json(&self.challenges, &tx, "challenge/")?),
            rates: scan_json(&self.rates, &tx, "rate/")?,
            audit,
            sessions: values(scan_json(&self.sessions, &tx, "session/")?),
            outbox: values(scan_json(&self.outbox, &tx, "outbox/")?),
        })
    }

    /// Load a dump into an **empty** store, rebuilding every index from the
    /// records in one transaction. Refused if this store holds anything, if
    /// the dump's records were indexed under a different pepper, or if the
    /// dump violates a uniqueness rule.
    pub fn restore(&self, dump: &SignupDump) -> Result<()> {
        if dump.version != DUMP_VERSION {
            return Err(StoreError::Restore(format!(
                "unsupported dump version {}",
                dump.version
            )));
        }
        let mut tx = self.engine.begin_write(Durability::Immediate)?;
        let seq = self
            .meta
            .get(&tx, &META_AUDIT_SEQ.to_string())?
            .unwrap_or(0);
        let any_tenant = !self
            .tenants
            .range(&tx, &"tenant/".to_string(), &format!("tenant/{KEY_MAX}"))?
            .is_empty();
        if seq != 0 || any_tenant {
            return Err(StoreError::Restore(
                "refusing to restore over a non-empty store".into(),
            ));
        }

        for t in &dump.tenants {
            let pkey = Tenant::public_key(&t.public_id);
            if self.index.get(&tx, &pkey)?.is_some() {
                return Err(StoreError::Restore(format!(
                    "duplicate public id for {}",
                    t.id
                )));
            }
            put_json(&self.tenants, &mut tx, &Tenant::key(&t.id), t)?;
            self.index.put(&mut tx, &pkey, &t.id.to_string())?;
        }
        for u in &dump.users {
            if self.tenant_in(&tx, &u.tenant)?.is_none() {
                return Err(StoreError::Restore(format!(
                    "user of unknown tenant {}",
                    u.tenant
                )));
            }
            if EmailIndex::derive(&self.pepper, &u.tenant, &u.email) != u.email_idx {
                return Err(StoreError::PepperMismatch);
            }
            let ekey = User::email_key(&u.tenant, &u.email_idx);
            if self.index.get(&tx, &ekey)?.is_some() {
                return Err(StoreError::Restore("two users share an address".into()));
            }
            put_json(&self.users, &mut tx, &User::key(&u.tenant, &u.id), u)?;
            self.index.put(&mut tx, &ekey, &u.id.to_string())?;
            if let Some(did) = &u.linked_did {
                let dkey = self.did_key(&u.tenant, did);
                if self.index.get(&tx, &dkey)?.is_some() {
                    return Err(StoreError::Restore("two users share a DID".into()));
                }
                self.index.put(&mut tx, &dkey, &u.id.to_string())?;
            }
            if let Some(name) = &u.username {
                let nkey = self.username_key(&u.tenant, name);
                if self.index.get(&tx, &nkey)?.is_some() {
                    return Err(StoreError::Restore("two users share a username".into()));
                }
                self.index.put(&mut tx, &nkey, &u.id.to_string())?;
            }
        }
        // The live index points at the newest unended challenge per address.
        let mut live: std::collections::BTreeMap<String, &Challenge> = Default::default();
        for ch in &dump.challenges {
            if EmailIndex::derive(&self.pepper, &ch.tenant, &ch.email) != ch.email_idx {
                return Err(StoreError::PepperMismatch);
            }
            put_json(
                &self.challenges,
                &mut tx,
                &Challenge::key(&ch.tenant, &ch.id),
                ch,
            )?;
            if ch.consumed_at.is_none() {
                let lkey = Challenge::live_key(&ch.tenant, &ch.email_idx);
                let newer = live
                    .get(&lkey)
                    .is_none_or(|cur| ch.issued_at >= cur.issued_at);
                if newer {
                    live.insert(lkey, ch);
                }
            }
        }
        for (lkey, ch) in live {
            self.index.put(&mut tx, &lkey, &ch.id.to_base64url())?;
        }
        for (key, w) in &dump.rates {
            put_json(&self.rates, &mut tx, key, w)?;
        }
        for row in &dump.audit {
            put_json_u64(&self.audit, &mut tx, row.seq, row)?;
        }
        for rec in &dump.sessions {
            put_json(&self.sessions, &mut tx, &session_key(&rec.token_hash), rec)?;
            self.index
                .put(&mut tx, &refresh_key(&rec.refresh_hash), &rec.token_hash)?;
        }
        for item in &dump.outbox {
            put_json(&self.outbox, &mut tx, &outbox_key(&item.id), item)?;
        }
        self.meta
            .put(&mut tx, &META_AUDIT_SEQ.to_string(), &dump.audit_seq)?;
        tx.commit()?;
        Ok(())
    }

    /// Check that every record has its index rows and every index row points
    /// at a matching record, that addresses are indexed under this store's
    /// pepper, and that the audit sequence is gap-free.
    pub fn check_integrity(&self) -> Result<IntegrityReport> {
        let tx = self.engine.begin_read()?;
        let mut r = IntegrityReport::default();
        let tenants: Vec<(String, Tenant)> = scan_json(&self.tenants, &tx, "tenant/")?;
        let users: Vec<(String, User)> = scan_json(&self.users, &tx, "user/")?;
        let challenges: Vec<(String, Challenge)> = scan_json(&self.challenges, &tx, "challenge/")?;
        r.tenants = tenants.len();
        r.users = users.len();
        r.challenges = challenges.len();

        for (key, t) in &tenants {
            if *key != Tenant::key(&t.id) {
                r.problems
                    .push(format!("tenant row {key} holds tenant {}", t.id));
            }
            match self.index.get(&tx, &Tenant::public_key(&t.public_id))? {
                Some(id) if id == t.id.as_str() => {}
                other => r
                    .problems
                    .push(format!("tenant {}: public index is {other:?}", t.id)),
            }
        }
        for (key, u) in &users {
            if *key != User::key(&u.tenant, &u.id) {
                r.problems
                    .push(format!("user row {key} holds user {}", u.id));
            }
            if self.tenant_in(&tx, &u.tenant)?.is_none() {
                r.problems.push(format!(
                    "user {} belongs to missing tenant {}",
                    u.id, u.tenant
                ));
            }
            if EmailIndex::derive(&self.pepper, &u.tenant, &u.email) != u.email_idx {
                r.problems.push(format!(
                    "user {}: address indexed under another pepper",
                    u.id
                ));
            }
            match self
                .index
                .get(&tx, &User::email_key(&u.tenant, &u.email_idx))?
            {
                Some(id) if id == u.id.as_str() => {}
                other => r
                    .problems
                    .push(format!("user {}: email index is {other:?}", u.id)),
            }
            if let Some(name) = &u.username {
                match self.index.get(&tx, &self.username_key(&u.tenant, name))? {
                    Some(id) if id == u.id.as_str() => {}
                    other => r
                        .problems
                        .push(format!("user {}: username index is {other:?}", u.id)),
                }
            }
            if let Some(did) = &u.linked_did {
                match self.index.get(&tx, &self.did_key(&u.tenant, did))? {
                    Some(id) if id == u.id.as_str() => {}
                    other => r
                        .problems
                        .push(format!("user {}: DID index is {other:?}", u.id)),
                }
            }
        }
        for (key, ch) in &challenges {
            if *key != Challenge::key(&ch.tenant, &ch.id) {
                r.problems
                    .push(format!("challenge row {key} holds {}", ch.id));
            }
        }

        // Index → record direction.
        for (key, id) in self.index.range(
            &tx,
            &"user-email/".to_string(),
            &format!("user-email/{KEY_MAX}"),
        )? {
            let Some(tenant) = key.split('/').nth(1).and_then(|t| TenantId::parse(t).ok()) else {
                r.problems.push(format!("malformed index key {key}"));
                continue;
            };
            let user = UserId::parse(&id)
                .ok()
                .map(|uid| get_json::<User>(&self.users, &tx, &User::key(&tenant, &uid)))
                .transpose()?
                .flatten();
            match user {
                Some(u) if User::email_key(&u.tenant, &u.email_idx) == key => {}
                _ => r
                    .problems
                    .push(format!("{key} points at a missing or different user")),
            }
        }
        for (key, id) in self.index.range(
            &tx,
            &"user-did/".to_string(),
            &format!("user-did/{KEY_MAX}"),
        )? {
            let Some(tenant) = key.split('/').nth(1).and_then(|t| TenantId::parse(t).ok()) else {
                r.problems.push(format!("malformed index key {key}"));
                continue;
            };
            let user = UserId::parse(&id)
                .ok()
                .map(|uid| get_json::<User>(&self.users, &tx, &User::key(&tenant, &uid)))
                .transpose()?
                .flatten();
            let ok = user.is_some_and(|u| {
                u.linked_did
                    .as_deref()
                    .is_some_and(|d| self.did_key(&u.tenant, d) == key)
            });
            if !ok {
                r.problems
                    .push(format!("{key} points at a missing or different user"));
            }
        }
        for (key, id) in self.index.range(
            &tx,
            &"challenge-live/".to_string(),
            &format!("challenge-live/{KEY_MAX}"),
        )? {
            let parsed = key
                .split('/')
                .nth(1)
                .and_then(|t| TenantId::parse(t).ok())
                .zip(ChallengeId::try_from(id.clone()).ok());
            let Some((tenant, cid)) = parsed else {
                r.problems
                    .push(format!("malformed live index {key} → {id}"));
                continue;
            };
            let ch: Option<Challenge> =
                get_json(&self.challenges, &tx, &Challenge::key(&tenant, &cid))?;
            match ch {
                Some(c)
                    if Challenge::live_key(&c.tenant, &c.email_idx) == key
                        && c.consumed_at.is_none() =>
                {
                    r.live_challenges += 1
                }
                _ => r.problems.push(format!(
                    "{key} points at a missing, foreign or ended challenge"
                )),
            }
        }
        for (key, id) in self.index.range(
            &tx,
            &"tenant-public/".to_string(),
            &format!("tenant-public/{KEY_MAX}"),
        )? {
            let ok = TenantId::parse(&id)
                .ok()
                .map(|t| self.tenant_in(&tx, &t))
                .transpose()?
                .flatten()
                .is_some_and(|t| Tenant::public_key(&t.public_id) == key);
            if !ok {
                r.problems
                    .push(format!("{key} points at a missing or different tenant"));
            }
        }

        for (key, id) in self.index.range(
            &tx,
            &"user-username/".to_string(),
            &format!("user-username/{KEY_MAX}"),
        )? {
            let Some(tenant) = key.split('/').nth(1).and_then(|t| TenantId::parse(t).ok()) else {
                r.problems.push(format!("malformed index key {key}"));
                continue;
            };
            let user = UserId::parse(&id)
                .ok()
                .map(|uid| get_json::<User>(&self.users, &tx, &User::key(&tenant, &uid)))
                .transpose()?
                .flatten();
            let ok = user.is_some_and(|u| {
                u.username
                    .as_deref()
                    .is_some_and(|n| self.username_key(&u.tenant, n) == key)
            });
            if !ok {
                r.problems
                    .push(format!("{key} points at a missing or different user"));
            }
        }
        let sessions: Vec<(String, SessionRecord)> = scan_json(&self.sessions, &tx, "session/")?;
        for (key, rec) in &sessions {
            if *key != session_key(&rec.token_hash) {
                r.problems
                    .push(format!("session row {key} holds another hash"));
            }
            if get_json::<User>(&self.users, &tx, &User::key(&rec.tenant, &rec.user))?.is_none() {
                r.problems
                    .push(format!("session {key} belongs to a missing user"));
            }
            if self
                .index
                .get(&tx, &refresh_key(&rec.refresh_hash))?
                .as_deref()
                != Some(rec.token_hash.as_str())
            {
                r.problems
                    .push(format!("session {key}: refresh index does not point back"));
            }
        }
        let seq = self
            .meta
            .get(&tx, &META_AUDIT_SEQ.to_string())?
            .unwrap_or(0);
        let rows = self.audit.range(&tx, &0, &u64::MAX)?;
        r.audit_rows = rows.len();
        for (i, (s, _)) in rows.iter().enumerate() {
            if *s != i as u64 + 1 {
                r.problems.push(format!("audit gap: row {i} has seq {s}"));
                break;
            }
        }
        if rows.len() as u64 != seq {
            r.problems.push(format!(
                "audit sequence says {seq}, log holds {}",
                rows.len()
            ));
        }
        Ok(r)
    }

    // ── internals ────────────────────────────────────────────────────────────

    fn tenant_in(&self, tx: &impl Readable, id: &TenantId) -> Result<Option<Tenant>> {
        get_json(&self.tenants, tx, &Tenant::key(id))
    }

    fn user_in(&self, tx: &impl Readable, tenant: &TenantId, id: &UserId) -> Result<User> {
        get_json(&self.users, tx, &User::key(tenant, id))?.ok_or(StoreError::UserNotFound)
    }

    fn user_by_index_in(
        &self,
        tx: &impl Readable,
        tenant: &TenantId,
        idx: &EmailIndex,
    ) -> Result<Option<User>> {
        let ekey = User::email_key(tenant, idx);
        match self.index.get(tx, &ekey)? {
            None => Ok(None),
            Some(id) => {
                let id = UserId::parse(&id).map_err(|e| corrupt(&ekey, e))?;
                let user = get_json(&self.users, tx, &User::key(tenant, &id))?;
                if user.is_none() {
                    return Err(StoreError::Corrupt {
                        key: ekey,
                        msg: "index points at a missing user".into(),
                    });
                }
                Ok(user)
            }
        }
    }

    fn live_challenge_in(
        &self,
        tx: &impl Readable,
        tenant: &TenantId,
        idx: &EmailIndex,
    ) -> Result<Option<Challenge>> {
        let lkey = Challenge::live_key(tenant, idx);
        match self.index.get(tx, &lkey)? {
            None => Ok(None),
            Some(id) => {
                let id = ChallengeId::try_from(id).map_err(|e| corrupt(&lkey, e))?;
                get_json(&self.challenges, tx, &Challenge::key(tenant, &id))
            }
        }
    }

    fn username_key(&self, tenant: &TenantId, name: &str) -> String {
        format!(
            "user-username/{tenant}/{}",
            scoped_index(&self.pepper, USERNAME_INDEX_DOMAIN, tenant, name)
        )
    }

    fn open_session_in(
        &self,
        tx: &mut impl WriteTx,
        user: &User,
        ttl: SessionTtl,
        now: u64,
        entropy: &mut dyn Entropy,
    ) -> Result<SessionTokens> {
        let mut a = [0u8; 32];
        let mut r = [0u8; 32];
        entropy.fill(&mut a).map_err(FlowError::from)?;
        entropy.fill(&mut r).map_err(FlowError::from)?;
        let tokens = SessionTokens {
            token: format!("sess_{}", enc::encode(&a)),
            refresh: format!("ref_{}", enc::encode(&r)),
            expires_at: now.saturating_add(ttl.access_secs),
            refresh_expires_at: now.saturating_add(ttl.refresh_secs),
        };
        let rec = SessionRecord {
            token_hash: token_hash(&tokens.token),
            refresh_hash: token_hash(&tokens.refresh),
            tenant: user.tenant.clone(),
            user: user.id.clone(),
            issued_at: now,
            expires_at: tokens.expires_at,
            refresh_expires_at: tokens.refresh_expires_at,
        };
        put_json(&self.sessions, tx, &session_key(&rec.token_hash), &rec)?;
        self.index
            .put(tx, &refresh_key(&rec.refresh_hash), &rec.token_hash)?;
        Ok(tokens)
    }

    fn drop_session_in(&self, tx: &mut impl WriteTx, rec: &SessionRecord) -> Result<()> {
        self.sessions.delete(tx, &session_key(&rec.token_hash))?;
        self.index.delete(tx, &refresh_key(&rec.refresh_hash))?;
        Ok(())
    }

    fn revoke_user_sessions_in(
        &self,
        tx: &mut impl WriteTx,
        tenant: &TenantId,
        id: &UserId,
    ) -> Result<usize> {
        let all: Vec<(String, SessionRecord)> = scan_json(&self.sessions, tx, "session/")?;
        let mut n = 0;
        for (_, rec) in all {
            if rec.tenant == *tenant && rec.user == *id {
                self.drop_session_in(tx, &rec)?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Queue `event` about `user` to every endpoint of `tenant` that wants
    /// it. `seq` is the audit sequence of the write that produced the event:
    /// the event id derives from it, so ids are unique and need no entropy.
    fn enqueue_in(
        &self,
        tx: &mut impl WriteTx,
        tenant: &Tenant,
        event_type: &str,
        user: &User,
        seq: u64,
        now: u64,
    ) -> Result<()> {
        let data = serde_json::json!({ "user": {
            "id": user.id.as_str(),
            "email": user.email.as_str(),
            "email_verified_at": user.email_verified_at,
            "username": user.username,
            "linked_did": user.linked_did,
            "created_at": user.created_at,
        }});
        let subject = EventSubject {
            user: Some(&user.id),
            email: user.email.as_str(),
        };
        self.enqueue_event_in(tx, tenant, event_type, subject, data, seq, now)
    }

    /// Queue `event_type` for every endpoint of `tenant` that wants it, each
    /// body in that endpoint's [`WebhookFormat`].
    #[allow(clippy::too_many_arguments)]
    fn enqueue_event_in(
        &self,
        tx: &mut impl WriteTx,
        tenant: &Tenant,
        event_type: &str,
        subject: EventSubject<'_>,
        data: serde_json::Value,
        seq: u64,
        now: u64,
    ) -> Result<()> {
        let event_id = format!("evt_{seq:012}_{}", event_type.replace('.', "_"));
        let event_body = serde_json::json!({
            "id": event_id,
            "type": event_type,
            "tenant": tenant.id.as_str(),
            "created_at": now,
            "data": data,
        })
        .to_string();
        for hook in tenant.webhooks.iter().filter(|w| w.wants(event_type)) {
            let payload = match hook.format {
                WebhookFormat::Event => event_body.clone(),
                WebhookFormat::Slack => serde_json::json!({
                    "text": WebhookFormat::slack_text(event_type, subject.email)
                })
                .to_string(),
            };
            let item = OutboxItem {
                id: format!("{event_id}.{}", hook.id),
                event_id: event_id.clone(),
                tenant: tenant.id.clone(),
                webhook_id: hook.id.clone(),
                event_type: event_type.to_string(),
                user: subject.user.cloned(),
                payload,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                last_error: None,
            };
            put_json(&self.outbox, tx, &outbox_key(&item.id), &item)?;
        }
        Ok(())
    }

    fn did_key(&self, tenant: &TenantId, did: &str) -> String {
        format!(
            "user-did/{tenant}/{}",
            scoped_index(&self.pepper, DID_INDEX_DOMAIN, tenant, did)
        )
    }

    /// Charge one send against a window; refused = nothing written (the
    /// caller drops the transaction).
    fn charge(&self, tx: &mut impl WriteTx, key: &str, rule: RateRule, now: u64) -> Result<()> {
        let mut w: RateWindow = get_json(&self.rates, tx, key)?
            .unwrap_or_else(|| RateWindow::new(rule.window_secs, rule.limit));
        w.reconfigure(rule.window_secs, rule.limit);
        w.check_and_record(now).map_err(FlowError::from)?;
        put_json(&self.rates, tx, key, &w)
    }

    fn append_audit(&self, tx: &mut impl WriteTx, events: &[AuditEvent]) -> Result<u64> {
        let key = META_AUDIT_SEQ.to_string();
        let mut seq = self.meta.get(tx, &key)?.unwrap_or(0);
        for e in events {
            seq += 1;
            put_json_u64(
                &self.audit,
                tx,
                seq,
                &AuditRow {
                    seq,
                    event: e.clone(),
                },
            )?;
        }
        self.meta.put(tx, &key, &seq)?;
        Ok(seq)
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn event(at: u64, tenant: &TenantId, kind: AuditKind) -> AuditEvent {
    AuditEvent {
        at,
        tenant: tenant.clone(),
        kind,
        user: None,
        challenge: None,
        email_idx: None,
    }
}

fn user_event(at: u64, user: &User, kind: AuditKind) -> AuditEvent {
    AuditEvent {
        at,
        tenant: user.tenant.clone(),
        kind,
        user: Some(user.id.clone()),
        challenge: None,
        email_idx: Some(user.email_idx),
    }
}

fn delivery_event(at: u64, item: &OutboxItem, kind: AuditKind) -> AuditEvent {
    AuditEvent {
        at,
        tenant: item.tenant.clone(),
        kind,
        user: item.user.clone(),
        challenge: None,
        email_idx: None,
    }
}

fn session_key(hash: &str) -> String {
    format!("session/{hash}")
}

fn refresh_key(hash: &str) -> String {
    format!("session-refresh/{hash}")
}

/// Who an event is about: the user (if a record exists yet) and the address.
#[derive(Clone, Copy)]
struct EventSubject<'a> {
    user: Option<&'a UserId>,
    email: &'a str,
}

/// An endpoint URL and event list a tenant may register.
fn check_webhook(url: &str, events: &[String]) -> Result<()> {
    let allowed_scheme = url.starts_with("https://") || url.starts_with("http://");
    if !allowed_scheme || url.len() > 2_048 || url.chars().any(char::is_whitespace) {
        return Err(StoreError::InvalidConfig(
            "webhook url must be an http(s) URL".into(),
        ));
    }
    if events.is_empty() || events.iter().any(|e| !WEBHOOK_EVENTS.contains(&e.as_str())) {
        return Err(StoreError::InvalidConfig(format!(
            "events must be a non-empty subset of {WEBHOOK_EVENTS:?}"
        )));
    }
    Ok(())
}

fn outbox_key(id: &str) -> String {
    format!("outbox/{id}")
}

/// base64url SHA-256 of a bearer secret — what the store keeps instead of it.
fn token_hash(token: &str) -> String {
    use sha2::Digest as _;
    enc::encode(&Sha256::digest(token.as_bytes()))
}

fn rate_key(scope: &str, tenant: &TenantId, idx: &str) -> String {
    format!("rate/{scope}/{tenant}/{idx}")
}

/// `base64url(HMAC-SHA256(pepper, domain ‖ tenant ‖ NUL ‖ value))` — a
/// lookup key that never puts the value itself in a store key.
fn scoped_index(pepper: &Pepper, domain: &[u8], tenant: &TenantId, value: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key length");
    mac.update(domain);
    mac.update(tenant.as_str().as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    enc::encode(&mac.finalize().into_bytes())
}

fn corrupt(key: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt {
        key: key.to_string(),
        msg: e.to_string(),
    }
}

fn decode<T: DeserializeOwned>(key: &str, json: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|e| corrupt(key, e))
}

fn get_json<T: DeserializeOwned>(
    c: &Collection<String, String>,
    tx: &impl Readable,
    key: &str,
) -> Result<Option<T>> {
    match c.get(tx, &key.to_string())? {
        None => Ok(None),
        Some(json) => decode(key, &json).map(Some),
    }
}

fn put_json<T: Serialize>(
    c: &Collection<String, String>,
    tx: &mut impl WriteTx,
    key: &str,
    value: &T,
) -> Result<()> {
    let json = serde_json::to_string(value).map_err(|e| corrupt(key, e))?;
    c.put(tx, &key.to_string(), &json)?;
    Ok(())
}

fn put_json_u64<T: Serialize>(
    c: &Collection<u64, String>,
    tx: &mut impl WriteTx,
    key: u64,
    value: &T,
) -> Result<()> {
    let json = serde_json::to_string(value).map_err(|e| corrupt(&key.to_string(), e))?;
    c.put(tx, &key, &json)?;
    Ok(())
}

fn scan_json<T: DeserializeOwned>(
    c: &Collection<String, String>,
    tx: &impl Readable,
    prefix: &str,
) -> Result<Vec<(String, T)>> {
    c.range(tx, &prefix.to_string(), &format!("{prefix}{KEY_MAX}"))?
        .into_iter()
        .map(|(k, json)| {
            let v = decode(&k, &json)?;
            Ok((k, v))
        })
        .collect()
}

fn values<T>(rows: Vec<(String, T)>) -> Vec<T> {
    rows.into_iter().map(|(_, v)| v).collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn load_or_create_kek(path: &Path) -> Result<[u8; KEY_LEN]> {
    match std::fs::read(path) {
        Ok(bytes) => bytes.try_into().map_err(|b: Vec<u8>| {
            StoreError::KeyFile(format!(
                "{} is {} bytes, expected {KEY_LEN}",
                path.display(),
                b.len()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; KEY_LEN];
            OsEntropy
                .fill(&mut key)
                .map_err(|e| StoreError::KeyFile(e.to_string()))?;
            write_secret(path, &key)?;
            Ok(key)
        }
        Err(e) => Err(StoreError::KeyFile(format!("{}: {e}", path.display()))),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| StoreError::KeyFile(format!("{}: {e}", path.display())))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| StoreError::KeyFile(format!("{}: {e}", path.display())))
}
