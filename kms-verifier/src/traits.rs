//! Trait objects the [`Verifier`](crate::Verifier) consumes.
//!
//! Production implementations:
//! - [`NonceStore`] — backed by Postgres in `kms-banking-proxy` (Phase 5).
//!   Redis is also viable.
//! - [`DidResolver`] — backed by an HTTP call to the public
//!   `kms_did_documents` table in `kms-resolver` (Phase 4).
//! - [`Clock`] — production uses [`SystemClock`]; tests inject a fake.
//! - [`NonceGenerator`] — production uses [`SystemNonceGenerator`] backed by
//!   OS randomness; tests inject deterministic bytes.

use async_trait::async_trait;
use kms_types::{DidDocumentV2, NonceEnvelope, VerifyError};

// The traits below use `async_trait`. On native, futures must be `Send` so
// axum/tokio can spawn them across worker threads. On wasm32, browser
// objects (reqwest's `Response`) are `!Send` by construction, so any
// resolver/store that touches HTTP would produce `!Send` futures. The
// cfg-conditional below uses the default `Send`-bound macro on native and
// the `?Send` variant on wasm32 — matching what the runtime can actually
// support per-target.
//
// Trait objects (`Arc<dyn DidResolver>`) inherit the same bound, so
// `Verifier` is `Send + Sync` on native and not necessarily either on wasm32.

/// Persistence layer for issued nonces.
///
/// Contract: `consume` is atomic. A successful `consume` returns the stored
/// envelope **and** marks the nonce as consumed in the same operation. A
/// `GET` + `DELETE` race that allows a single nonce to be used twice is a
/// correctness bug — implementations must use
/// `DELETE ... WHERE nonce = $1 RETURNING ...` or equivalent.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait NonceStore: MaybeSendSync {
    /// Persist a freshly-issued nonce.
    ///
    /// Returns [`VerifyError::StorageError`] on backend failure. The 32-byte
    /// random nonce should never collide in practice; if it does (e.g., RNG
    /// degenerate), implementations may return [`VerifyError::StorageError`]
    /// — the verifier will surface it as an opaque 500 to the client.
    async fn put(&self, envelope: &NonceEnvelope) -> Result<(), VerifyError>;

    /// Atomically check + delete.
    ///
    /// On success: returns the stored envelope. The verifier compares it
    /// byte-equivalently to the embedded envelope in the signed assertion to
    /// detect tampering.
    ///
    /// Failure modes:
    /// - [`VerifyError::NonceNotFound`] — no record with this random nonce
    /// - [`VerifyError::NonceAlreadyConsumed`] — record exists, was consumed
    /// - [`VerifyError::NonceExpired`] — record exists, `expires_at < now`
    /// - [`VerifyError::StorageError`] — backend failure
    async fn consume(
        &self,
        nonce_bytes: &[u8; 32],
        now_secs: u64,
    ) -> Result<NonceEnvelope, VerifyError>;
}

/// Resolves a `did:mata:...` to its current [`DidDocumentV2`].
///
/// Production impl in `kms-resolver` (Phase 4) hits the public
/// `kms_did_documents` table over HTTP and may cache with a short TTL
/// (per [did_document_v2.md §"Caching"](../../../docs/kms/did_document_v2.md)).
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait DidResolver: MaybeSendSync {
    /// Returns the current DID document or a typed error.
    ///
    /// Failure modes:
    /// - [`VerifyError::DidNotFound`] — no row for this DID
    /// - [`VerifyError::StorageError`] — backend failure
    async fn resolve(&self, did: &str) -> Result<DidDocumentV2, VerifyError>;
}

/// Wall clock — abstracted for deterministic tests.
pub trait Clock: Send + Sync {
    /// Unix timestamp in seconds, UTC.
    fn now_secs(&self) -> u64;
}

/// 32-byte random nonce generator — abstracted for deterministic tests.
pub trait NonceGenerator: Send + Sync {
    /// Return 32 cryptographically random bytes.
    fn random_32(&self) -> [u8; 32];
}

// ── MaybeSendSync helper ────────────────────────────────────────────────────
//
// Trait alias that resolves to `Send + Sync` on native and to the empty
// bound on wasm32. Used as the supertrait for `NonceStore` and `DidResolver`
// so the `Arc<dyn Trait>` field on `Verifier` requires Send+Sync on native
// (so axum can spawn) and doesn't require it on wasm32 (where browser
// objects in the impl bodies are `!Send`).

/// Supertrait alias: `Send + Sync` on native, empty on wasm32. See
/// trait module docs for the rationale.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync> MaybeSendSync for T {}

/// Supertrait alias: empty on wasm32, `Send + Sync` on native. See trait
/// module docs for the rationale.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}

#[cfg(target_arch = "wasm32")]
impl<T> MaybeSendSync for T {}

// ── Production impls ────────────────────────────────────────────────────────

/// Real-clock implementation of [`Clock`].
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            // SystemTime before epoch shouldn't happen on any sane host. If
            // it does, return 0 — every nonce will expire instantly. Better
            // than panicking.
            .unwrap_or(0)
    }
}

/// OS-random implementation of [`NonceGenerator`].
pub struct SystemNonceGenerator;

impl NonceGenerator for SystemNonceGenerator {
    fn random_32(&self) -> [u8; 32] {
        use rand_core::{OsRng, RngCore};
        let mut out = [0u8; 32];
        // OsRng::fill_bytes is infallible in rand_core 0.6 — it panics if the
        // OS RNG fails, which is the right behavior (we cannot continue if
        // we can't get random bytes for a nonce).
        OsRng.fill_bytes(&mut out);
        out
    }
}
