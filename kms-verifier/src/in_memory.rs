//! In-memory implementations of [`NonceStore`] and [`DidResolver`].
//!
//! Primary use: unit/integration tests. Also usable as a production cut for
//! a single-instance deploy of `kms-banking-proxy` if persistence isn't a
//! requirement yet — both impls are `Send + Sync` and behave correctly under
//! concurrent access.

use async_trait::async_trait;
use kms_types::{DidDocumentV2, NonceEnvelope, VerifyError};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::{DidResolver, NonceStore};

/// In-memory [`NonceStore`].
///
/// Internally a `Mutex<HashMap>`. The mutex is held only for the duration of
/// the single-shot `put` / `consume` operations; there are no async awaits
/// while holding the lock.
#[derive(Default)]
pub struct InMemoryNonceStore {
    inner: Mutex<HashMap<[u8; 32], NonceEnvelope>>,
}

impl InMemoryNonceStore {
    /// Construct an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count of currently-held (unconsumed, unexpired) nonces. Useful for
    /// tests that assert "this verify consumed exactly one nonce."
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Drop every nonce that expired before `now_secs` (issued, never used).
    /// A long-running service calls this on a timer; without it, abandoned
    /// nonces accumulate forever. Returns how many were dropped.
    pub async fn prune_expired(&self, now_secs: u64) -> usize {
        let mut guard = self.inner.lock().await;
        let before = guard.len();
        guard.retain(|_, e| e.expires_at >= now_secs);
        before - guard.len()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl NonceStore for InMemoryNonceStore {
    async fn put(&self, envelope: &NonceEnvelope) -> Result<(), VerifyError> {
        let key: [u8; 32] = envelope
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::MalformedNonce)?;
        let mut guard = self.inner.lock().await;
        if guard.contains_key(&key) {
            // 32 random bytes colliding is vanishingly unlikely outside of
            // bugged RNGs. Surface as a storage error rather than silently
            // overwriting.
            return Err(VerifyError::StorageError(
                "nonce collision".to_string(),
            ));
        }
        guard.insert(key, envelope.clone());
        Ok(())
    }

    async fn consume(
        &self,
        nonce_bytes: &[u8; 32],
        now_secs: u64,
    ) -> Result<NonceEnvelope, VerifyError> {
        let mut guard = self.inner.lock().await;
        // Atomic: take it out of the map. If we then discover expiry, we
        // don't put it back — the nonce was single-use either way.
        let envelope = guard
            .remove(nonce_bytes)
            .ok_or(VerifyError::NonceNotFound)?;
        if envelope.expires_at < now_secs {
            return Err(VerifyError::NonceExpired);
        }
        Ok(envelope)
    }
}

/// In-memory [`DidResolver`].
///
/// Backed by a `Mutex<HashMap>` so tests can mutate the roster mid-flight
/// (simulate a revocation, simulate a roster update).
#[derive(Default)]
pub struct InMemoryDidResolver {
    inner: Mutex<HashMap<String, DidDocumentV2>>,
}

impl InMemoryDidResolver {
    /// Construct an empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish (or replace) the DID document for a given DID. Tests use this
    /// to set up rosters before exercising the verifier.
    pub async fn upsert(&self, doc: DidDocumentV2) {
        let mut guard = self.inner.lock().await;
        guard.insert(doc.did.clone(), doc);
    }

    /// Remove a DID — simulates a DID that was never published.
    pub async fn remove(&self, did: &str) {
        let mut guard = self.inner.lock().await;
        guard.remove(did);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl DidResolver for InMemoryDidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocumentV2, VerifyError> {
        let guard = self.inner.lock().await;
        guard
            .get(did)
            .cloned()
            .ok_or(VerifyError::DidNotFound)
    }
}
