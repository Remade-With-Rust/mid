use std::sync::Arc;

use async_trait::async_trait;
use kms_types::{DidDocumentV2, RosterEntry, VerifyError};
use kms_verifier::DidResolver;

/// The device id a key-derived DID's one roster entry carries: a backend
/// signing as a bare key signs its assertions with this device id.
pub const KEY_DID_DEVICE_ID: &str = "root";

/// Resolves a **key-derived** `did:mata` (base58 of a compressed P-256 key)
/// to a one-entry roster holding that key — no network, no registry. A
/// tenant's backend can hold one key and be a DID.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyDidResolver;

#[async_trait]
impl DidResolver for KeyDidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocumentV2, VerifyError> {
        let pubkey =
            kms_verifier::pubkey_sec1_from_did(did).map_err(|_| VerifyError::DidNotFound)?;
        Ok(DidDocumentV2 {
            did: did.to_string(),
            roster_version: 1,
            roster: vec![RosterEntry {
                device_id: KEY_DID_DEVICE_ID.to_string(),
                pubkey,
                added_at: 0,
                label: "key-derived".to_string(),
            }],
            updated_at: 0,
        })
    }
}

/// Ask `primary` (e.g. a registry); only when it has **no document** fall
/// back to `fallback`. A DID the registry knows is always judged by its
/// registered roster — so a revoked genesis key cannot sneak back in
/// through the key-derived path.
pub struct ChainResolver {
    primary: Arc<dyn DidResolver>,
    fallback: Arc<dyn DidResolver>,
}

impl ChainResolver {
    /// `primary` first, `fallback` on `DidNotFound` only.
    pub fn new(primary: Arc<dyn DidResolver>, fallback: Arc<dyn DidResolver>) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl DidResolver for ChainResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocumentV2, VerifyError> {
        match self.primary.resolve(did).await {
            Err(VerifyError::DidNotFound) => self.fallback.resolve(did).await,
            other => other,
        }
    }
}
