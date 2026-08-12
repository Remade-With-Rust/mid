//! Embedded persistent [`NonceStore`] + [`AnchorStore`] over redb — the
//! pure-Rust storage engine spacedb-store uses. One file, two tables, no
//! schema for the adopter to manage: this is the "bolt into your database"
//! default for RPs that don't want to wire the traits into their own DB.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::anchor::AnchorStore;
use crate::error::RpError;
use crate::nonce::{fresh_nonce, NonceStore, DEFAULT_MAX_LIVE_NONCES, DEFAULT_NONCE_TTL_SECS};

/// nonce (hex) → issued_at (Unix seconds)
const NONCES: TableDefinition<&str, u64> = TableDefinition::new("mid_rp_nonces");
/// did → 40 bytes: genesis_roster_hash (32) ‖ last_seen_version (u64 BE)
const ANCHORS: TableDefinition<&str, &[u8]> = TableDefinition::new("mid_rp_anchors");

/// A single-file persistent store implementing both [`NonceStore`] and
/// [`AnchorStore`]. Live nonces survive a restart (an issued nonce can be
/// consumed by the post-restart process) and — more importantly — anchors
/// survive, so genesis-spoofing and rollback detection keep their memory
/// across deploys.
///
/// ```ignore
/// let store = Arc::new(RedbStore::open("mata-auth.redb")?);
/// let auth = Authenticator::new(store.clone(), store);
/// ```
pub struct RedbStore {
    db: Database,
    ttl_secs: u64,
    max_live: usize,
}

impl RedbStore {
    /// Open (or create) the store at `path` with default nonce limits.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RpError> {
        Self::open_with_limits(path, DEFAULT_NONCE_TTL_SECS, DEFAULT_MAX_LIVE_NONCES)
    }

    /// Open (or create) the store with explicit nonce TTL and live ceiling.
    pub fn open_with_limits(
        path: impl AsRef<Path>,
        ttl_secs: u64,
        max_live: usize,
    ) -> Result<Self, RpError> {
        let db = Database::create(path).map_err(store_err)?;
        // Materialize both tables so later read transactions never hit
        // TableDoesNotExist on a fresh file.
        let txn = db.begin_write().map_err(store_err)?;
        {
            txn.open_table(NONCES).map_err(store_err)?;
            txn.open_table(ANCHORS).map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(Self {
            db,
            ttl_secs,
            max_live,
        })
    }
}

impl NonceStore for RedbStore {
    fn issue(&self, now_unix_secs: u64) -> Result<String, RpError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(NONCES).map_err(store_err)?;
            if table.len().map_err(store_err)? as usize >= self.max_live {
                // Sweep expired entries before declaring capacity.
                let expired: Vec<String> = table
                    .iter()
                    .map_err(store_err)?
                    .filter_map(|entry| entry.ok())
                    .filter(|(_, issued_at)| {
                        now_unix_secs >= issued_at.value().saturating_add(self.ttl_secs)
                    })
                    .map(|(nonce, _)| nonce.value().to_owned())
                    .collect();
                for nonce in &expired {
                    table.remove(nonce.as_str()).map_err(store_err)?;
                }
                if table.len().map_err(store_err)? as usize >= self.max_live {
                    return Err(RpError::NonceCapacity {
                        max_live: self.max_live,
                    });
                }
            }
            let nonce = fresh_nonce()?;
            table
                .insert(nonce.as_str(), now_unix_secs)
                .map_err(store_err)?;
            drop(table);
            txn.commit().map_err(store_err)?;
            return Ok(nonce);
        }
    }

    fn consume(&self, nonce: &str, now_unix_secs: u64) -> Result<bool, RpError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        let consumed = {
            let mut table = txn.open_table(NONCES).map_err(store_err)?;
            let issued_at = table
                .remove(nonce)
                .map_err(store_err)?
                .map(|guard| guard.value());
            match issued_at {
                Some(issued_at) => now_unix_secs < issued_at.saturating_add(self.ttl_secs),
                None => false,
            }
        };
        txn.commit().map_err(store_err)?;
        Ok(consumed)
    }
}

impl AnchorStore for RedbStore {
    fn check_and_update(
        &self,
        did: &str,
        genesis_roster_hash: &[u8; 32],
        current_version: u64,
    ) -> Result<(), RpError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ANCHORS).map_err(store_err)?;
            let existing = table
                .get(did)
                .map_err(store_err)?
                .map(|guard| decode_anchor(guard.value()))
                .transpose()?;
            match existing {
                Some((anchored_hash, last_seen_version)) => {
                    if &anchored_hash != genesis_roster_hash {
                        return Err(RpError::GenesisMismatch {
                            did: did.to_owned(),
                        });
                    }
                    if current_version < last_seen_version {
                        return Err(RpError::Rollback {
                            did: did.to_owned(),
                            presented: current_version,
                            last_seen: last_seen_version,
                        });
                    }
                }
                None => {}
            }
            let encoded = encode_anchor(genesis_roster_hash, current_version);
            table
                .insert(did, encoded.as_slice())
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }
}

fn encode_anchor(genesis_roster_hash: &[u8; 32], version: u64) -> [u8; 40] {
    let mut out = [0u8; 40];
    out[..32].copy_from_slice(genesis_roster_hash);
    out[32..].copy_from_slice(&version.to_be_bytes());
    out
}

fn decode_anchor(bytes: &[u8]) -> Result<([u8; 32], u64), RpError> {
    if bytes.len() != 40 {
        return Err(RpError::Store(format!(
            "corrupt anchor record: {} bytes, expected 40",
            bytes.len()
        )));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[..32]);
    let mut version_bytes = [0u8; 8];
    version_bytes.copy_from_slice(&bytes[32..]);
    Ok((hash, u64::from_be_bytes(version_bytes)))
}

fn store_err(e: impl std::fmt::Display) -> RpError {
    RpError::Store(e.to_string())
}
