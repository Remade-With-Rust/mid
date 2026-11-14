//! Embedded persistent [`NonceStore`] + [`AnchorStore`] over redb — the
//! pure-Rust storage engine spacedb-store uses. One file, two tables, no
//! schema for the adopter to manage: this is the "bolt into your database"
//! default for RPs that don't want to wire the traits into their own DB.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::anchor::{check_against_anchor, AnchorStore, PresentedRoster};
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
    fn check_and_update(&self, did: &str, presented: &PresentedRoster) -> Result<(), RpError> {
        let txn = self.db.begin_write().map_err(store_err)?;
        {
            let mut table = txn.open_table(ANCHORS).map_err(store_err)?;
            let existing = table
                .get(did)
                .map_err(store_err)?
                .map(|guard| decode_anchor(guard.value()))
                .transpose()?;
            if let Some((anchored_hash, last_seen_version, last_seen_head)) = existing {
                check_against_anchor(did, &anchored_hash, last_seen_version, last_seen_head, presented)?;
            }
            let encoded = encode_anchor(
                &presented.genesis_roster_hash,
                presented.current_version,
                &presented.head_hash(),
            );
            table
                .insert(did, encoded.as_slice())
                .map_err(store_err)?;
        }
        txn.commit().map_err(store_err)?;
        Ok(())
    }
}

/// genesis hash (32) ‖ version (8, big-endian) ‖ head roster hash (32).
fn encode_anchor(genesis_roster_hash: &[u8; 32], version: u64, head: &[u8; 32]) -> [u8; 72] {
    let mut out = [0u8; 72];
    out[..32].copy_from_slice(genesis_roster_hash);
    out[32..40].copy_from_slice(&version.to_be_bytes());
    out[40..].copy_from_slice(head);
    out
}

/// Reads the 72-byte record, and the 40-byte one written before heads were
/// kept (its head is `None` until the next sign-in rewrites it).
fn decode_anchor(bytes: &[u8]) -> Result<([u8; 32], u64, Option<[u8; 32]>), RpError> {
    if bytes.len() != 40 && bytes.len() != 72 {
        return Err(RpError::Store(format!(
            "corrupt anchor record: {} bytes, expected 72 (or 40 from before heads)",
            bytes.len()
        )));
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[..32]);
    let mut version_bytes = [0u8; 8];
    version_bytes.copy_from_slice(&bytes[32..40]);
    let head = (bytes.len() == 72).then(|| {
        let mut head = [0u8; 32];
        head.copy_from_slice(&bytes[40..]);
        head
    });
    Ok((hash, u64::from_be_bytes(version_bytes), head))
}

fn store_err(e: impl std::fmt::Display) -> RpError {
    RpError::Store(e.to_string())
}

#[cfg(test)]
mod anchor_record_tests {
    use super::*;

    #[test]
    fn a_record_from_before_heads_still_reads() {
        let mut old = [0u8; 40];
        old[..32].copy_from_slice(&[3u8; 32]);
        old[32..].copy_from_slice(&9u64.to_be_bytes());
        assert_eq!(decode_anchor(&old).unwrap(), ([3u8; 32], 9, None));
        let new = encode_anchor(&[3u8; 32], 9, &[4u8; 32]);
        assert_eq!(decode_anchor(&new).unwrap(), ([3u8; 32], 9, Some([4u8; 32])));
        assert!(decode_anchor(&[0u8; 41]).is_err());
    }
}
