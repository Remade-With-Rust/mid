use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::RpError;

/// A per-DID anchor store enforcing two cross-sign-in invariants the
/// (stateless) verifier cannot:
///
/// 1. **Genesis immutability** — a known DID must always present the same
///    genesis-roster hash; a different one signals identity spoofing.
/// 2. **Version monotonicity** — the head-roster version must never
///    decrease; a lower version signals a stolen-device rollback to a
///    pre-revocation roster.
///
/// The relying party persists `(did → genesis_hash, last_seen_version)` and
/// checks here on every sign-in. First sight of a DID records its anchor —
/// the same trust-on-first-use model as SSH host keys.
pub trait AnchorStore: Send + Sync {
    /// Check a freshly-verified identity against its anchor and record the
    /// new high-water version. On first sight, records the anchor and
    /// returns `Ok`.
    fn check_and_update(
        &self,
        did: &str,
        genesis_roster_hash: &[u8; 32],
        current_version: u64,
    ) -> Result<(), RpError>;
}

struct Anchor {
    genesis_roster_hash: [u8; 32],
    last_seen_version: u64,
}

/// Process-local [`AnchorStore`]. Anchors vanish on restart — every DID
/// becomes first-sight again, which weakens (not breaks) rollback detection.
/// Production deployments should use `RedbStore` (feature `redb-store`) or
/// implement the trait over their own users table.
#[derive(Default)]
pub struct InMemoryAnchorStore {
    anchors: Mutex<HashMap<String, Anchor>>,
}

impl InMemoryAnchorStore {
    /// An empty in-memory anchor store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AnchorStore for InMemoryAnchorStore {
    fn check_and_update(
        &self,
        did: &str,
        genesis_roster_hash: &[u8; 32],
        current_version: u64,
    ) -> Result<(), RpError> {
        let mut anchors = self.anchors.lock().expect("anchor mutex poisoned");
        match anchors.get_mut(did) {
            Some(anchor) => {
                if &anchor.genesis_roster_hash != genesis_roster_hash {
                    return Err(RpError::GenesisMismatch {
                        did: did.to_owned(),
                    });
                }
                if current_version < anchor.last_seen_version {
                    return Err(RpError::Rollback {
                        did: did.to_owned(),
                        presented: current_version,
                        last_seen: anchor.last_seen_version,
                    });
                }
                anchor.last_seen_version = current_version;
                Ok(())
            }
            None => {
                anchors.insert(
                    did.to_owned(),
                    Anchor {
                        genesis_roster_hash: *genesis_roster_hash,
                        last_seen_version: current_version,
                    },
                );
                Ok(())
            }
        }
    }
}
