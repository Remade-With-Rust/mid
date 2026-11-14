use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::RpError;

/// A per-DID anchor store enforcing three cross-sign-in invariants the
/// (stateless) verifier cannot:
///
/// 1. **Genesis immutability** — a known DID must always present the same
///    genesis-roster hash; a different one signals identity spoofing.
/// 2. **Version monotonicity** — the head-roster version must never
///    decrease; a lower version signals a stolen-device rollback to a
///    pre-revocation roster.
/// 3. **Continuity** — the presented history must contain the exact roster
///    seen last, at its version. A device removed at v3 but listed at v2 can
///    sign its own v3′ from v2; versions alone do not tell v3′ from v3.
///
/// The relying party persists `(did → genesis_hash, last_seen_version,
/// last_seen_head)` and checks here on every sign-in. First sight of a DID
/// records its anchor — the same trust-on-first-use model as SSH host keys.
/// [`check_against_anchor`] is the check every implementation makes.
pub trait AnchorStore: Send + Sync {
    /// Check a freshly-verified identity against its anchor and record the
    /// new head. On first sight, records the anchor and returns `Ok`.
    fn check_and_update(&self, did: &str, presented: &PresentedRoster) -> Result<(), RpError>;
}

/// What a sign-in presents to the anchor store ([`crate::RpSession::presented_roster`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedRoster {
    /// Hash of the DID's genesis roster.
    pub genesis_roster_hash: [u8; 32],
    /// The head roster's version.
    pub current_version: u64,
    /// `(version, hash)` of every roster in the token's history, genesis first.
    pub roster_hashes: Vec<(u64, [u8; 32])>,
}

impl PresentedRoster {
    /// The hash of the head roster, which the store records.
    pub fn head_hash(&self) -> [u8; 32] {
        self.roster_hashes
            .last()
            .map(|(_, hash)| *hash)
            .unwrap_or(self.genesis_roster_hash)
    }
}

/// The checks every [`AnchorStore`] makes against what it recorded for `did`.
///
/// `last_seen_head` is `None` for a record written before heads were kept: such
/// a record is checked for genesis and version only, and gains its head when
/// the store writes the update.
pub fn check_against_anchor(
    did: &str,
    anchored_genesis: &[u8; 32],
    last_seen_version: u64,
    last_seen_head: Option<[u8; 32]>,
    presented: &PresentedRoster,
) -> Result<(), RpError> {
    if anchored_genesis != &presented.genesis_roster_hash {
        return Err(RpError::GenesisMismatch { did: did.to_owned() });
    }
    if presented.current_version < last_seen_version {
        return Err(RpError::Rollback {
            did: did.to_owned(),
            presented: presented.current_version,
            last_seen: last_seen_version,
        });
    }
    if let Some(head) = last_seen_head {
        let carried = presented
            .roster_hashes
            .iter()
            .find(|(version, _)| *version == last_seen_version)
            .map(|(_, hash)| *hash);
        if carried != Some(head) {
            return Err(RpError::Fork { did: did.to_owned(), version: last_seen_version });
        }
    }
    Ok(())
}

struct Anchor {
    genesis_roster_hash: [u8; 32],
    last_seen_version: u64,
    last_seen_head: Option<[u8; 32]>,
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
    fn check_and_update(&self, did: &str, presented: &PresentedRoster) -> Result<(), RpError> {
        let mut anchors = self.anchors.lock().expect("anchor mutex poisoned");
        if let Some(anchor) = anchors.get(did) {
            check_against_anchor(
                did,
                &anchor.genesis_roster_hash,
                anchor.last_seen_version,
                anchor.last_seen_head,
                presented,
            )?;
        }
        anchors.insert(
            did.to_owned(),
            Anchor {
                genesis_roster_hash: presented.genesis_roster_hash,
                last_seen_version: presented.current_version,
                last_seen_head: Some(presented.head_hash()),
            },
        );
        Ok(())
    }
}

