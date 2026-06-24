//! [`DidDocumentV2`] — the resolver's view of a DID's current roster.

use crate::RosterEntry;
use serde::{Deserialize, Serialize};

/// A DID's currently-published roster, as returned by `kms-resolver`.
///
/// This is the resolver's projection of one row in the
/// [`kms_did_documents`](../../../docs/kms/did_document_v2.md) table.
///
/// Wire format mirrors the table columns:
///
/// ```json
/// {
///   "did": "did:mata:<base58-pubkey>",
///   "roster_version": 8,
///   "roster": [ ... ],
///   "updated_at": 1716583200
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocumentV2 {
    /// The DID this document describes.
    pub did: String,
    /// Monotonically increasing version. Incremented by each accepted
    /// [`RosterUpdate`](crate::RosterUpdate).
    pub roster_version: u64,
    /// Current roster — the source of truth for "who can sign for this DID."
    pub roster: Vec<RosterEntry>,
    /// When the row was last updated (Unix seconds, UTC).
    pub updated_at: u64,
}

impl DidDocumentV2 {
    /// Find a roster entry by `device_id`. Used by the verifier to locate the
    /// pubkey of an asserting device.
    pub fn find_entry(&self, device_id: &str) -> Option<&RosterEntry> {
        self.roster.iter().find(|e| e.device_id == device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey(fill: u8) -> Vec<u8> {
        let mut k = vec![0x04];
        k.extend(vec![fill; 64]);
        k
    }

    fn sample() -> DidDocumentV2 {
        DidDocumentV2 {
            did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZ".into(),
            roster_version: 1,
            roster: vec![
                RosterEntry {
                    device_id: "dev-laptop".into(),
                    pubkey: sample_pubkey(0x11),
                    added_at: 1_716_580_000,
                    label: "Tim's MacBook Pro".into(),
                },
                RosterEntry {
                    device_id: "dev-phone".into(),
                    pubkey: sample_pubkey(0x22),
                    added_at: 1_716_581_000,
                    label: "Tim's iPhone".into(),
                },
            ],
            updated_at: 1_716_583_200,
        }
    }

    #[test]
    fn roundtrip_json() {
        let doc = sample();
        let json = serde_json::to_string(&doc).unwrap();
        let decoded: DidDocumentV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, decoded);
    }

    #[test]
    fn find_entry_returns_matching_device() {
        let doc = sample();
        assert_eq!(doc.find_entry("dev-laptop").unwrap().label, "Tim's MacBook Pro");
        assert_eq!(doc.find_entry("dev-phone").unwrap().label, "Tim's iPhone");
    }

    #[test]
    fn find_entry_returns_none_for_unknown_device() {
        let doc = sample();
        assert!(doc.find_entry("dev-unknown").is_none());
    }
}
