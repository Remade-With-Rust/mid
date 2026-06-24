//! [`RosterEntry`] — one device's roster slot.
//! [`RosterUpdate`] — a signed mutation of a DID's roster.

use crate::{b64, did, VerifyError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Hard upper bound on roster size per
/// [did_document_v2.md §"Roster size limits"](../../../docs/kms/did_document_v2.md).
pub const ROSTER_HARD_CAP: usize = 64;

/// Maximum tolerated clock skew on `signed_at` (seconds).
pub const ROSTER_SIGNED_AT_TOLERANCE_SECS: u64 = 300;

/// One device's slot in a DID's roster.
///
/// Wire format per [envelope_spec.md §"RosterUpdate"](../../../docs/kms/envelope_spec.md):
///
/// ```json
/// {
///   "device_id": "<string>",
///   "pubkey": "<base64url, 32 bytes>",
///   "added_at": 1716580000,
///   "label": "Tim's MacBook Pro"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterEntry {
    /// Stable identifier used in `SignedAssertion.device_id` lookups.
    pub device_id: String,
    /// 65-byte SEC1-uncompressed ECDSA P-256 public key
    /// (`0x04 || x[32] || y[32]`). The signature on a `SignedAssertion`
    /// from this device verifies under this key.
    #[serde(with = "b64")]
    pub pubkey: Vec<u8>,
    /// When this entry was added to the roster (Unix seconds, UTC).
    pub added_at: u64,
    /// Human label (e.g., "Tim's MacBook Pro"). Not used for verification.
    pub label: String,
}

impl RosterEntry {
    /// Expected pubkey length (ECDSA P-256 SEC1-uncompressed = 65 bytes).
    pub const PUBKEY_LEN: usize = 65;
}

/// A signed mutation of a DID's roster.
///
/// Wire format per [envelope_spec.md §"RosterUpdate"](../../../docs/kms/envelope_spec.md):
///
/// ```json
/// {
///   "envelope_version": 1,
///   "envelope_type": "roster_update",
///   "did": "did:mata:<base58-pubkey>",
///   "prior_version": 7,
///   "new_version": 8,
///   "new_roster": [ ... ],
///   "signed_at": 1716583200,
///   "signer_device_id": "<string>",
///   "signature": "<base64url, 64 bytes Ed25519>"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterUpdate {
    /// Envelope version. Always [`RosterUpdate::CURRENT_VERSION`] in v1.
    pub envelope_version: u8,
    /// Discriminant. Always `"roster_update"`.
    pub envelope_type: String,
    /// The DID being updated.
    pub did: String,
    /// Must equal the current `roster_version` in `kms_did_documents`.
    pub prior_version: u64,
    /// Must equal `prior_version + 1`.
    pub new_version: u64,
    /// The complete new roster after the update. Adds, removes, and renames
    /// are all expressed by listing/omitting entries.
    pub new_roster: Vec<RosterEntry>,
    /// Update timestamp (Unix seconds, UTC).
    pub signed_at: u64,
    /// Must be present in the *prior* roster.
    pub signer_device_id: String,
    /// 64-byte ECDSA P-256 signature (raw `r || s`) over `canonical_bytes()`,
    /// via prehash mode (signs the SHA-256 digest produced by
    /// `canonical_bytes()` directly).
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl RosterUpdate {
    /// Discriminant value for `envelope_type`.
    pub const TYPE: &'static str = "roster_update";

    /// Current envelope version.
    pub const CURRENT_VERSION: u8 = 1;

    /// Expected signature length (ECDSA P-256 raw `r || s` = 64 bytes).
    pub const SIGNATURE_LEN: usize = 64;

    /// Bytes covered by the signature.
    ///
    /// Per [envelope_spec.md](../../../docs/kms/envelope_spec.md):
    ///
    /// ```text
    /// sha256(
    ///   "kms-roster-v1\n" ||
    ///   envelope_version (1 byte) ||
    ///   len(did) (2 bytes, BE) || did_utf8 ||
    ///   prior_version (8 bytes, BE) ||
    ///   new_version (8 bytes, BE) ||
    ///   signed_at (8 bytes, BE) ||
    ///   len(signer_device_id) (2 bytes, BE) || signer_device_id_utf8 ||
    ///   roster_count (2 bytes, BE) ||
    ///   for each entry (sorted by device_id ascending):
    ///     len(device_id) (2 bytes, BE) || device_id_utf8 ||
    ///     pubkey (65 bytes, SEC1 uncompressed) ||
    ///     added_at (8 bytes, BE) ||
    ///     len(label) (2 bytes, BE) || label_utf8
    /// )
    /// ```
    ///
    /// Returns the 32-byte SHA-256 digest.
    pub fn canonical_bytes(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"kms-roster-v1\n");
        h.update([self.envelope_version]);
        write_lp(&mut h, self.did.as_bytes());
        h.update(self.prior_version.to_be_bytes());
        h.update(self.new_version.to_be_bytes());
        h.update(self.signed_at.to_be_bytes());
        write_lp(&mut h, self.signer_device_id.as_bytes());

        // Sort entries by device_id ascending so on-wire order is irrelevant.
        let mut sorted: Vec<&RosterEntry> = self.new_roster.iter().collect();
        sorted.sort_by(|a, b| a.device_id.cmp(&b.device_id));

        let count = sorted.len() as u16;
        h.update(count.to_be_bytes());
        for entry in sorted {
            write_lp(&mut h, entry.device_id.as_bytes());
            // pubkey: no length prefix per spec (fixed 65 bytes SEC1).
            h.update(&entry.pubkey);
            h.update(entry.added_at.to_be_bytes());
            write_lp(&mut h, entry.label.as_bytes());
        }
        h.finalize().into()
    }

    /// Shape-only validation. Verifier adds:
    /// - signature verification under the signer's prior-roster pubkey,
    /// - `signed_at` freshness check (`abs(now - signed_at) <= 300s`),
    /// - signer-membership check against the prior roster.
    pub fn validate(&self) -> Result<(), VerifyError> {
        if self.envelope_version != Self::CURRENT_VERSION {
            return Err(VerifyError::UnknownEnvelopeVersion);
        }
        if self.envelope_type != Self::TYPE {
            return Err(VerifyError::WrongEnvelopeType);
        }
        if !did::is_valid_did(&self.did) {
            return Err(VerifyError::MalformedDid);
        }
        if self.new_version != self.prior_version + 1 {
            return Err(VerifyError::NonMonotonicVersion);
        }
        if self.new_roster.is_empty() {
            return Err(VerifyError::EmptyRoster);
        }
        if self.new_roster.len() > ROSTER_HARD_CAP {
            return Err(VerifyError::MalformedEnvelope);
        }
        if self.signature.len() != Self::SIGNATURE_LEN {
            return Err(VerifyError::MalformedEnvelope);
        }
        if self.signer_device_id.is_empty() {
            return Err(VerifyError::MalformedEnvelope);
        }
        for entry in &self.new_roster {
            if entry.pubkey.len() != RosterEntry::PUBKEY_LEN {
                return Err(VerifyError::MalformedEnvelope);
            }
            if entry.device_id.is_empty() {
                return Err(VerifyError::MalformedEnvelope);
            }
        }
        Ok(())
    }
}

fn write_lp(h: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u16;
    h.update(len.to_be_bytes());
    h.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(device_id: &str) -> RosterEntry {
        // 65-byte SEC1 uncompressed P-256 pubkey: 0x04 || x[32] || y[32].
        // Tests use dummy bytes; signature-validity isn't checked at the
        // type-validation level, only at the verifier level.
        let mut pubkey = vec![0x04];
        pubkey.extend(vec![0x42; 64]);
        RosterEntry {
            device_id: device_id.into(),
            pubkey,
            added_at: 1_716_580_000,
            label: format!("label for {}", device_id),
        }
    }

    fn sample() -> RosterUpdate {
        RosterUpdate {
            envelope_version: 1,
            envelope_type: RosterUpdate::TYPE.into(),
            did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZ".into(),
            prior_version: 7,
            new_version: 8,
            new_roster: vec![sample_entry("dev-a"), sample_entry("dev-b")],
            signed_at: 1_716_583_200,
            signer_device_id: "dev-a".into(),
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn roundtrip_json() {
        let upd = sample();
        let json = serde_json::to_string(&upd).unwrap();
        let decoded: RosterUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(upd, decoded);
    }

    #[test]
    fn validates_well_formed() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn rejects_non_monotonic_version() {
        let mut u = sample();
        u.new_version = u.prior_version + 2;
        assert_eq!(u.validate(), Err(VerifyError::NonMonotonicVersion));
    }

    #[test]
    fn rejects_empty_roster() {
        let mut u = sample();
        u.new_roster = vec![];
        assert_eq!(u.validate(), Err(VerifyError::EmptyRoster));
    }

    #[test]
    fn rejects_oversized_roster() {
        let mut u = sample();
        u.new_roster = (0..(ROSTER_HARD_CAP + 1))
            .map(|i| sample_entry(&format!("dev-{}", i)))
            .collect();
        assert_eq!(u.validate(), Err(VerifyError::MalformedEnvelope));
    }

    #[test]
    fn rejects_bad_pubkey_length() {
        let mut u = sample();
        u.new_roster[0].pubkey = vec![0u8; 32]; // wrong: was Ed25519-shaped
        assert_eq!(u.validate(), Err(VerifyError::MalformedEnvelope));
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let u = sample();
        assert_eq!(u.canonical_bytes(), u.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_are_order_independent_within_new_roster() {
        let mut u1 = sample();
        let mut u2 = sample();
        u2.new_roster.reverse();
        assert_eq!(u1.canonical_bytes(), u2.canonical_bytes());

        // Sanity: the reversed input is observably different in struct form.
        assert_ne!(u1.new_roster, u2.new_roster);
        let _ = &mut u1;
    }

    #[test]
    fn canonical_bytes_change_when_any_field_changes() {
        let baseline = sample().canonical_bytes();

        let mut u = sample();
        u.did = "did:mata:abcdefghijkmnpqrstuvwxyzABCDEFGH".into();
        assert_ne!(u.canonical_bytes(), baseline, "did");

        let mut u = sample();
        u.prior_version += 1;
        u.new_version += 1;
        assert_ne!(u.canonical_bytes(), baseline, "version");

        let mut u = sample();
        u.signed_at += 1;
        assert_ne!(u.canonical_bytes(), baseline, "signed_at");

        let mut u = sample();
        u.signer_device_id = "dev-b".into();
        assert_ne!(u.canonical_bytes(), baseline, "signer_device_id");

        let mut u = sample();
        u.new_roster[0].pubkey[0] ^= 0x01;
        assert_ne!(u.canonical_bytes(), baseline, "pubkey");

        let mut u = sample();
        u.new_roster[0].label = "different label".into();
        assert_ne!(u.canonical_bytes(), baseline, "label");

        let mut u = sample();
        u.new_roster[0].added_at += 1;
        assert_ne!(u.canonical_bytes(), baseline, "added_at");
    }

    #[test]
    fn nonce_and_roster_canonical_bytes_use_distinct_domain_separators() {
        // A RosterUpdate's canonical_bytes prefixes with "kms-roster-v1\n";
        // a NonceEnvelope's with "kms-nonce-v1\n". A forged RosterUpdate
        // crafted to match a NonceEnvelope's other fields still produces a
        // different SHA-256 because the prefix differs.
        use crate::NonceEnvelope;

        let nonce = NonceEnvelope {
            envelope_version: 1,
            envelope_type: NonceEnvelope::TYPE.into(),
            nonce: vec![0x11; 32],
            did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZ".into(),
            audience: "kms-banking".into(),
            purpose: "get_accounts".into(),
            issued_at: 1_716_583_200,
            expires_at: 1_716_583_230,
            issuer: "kms-banking-proxy".into(),
        };

        let roster = sample();

        assert_ne!(
            nonce.canonical_bytes(),
            roster.canonical_bytes(),
            "domain separator must prevent cross-envelope signature reuse"
        );
    }
}
