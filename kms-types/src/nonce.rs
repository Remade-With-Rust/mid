//! [`NonceEnvelope`] — issued by the verifier, signed by the client.

use crate::{b64, did, VerifyError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A server-issued challenge bound to a DID, audience, and purpose.
///
/// Wire format per [envelope_spec.md §"NonceEnvelope"](../../../docs/kms/envelope_spec.md):
///
/// ```json
/// {
///   "envelope_version": 1,
///   "envelope_type": "nonce",
///   "nonce": "<base64-url no-pad, 32 bytes>",
///   "did": "did:mata:<base58-pubkey>",
///   "audience": "kms-banking",
///   "purpose": "get_accounts",
///   "issued_at": 1716583200,
///   "expires_at": 1716583230,
///   "issuer": "kms-banking-proxy"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceEnvelope {
    /// Envelope version. Always [`NonceEnvelope::CURRENT_VERSION`] in v1.
    pub envelope_version: u8,
    /// Discriminant. Always `"nonce"`.
    pub envelope_type: String,
    /// 32 cryptographically random bytes. Single-use.
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    /// The DID this nonce is bound to.
    pub did: String,
    /// Service that issued and will consume this nonce.
    pub audience: String,
    /// Specific operation this nonce authorizes.
    pub purpose: String,
    /// Issuance timestamp (Unix seconds, UTC).
    pub issued_at: u64,
    /// Expiry timestamp (Unix seconds, UTC).
    pub expires_at: u64,
    /// Identifier of the service instance that minted this nonce.
    pub issuer: String,
}

impl NonceEnvelope {
    /// Discriminant value for `envelope_type`.
    pub const TYPE: &'static str = "nonce";

    /// Current envelope version.
    pub const CURRENT_VERSION: u8 = 1;

    /// Hard upper bound on `expires_at - issued_at`. Per spec, 5 minutes.
    pub const MAX_TTL_SECS: u64 = 300;

    /// Bytes covered by the signature.
    ///
    /// Per [envelope_spec.md](../../../docs/kms/envelope_spec.md) the
    /// canonical form for `NonceEnvelope` is:
    ///
    /// ```text
    /// sha256(
    ///   "kms-nonce-v1\n" ||
    ///   envelope_version (1 byte) ||
    ///   len(nonce) (2 bytes, BE) || nonce ||
    ///   len(did) (2 bytes, BE) || did_utf8 ||
    ///   len(audience) (2 bytes, BE) || audience_utf8 ||
    ///   len(purpose) (2 bytes, BE) || purpose_utf8 ||
    ///   issued_at (8 bytes, BE) ||
    ///   expires_at (8 bytes, BE) ||
    ///   len(issuer) (2 bytes, BE) || issuer_utf8
    /// )
    /// ```
    ///
    /// Returns the 32-byte SHA-256 digest. Callers sign this digest with
    /// Ed25519.
    pub fn canonical_bytes(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"kms-nonce-v1\n");
        h.update([self.envelope_version]);
        write_lp(&mut h, &self.nonce);
        write_lp(&mut h, self.did.as_bytes());
        write_lp(&mut h, self.audience.as_bytes());
        write_lp(&mut h, self.purpose.as_bytes());
        h.update(self.issued_at.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        write_lp(&mut h, self.issuer.as_bytes());
        h.finalize().into()
    }

    /// Shape-only validation. Verifier adds nonce-state, signature, and
    /// audience-allow-list checks.
    pub fn validate(&self) -> Result<(), VerifyError> {
        if self.envelope_version != Self::CURRENT_VERSION {
            return Err(VerifyError::UnknownEnvelopeVersion);
        }
        if self.envelope_type != Self::TYPE {
            return Err(VerifyError::WrongEnvelopeType);
        }
        if self.nonce.len() != 32 {
            return Err(VerifyError::MalformedNonce);
        }
        if !did::is_valid_did(&self.did) {
            return Err(VerifyError::MalformedDid);
        }
        if self.expires_at <= self.issued_at {
            return Err(VerifyError::InvalidTimestamps);
        }
        if self.expires_at - self.issued_at > Self::MAX_TTL_SECS {
            return Err(VerifyError::InvalidTimestamps);
        }
        Ok(())
    }
}

/// Length-prefixed write: 2-byte big-endian length, then the bytes.
fn write_lp(h: &mut Sha256, bytes: &[u8]) {
    let len = bytes.len() as u16;
    h.update(len.to_be_bytes());
    h.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> NonceEnvelope {
        NonceEnvelope {
            envelope_version: 1,
            envelope_type: "nonce".into(),
            nonce: vec![0xAB; 32],
            did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZ".into(),
            audience: "kms-banking".into(),
            purpose: "get_accounts".into(),
            issued_at: 1_716_583_200,
            expires_at: 1_716_583_230,
            issuer: "kms-banking-proxy".into(),
        }
    }

    #[test]
    fn roundtrip_json() {
        let envelope = sample();
        let json = serde_json::to_string(&envelope).unwrap();
        let decoded: NonceEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, decoded);
    }

    #[test]
    fn validates_well_formed() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn rejects_unknown_version() {
        let mut e = sample();
        e.envelope_version = 2;
        assert_eq!(e.validate(), Err(VerifyError::UnknownEnvelopeVersion));
    }

    #[test]
    fn rejects_wrong_type() {
        let mut e = sample();
        e.envelope_type = "signed_assertion".into();
        assert_eq!(e.validate(), Err(VerifyError::WrongEnvelopeType));
    }

    #[test]
    fn rejects_wrong_nonce_length() {
        let mut e = sample();
        e.nonce = vec![0; 16];
        assert_eq!(e.validate(), Err(VerifyError::MalformedNonce));
    }

    #[test]
    fn rejects_bad_did() {
        let mut e = sample();
        e.did = "not-a-did".into();
        assert_eq!(e.validate(), Err(VerifyError::MalformedDid));
    }

    #[test]
    fn rejects_inverted_timestamps() {
        let mut e = sample();
        e.expires_at = e.issued_at - 1;
        assert_eq!(e.validate(), Err(VerifyError::InvalidTimestamps));
    }

    #[test]
    fn rejects_ttl_over_max() {
        let mut e = sample();
        e.expires_at = e.issued_at + NonceEnvelope::MAX_TTL_SECS + 1;
        assert_eq!(e.validate(), Err(VerifyError::InvalidTimestamps));
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let e = sample();
        assert_eq!(e.canonical_bytes(), e.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_change_when_any_field_changes() {
        let baseline = sample().canonical_bytes();

        let mut e = sample();
        e.nonce = vec![0xCD; 32];
        assert_ne!(e.canonical_bytes(), baseline, "nonce change");

        let mut e = sample();
        e.audience = "kms-oidc".into();
        assert_ne!(e.canonical_bytes(), baseline, "audience change");

        let mut e = sample();
        e.purpose = "get_transactions".into();
        assert_ne!(e.canonical_bytes(), baseline, "purpose change");

        let mut e = sample();
        e.issued_at += 1;
        assert_ne!(e.canonical_bytes(), baseline, "issued_at change");

        let mut e = sample();
        e.expires_at += 1;
        assert_ne!(e.canonical_bytes(), baseline, "expires_at change");

        let mut e = sample();
        e.issuer = "kms-oidc-adapter".into();
        assert_ne!(e.canonical_bytes(), baseline, "issuer change");

        let mut e = sample();
        e.did = "did:mata:abcdefghijkmnpqrstuvwxyzABCDEFGH".into();
        assert_ne!(e.canonical_bytes(), baseline, "did change");
    }

    #[test]
    fn canonical_bytes_include_envelope_version() {
        let baseline = sample().canonical_bytes();
        let mut e = sample();
        e.envelope_version = 2;
        assert_ne!(e.canonical_bytes(), baseline);
    }

    #[test]
    fn json_uses_base64url_no_pad_for_nonce() {
        let e = sample();
        let json = serde_json::to_value(&e).unwrap();
        let nonce_str = json["nonce"].as_str().unwrap();
        // 32 bytes → 43 base64url chars (no padding).
        assert_eq!(nonce_str.len(), 43);
        assert!(!nonce_str.contains('='));
        assert!(!nonce_str.contains('+'));
        assert!(!nonce_str.contains('/'));
    }
}
