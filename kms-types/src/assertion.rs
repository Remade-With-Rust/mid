//! [`SignedAssertion`] — the client's signed envelope wrapping a
//! [`NonceEnvelope`](crate::NonceEnvelope).

use crate::{b64, NonceEnvelope, VerifyError};
use serde::{Deserialize, Serialize};

/// A client-signed assertion. Carries the verbatim [`NonceEnvelope`] plus the
/// device id of the signer and an Ed25519 signature over the nonce envelope's
/// canonical bytes.
///
/// Wire format per [envelope_spec.md §"SignedAssertion"](../../../docs/kms/envelope_spec.md):
///
/// ```json
/// {
///   "envelope_version": 1,
///   "envelope_type": "signed_assertion",
///   "nonce_envelope": { ... },
///   "device_id": "<base58, 16-32 bytes>",
///   "signature": "<base64-url no-pad, 64 bytes Ed25519>"
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAssertion {
    /// Envelope version. Always [`SignedAssertion::CURRENT_VERSION`] in v1.
    pub envelope_version: u8,
    /// Discriminant. Always `"signed_assertion"`.
    pub envelope_type: String,
    /// The nonce envelope verbatim. The verifier re-canonicalizes from this
    /// embedded copy — the wire format can't smuggle alternate canonical forms.
    pub nonce_envelope: NonceEnvelope,
    /// Identifies which roster entry signed. Looked up by `device_id` in the
    /// resolved roster.
    pub device_id: String,
    /// 64-byte Ed25519 signature over `nonce_envelope.canonical_bytes()`.
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl SignedAssertion {
    /// Discriminant value for `envelope_type`.
    pub const TYPE: &'static str = "signed_assertion";

    /// Current envelope version.
    pub const CURRENT_VERSION: u8 = 1;

    /// Expected signature length (Ed25519 = 64 bytes).
    pub const SIGNATURE_LEN: usize = 64;

    /// Shape-only validation. Delegates the embedded `NonceEnvelope` check to
    /// [`NonceEnvelope::validate`]. Signature verification stays in the
    /// verifier (needs the resolved roster pubkey).
    pub fn validate(&self) -> Result<(), VerifyError> {
        if self.envelope_version != Self::CURRENT_VERSION {
            return Err(VerifyError::UnknownEnvelopeVersion);
        }
        if self.envelope_type != Self::TYPE {
            return Err(VerifyError::WrongEnvelopeType);
        }
        if self.signature.len() != Self::SIGNATURE_LEN {
            return Err(VerifyError::MalformedEnvelope);
        }
        if self.device_id.is_empty() {
            return Err(VerifyError::MalformedEnvelope);
        }
        self.nonce_envelope.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_nonce() -> NonceEnvelope {
        NonceEnvelope {
            envelope_version: 1,
            envelope_type: NonceEnvelope::TYPE.into(),
            nonce: vec![0xAB; 32],
            did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZ".into(),
            audience: "kms-banking".into(),
            purpose: "get_accounts".into(),
            issued_at: 1_716_583_200,
            expires_at: 1_716_583_230,
            issuer: "kms-banking-proxy".into(),
        }
    }

    fn sample() -> SignedAssertion {
        SignedAssertion {
            envelope_version: 1,
            envelope_type: SignedAssertion::TYPE.into(),
            nonce_envelope: sample_nonce(),
            device_id: "device-abc-123".into(),
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn roundtrip_json() {
        let assertion = sample();
        let json = serde_json::to_string(&assertion).unwrap();
        let decoded: SignedAssertion = serde_json::from_str(&json).unwrap();
        assert_eq!(assertion, decoded);
    }

    #[test]
    fn validates_well_formed() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn rejects_wrong_type() {
        let mut a = sample();
        a.envelope_type = "nonce".into();
        assert_eq!(a.validate(), Err(VerifyError::WrongEnvelopeType));
    }

    #[test]
    fn rejects_wrong_signature_length() {
        let mut a = sample();
        a.signature = vec![0u8; 32];
        assert_eq!(a.validate(), Err(VerifyError::MalformedEnvelope));
    }

    #[test]
    fn rejects_empty_device_id() {
        let mut a = sample();
        a.device_id = String::new();
        assert_eq!(a.validate(), Err(VerifyError::MalformedEnvelope));
    }

    #[test]
    fn delegates_nonce_validation() {
        let mut a = sample();
        a.nonce_envelope.envelope_version = 2;
        assert_eq!(a.validate(), Err(VerifyError::UnknownEnvelopeVersion));
    }

    #[test]
    fn json_uses_base64url_no_pad_for_signature() {
        let a = sample();
        let json = serde_json::to_value(&a).unwrap();
        let sig_str = json["signature"].as_str().unwrap();
        // 64 bytes → 86 base64url chars (no padding).
        assert_eq!(sig_str.len(), 86);
        assert!(!sig_str.contains('='));
    }
}
