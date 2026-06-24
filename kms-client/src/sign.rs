//! The pure sign-an-envelope transformation.

use kms_types::{NonceEnvelope, RosterEntry, RosterUpdate, SignedAssertion, VerifyError};

use crate::DeviceSigner;

/// Produce a [`SignedAssertion`] from a [`NonceEnvelope`] using the given
/// signer's M5 key.
///
/// Validates the envelope's shape before signing — a malformed envelope from
/// a hostile server cannot trick the device into producing a signature over
/// garbage.
///
/// The returned assertion's signature is in canonical low-s form (enforced
/// by [`DeviceSigner::sign_prehash`]). The verifier will accept it.
pub fn sign_assertion(
    signer: &dyn DeviceSigner,
    envelope: NonceEnvelope,
) -> Result<SignedAssertion, VerifyError> {
    envelope.validate()?;
    let canonical = envelope.canonical_bytes();
    let signature = signer.sign_prehash(&canonical);
    Ok(SignedAssertion {
        envelope_version: SignedAssertion::CURRENT_VERSION,
        envelope_type: SignedAssertion::TYPE.to_string(),
        nonce_envelope: envelope,
        device_id: signer.device_id().to_string(),
        signature: signature.to_vec(),
    })
}

/// Build and sign a [`RosterUpdate`] using the given signer's M5 key.
///
/// `signer` must be a device currently in the DID's roster (the proxy's
/// `verify_roster_update` will reject otherwise). `prior_version` is the
/// `roster_version` the caller just resolved — on `StaleRosterVersion`
/// failure the caller should re-resolve and retry.
///
/// `signed_at` is in seconds since the Unix epoch. The proxy accepts
/// `|now - signed_at| <= 300s`; callers should stamp it just before
/// posting.
///
/// The returned update's signature is canonical low-s (the verifier
/// rejects high-s). Shape-validates the envelope pre-sign so a buggy
/// caller can't sign garbage.
pub fn sign_roster_update(
    signer: &dyn DeviceSigner,
    did: String,
    prior_version: u64,
    new_roster: Vec<RosterEntry>,
    signed_at: u64,
) -> Result<RosterUpdate, VerifyError> {
    // Stub a zero-signature first so `validate()` accepts the shape
    // (signature length is checked in validate). The real signature
    // overwrites it after canonical_bytes() is computed.
    let mut update = RosterUpdate {
        envelope_version: RosterUpdate::CURRENT_VERSION,
        envelope_type: RosterUpdate::TYPE.to_string(),
        did,
        prior_version,
        new_version: prior_version + 1,
        new_roster,
        signed_at,
        signer_device_id: signer.device_id().to_string(),
        signature: vec![0u8; RosterUpdate::SIGNATURE_LEN],
    };
    update.validate()?;
    let canonical = update.canonical_bytes();
    let signature = signer.sign_prehash(&canonical);
    update.signature = signature.to_vec();
    Ok(update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InMemoryDeviceSigner;

    fn valid_envelope() -> NonceEnvelope {
        NonceEnvelope {
            envelope_version: NonceEnvelope::CURRENT_VERSION,
            envelope_type: NonceEnvelope::TYPE.into(),
            nonce: vec![0xAB; 32],
            did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXY".into(),
            audience: "kms-banking".into(),
            purpose: "get_accounts".into(),
            issued_at: 1_716_583_200,
            expires_at: 1_716_583_230,
            issuer: "kms-banking-proxy".into(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sign_produces_well_formed_assertion() {
        let signer = InMemoryDeviceSigner::generate("dev-laptop");
        let assertion = sign_assertion(&signer, valid_envelope()).unwrap();
        assert_eq!(assertion.envelope_version, SignedAssertion::CURRENT_VERSION);
        assert_eq!(assertion.envelope_type, SignedAssertion::TYPE);
        assert_eq!(assertion.device_id, "dev-laptop");
        assert_eq!(assertion.signature.len(), SignedAssertion::SIGNATURE_LEN);
        assert_eq!(assertion.nonce_envelope, valid_envelope());
        assertion.validate().unwrap();
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn sign_rejects_invalid_envelope() {
        let signer = InMemoryDeviceSigner::generate("dev-laptop");
        let mut bad = valid_envelope();
        bad.envelope_version = 99;
        let err = sign_assertion(&signer, bad).unwrap_err();
        assert_eq!(err, VerifyError::UnknownEnvelopeVersion);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn signature_is_deterministic_for_rfc6979() {
        // The p256 crate uses RFC 6979 deterministic ECDSA. Same key, same
        // input → same signature. Useful for test vectors.
        let signer = InMemoryDeviceSigner::generate("dev-laptop");
        let env = valid_envelope();
        let a = sign_assertion(&signer, env.clone()).unwrap();
        let b = sign_assertion(&signer, env).unwrap();
        assert_eq!(a.signature, b.signature);
    }
}
