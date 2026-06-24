//! Key decoding from the wire-format strings.
//!
//! Two surfaces are exposed:
//!
//! - [`pubkey_from_did`] — decodes the genesis public key from the
//!   `did:mata:<base58btc-of-33-byte-compressed-pubkey>` identifier.
//! - [`pubkey_from_multibase`] — decodes a verification method's
//!   `publicKeyMultibase` field (the `z6Mk...` form from the DID-document
//!   spec).
//!
//! Both forms expect a 33-byte SEC1-compressed P-256 public key (first
//! byte `0x02` or `0x03`, next 32 bytes are the X coordinate).
//!
//! v0 keeps things simple: the multibase prefix is `z` (base58btc) and
//! the encoded bytes ARE the raw SEC1-compressed pubkey, no multicodec
//! varint prefix. When we want did:key wire compatibility (future work),
//! we'll prepend the `p256-pub` multicodec varint `[0x80, 0x24]` and
//! decode accordingly. The wire-format bump goes through a follow-on ADR.

use p256::ecdsa::VerifyingKey;

use crate::error::VerifyError;

/// Decode the genesis P-256 public key from the DID identifier.
///
/// Expects the form `did:mata:<base58btc>` where the base58 portion
/// decodes to exactly 33 bytes (SEC1 compressed). Any other form
/// (legacy UUID-shaped DIDs from kms-types, malformed bytes, wrong
/// length) is rejected.
pub fn pubkey_from_did(did: &str) -> Result<VerifyingKey, VerifyError> {
    let suffix = did
        .strip_prefix("did:mata:")
        .ok_or_else(|| VerifyError::MalformedDid { did: did.to_string() })?;
    let bytes = bs58::decode(suffix)
        .into_vec()
        .map_err(|_| VerifyError::MalformedDid { did: did.to_string() })?;
    if bytes.len() != 33 {
        return Err(VerifyError::MalformedDid { did: did.to_string() });
    }
    VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|_| VerifyError::MalformedDid { did: did.to_string() })
}

/// Decode a verification method's `publicKeyMultibase` field to a
/// P-256 public key.
///
/// Expects the form `z<base58btc>` where the base58 portion decodes to
/// exactly 33 bytes (SEC1 compressed). The `vm_id` is taken purely for
/// error reporting — if decoding fails, the error names which VM was
/// at fault so an RP debugging a forged response can correlate.
pub fn pubkey_from_multibase(mb: &str, vm_id: &str) -> Result<VerifyingKey, VerifyError> {
    let suffix = mb
        .strip_prefix('z')
        .ok_or_else(|| VerifyError::MalformedVmPubkey { vm_id: vm_id.to_string() })?;
    let bytes = bs58::decode(suffix)
        .into_vec()
        .map_err(|_| VerifyError::MalformedVmPubkey { vm_id: vm_id.to_string() })?;
    if bytes.len() != 33 {
        return Err(VerifyError::MalformedVmPubkey { vm_id: vm_id.to_string() });
    }
    VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|_| VerifyError::MalformedVmPubkey { vm_id: vm_id.to_string() })
}

/// Encode a P-256 verifying key as the DID's base58 suffix. Used in test
/// fixtures to construct valid `did:mata:<...>` identifiers from a
/// generated keypair. Production wallets follow the same encoding when
/// minting their genesis DID.
pub fn did_from_pubkey(verifying_key: &VerifyingKey) -> String {
    let encoded = verifying_key.to_encoded_point(true); // compressed = 33 bytes
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes.len(), 33);
    format!("did:mata:{}", bs58::encode(bytes).into_string())
}

/// Encode a P-256 verifying key as the multibase form for a
/// `verificationMethod.publicKeyMultibase` field.
pub fn multibase_from_pubkey(verifying_key: &VerifyingKey) -> String {
    let encoded = verifying_key.to_encoded_point(true);
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes.len(), 33);
    format!("z{}", bs58::encode(bytes).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};

    /// Deterministic test keypair (matches mid-issuer's test helper pattern).
    fn test_key(seed: &str) -> SigningKey {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b"-mid-verify-test-seed");
        let bytes: [u8; 32] = hasher.finalize().into();
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    #[test]
    fn round_trip_pubkey_through_did() {
        let sk = test_key("device-A");
        let vk = *sk.verifying_key();
        let did = did_from_pubkey(&vk);
        let recovered = pubkey_from_did(&did).unwrap();
        assert_eq!(vk.to_encoded_point(true), recovered.to_encoded_point(true));
    }

    #[test]
    fn round_trip_pubkey_through_multibase() {
        let sk = test_key("device-A");
        let vk = *sk.verifying_key();
        let mb = multibase_from_pubkey(&vk);
        let recovered = pubkey_from_multibase(&mb, "did:mata:abc#dev").unwrap();
        assert_eq!(vk.to_encoded_point(true), recovered.to_encoded_point(true));
    }

    #[test]
    fn pubkey_from_did_rejects_non_mata_prefix() {
        let err = pubkey_from_did("did:key:zFakeKey").unwrap_err();
        matches!(err, VerifyError::MalformedDid { .. });
    }

    #[test]
    fn pubkey_from_did_rejects_uuid_suffix() {
        // Legacy mata-identity UUID DID — valid by kms-types::did but NOT
        // by mid-verify (no pubkey to decode).
        let err = pubkey_from_did("did:mata:550e8400-e29b-41d4-a716-446655440000").unwrap_err();
        matches!(err, VerifyError::MalformedDid { .. });
    }

    #[test]
    fn pubkey_from_did_rejects_random_base58() {
        // Right alphabet, wrong length when decoded.
        let err = pubkey_from_did("did:mata:abc123").unwrap_err();
        matches!(err, VerifyError::MalformedDid { .. });
    }

    #[test]
    fn pubkey_from_multibase_rejects_missing_z_prefix() {
        let sk = test_key("device-A");
        let vk = *sk.verifying_key();
        let mb_no_z = bs58::encode(vk.to_encoded_point(true).as_bytes()).into_string();
        let err = pubkey_from_multibase(&mb_no_z, "test#vm").unwrap_err();
        matches!(err, VerifyError::MalformedVmPubkey { .. });
    }

    #[test]
    fn two_different_keys_produce_different_dids() {
        let sk_a = test_key("device-A");
        let sk_b = test_key("device-B");
        let did_a = did_from_pubkey(sk_a.verifying_key());
        let did_b = did_from_pubkey(sk_b.verifying_key());
        assert_ne!(did_a, did_b);
    }
}
