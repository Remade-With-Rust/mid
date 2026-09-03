//! The device-signing seam of MATA mID.
//!
//! Every place a device signs — `kms-client`'s assertions, `mid-issuer`'s
//! genesis roster, `mata-sign`'s tokens, a Janus microcontroller's manifest —
//! asks for the same two things: a stable device id and a canonical (low-s)
//! ECDSA P-256 signature over a 32-byte prehash. That contract is
//! [`DeviceSigner`]. This crate is the leaf that holds it, so a hardware
//! implementation (a secure element, an eFuse-backed key, a microcontroller's
//! DS peripheral) depends on nothing but this and `p256`, and no consumer has
//! to pull an HTTP client to name the trait.
//!
//! [`InMemoryDeviceSigner`] is the plain-software implementation: tests, a
//! first-cut deploy where the key lives in an encrypted vault, and the
//! reference every other implementation is checked against (same key, same
//! prehash, same 64 bytes — RFC 6979 makes it deterministic).
//!
//! `no_std` + `alloc` without the `std` feature.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// The abstract capability a device's signing key provides.
///
/// Implementations MUST:
///
/// 1. Return a stable, deterministic identifier for the signing device via
///    [`device_id`](DeviceSigner::device_id) — it is matched against a
///    `device_id` in the user's DID roster.
/// 2. Produce a canonical (low-s) ECDSA P-256 signature over a 32-byte
///    prehash via [`sign_prehash`](DeviceSigner::sign_prehash). Every MATA
///    verifier rejects high-s as a malleability defence.
pub trait DeviceSigner {
    /// Stable identifier of this signing device. Matched against the user's
    /// DID roster at the verifier.
    fn device_id(&self) -> &str;

    /// Sign a 32-byte SHA-256 prehash. Returns the canonical (low-s) 64-byte
    /// `r || s` representation.
    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64];
}

impl<T: DeviceSigner + ?Sized> DeviceSigner for &T {
    fn device_id(&self) -> &str {
        (**self).device_id()
    }

    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64] {
        (**self).sign_prehash(prehash)
    }
}

/// Canonicalise a signature to low-s and lay it out as `r || s`.
///
/// The one function every software [`DeviceSigner`] shares, exposed so a
/// hardware-backed implementation that gets raw `(r, s)` from its part can
/// apply the same rule.
#[must_use]
pub fn canonical_bytes(raw: Signature) -> [u8; 64] {
    let normalized = raw.normalize_s().unwrap_or(raw);
    let bytes = normalized.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

/// In-memory [`DeviceSigner`] backed by a raw [`SigningKey`].
///
/// Use this for tests and for a first-cut production deploy where the
/// signing key lives in the app's encrypted vault rather than in a Secure
/// Enclave / Keystore. Hardware-backed implementations replace this without
/// changing call sites — the trait is the contract.
pub struct InMemoryDeviceSigner {
    device_id: String,
    signing_key: SigningKey,
}

impl InMemoryDeviceSigner {
    /// Wrap an existing [`SigningKey`] under a stable `device_id`.
    pub fn new(device_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            device_id: device_id.into(),
            signing_key,
        }
    }

    /// Generate a fresh P-256 keypair using OS randomness. Convenience for
    /// tests and bootstrap flows.
    #[cfg(all(feature = "std", not(target_arch = "wasm32")))]
    pub fn generate(device_id: impl Into<String>) -> Self {
        use rand_core::OsRng;
        Self::new(device_id, SigningKey::random(&mut OsRng))
    }

    /// 65-byte SEC1-uncompressed public key (`0x04 || x[32] || y[32]`).
    /// Use this when adding the device to the user's roster.
    pub fn pubkey_sec1(&self) -> Vec<u8> {
        self.verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    /// Underlying public key handle. Most callers want
    /// [`pubkey_sec1`](Self::pubkey_sec1) instead.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Borrow the underlying [`SigningKey`]. Used by tests that need to
    /// construct unusual signatures for adversarial cases; production code
    /// should not reach for this.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl DeviceSigner for InMemoryDeviceSigner {
    fn device_id(&self) -> &str {
        &self.device_id
    }

    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64] {
        let raw: Signature = self
            .signing_key
            .sign_prehash(prehash)
            .expect("sign_prehash with 32-byte input cannot fail for a valid key");
        canonical_bytes(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use sha2::{Digest, Sha256};

    fn signer() -> InMemoryDeviceSigner {
        let seed: [u8; 32] = Sha256::digest(b"mid-signer test key").into();
        InMemoryDeviceSigner::new("dev-1", SigningKey::from_bytes(&seed.into()).unwrap())
    }

    #[test]
    fn every_signature_is_low_s_deterministic_and_verifies() {
        let s = signer();
        assert_eq!(s.device_id(), "dev-1");
        for i in 0..200u32 {
            let prehash: [u8; 32] = Sha256::digest(i.to_le_bytes()).into();
            let bytes = s.sign_prehash(&prehash);
            assert_eq!(bytes, s.sign_prehash(&prehash), "RFC 6979: deterministic");
            let sig = Signature::from_slice(&bytes).unwrap();
            assert!(sig.normalize_s().is_none(), "low-s, always");
            s.verifying_key().verify_prehash(&prehash, &sig).unwrap();
        }
    }

    #[test]
    fn canonical_bytes_flips_a_high_s_and_leaves_a_low_s() {
        let s = signer();
        let prehash: [u8; 32] = Sha256::digest(b"x").into();
        let low = Signature::from_slice(&s.sign_prehash(&prehash)).unwrap();
        let (r, sc) = low.split_scalars();
        let high = Signature::from_scalars(r, -*sc).unwrap();
        assert!(high.normalize_s().is_some());
        assert_eq!(canonical_bytes(high), canonical_bytes(low));
        assert_eq!(canonical_bytes(low), s.sign_prehash(&prehash));
    }

    #[test]
    fn a_reference_to_a_signer_is_a_signer() {
        fn takes(signer: impl DeviceSigner) -> [u8; 64] {
            signer.sign_prehash(&[7u8; 32])
        }
        let s = signer();
        assert_eq!(takes(&s), s.sign_prehash(&[7u8; 32]));
        let dynamic: &dyn DeviceSigner = &s;
        assert_eq!(dynamic.device_id(), "dev-1");
    }

    #[test]
    fn pubkey_is_sec1_uncompressed() {
        let s = signer();
        let pk = s.pubkey_sec1();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
        assert_eq!(
            VerifyingKey::from_sec1_bytes(&pk).unwrap(),
            *s.verifying_key()
        );
    }
}
