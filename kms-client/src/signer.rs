//! Device-signing abstraction.
//!
//! Production implementations live in `packages/ui` (or wherever the M5
//! signing key actually resides). This crate ships only the trait and a
//! plain-software implementation usable as a test helper or bootstrap.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// The abstract capability `kms-client` needs from a device's signing key.
///
/// Implementations MUST:
///
/// 1. Return a stable, deterministic identifier for the signing device via
///    [`device_id`](DeviceSigner::device_id) — must match a `device_id` in
///    the user's DID roster.
/// 2. Produce a canonical (low-s) ECDSA P-256 signature over a 32-byte
///    prehash via [`sign_prehash`](DeviceSigner::sign_prehash). High-s
///    signatures will be rejected by `kms-verifier` as
///    [`VerifyError::SignatureInvalid`].
pub trait DeviceSigner {
    /// Stable identifier of this signing device. Matched against the user's
    /// DID roster at the verifier.
    fn device_id(&self) -> &str;

    /// Sign a 32-byte SHA-256 prehash. Returns the canonical (low-s) 64-byte
    /// `r || s` representation.
    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64];
}

/// In-memory [`DeviceSigner`] backed by a raw [`SigningKey`].
///
/// Use this for tests and for a first-cut production deploy where the
/// signing key lives in the app's encrypted vault rather than in a Secure
/// Enclave / Keystore. Future hardware-backed implementations replace this
/// without changing call sites — the trait is the contract.
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
    #[cfg(not(target_arch = "wasm32"))]
    pub fn generate(device_id: impl Into<String>) -> Self {
        use rand_core::OsRng;
        Self::new(device_id, SigningKey::random(&mut OsRng))
    }

    /// 65-byte SEC1-uncompressed public key (`0x04 || x[32] || y[32]`).
    /// Use this when adding the device to the user's roster.
    pub fn pubkey_sec1(&self) -> Vec<u8> {
        self.verifying_key().to_encoded_point(false).as_bytes().to_vec()
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
        // Canonicalize to low-s — the verifier rejects high-s as a
        // malleability defense.
        let normalized = raw.normalize_s().unwrap_or(raw);
        let bytes = normalized.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes.as_slice());
        out
    }
}
