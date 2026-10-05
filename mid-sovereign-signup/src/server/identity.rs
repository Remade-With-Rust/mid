use p256::ecdsa::SigningKey;

use crate::attest::{sign_attestation_single_device, AttestationClaims};
use crate::{FlowError, User};

/// The service's own `did:mata` — a single-key identity whose DID *is* its
/// key, so every attestation it signs verifies offline with no registry.
/// Pin [`Self::did`] in the consumers that trust this service.
pub struct ServiceIdentity {
    did: String,
    multibase: String,
    device_id: String,
    signer: kms_client::InMemoryDeviceSigner,
}

impl ServiceIdentity {
    /// The device id stamped into the identity's single-entry roster.
    pub const DEVICE_ID: &'static str = "signupd";

    /// Build from a 32-byte P-256 secret scalar (keep it with the store's
    /// key-encryption key; losing it changes the DID consumers pinned).
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, String> {
        let key = SigningKey::from_bytes(&secret.into())
            .map_err(|_| "the identity key is not a valid P-256 scalar".to_string())?;
        let vk = *key.verifying_key();
        Ok(Self {
            did: mid_verify::keys::did_from_pubkey(&vk),
            multibase: mid_verify::keys::multibase_from_pubkey(&vk),
            device_id: Self::DEVICE_ID.to_string(),
            signer: kms_client::InMemoryDeviceSigner::new(Self::DEVICE_ID, key),
        })
    }

    /// The service DID (`did:mata:<base58 compressed key>`).
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Sign an attestation for a verified user, valid `ttl_secs` from `now`.
    pub fn attest(&self, user: &User, now: u64, ttl_secs: u64) -> Result<String, FlowError> {
        let claims = AttestationClaims::for_user(user)?;
        sign_attestation_single_device(
            &self.did,
            &self.multibase,
            &self.device_id,
            &claims,
            &self.signer,
            now,
            ttl_secs,
        )
        .map_err(|e| {
            tracing::error!(error = %e, "attestation signing failed");
            FlowError::NotVerified
        })
    }
}

impl std::fmt::Debug for ServiceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceIdentity")
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}
