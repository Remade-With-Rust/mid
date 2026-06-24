//! M4 — controlled-entity identity (SMB mission Milestone 4).
//!
//! A holding's optional, self-attested **entity identity**: a P-256 keypair
//! derived deterministically under the user's vault key (so it's identical on
//! every paired device with no handshake — the same instinct as `#encryption`),
//! plus a **control proof** signed by the user's personal `#root` key attesting
//! "this personal DID controls this entity DID."
//!
//! Substrate only (Phase 1): this proves control and stores the proof. It ships
//! **no** delegation, no external resolution of `did:mata:entity:…`, and no
//! MATA notarization — those wait on M7 attestation + a KYB process.
//!
//! ## Forward-compatibility (Workstream C)
//!
//! The proof is versioned ([`ENTITY_PROOF_VERSION`]). Future multi-controller
//! delegation adds *additional* signed control statements; it must never
//! require re-deriving the entity key or re-issuing the v1 proof.

use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};

use crate::{
    derive_subordinate_key, sign_with_private_key, verify_signature_sec1, IdentityError,
};

/// Current control-proof format version. Bump only with a migration story; v1
/// delegation must extend, never re-issue (see module docs).
pub const ENTITY_PROOF_VERSION: u32 = 1;

/// The HKDF purpose label for a holding's entity key. Versioned by the
/// `MATA-PKI-v1/` salt inside [`derive_subordinate_key`]; domain-separated from
/// `business-banking/{id}` and `#encryption` so the keys never collide.
fn entity_purpose(holding_id: &str) -> String {
    format!("entity/{holding_id}")
}

/// A holding's deterministic entity identity, derived from
/// `(vault_key, holding_id)`. The private scalar is sensitive — zeroize or drop
/// it promptly; only [`entity_did`](Self::entity_did) and
/// [`public_key_sec1`](Self::public_key_sec1) are safe to persist.
pub struct EntityIdentity {
    /// `did:mata:entity:<base58btc(compressed P-256 pubkey)>` — a clearly
    /// namespaced variant of the personal `did:mata:` so a resolver can tell a
    /// person from an entity.
    pub entity_did: String,
    /// Raw 32-byte P-256 private scalar. **Sensitive.**
    pub private_scalar: [u8; 32],
    /// SEC1 uncompressed public key (65 bytes, `0x04 || X || Y`).
    pub public_key_sec1: Vec<u8>,
}

/// Derive the entity identity for a holding. Deterministic ⇒ reproducible on
/// any paired device that can decrypt the vault key, with no handshake.
pub fn derive_entity_identity(
    vault_key: &[u8],
    holding_id: &str,
) -> Result<EntityIdentity, IdentityError> {
    let seed = derive_subordinate_key(vault_key, &entity_purpose(holding_id));
    let sk = SigningKey::from_bytes((&seed).into()).map_err(|_| IdentityError::InvalidPrivateKey)?;
    let vk = sk.verifying_key();
    let entity_did = format!(
        "did:mata:entity:{}",
        bs58::encode(vk.to_encoded_point(true).as_bytes()).into_string()
    );
    Ok(EntityIdentity {
        entity_did,
        private_scalar: seed,
        public_key_sec1: vk.to_encoded_point(false).as_bytes().to_vec(),
    })
}

/// The exact statement that gets canonicalized + signed. Kept private so the
/// only way to produce signing bytes is through [`build_control_proof`] /
/// [`verify_control_proof`], guaranteeing both sides hash identical bytes.
#[derive(Serialize, Deserialize)]
struct ControlStatement<'a> {
    controller_did: &'a str,
    entity_did: &'a str,
    version: u32,
    created_at_unix_ms: i64,
}

fn canonical_statement(
    controller_did: &str,
    entity_did: &str,
    version: u32,
    created_at_unix_ms: i64,
) -> Result<Vec<u8>, IdentityError> {
    let stmt = ControlStatement { controller_did, entity_did, version, created_at_unix_ms };
    serde_jcs::to_string(&stmt)
        .map(String::into_bytes)
        .map_err(|e| IdentityError::Canonicalize(e.to_string()))
}

/// A verifiable proof that `controller_did` controls `entity_did` — the
/// personal `#root` key's self-signature over the RFC 8785 (JCS) canonical
/// statement. Stored alongside the holding; verified with the controller's
/// `#root` public key via [`verify_control_proof`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntityControlProof {
    /// Proof format version ([`ENTITY_PROOF_VERSION`]).
    pub version: u32,
    /// The personal DID asserting control (`did:mata:<uuid>`).
    pub controller_did: String,
    /// The entity being controlled (`did:mata:entity:<…>`).
    pub entity_did: String,
    /// When the proof was minted (ms since epoch).
    pub created_at_unix_ms: i64,
    /// DER-encoded ECDSA-P256-SHA256 signature over the JCS statement,
    /// base64url (no padding).
    pub signature_b64: String,
}

/// Build a control proof by signing the canonical statement with the personal
/// `#root` private scalar (32 raw bytes, decrypted from the credential).
pub fn build_control_proof(
    root_private_scalar: &[u8],
    controller_did: &str,
    entity_did: &str,
    created_at_unix_ms: i64,
) -> Result<EntityControlProof, IdentityError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let canonical =
        canonical_statement(controller_did, entity_did, ENTITY_PROOF_VERSION, created_at_unix_ms)?;
    let der = sign_with_private_key(root_private_scalar, &canonical)?;
    Ok(EntityControlProof {
        version: ENTITY_PROOF_VERSION,
        controller_did: controller_did.to_string(),
        entity_did: entity_did.to_string(),
        created_at_unix_ms,
        signature_b64: URL_SAFE_NO_PAD.encode(der),
    })
}

/// Verify a control proof against the controller's `#root` public key (SEC1
/// uncompressed, 65 bytes). Returns `Ok(())` iff the signature is valid over the
/// recomputed canonical statement — a forged controller, tampered DID, or
/// altered timestamp all fail.
pub fn verify_control_proof(
    proof: &EntityControlProof,
    controller_root_pubkey_sec1: &[u8],
) -> Result<(), IdentityError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let canonical = canonical_statement(
        &proof.controller_did,
        &proof.entity_did,
        proof.version,
        proof.created_at_unix_ms,
    )?;
    let der = URL_SAFE_NO_PAD
        .decode(proof.signature_b64.as_bytes())
        .map_err(|_| IdentityError::InvalidSignature)?;
    verify_signature_sec1(controller_root_pubkey_sec1, &canonical, &der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair_from_scalar_bytes;

    const VAULT: &[u8] = &[42u8; 32];

    /// A deterministic stand-in for the personal `#root` keypair.
    fn root_keypair() -> (Vec<u8>, Vec<u8>) {
        keypair_from_scalar_bytes(&[9u8; 32]).unwrap()
    }

    #[test]
    fn derivation_is_deterministic_and_namespaced() {
        let a = derive_entity_identity(VAULT, "holding-1").unwrap();
        let b = derive_entity_identity(VAULT, "holding-1").unwrap();
        assert_eq!(a.entity_did, b.entity_did, "same inputs ⇒ same DID (no handshake)");
        assert_eq!(a.private_scalar, b.private_scalar);
        assert!(a.entity_did.starts_with("did:mata:entity:"));

        // Different holdings ⇒ different entity (domain separation).
        let other = derive_entity_identity(VAULT, "holding-2").unwrap();
        assert_ne!(a.entity_did, other.entity_did);

        // Different vault ⇒ different entity.
        let other_vault = derive_entity_identity(&[7u8; 32], "holding-1").unwrap();
        assert_ne!(a.entity_did, other_vault.entity_did);
    }

    #[test]
    fn proof_signs_and_verifies() {
        let (root_priv, root_pub) = root_keypair();
        let ent = derive_entity_identity(VAULT, "h1").unwrap();
        let controller = "did:mata:11111111-1111-1111-1111-111111111111";

        let proof = build_control_proof(&root_priv, controller, &ent.entity_did, 1_700_000_000_000).unwrap();
        assert_eq!(proof.version, ENTITY_PROOF_VERSION);
        verify_control_proof(&proof, &root_pub).expect("valid proof must verify");
    }

    #[test]
    fn forged_controller_key_is_rejected() {
        let (root_priv, _root_pub) = root_keypair();
        let (_other_priv, other_pub) = keypair_from_scalar_bytes(&[3u8; 32]).unwrap();
        let ent = derive_entity_identity(VAULT, "h1").unwrap();

        let proof = build_control_proof(&root_priv, "did:mata:u", &ent.entity_did, 1).unwrap();
        // A different key can't be the verified controller.
        assert!(verify_control_proof(&proof, &other_pub).is_err());
    }

    #[test]
    fn tampered_fields_are_rejected() {
        let (root_priv, root_pub) = root_keypair();
        let ent = derive_entity_identity(VAULT, "h1").unwrap();
        let proof = build_control_proof(&root_priv, "did:mata:u", &ent.entity_did, 1).unwrap();

        // Tamper the entity DID.
        let mut t1 = proof.clone();
        t1.entity_did = "did:mata:entity:zzz".into();
        assert!(verify_control_proof(&t1, &root_pub).is_err());

        // Tamper the controller.
        let mut t2 = proof.clone();
        t2.controller_did = "did:mata:attacker".into();
        assert!(verify_control_proof(&t2, &root_pub).is_err());

        // Tamper the timestamp.
        let mut t3 = proof.clone();
        t3.created_at_unix_ms = 2;
        assert!(verify_control_proof(&t3, &root_pub).is_err());
    }
}
