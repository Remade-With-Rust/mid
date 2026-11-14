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
///
/// **v2** (ADR 0010): the entity DID is registry-native, `did:mata:<base58>`, with no
/// `entity:` infix. The derivation, the key and the proof's signer are unchanged; only
/// the string the statement names. A v1 proof still verifies *as v1* — the statement
/// embeds the version and the DID it was signed over, so old proofs neither break nor
/// silently upgrade. See [`verify_control_proof`].
///
/// **v3** (ADR 0011, DID-logins M1): the controller is the *derived* personal root.
/// The statement's shape does not change; the version records that the signer is the
/// root every device of the person shares, so a v3 proof verifies from any of them.
/// A v2 proof (signed by a retired random root) still verifies *as v2* against the
/// key it names — the version sits inside the signed statement — and the migrating
/// release re-signs every stored proof at v3.
pub const ENTITY_PROOF_VERSION: u32 = 3;

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
    /// `did:mata:<base58btc(compressed P-256 pubkey)>` — the spec-target form, the
    /// same one a device or a person derives. Registry-native by construction: the
    /// key *is* the DID, so `verify_genesis` accepts the company's own signature as
    /// its whole authorization (ADR 0010, superseding ADR 0008 D1).
    ///
    /// Deliberately indistinguishable from a personal DID at the protocol layer. The
    /// ledger, the gateway and the registry should not care what kind of thing an
    /// identity is; the directory that records "person P controls company C" does.
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
        "did:mata:{}",
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

    /// **A v2 proof still verifies, as v2** (ADR 0011). The proofs every holding
    /// stored before the derived root were signed by a random `#root` that is now
    /// retired; they verify against that key at the version they declare, and only
    /// a re-sign by the derived root produces a v3.
    #[test]
    fn a_v2_proof_by_a_retired_root_still_verifies_as_v2() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let (retired_priv, retired_pub) = root_keypair();
        let ent = derive_entity_identity(VAULT, "h-v2").unwrap();
        let controller = "did:mata:retiredRandomRoot";
        let canonical = canonical_statement(controller, &ent.entity_did, 2, 5).unwrap();
        let der = sign_with_private_key(&retired_priv, &canonical).unwrap();
        let v2 = EntityControlProof {
            version: 2,
            controller_did: controller.into(),
            entity_did: ent.entity_did.clone(),
            created_at_unix_ms: 5,
            signature_b64: URL_SAFE_NO_PAD.encode(der),
        };
        verify_control_proof(&v2, &retired_pub).expect("a v2 proof verifies at v2");

        // Relabelling it v3 fails: the version is inside the signature.
        let mut promoted = v2.clone();
        promoted.version = ENTITY_PROOF_VERSION;
        assert!(verify_control_proof(&promoted, &retired_pub).is_err(), "no silent upgrade");

        // A re-sign by the derived root is a v3 that the retired key cannot vouch for.
        let derived = crate::derive_root_identity(VAULT).unwrap();
        let v3 = build_control_proof(&derived.private_scalar, &derived.did, &ent.entity_did, 6).unwrap();
        assert_eq!(v3.version, ENTITY_PROOF_VERSION);
        verify_control_proof(&v3, &derived.public_key_sec1).unwrap();
        assert!(verify_control_proof(&v3, &retired_pub).is_err());
    }

    #[test]
    fn derivation_is_deterministic_and_namespaced() {
        let a = derive_entity_identity(VAULT, "holding-1").unwrap();
        let b = derive_entity_identity(VAULT, "holding-1").unwrap();
        assert_eq!(a.entity_did, b.entity_did, "same inputs ⇒ same DID (no handshake)");
        assert_eq!(a.private_scalar, b.private_scalar);
        assert!(a.entity_did.starts_with("did:mata:"), "{}", a.entity_did);
        assert!(!a.entity_did.contains("entity:"), "no infix (ADR 0010): {}", a.entity_did);

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
        t1.entity_did = "did:mata:zzz".into();
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

    /// **The DID is the key.** The base58 suffix decodes to exactly the 33-byte compressed
    /// public key, which is what lets the registry's genesis door accept the company's
    /// own signature as its whole authorization. An infix, a UUID, or any other spelling
    /// would fail this and therefore fail to register.
    #[test]
    fn the_entity_did_is_the_compressed_public_key() {
        let ent = derive_entity_identity(VAULT, "h-registry").unwrap();
        let suffix = ent.entity_did.strip_prefix("did:mata:").expect("prefix");
        let bytes = bs58::decode(suffix).into_vec().expect("base58");
        assert_eq!(bytes.len(), 33, "compressed SEC1 point");
        // And it is the key we derived, not some other bytes.
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).expect("a P-256 point");
        assert_eq!(vk.to_encoded_point(false).as_bytes(), ent.public_key_sec1.as_slice());
    }

    /// **A v1 proof still verifies, as v1.** The statement carries its version and the
    /// DID string it was signed over, so a proof minted before ADR 0010 is neither
    /// broken by the new form nor quietly promoted to it.
    #[test]
    fn a_v1_proof_over_the_old_form_still_verifies_as_v1() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let (root_priv, root_pub) = root_keypair();
        let ent = derive_entity_identity(VAULT, "h-legacy").unwrap();
        // The v1 spelling of the same key.
        let legacy_did = ent.entity_did.replacen("did:mata:", "did:mata:entity:", 1);
        let controller = "did:mata:11111111-1111-1111-1111-111111111111";
        let canonical = canonical_statement(controller, &legacy_did, 1, 5).unwrap();
        let der = sign_with_private_key(&root_priv, &canonical).unwrap();
        let v1 = EntityControlProof {
            version: 1,
            controller_did: controller.into(),
            entity_did: legacy_did.clone(),
            created_at_unix_ms: 5,
            signature_b64: URL_SAFE_NO_PAD.encode(der),
        };
        verify_control_proof(&v1, &root_pub).expect("a v1 proof verifies at v1");

        // It does not verify if relabelled as v2 -- the version is inside the signature.
        let mut promoted = v1.clone();
        promoted.version = 2;
        assert!(verify_control_proof(&promoted, &root_pub).is_err(), "no silent upgrade");

        // And new proofs are v2 over the new form.
        let v2 = build_control_proof(&root_priv, controller, &ent.entity_did, 6).unwrap();
        assert_eq!(v2.version, ENTITY_PROOF_VERSION);
        verify_control_proof(&v2, &root_pub).unwrap();
    }
}
