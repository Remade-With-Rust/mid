//! Wallet-side signing helpers for producing embedded roster envelopes.
//!
//! Two operations:
//!
//! - [`sign_genesis_roster`] — called ONCE at signup. The wallet has just
//!   minted its first M5 device keypair; it computes the DID from the
//!   pubkey, constructs the genesis verification method, and self-signs
//!   the canonical bytes. The resulting envelope is persisted locally
//!   forever; every future mID response bundles it.
//!
//! - [`sign_roster_chain_entry`] — called each time the user adds or
//!   removes a device. The wallet builds the new full roster (the set of
//!   currently-authorized verification methods) and signs the canonical
//!   bytes with a verification method that's in the PRIOR roster. The
//!   resulting envelope is appended to the chain.
//!
//! Both functions are pure transformations: they take inputs, sign canonical
//! bytes via the supplied `DeviceSigner`, and return a populated envelope.
//! No I/O, no clock reads (the caller passes `signed_at`), no randomness in
//! the envelope assembly (signature randomness comes from the signer).
//!
//! The canonical bytes are produced by [`crate::canonical`] — the same form
//! `mid-verify` re-computes when verifying. Single source of truth.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kms_client::DeviceSigner;
use sha2::{Digest, Sha256};

use crate::canonical;
use crate::types::{EmbeddedGenesisRoster, EmbeddedRosterChainEntry, VerificationMethod};

/// W3C DID-spec verification method type for ECDSA P-256.
pub const VM_TYPE_ECDSA_P256: &str = "EcdsaSecp256r1VerificationKey2019";

/// Construct and self-sign the genesis roster envelope.
///
/// Called ONCE per DID at wallet signup. The wallet has just generated
/// its first M5 device keypair (the "genesis key"); this function:
///
/// 1. Constructs the genesis device's `VerificationMethod` from the
///    supplied identifiers.
/// 2. Assembles the `EmbeddedGenesisRoster` at version 1 with the single
///    VM.
/// 3. Computes the canonical bytes via
///    [`crate::canonical::genesis_canonical_bytes`].
/// 4. SHA-256 prehashes them and asks the signer to produce a low-s
///    canonical ECDSA P-256 signature.
/// 5. base64url-encodes the signature into `self_signed_by_genesis_key`.
///
/// The caller is responsible for:
///
/// - Computing `did` from the genesis pubkey (use
///   [`mid_verify::keys::did_from_pubkey`] for the canonical encoding).
/// - Computing `device_pubkey_multibase` (use
///   [`mid_verify::keys::multibase_from_pubkey`]).
/// - Ensuring `signer.device_id()` matches `device_id` — the signer must
///   be the genesis device.
/// - Stamping `signed_at` from a trusted wall clock.
///
/// The returned envelope is ready to persist + bundle in every future
/// mID response.
pub fn sign_genesis_roster(
    did: String,
    device_id: &str,
    device_pubkey_multibase: String,
    signed_at: u64,
    signer: &dyn DeviceSigner,
) -> EmbeddedGenesisRoster {
    let vm = VerificationMethod {
        id: format!("{did}#{device_id}"),
        vm_type: VM_TYPE_ECDSA_P256.to_string(),
        controller: did.clone(),
        public_key_multibase: device_pubkey_multibase,
    };

    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did,
        verification_methods: vec![vm],
        signed_at,
        // Placeholder — canonical_bytes deliberately excludes this field
        // so the canonical form is computable before the signature exists.
        self_signed_by_genesis_key: String::new(),
    };

    let canonical_bytes = canonical::genesis_canonical_bytes(&genesis);
    let prehash: [u8; 32] = Sha256::digest(&canonical_bytes).into();
    let signature = signer.sign_prehash(&prehash);
    genesis.self_signed_by_genesis_key = URL_SAFE_NO_PAD.encode(signature);

    genesis
}

/// Construct and sign a roster-chain entry recording a roster mutation.
///
/// Called each time the user adds or removes a device. The wallet:
///
/// 1. Determines the new full roster (after the mutation).
/// 2. Picks a signer from the PRIOR roster — typically the device the
///    user is currently using to perform the mutation.
/// 3. Calls this function with the new VMs + the signer's `device_id` as
///    `signer_kid` + `new_version = prior_version + 1`.
///
/// The function:
///
/// 1. Assembles the `EmbeddedRosterChainEntry`.
/// 2. Computes the canonical bytes via
///    [`crate::canonical::chain_entry_canonical_bytes`].
/// 3. SHA-256 prehashes and signs.
/// 4. base64url-encodes the signature into
///    `signed_by_signer_in_prior_roster`.
///
/// The caller is responsible for:
///
/// - Ensuring `signer_kid` corresponds to a VM present in the PRIOR
///   roster.
/// - Ensuring `new_version > prior_version` (the verifier rejects
///   non-monotonic chains).
/// - Building `new_verification_methods` correctly (e.g. include the
///   newly-added VM; exclude the just-revoked one).
pub fn sign_roster_chain_entry(
    did: String,
    new_version: u64,
    new_verification_methods: Vec<VerificationMethod>,
    signer_kid: String,
    signed_at: u64,
    signer: &dyn DeviceSigner,
) -> EmbeddedRosterChainEntry {
    let mut entry = EmbeddedRosterChainEntry {
        version: new_version,
        did,
        verification_methods: new_verification_methods,
        signed_at,
        signed_by_signer_in_prior_roster: String::new(),
        signer_kid,
    };

    let canonical_bytes = canonical::chain_entry_canonical_bytes(&entry);
    let prehash: [u8; 32] = Sha256::digest(&canonical_bytes).into();
    let signature = signer.sign_prehash(&prehash);
    entry.signed_by_signer_in_prior_roster = URL_SAFE_NO_PAD.encode(signature);

    entry
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kms_client::InMemoryDeviceSigner;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

    /// Deterministic test signer — same recipe as the mid-issuer test
    /// helper.
    fn make_signer(seed: &str, device_id: &str) -> (SigningKey, InMemoryDeviceSigner) {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b"-mid-bootstrap-test-seed");
        let bytes: [u8; 32] = hasher.finalize().into();
        let sk = SigningKey::from_bytes(&bytes.into()).unwrap();
        let signer = InMemoryDeviceSigner::new(device_id, sk.clone());
        (sk, signer)
    }

    fn verify_signature_against_pubkey(
        canonical_bytes: &[u8],
        signature_b64: &str,
        pubkey: &VerifyingKey,
    ) -> bool {
        let prehash: [u8; 32] = Sha256::digest(canonical_bytes).into();
        let sig_bytes = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();
        pubkey.verify_prehash(&prehash, &sig).is_ok()
    }

    // ─── sign_genesis_roster ───────────────────────────────────────────────

    #[test]
    fn sign_genesis_roster_produces_well_formed_envelope() {
        let (_sk, signer) = make_signer("genesis-test", "dev-laptop");
        let genesis = sign_genesis_roster(
            "did:mata:abc123".to_string(),
            "dev-laptop",
            "zFakeMultibase".to_string(),
            1_700_000_000,
            &signer,
        );

        assert_eq!(genesis.version, 1);
        assert_eq!(genesis.did, "did:mata:abc123");
        assert_eq!(genesis.verification_methods.len(), 1);
        assert_eq!(genesis.verification_methods[0].id, "did:mata:abc123#dev-laptop");
        assert_eq!(
            genesis.verification_methods[0].vm_type,
            "EcdsaSecp256r1VerificationKey2019"
        );
        assert_eq!(genesis.verification_methods[0].controller, "did:mata:abc123");
        assert_eq!(genesis.signed_at, 1_700_000_000);
        assert!(!genesis.self_signed_by_genesis_key.is_empty());
    }

    #[test]
    fn sign_genesis_roster_signature_verifies_against_genesis_key() {
        let (sk, signer) = make_signer("genesis-test", "dev-laptop");
        let genesis = sign_genesis_roster(
            "did:mata:abc123".to_string(),
            "dev-laptop",
            "zFakeMultibase".to_string(),
            1_700_000_000,
            &signer,
        );

        let canonical_bytes = canonical::genesis_canonical_bytes(&genesis);
        let ok = verify_signature_against_pubkey(
            &canonical_bytes,
            &genesis.self_signed_by_genesis_key,
            sk.verifying_key(),
        );
        assert!(ok, "genesis signature MUST verify against the signing key");
    }

    #[test]
    fn sign_genesis_roster_signature_decodes_to_64_bytes() {
        let (_sk, signer) = make_signer("genesis-test", "dev-laptop");
        let genesis = sign_genesis_roster(
            "did:mata:abc123".to_string(),
            "dev-laptop",
            "zFakeMultibase".to_string(),
            1_700_000_000,
            &signer,
        );
        let decoded = URL_SAFE_NO_PAD
            .decode(&genesis.self_signed_by_genesis_key)
            .expect("base64url decode");
        assert_eq!(decoded.len(), 64, "ES256 signature is exactly 64 bytes (r || s)");
    }

    #[test]
    fn sign_genesis_roster_signature_fails_against_wrong_key() {
        let (_sk_genesis, signer) = make_signer("genesis-test", "dev-laptop");
        let (sk_other, _) = make_signer("other-test", "dev-other");

        let genesis = sign_genesis_roster(
            "did:mata:abc123".to_string(),
            "dev-laptop",
            "zFakeMultibase".to_string(),
            1_700_000_000,
            &signer,
        );

        let canonical_bytes = canonical::genesis_canonical_bytes(&genesis);
        let ok = verify_signature_against_pubkey(
            &canonical_bytes,
            &genesis.self_signed_by_genesis_key,
            sk_other.verifying_key(),
        );
        assert!(!ok, "signature MUST NOT verify against an unrelated key");
    }

    #[test]
    fn sign_genesis_unsigned_fields_are_deterministic() {
        // Same inputs → same unsigned-portion (everything except the
        // signature itself; ECDSA produces a fresh random nonce each call).
        let (_sk, signer1) = make_signer("genesis-test", "dev-laptop");
        let (_sk, signer2) = make_signer("genesis-test", "dev-laptop");

        let g1 = sign_genesis_roster(
            "did:mata:abc123".to_string(),
            "dev-laptop",
            "zFakeMultibase".to_string(),
            1_700_000_000,
            &signer1,
        );
        let g2 = sign_genesis_roster(
            "did:mata:abc123".to_string(),
            "dev-laptop",
            "zFakeMultibase".to_string(),
            1_700_000_000,
            &signer2,
        );

        assert_eq!(g1.version, g2.version);
        assert_eq!(g1.did, g2.did);
        assert_eq!(g1.verification_methods, g2.verification_methods);
        assert_eq!(g1.signed_at, g2.signed_at);
        // Both signatures must verify against the same pubkey even
        // though they may differ byte-for-byte (random ECDSA nonce).
        let bytes = canonical::genesis_canonical_bytes(&g1);
        let pk_bytes = SigningKey::from_bytes(
            &Sha256::digest(b"genesis-test-mid-bootstrap-test-seed").into(),
        )
        .unwrap();
        assert!(verify_signature_against_pubkey(
            &bytes,
            &g1.self_signed_by_genesis_key,
            pk_bytes.verifying_key()
        ));
        assert!(verify_signature_against_pubkey(
            &bytes,
            &g2.self_signed_by_genesis_key,
            pk_bytes.verifying_key()
        ));
    }

    // ─── sign_roster_chain_entry ───────────────────────────────────────────

    #[test]
    fn sign_chain_entry_produces_well_formed_envelope() {
        let (_sk, signer) = make_signer("genesis-test", "dev-laptop");

        let new_vm_phone = VerificationMethod {
            id: "did:mata:abc123#dev-phone".to_string(),
            vm_type: VM_TYPE_ECDSA_P256.to_string(),
            controller: "did:mata:abc123".to_string(),
            public_key_multibase: "zPhoneKey".to_string(),
        };
        let genesis_vm = VerificationMethod {
            id: "did:mata:abc123#dev-laptop".to_string(),
            vm_type: VM_TYPE_ECDSA_P256.to_string(),
            controller: "did:mata:abc123".to_string(),
            public_key_multibase: "zFakeMultibase".to_string(),
        };

        let entry = sign_roster_chain_entry(
            "did:mata:abc123".to_string(),
            2,
            vec![genesis_vm, new_vm_phone],
            "dev-laptop".to_string(),
            1_710_000_000,
            &signer,
        );

        assert_eq!(entry.version, 2);
        assert_eq!(entry.did, "did:mata:abc123");
        assert_eq!(entry.verification_methods.len(), 2);
        assert_eq!(entry.signer_kid, "dev-laptop");
        assert_eq!(entry.signed_at, 1_710_000_000);
        assert!(!entry.signed_by_signer_in_prior_roster.is_empty());
    }

    #[test]
    fn sign_chain_entry_signature_verifies_against_signer_key() {
        let (sk, signer) = make_signer("genesis-test", "dev-laptop");

        let vm = VerificationMethod {
            id: "did:mata:abc123#dev-laptop".to_string(),
            vm_type: VM_TYPE_ECDSA_P256.to_string(),
            controller: "did:mata:abc123".to_string(),
            public_key_multibase: "zFakeMultibase".to_string(),
        };

        let entry = sign_roster_chain_entry(
            "did:mata:abc123".to_string(),
            2,
            vec![vm],
            "dev-laptop".to_string(),
            1_710_000_000,
            &signer,
        );

        let canonical_bytes = canonical::chain_entry_canonical_bytes(&entry);
        let ok = verify_signature_against_pubkey(
            &canonical_bytes,
            &entry.signed_by_signer_in_prior_roster,
            sk.verifying_key(),
        );
        assert!(ok, "chain entry signature MUST verify against the signer's key");
    }

    #[test]
    fn sign_chain_entry_signer_kid_is_bound_to_signature() {
        // Confirms `signer_kid` is included in canonical bytes — changing
        // it post-signing invalidates the signature.
        let (sk, signer) = make_signer("genesis-test", "dev-laptop");

        let vm = VerificationMethod {
            id: "did:mata:abc123#dev-laptop".to_string(),
            vm_type: VM_TYPE_ECDSA_P256.to_string(),
            controller: "did:mata:abc123".to_string(),
            public_key_multibase: "zFakeMultibase".to_string(),
        };

        let mut entry = sign_roster_chain_entry(
            "did:mata:abc123".to_string(),
            2,
            vec![vm],
            "dev-laptop".to_string(),
            1_710_000_000,
            &signer,
        );

        // Tamper signer_kid.
        entry.signer_kid = "ghost-device".into();

        let canonical_bytes = canonical::chain_entry_canonical_bytes(&entry);
        let ok = verify_signature_against_pubkey(
            &canonical_bytes,
            &entry.signed_by_signer_in_prior_roster,
            sk.verifying_key(),
        );
        assert!(!ok, "tampered signer_kid MUST invalidate the signature");
    }
}
