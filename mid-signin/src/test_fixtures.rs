//! Test-only fixture builders that mint REAL mID JWTs through `mid-issuer`
//! and `kms-client`'s in-memory device signer — the same pattern
//! `mid-verify`'s own test suite uses, so every test in this crate exercises
//! the genuine end-to-end artifact rather than a mock.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use kms_client::DeviceSigner;
use mid_issuer::{
    build_mid_jwt, AttestedBy, ClaimRequest, ClaimValue, EmbeddedGenesisRoster,
    EmbeddedRosterChainEntry, EmbeddedVerificationMethod, IdentitySnapshot, RpRequest,
    VerificationMethod,
};
use mid_verify::keys;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// Build a deterministic signing key from a seed string.
pub fn make_signing_key(seed: &str) -> SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(b"-mid-signin-test-seed");
    let bytes: [u8; 32] = hasher.finalize().into();
    SigningKey::from_bytes(&bytes.into()).unwrap()
}

/// A single device's key material; the DID it serves is owned by
/// [`IdentityFixture`].
pub struct DeviceKey {
    pub device_id: String,
    pub signing_key: SigningKey,
}

impl DeviceKey {
    pub fn new(seed: &str, device_id: &str) -> Self {
        Self {
            device_id: device_id.into(),
            signing_key: make_signing_key(seed),
        }
    }
}

/// A test identity centered on a genesis device.
pub struct IdentityFixture {
    pub genesis: DeviceKey,
}

impl IdentityFixture {
    pub fn new(genesis_seed: &str, genesis_device_id: &str) -> Self {
        Self {
            genesis: DeviceKey::new(genesis_seed, genesis_device_id),
        }
    }

    /// The DID derived from the genesis key.
    pub fn did(&self) -> String {
        keys::did_from_pubkey(self.genesis.signing_key.verifying_key())
    }

    pub fn vm_for(&self, device: &DeviceKey) -> VerificationMethod {
        let did = self.did();
        VerificationMethod {
            id: format!("{did}#{}", device.device_id),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did,
            public_key_multibase: keys::multibase_from_pubkey(device.signing_key.verifying_key()),
        }
    }

    pub fn embedded_vm_for(&self, device: &DeviceKey) -> EmbeddedVerificationMethod {
        let did = self.did();
        EmbeddedVerificationMethod {
            id: format!("{did}#{}", device.device_id),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did,
            public_key_multibase: keys::multibase_from_pubkey(device.signing_key.verifying_key()),
        }
    }
}

pub fn sign_genesis(roster: &EmbeddedGenesisRoster, signing_key: &SigningKey) -> String {
    let canonical = mid_issuer::canonical::genesis_canonical_bytes(roster);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    let sig: Signature = signing_key.sign_prehash(&prehash).unwrap();
    let normalized = sig.normalize_s().unwrap_or(sig);
    URL_SAFE_NO_PAD.encode(normalized.to_bytes())
}

pub fn sign_chain_entry(entry: &EmbeddedRosterChainEntry, signing_key: &SigningKey) -> String {
    let canonical = mid_issuer::canonical::chain_entry_canonical_bytes(entry);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    let sig: Signature = signing_key.sign_prehash(&prehash).unwrap();
    let normalized = sig.normalize_s().unwrap_or(sig);
    URL_SAFE_NO_PAD.encode(normalized.to_bytes())
}

/// A single-device identity snapshot (genesis only, roster version 1).
pub fn fresh_identity(identity: &IdentityFixture) -> IdentitySnapshot {
    let genesis_vm = identity.vm_for(&identity.genesis);
    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did: identity.did(),
        verification_methods: vec![genesis_vm],
        signed_at: 1_700_000_000,
        self_signed_by_genesis_key: String::new(),
    };
    genesis.self_signed_by_genesis_key = sign_genesis(&genesis, &identity.genesis.signing_key);

    let mut approved = BTreeMap::new();
    approved.insert(
        "did".into(),
        ClaimValue {
            value: serde_json::Value::String(identity.did()),
            attested_by: AttestedBy::SelfAttested,
            verified_at_signup: None,
            computed_at: None,
            formula_version: None,
        },
    );

    IdentitySnapshot {
        did: identity.did(),
        genesis_roster: genesis,
        roster_chain: vec![],
        current_verification_method: identity.embedded_vm_for(&identity.genesis),
        approved_claims: approved,
    }
}

/// A two-device identity snapshot: genesis + one chain entry (version 2)
/// adding `new_device`, signed by the genesis key.
pub fn two_device_identity(identity: &IdentityFixture, new_device: &DeviceKey) -> IdentitySnapshot {
    let mut base = fresh_identity(identity);

    let mut chain_entry = EmbeddedRosterChainEntry {
        version: 2,
        did: identity.did(),
        verification_methods: vec![identity.vm_for(&identity.genesis), identity.vm_for(new_device)],
        signed_at: 1_710_000_000,
        signed_by_signer_in_prior_roster: String::new(),
        signer_kid: identity.genesis.device_id.clone(),
    };
    chain_entry.signed_by_signer_in_prior_roster =
        sign_chain_entry(&chain_entry, &identity.genesis.signing_key);

    base.roster_chain.push(chain_entry);
    base.current_verification_method = identity.embedded_vm_for(new_device);
    base
}

/// Sign and emit a JWT against the given snapshot.
pub fn mint_jwt(
    snapshot: &IdentitySnapshot,
    signer: &dyn DeviceSigner,
    rp_origin: &str,
    nonce: &str,
    iat: u64,
) -> String {
    let req = RpRequest {
        rp_origin: rp_origin.into(),
        nonce: nonce.into(),
        claims: ClaimRequest {
            required: vec!["did".into()],
            optional: vec![],
            custom: BTreeMap::new(),
        },
    };
    build_mid_jwt(&req, snapshot, signer, iat).expect("mint JWT")
}
