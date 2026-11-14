//! The derived-identity vector, end to end: a JWT minted on the derived root
//! must pass the four checks, and what the relying party sees — the DID and the
//! genesis hash it anchors on — must be exactly what the vector records.
//!
//! This is the test that says "a person who signs in from any device that holds
//! the vault key is the same person to every relying party". The vector lives in
//! `mata-identity`; this crate reads the same file.

use std::collections::BTreeMap;

use kms_client::InMemoryDeviceSigner;
use mid_issuer::bootstrap::sign_genesis_roster;
use mid_issuer::{
    build_mid_jwt, AttestedBy, ClaimRequest, ClaimValue, EmbeddedVerificationMethod,
    IdentitySnapshot, RpRequest,
};
use mid_verify::{keys, verify_mid_response, VerifyConfig};
use p256::ecdsa::SigningKey;

const VECTOR: &str = include_str!("../../mata-identity/tests/vectors/derived_identity_v1.json");

struct Vector {
    scalar: [u8; 32],
    did: String,
    multibase: String,
    kid: String,
    epoch: u64,
    genesis_hash_hex: String,
}

fn vector() -> Vector {
    let v: serde_json::Value =
        serde_json::from_str(VECTOR).expect("derived_identity_v1.json parses");
    let scalar_vec = hex::decode(v["root_private_scalar_hex"].as_str().unwrap()).unwrap();
    Vector {
        scalar: scalar_vec.try_into().expect("32-byte scalar"),
        did: v["did"].as_str().unwrap().to_string(),
        multibase: v["public_key_multibase"].as_str().unwrap().to_string(),
        kid: v["genesis"]["device_kid"].as_str().unwrap().to_string(),
        epoch: v["genesis"]["signed_at"].as_u64().unwrap(),
        genesis_hash_hex: v["genesis"]["canonical_sha256_hex"]
            .as_str()
            .unwrap()
            .to_string(),
    }
}

fn snapshot_and_signer(v: &Vector) -> (IdentitySnapshot, InMemoryDeviceSigner) {
    let sk = SigningKey::from_bytes((&v.scalar).into()).expect("scalar on the curve");
    let signer = InMemoryDeviceSigner::new(v.kid.clone(), sk);
    let genesis = sign_genesis_roster(v.did.clone(), &v.kid, v.multibase.clone(), v.epoch, &signer);

    let mut approved = BTreeMap::new();
    approved.insert(
        "did".to_string(),
        ClaimValue {
            value: serde_json::Value::String(v.did.clone()),
            attested_by: AttestedBy::SelfAttested,
            verified_at_signup: None,
            computed_at: None,
            formula_version: None,
        },
    );

    let snapshot = IdentitySnapshot {
        did: v.did.clone(),
        genesis_roster: genesis,
        roster_chain: vec![],
        current_verification_method: EmbeddedVerificationMethod {
            id: format!("{}#{}", v.did, v.kid),
            vm_type: "EcdsaSecp256r1VerificationKey2019".to_string(),
            controller: v.did.clone(),
            public_key_multibase: v.multibase.clone(),
        },
        approved_claims: approved,
    };
    (snapshot, signer)
}

#[test]
fn derived_identity_encodings_match_the_verifier() {
    // The DID and multibase the wallet derives must be what this crate would
    // compute from the same key. If these ever disagree, every sign-in fails
    // at check 1 (genesis self-signature against the key decoded from the DID).
    let v = vector();
    let sk = SigningKey::from_bytes((&v.scalar).into()).unwrap();
    assert_eq!(keys::did_from_pubkey(sk.verifying_key()), v.did);
    assert_eq!(keys::multibase_from_pubkey(sk.verifying_key()), v.multibase);
    assert!(
        keys::pubkey_from_did(&v.did).is_ok(),
        "DID must decode back to a P-256 key"
    );
}

#[test]
fn jwt_minted_on_the_derived_identity_verifies_and_anchors_on_the_vector_hash() {
    let v = vector();
    let (snapshot, signer) = snapshot_and_signer(&v);

    let req = RpRequest {
        rp_origin: "https://acme.com".to_string(),
        nonce: "nonce-derived-v1".to_string(),
        claims: ClaimRequest {
            required: vec!["did".to_string()],
            optional: vec![],
            custom: BTreeMap::new(),
        },
    };
    let iat = 1_759_190_400 + 60;
    let jwt =
        build_mid_jwt(&req, &snapshot, &signer, iat).expect("mint JWT on the derived identity");

    let config = VerifyConfig {
        expected_audience: "https://acme.com".to_string(),
        expected_nonce: "nonce-derived-v1".to_string(),
        max_iat_skew_secs: 120,
        now_unix_secs: iat + 5,
    };
    let verified = verify_mid_response(&jwt, &config).expect("the four checks pass");

    assert_eq!(verified.did, v.did);
    assert_eq!(verified.current_version, 1);
    assert_eq!(
        hex::encode(verified.genesis_roster_hash),
        v.genesis_hash_hex,
        "the anchor a relying party records must be the vector's genesis hash"
    );
}

#[test]
fn two_independent_mints_present_the_same_anchor() {
    // Two devices that each derive the identity and sign their own genesis
    // (different ECDSA randomness, same canonical bytes) must be anchored
    // identically by a relying party. This is the property the whole plan
    // rests on; it holds because the hash excludes the signature field.
    let v = vector();
    let (snap_a, signer_a) = snapshot_and_signer(&v);
    let (snap_b, signer_b) = snapshot_and_signer(&v);
    let req = RpRequest {
        rp_origin: "https://acme.com".to_string(),
        nonce: "n".to_string(),
        claims: ClaimRequest {
            required: vec!["did".to_string()],
            optional: vec![],
            custom: BTreeMap::new(),
        },
    };
    let iat = 1_759_190_400 + 60;
    let config = VerifyConfig {
        expected_audience: "https://acme.com".to_string(),
        expected_nonce: "n".to_string(),
        max_iat_skew_secs: 120,
        now_unix_secs: iat + 5,
    };
    let a = verify_mid_response(
        &build_mid_jwt(&req, &snap_a, &signer_a, iat).unwrap(),
        &config,
    )
    .unwrap();
    let b = verify_mid_response(
        &build_mid_jwt(&req, &snap_b, &signer_b, iat).unwrap(),
        &config,
    )
    .unwrap();
    assert_eq!(a.genesis_roster_hash, b.genesis_roster_hash);
    assert_eq!(a.did, b.did);
}
