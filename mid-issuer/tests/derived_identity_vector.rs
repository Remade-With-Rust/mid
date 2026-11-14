//! The derived-identity vector, from the issuer's side: given the root scalar,
//! DID and multibase the vector records, `sign_genesis_roster` at the frozen
//! epoch must produce the genesis whose canonical SHA-256 the vector records.
//! That hash is what every relying party anchors on, so this test is the line
//! between "the same person on every device" and a `GenesisMismatch`.
//!
//! The vector lives in `mata-identity` (which owns the derivation); this crate
//! reads the same file so the two sides cannot drift apart unnoticed.

use kms_client::InMemoryDeviceSigner;
use mid_issuer::bootstrap::sign_genesis_roster;
use mid_issuer::canonical::genesis_canonical_bytes;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

const VECTOR: &str = include_str!("../../mata-identity/tests/vectors/derived_identity_v1.json");

fn vector() -> serde_json::Value {
    serde_json::from_str(VECTOR).expect("derived_identity_v1.json parses")
}

fn signer_from_vector(
    v: &serde_json::Value,
) -> (InMemoryDeviceSigner, String, String, &'static str, u64) {
    let scalar_vec = hex::decode(v["root_private_scalar_hex"].as_str().unwrap()).unwrap();
    let scalar: [u8; 32] = scalar_vec.try_into().expect("32-byte scalar");
    let sk = SigningKey::from_bytes((&scalar).into()).expect("scalar on the curve");
    let did = v["did"].as_str().unwrap().to_string();
    let multibase = v["public_key_multibase"].as_str().unwrap().to_string();
    let kid: &'static str = Box::leak(
        v["genesis"]["device_kid"]
            .as_str()
            .unwrap()
            .to_string()
            .into_boxed_str(),
    );
    let epoch = v["genesis"]["signed_at"].as_u64().unwrap();
    (
        InMemoryDeviceSigner::new(kid, sk),
        did,
        multibase,
        kid,
        epoch,
    )
}

#[test]
fn derived_genesis_hash_matches_vector_v1() {
    let v = vector();
    let (signer, did, multibase, kid, epoch) = signer_from_vector(&v);

    let genesis = sign_genesis_roster(did.clone(), kid, multibase.clone(), epoch, &signer);

    assert_eq!(genesis.version, 1);
    assert_eq!(genesis.did, did);
    assert_eq!(genesis.signed_at, epoch);
    assert_eq!(genesis.verification_methods.len(), 1);
    let vm = &genesis.verification_methods[0];
    assert_eq!(vm.id, format!("{did}#{kid}"));
    assert_eq!(vm.controller, did);
    assert_eq!(vm.public_key_multibase, multibase);

    let hash = hex::encode(Sha256::digest(genesis_canonical_bytes(&genesis)));
    assert_eq!(
        hash,
        v["genesis"]["canonical_sha256_hex"].as_str().unwrap(),
        "genesis canonical hash moved: every relying-party anchor would break"
    );
}

#[test]
fn derived_genesis_hash_ignores_signature_randomness() {
    // Two independent signings of the same derived genesis must hash the same:
    // the canonical bytes exclude the signature field. This is what lets every
    // device compute the anchor without exchanging a single byte.
    let v = vector();
    let (signer, did, multibase, kid, epoch) = signer_from_vector(&v);
    let a = sign_genesis_roster(did.clone(), kid, multibase.clone(), epoch, &signer);
    let b = sign_genesis_roster(did, kid, multibase, epoch, &signer);
    assert_eq!(genesis_canonical_bytes(&a), genesis_canonical_bytes(&b));
}

#[test]
fn a_different_epoch_is_a_different_anchor() {
    // Documents the trap the derivation retires: `signed_at` is inside the
    // canonical bytes, so a per-device timestamp yields a per-device anchor.
    let v = vector();
    let (signer, did, multibase, kid, epoch) = signer_from_vector(&v);
    let frozen = sign_genesis_roster(did.clone(), kid, multibase.clone(), epoch, &signer);
    let drifted = sign_genesis_roster(did, kid, multibase, epoch + 1, &signer);
    assert_ne!(
        genesis_canonical_bytes(&frozen),
        genesis_canonical_bytes(&drifted)
    );
}
