//! Prints a real `mata-sign` token + its content to stdout, for use as a
//! cross-implementation conformance fixture in the JS verifier's test suite.
//!
//! Run: `cargo run -p mata-sign --example print_token`
//!
//! The genesis key is seed-derived, so the DID is stable across runs; the
//! ECDSA signatures vary per run (random k) but any captured token stays valid
//! forever, so the printed token can be pasted into a JS test as a fixture.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use kms_client::InMemoryDeviceSigner;
use mid_issuer::{
    EmbeddedGenesisRoster, EmbeddedVerificationMethod, IdentitySnapshot, VerificationMethod,
};
use mid_verify::keys::{did_from_pubkey, multibase_from_pubkey};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use mata_sign::{sign_statement, StatementInput};

fn main() {
    // Deterministic genesis key → stable DID.
    let mut h = Sha256::new();
    h.update(b"alice");
    h.update(b"-mata-sign-test-seed");
    let seed: [u8; 32] = h.finalize().into();
    let key = SigningKey::from_bytes(&seed.into()).unwrap();
    let did = did_from_pubkey(key.verifying_key());
    let vm_id = format!("{did}#laptop");

    let vm = VerificationMethod {
        id: vm_id.clone(),
        vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
        controller: did.clone(),
        public_key_multibase: multibase_from_pubkey(key.verifying_key()),
    };
    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did: did.clone(),
        verification_methods: vec![vm],
        signed_at: 1_700_000_000,
        self_signed_by_genesis_key: String::new(),
    };
    // Self-sign the genesis roster.
    let canonical = mid_issuer::canonical::genesis_canonical_bytes(&genesis);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    let sig: Signature = key.sign_prehash(&prehash).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    genesis.self_signed_by_genesis_key = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let snapshot = IdentitySnapshot {
        did: did.clone(),
        genesis_roster: genesis,
        roster_chain: vec![],
        current_verification_method: EmbeddedVerificationMethod {
            id: vm_id,
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did.clone(),
            public_key_multibase: multibase_from_pubkey(key.verifying_key()),
        },
        approved_claims: BTreeMap::new(),
    };
    let signer = InMemoryDeviceSigner::new("laptop", key);

    let content = "I am a real human. — signed via MATA";
    let input = StatementInput {
        content: mata_sign::Content::Bytes(content.as_bytes()),
        content_type: "text/plain".into(),
        context: Some("iamhuman".into()),
        nonce: None,
        exp: None,
        preview: Some(content.into()),
    };
    let token = sign_statement(&input, &snapshot, &signer, 1_716_700_000).unwrap();

    println!("DID:     {did}");
    println!("CONTENT: {content}");
    println!("TOKEN:   {token}");
}
