//! Prints a real IAMHUMAN **username-claim** token: the username signed under
//! `context = "iamhuman-username-claim"`, by the same deterministic identity as
//! `print_token` (so the claim and the proof share a DID). Use it to exercise
//! `POST /v1/username/claim` on `iamhuman-host`.
//!
//! Run: `cargo run -p mata-sign --example print_claim_token [username]`
//! (default username: `farmer_timmm`).

use std::collections::BTreeMap;
use std::env;

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
    let username = env::args().nth(1).unwrap_or_else(|| "farmer_timmm".to_string());

    // Same deterministic genesis key as print_token → same stable DID.
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

    // The signed content IS the username — binds the signature to this exact
    // handle so a claim token can't be replayed for a different username.
    let input = StatementInput {
        content: mata_sign::Content::Bytes(username.as_bytes()),
        content_type: "text/plain".into(),
        context: Some("iamhuman-username-claim".into()),
        nonce: None,
        exp: None,
        preview: Some(username.clone()),
        platform_binding: None,
    };
    let token = sign_statement(&input, &snapshot, &signer, 1_716_700_000).unwrap();

    println!("DID:        {did}");
    println!("USERNAME:   {username}");
    println!("CLAIM_TOKEN:{token}");
}
