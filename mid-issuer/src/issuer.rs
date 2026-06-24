//! The main `build_mid_jwt` orchestrator.
//!
//! Per ADR 0005 Decision 1, this function:
//!
//! 1. Validates the [`IdentitySnapshot`] is internally consistent (signer's
//!    VM is in head roster, DIDs match).
//! 2. Validates all `required` claims in the request are present in the
//!    approved-claims map.
//! 3. Assembles the [`MidJwtPayload`] from the snapshot + request.
//! 4. JSON-serializes the payload.
//! 5. Hands off to [`crate::jws::build_jws_compact`] for ES256 signing.
//!
//! ## Determinism
//!
//! Given the same inputs (including `iat` — which is the only
//! caller-supplied wall-clock value), this function produces a
//! byte-identical JWT. `BTreeMap` for the claims map and `serde_json`'s
//! stable struct ordering give us deterministic JSON. Round-trip tests in
//! `tests/` lean on this.

use crate::error::MidIssuerError;
use crate::jws::build_jws_compact;
use crate::types::{IdentitySnapshot, MidJwtPayload, RpRequest};
use kms_client::DeviceSigner;

/// Default token lifetime — 1 hour. RPs that want longer-lived sessions
/// handle their own session-cookie issuance after first verify; mID
/// short-lifetime is the v1 stance.
const DEFAULT_TOKEN_LIFETIME_SECS: u64 = 3600;

/// Build a signed mID JWT.
///
/// `iat` is supplied by the caller (the wallet reads the wall clock once,
/// passes it in) so this function stays pure-functional and testable. `exp`
/// is computed as `iat + DEFAULT_TOKEN_LIFETIME_SECS`.
///
/// The caller is responsible for:
///
/// - Filtering [`IdentitySnapshot::approved_claims`] to only the keys the
///   user actually consented to disclose (no over-disclosure).
/// - Confirming `request.rp_origin` matches the actual calling page's
///   origin (the extension does this via `sender.tab.url`; the native app
///   does this via the verified Universal Link / App Link payload).
/// - Providing a `signer` whose `device_id` corresponds to
///   `snapshot.current_verification_method`.
///
/// Returns the JWS compact-form token string ready to deliver to the RP
/// page (via `postMessage` for the extension, OS callback URL for the
/// native app).
pub fn build_mid_jwt(
    request: &RpRequest,
    snapshot: &IdentitySnapshot,
    signer: &dyn DeviceSigner,
    iat: u64,
) -> Result<String, MidIssuerError> {
    // ─── Validate the snapshot is internally consistent ───────────────────

    if snapshot.current_verification_method.controller != snapshot.did {
        return Err(MidIssuerError::DidVmMismatch {
            snapshot_did: snapshot.did.clone(),
            vm_controller: snapshot.current_verification_method.controller.clone(),
        });
    }

    let head_vms = head_roster_verification_method_ids(snapshot);
    if !head_vms
        .iter()
        .any(|id| id == &snapshot.current_verification_method.id)
    {
        return Err(MidIssuerError::SignerNotInHeadRoster(
            snapshot.current_verification_method.id.clone(),
        ));
    }

    // ─── Validate required claims are present ────────────────────────────

    for required in &request.claims.required {
        if !snapshot.approved_claims.contains_key(required) {
            return Err(MidIssuerError::RequiredClaimMissing(required.clone()));
        }
    }

    // ─── Compute exp ─────────────────────────────────────────────────────

    let exp = iat
        .checked_add(DEFAULT_TOKEN_LIFETIME_SECS)
        .ok_or(MidIssuerError::InvalidTokenLifetime {
            iat,
            exp: u64::MAX,
        })?;
    if exp <= iat {
        // Unreachable given the checked_add above, but defense in depth.
        return Err(MidIssuerError::InvalidTokenLifetime { iat, exp });
    }

    // ─── Assemble the payload ────────────────────────────────────────────

    let payload = MidJwtPayload {
        iss: snapshot.did.clone(),
        sub: snapshot.did.clone(),
        aud: request.rp_origin.clone(),
        iat,
        exp,
        nonce: request.nonce.clone(),
        claims: snapshot.approved_claims.clone(),
        embedded_genesis_roster: snapshot.genesis_roster.clone(),
        embedded_roster_chain: snapshot.roster_chain.clone(),
        embedded_verification_method: snapshot.current_verification_method.clone(),
    };

    let payload_json = serde_json::to_vec(&payload)?;

    // ─── Sign and return ─────────────────────────────────────────────────

    build_jws_compact(&payload_json, signer)
}

/// Return the verification-method IDs in the head roster of the chain.
/// If the chain is empty, the head is the genesis roster.
fn head_roster_verification_method_ids(snapshot: &IdentitySnapshot) -> Vec<String> {
    match snapshot.roster_chain.last() {
        Some(head) => head.verification_methods.iter().map(|vm| vm.id.clone()).collect(),
        None => snapshot
            .genesis_roster
            .verification_methods
            .iter()
            .map(|vm| vm.id.clone())
            .collect(),
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AttestedBy, ClaimRequest, ClaimValue, EmbeddedGenesisRoster, EmbeddedVerificationMethod,
        VerificationMethod,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use kms_client::InMemoryDeviceSigner;
    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    /// Deterministic test signer (see jws::tests::make_test_signer).
    fn make_test_signer(device_id: &str) -> InMemoryDeviceSigner {
        let mut hasher = Sha256::new();
        hasher.update(device_id.as_bytes());
        hasher.update(b"-mid-issuer-test-seed");
        let seed: [u8; 32] = hasher.finalize().into();
        let signing_key = SigningKey::from_bytes(&seed.into()).expect("non-zero test seed");
        InMemoryDeviceSigner::new(device_id, signing_key)
    }

    fn fixture_snapshot(device_id: &str) -> IdentitySnapshot {
        let did = "did:mata:abc123".to_string();
        let vm_id = format!("{did}#{device_id}");
        let vm = EmbeddedVerificationMethod {
            id: vm_id.clone(),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did.clone(),
            public_key_multibase: "z6MkFake".into(),
        };
        IdentitySnapshot {
            did: did.clone(),
            genesis_roster: EmbeddedGenesisRoster {
                version: 1,
                did: did.clone(),
                verification_methods: vec![VerificationMethod {
                    id: vm_id.clone(),
                    vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
                    controller: did,
                    public_key_multibase: "z6MkFake".into(),
                }],
                signed_at: 1_700_000_000,
                self_signed_by_genesis_key: "AAAA".into(),
            },
            roster_chain: vec![],
            current_verification_method: vm,
            approved_claims: BTreeMap::new(),
        }
    }

    fn fixture_request(required: Vec<&str>) -> RpRequest {
        RpRequest {
            rp_origin: "https://acme.com".into(),
            nonce: "nonce-abc".into(),
            claims: ClaimRequest {
                required: required.into_iter().map(String::from).collect(),
                optional: vec![],
                custom: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn happy_path_produces_three_segment_jws() {
        let signer = make_test_signer("dev-laptop");
        let mut snapshot = fixture_snapshot("dev-laptop");
        snapshot.approved_claims.insert(
            "did".into(),
            ClaimValue {
                value: serde_json::Value::String(snapshot.did.clone()),
                attested_by: AttestedBy::SelfAttested,
                verified_at_signup: None,
                computed_at: None,
                formula_version: None,
            },
        );
        let request = fixture_request(vec!["did"]);

        let jwt = build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000).unwrap();
        assert_eq!(jwt.matches('.').count(), 2);
    }

    #[test]
    fn missing_required_claim_errors() {
        let signer = make_test_signer("dev-laptop");
        let snapshot = fixture_snapshot("dev-laptop");
        let request = fixture_request(vec!["did"]); // required but approved_claims is empty

        match build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000) {
            Err(MidIssuerError::RequiredClaimMissing(c)) => assert_eq!(c, "did"),
            other => panic!("expected RequiredClaimMissing, got {other:?}"),
        }
    }

    #[test]
    fn signer_not_in_head_roster_errors() {
        let signer = make_test_signer("dev-laptop");
        // Snapshot's VM is "dev-laptop" — but we'll mutate it to claim a
        // different device that isn't in the genesis roster.
        let mut snapshot = fixture_snapshot("dev-laptop");
        snapshot.current_verification_method.id = "did:mata:abc123#some-revoked-device".into();
        let mut request = fixture_request(vec!["did"]);
        request.claims.required = vec![]; // skip required-claim check to isolate this failure

        match build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000) {
            Err(MidIssuerError::SignerNotInHeadRoster(id)) => {
                assert_eq!(id, "did:mata:abc123#some-revoked-device")
            }
            other => panic!("expected SignerNotInHeadRoster, got {other:?}"),
        }
    }

    #[test]
    fn did_vm_mismatch_errors() {
        let signer = make_test_signer("dev-laptop");
        let mut snapshot = fixture_snapshot("dev-laptop");
        snapshot.current_verification_method.controller = "did:mata:different".into();
        let request = fixture_request(vec![]);

        match build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000) {
            Err(MidIssuerError::DidVmMismatch { .. }) => {}
            other => panic!("expected DidVmMismatch, got {other:?}"),
        }
    }

    #[test]
    fn jwt_payload_segment_decodes_to_expected_claims() {
        let signer = make_test_signer("dev-laptop");
        let mut snapshot = fixture_snapshot("dev-laptop");
        snapshot.approved_claims.insert(
            "did".into(),
            ClaimValue {
                value: serde_json::Value::String(snapshot.did.clone()),
                attested_by: AttestedBy::SelfAttested,
                verified_at_signup: None,
                computed_at: None,
                formula_version: None,
            },
        );
        let request = fixture_request(vec!["did"]);

        let jwt = build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000).unwrap();
        let payload_segment = jwt.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_segment).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(payload["iss"], "did:mata:abc123");
        assert_eq!(payload["sub"], "did:mata:abc123");
        assert_eq!(payload["aud"], "https://acme.com");
        assert_eq!(payload["iat"], 1_716_700_000);
        assert_eq!(payload["exp"], 1_716_700_000 + DEFAULT_TOKEN_LIFETIME_SECS);
        assert_eq!(payload["nonce"], "nonce-abc");
        assert_eq!(payload["claims"]["did"]["attested_by"], "self");
    }

    #[test]
    fn determinism_same_iat_produces_byte_identical_jwt() {
        // ECDSA is non-deterministic by default (random k), so signatures
        // CAN differ across calls — but the unsigned segments (header,
        // payload) MUST be byte-identical for the same inputs. This is the
        // property we lean on for snapshot tests.
        let signer = make_test_signer("dev-laptop");
        let mut snapshot = fixture_snapshot("dev-laptop");
        snapshot.approved_claims.insert(
            "did".into(),
            ClaimValue {
                value: serde_json::Value::String(snapshot.did.clone()),
                attested_by: AttestedBy::SelfAttested,
                verified_at_signup: None,
                computed_at: None,
                formula_version: None,
            },
        );
        let request = fixture_request(vec!["did"]);

        let jwt_a = build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000).unwrap();
        let jwt_b = build_mid_jwt(&request, &snapshot, &signer, 1_716_700_000).unwrap();

        // First two segments (header and payload) MUST match — they're pure
        // functions of the inputs.
        let (head_a, _sig_a): (Vec<&str>, &str) = {
            let mut parts: Vec<&str> = jwt_a.split('.').collect();
            let sig = parts.pop().unwrap();
            (parts, sig)
        };
        let (head_b, _sig_b): (Vec<&str>, &str) = {
            let mut parts: Vec<&str> = jwt_b.split('.').collect();
            let sig = parts.pop().unwrap();
            (parts, sig)
        };
        assert_eq!(head_a, head_b, "header + payload segments must be byte-identical");
    }
}
