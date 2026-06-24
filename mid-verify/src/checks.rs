//! The four cryptographic checks per ADR 0005 Decision 1.
//!
//! Each check is a pure function isolated from the others — easier to
//! reason about, easier to test in isolation. The orchestrator in
//! [`crate::verify`] runs them in order; if any fails, verification
//! short-circuits.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mid_issuer::canonical;
use mid_issuer::{EmbeddedRosterChainEntry, MidJwtPayload, VerificationMethod};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use crate::error::VerifyError;
use crate::keys::{pubkey_from_did, pubkey_from_multibase};

/// Decode a base64url-encoded ECDSA P-256 signature into the
/// `p256::ecdsa::Signature` type used by `verify_prehash`.
fn decode_signature(b64: &str) -> Result<Signature, VerifyError> {
    let bytes = URL_SAFE_NO_PAD.decode(b64).map_err(|source| VerifyError::Base64Decode {
        segment: "signature",
        source,
    })?;
    if bytes.len() != 64 {
        return Err(VerifyError::SignatureWrongLength { actual: bytes.len() });
    }
    Signature::from_slice(&bytes).map_err(|_| VerifyError::SignatureWrongLength { actual: bytes.len() })
}

/// **Check 1.** Verify the genesis roster's self-signature against the
/// public key recoverable from the DID. Proves "this genesis roster was
/// authored by the holder of the genesis key" — and the genesis key is
/// recoverable from the DID itself, so this is a fully self-contained
/// check (no MATA dependency).
pub fn check_genesis_self_signature(payload: &MidJwtPayload) -> Result<(), VerifyError> {
    // The DID's iss claim encodes the genesis pubkey.
    let genesis_pubkey = pubkey_from_did(&payload.iss)?;

    // The signed bytes are the domain-separated canonical form (excludes
    // the signature field itself).
    let canonical_bytes = canonical::genesis_canonical_bytes(&payload.embedded_genesis_roster);
    let prehash: [u8; 32] = Sha256::digest(&canonical_bytes).into();

    let signature =
        decode_signature(&payload.embedded_genesis_roster.self_signed_by_genesis_key)?;

    genesis_pubkey
        .verify_prehash(&prehash, &signature)
        .map_err(|_| VerifyError::GenesisSignatureInvalid)
}

/// **Check 2.** Verify the roster chain — each entry must be signed by
/// a verification method present in the prior entry's roster, and
/// versions must strictly increase. Proves "the current roster
/// legitimately descends from genesis via signer-in-prior-roster
/// signatures."
pub fn check_roster_chain(payload: &MidJwtPayload) -> Result<(), VerifyError> {
    let mut prior_vms: &[VerificationMethod] =
        &payload.embedded_genesis_roster.verification_methods;
    let mut prior_version: u64 = payload.embedded_genesis_roster.version;

    for entry in &payload.embedded_roster_chain {
        check_one_chain_entry(entry, prior_vms, prior_version)?;
        prior_vms = &entry.verification_methods;
        prior_version = entry.version;
    }

    Ok(())
}

fn check_one_chain_entry(
    entry: &EmbeddedRosterChainEntry,
    prior_vms: &[VerificationMethod],
    prior_version: u64,
) -> Result<(), VerifyError> {
    // 1. Monotonic version
    if entry.version <= prior_version {
        return Err(VerifyError::ChainVersionNotMonotonic {
            entry_version: entry.version,
            prior_version,
        });
    }

    // 2. Find the signer's VM in the prior roster.
    //
    // `signer_kid` is the bare device kid (e.g., "dev-laptop"); the VM
    // ID in the prior roster is `<did>#<kid>`. Match by suffix to avoid
    // hardcoding the DID-prefix shape here.
    let kid_suffix = format!("#{}", entry.signer_kid);
    let signer_vm = prior_vms
        .iter()
        .find(|vm| vm.id.ends_with(&kid_suffix))
        .ok_or_else(|| VerifyError::ChainSignerNotInPriorRoster {
            entry_version: entry.version,
            signer_kid: entry.signer_kid.clone(),
        })?;

    // 3. Decode the signer's pubkey and verify the signature.
    let signer_pubkey = pubkey_from_multibase(&signer_vm.public_key_multibase, &signer_vm.id)?;
    let canonical_bytes = canonical::chain_entry_canonical_bytes(entry);
    let prehash: [u8; 32] = Sha256::digest(&canonical_bytes).into();
    let signature = decode_signature(&entry.signed_by_signer_in_prior_roster)?;

    signer_pubkey
        .verify_prehash(&prehash, &signature)
        .map_err(|_| VerifyError::ChainSignatureInvalid { entry_version: entry.version })
}

/// **Check 3.** Verify the embedded verification method (the device that
/// signed this JWT) is present in the head roster. Proves "this device's
/// key is currently authorized for this DID."
///
/// The head roster is the last entry of the chain, or the genesis roster
/// if the chain is empty.
pub fn check_current_vm_in_head(payload: &MidJwtPayload) -> Result<(), VerifyError> {
    let head_vms: &[VerificationMethod] = match payload.embedded_roster_chain.last() {
        Some(head) => &head.verification_methods,
        None => &payload.embedded_genesis_roster.verification_methods,
    };
    let current_id = &payload.embedded_verification_method.id;
    if !head_vms.iter().any(|vm| &vm.id == current_id) {
        return Err(VerifyError::CurrentVmNotInHeadRoster {
            vm_id: current_id.clone(),
        });
    }
    Ok(())
}

/// **Check 4.** Verify the JWS outer signature against the embedded
/// verification method's public key. Standard ES256 verification: SHA-256
/// the `header.payload` signing input, verify the ECDSA signature.
///
/// `signing_input` is the `<header_b64>.<payload_b64>` bytes (no leading
/// or trailing chars). `signature_b64` is the third JWS segment.
pub fn check_jws_signature(
    payload: &MidJwtPayload,
    signing_input: &str,
    signature_b64: &str,
) -> Result<(), VerifyError> {
    let current_vm = &payload.embedded_verification_method;
    let current_pubkey = pubkey_from_multibase(&current_vm.public_key_multibase, &current_vm.id)?;

    let prehash: [u8; 32] = Sha256::digest(signing_input.as_bytes()).into();
    let signature_bytes =
        URL_SAFE_NO_PAD.decode(signature_b64).map_err(|source| VerifyError::Base64Decode {
            segment: "signature",
            source,
        })?;
    if signature_bytes.len() != 64 {
        return Err(VerifyError::SignatureWrongLength { actual: signature_bytes.len() });
    }
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| VerifyError::SignatureWrongLength { actual: signature_bytes.len() })?;

    current_pubkey
        .verify_prehash(&prehash, &signature)
        .map_err(|_| VerifyError::JwtSignatureInvalid)
}

// ─── Shape: parse the JWS into (header_b64, payload_b64, signature_b64) ────

/// Decompose a JWS compact-form string into its three base64url-encoded
/// segments. Returns the bytes of the decoded header + payload alongside
/// the still-encoded signing_input + signature_b64 (the latter two are
/// needed verbatim for check 4).
pub fn split_jws(jwt: &str) -> Result<JwsParts<'_>, VerifyError> {
    let segments: Vec<&str> = jwt.split('.').collect();
    if segments.len() != 3 {
        return Err(VerifyError::InvalidJwsShape(segments.len()));
    }
    let header_b64 = segments[0];
    let payload_b64 = segments[1];
    let signature_b64 = segments[2];

    // Signing input is what the JWS signature was computed over.
    // Equivalent to &jwt[..jwt.rfind('.').unwrap()].
    let signing_input_end = header_b64.len() + 1 + payload_b64.len();
    let signing_input = &jwt[..signing_input_end];

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|source| {
        VerifyError::Base64Decode { segment: "header", source }
    })?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|source| {
        VerifyError::Base64Decode { segment: "payload", source }
    })?;

    Ok(JwsParts {
        header_bytes,
        payload_bytes,
        signing_input,
        signature_b64,
    })
}

/// Decomposed JWS pieces ready for verification.
pub struct JwsParts<'a> {
    /// Decoded header JSON bytes.
    pub header_bytes: Vec<u8>,
    /// Decoded payload JSON bytes.
    pub payload_bytes: Vec<u8>,
    /// `<header_b64>.<payload_b64>` — the bytes the signature covers.
    pub signing_input: &'a str,
    /// The third JWS segment, still base64url-encoded.
    pub signature_b64: &'a str,
}

/// Validate the JWS header asserts the expected algorithm + type. mID v1
/// requires `alg: ES256` and `typ: JWT` exactly.
pub fn validate_jws_header(header_bytes: &[u8]) -> Result<(), VerifyError> {
    let header: serde_json::Value =
        serde_json::from_slice(header_bytes).map_err(|_| VerifyError::InvalidJwsHeader)?;
    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or(VerifyError::InvalidJwsHeader)?;
    let typ = header.get("typ").and_then(|v| v.as_str()).ok_or(VerifyError::InvalidJwsHeader)?;
    if alg != "ES256" || typ != "JWT" {
        return Err(VerifyError::InvalidJwsHeader);
    }
    Ok(())
}
