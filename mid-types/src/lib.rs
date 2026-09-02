#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! # `mid-types` — the mID wire format, `no_std`
//!
//! The types every mID party agrees on — the JWT payload, the embedded
//! genesis roster and roster chain, the verification methods — and the
//! canonical bytes their signatures cover. `mid-issuer` builds them,
//! `mid-verify` checks them, and a device that signs its own genesis roster
//! and self-issued token (the Janus ESP32 family) carries only this crate
//! and a verifier. `no_std` + `alloc`; `std` (default) only forwards to
//! serde and serde_json.
//!
//! Every field name here MUST exactly match the JSON serialization the
//! verifier and the JS SDK expect (ADR 0005 Decision 1). Changing a field
//! name is a wire-format break.

extern crate alloc;

pub mod canonical;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

// ─── Request side ──────────────────────────────────────────────────────────

/// The relying party's sign-in request, posted into the wallet by the
/// `@mata/mid` SDK on the RP page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpRequest {
    /// The RP's bare origin, e.g. `"https://acme.com"`. The wallet verifies
    /// this matches the page's actual origin before issuing.
    pub rp_origin: String,
    /// RP-issued single-use nonce. The wallet echoes it in the JWT for
    /// replay defense.
    pub nonce: String,
    /// Per-claim categorization (required/optional/custom).
    pub claims: ClaimRequest,
}

/// Categorized claim request from the RP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// Claims that block sign-in if denied. Almost always just `["did"]`.
    pub required: Vec<String>,
    /// Claims the user can include or skip.
    #[serde(default)]
    pub optional: Vec<String>,
    /// Arbitrary keys outside the standard catalog — looked up in the
    /// wallet's local `profile_kv`.
    #[serde(default)]
    pub custom: BTreeMap<String, CustomClaimRequest>,
}

/// Per-key custom-claim metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomClaimRequest {
    /// Always true in v1 — custom claims cannot be required (the wallet
    /// doesn't know what they mean to the RP).
    pub optional: bool,
    /// Optional human-readable description the consent UI surfaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ─── Identity snapshot ─────────────────────────────────────────────────────

/// The wallet's identity state at the moment of sign-in, assembled by the
/// caller from `mata-identity` plus the `mid_user_consents` Y-CRDT lookup.
///
/// This crate consumes the snapshot read-only — it never mutates wallet
/// state.
#[derive(Debug, Clone)]
pub struct IdentitySnapshot {
    /// The user's DID, e.g. `"did:mata:p3k7q...8x2h"`.
    pub did: String,
    /// The genesis roster envelope, self-signed at signup by the genesis
    /// device's key. Held in wallet storage forever.
    pub genesis_roster: EmbeddedGenesisRoster,
    /// The wallet-signed roster mutations from genesis to current. May be
    /// empty if the user has only ever had the genesis device.
    pub roster_chain: Vec<EmbeddedRosterChainEntry>,
    /// The verification method for the device that's about to sign this
    /// mID JWT. MUST appear in either the genesis roster (if `roster_chain`
    /// is empty) or in the head roster chain entry.
    pub current_verification_method: EmbeddedVerificationMethod,
    /// Pre-built claim values keyed by claim name. The caller looks each
    /// claim up against the wallet's local stores (profile, achievements,
    /// computed level ratings) and populates this map BEFORE calling
    /// [`crate::build_mid_jwt`].
    ///
    /// Claims the user denied at the consent screen MUST be absent from
    /// this map — the issuer trusts the caller's filtering.
    pub approved_claims: BTreeMap<String, ClaimValue>,
}

// ─── JWT payload ───────────────────────────────────────────────────────────

/// The mID JWT payload — the JSON object that's base64url-encoded as the
/// second segment of the JWS compact-form token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MidJwtPayload {
    /// Issuer — the user's DID.
    pub iss: String,
    /// Subject — same as `iss` for self-issued tokens.
    pub sub: String,
    /// Audience — the RP's bare origin from the request.
    pub aud: String,
    /// Issued-at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds. v1 ships short-lived (~1 hour) tokens.
    pub exp: u64,
    /// RP-supplied nonce, echoed for replay defense.
    pub nonce: String,
    /// Claim values approved by the user, keyed by claim name.
    pub claims: BTreeMap<String, ClaimValue>,
    /// Self-signed genesis roster (signed by the key encoded in the DID).
    pub embedded_genesis_roster: EmbeddedGenesisRoster,
    /// Chain of wallet-signed roster mutations from genesis to current.
    pub embedded_roster_chain: Vec<EmbeddedRosterChainEntry>,
    /// The device key signing this JWT — must appear in the head roster.
    pub embedded_verification_method: EmbeddedVerificationMethod,
}

/// A single claim value with provenance metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimValue {
    /// The claim's value. Free-form per RFC 7519; common shapes are
    /// strings, numbers, booleans.
    pub value: serde_json::Value,
    /// Provenance — `self` in v1; v2 may add `third_party_vc`.
    pub attested_by: AttestedBy,
    /// Only set on the `email` claim if the user completed signup OTP.
    /// Historical fact, not a MATA signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at_signup: Option<bool>,
    /// Only set on derived claims (level ratings) — the wall-clock the
    /// wallet computed the score at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<u64>,
    /// Only set on derived claims — pins the formula generation. RPs can
    /// reject older versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formula_version: Option<String>,
}

/// Attestation provenance for a claim.
///
/// v1 ships only `self`. The enum is open for future provenance categories
/// without breaking the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestedBy {
    /// User-supplied, signed by the user's M5 device key as part of the
    /// outer JWT signature. MATA never witnessed this value.
    #[serde(rename = "self")]
    SelfAttested,
}

// ─── Embedded roster + verification method ─────────────────────────────────

/// The genesis roster envelope — version 1, self-signed by the genesis
/// device's signing key (the key whose public form is encoded in the DID
/// identifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedGenesisRoster {
    /// Always 1 for the genesis envelope.
    pub version: u64,
    /// The DID this roster belongs to.
    pub did: String,
    /// Verification methods present in the genesis roster. v1 wallets ship
    /// a one-entry genesis roster (just the genesis device); future
    /// versions could initialize multi-device genesis.
    pub verification_methods: Vec<VerificationMethod>,
    /// When the genesis roster was signed, Unix seconds.
    pub signed_at: u64,
    /// Signature by the genesis key over the canonical envelope bytes.
    /// Verifiable against the public key recovered from the DID.
    /// base64url-encoded `r || s` (64 bytes total).
    pub self_signed_by_genesis_key: String,
}

/// One entry in the wallet-signed roster chain. Each entry is signed by a
/// verification method present in the prior entry's roster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedRosterChainEntry {
    /// Monotonically increasing across the chain. genesis is version 1; the
    /// first chain entry is version 2.
    pub version: u64,
    /// The DID this roster belongs to.
    pub did: String,
    /// Verification methods after this mutation.
    pub verification_methods: Vec<VerificationMethod>,
    /// When this mutation was signed, Unix seconds.
    pub signed_at: u64,
    /// Signature by a verification method present in the PRIOR roster.
    /// base64url-encoded `r || s` (64 bytes total).
    pub signed_by_signer_in_prior_roster: String,
    /// The `kid` of the verification method in the prior roster that
    /// produced this signature. Lets the verifier skip a scan.
    pub signer_kid: String,
}

/// A verification method = a public key bound to a DID. Same shape as the
/// W3C DID document `verificationMethod[]` entry, minimum-fields form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Fully-qualified ID, e.g. `"did:mata:abc...#dev-laptop"`.
    pub id: String,
    /// Always `"EcdsaSecp256r1VerificationKey2019"` in v1.
    #[serde(rename = "type")]
    pub vm_type: String,
    /// The DID that controls this verification method.
    pub controller: String,
    /// Multibase-encoded public key. v1 wallets use `z6Mk...` base58btc
    /// per the multibase spec.
    pub public_key_multibase: String,
}

/// The current device's verification method — the key that's about to sign
/// the JWT. Slim form (just the key + identity), no extra DID-document
/// metadata. Must appear in the head roster of the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedVerificationMethod {
    /// Fully-qualified ID, e.g. `"did:mata:abc...#dev-laptop"`.
    pub id: String,
    /// Always `"EcdsaSecp256r1VerificationKey2019"` in v1.
    #[serde(rename = "type")]
    pub vm_type: String,
    /// The DID that controls this verification method.
    pub controller: String,
    /// Multibase-encoded public key.
    pub public_key_multibase: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attested_by_serializes_as_lowercase_self() {
        let cv = ClaimValue {
            value: serde_json::Value::String("tim@example.com".into()),
            attested_by: AttestedBy::SelfAttested,
            verified_at_signup: Some(true),
            computed_at: None,
            formula_version: None,
        };
        let json = serde_json::to_string(&cv).unwrap();
        assert!(
            json.contains(r#""attested_by":"self""#),
            "attested_by must serialize as the lowercase string 'self' per ADR 0005 Decision 1, got: {json}"
        );
        assert!(
            json.contains(r#""verified_at_signup":true"#),
            "verified_at_signup must be present when Some, got: {json}"
        );
    }

    #[test]
    fn claim_value_omits_optional_fields_when_none() {
        let cv = ClaimValue {
            value: serde_json::Value::String("Tim".into()),
            attested_by: AttestedBy::SelfAttested,
            verified_at_signup: None,
            computed_at: None,
            formula_version: None,
        };
        let json = serde_json::to_string(&cv).unwrap();
        assert!(!json.contains("verified_at_signup"), "absent when None");
        assert!(!json.contains("computed_at"), "absent when None");
        assert!(!json.contains("formula_version"), "absent when None");
    }

    #[test]
    fn verification_method_type_field_serializes_as_type() {
        let vm = VerificationMethod {
            id: "did:mata:abc#dev".into(),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: "did:mata:abc".into(),
            public_key_multibase: "z6Mk...".into(),
        };
        let json = serde_json::to_string(&vm).unwrap();
        assert!(
            json.contains(r#""type":"EcdsaSecp256r1VerificationKey2019""#),
            "vm_type must serialize as JSON field 'type' per the DID document standard, got: {json}"
        );
    }
}
