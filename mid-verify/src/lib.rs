#![cfg_attr(not(feature = "std"), no_std)]
//! # `mid-verify` — RP-side mID JWT verifier
//!
//! Phase 0 of the [mID Mission](../../../docs/plans/phase%201%20sso_permissionless_mission.md).
//! Implements the four-step verification from
//! [ADR 0005 Decision 1](../../../docs/adr/0005-mid-protocol-v1-phase-0-spec-lockin.md):
//! given a JWS compact-form mID token and a [`VerifyConfig`], run all
//! cryptographic checks entirely locally and return a [`VerifiedMid`]
//! that captures the user's DID, current roster version, and disclosed
//! claims.
//!
//! ## The four-step verification
//!
//! 1. **Genesis self-signature.** Decode the genesis public key from the
//!    DID's base58 suffix; verify the genesis roster envelope's
//!    `self_signed_by_genesis_key` against it.
//! 2. **Roster chain.** Each chain entry signed by a VM present in the
//!    prior entry's roster; versions strictly monotonic.
//! 3. **Current VM in head.** The device that signed this JWT is in the
//!    head (current) roster.
//! 4. **JWS outer signature.** Standard ES256 verification against the
//!    embedded verification method's public key.
//!
//! ## Zero MATA runtime calls
//!
//! Per ADR 0005, RPs make zero HTTP requests to MATA infrastructure
//! during verification. Every cryptographic input the verifier needs
//! travels inside the JWT itself; everything else is RP-local
//! configuration ([`VerifyConfig`]) or RP-local state (the optional
//! rollback check the RP runs against its own database AFTER calling
//! [`verify_mid_response`]).
//!
//! ## Usage
//!
//! ```ignore
//! use mid_verify::{verify_mid_response, VerifyConfig};
//!
//! let config = VerifyConfig {
//!     expected_audience: "https://acme.com".to_string(),
//!     expected_nonce: my_session_nonce.clone(),
//!     max_iat_skew_secs: 120,
//!     now_unix_secs: current_wall_clock_secs(),
//! };
//!
//! let verified = verify_mid_response(&incoming_jwt, &config)?;
//!
//! // Optional rollback check — look up the highest version this RP has
//! // seen for this DID in its own database, then:
//! let last_seen = db.lookup_last_seen_version(&verified.did).await?;
//! verified.check_rollback(last_seen)?;
//!
//! // Persist user, issue session...
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod checks;
mod error;
pub mod keys;

pub use error::VerifyError;
pub use keys::{did_from_pubkey, multibase_from_pubkey, pubkey_from_did, pubkey_from_multibase};

// Re-export the wire-format types from mid-issuer so RPs only need one
// `cargo add mid-verify` to access everything they need.
pub use mid_types::{
    AttestedBy, ClaimValue, EmbeddedGenesisRoster, EmbeddedRosterChainEntry,
    EmbeddedVerificationMethod, MidJwtPayload, VerificationMethod,
};

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use sha2::{Digest, Sha256};

// ─── Public API ────────────────────────────────────────────────────────────

/// Configuration the RP supplies to [`verify_mid_response`].
///
/// All fields are RP-supplied and reflect RP-local policy. The verifier
/// never reaches out to MATA infrastructure to populate any of these.
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// The RP's bare origin (e.g. `"https://acme.com"`). Must equal the
    /// JWT's `aud` claim exactly. The wallet sets `aud` from the
    /// `rp_origin` field in the original sign-in request; this check
    /// catches a token issued to one RP being replayed at another.
    pub expected_audience: String,
    /// The single-use nonce the RP issued for this sign-in session. Must
    /// equal the JWT's `nonce` claim exactly. The RP fetches this from
    /// its own per-session store (e.g. the `auth_nonces` table).
    pub expected_nonce: String,
    /// Maximum allowed forward clock skew between the wallet's `iat`
    /// and the verifier's wall clock, in seconds. Tokens with `iat >
    /// now + max_iat_skew_secs` are rejected as "not yet valid"; this
    /// guards against forward-dated tokens. 120s is a reasonable
    /// default.
    pub max_iat_skew_secs: u64,
    /// The verifier's current wall-clock time in Unix seconds. Passed
    /// in by the caller (rather than read here) so the verifier stays a
    /// pure function — testable with fixed clocks, deterministic in
    /// production retries.
    pub now_unix_secs: u64,
}

/// The result of a successful verification. Carries everything an RP
/// needs to upsert a user row, issue a session, and (optionally) run a
/// rollback check.
#[derive(Debug, Clone)]
pub struct VerifiedMid {
    /// The user's DID. Stable across the user's lifetime; the RP's user
    /// table primary key.
    pub did: String,
    /// SHA-256 of the canonical genesis-roster bytes. The RP records
    /// this on first sight as the user's anchor; on subsequent sign-ins
    /// the same DID MUST produce the same `genesis_roster_hash` (the
    /// RP's upsert can guard the invariant).
    pub genesis_roster_hash: [u8; 32],
    /// The head roster's version. Monotonically increases as the user
    /// adds / revokes devices. The RP can record this and reject lower
    /// versions on subsequent sign-ins to defeat stolen-device replay.
    pub current_version: u64,
    /// The claim values the user consented to disclose, exactly as the
    /// wallet asserted them.
    pub claims: BTreeMap<String, ClaimValue>,
    /// The JWT's issued-at, Unix seconds.
    pub iat: u64,
    /// The JWT's expiry, Unix seconds.
    pub exp: u64,
    /// The JWT's audience — equals `config.expected_audience` after
    /// successful verify.
    pub aud: String,
}

impl VerifiedMid {
    /// Check that the current roster version is at least as new as the
    /// last version the RP has seen for this DID.
    ///
    /// The RP fetches `last_seen_version` from its own per-DID store
    /// (typically a `users.last_seen_roster_version` column). Pass
    /// `None` if this is a DID the RP has never seen — in that case
    /// the check trivially passes and the RP records the current
    /// version as the new high-water mark.
    pub fn check_rollback(&self, last_seen_version: Option<u64>) -> Result<(), VerifyError> {
        match last_seen_version {
            Some(seen) if seen > self.current_version => Err(VerifyError::RollbackDetected {
                current: self.current_version,
                last_seen: seen,
            }),
            _ => Ok(()),
        }
    }
}

/// Run the four-step mID verification against `jwt` per [`VerifyConfig`].
///
/// On success, returns a [`VerifiedMid`]. On any failure, returns the
/// specific [`VerifyError`] variant — caller can `match` to log /
/// respond distinctly.
///
/// This function is a pure function of its inputs. It does no I/O,
/// reads no clock, makes no remote calls. The caller supplies the
/// wall-clock time via [`VerifyConfig::now_unix_secs`].
pub fn verify_mid_response(jwt: &str, config: &VerifyConfig) -> Result<VerifiedMid, VerifyError> {
    // 1. Split JWS into segments + decode header/payload.
    let parts = checks::split_jws(jwt)?;
    checks::validate_jws_header(&parts.header_bytes)?;
    let payload: MidJwtPayload = serde_json::from_slice(&parts.payload_bytes)?;

    // 2. Metadata checks: audience, nonce, expiry, not-yet-valid.
    if payload.aud != config.expected_audience {
        return Err(VerifyError::AudienceMismatch {
            expected: config.expected_audience.clone(),
            actual: payload.aud.clone(),
        });
    }
    if payload.nonce != config.expected_nonce {
        return Err(VerifyError::NonceMismatch);
    }
    if config.now_unix_secs >= payload.exp {
        return Err(VerifyError::Expired {
            exp: payload.exp,
            now: config.now_unix_secs,
        });
    }
    if payload.iat > config.now_unix_secs.saturating_add(config.max_iat_skew_secs) {
        return Err(VerifyError::NotYetValid {
            iat: payload.iat,
            now: config.now_unix_secs,
            max_skew_secs: config.max_iat_skew_secs,
        });
    }

    // 3. The four cryptographic checks. Each is isolated; the
    //    orchestrator just calls them in order.
    checks::check_genesis_self_signature(&payload)?;
    checks::check_roster_chain(&payload)?;
    checks::check_current_vm_in_head(&payload)?;
    checks::check_jws_signature(&payload, parts.signing_input, parts.signature_b64)?;

    // 4. Compute genesis_roster_hash + current_version for the RP's
    //    anchoring + rollback-detection use.
    let genesis_canonical = mid_types::canonical::genesis_canonical_bytes(
        &payload.embedded_genesis_roster,
    );
    let genesis_roster_hash: [u8; 32] = Sha256::digest(&genesis_canonical).into();
    let current_version = payload
        .embedded_roster_chain
        .last()
        .map(|e| e.version)
        .unwrap_or(payload.embedded_genesis_roster.version);

    Ok(VerifiedMid {
        did: payload.iss.clone(),
        genesis_roster_hash,
        current_version,
        claims: payload.claims,
        iat: payload.iat,
        exp: payload.exp,
        aud: payload.aud,
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use kms_client::{DeviceSigner, InMemoryDeviceSigner};
    use mid_issuer::{
        build_mid_jwt, AttestedBy, ClaimRequest, ClaimValue, EmbeddedGenesisRoster,
        EmbeddedRosterChainEntry, EmbeddedVerificationMethod, IdentitySnapshot, RpRequest,
        VerificationMethod,
    };
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use std::collections::BTreeMap;

    // ─── Fixture builders ──────────────────────────────────────────────────

    /// Build a deterministic signing key from a seed string (matches
    /// the mid-issuer test helper).
    fn make_signing_key(seed: &str) -> SigningKey {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b"-mid-verify-test-seed");
        let bytes: [u8; 32] = hasher.finalize().into();
        SigningKey::from_bytes(&bytes.into()).unwrap()
    }

    /// A single device's key material. The DID it belongs to is owned
    /// by [`IdentityFixture`] — a device's `signing_key` is its own,
    /// but it serves whatever identity it's been added to.
    struct DeviceKey {
        device_id: String,
        signing_key: SigningKey,
    }

    impl DeviceKey {
        fn new(seed: &str, device_id: &str) -> Self {
            Self {
                device_id: device_id.into(),
                signing_key: make_signing_key(seed),
            }
        }
    }

    /// A test identity centered on a genesis device. Additional devices
    /// are added to the SAME DID — they don't bring their own DID.
    struct IdentityFixture {
        genesis: DeviceKey,
    }

    impl IdentityFixture {
        fn new(genesis_seed: &str, genesis_device_id: &str) -> Self {
            Self {
                genesis: DeviceKey::new(genesis_seed, genesis_device_id),
            }
        }

        /// The DID derived from the genesis key. Every device added to
        /// this identity serves this DID — its VM's `controller` is this
        /// DID, its VM's `id` is `<this_did>#<its_device_id>`.
        fn did(&self) -> String {
            keys::did_from_pubkey(self.genesis.signing_key.verifying_key())
        }

        /// Build a verification method for any device under this identity.
        fn vm_for(&self, device: &DeviceKey) -> VerificationMethod {
            let did = self.did();
            VerificationMethod {
                id: format!("{did}#{}", device.device_id),
                vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
                controller: did,
                public_key_multibase: keys::multibase_from_pubkey(
                    device.signing_key.verifying_key(),
                ),
            }
        }

        /// Build the embedded-VM form (the JWT's current_verification_method).
        fn embedded_vm_for(&self, device: &DeviceKey) -> EmbeddedVerificationMethod {
            let did = self.did();
            EmbeddedVerificationMethod {
                id: format!("{did}#{}", device.device_id),
                vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
                controller: did,
                public_key_multibase: keys::multibase_from_pubkey(
                    device.signing_key.verifying_key(),
                ),
            }
        }
    }

    /// Sign the canonical bytes of a genesis roster with the given key,
    /// returning the base64url-encoded `r || s`.
    fn sign_genesis(roster: &EmbeddedGenesisRoster, signing_key: &SigningKey) -> String {
        let canonical = mid_types::canonical::genesis_canonical_bytes(roster);
        let prehash: [u8; 32] = Sha256::digest(&canonical).into();
        let sig: Signature = signing_key.sign_prehash(&prehash).unwrap();
        let normalized = sig.normalize_s().unwrap_or(sig);
        let bytes = normalized.to_bytes();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Sign the canonical bytes of a chain entry with the given key.
    fn sign_chain_entry(entry: &EmbeddedRosterChainEntry, signing_key: &SigningKey) -> String {
        let canonical = mid_types::canonical::chain_entry_canonical_bytes(entry);
        let prehash: [u8; 32] = Sha256::digest(&canonical).into();
        let sig: Signature = signing_key.sign_prehash(&prehash).unwrap();
        let normalized = sig.normalize_s().unwrap_or(sig);
        let bytes = normalized.to_bytes();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Build a single-device identity snapshot (genesis only, no chain).
    fn fresh_identity(identity: &IdentityFixture) -> IdentitySnapshot {
        let genesis_vm = identity.vm_for(&identity.genesis);
        let mut genesis = EmbeddedGenesisRoster {
            version: 1,
            did: identity.did(),
            verification_methods: vec![genesis_vm],
            signed_at: 1_700_000_000,
            self_signed_by_genesis_key: String::new(),
        };
        genesis.self_signed_by_genesis_key =
            sign_genesis(&genesis, &identity.genesis.signing_key);

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

    /// Build a two-device identity snapshot: genesis + one chain entry
    /// adding the second device. Signs the chain entry with the genesis
    /// device's key (the only one in the prior roster).
    fn two_device_identity(
        identity: &IdentityFixture,
        new_device: &DeviceKey,
    ) -> IdentitySnapshot {
        let mut base = fresh_identity(identity);

        let mut chain_entry = EmbeddedRosterChainEntry {
            version: 2,
            did: identity.did(),
            verification_methods: vec![
                identity.vm_for(&identity.genesis),
                identity.vm_for(new_device),
            ],
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

    /// Sign and emit a JWT against the given snapshot. The signer is
    /// derived from the snapshot's `current_verification_method` —
    /// caller is responsible for matching the snapshot to the signer.
    fn mint_jwt(
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

    fn fresh_config(now: u64, nonce: &str) -> VerifyConfig {
        VerifyConfig {
            expected_audience: "https://acme.com".into(),
            expected_nonce: nonce.into(),
            max_iat_skew_secs: 120,
            now_unix_secs: now,
        }
    }

    // ─── Happy path ────────────────────────────────────────────────────────

    #[test]
    fn happy_path_single_device_verifies() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));

        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let config = fresh_config(1_716_700_010, "nonce-abc");
        let verified = verify_mid_response(&jwt, &config).expect("happy path verify");

        assert_eq!(verified.did, identity.did());
        assert_eq!(verified.current_version, 1);
        assert_eq!(verified.aud, "https://acme.com");
        assert_eq!(verified.iat, 1_716_700_000);
        assert_eq!(verified.exp, 1_716_700_000 + 3600);
        assert!(verified.claims.contains_key("did"));
    }

    #[test]
    fn happy_path_two_devices_chain_verifies() {
        let identity = IdentityFixture::new("genesis", "dev-laptop");
        let new_device = DeviceKey::new("new-phone", "dev-phone");
        let snapshot = two_device_identity(&identity, &new_device);
        let signer = InMemoryDeviceSigner::new("dev-phone", make_signing_key("new-phone"));

        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let config = fresh_config(1_716_700_010, "nonce-abc");
        let verified = verify_mid_response(&jwt, &config).expect("two-device verify");

        assert_eq!(verified.did, identity.did());
        assert_eq!(verified.current_version, 2);
    }

    // ─── Tamper checks ─────────────────────────────────────────────────────

    #[test]
    fn tampered_jws_signature_rejected() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let config = fresh_config(1_716_700_010, "nonce-abc");

        // Flip a bit in the last segment (the signature).
        let mut parts: Vec<String> = jwt.split('.').map(|s| s.to_string()).collect();
        let last_idx = parts.len() - 1;
        let sig_bytes = URL_SAFE_NO_PAD.decode(&parts[last_idx]).unwrap();
        let mut tampered = sig_bytes.clone();
        tampered[0] ^= 0x80;
        parts[last_idx] = URL_SAFE_NO_PAD.encode(tampered);
        let tampered_jwt = parts.join(".");

        let err = verify_mid_response(&tampered_jwt, &config).unwrap_err();
        assert!(
            matches!(err, VerifyError::JwtSignatureInvalid | VerifyError::SignatureWrongLength { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn audience_mismatch_rejected() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        let mut config = fresh_config(1_716_700_010, "nonce-abc");
        config.expected_audience = "https://attacker.com".into();

        match verify_mid_response(&jwt, &config) {
            Err(VerifyError::AudienceMismatch { expected, actual }) => {
                assert_eq!(expected, "https://attacker.com");
                assert_eq!(actual, "https://acme.com");
            }
            other => panic!("expected AudienceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        let config = fresh_config(1_716_700_010, "different-nonce");
        match verify_mid_response(&jwt, &config) {
            Err(VerifyError::NonceMismatch) => {}
            other => panic!("expected NonceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn expired_jwt_rejected() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        // Default token lifetime is 3600s. Time-travel past exp.
        let config = fresh_config(1_716_700_000 + 3601, "nonce-abc");
        match verify_mid_response(&jwt, &config) {
            Err(VerifyError::Expired { exp, now }) => {
                assert_eq!(exp, 1_716_700_000 + 3600);
                assert_eq!(now, 1_716_700_000 + 3601);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn forward_dated_jwt_beyond_skew_rejected() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        // Mint with iat far in the future.
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        // Verifier's wall clock is well before iat — beyond the 120s skew.
        let config = fresh_config(1_716_600_000, "nonce-abc");
        match verify_mid_response(&jwt, &config) {
            Err(VerifyError::NotYetValid { iat, now, max_skew_secs }) => {
                assert_eq!(iat, 1_716_700_000);
                assert_eq!(now, 1_716_600_000);
                assert_eq!(max_skew_secs, 120);
            }
            other => panic!("expected NotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn tampered_genesis_signature_rejected() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let mut snapshot = fresh_identity(&identity);
        // Flip a byte in the genesis signature.
        let mut sig_bytes =
            URL_SAFE_NO_PAD.decode(&snapshot.genesis_roster.self_signed_by_genesis_key).unwrap();
        sig_bytes[0] ^= 0x80;
        snapshot.genesis_roster.self_signed_by_genesis_key = URL_SAFE_NO_PAD.encode(sig_bytes);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        let config = fresh_config(1_716_700_010, "nonce-abc");
        let err = verify_mid_response(&jwt, &config).unwrap_err();
        assert!(
            matches!(err, VerifyError::GenesisSignatureInvalid),
            "got {err:?}"
        );
    }

    #[test]
    fn broken_chain_signer_not_in_prior_rejected() {
        let identity = IdentityFixture::new("genesis", "dev-laptop");
        let new_device = DeviceKey::new("new-phone", "dev-phone");
        let mut snapshot = two_device_identity(&identity, &new_device);

        // Forge: claim the chain entry was signed by a non-existent
        // device. The signature won't even be checked — the lookup
        // fails first.
        snapshot.roster_chain[0].signer_kid = "ghost-device".into();
        snapshot.roster_chain[0].signed_by_signer_in_prior_roster =
            sign_chain_entry(&snapshot.roster_chain[0], &identity.genesis.signing_key);

        let signer = InMemoryDeviceSigner::new("dev-phone", make_signing_key("new-phone"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        let config = fresh_config(1_716_700_010, "nonce-abc");
        match verify_mid_response(&jwt, &config) {
            Err(VerifyError::ChainSignerNotInPriorRoster { signer_kid, .. }) => {
                assert_eq!(signer_kid, "ghost-device");
            }
            other => panic!("expected ChainSignerNotInPriorRoster, got {other:?}"),
        }
    }

    #[test]
    fn non_monotonic_chain_version_rejected() {
        let identity = IdentityFixture::new("genesis", "dev-laptop");
        let new_device = DeviceKey::new("new-phone", "dev-phone");
        let mut snapshot = two_device_identity(&identity, &new_device);

        // Roll back the chain entry's version to match the genesis.
        snapshot.roster_chain[0].version = 1;
        snapshot.roster_chain[0].signed_by_signer_in_prior_roster =
            sign_chain_entry(&snapshot.roster_chain[0], &identity.genesis.signing_key);

        let signer = InMemoryDeviceSigner::new("dev-phone", make_signing_key("new-phone"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        let config = fresh_config(1_716_700_010, "nonce-abc");
        match verify_mid_response(&jwt, &config) {
            Err(VerifyError::ChainVersionNotMonotonic { entry_version, prior_version }) => {
                assert_eq!(entry_version, 1);
                assert_eq!(prior_version, 1);
            }
            other => panic!("expected ChainVersionNotMonotonic, got {other:?}"),
        }
    }

    #[test]
    fn current_vm_not_in_head_rejected() {
        let identity = IdentityFixture::new("genesis", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        // Build a JWT with a forged current_verification_method that
        // claims to be a device NOT in the head roster. We have to do
        // this manually — mid-issuer's build_mid_jwt would reject it
        // before signing. So we mint a normal JWT, then surgically
        // replace the embedded VM in the payload.

        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("genesis"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);

        // Decode + tamper the payload.
        let parts: Vec<&str> = jwt.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let mut payload: MidJwtPayload = serde_json::from_slice(&payload_bytes).unwrap();
        payload.embedded_verification_method.id = format!("{}#ghost", identity.did());
        let new_payload_bytes = serde_json::to_vec(&payload).unwrap();
        let new_payload_b64 = URL_SAFE_NO_PAD.encode(new_payload_bytes);
        let tampered_jwt = format!("{}.{}.{}", parts[0], new_payload_b64, parts[2]);

        let config = fresh_config(1_716_700_010, "nonce-abc");
        match verify_mid_response(&tampered_jwt, &config) {
            Err(VerifyError::CurrentVmNotInHeadRoster { vm_id }) => {
                assert!(vm_id.ends_with("#ghost"));
            }
            other => panic!("expected CurrentVmNotInHeadRoster, got {other:?}"),
        }
    }

    // ─── Rollback detection (caller-side) ──────────────────────────────────

    #[test]
    fn rollback_passes_when_no_history() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let verified =
            verify_mid_response(&jwt, &fresh_config(1_716_700_010, "nonce-abc")).unwrap();

        assert!(verified.check_rollback(None).is_ok());
    }

    #[test]
    fn rollback_passes_when_current_equals_last_seen() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let verified =
            verify_mid_response(&jwt, &fresh_config(1_716_700_010, "nonce-abc")).unwrap();

        assert!(verified.check_rollback(Some(1)).is_ok());
    }

    #[test]
    fn rollback_rejected_when_current_below_last_seen() {
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let verified =
            verify_mid_response(&jwt, &fresh_config(1_716_700_010, "nonce-abc")).unwrap();

        match verified.check_rollback(Some(5)) {
            Err(VerifyError::RollbackDetected { current, last_seen }) => {
                assert_eq!(current, 1);
                assert_eq!(last_seen, 5);
            }
            other => panic!("expected RollbackDetected, got {other:?}"),
        }
    }

    // ─── Shape checks ──────────────────────────────────────────────────────

    #[test]
    fn malformed_jws_shape_rejected() {
        let config = fresh_config(1_716_700_010, "nonce-abc");
        let err = verify_mid_response("not.a.valid.jws.has.too.many.dots", &config).unwrap_err();
        assert!(matches!(err, VerifyError::InvalidJwsShape(_)));
    }

    #[test]
    fn genesis_roster_hash_is_deterministic() {
        // Two verifications of the same JWT MUST produce the same hash.
        let identity = IdentityFixture::new("device-A", "dev-laptop");
        let snapshot = fresh_identity(&identity);
        let signer = InMemoryDeviceSigner::new("dev-laptop", make_signing_key("device-A"));
        let jwt = mint_jwt(&snapshot, &signer, "https://acme.com", "nonce-abc", 1_716_700_000);
        let config = fresh_config(1_716_700_010, "nonce-abc");

        let v1 = verify_mid_response(&jwt, &config).unwrap();
        let v2 = verify_mid_response(&jwt, &config).unwrap();
        assert_eq!(v1.genesis_roster_hash, v2.genesis_roster_hash);
    }
}
