//! Identity-snapshot assembly + validation.
//!
//! The wallet calls [`assemble_identity_snapshot`] right before invoking
//! [`crate::build_mid_jwt`] to bind its persisted state (genesis envelope
//! + roster chain + current device VM) plus the consent decision (approved
//! claims) into the [`IdentitySnapshot`] the issuer consumes.
//!
//! This function is a *defensive* smart constructor: it runs validation
//! checks that catch wallet-side bugs (corrupted storage, stale device
//! state, missing chain links) BEFORE the issuer signs anything. The
//! issuer also does its own pre-flight (in [`crate::build_mid_jwt`]) but
//! covers a smaller surface; this function covers the full snapshot.
//!
//! ## Validation rules
//!
//! 1. Genesis roster MUST have version 1.
//! 2. Genesis roster's `did` MUST equal the snapshot DID.
//! 3. Every chain entry's `did` MUST equal the snapshot DID.
//! 4. First chain entry (if any) MUST have version 2.
//! 5. Chain entry versions MUST strictly increase.
//! 6. Current VM's `controller` MUST equal the snapshot DID.
//! 7. Current VM MUST appear in the head roster (last chain entry's VMs,
//!    or genesis's VMs if the chain is empty).
//!
//! Cryptographic checks (genesis signature, chain signatures, JWT
//! signature) are NOT performed here — those happen at the verifier
//! ([`mid-verify`](../mid_verify/)). The snapshot builder catches
//! shape/policy bugs locally; cryptographic correctness is the verifier's
//! responsibility.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::types::{
    ClaimValue, EmbeddedGenesisRoster, EmbeddedRosterChainEntry, EmbeddedVerificationMethod,
    IdentitySnapshot, VerificationMethod,
};

/// Errors from [`assemble_identity_snapshot`].
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Genesis roster has a version other than 1 — corrupted local
    /// storage or a bug in the bootstrap flow.
    #[error("genesis roster has version {got}, expected 1")]
    GenesisVersionNotOne {
        /// The bad version value.
        got: u64,
    },
    /// A DID embedded in the snapshot doesn't match the snapshot's own
    /// DID. Names which envelope was at fault and what it contained.
    #[error("DID mismatch: snapshot DID `{snapshot_did}` does not match {which} DID `{found_did}`")]
    DidMismatch {
        /// The snapshot's `did` field.
        snapshot_did: String,
        /// Which envelope contained the mismatched DID (e.g. `"genesis"`,
        /// `"chain entry version 2"`).
        which: String,
        /// The DID that appeared in the offending envelope.
        found_did: String,
    },
    /// The first chain entry doesn't have version 2. Versions in the
    /// chain must strictly increase from the genesis's version 1, so
    /// the first entry must be version 2.
    #[error("first chain entry has version {got}, expected 2")]
    FirstChainEntryWrongVersion {
        /// The bad version value.
        got: u64,
    },
    /// Two consecutive chain entries had non-monotonic versions —
    /// indicates the wallet's chain storage is corrupted or out of order.
    #[error(
        "chain version not strictly monotonic: entry version {entry_version} <= prior version {prior_version}"
    )]
    ChainVersionNotMonotonic {
        /// The non-monotonic entry's version.
        entry_version: u64,
        /// The prior entry's version (must be < entry_version).
        prior_version: u64,
    },
    /// The current verification method's controller doesn't match the
    /// snapshot's DID. Indicates wrong device key paired with wrong
    /// identity.
    #[error(
        "current verification method controller `{vm_controller}` does not match snapshot DID `{snapshot_did}`"
    )]
    CurrentVmDidMismatch {
        /// The VM's controller field.
        vm_controller: String,
        /// The snapshot's DID.
        snapshot_did: String,
    },
    /// The current verification method is not present in the head
    /// roster — the signing device has been revoked, or the wallet's
    /// roster cache is stale.
    #[error(
        "current verification method `{vm_id}` is not in the head roster — this device may have been revoked"
    )]
    CurrentVmNotInHeadRoster {
        /// The VM ID that's missing from the head roster.
        vm_id: String,
    },
}

/// Assemble + validate an [`IdentitySnapshot`] from the wallet's stored
/// state and the user's consent decision.
///
/// The wallet calls this with:
///
/// - `did` — the user's DID (looked up from wallet credentials).
/// - `genesis_roster` — read from the wallet's local genesis store
///   (populated by [`crate::bootstrap::sign_genesis_roster`] at signup).
/// - `roster_chain` — read from the wallet's local chain store (populated
///   by [`crate::bootstrap::sign_roster_chain_entry`] each time the user
///   adds or removes a device). May be empty for single-device wallets.
/// - `current_verification_method` — the VM corresponding to the device
///   that's about to sign the JWT (this binary's M5 device key's pubkey
///   encoded as multibase, wrapped in the embedded form).
/// - `approved_claims` — the set of claim values the user explicitly
///   consented to disclose on the consent screen.
///
/// On success returns the [`IdentitySnapshot`] ready for
/// [`crate::build_mid_jwt`]. On validation failure returns a specific
/// [`SnapshotError`] variant; the wallet UI can surface a specific
/// recovery hint (e.g., "this device has been revoked — please re-pair").
pub fn assemble_identity_snapshot(
    did: String,
    genesis_roster: EmbeddedGenesisRoster,
    roster_chain: Vec<EmbeddedRosterChainEntry>,
    current_verification_method: EmbeddedVerificationMethod,
    approved_claims: BTreeMap<String, ClaimValue>,
) -> Result<IdentitySnapshot, SnapshotError> {
    // ─── 1. Genesis version is exactly 1 ──────────────────────────────────
    if genesis_roster.version != 1 {
        return Err(SnapshotError::GenesisVersionNotOne {
            got: genesis_roster.version,
        });
    }

    // ─── 2. Genesis DID matches snapshot DID ──────────────────────────────
    if genesis_roster.did != did {
        return Err(SnapshotError::DidMismatch {
            snapshot_did: did.clone(),
            which: "genesis".to_string(),
            found_did: genesis_roster.did.clone(),
        });
    }

    // ─── 3 + 4 + 5. Chain entry validation ────────────────────────────────
    let mut prior_version = genesis_roster.version;
    for (i, entry) in roster_chain.iter().enumerate() {
        if entry.did != did {
            return Err(SnapshotError::DidMismatch {
                snapshot_did: did.clone(),
                which: format!("chain entry version {}", entry.version),
                found_did: entry.did.clone(),
            });
        }
        if i == 0 && entry.version != 2 {
            return Err(SnapshotError::FirstChainEntryWrongVersion { got: entry.version });
        }
        if entry.version <= prior_version {
            return Err(SnapshotError::ChainVersionNotMonotonic {
                entry_version: entry.version,
                prior_version,
            });
        }
        prior_version = entry.version;
    }

    // ─── 6. Current VM controller matches snapshot DID ────────────────────
    if current_verification_method.controller != did {
        return Err(SnapshotError::CurrentVmDidMismatch {
            vm_controller: current_verification_method.controller.clone(),
            snapshot_did: did.clone(),
        });
    }

    // ─── 7. Current VM in head roster ─────────────────────────────────────
    let head_vms: &[VerificationMethod] = match roster_chain.last() {
        Some(head) => &head.verification_methods,
        None => &genesis_roster.verification_methods,
    };
    if !head_vms.iter().any(|vm| vm.id == current_verification_method.id) {
        return Err(SnapshotError::CurrentVmNotInHeadRoster {
            vm_id: current_verification_method.id.clone(),
        });
    }

    Ok(IdentitySnapshot {
        did,
        genesis_roster,
        roster_chain,
        current_verification_method,
        approved_claims,
    })
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AttestedBy, EmbeddedVerificationMethod, VerificationMethod};

    fn make_vm(did: &str, device_id: &str) -> VerificationMethod {
        VerificationMethod {
            id: format!("{did}#{device_id}"),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did.into(),
            public_key_multibase: format!("zFake-{device_id}"),
        }
    }

    fn make_embedded_vm(did: &str, device_id: &str) -> EmbeddedVerificationMethod {
        EmbeddedVerificationMethod {
            id: format!("{did}#{device_id}"),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: did.into(),
            public_key_multibase: format!("zFake-{device_id}"),
        }
    }

    fn make_genesis(did: &str, device_id: &str) -> EmbeddedGenesisRoster {
        EmbeddedGenesisRoster {
            version: 1,
            did: did.into(),
            verification_methods: vec![make_vm(did, device_id)],
            signed_at: 1_700_000_000,
            self_signed_by_genesis_key: "placeholder".into(),
        }
    }

    fn empty_claims() -> BTreeMap<String, ClaimValue> {
        let mut m = BTreeMap::new();
        m.insert(
            "did".into(),
            ClaimValue {
                value: serde_json::Value::String("did:mata:abc".into()),
                attested_by: AttestedBy::SelfAttested,
                verified_at_signup: None,
                computed_at: None,
                formula_version: None,
            },
        );
        m
    }

    // ─── Happy paths ───────────────────────────────────────────────────────

    #[test]
    fn assembles_single_device_snapshot() {
        let did = "did:mata:abc".to_string();
        let snapshot = assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![],
            make_embedded_vm(&did, "dev-laptop"),
            empty_claims(),
        )
        .unwrap();

        assert_eq!(snapshot.did, did);
        assert_eq!(snapshot.roster_chain.len(), 0);
    }

    #[test]
    fn assembles_two_device_snapshot() {
        let did = "did:mata:abc".to_string();
        let chain_entry = EmbeddedRosterChainEntry {
            version: 2,
            did: did.clone(),
            verification_methods: vec![
                make_vm(&did, "dev-laptop"),
                make_vm(&did, "dev-phone"),
            ],
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };

        let snapshot = assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![chain_entry],
            make_embedded_vm(&did, "dev-phone"),
            empty_claims(),
        )
        .unwrap();

        assert_eq!(snapshot.roster_chain.len(), 1);
        assert_eq!(snapshot.current_verification_method.id, format!("{did}#dev-phone"));
    }

    // ─── Failure modes ─────────────────────────────────────────────────────

    #[test]
    fn rejects_genesis_with_wrong_version() {
        let did = "did:mata:abc".to_string();
        let mut genesis = make_genesis(&did, "dev-laptop");
        genesis.version = 2;

        match assemble_identity_snapshot(
            did.clone(),
            genesis,
            vec![],
            make_embedded_vm(&did, "dev-laptop"),
            empty_claims(),
        ) {
            Err(SnapshotError::GenesisVersionNotOne { got: 2 }) => {}
            other => panic!("expected GenesisVersionNotOne, got {other:?}"),
        }
    }

    #[test]
    fn rejects_genesis_did_mismatch() {
        let did = "did:mata:abc".to_string();
        let mut genesis = make_genesis(&did, "dev-laptop");
        genesis.did = "did:mata:somebody-else".into();

        match assemble_identity_snapshot(
            did.clone(),
            genesis,
            vec![],
            make_embedded_vm(&did, "dev-laptop"),
            empty_claims(),
        ) {
            Err(SnapshotError::DidMismatch { which, found_did, .. }) => {
                assert_eq!(which, "genesis");
                assert_eq!(found_did, "did:mata:somebody-else");
            }
            other => panic!("expected DidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_chain_entry_did_mismatch() {
        let did = "did:mata:abc".to_string();
        let bad_entry = EmbeddedRosterChainEntry {
            version: 2,
            did: "did:mata:other".into(),
            verification_methods: vec![make_vm(&did, "dev-laptop")],
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };

        match assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![bad_entry],
            make_embedded_vm(&did, "dev-laptop"),
            empty_claims(),
        ) {
            Err(SnapshotError::DidMismatch { which, .. }) => {
                assert!(which.contains("chain entry version 2"));
            }
            other => panic!("expected DidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_first_chain_entry_wrong_version() {
        let did = "did:mata:abc".to_string();
        let bad_entry = EmbeddedRosterChainEntry {
            version: 5,
            did: did.clone(),
            verification_methods: vec![make_vm(&did, "dev-laptop")],
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };

        match assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![bad_entry],
            make_embedded_vm(&did, "dev-laptop"),
            empty_claims(),
        ) {
            Err(SnapshotError::FirstChainEntryWrongVersion { got: 5 }) => {}
            other => panic!("expected FirstChainEntryWrongVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_monotonic_chain() {
        let did = "did:mata:abc".to_string();
        let entry_v2 = EmbeddedRosterChainEntry {
            version: 2,
            did: did.clone(),
            verification_methods: vec![make_vm(&did, "dev-laptop")],
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };
        let entry_v2_again = EmbeddedRosterChainEntry {
            version: 2,
            did: did.clone(),
            verification_methods: vec![make_vm(&did, "dev-laptop")],
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };

        match assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![entry_v2, entry_v2_again],
            make_embedded_vm(&did, "dev-laptop"),
            empty_claims(),
        ) {
            Err(SnapshotError::ChainVersionNotMonotonic {
                entry_version: 2,
                prior_version: 2,
            }) => {}
            other => panic!("expected ChainVersionNotMonotonic, got {other:?}"),
        }
    }

    #[test]
    fn rejects_current_vm_with_wrong_controller() {
        let did = "did:mata:abc".to_string();
        let mut vm = make_embedded_vm(&did, "dev-laptop");
        vm.controller = "did:mata:different".into();

        match assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![],
            vm,
            empty_claims(),
        ) {
            Err(SnapshotError::CurrentVmDidMismatch { .. }) => {}
            other => panic!("expected CurrentVmDidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_current_vm_not_in_head_roster() {
        let did = "did:mata:abc".to_string();
        let mut vm = make_embedded_vm(&did, "dev-phone");
        // Phone's controller is the snapshot DID (passes step 6), but
        // it's not in the genesis roster (which only has dev-laptop).
        vm.controller = did.clone();

        match assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![],
            vm,
            empty_claims(),
        ) {
            Err(SnapshotError::CurrentVmNotInHeadRoster { vm_id }) => {
                assert!(vm_id.ends_with("#dev-phone"));
            }
            other => panic!("expected CurrentVmNotInHeadRoster, got {other:?}"),
        }
    }

    #[test]
    fn uses_chain_head_when_chain_is_non_empty() {
        // dev-laptop is in genesis, dev-phone is added in entry v2.
        // Current device is dev-phone, which is only in the chain head.
        // Should succeed.
        let did = "did:mata:abc".to_string();
        let chain_entry = EmbeddedRosterChainEntry {
            version: 2,
            did: did.clone(),
            verification_methods: vec![
                make_vm(&did, "dev-laptop"),
                make_vm(&did, "dev-phone"),
            ],
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };

        assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![chain_entry],
            make_embedded_vm(&did, "dev-phone"),
            empty_claims(),
        )
        .expect("dev-phone is in head roster (chain entry v2)");
    }

    #[test]
    fn rejects_revoked_device_via_chain_omission() {
        // dev-laptop is in genesis. Chain v2 ADDS dev-phone but REMOVES
        // dev-laptop. Trying to sign with dev-laptop should fail because
        // it's no longer in the head roster.
        let did = "did:mata:abc".to_string();
        let chain_revoking_laptop = EmbeddedRosterChainEntry {
            version: 2,
            did: did.clone(),
            verification_methods: vec![make_vm(&did, "dev-phone")], // laptop excluded
            signed_at: 1_710_000_000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev-laptop".into(),
        };

        match assemble_identity_snapshot(
            did.clone(),
            make_genesis(&did, "dev-laptop"),
            vec![chain_revoking_laptop],
            make_embedded_vm(&did, "dev-laptop"), // trying to sign with revoked device
            empty_claims(),
        ) {
            Err(SnapshotError::CurrentVmNotInHeadRoster { vm_id }) => {
                assert!(vm_id.ends_with("#dev-laptop"));
            }
            other => panic!("expected CurrentVmNotInHeadRoster, got {other:?}"),
        }
    }
}
