//! The roster lifecycle of one derived identity, seen from a relying party
//! (DID-logins M4, ADR 0011 D5).
//!
//! One person, one vault key, one DID. Every device derives the same root and
//! the same canonical genesis (`device-0`, the frozen epoch), so a relying
//! party anchors every device on one hash. Devices then enter the roster as
//! chain entries signed by a rostered key, sign their own tokens under
//! `device-<id>`, can be revoked by another rostered device, and once every
//! device is rostered the root retires — after which a vault alone signs
//! nothing a relying party accepts.
//!
//! These tests mint real JWTs and drive the real [`Authenticator`] with its
//! anchor store, so each expectation is what a deployed RP would do.

use kms_client::InMemoryDeviceSigner;

use crate::test_fixtures::{
    make_signing_key, mint_jwt, sign_chain_entry, sign_genesis, DeviceKey, IdentityFixture,
};
use crate::{Authenticator, RpError, VerifyError, VerifyParams};
use mid_issuer::{
    build_mid_jwt, AttestedBy, ClaimRequest, ClaimValue, EmbeddedGenesisRoster,
    EmbeddedRosterChainEntry, IdentitySnapshot, MidIssuerError, MidJwtPayload, RpRequest,
    VerificationMethod,
};
use std::collections::BTreeMap;

const RP: &str = "https://acme.com";
/// `mata_identity::MID_DERIVED_GENESIS_EPOCH` (2025-09-30T00:00Z; the value is arbitrary and frozen), the frozen
/// `signed_at` of every canonical genesis. Spelled out here because this crate
/// is open-core and depends on nothing proprietary; the vector of record pins
/// the same value.
const EPOCH: u64 = 1_759_190_400;
const IAT: u64 = EPOCH + 60;
const NOW: u64 = IAT + 10;
const ROOT_KID: &str = "device-0";

/// The person: a root as `device-0` (stands in for the derived `#root`) and
/// two devices with their own M5 keys.
struct Person {
    identity: IdentityFixture,
    alienware: DeviceKey,
    macbook: DeviceKey,
}

impl Person {
    fn new() -> Self {
        Self {
            identity: IdentityFixture::new("vault-derived-root", ROOT_KID),
            alienware: DeviceKey::new("m5-alienware", "device-alienware"),
            macbook: DeviceKey::new("m5-macbook", "device-macbook"),
        }
    }

    fn did(&self) -> String {
        self.identity.did()
    }

    fn root_vm(&self) -> VerificationMethod {
        self.identity.vm_for(&self.identity.genesis)
    }

    /// The canonical genesis, self-signed by the root. Each call signs anew,
    /// which is exactly what two devices deriving it independently do.
    fn canonical_genesis(&self) -> EmbeddedGenesisRoster {
        let mut genesis = EmbeddedGenesisRoster {
            version: 1,
            did: self.did(),
            verification_methods: vec![self.root_vm()],
            signed_at: EPOCH,
            self_signed_by_genesis_key: String::new(),
        };
        genesis.self_signed_by_genesis_key =
            sign_genesis(&genesis, &self.identity.genesis.signing_key);
        genesis
    }

    /// One chain link: `new_vms` becomes the head at `version`, signed by
    /// `signer` under `signer_kid`.
    fn link(
        &self,
        version: u64,
        new_vms: Vec<VerificationMethod>,
        signer_kid: &str,
        signer: &DeviceKey,
    ) -> EmbeddedRosterChainEntry {
        let mut entry = EmbeddedRosterChainEntry {
            version,
            did: self.did(),
            verification_methods: new_vms,
            signed_at: EPOCH + 100 * version,
            signed_by_signer_in_prior_roster: String::new(),
            signer_kid: signer_kid.to_string(),
        };
        entry.signed_by_signer_in_prior_roster = sign_chain_entry(&entry, &signer.signing_key);
        entry
    }

    /// v2: the root adds both devices — what `bootstrap_roster` appends on the
    /// first boot where every paired device has announced under the DID.
    fn v2_root_adds_both(&self) -> EmbeddedRosterChainEntry {
        self.link(
            2,
            vec![
                self.root_vm(),
                self.identity.vm_for(&self.alienware),
                self.identity.vm_for(&self.macbook),
            ],
            ROOT_KID,
            &self.identity.genesis,
        )
    }

    /// v3: the Alienware removes the MacBook, signed with its own rostered key
    /// — `revoke_device` riding `paired_devices_store::remove`.
    fn v3_alienware_revokes_macbook(&self) -> EmbeddedRosterChainEntry {
        self.link(
            3,
            vec![self.root_vm(), self.identity.vm_for(&self.alienware)],
            "device-alienware",
            &self.alienware,
        )
    }

    /// v4: the Alienware retires the root — `maybe_retire_root` once every
    /// admitted device is in the head and this device signs with its own key.
    fn v4_alienware_retires_root(&self) -> EmbeddedRosterChainEntry {
        self.link(
            4,
            vec![self.identity.vm_for(&self.alienware)],
            "device-alienware",
            &self.alienware,
        )
    }

    /// The wallet state a device presents: the canonical genesis (signed by
    /// this device's own derivation), the chain it has synced, and its own
    /// verification method as the signer.
    fn snapshot(&self, chain: Vec<EmbeddedRosterChainEntry>, device: &DeviceKey) -> IdentitySnapshot {
        let mut approved = BTreeMap::new();
        approved.insert(
            "did".into(),
            ClaimValue {
                value: serde_json::Value::String(self.did()),
                attested_by: AttestedBy::SelfAttested,
                verified_at_signup: None,
                computed_at: None,
                formula_version: None,
            },
        );
        IdentitySnapshot {
            did: self.did(),
            genesis_roster: self.canonical_genesis(),
            roster_chain: chain,
            current_verification_method: self.identity.embedded_vm_for(device),
            approved_claims: approved,
        }
    }

    fn signer_for(&self, device: &DeviceKey, seed: &str) -> InMemoryDeviceSigner {
        InMemoryDeviceSigner::new(device.device_id.clone(), make_signing_key(seed))
    }

    /// What an honest wallet does: ask the issuer for a token. The issuer's
    /// pre-flight refuses when this device's key is not in the head roster —
    /// a vault without a rostered device key cannot sign, before any RP is
    /// involved.
    fn mint_attempt(
        &self,
        chain: Vec<EmbeddedRosterChainEntry>,
        device: &DeviceKey,
        seed: &str,
    ) -> Result<String, MidIssuerError> {
        let snapshot = self.snapshot(chain, device);
        let signer = self.signer_for(device, seed);
        let req = RpRequest {
            rp_origin: RP.into(),
            nonce: "n".into(),
            claims: ClaimRequest { required: vec!["did".into()], optional: vec![], custom: BTreeMap::new() },
        };
        build_mid_jwt(&req, &snapshot, &signer, IAT)
    }

    /// What a dishonest wallet does: skip the issuer's pre-flight and sign the
    /// payload anyway. This is the token a relying party must still reject.
    fn forge_jwt(
        &self,
        chain: Vec<EmbeddedRosterChainEntry>,
        device: &DeviceKey,
        seed: &str,
        nonce: &str,
    ) -> String {
        let snapshot = self.snapshot(chain, device);
        let signer = self.signer_for(device, seed);
        let payload = MidJwtPayload {
            iss: snapshot.did.clone(),
            sub: snapshot.did.clone(),
            aud: RP.into(),
            iat: IAT,
            exp: IAT + 300,
            nonce: nonce.into(),
            claims: snapshot.approved_claims.clone(),
            embedded_genesis_roster: snapshot.genesis_roster.clone(),
            embedded_roster_chain: snapshot.roster_chain.clone(),
            embedded_verification_method: snapshot.current_verification_method.clone(),
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();
        mid_issuer::jws::build_jws_compact(&payload_json, &signer).expect("raw JWS")
    }

    /// Sign in as `device` presenting `chain` at `auth`.
    fn sign_in(
        &self,
        auth: &Authenticator,
        chain: Vec<EmbeddedRosterChainEntry>,
        device: &DeviceKey,
        seed: &str,
    ) -> Result<crate::RpSession, RpError> {
        let snapshot = self.snapshot(chain, device);
        let signer = self.signer_for(device, seed);
        let nonce = auth.issue_nonce(NOW).unwrap();
        let jwt = mint_jwt(&snapshot, &signer, RP, &nonce, IAT);
        auth.authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
    }
}

/// Two devices of one person, each deriving the genesis on its own, sign in
/// at one relying party under their own keys, on one anchor, at roster v2.
#[test]
fn two_devices_authenticate_at_one_relying_party_on_one_anchor() {
    let p = Person::new();
    let auth = Authenticator::in_memory();
    let chain = vec![p.v2_root_adds_both()];

    let a = p
        .sign_in(&auth, chain.clone(), &p.alienware, "m5-alienware")
        .expect("the Alienware signs in under device-alienware");
    let b = p
        .sign_in(&auth, chain.clone(), &p.macbook, "m5-macbook")
        .expect("the MacBook signs in under device-macbook, on the anchor the Alienware set");
    assert_eq!(a.did, p.did());
    assert_eq!(b.did, p.did());
    assert_eq!(a.current_version, 2);
    assert_eq!(b.current_version, 2);

    // The root itself still signs while `device-0` is in the head.
    let r = p
        .sign_in(&auth, chain, &p.identity.genesis, "vault-derived-root")
        .expect("the root signs as device-0 until retired");
    assert_eq!(r.current_version, 2);
}

/// A device that arrives with only the genesis (roster v1) after another
/// device has already presented v2 is a rollback, exactly as a stolen device
/// replaying an old state would be — the gate in `bootstrap_roster` exists so
/// this never happens to a legitimate device.
#[test]
fn a_device_behind_the_roster_head_reads_as_a_rollback() {
    let p = Person::new();
    let auth = Authenticator::in_memory();
    p.sign_in(&auth, vec![p.v2_root_adds_both()], &p.alienware, "m5-alienware")
        .expect("v2 seen");
    let err = p
        .sign_in(&auth, vec![], &p.identity.genesis, "vault-derived-root")
        .unwrap_err();
    assert!(
        matches!(err, RpError::Rollback { presented: 1, last_seen: 2, .. }),
        "got {err:?}"
    );
}

/// Revocation: the Alienware removes the MacBook with its own rostered key.
/// The MacBook's wallet then refuses to mint at all (its key is not in the
/// head); a forged token is refused by every relying party that sees the new
/// chain (`CurrentVmNotInHeadRoster`); and presenting the old head it was
/// still in is a rollback at any that saw v3.
#[test]
fn a_revoked_device_is_refused_and_its_old_head_is_a_rollback() {
    let p = Person::new();
    let auth = Authenticator::in_memory();
    let v2 = p.v2_root_adds_both();
    let v3 = p.v3_alienware_revokes_macbook();

    // Both in, then the revocation lands and the Alienware presents it.
    p.sign_in(&auth, vec![v2.clone()], &p.macbook, "m5-macbook")
        .expect("the MacBook was rostered at v2");
    let a = p
        .sign_in(&auth, vec![v2.clone(), v3.clone()], &p.alienware, "m5-alienware")
        .expect("a device-signed removal verifies");
    assert_eq!(a.current_version, 3);

    // The honest MacBook wallet with the honest chain: its issuer refuses.
    let err = p
        .mint_attempt(vec![v2.clone(), v3.clone()], &p.macbook, "m5-macbook")
        .unwrap_err();
    assert!(matches!(err, MidIssuerError::SignerNotInHeadRoster(_)), "got {err:?}");

    // A forged MacBook token over the honest chain: the RP refuses too.
    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = p.forge_jwt(vec![v2.clone(), v3.clone()], &p.macbook, "m5-macbook", &nonce);
    let err = auth
        .authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
        .unwrap_err();
    assert!(
        matches!(err, RpError::Verify(VerifyError::CurrentVmNotInHeadRoster { .. })),
        "got {err:?}"
    );

    // The MacBook replaying the head it was still in: a rollback.
    let err = p
        .sign_in(&auth, vec![v2.clone()], &p.macbook, "m5-macbook")
        .unwrap_err();
    assert!(
        matches!(err, RpError::Rollback { presented: 2, last_seen: 3, .. }),
        "got {err:?}"
    );

    // And the revoked key cannot sign a link that re-admits itself: the
    // issuer lets it through (its own forged head lists it), the RP does not.
    let forged = p.link(
        4,
        vec![p.root_vm(), p.identity.vm_for(&p.alienware), p.identity.vm_for(&p.macbook)],
        "device-macbook",
        &p.macbook,
    );
    let err = p
        .sign_in(&auth, vec![v2, v3, forged], &p.macbook, "m5-macbook")
        .unwrap_err();
    assert!(
        matches!(err, RpError::Verify(VerifyError::ChainSignerNotInPriorRoster { .. })),
        "got {err:?}"
    );
}

/// Root retirement: once every admitted device is rostered, the Alienware
/// drops `device-0`. From then on the vault alone — the root key — signs
/// nothing: its wallet refuses to mint, a forged token is refused by the RP,
/// and it cannot sign a link to get back in. The rostered device keeps
/// signing in and can still admit devices.
#[test]
fn after_root_retirement_the_vault_alone_cannot_sign() {
    let p = Person::new();
    let auth = Authenticator::in_memory();
    let v2 = p.v2_root_adds_both();
    let v3 = p.v3_alienware_revokes_macbook();
    let v4 = p.v4_alienware_retires_root();
    let chain = vec![v2, v3, v4];

    let a = p
        .sign_in(&auth, chain.clone(), &p.alienware, "m5-alienware")
        .expect("the rostered device signs in after retirement");
    assert_eq!(a.current_version, 4);

    // The honest root wallet with the honest chain: its issuer refuses.
    let err = p
        .mint_attempt(chain.clone(), &p.identity.genesis, "vault-derived-root")
        .unwrap_err();
    assert!(matches!(err, MidIssuerError::SignerNotInHeadRoster(_)), "got {err:?}");

    // A forged root token over the honest chain: `device-0` is not in the head.
    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = p.forge_jwt(chain.clone(), &p.identity.genesis, "vault-derived-root", &nonce);
    let err = auth
        .authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
        .unwrap_err();
    assert!(
        matches!(err, RpError::Verify(VerifyError::CurrentVmNotInHeadRoster { .. })),
        "a vault without a rostered device key cannot sign in: got {err:?}"
    );

    // The root presenting the chain from before its retirement: a rollback.
    let err = p
        .sign_in(&auth, chain[..2].to_vec(), &p.identity.genesis, "vault-derived-root")
        .unwrap_err();
    assert!(
        matches!(err, RpError::Rollback { presented: 3, last_seen: 4, .. }),
        "got {err:?}"
    );

    // The root signing a link that re-adds itself: not a signer in the prior roster.
    let mut readd = chain.clone();
    readd.push(p.link(
        5,
        vec![p.identity.vm_for(&p.alienware), p.root_vm()],
        ROOT_KID,
        &p.identity.genesis,
    ));
    let err = p
        .sign_in(&auth, readd, &p.identity.genesis, "vault-derived-root")
        .unwrap_err();
    assert!(
        matches!(err, RpError::Verify(VerifyError::ChainSignerNotInPriorRoster { .. })),
        "got {err:?}"
    );

    // A rostered device can still add a device after retirement.
    let mut readmit = chain;
    readmit.push(p.link(
        5,
        vec![p.identity.vm_for(&p.alienware), p.identity.vm_for(&p.macbook)],
        "device-alienware",
        &p.alienware,
    ));
    let b = p
        .sign_in(&auth, readmit, &p.macbook, "m5-macbook")
        .expect("re-admitted by a rostered device key, no root needed");
    assert_eq!(b.current_version, 5);
}

/// The anchor never moves: a genesis that is not the canonical one — the
/// pre-ADR-0011 profile-stamped anchor a stale cache could still hold — is a
/// different identity to a relying party that anchored the canonical hash.
#[test]
fn a_legacy_anchor_is_a_different_identity_to_the_relying_party() {
    let p = Person::new();
    let auth = Authenticator::in_memory();
    p.sign_in(&auth, vec![], &p.identity.genesis, "vault-derived-root")
        .expect("canonical genesis anchored");

    let mut stale = p.snapshot(vec![], &p.identity.genesis);
    stale.genesis_roster.signed_at = EPOCH - 12_345; // a profile stamp
    stale.genesis_roster.self_signed_by_genesis_key =
        sign_genesis(&stale.genesis_roster, &p.identity.genesis.signing_key);
    let signer = p.signer_for(&p.identity.genesis, "vault-derived-root");
    let nonce = auth.issue_nonce(NOW).unwrap();
    let jwt = mint_jwt(&stale, &signer, RP, &nonce, IAT);
    let err = auth
        .authenticate(&jwt, &VerifyParams::new(RP, &nonce, NOW))
        .unwrap_err();
    assert!(matches!(err, RpError::GenesisMismatch { .. }), "got {err:?}");
}
