//! The verification engine itself.

use std::collections::HashSet;
use std::sync::Arc;

use kms_types::{
    is_valid_did, NonceEnvelope, RosterUpdate, SignedAssertion, VerifyError,
    ROSTER_SIGNED_AT_TOLERANCE_SECS,
};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};

use crate::{Clock, DidResolver, NonceGenerator, NonceStore, SystemClock, SystemNonceGenerator};

/// The successful result of a verification.
///
/// Returned to the caller (e.g., the banking proxy's endpoint handler) so it
/// knows *who* it just authenticated and *what* operation they're allowed to
/// perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The verified DID (subject of the assertion).
    pub did: String,
    /// The roster device that signed the assertion. Useful for audit logs
    /// ("device X on the laptop just spent your banking access at 14:02").
    pub device_id: String,
    /// The verified purpose (copied verbatim from the signed envelope).
    pub purpose: String,
    /// The roster version that was current at verify time. Callers that
    /// want strong guarantees against TOCTOU revocation races can pass this
    /// through to downstream calls.
    pub roster_version: u64,
}

/// Verification engine. One instance per `(audience, issuer)` pair.
///
/// A banking-proxy will have one `Verifier` whose audience is `"kms-banking"`
/// and whose issuer is `"kms-banking-proxy"`. A future OIDC adapter will have
/// its own `Verifier` with audience `"kms-oidc"` and issuer `"kms-oidc-adapter"`.
/// The two cannot accept each other's signed assertions even if they share a
/// nonce store, because the audience and issuer fields are part of the
/// signed canonical bytes.
pub struct Verifier {
    issuer: String,
    audience: String,
    allowed_purposes: HashSet<String>,
    nonce_store: Arc<dyn NonceStore>,
    resolver: Arc<dyn DidResolver>,
    clock: Arc<dyn Clock>,
    nonce_generator: Arc<dyn NonceGenerator>,
    nonce_ttl_secs: u64,
}

impl Verifier {
    /// Build a new verifier with [`SystemClock`] and [`SystemNonceGenerator`].
    /// Use [`Verifier::with_clock`] / [`Verifier::with_nonce_generator`] to
    /// inject test fakes.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        allowed_purposes: impl IntoIterator<Item = String>,
        nonce_store: Arc<dyn NonceStore>,
        resolver: Arc<dyn DidResolver>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            allowed_purposes: allowed_purposes.into_iter().collect(),
            nonce_store,
            resolver,
            clock: Arc::new(SystemClock),
            nonce_generator: Arc::new(SystemNonceGenerator),
            nonce_ttl_secs: 30,
        }
    }

    /// Override the clock (tests).
    /// The DID resolver this verifier reads rosters from.
    ///
    /// Exposed because verifying an assertion is not the only reason to need a DID
    /// document. Self-service enrollment has to check a signature made by a **third**
    /// party — the device being claimed, which is not the caller — and the roster that
    /// says which keys speak for that device is exactly what a resolver returns. Giving
    /// the caller its own resolver would mean two configured registry URLs that could
    /// disagree about who a DID is, which is the sort of drift nobody notices until a
    /// signature is rejected for reasons no log explains.
    pub fn resolver(&self) -> &Arc<dyn DidResolver> {
        &self.resolver
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Override the nonce generator (tests).
    pub fn with_nonce_generator(mut self, gen: Arc<dyn NonceGenerator>) -> Self {
        self.nonce_generator = gen;
        self
    }

    /// Override the nonce TTL. Default is 30s. Verifier rejects values > 300s
    /// at validate time (spec hard cap).
    pub fn with_nonce_ttl_secs(mut self, secs: u64) -> Self {
        self.nonce_ttl_secs = secs;
        self
    }

    /// Issue a fresh nonce for `(did, purpose)` against this verifier's
    /// configured audience and issuer.
    ///
    /// Failure modes:
    /// - [`VerifyError::MalformedDid`] — `did` isn't `did:mata:<base58>`.
    /// - [`VerifyError::UnknownPurpose`] — `purpose` isn't in the allow-list.
    /// - [`VerifyError::StorageError`] — nonce store rejected the write.
    pub async fn issue_nonce(
        &self,
        did: &str,
        purpose: &str,
    ) -> Result<NonceEnvelope, VerifyError> {
        if !is_valid_did(did) {
            return Err(VerifyError::MalformedDid);
        }
        if !self.allowed_purposes.contains(purpose) {
            return Err(VerifyError::UnknownPurpose);
        }
        let now = self.clock.now_secs();
        let envelope = NonceEnvelope {
            envelope_version: NonceEnvelope::CURRENT_VERSION,
            envelope_type: NonceEnvelope::TYPE.to_string(),
            nonce: self.nonce_generator.random_32().to_vec(),
            did: did.to_string(),
            audience: self.audience.clone(),
            purpose: purpose.to_string(),
            issued_at: now,
            expires_at: now + self.nonce_ttl_secs,
            issuer: self.issuer.clone(),
        };
        // Shape sanity-check the envelope we just minted. If this fails,
        // it's a verifier bug (misconfigured TTL, etc.) — fail fast.
        envelope.validate()?;
        self.nonce_store.put(&envelope).await?;
        Ok(envelope)
    }

    /// Verify a signed assertion against `expected_purpose`.
    ///
    /// On success returns [`VerifiedIdentity`]. On any failure returns a
    /// typed [`VerifyError`]; per
    /// [envelope_spec.md §"Error taxonomy"](../../../docs/kms/envelope_spec.md)
    /// the caller should surface all failure variants as a single opaque
    /// `"invalid assertion"` response to the client and log the granular
    /// variant for ops.
    ///
    /// See [crate-level docs](crate) for the full check ordering rationale.
    pub async fn verify(
        &self,
        assertion: &SignedAssertion,
        expected_purpose: &str,
    ) -> Result<VerifiedIdentity, VerifyError> {
        // 1. Shape check.
        assertion.validate()?;

        let env = &assertion.nonce_envelope;

        // 2. Audience match (verifier's configured audience).
        if env.audience != self.audience {
            return Err(VerifyError::AudienceMismatch);
        }

        // 3. Purpose match (endpoint's expected purpose). Belt-and-braces: we
        // also confirm it's in the allow-list, defending against a verifier
        // configured to accept a purpose that the issuance side wouldn't mint.
        if env.purpose != expected_purpose {
            return Err(VerifyError::PurposeMismatch);
        }
        if !self.allowed_purposes.contains(&env.purpose) {
            return Err(VerifyError::UnknownPurpose);
        }

        // 4. Issuer match.
        if env.issuer != self.issuer {
            return Err(VerifyError::IssuerMismatch);
        }

        // 5. Resolve DID document.
        let did_doc = self.resolver.resolve(&env.did).await?;

        // 6. Find device in roster.
        let entry = did_doc
            .find_entry(&assertion.device_id)
            .ok_or(VerifyError::DeviceNotInRoster)?;

        // 7. Verify ECDSA P-256 signature against the canonical bytes of the
        //    embedded envelope.
        //
        //    Defense-in-depth: ECDSA signatures are malleable — for any valid
        //    (r, s), (r, -s mod n) is also valid. We enforce the canonical
        //    "low-s" form by rejecting any signature where `s` is in the
        //    upper half of the curve order. The `p256` crate's
        //    `SigningKey::sign()` already produces low-s by default, so
        //    legitimate clients are unaffected; an attacker who flipped `s`
        //    to its high counterpart gets `SignatureInvalid`. This kills the
        //    ECDSA malleability attack vector at the verifier.
        //
        //    `VerifyingKey::from_sec1_bytes` validates the point is on the
        //    curve and is not the identity — required for ECDSA safety.
        let verifying_key = VerifyingKey::from_sec1_bytes(&entry.pubkey)
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let sig_bytes: [u8; 64] = assertion
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::SignatureInvalid)?;
        // Reject high-s signatures explicitly. `normalize_s` returns Some(new)
        // if the input is high-s, in which case we reject; None if already low.
        if signature.normalize_s().is_some() {
            return Err(VerifyError::SignatureInvalid);
        }
        let canonical = env.canonical_bytes();
        verifying_key
            .verify_prehash(&canonical, &signature)
            .map_err(|_| VerifyError::SignatureInvalid)?;

        // 8. Consume the nonce (atomic check-and-delete). This is the one
        //    state mutation. By placing it after the signature verification
        //    we avoid burning a nonce on a corrupted-network-packet failure.
        let nonce_bytes: [u8; 32] = env
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::MalformedNonce)?;
        let now = self.clock.now_secs();
        let stored = self.nonce_store.consume(&nonce_bytes, now).await?;

        // 9. Tamper check: the envelope the verifier issued must equal the
        //    envelope embedded in the signed assertion. Defends against the
        //    case where a client signs a forged envelope that happens to
        //    share the issued random bytes but tampered audience/purpose/
        //    timestamps. Without this check, the signature verifies against
        //    the embedded (tampered) bytes but the user authorized something
        //    else.
        if stored != *env {
            return Err(VerifyError::MalformedEnvelope);
        }

        Ok(VerifiedIdentity {
            did: env.did.clone(),
            device_id: assertion.device_id.clone(),
            purpose: env.purpose.clone(),
            roster_version: did_doc.roster_version,
        })
    }

    /// Verify a [`RosterUpdate`] envelope. Used by the proxy's
    /// `/v1/internal/roster-update` endpoint to authorize a roster
    /// mutation before it lands in `kms_did_documents`.
    ///
    /// Unlike [`Self::verify`], a `RosterUpdate` carries its own
    /// freshness window (`signed_at` ±
    /// [`ROSTER_SIGNED_AT_TOLERANCE_SECS`]) instead of a nonce — roster
    /// mutations are a slower-cadence operation than per-call banking
    /// assertions, and the nonce dance would force every joining device
    /// to round-trip the proxy before it could be added by a sibling.
    ///
    /// Checks (in order):
    /// 1. Shape validation via [`RosterUpdate::validate`].
    /// 2. Resolve the DID document — [`VerifyError::DidNotFound`] if
    ///    the DID hasn't been bootstrapped.
    /// 3. `update.prior_version == did_doc.roster_version`
    ///    ([`VerifyError::StaleRosterVersion`] otherwise).
    /// 4. `update.signer_device_id` is in the **prior** roster
    ///    ([`VerifyError::DeviceNotInRoster`] otherwise).
    /// 5. ECDSA P-256 signature over `update.canonical_bytes()`
    ///    verifies under the signer's prior-roster pubkey, low-s
    ///    canonical form enforced.
    /// 6. `|now - signed_at| <= ROSTER_SIGNED_AT_TOLERANCE_SECS`
    ///    ([`VerifyError::RosterTimestampOutOfRange`] otherwise).
    ///
    /// Returns the verified `(signer_device_id, new_roster_version)` on
    /// success — the proxy passes both to the store + audit log.
    pub async fn verify_roster_update(
        &self,
        update: &RosterUpdate,
    ) -> Result<VerifiedRosterUpdate, VerifyError> {
        // 1. Shape.
        update.validate()?;

        // 2. Resolve current DID document.
        let did_doc = self.resolver.resolve(&update.did).await?;

        // 3. Monotonic version match against the on-server roster.
        if update.prior_version != did_doc.roster_version {
            return Err(VerifyError::StaleRosterVersion);
        }

        // 4. Signer must be in the PRIOR roster (the roster that's
        //    currently authoritative — what the resolver just returned).
        let signer_entry = did_doc
            .find_entry(&update.signer_device_id)
            .ok_or(VerifyError::DeviceNotInRoster)?;

        // 5. ECDSA P-256 signature, low-s enforced (matches the
        //    SignedAssertion verifier's malleability defense).
        let verifying_key = VerifyingKey::from_sec1_bytes(&signer_entry.pubkey)
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let sig_bytes: [u8; 64] = update
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::SignatureInvalid)?;
        if signature.normalize_s().is_some() {
            return Err(VerifyError::SignatureInvalid);
        }
        let canonical = update.canonical_bytes();
        verifying_key
            .verify_prehash(&canonical, &signature)
            .map_err(|_| VerifyError::SignatureInvalid)?;

        // 6. Freshness window. Done LAST so a slightly-stale signature
        //    can't burn server resources on the resolver round-trip —
        //    but we do the cheap shape + version checks before the
        //    resolver call too. Net: an attacker forging a fresh
        //    timestamp still pays the signature-verify cost.
        let now = self.clock.now_secs();
        let skew = now.abs_diff(update.signed_at);
        if skew > ROSTER_SIGNED_AT_TOLERANCE_SECS {
            return Err(VerifyError::RosterTimestampOutOfRange);
        }

        Ok(VerifiedRosterUpdate {
            did: update.did.clone(),
            signer_device_id: update.signer_device_id.clone(),
            new_roster_version: update.new_version,
        })
    }
}

/// Successful outcome of [`Verifier::verify_roster_update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRosterUpdate {
    /// The DID whose roster is being mutated.
    pub did: String,
    /// The device that signed this update — must have been in the prior
    /// roster. Logged for audit.
    pub signer_device_id: String,
    /// The new `roster_version` the store should set on success.
    /// Equals `update.new_version`.
    pub new_roster_version: u64,
}

// ── Genesis: the self-certifying bootstrap (did_document_v2.md §"Post-transition bootstrap") ──

/// The DID a P-256 public key names: `did:mata:` + base58 of the 33-byte
/// **compressed** SEC1 point. Accepts a 65-byte uncompressed or 33-byte compressed
/// key; anything else is not a key. This is the one place the string ↔ key
/// binding is computed, so a registry, a wallet and a verifier cannot disagree.
pub fn did_from_pubkey_sec1(pubkey: &[u8]) -> Result<String, VerifyError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| VerifyError::SignatureInvalid)?;
    let compressed = vk.to_encoded_point(true);
    Ok(format!(
        "did:mata:{}",
        bs58::encode(compressed.as_bytes()).into_string()
    ))
}

/// The inverse: the genesis public key a key-derived DID *is*, as 65-byte SEC1 uncompressed.
///
/// Kept beside [`did_from_pubkey_sec1`] because the two are one binding read in two
/// directions, and the string-to-key rule must live in exactly one place. A legacy
/// `did:mata:<uuid>` carries no key and is [`VerifyError::MalformedDid`]: a caller shaped
/// like that cannot be proven to hold any key from the DID alone, and a verifier must say
/// so rather than guess.
pub fn pubkey_sec1_from_did(did: &str) -> Result<Vec<u8>, VerifyError> {
    let suffix = did.strip_prefix("did:mata:").ok_or(VerifyError::MalformedDid)?;
    let bytes = bs58::decode(suffix).into_vec().map_err(|_| VerifyError::MalformedDid)?;
    if bytes.len() != 33 {
        return Err(VerifyError::MalformedDid);
    }
    let vk = VerifyingKey::from_sec1_bytes(&bytes).map_err(|_| VerifyError::MalformedDid)?;
    Ok(vk.to_encoded_point(false).as_bytes().to_vec())
}

/// Verify a **genesis** roster envelope — a [`RosterUpdate`] with `prior_version == 0`
/// and `new_version == 1` — with no prior document to consult. There is none: this
/// is how a DID comes into existence without a Supabase JWT or any other bearer.
///
/// The trust comes from the DID itself. The signer must be an entry of the new
/// roster, and that entry's public key must *derive the DID being claimed*
/// ([`did_from_pubkey_sec1`]); the signature is then verified under that key with
/// the same canonical bytes, low-s rule and freshness window as every other roster
/// update. Nobody can bootstrap a DID they do not hold the key for.
///
/// Pure: `now_unix` is a parameter, exactly like [`Verifier::verify_roster_update`].
pub fn verify_genesis(
    update: &RosterUpdate,
    now_unix: u64,
) -> Result<VerifiedRosterUpdate, VerifyError> {
    // 1. Shape — the same envelope, at version 0 → 1.
    update.validate()?;
    if update.prior_version != 0 || update.new_version != 1 {
        return Err(VerifyError::NonMonotonicVersion);
    }
    if update.new_roster.is_empty() {
        return Err(VerifyError::DeviceNotInRoster);
    }

    // 2. The signer is in the roster it is creating…
    let signer = update
        .new_roster
        .iter()
        .find(|e| e.device_id == update.signer_device_id)
        .ok_or(VerifyError::DeviceNotInRoster)?;

    // 3. …and its key IS the DID. A key-derived DID is the whole authorization.
    if did_from_pubkey_sec1(&signer.pubkey)? != update.did {
        return Err(VerifyError::SignatureInvalid);
    }

    // 4. Signature: low-s only, prehash over the canonical bytes.
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&signer.pubkey).map_err(|_| VerifyError::SignatureInvalid)?;
    let sig_bytes: [u8; 64] = update
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::SignatureInvalid)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::SignatureInvalid)?;
    if signature.normalize_s().is_some() {
        return Err(VerifyError::SignatureInvalid);
    }
    verifying_key
        .verify_prehash(&update.canonical_bytes(), &signature)
        .map_err(|_| VerifyError::SignatureInvalid)?;

    // 5. Freshness — the same 300 s window a roster update gets.
    if now_unix.abs_diff(update.signed_at) > ROSTER_SIGNED_AT_TOLERANCE_SECS {
        return Err(VerifyError::RosterTimestampOutOfRange);
    }

    Ok(VerifiedRosterUpdate {
        did: update.did.clone(),
        signer_device_id: update.signer_device_id.clone(),
        new_roster_version: update.new_version,
    })
}

#[cfg(test)]
mod genesis_tests {
    use super::*;
    use kms_types::RosterEntry;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    const NOW: u64 = 1_788_470_400;

    fn device() -> (SigningKey, Vec<u8>) {
        let key = SigningKey::random(&mut OsRng);
        let pubkey = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(pubkey.len(), 65);
        (key, pubkey)
    }

    fn genesis_for(key: &SigningKey, pubkey: &[u8], did: &str, signer_id: &str) -> RosterUpdate {
        let mut u = RosterUpdate {
            envelope_version: RosterUpdate::CURRENT_VERSION,
            envelope_type: RosterUpdate::TYPE.to_string(),
            did: did.to_string(),
            prior_version: 0,
            new_version: 1,
            new_roster: vec![RosterEntry {
                device_id: "dev-1".into(),
                pubkey: pubkey.to_vec(),
                added_at: NOW,
                label: "laptop".into(),
            }],
            signed_at: NOW,
            signer_device_id: signer_id.to_string(),
            signature: Vec::new(),
        };
        let sig: Signature = key.sign_prehash(&u.canonical_bytes()).unwrap();
        // hazmat signing does not normalize; the wallet path does, so match it here.
        let sig = sig.normalize_s().unwrap_or(sig);
        u.signature = sig.to_bytes().to_vec();
        u
    }

    #[test]
    fn a_key_derived_did_is_a_valid_base58_did() {
        let (_, pubkey) = device();
        let did = did_from_pubkey_sec1(&pubkey).unwrap();
        assert!(kms_types::is_valid_did(&did), "{did}");
        // compressed input names the same DID
        let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
        let compressed = vk.to_encoded_point(true);
        assert_eq!(did_from_pubkey_sec1(compressed.as_bytes()).unwrap(), did);
        assert!(did_from_pubkey_sec1(&[4u8; 10]).is_err(), "not a key");
    }

    #[test]
    fn a_self_signed_genesis_by_the_key_that_names_the_did_verifies() {
        let (key, pubkey) = device();
        let did = did_from_pubkey_sec1(&pubkey).unwrap();
        let u = genesis_for(&key, &pubkey, &did, "dev-1");
        let v = verify_genesis(&u, NOW + 10).unwrap();
        assert_eq!(v.did, did);
        assert_eq!(v.new_roster_version, 1);
        assert_eq!(v.signer_device_id, "dev-1");
    }

    #[test]
    fn a_did_the_key_does_not_name_is_refused() {
        let (key, pubkey) = device();
        let (_, other_pubkey) = device();
        let someone_else = did_from_pubkey_sec1(&other_pubkey).unwrap();
        // the signature is genuine, but this key does not own that DID
        let u = genesis_for(&key, &pubkey, &someone_else, "dev-1");
        assert!(matches!(
            verify_genesis(&u, NOW),
            Err(VerifyError::SignatureInvalid)
        ));
    }

    #[test]
    fn a_signer_outside_the_new_roster_is_refused() {
        let (key, pubkey) = device();
        let did = did_from_pubkey_sec1(&pubkey).unwrap();
        let u = genesis_for(&key, &pubkey, &did, "not-in-roster");
        assert!(matches!(
            verify_genesis(&u, NOW),
            Err(VerifyError::DeviceNotInRoster)
        ));
    }

    #[test]
    fn only_zero_to_one_is_a_genesis() {
        let (key, pubkey) = device();
        let did = did_from_pubkey_sec1(&pubkey).unwrap();
        let mut u = genesis_for(&key, &pubkey, &did, "dev-1");
        u.prior_version = 1;
        u.new_version = 2;
        let sig: Signature = key.sign_prehash(&u.canonical_bytes()).unwrap();
        // hazmat signing does not normalize; the wallet path does, so match it here.
        let sig = sig.normalize_s().unwrap_or(sig);
        u.signature = sig.to_bytes().to_vec();
        assert!(matches!(
            verify_genesis(&u, NOW),
            Err(VerifyError::NonMonotonicVersion)
        ));
    }

    #[test]
    fn a_tampered_or_stale_genesis_is_refused() {
        let (key, pubkey) = device();
        let did = did_from_pubkey_sec1(&pubkey).unwrap();
        let mut tampered = genesis_for(&key, &pubkey, &did, "dev-1");
        tampered.new_roster[0].label = "renamed after signing".into();
        assert!(matches!(
            verify_genesis(&tampered, NOW),
            Err(VerifyError::SignatureInvalid)
        ));

        let stale = genesis_for(&key, &pubkey, &did, "dev-1");
        assert!(matches!(
            verify_genesis(&stale, NOW + ROSTER_SIGNED_AT_TOLERANCE_SECS + 1),
            Err(VerifyError::RosterTimestampOutOfRange)
        ));
    }

    #[test]
    fn a_high_s_signature_is_refused_even_though_it_would_verify() {
        let (key, pubkey) = device();
        let did = did_from_pubkey_sec1(&pubkey).unwrap();
        let mut u = genesis_for(&key, &pubkey, &did, "dev-1");
        // flip s to its high counterpart (n - s): mathematically valid, canonically not
        let sig = Signature::from_slice(&u.signature).unwrap();
        let high_s = -*sig.s();
        let high = Signature::from_scalars(sig.r().to_bytes(), high_s.to_bytes()).unwrap();
        u.signature = high.to_bytes().to_vec();
        assert!(matches!(
            verify_genesis(&u, NOW),
            Err(VerifyError::SignatureInvalid)
        ));
    }

    /// **One binding, two directions.** A DID made from a key must give that key back,
    /// and a DID that carries no key must say so instead of inventing one.
    #[test]
    fn a_key_derived_did_round_trips_to_its_key() {
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let did = did_from_pubkey_sec1(&sec1).unwrap();
        assert_eq!(pubkey_sec1_from_did(&did).unwrap(), sec1);
        assert!(
            matches!(
                pubkey_sec1_from_did("did:mata:63c58bf2-ddfe-426c-9476-2f1625bc3f12"),
                Err(VerifyError::MalformedDid)
            ),
            "a legacy uuid DID carries no key"
        );
    }
}
