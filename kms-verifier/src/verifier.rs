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
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|_| VerifyError::SignatureInvalid)?;
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
