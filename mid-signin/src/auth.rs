use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::anchor::{AnchorStore, InMemoryAnchorStore};
use crate::error::RpError;
use crate::nonce::{InMemoryNonceStore, NonceStore};
use crate::session::{verify, RpSession, VerifyParams};

/// The full relying-party sign-in flow: cryptographic verification
/// (`mid-verify`) plus the stateful duties it leaves to the relying party —
/// single-use nonce enforcement and the genesis-anchor / rollback checks.
///
/// Backed by pluggable [`NonceStore`] and [`AnchorStore`] (`Arc`, so one
/// object — e.g. `RedbStore` — can serve as both). [`Authenticator::in_memory`]
/// wires up the process-local implementations.
pub struct Authenticator {
    nonces: Arc<dyn NonceStore>,
    anchors: Arc<dyn AnchorStore>,
}

impl Authenticator {
    /// Construct over explicit stores (e.g. persistent ones).
    pub fn new(nonces: Arc<dyn NonceStore>, anchors: Arc<dyn AnchorStore>) -> Self {
        Self { nonces, anchors }
    }

    /// A process-local authenticator backed by in-memory stores. Anchors and
    /// live nonces vanish on restart — fine for development; production
    /// wants `RedbStore` or custom trait impls over the app's database.
    pub fn in_memory() -> Self {
        Self {
            nonces: Arc::new(InMemoryNonceStore::new()),
            anchors: Arc::new(InMemoryAnchorStore::new()),
        }
    }

    /// Issue a fresh single-use nonce to embed in a sign-in request.
    pub fn issue_nonce(&self, now_unix_secs: u64) -> Result<String, RpError> {
        self.nonces.issue(now_unix_secs)
    }

    /// Run the full flow and return the authenticated [`RpSession`]:
    ///
    /// 1. Verify the token cryptographically (signature, audience, nonce
    ///    equality, expiry, roster chain). A failure here does **not**
    ///    consume the nonce, so a legitimate retry remains possible.
    /// 2. Consume the expected nonce; if it was not live, reject as replay.
    /// 3. Check the DID's genesis anchor and version monotonicity, recording
    ///    the new high-water version.
    pub fn authenticate(&self, jwt: &str, params: &VerifyParams) -> Result<RpSession, RpError> {
        let session = verify(jwt, params)?;
        if !self
            .nonces
            .consume(&params.expected_nonce, params.now_unix_secs)?
        {
            return Err(RpError::NonceRejected);
        }
        self.anchors.check_and_update(
            &session.did,
            &session.genesis_roster_hash,
            session.current_version,
        )?;
        Ok(session)
    }

    /// [`Authenticator::authenticate`] without the caller tracking which
    /// nonce belongs to which sign-in: the expected nonce is read from the
    /// token's own echoed `nonce` field, then required to be **live in the
    /// nonce store**.
    ///
    /// Sound because the peeked value is only a *lookup key*: `mid-verify`
    /// re-checks nonce equality under the signature, and the real defense —
    /// "we issued it, and it is single-use" — is enforced by the store. A
    /// forged or replayed nonce fails at consumption. This is the pattern
    /// the drop-in HTTP routes use (the SIWE model: no server-side session
    /// needed before sign-in).
    pub fn authenticate_with_embedded_nonce(
        &self,
        jwt: &str,
        expected_audience: &str,
        now_unix_secs: u64,
        max_iat_skew_secs: u64,
    ) -> Result<RpSession, RpError> {
        let nonce = peek_nonce(jwt)?;
        let params = VerifyParams {
            expected_audience: expected_audience.to_owned(),
            expected_nonce: nonce,
            now_unix_secs,
            max_iat_skew_secs,
        };
        self.authenticate(jwt, &params)
    }
}

/// Read the echoed `nonce` from a JWS compact-form mID token **without
/// verifying it**. The value is untrusted until [`Authenticator::authenticate`]
/// has both verified the signature and consumed the nonce from the store —
/// never use it for anything but that lookup.
pub fn peek_nonce(jwt: &str) -> Result<String, RpError> {
    #[derive(Deserialize)]
    struct NonceOnly {
        nonce: String,
    }
    let mut segments = jwt.split('.');
    let (_header, payload_b64) = match (segments.next(), segments.next(), segments.next()) {
        (Some(h), Some(p), Some(_sig)) if segments.next().is_none() => (h, p),
        _ => return Err(RpError::MalformedToken),
    };
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| RpError::MalformedToken)?;
    let peeked: NonceOnly =
        serde_json::from_slice(&payload_bytes).map_err(|_| RpError::MalformedToken)?;
    Ok(peeked.nonce)
}
