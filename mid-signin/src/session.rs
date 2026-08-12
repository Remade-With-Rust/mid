use std::collections::BTreeMap;

use mid_verify::{verify_mid_response, ClaimValue, VerifiedMid, VerifyConfig};

use crate::error::RpError;

/// Relying-party verification parameters for a single sign-in.
#[derive(Debug, Clone)]
pub struct VerifyParams {
    /// This RP's origin (the value passed as `rpOrigin` to the frontend
    /// SDK); must equal the token's `aud`.
    pub expected_audience: String,
    /// The single-use nonce this RP issued for this sign-in; must equal the
    /// token's echoed `nonce`.
    pub expected_nonce: String,
    /// The RP's current wall-clock time, Unix seconds.
    pub now_unix_secs: u64,
    /// Maximum allowed forward clock skew on the token's `iat`, in seconds.
    pub max_iat_skew_secs: u64,
}

impl VerifyParams {
    /// Construct with the default 120 s forward-skew allowance.
    pub fn new(
        expected_audience: impl Into<String>,
        expected_nonce: impl Into<String>,
        now_unix_secs: u64,
    ) -> Self {
        Self {
            expected_audience: expected_audience.into(),
            expected_nonce: expected_nonce.into(),
            now_unix_secs,
            max_iat_skew_secs: 120,
        }
    }
}

/// A verified mID identity for the current sign-in. Produced by [`verify`] /
/// [`crate::Authenticator::authenticate`]. Holds the user's DID, the claims
/// they disclosed, and the anchoring data (genesis hash + head version) the
/// relying party persists via its [`crate::AnchorStore`].
///
/// What the application does next — mint its own session cookie, upsert a
/// users row keyed on `did` — is deliberately out of this crate's scope.
#[derive(Debug, Clone)]
pub struct RpSession {
    /// The user's stable identifier: `did:mata:<base58-pubkey>`.
    pub did: String,
    /// Claims the user approved for disclosure, keyed by claim name
    /// (`"did"`, `"email"`, `"name"`, …). All `attested_by: self` in mID v1.
    pub claims: BTreeMap<String, ClaimValue>,
    /// Head-roster version of the presented chain (the rollback high-water
    /// mark the anchor store records).
    pub current_version: u64,
    /// Hash of the DID's self-signed genesis roster (the spoofing anchor).
    pub genesis_roster_hash: [u8; 32],
    /// Token issued-at, Unix seconds.
    pub iat: u64,
    /// Token expiry, Unix seconds.
    pub exp: u64,
    /// The audience the token was minted for (this RP's origin).
    pub aud: String,
}

impl RpSession {
    fn from_verified(verified: VerifiedMid) -> Self {
        Self {
            did: verified.did,
            claims: verified.claims,
            current_version: verified.current_version,
            genesis_roster_hash: verified.genesis_roster_hash,
            iat: verified.iat,
            exp: verified.exp,
            aud: verified.aud,
        }
    }

    /// Whether the token is at or past its expiry at `now_unix_secs`.
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.exp
    }

    /// `Ok` if the token has not expired, else [`RpError::SessionExpired`].
    pub fn ensure_valid(&self, now_unix_secs: u64) -> Result<(), RpError> {
        if self.is_expired(now_unix_secs) {
            Err(RpError::SessionExpired {
                exp: self.exp,
                now: now_unix_secs,
            })
        } else {
            Ok(())
        }
    }

    /// A disclosed claim by name (e.g. `"email"`).
    pub fn claim(&self, name: &str) -> Option<&ClaimValue> {
        self.claims.get(name)
    }

    /// A disclosed claim's value as a string, when it is one — the common
    /// case for `"did"`, `"email"`, and `"name"`.
    pub fn claim_str(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(|c| c.value.as_str())
    }
}

/// Run mID's cryptographic verification and produce an [`RpSession`].
///
/// This is the pure verification step. It does **not** enforce single-use of
/// the nonce or the genesis-anchor / rollback invariants — those are the
/// relying party's stateful duties, composed by
/// [`crate::Authenticator::authenticate`].
pub fn verify(jwt: &str, params: &VerifyParams) -> Result<RpSession, RpError> {
    let config = VerifyConfig {
        expected_audience: params.expected_audience.clone(),
        expected_nonce: params.expected_nonce.clone(),
        max_iat_skew_secs: params.max_iat_skew_secs,
        now_unix_secs: params.now_unix_secs,
    };
    let verified = verify_mid_response(jwt, &config)?;
    Ok(RpSession::from_verified(verified))
}
