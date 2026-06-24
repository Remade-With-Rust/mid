//! Typed error variants for the mID issuer.
//!
//! Every variant maps to a specific failure mode that a caller can react to
//! distinctly — generic wrappers (e.g. `Other`) are avoided so the
//! extension popup / native app handler can show a specific message rather
//! than "something went wrong."

use thiserror::Error;

/// The single error type returned by [`crate::build_mid_jwt`].
#[derive(Debug, Error)]
pub enum MidIssuerError {
    /// A claim listed in [`crate::types::ClaimRequest::required`] was not
    /// present in [`crate::types::IdentitySnapshot::approved_claims`].
    /// Caller's job to either prompt the user again or surface an
    /// `access_denied` to the RP.
    #[error("required claim `{0}` was not approved")]
    RequiredClaimMissing(String),

    /// The current verification method is not present in the head roster
    /// (either the head of `roster_chain`, or `genesis_roster` if the
    /// chain is empty). Indicates the signer is on a revoked or stale
    /// device and the wallet's roster cache is out of sync.
    #[error(
        "current verification method `{0}` is not in the head roster — signer is not a current authorized device"
    )]
    SignerNotInHeadRoster(String),

    /// The DID in the [`crate::types::IdentitySnapshot`] does not match
    /// the `controller` of the current verification method.
    #[error("identity snapshot DID `{snapshot_did}` does not match VM controller `{vm_controller}`")]
    DidVmMismatch {
        /// The DID claimed in the identity snapshot.
        snapshot_did: String,
        /// The DID asserted by the current verification method's
        /// `controller` field.
        vm_controller: String,
    },

    /// The `iat` + token-lifetime is invalid (computed `exp` was earlier
    /// than `iat`). Internal bug; should never trip in production.
    #[error("computed token expiry `{exp}` is not after `iat` `{iat}`")]
    InvalidTokenLifetime {
        /// Issued-at value used.
        iat: u64,
        /// Computed expiry value.
        exp: u64,
    },

    /// JSON serialization of the payload failed. Should not happen with
    /// well-formed inputs; included for completeness.
    #[error("payload JSON serialization failed: {0}")]
    PayloadSerialization(#[from] serde_json::Error),
}
