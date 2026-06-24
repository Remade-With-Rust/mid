//! # `kms-types` — shared envelope types for MATA KMS sovereign-auth
//!
//! Phase 1 of the [Phase 1 Wallet Overhaul Mission](../../../docs/kms/phase_1_wallet_overhaul_mission.md).
//! This crate defines the wire-format types every other `kms-*` crate consumes:
//!
//! - [`NonceEnvelope`] — issued by the verifier, signed by the client.
//! - [`SignedAssertion`] — the client's signed envelope wrapping a `NonceEnvelope`.
//! - [`RosterEntry`] — one device's roster slot.
//! - [`RosterUpdate`] — a signed mutation of a DID's roster.
//! - [`DidDocumentV2`] — the resolver's view of a DID's current roster.
//! - [`VerifyError`] — the spec-frozen error taxonomy from
//!   [envelope_spec.md §"Error taxonomy"](../../../docs/kms/envelope_spec.md).
//!
//! Per [docs/kms/envelope_spec.md](../../../docs/kms/envelope_spec.md), each
//! envelope carries `envelope_version: u8` and an `envelope_type` discriminant.
//! Two envelope types are deliberately byte-distinguishable via the
//! domain-separator prefixes built into [`NonceEnvelope::canonical_bytes`] and
//! [`RosterUpdate::canonical_bytes`] — a banking signature can never validate
//! as a roster-update signature.
//!
//! ## "No logic" caveat
//!
//! The mission doc scopes this crate as "serde-derived, no logic." This crate
//! includes two narrow exceptions:
//!
//! 1. [`NonceEnvelope::canonical_bytes`] and [`RosterUpdate::canonical_bytes`]
//!    — deterministic implementations of the signing form from
//!    [envelope_spec.md](../../../docs/kms/envelope_spec.md). The signing form
//!    is the envelope's contract; if it lived in `kms-verifier`, every signer
//!    (client, verifier, bootstrap) would re-implement it.
//! 2. `validate()` on each envelope — shape-only validation. Audience/purpose
//!    allow-listing and signature verification stay in `kms-verifier`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod assertion;
mod b64;
mod did;
mod did_document;
mod error;
mod nonce;
mod roster;

pub use assertion::SignedAssertion;
pub use did_document::DidDocumentV2;
pub use error::VerifyError;
pub use nonce::NonceEnvelope;
pub use roster::{RosterEntry, RosterUpdate, ROSTER_HARD_CAP, ROSTER_SIGNED_AT_TOLERANCE_SECS};

/// `did:mata:<base58-pubkey>` shape check. ASCII-only, length 32–48 in the
/// base58 charset (excluding `0`, `O`, `I`, `l`).
///
/// Per [envelope_spec.md](../../../docs/kms/envelope_spec.md) `did` regex:
/// `^did:mata:[1-9A-HJ-NP-Za-km-z]{32,48}$`.
pub fn is_valid_did(s: &str) -> bool {
    did::is_valid_did(s)
}
