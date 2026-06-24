//! # `mid-issuer` — wallet-side mID JWT minter
//!
//! Phase 0 of the [mID Mission](../../../docs/plans/phase%201%20sso_permissionless_mission.md).
//! Implements [ADR 0005 Decision 1](../../../docs/adr/0005-mid-protocol-v1-phase-0-spec-lockin.md):
//! given an [`IdentitySnapshot`] of the wallet's identity state, an
//! [`RpRequest`] from the relying party, and a [`DeviceSigner`] (the M5
//! signing key on this device), produce a JWS compact-form mID token.
//!
//! ## Surfaces this crate is consumed from
//!
//! Both v1 issuance surfaces use the same `mid-issuer` crate:
//!
//! - **The MATA browser extension** (content script + popup consent UI)
//!   — calls [`build_mid_jwt`] from the extension-background worker after
//!   the user approves the consent screen.
//! - **The MATA native app** (desktop + mobile) — calls [`build_mid_jwt`]
//!   from the URL-scheme handler after the biometric gate unlocks.
//!
//! ## What this crate is NOT
//!
//! - **Not the consent UI.** The caller decides whether to issue; this crate
//!   just builds the JWT once the decision is made.
//! - **Not the surface dispatcher.** The `@mata/mid` JS SDK probes for the
//!   extension/native-app; this crate runs after that probe succeeds.
//! - **Not the wallet's identity store.** The caller assembles the
//!   [`IdentitySnapshot`] from [`mata-identity`](../mata_identity/) and the
//!   `mid_user_consents` Y-CRDT type; this crate consumes the snapshot
//!   read-only.
//! - **Not a verifier.** RPs use [`mid-verify`](../mid_verify/) for that.
//!
//! ## Wire format
//!
//! The JWT payload follows ADR 0005 Decision 1 exactly — see [`types`] for
//! the Rust types and [`docs/adr/0005-mid-protocol-v1-phase-0-spec-lockin.md`]
//! for the locked JSON example.
//!
//! ## Cryptographic posture
//!
//! - **Outer JWT signature.** ES256 (ECDSA P-256 with SHA-256), low-s
//!   canonical form per RFC 7515 / RFC 7518. Produced by
//!   [`DeviceSigner::sign_prehash`].
//! - **Embedded roster signatures.** Already produced at roster-mutation
//!   time by the wallet's existing roster machinery
//!   ([`kms-types::RosterUpdate`](../kms_types/struct.RosterUpdate.html));
//!   this crate bundles them unchanged.
//! - **Domain separation.** The JWS header's `"typ": "JWT"` plus the
//!   payload's `aud` field together pin the audience; the M5 key cannot be
//!   tricked into producing a banking-valid signature for an mID flow
//!   because the canonical signing form differs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bootstrap;
pub mod canonical;
mod error;
mod issuer;
pub mod jws;
pub mod snapshot;
mod types;

pub use error::MidIssuerError;
pub use issuer::build_mid_jwt;
pub use jws::build_jws_compact;
pub use types::{
    AttestedBy, ClaimRequest, ClaimValue, CustomClaimRequest, EmbeddedGenesisRoster,
    EmbeddedRosterChainEntry, EmbeddedVerificationMethod, IdentitySnapshot, MidJwtPayload,
    RpRequest, VerificationMethod,
};

// Re-export the signer trait so callers don't need an extra `use kms_client::DeviceSigner`.
pub use kms_client::DeviceSigner;
