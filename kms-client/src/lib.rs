//! # `kms-client` — client-side helpers for MATA KMS sovereign-auth
//!
//! Phase 3 of the [Phase 1 Wallet Overhaul Mission](../../../docs/kms/phase_1_wallet_overhaul_mission.md).
//!
//! This crate is what the wallet (and the future OIDC client SDK) uses to
//! turn an unsigned [`NonceEnvelope`] into a [`SignedAssertion`] the
//! `kms-verifier` will accept. Two surfaces:
//!
//! ## Low-level: [`sign_assertion`]
//!
//! Given anything that implements [`DeviceSigner`] and a [`NonceEnvelope`],
//! produces a canonical [`SignedAssertion`]. No HTTP, no async — just the
//! pure transformation. Use this when you already have a nonce in hand
//! (e.g., the verifier issued one in a same-process integration test).
//!
//! ## High-level: [`KmsClient`]
//!
//! The full round-trip: POSTs to `/v1/nonce`, signs the response, returns the
//! signed assertion ready to send to the endpoint. Use this when talking to a
//! remote `kms-banking-proxy` (or a future `kms-oidc-adapter`).
//!
//! ## Production [`DeviceSigner`] implementations
//!
//! Live elsewhere. This crate ships [`InMemoryDeviceSigner`] as a test helper
//! and bootstrap impl. The wallet will eventually wire a `SecureEnclaveSigner`
//! / `KeystoreSigner` / `WebAuthnSigner` that pulls the M5 signing key from
//! `mata-identity` / `dioxus-webauthn`. Those wrappers live in `packages/ui`
//! to keep `kms-client` free of platform deps.
//!
//! ## Canonical signature rule
//!
//! Per [envelope_spec.md](../../../docs/kms/envelope_spec.md), every
//! produced signature is normalized to **low-s** form. The verifier rejects
//! high-s signatures to kill ECDSA malleability. All
//! [`DeviceSigner::sign_prehash`] implementations MUST honor this — see the
//! trait docs.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod sign;

pub use client::{ClientError, KmsClient};
pub use mid_signer::{DeviceSigner, InMemoryDeviceSigner};
pub use sign::{sign_assertion, sign_roster_update};

// Re-exported so callers don't need to depend on kms-types directly.
pub use kms_types::{
    DidDocumentV2, NonceEnvelope, RosterEntry, RosterUpdate, SignedAssertion, VerifyError,
};

/// Compiles the README's examples as doctests, so the documented API can never
/// drift from the real one. Not part of the public API, and not rendered into
/// the crate docs — it exists only under `cargo test --doc`.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
