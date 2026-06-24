//! # `kms-verifier` — MATA KMS sovereign-auth verification engine
//!
//! Phase 2 of the [Phase 1 Wallet Overhaul Mission](../../../docs/kms/phase_1_wallet_overhaul_mission.md).
//!
//! This crate is the trust gate. Every Plaid/Stripe call in the future
//! `kms-banking-proxy` (Phase 5) passes through [`Verifier::verify`], and so
//! will every `/authorize` call in a future `kms-oidc-adapter`. Banking and
//! SSO share this verifier — it has no awareness of either.
//!
//! ## Mental model
//!
//! ```text
//!   client                                  verifier
//!     │                                        │
//!     │  POST /v1/nonce                        │
//!     ├───────────────────────────────────────►│
//!     │                                        │
//!     │             NonceEnvelope              │
//!     │◄───────────────────────────────────────┤
//!     │                                        │
//!     │ sign(envelope.canonical_bytes())       │
//!     │ with M5 signing key                    │
//!     │                                        │
//!     │  POST /v1/plaid/accounts               │
//!     │  SignedAssertion                       │
//!     ├───────────────────────────────────────►│
//!     │                                        │
//!     │                       verify()         │
//!     │                       ┌──────┐         │
//!     │                       │shape │         │
//!     │                       │audience│       │
//!     │                       │purpose│        │
//!     │                       │issuer │        │
//!     │                       │resolve│        │
//!     │                       │roster │        │
//!     │                       │sig    │        │
//!     │                       │consume│        │
//!     │                       └──────┘         │
//!     │                                        │
//!     │           VerifiedIdentity             │
//!     │◄───────────────────────────────────────┤
//! ```
//!
//! ## What this crate does NOT do
//!
//! - **No HTTP.** [`NonceStore`] and [`DidResolver`] are trait objects.
//!   Production implementations (Postgres-backed nonce store,
//!   `kms-resolver` HTTP client) live in other crates.
//! - **No DB.** Same — the verifier is pure logic.
//! - **No key generation.** Devices generate their own M5 signing keys via
//!   `dioxus-webauthn` / `mata-identity`. The verifier only verifies.
//! - **No bootstrap.** The first roster for a DID is created via the
//!   `kms_bootstrap_did` SECURITY DEFINER function described in
//!   [did_document_v2.md §Bootstrap](../../../docs/kms/did_document_v2.md),
//!   not through this verifier.
//!
//! ## Check ordering (defensive)
//!
//! [`Verifier::verify`] runs checks in this order, cheapest-first, with
//! state-mutating consumption last:
//!
//! 1. Envelope shape ([`SignedAssertion::validate`])
//! 2. Audience match (verifier's configured audience)
//! 3. Purpose match (endpoint's expected purpose)
//! 4. Issuer match (verifier's configured issuer)
//! 5. Resolve DID document
//! 6. Find device in roster
//! 7. Ed25519 signature verification
//! 8. Atomic nonce consume (the single state mutation)
//! 9. Tamper check: stored envelope must equal embedded envelope
//!
//! A failure at any step short-circuits; a non-final failure never consumes
//! the nonce, so a corrupted network packet doesn't burn the user's only
//! retry opportunity.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod in_memory;
mod traits;
mod verifier;

pub use in_memory::{InMemoryDidResolver, InMemoryNonceStore};
pub use traits::{Clock, DidResolver, NonceGenerator, NonceStore, SystemClock, SystemNonceGenerator};
pub use verifier::{VerifiedIdentity, VerifiedRosterUpdate, Verifier};

// Re-exported so callers don't need to depend on kms-types directly when
// they only consume the verifier's surface.
pub use kms_types::{
    DidDocumentV2, NonceEnvelope, RosterEntry, RosterUpdate, SignedAssertion, VerifyError,
};
