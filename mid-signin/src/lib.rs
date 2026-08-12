//! # mid-signin
//!
//! The drop-in Relying-Party (RP) kit for **Sign in with MATA** (mID).
//!
//! [`mid_verify`] does the cryptography — the four-step, zero-MATA-runtime
//! verification of a self-issued mID JWT — and deliberately stops there: it is
//! a pure function with no state. A production RP still owes three duties the
//! verifier cannot perform:
//!
//! 1. **Single-use nonces.** The verifier only checks nonce *equality*; the RP
//!    must prove the nonce was one it issued and consume it exactly once, or a
//!    captured token replays forever. ([`NonceStore`])
//! 2. **Genesis anchoring + rollback detection.** A DID must present the same
//!    genesis-roster hash on every sign-in (anything else is spoofing) and a
//!    head-roster version that never decreases (a decrease is a stolen-device
//!    rollback). The verifier is stateless, so the RP persists the anchor.
//!    ([`AnchorStore`])
//! 3. **Session production.** Turning a verified token into "this request is
//!    Alice" — which stays the application's choice; this crate hands back an
//!    [`RpSession`] and gets out of the way.
//!
//! [`Authenticator`] composes all of it: verify → consume nonce → check
//! anchor. The `redb-store` feature adds a zero-schema embedded persistent
//! store; the `routes` feature adds ready-made axum routes that pair with the
//! `@matanetwork/sovereign-id` frontend SDK.
//!
//! ## Ten-line integration (axum)
//!
//! ```ignore
//! use std::sync::Arc;
//! use mid_signin::{Authenticator, MidRp, MidRpConfig, RedbStore};
//!
//! let store = Arc::new(RedbStore::open("mata-auth.redb")?);
//! let auth = Authenticator::new(store.clone(), store);
//! let rp = Arc::new(MidRp::new(
//!     MidRpConfig::new("https://acme.com"),
//!     auth,
//! ));
//! let app = axum::Router::new()
//!     .merge(mid_signin::routes::router(rp));
//! // Frontend: signIn({ rpOrigin: "https://acme.com", nonce, claims: … })
//! // with nonce from POST /auth/mid/nonce; POST the JWT to /auth/mid/verify.
//! ```
//!
//! ## Purity contract
//!
//! The core (everything outside the `routes` module) reads no clock and does
//! no I/O of its own: `now_unix_secs` is always a parameter, mirroring
//! `mid_verify::VerifyConfig`. The impure boundary — `SystemTime`, HTTP —
//! lives only in [`routes`].
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod anchor;
mod auth;
mod error;
mod nonce;
mod session;

#[cfg(feature = "redb-store")]
mod store_redb;

#[cfg(feature = "routes")]
pub mod routes;

#[cfg(test)]
pub(crate) mod test_fixtures;
#[cfg(test)]
mod tests;

pub use anchor::{AnchorStore, InMemoryAnchorStore};
pub use auth::{peek_nonce, Authenticator};
pub use error::RpError;
pub use nonce::{InMemoryNonceStore, NonceStore, DEFAULT_MAX_LIVE_NONCES, DEFAULT_NONCE_TTL_SECS};
pub use session::{verify, RpSession, VerifyParams};

#[cfg(feature = "redb-store")]
pub use store_redb::RedbStore;

#[cfg(feature = "routes")]
pub use routes::{MidRp, MidRpConfig};

// The mID vocabulary callers need, re-exported so an RP depends only on
// this crate.
pub use mid_verify::{ClaimValue, VerifyError};
