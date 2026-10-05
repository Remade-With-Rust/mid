//! # mid-sovereign-signup
//!
//! Headless **email + one-time-code** sign-up and sign-in for Rust services.
//! It is the open sibling of [`mid-signin`](https://crates.io/crates/mid-signin):
//! that crate proves a user through a wallet-held `did:mata` key; this one
//! proves a user through an inbox, for the people who **do not (yet) hold a
//! MATA DID** and the services that want to let them in anyway. A tenant can
//! accept either, or both — a user who signs up by email can later link a
//! DID ([`User::linked_did`]) and the record carries both proofs.
//!
//! The flow is the one every "magic code" product runs, done once and done
//! carefully:
//!
//! ```text
//!   client ──start(email)──▶ core ──code──▶ Mailer ──▶ inbox
//!   client ──verify(email, code)──▶ core ──▶ User (+ Attestation)
//! ```
//!
//! * [`flow::start`] normalizes the address, mints a six-digit code from the
//!   caller's entropy, and returns a [`Challenge`] that stores only an
//!   HMAC-SHA256 **commitment** to the code under a server-held [`Pepper`].
//!   The code itself exists only in the returned [`Code`] (to be mailed) and is
//!   never persisted.
//! * [`flow::verify`] checks a presented code in constant time, counts the
//!   attempt, expires and exhausts the challenge per [`Policy`], and on success
//!   creates or signs in the [`User`] — returning every record the caller must
//!   write back so the whole step is **one atomic transaction** in whatever
//!   store wraps it.
//! * [`attest::sign_attestation`] turns a verified user into a
//!   [`mata-sign`](https://crates.io/crates/mata-sign) statement signed by the
//!   service's own DID: the artifact a tenant's backend, or any third party,
//!   verifies **offline** with [`attest::verify_attestation`], the same way it
//!   would verify a MATA sign-in.
//!
//! ## What is deliberately not here
//!
//! This crate is the **pure core**. It reads no clock (`now` is always a
//! parameter), performs no I/O, holds no state, and depends on no store, mail
//! provider, or HTTP framework. Those are seams the caller fills:
//!
//! | Seam | Trait | Ships with |
//! |---|---|---|
//! | randomness | [`Entropy`] | [`OsEntropy`] (OS RNG), [`FixedEntropy`] (tests, vectors) |
//! | email delivery | [`Mailer`] | [`StubMailer`] (records messages; dev/test) |
//! | persistence | — | the record types + their key namespace ([`records`]); feature `store` ships [`SignupStore`] |
//!
//! Feature `store` adds the persistent layer on SpaceDB (one redb file, every
//! row sealed, every accepted write one fsync'd transaction carrying its audit
//! rows). A mail transport, HTTP routes, and a client follow as further
//! feature-gated layers, the way `mid-signin` adds `redb-store` and `routes`
//! over its core. Anyone can run the whole thing on
//! their own hardware; a hosted operator is just one adopter of it.
//!
//! ## Security properties
//!
//! * **Codes are commitments, not secrets at rest.** The store holds
//!   `HMAC-SHA256(pepper, tenant ‖ email_idx ‖ challenge_id ‖ code)`; a leaked
//!   store without the pepper reveals nothing, and a leaked store *with* the
//!   pepper is still one guess per attempt.
//! * **Brute force is bounded.** A code is one of 10⁶, a challenge allows
//!   [`Policy::max_attempts`] guesses (default 5) within
//!   [`Policy::code_ttl_secs`] (default 10 min), and a correct guess consumes
//!   the challenge. Comparison is constant-time ([`subtle`]).
//! * **Addresses are indexed, not exposed.** Lookups go through
//!   [`EmailIndex`] = `HMAC-SHA256(pepper, tenant ‖ email)`, so the store's
//!   keys never contain an address; audit events carry only the index.
//! * **Start reveals nothing.** Starting a challenge produces the same outcome
//!   whether or not the address is enrolled; enrollment is only decided at
//!   verify, by someone who controls the inbox.
//! * **Nothing proprietary.** Every dependency is open; the attestation is a
//!   plain `mata-sign` statement verifiable with zero network calls.
//!
//! ## Purity contract
//!
//! Everything in this crate is deterministic given its inputs: `now_unix_secs`
//! is a parameter, randomness comes through [`Entropy`], and no function
//! touches the network, the filesystem, or a clock. Feature-gated layers that
//! break this (routes, stores, SES) will say so at their boundary.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attest;
#[cfg(feature = "client")]
pub mod client;
mod code;
mod email;
mod enc;
mod error;
pub mod flow;
#[cfg(feature = "mail-ses")]
pub mod mail_ses;
pub mod migrate;
mod pepper;
mod policy;
pub mod records;
pub mod referrals;
mod seams;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "store")]
pub mod store;
pub mod webhook;

#[cfg(test)]
mod tests;

pub use code::{Code, CodeError, CodeMac, CODE_DIGITS, CODE_SPACE};
pub use email::{
    EmailError, EmailIndex, NormalizedEmail, MAX_DOMAIN_LEN, MAX_EMAIL_LEN, MAX_LABEL_LEN,
    MAX_LOCAL_LEN,
};
pub use error::FlowError;
pub use flow::{start, verify, StartOutcome, StartRequest, Verified, VerifyRequest, VerifyResult};
pub use pepper::{Pepper, PepperError};
pub use policy::{Policy, PolicyError, RateLimited, RateWindow};
pub use records::{
    normalize_username, AuditEvent, AuditKind, Challenge, ChallengeId, ConsumedReason,
    RejectReason, Tenant, TenantId, TenantIdError, TenantMember, User, UserId, UserIdError,
    WebhookEndpoint, WebhookFormat, WEBHOOK_EVENTS,
};
pub use seams::{
    BoxFuture, CodeMessage, Entropy, EntropyError, FixedEntropy, MailError, Mailer, OsEntropy,
    StubMailer, WelcomeMessage,
};

#[cfg(feature = "store")]
pub use store::{
    AuditRow, Delivery, ImportOutcome, IntegrityReport, Limits, OutboxItem, RateRule,
    SessionRecord, SessionTokens, SessionTtl, SignupDump, SignupStore, StoreError,
    UsernameConflict, UsernameDropped,
};

// The signing vocabulary an adopter needs for attestations, re-exported so a
// service depends on this crate only.
pub use mata_sign::{DeviceSigner, SignError};
pub use mid_issuer::IdentitySnapshot;
