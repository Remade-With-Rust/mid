//! Wire-format types for the mID JWT, locked by ADR 0005 Decision 1.
//!
//! They live in `mid-types` (`no_std` + `alloc`) so a verifier or a device
//! can carry them without this crate's issuer machinery; this module keeps
//! every path that named them here.

pub use mid_types::{
    AttestedBy, ClaimRequest, ClaimValue, CustomClaimRequest, EmbeddedGenesisRoster,
    EmbeddedRosterChainEntry, EmbeddedVerificationMethod, IdentitySnapshot, MidJwtPayload,
    RpRequest, VerificationMethod,
};
