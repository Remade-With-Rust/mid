//! Canonical byte encodings for roster signatures (ADR 0005 Decision 1).
//!
//! Defined in `mid-types::canonical`; re-exported here so every path that
//! named them keeps working.

pub use mid_types::canonical::{
    chain_entry_canonical_bytes, genesis_canonical_bytes, CHAIN_ENTRY_DOMAIN, GENESIS_DOMAIN,
};
