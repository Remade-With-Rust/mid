//! Domain-separated canonical byte forms for the embedded roster envelopes.
//!
//! These bytes are what the wallet SIGNS (at signup for the genesis roster,
//! at each device-add/remove for chain entries) and what the verifier
//! [`mid-verify`](../mid_verify/) re-computes to verify the signatures.
//! Both crates MUST agree on the byte-exact output of these functions —
//! any change here is a wire-format break.
//!
//! ## Format
//!
//! ```text
//! domain_separator           (literal bytes, length 21 or 19)
//! version                    (u64 big-endian, 8 bytes)
//! did_len                    (u32 big-endian, 4 bytes)
//! did_bytes                  (UTF-8)
//! vm_count                   (u32 big-endian, 4 bytes)
//! for each verification_method:
//!     id_len + id            (u32 BE length + UTF-8)
//!     vm_type_len + vm_type  (u32 BE length + UTF-8)
//!     controller_len + ...   (u32 BE length + UTF-8)
//!     public_key_multibase_len + ...   (u32 BE length + UTF-8)
//! signed_at                  (u64 big-endian, 8 bytes)
//! [chain entries only]
//!     signer_kid_len + bytes (u32 BE length + UTF-8)
//! ```
//!
//! ## Why a custom binary form (not canonical JSON)?
//!
//! - **Deterministic.** JSON serialization is sensitive to key order,
//!   whitespace, integer encoding choices, and float NaN handling. A
//!   length-prefixed binary form has exactly one representation per input.
//! - **Domain separation.** The leading literal bytes prevent a signature
//!   over a genesis roster from being misinterpreted as a signature over a
//!   chain entry (or any other envelope). This is the same pattern the
//!   existing [`kms-types`](../kms_types/) envelopes use for banking and
//!   roster updates.
//! - **Cheap to verify.** Verifiers don't need a JSON parser to compute
//!   the prehash — they just walk the struct once.

use alloc::vec::Vec;

use crate::{EmbeddedGenesisRoster, EmbeddedRosterChainEntry, VerificationMethod};

/// Domain separator for the genesis roster envelope. Distinct from the
/// chain entry separator so a genesis signature cannot be replayed as a
/// chain signature even if all other bytes happened to align.
pub const GENESIS_DOMAIN: &[u8] = b"mid-genesis-roster-v1";

/// Domain separator for chain entries.
pub const CHAIN_ENTRY_DOMAIN: &[u8] = b"mid-roster-chain-v1";

/// Compute the canonical bytes that the genesis roster's
/// `self_signed_by_genesis_key` signature covers. The signature field itself
/// is NOT included.
pub fn genesis_canonical_bytes(genesis: &EmbeddedGenesisRoster) -> Vec<u8> {
    let mut buf = Vec::with_capacity(GENESIS_DOMAIN.len() + 64);
    buf.extend_from_slice(GENESIS_DOMAIN);
    buf.extend_from_slice(&genesis.version.to_be_bytes());
    push_string(&mut buf, &genesis.did);
    push_vms(&mut buf, &genesis.verification_methods);
    buf.extend_from_slice(&genesis.signed_at.to_be_bytes());
    buf
}

/// Compute the canonical bytes that a chain entry's
/// `signed_by_signer_in_prior_roster` signature covers. The signature field
/// itself is NOT included; `signer_kid` IS included (it identifies which
/// VM produced the signature, so it must be bound to the message).
pub fn chain_entry_canonical_bytes(entry: &EmbeddedRosterChainEntry) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CHAIN_ENTRY_DOMAIN.len() + 64);
    buf.extend_from_slice(CHAIN_ENTRY_DOMAIN);
    buf.extend_from_slice(&entry.version.to_be_bytes());
    push_string(&mut buf, &entry.did);
    push_vms(&mut buf, &entry.verification_methods);
    buf.extend_from_slice(&entry.signed_at.to_be_bytes());
    push_string(&mut buf, &entry.signer_kid);
    buf
}

fn push_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn push_vms(buf: &mut Vec<u8>, vms: &[VerificationMethod]) {
    buf.extend_from_slice(&(vms.len() as u32).to_be_bytes());
    for vm in vms {
        push_string(buf, &vm.id);
        push_string(buf, &vm.vm_type);
        push_string(buf, &vm.controller);
        push_string(buf, &vm.public_key_multibase);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vm(id: &str) -> VerificationMethod {
        VerificationMethod {
            id: id.into(),
            vm_type: "EcdsaSecp256r1VerificationKey2019".into(),
            controller: "did:mata:abc".into(),
            public_key_multibase: "zFake".into(),
        }
    }

    fn make_genesis(vm_ids: &[&str], signed_at: u64) -> EmbeddedGenesisRoster {
        EmbeddedGenesisRoster {
            version: 1,
            did: "did:mata:abc".into(),
            verification_methods: vm_ids.iter().map(|id| make_vm(id)).collect(),
            signed_at,
            self_signed_by_genesis_key: "placeholder".into(),
        }
    }

    #[test]
    fn genesis_canonical_starts_with_domain_separator() {
        let g = make_genesis(&["did:mata:abc#dev"], 1000);
        let bytes = genesis_canonical_bytes(&g);
        assert!(bytes.starts_with(GENESIS_DOMAIN));
    }

    #[test]
    fn genesis_canonical_excludes_signature_field() {
        let mut g = make_genesis(&["did:mata:abc#dev"], 1000);
        let bytes_a = genesis_canonical_bytes(&g);
        g.self_signed_by_genesis_key = "completely-different-value".into();
        let bytes_b = genesis_canonical_bytes(&g);
        assert_eq!(
            bytes_a, bytes_b,
            "canonical bytes MUST NOT depend on the signature field"
        );
    }

    #[test]
    fn genesis_canonical_is_deterministic() {
        let g1 = make_genesis(&["did:mata:abc#dev"], 1000);
        let g2 = make_genesis(&["did:mata:abc#dev"], 1000);
        assert_eq!(genesis_canonical_bytes(&g1), genesis_canonical_bytes(&g2));
    }

    #[test]
    fn genesis_canonical_changes_with_vm_set() {
        let g_a = make_genesis(&["did:mata:abc#dev1"], 1000);
        let g_b = make_genesis(&["did:mata:abc#dev1", "did:mata:abc#dev2"], 1000);
        assert_ne!(genesis_canonical_bytes(&g_a), genesis_canonical_bytes(&g_b));
    }

    #[test]
    fn chain_entry_canonical_uses_different_domain_than_genesis() {
        let g = make_genesis(&["did:mata:abc#dev"], 1000);
        let g_bytes = genesis_canonical_bytes(&g);

        let e = EmbeddedRosterChainEntry {
            version: 2,
            did: "did:mata:abc".into(),
            verification_methods: vec![make_vm("did:mata:abc#dev")],
            signed_at: 1000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev".into(),
        };
        let e_bytes = chain_entry_canonical_bytes(&e);

        // Different domain separators → bytes diverge even if other
        // fields match. Both start with "mid-" so check the first 10
        // bytes to catch the actual divergence point ("mid-genesis-"
        // vs. "mid-roster").
        assert_ne!(&g_bytes[..10], &e_bytes[..10]);
        assert!(e_bytes.starts_with(CHAIN_ENTRY_DOMAIN));
    }

    #[test]
    fn chain_entry_canonical_includes_signer_kid() {
        let e1 = EmbeddedRosterChainEntry {
            version: 2,
            did: "did:mata:abc".into(),
            verification_methods: vec![make_vm("did:mata:abc#dev")],
            signed_at: 1000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev1".into(),
        };
        let e2 = EmbeddedRosterChainEntry {
            signer_kid: "dev2".into(),
            ..e1.clone()
        };
        assert_ne!(
            chain_entry_canonical_bytes(&e1),
            chain_entry_canonical_bytes(&e2),
            "signer_kid MUST be bound to the signature"
        );
    }

    #[test]
    fn chain_entry_canonical_excludes_signature_field() {
        let mut e = EmbeddedRosterChainEntry {
            version: 2,
            did: "did:mata:abc".into(),
            verification_methods: vec![make_vm("did:mata:abc#dev")],
            signed_at: 1000,
            signed_by_signer_in_prior_roster: "placeholder".into(),
            signer_kid: "dev".into(),
        };
        let bytes_a = chain_entry_canonical_bytes(&e);
        e.signed_by_signer_in_prior_roster = "different".into();
        let bytes_b = chain_entry_canonical_bytes(&e);
        assert_eq!(bytes_a, bytes_b);
    }
}
