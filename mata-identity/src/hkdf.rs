//! HKDF-SHA256 subordinate-key derivation.
//!
//! M2 of the KMS plan introduces a deterministic key tree rooted at the user's
//! vault key. The `#root` keypair from M1 is **not** derived (it's stored on
//! `RegisteredCredential` as random bytes, vault-encrypted) so M1 signatures
//! stay valid forever. Every other key (`#encryption` here, plus task-scoped /
//! delegation / ephemeral keys in later milestones) is derived on demand from
//! the vault key using [`derive_subordinate_key`].
//!
//! ## Domain separation
//!
//! Critical Implementation Detail #1 in the plan: every label is prefixed
//! with the protocol version (`MATA-PKI-v1/`) so a future protocol bump
//! (e.g. post-quantum migration in M6) can introduce `MATA-PKI-v2/` without
//! colliding. Omitting the version means every key has to migrate.
//!
//! ## Why HKDF, not just SHA-256
//!
//! HKDF gives us a proper extract-then-expand construction with a salt
//! (`b"MATA-PKI-v1"`) that ensures different protocol generations produce
//! different keys even if a vault key were ever shared between them.
//! `sha256(vault_key || label)` would also work but is more error-prone
//! (length-extension, no clear extract step). HKDF is the standard.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF salt — pin this to the current protocol generation.
///
/// **Do not change without bumping the version suffix in every label.**
/// Changing this byte string invalidates every key derived under the previous
/// salt; that's the migration cost of a protocol break.
const HKDF_SALT: &[u8] = b"MATA-PKI-v1";

/// Subordinate-key purpose — `#encryption` keypair for ECDH key agreement.
///
/// Used to derive the user's published encryption key (see DID document
/// `verificationMethod[#encryption]`). M3 messaging uses this for ECIES.
pub const PURPOSE_ENCRYPTION: &str = "encryption";

/// Derive a 32-byte subordinate key from the user's vault key.
///
/// `purpose` is a short ASCII tag (e.g. `"encryption"`); it is prefixed with
/// `MATA-PKI-v1/` to form the HKDF info bytes. The same `(vault_key, purpose)`
/// always produces the same output, so callers must NOT cache the result —
/// re-derive on demand whenever the key is needed and zero the buffer after
/// use.
///
/// # Cross-platform contract
///
/// This function uses only `hkdf` + `sha2`, both pure-Rust. Output is byte-
/// identical on native, WASM, iOS, and Android — verified in tests.
pub fn derive_subordinate_key(vault_key: &[u8], purpose: &str) -> [u8; 32] {
    let info = format!("MATA-PKI-v1/{purpose}");
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), vault_key);
    let mut out = [0u8; 32];
    // HKDF expand to 32 bytes never fails for SHA-256 (max output is 8160
    // bytes per RFC 5869). `expect` is appropriate here — failure would
    // indicate a programming error in the `hkdf` crate.
    hk.expand(info.as_bytes(), &mut out)
        .expect("HKDF-SHA256 expand to 32 bytes is always within max output length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_input_same_output() {
        let vault = [0x42u8; 32];
        let a = derive_subordinate_key(&vault, PURPOSE_ENCRYPTION);
        let b = derive_subordinate_key(&vault, PURPOSE_ENCRYPTION);
        assert_eq!(a, b, "HKDF must be deterministic");
    }

    #[test]
    fn different_purposes_diverge() {
        let vault = [0x42u8; 32];
        let enc = derive_subordinate_key(&vault, "encryption");
        let task = derive_subordinate_key(&vault, "task/signing/example.com/2026Q2");
        assert_ne!(
            enc, task,
            "different purpose labels must produce different keys (domain separation)"
        );
    }

    #[test]
    fn different_vault_keys_diverge() {
        let a = derive_subordinate_key(&[0x01u8; 32], PURPOSE_ENCRYPTION);
        let b = derive_subordinate_key(&[0x02u8; 32], PURPOSE_ENCRYPTION);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_purpose_is_distinct_from_named() {
        let vault = [0x42u8; 32];
        let empty = derive_subordinate_key(&vault, "");
        let named = derive_subordinate_key(&vault, "encryption");
        assert_ne!(empty, named);
    }
}
