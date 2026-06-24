//! DID shape validation.
//!
//! Accepts two formats during the transition from the legacy
//! `mata-identity` DIDs (`did:mata:<UUID>`, used by the wallet today)
//! to the spec's intended `did:mata:<base58-pubkey>` (used by future
//! crypto-derived DIDs).
//!
//! Both formats are accepted because the cryptographic identity is bound
//! to the pubkey stored in `kms_did_documents.roster`, not to the DID
//! string itself. The DID is an opaque key for that row; the security
//! property of "signature verifies against the device's pubkey" holds
//! either way.
//!
//! When the wallet migrates to crypto-derived DIDs (separate mission),
//! the UUID-acceptance branch can be removed.

/// Returns true iff `s` is a valid `did:mata:` identifier in either:
/// - base58 format: `^did:mata:[1-9A-HJ-NP-Za-km-z]{32,48}$` (spec target)
/// - UUID format:   `^did:mata:<8-4-4-4-12 lowercase-hyphenated UUID>$` (legacy)
pub fn is_valid_did(s: &str) -> bool {
    let suffix = match s.strip_prefix("did:mata:") {
        Some(s) => s,
        None => return false,
    };
    is_valid_base58_suffix(suffix) || is_valid_uuid_suffix(suffix)
}

/// Spec-target base58 suffix: 32–48 chars, Bitcoin base58 charset.
fn is_valid_base58_suffix(suffix: &str) -> bool {
    if suffix.len() < 32 || suffix.len() > 48 {
        return false;
    }
    suffix.chars().all(is_base58_char)
}

/// Legacy UUID suffix: lowercase hex with `-` separators at positions 8/13/18/23.
/// Total length 36 (8+1+4+1+4+1+4+1+12). Matches what `uuid::Uuid::to_string()`
/// produces (lowercase, hyphenated). Reject uppercase hex to keep the format
/// canonical and prevent two valid spellings of the same DID.
fn is_valid_uuid_suffix(suffix: &str) -> bool {
    if suffix.len() != 36 {
        return false;
    }
    let bytes = suffix.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        if !b.is_ascii_hexdigit() || b.is_ascii_uppercase() {
            return false;
        }
    }
    true
}

/// Bitcoin base58 alphabet: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.
/// Excludes `0`, `O`, `I`, `l`.
fn is_base58_char(c: char) -> bool {
    matches!(c,
        '1'..='9'
        | 'A'..='H'
        | 'J'..='N'
        | 'P'..='Z'
        | 'a'..='k'
        | 'm'..='z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_did() {
        // Min length: 32-char base58 suffix (`123456789` 9 + `ABCDEFGHJKLMNPQRSTUVWXY` 23).
        let min_did = "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXY";
        assert_eq!(min_did.len(), "did:mata:".len() + 32);
        assert!(is_valid_did(min_did));

        // Max length: 48-char base58 suffix.
        let max_did = "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpq";
        assert_eq!(max_did.len(), "did:mata:".len() + 48);
        assert!(is_valid_did(max_did));
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(!is_valid_did("mata:123456789ABCDEFGHJKLMNPQRSTUVWXYZ"));
        assert!(!is_valid_did("123456789ABCDEFGHJKLMNPQRSTUVWXYZ"));
    }

    #[test]
    fn rejects_too_short() {
        assert!(!is_valid_did("did:mata:abc"));
    }

    #[test]
    fn rejects_too_long() {
        let suffix: String = std::iter::repeat('A').take(49).collect();
        assert!(!is_valid_did(&format!("did:mata:{}", suffix)));
    }

    #[test]
    fn accepts_legacy_uuid_did() {
        // What the wallet's mata-identity layer produces today.
        assert!(is_valid_did(
            "did:mata:63c58bf2-ddfe-426c-9476-2f1625bc3f12"
        ));
        // All-zeros UUID is still well-formed shape-wise.
        assert!(is_valid_did(
            "did:mata:00000000-0000-0000-0000-000000000000"
        ));
    }

    #[test]
    fn rejects_uppercase_uuid() {
        // Uppercase hex isn't the format `uuid::Uuid::to_string()` produces;
        // accepting it would let two strings represent the same DID.
        assert!(!is_valid_did(
            "did:mata:63C58BF2-DDFE-426C-9476-2F1625BC3F12"
        ));
    }

    #[test]
    fn rejects_uuid_with_wrong_separator_positions() {
        // Hyphens in wrong places — 7/13/18/23 instead of 8/13/18/23.
        assert!(!is_valid_did(
            "did:mata:6c58bf-2ddfe-426c-9476-2f1625bc3f12a"
        ));
    }

    #[test]
    fn rejects_uuid_with_non_hex_char() {
        // 'z' at position 7 is in the base58 charset but not hex — checks
        // that we don't accidentally accept it via base58 fallback because
        // UUID format requires hex.
        assert!(!is_valid_did(
            "did:mata:63c58bfz-ddfe-426c-9476-2f1625bc3f12"
        ));
    }

    #[test]
    fn rejects_invalid_base58_chars() {
        // Contains 'O' (excluded from base58)
        assert!(!is_valid_did("did:mata:123456789ABCDEFGHJKLMNOPQRSTUVWXYZ"));
        // Contains 'l' (excluded)
        assert!(!is_valid_did(
            "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXYabcdefghijklmnpq"
        ));
        // Contains '0' (excluded)
        assert!(!is_valid_did("did:mata:0123456789ABCDEFGHJKLMNPQRSTUVWX"));
        // Contains 'I' (excluded)
        assert!(!is_valid_did("did:mata:123456789ABCDEFGHIJKLMNPQRSTUVWXY"));
    }
}
