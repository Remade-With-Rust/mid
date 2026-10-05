use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::email::EmailIndex;
use crate::enc;
use crate::pepper::Pepper;
use crate::records::{ChallengeId, TenantId};
use crate::seams::{Entropy, EntropyError};

/// Digits in a code.
pub const CODE_DIGITS: usize = 6;
/// Number of distinct codes (10⁶).
pub const CODE_SPACE: u32 = 1_000_000;

const CODE_MAC_DOMAIN: &[u8] = b"mid-sovereign-signup/code/v1\0";

/// A six-digit one-time code, zero-padded (`"004217"`).
///
/// Lives only in transit: [`crate::flow::start`] returns it for the
/// [`Mailer`](crate::Mailer), and [`crate::flow::verify`] parses the user's
/// entry. It is never stored — the [`Challenge`](crate::Challenge) holds a
/// [`CodeMac`] commitment instead. There is no `PartialEq`: codes are only
/// ever compared through [`CodeMac::verify`], in constant time. `Debug` is
/// redacted.
#[derive(Clone)]
pub struct Code([u8; CODE_DIGITS]);

impl Code {
    /// Draw a uniformly random code. Uses rejection sampling over a 32-bit
    /// draw so no value is favoured by the modulus (the rejected band is
    /// `u32::MAX % 10⁶` wide — about one draw in 4,400 is retried).
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Self, EntropyError> {
        const LIMIT: u32 = u32::MAX - (u32::MAX % CODE_SPACE);
        loop {
            let mut raw = [0u8; 4];
            entropy.fill(&mut raw)?;
            let n = u32::from_be_bytes(raw);
            if n < LIMIT {
                return Ok(Self::from_u32(n % CODE_SPACE));
            }
        }
    }

    fn from_u32(n: u32) -> Self {
        debug_assert!(n < CODE_SPACE);
        let s = format!("{n:0width$}", width = CODE_DIGITS);
        Self(s.as_bytes().try_into().expect("six ASCII digits"))
    }

    /// Parse user entry. ASCII whitespace and hyphens between digits are
    /// ignored (`"123 456"`, `"123-456"`), so copy-paste from a formatted
    /// message works; anything else must be exactly six digits.
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        let mut digits = [0u8; CODE_DIGITS];
        let mut n = 0;
        for c in input.chars() {
            if c.is_ascii_whitespace() || c == '-' {
                continue;
            }
            if !c.is_ascii_digit() {
                return Err(CodeError::NotDigits);
            }
            if n == CODE_DIGITS {
                return Err(CodeError::WrongLength);
            }
            digits[n] = c as u8;
            n += 1;
        }
        if n != CODE_DIGITS {
            return Err(CodeError::WrongLength);
        }
        Ok(Self(digits))
    }

    /// The six digits, for the message body.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("ASCII digits")
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(******)")
    }
}

/// Why user entry was not a code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodeError {
    /// Not exactly six digits once separators are dropped.
    #[error("a code is exactly {CODE_DIGITS} digits")]
    WrongLength,
    /// A character other than a digit, whitespace, or hyphen.
    #[error("a code contains only digits")]
    NotDigits,
}

/// The stored commitment to a code:
/// `HMAC-SHA256(pepper, "…/code/v1" ‖ tenant ‖ NUL ‖ email_idx ‖ challenge_id ‖ code)`.
///
/// Binding the tenant, the address index and the challenge id means a
/// commitment proves nothing outside the one challenge it was minted for — a
/// resend invalidates the previous code structurally, not by bookkeeping.
/// Verification is constant-time. `Debug` is redacted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CodeMac([u8; 32]);

impl CodeMac {
    /// Commit to `code` for one challenge.
    pub fn commit(
        pepper: &Pepper,
        tenant: &TenantId,
        email_idx: &EmailIndex,
        challenge: &ChallengeId,
        code: &Code,
    ) -> Self {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key length");
        mac.update(CODE_MAC_DOMAIN);
        mac.update(tenant.as_str().as_bytes());
        mac.update(b"\0");
        mac.update(email_idx.as_bytes());
        mac.update(challenge.as_bytes());
        mac.update(&code.0);
        Self(mac.finalize().into_bytes().into())
    }

    /// `true` iff `candidate` is the committed code, compared in constant
    /// time. The cost is one HMAC either way, so a wrong guess and a right
    /// one are indistinguishable by timing.
    pub fn verify(
        &self,
        pepper: &Pepper,
        tenant: &TenantId,
        email_idx: &EmailIndex,
        challenge: &ChallengeId,
        candidate: &Code,
    ) -> bool {
        let expected = Self::commit(pepper, tenant, email_idx, challenge, candidate);
        bool::from(self.0.ct_eq(&expected.0))
    }

    /// Wrap raw bytes read back from a store.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// base64url (no padding), the at-rest encoding.
    pub fn to_base64url(&self) -> String {
        enc::encode(&self.0)
    }
}

/// Constant-time, so `==` on a commitment can never become a timing oracle.
impl PartialEq for CodeMac {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for CodeMac {}

impl fmt::Debug for CodeMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeMac(<redacted>)")
    }
}

impl TryFrom<String> for CodeMac {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        enc::decode_exact::<32>(&s).map(Self)
    }
}

impl From<CodeMac> for String {
    fn from(m: CodeMac) -> Self {
        m.to_base64url()
    }
}
