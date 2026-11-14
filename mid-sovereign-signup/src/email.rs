use std::fmt;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::enc;
use crate::pepper::Pepper;
use crate::records::TenantId;

/// Longest accepted address, in bytes (RFC 5321 path limit).
pub const MAX_EMAIL_LEN: usize = 254;
/// Longest accepted local part (the text before `@`), in bytes.
pub const MAX_LOCAL_LEN: usize = 64;
/// Longest accepted domain, in bytes.
pub const MAX_DOMAIN_LEN: usize = 253;
/// Longest accepted DNS label inside the domain, in bytes.
pub const MAX_LABEL_LEN: usize = 63;

/// Why an address was refused by [`NormalizedEmail::parse`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EmailError {
    /// Nothing but whitespace.
    #[error("empty")]
    Empty,
    /// Longer than [`MAX_EMAIL_LEN`] after trimming.
    #[error("too long ({len} > {MAX_EMAIL_LEN})")]
    TooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// No `@`.
    #[error("missing '@'")]
    MissingAt,
    /// More than one `@` (quoted local parts are not supported).
    #[error("more than one '@'")]
    MultipleAt,
    /// Nothing before the `@`.
    #[error("empty local part")]
    EmptyLocal,
    /// Local part longer than [`MAX_LOCAL_LEN`].
    #[error("local part too long ({len} > {MAX_LOCAL_LEN})")]
    LocalTooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// The local part contains whitespace, a control character, or one of
    /// `< > ( ) [ ] \ , ; : "`.
    #[error("local part contains a forbidden character")]
    BadLocalChar,
    /// Nothing after the `@`.
    #[error("empty domain")]
    EmptyDomain,
    /// Domain longer than [`MAX_DOMAIN_LEN`].
    #[error("domain too long ({len} > {MAX_DOMAIN_LEN})")]
    DomainTooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// The domain has a single label (`user@localhost`): undeliverable on the
    /// public internet, and the one shape typo'd addresses most often take.
    #[error("domain must have at least two labels (e.g. example.com)")]
    DomainNeedsDot,
    /// A domain label is empty, longer than [`MAX_LABEL_LEN`], contains
    /// something other than ASCII letters, digits and hyphens, or starts or
    /// ends with a hyphen. Internationalized domains must arrive as punycode.
    #[error("domain label is empty, too long, or not letters/digits/hyphens")]
    BadDomainLabel,
}

/// An email address in canonical form: trimmed, lowercased, structurally
/// valid. Two inputs that normalize equal are the same account.
///
/// Lowercasing the **whole** address (not only the domain) follows what every
/// mainstream provider and the systems this crate replaces do; the RFC's
/// case-sensitive local part is honoured by nobody a user can actually mail.
/// Plus-addressing and dots are preserved: `a.b+c@x.com` and `ab@x.com` are
/// different accounts, as they are at the provider.
///
/// `Debug` masks the local part so records can be logged without leaking the
/// address; use [`Self::as_str`] when you mean to send mail.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NormalizedEmail(String);

impl NormalizedEmail {
    /// Normalize and validate a raw address.
    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(EmailError::Empty);
        }
        let lowered = trimmed.to_lowercase();
        if lowered.len() > MAX_EMAIL_LEN {
            return Err(EmailError::TooLong { len: lowered.len() });
        }
        match lowered.matches('@').count() {
            0 => return Err(EmailError::MissingAt),
            1 => {}
            _ => return Err(EmailError::MultipleAt),
        }
        let (local, domain) = lowered.split_once('@').expect("exactly one '@'");
        validate_local(local)?;
        validate_domain(domain)?;
        Ok(Self(lowered))
    }

    /// The canonical address.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The text before `@`.
    pub fn local(&self) -> &str {
        self.0.split_once('@').map(|(l, _)| l).unwrap_or("")
    }

    /// The text after `@`.
    pub fn domain(&self) -> &str {
        self.0.split_once('@').map(|(_, d)| d).unwrap_or("")
    }
}

fn validate_local(local: &str) -> Result<(), EmailError> {
    if local.is_empty() {
        return Err(EmailError::EmptyLocal);
    }
    if local.len() > MAX_LOCAL_LEN {
        return Err(EmailError::LocalTooLong { len: local.len() });
    }
    const FORBIDDEN: &str = "<>()[]\\,;:\"";
    if local
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || FORBIDDEN.contains(c))
    {
        return Err(EmailError::BadLocalChar);
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<(), EmailError> {
    if domain.is_empty() {
        return Err(EmailError::EmptyDomain);
    }
    if domain.len() > MAX_DOMAIN_LEN {
        return Err(EmailError::DomainTooLong { len: domain.len() });
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(EmailError::DomainNeedsDot);
    }
    for label in labels {
        let ok = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(EmailError::BadDomainLabel);
        }
    }
    Ok(())
}

impl fmt::Display for NormalizedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for NormalizedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let first = self.local().chars().next().unwrap_or('?');
        write!(f, "NormalizedEmail({first}***@{})", self.domain())
    }
}

impl TryFrom<String> for NormalizedEmail {
    type Error = EmailError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<NormalizedEmail> for String {
    fn from(e: NormalizedEmail) -> Self {
        e.0
    }
}

impl AsRef<str> for NormalizedEmail {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

const EMAIL_INDEX_DOMAIN: &[u8] = b"mid-sovereign-signup/email-index/v1\0";

/// The peppered lookup key for an address within a tenant:
/// `HMAC-SHA256(pepper, "…/email-index/v1" ‖ tenant ‖ NUL ‖ email)`.
///
/// Stores index users and live challenges by this value, so their key space
/// never contains an address; audit events carry it in place of the address.
/// It is a lookup key, not a secret — equality is plain equality.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EmailIndex([u8; 32]);

impl EmailIndex {
    /// Derive the index for `email` within `tenant`.
    pub fn derive(pepper: &Pepper, tenant: &TenantId, email: &NormalizedEmail) -> Self {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).expect("HMAC accepts any key length");
        mac.update(EMAIL_INDEX_DOMAIN);
        mac.update(tenant.as_str().as_bytes());
        mac.update(b"\0");
        mac.update(email.as_str().as_bytes());
        Self(mac.finalize().into_bytes().into())
    }

    /// Wrap raw bytes read back from a store.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// base64url (no padding) — the form used in keys, audit rows and the
    /// attestation.
    pub fn to_base64url(&self) -> String {
        enc::encode(&self.0)
    }
}

impl fmt::Display for EmailIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64url())
    }
}

impl fmt::Debug for EmailIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmailIndex({})", self.to_base64url())
    }
}

impl TryFrom<String> for EmailIndex {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        enc::decode_exact::<32>(&s).map(Self)
    }
}

impl From<EmailIndex> for String {
    fn from(i: EmailIndex) -> Self {
        i.to_base64url()
    }
}
