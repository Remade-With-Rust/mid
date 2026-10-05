use std::fmt;

use zeroize::Zeroize;

use crate::enc;
use crate::seams::{Entropy, EntropyError};

/// The server-held secret under which code commitments and email indexes are
/// computed. 32 bytes; generate once per deployment, keep it out of the store
/// it protects, and treat rotation as a migration (every stored index and
/// live challenge is bound to it).
///
/// Zeroized on drop. `Debug` never prints the bytes.
pub struct Pepper([u8; Pepper::LEN]);

impl Pepper {
    /// Pepper length in bytes.
    pub const LEN: usize = 32;

    /// Wrap caller-supplied bytes (e.g. decoded from a secrets manager).
    pub fn from_bytes(bytes: [u8; Pepper::LEN]) -> Self {
        Self(bytes)
    }

    /// Mint a fresh pepper from the entropy source.
    pub fn generate(entropy: &mut dyn Entropy) -> Result<Self, EntropyError> {
        let mut bytes = [0u8; Pepper::LEN];
        entropy.fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Decode a pepper from base64url (no padding), the form
    /// [`Self::expose_base64url`] produces.
    pub fn from_base64url(s: &str) -> Result<Self, PepperError> {
        enc::decode_exact::<{ Pepper::LEN }>(s.trim())
            .map(Self)
            .map_err(PepperError)
    }

    /// The pepper as base64url — for writing a freshly generated pepper to a
    /// secret store **once**. Named to make the exposure visible at the call
    /// site.
    pub fn expose_base64url(&self) -> String {
        enc::encode(&self.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; Pepper::LEN] {
        &self.0
    }
}

impl Drop for Pepper {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Pepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pepper(<redacted>)")
    }
}

/// The supplied pepper encoding was not exactly 32 bytes of base64url.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("pepper must be exactly 32 bytes base64url: {0}")]
pub struct PepperError(
    /// What was wrong with the encoding.
    pub String,
);
