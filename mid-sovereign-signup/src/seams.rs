use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use crate::code::Code;
use crate::email::NormalizedEmail;
use crate::records::TenantId;

// ─── Entropy ─────────────────────────────────────────────────────────────────

/// A source of random bytes. The core draws challenge ids, codes, user ids
/// and peppers through this seam so it stays deterministic under test and
/// pinnable in vectors.
pub trait Entropy {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError>;
}

/// The entropy source failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("entropy source failed: {0}")]
pub struct EntropyError(
    /// What failed.
    pub String,
);

/// The operating system's RNG (`getrandom`). The production source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(buf).map_err(|e| EntropyError(format!("OS RNG unavailable: {e}")))
    }
}

/// A fixed byte string handed out in order. For tests and vectors only: it
/// fails once exhausted rather than repeat, so a test that draws more than it
/// planned is told.
#[derive(Debug, Clone)]
pub struct FixedEntropy {
    bytes: Vec<u8>,
    pos: usize,
}

impl FixedEntropy {
    /// Serve exactly these bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
            pos: 0,
        }
    }

    /// Bytes not yet served.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}

impl Entropy for FixedEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
        if self.remaining() < buf.len() {
            return Err(EntropyError(format!(
                "fixed entropy exhausted: {} bytes requested, {} left",
                buf.len(),
                self.remaining()
            )));
        }
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + buf.len()]);
        self.pos += buf.len();
        Ok(())
    }
}

// ─── Mailer ──────────────────────────────────────────────────────────────────

/// A boxed future; `Send` everywhere but wasm32, where futures are not.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
/// A boxed future; `Send` everywhere but wasm32, where futures are not.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// The one message this crate sends: a code to an address. Built by
/// [`StartOutcome::message`](crate::StartOutcome::message); rendered by
/// [`Self::subject`] and [`Self::text_body`] unless the transport supplies
/// its own template.
#[derive(Debug, Clone)]
pub struct CodeMessage {
    /// Recipient.
    pub to: NormalizedEmail,
    /// The tenant the code belongs to.
    pub tenant: TenantId,
    /// The tenant's display name, for the subject and body.
    pub tenant_name: String,
    /// The code.
    pub code: Code,
    /// How long the code is valid from now.
    pub expires_in_secs: u64,
    /// Whether this is a first sign-up (`true`) or a sign-in to an account
    /// that may already exist. Lets a template say "welcome" vs "sign in"
    /// without the core knowing which.
    pub create_user: bool,
}

impl CodeMessage {
    /// `"123456 is your Acme code"` — the code first, so it shows in a
    /// notification preview.
    pub fn subject(&self) -> String {
        format!("{} is your {} code", self.code, self.tenant_name)
    }

    /// A plain-text body. Deliberately plain: no links (nothing to phish),
    /// no HTML, the code and its lifetime.
    pub fn text_body(&self) -> String {
        let minutes = self.expires_in_secs.div_ceil(60);
        format!(
            "Your {name} code is:\n\n    {code}\n\nIt expires in {minutes} minute{s}. \
             If you did not request it, ignore this message — nothing happens \
             without the code.\n",
            name = self.tenant_name,
            code = self.code,
            s = if minutes == 1 { "" } else { "s" },
        )
    }
}

/// The one-time welcome after a first sign-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeMessage {
    /// Recipient.
    pub to: NormalizedEmail,
    /// The tenant.
    pub tenant: TenantId,
    /// The tenant's display name.
    pub tenant_name: String,
    /// The handle the user chose, when they have one yet.
    pub username: Option<String>,
}

/// Email delivery. Implement over your transport (SES, SMTP, a queue); the
/// core only hands you a [`CodeMessage`].
pub trait Mailer {
    /// Deliver the code. A failure means the user never got it: the caller
    /// should surface a retry, not pretend.
    fn send_code(&self, msg: CodeMessage) -> BoxFuture<'_, Result<(), MailError>>;

    /// Welcome a new user (once, after their first sign-up). Best-effort: a
    /// failure is logged, never shown to the user. The default sends nothing.
    fn send_welcome(&self, msg: WelcomeMessage) -> BoxFuture<'_, Result<(), MailError>> {
        let _ = msg;
        Box::pin(async { Ok(()) })
    }

    /// A short name for health reports (`"ses"`, `"stub"`, …).
    fn kind(&self) -> &'static str {
        "custom"
    }
}

/// Delivery failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MailError {
    /// The transport could not be reached or errored.
    #[error("mail transport failed: {0}")]
    Transport(String),
    /// The provider refused the message (bad recipient, suppressed address).
    #[error("mail rejected by the provider: {0}")]
    Rejected(String),
}

/// A [`Mailer`] that records messages instead of sending them. The
/// development transport (an operator with no mail provider configured reads
/// codes from it) and the test double.
#[derive(Default)]
pub struct StubMailer {
    sent: Mutex<Vec<CodeMessage>>,
    welcomed: Mutex<Vec<WelcomeMessage>>,
}

impl StubMailer {
    /// An empty stub.
    pub fn new() -> Self {
        Self::default()
    }

    /// Messages recorded so far.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// `true` iff nothing was recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The welcomes recorded so far.
    pub fn welcomes(&self) -> Vec<WelcomeMessage> {
        self.welcomed.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Drain the recorded messages.
    pub fn take(&self) -> Vec<CodeMessage> {
        std::mem::take(&mut *self.lock())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<CodeMessage>> {
        self.sent.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl fmt::Debug for StubMailer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StubMailer({} queued)", self.len())
    }
}

impl Mailer for StubMailer {
    fn send_code(&self, msg: CodeMessage) -> BoxFuture<'_, Result<(), MailError>> {
        self.lock().push(msg);
        Box::pin(async { Ok(()) })
    }

    fn send_welcome(&self, msg: WelcomeMessage) -> BoxFuture<'_, Result<(), MailError>> {
        self.welcomed.lock().unwrap_or_else(|e| e.into_inner()).push(msg);
        Box::pin(async { Ok(()) })
    }

    fn kind(&self) -> &'static str {
        "stub"
    }
}
