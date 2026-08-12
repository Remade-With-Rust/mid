//! # `mata-sign` — sign arbitrary content as a `did:mata`, verifiable offline
//!
//! M1 of the [Signing Primitive Mission](../../../docs/plans/signing%20primitive%20mission.md).
//!
//! mID ([`mid-issuer`] / [`mid-verify`]) is already a signing primitive over
//! *identity claims*: a self-issued, **self-contained** token that proves a
//! `did:mata` authored it, verifiable by anyone with **zero MATA lookups**.
//! `mata-sign` generalizes that machinery from "claims" to **arbitrary
//! content** — a hiring document, a contract, or a Reddit/X/forum post
//! (IAMHUMAN, a PGP-equivalent for the open web).
//!
//! ## What it reuses (no crypto re-rolled here)
//!
//! - **Signing:** [`mid_issuer::build_jws_compact`] (ES256, P-256, low-s) over
//!   a JSON payload, plus the embedded-roster wire types + [`IdentitySnapshot`].
//! - **Verification:** the four self-contained checks from
//!   [`mid_verify::checks`] (genesis self-signature → roster chain → current VM
//!   in head roster → JWS signature) and the key/DID decoders.
//!
//! The only new surface is the **payload shape**: instead of mID's
//! `aud`/`nonce`/`claims`, [`SignedStatement`] carries `content_type` +
//! `content_hash` (+ optional `context`/`nonce`/`exp`/`content_preview`). The
//! identity-proof fields (`embedded_genesis_roster`, `embedded_roster_chain`,
//! `embedded_verification_method`) are the same ones mID embeds, so the
//! audited verification checks apply unchanged — `mata-sign` hands them a
//! synthetic [`mid_issuer::MidJwtPayload`] assembled from the statement's
//! identity fields.
//!
//! ## Detached by default
//!
//! [`sign_statement`] signs a **hash** of the content, not the content itself,
//! so signing a 2 GB PDF costs the same as signing a tweet. The verifier gets
//! the hash back in [`VerifiedStatement`] and confirms the bytes it holds via
//! [`VerifiedStatement::matches_content`]. An optional `content_preview`
//! inlines short text (e.g. a forum post) so a renderer can show the message
//! without a side channel.
//!
//! ## Self-contained model
//!
//! Every signature embeds the signer's device roster + proof-of-control inline
//! (exactly like an mID JWT), so a third party — a stranger on Reddit, an
//! offline verifier — checks it with no network and no MATA dependency. Public
//! signature hosting (`iamhuman.mata.network/<username>/<signedmessage>`) and
//! the post-appended verify URL are *future* features built on top of this
//! primitive; they are explicitly out of scope for M1.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mid_issuer::{
    build_jws_compact, EmbeddedGenesisRoster, EmbeddedRosterChainEntry,
    EmbeddedVerificationMethod, IdentitySnapshot, MidJwtPayload, VerificationMethod,
};
use mid_verify::checks;

/// `signed_at` stamped on the synthetic genesis roster built by
/// [`sign_single_device`]. Fixed (not the wall clock) so a given DID always
/// presents the same genesis roster — the value is irrelevant to verification
/// (the self-signature covers it, and no freshness check reads it).
const SINGLE_DEVICE_GENESIS_SIGNED_AT: u64 = 1_700_000_000;

const VM_TYPE_P256: &str = "EcdsaSecp256r1VerificationKey2019";

// Re-export the signer trait so callers don't need a separate `use`.
pub use mid_issuer::DeviceSigner;

// ─── The signed envelope ─────────────────────────────────────────────────────

/// S1 platform binding — ties a statement to *where* and *as which account* it
/// was signed for posting (frozen in
/// `docs/iamhuman/s1-platform-binding.md`).
///
/// The binding is **claimed by the signer** at sign time (the site adapter
/// reads the logged-in page); the signature makes the claim non-repudiable,
/// and platform-side observation (account-linking evidence) corroborates it.
/// A verifier should render it as "signed for posting on {platform} as
/// @{handle}", never "posted by @{handle}".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformBinding {
    /// Normalized platform host, e.g. `"x.com"` (adapters map aliases such as
    /// `twitter.com` onto one canonical value). Lowercase registrable host —
    /// no scheme, no path.
    pub platform: String,
    /// The account's display handle without `@`, if the adapter could read it.
    pub author_handle: Option<String>,
    /// The platform's **immutable** account id (e.g. X's numeric `rest_id`),
    /// if available. Handles rename and get recycled; this doesn't — a
    /// verifier should prefer it over `author_handle` when both are present.
    pub author_id: Option<String>,
}

/// The JSON payload of a signed statement — the JWS second segment.
///
/// Generalizes [`mid_issuer::MidJwtPayload`]: it keeps the three identity-proof
/// fields verbatim (so the audited mID checks apply unchanged) and swaps the
/// claim-specific fields for content-specific ones. Field order is the
/// serialization order; `serde_json` is deterministic for this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedStatement {
    /// Issuer — the signer's DID (`did:mata:…`). The genesis pubkey is
    /// recoverable from it, anchoring check 1.
    pub iss: String,
    /// Issued-at, Unix seconds. Caller-supplied (keeps signing pure).
    pub iat: u64,
    /// Optional expiry, Unix seconds. Documents typically have none; a
    /// short-lived post attestation might set one.
    pub exp: Option<u64>,
    /// Optional single-use nonce for anti-replay when a verifier issued one.
    pub nonce: Option<String>,
    /// Optional domain tag binding the signature to a use case, e.g.
    /// `"iamhuman"` or `"mata-doc"`. A verifier can require a specific value
    /// so an IAMHUMAN post signature can't be replayed as a document signature.
    pub context: Option<String>,
    /// IANA-style media type of the signed content, e.g. `"text/plain"`,
    /// `"application/pdf"`, `"application/json"`.
    pub content_type: String,
    /// `base64url(SHA-256(content))` — the detached content digest.
    pub content_hash: String,
    /// Optional inline copy of short text content (e.g. a forum post) so a
    /// renderer can show the message without fetching it separately. Never
    /// required for verification — the hash is authoritative.
    pub content_preview: Option<String>,
    /// Optional S1 platform binding — where / as which account this content
    /// was signed for posting. Absent (and absent from the serialized payload)
    /// for non-platform statements, so pre-S1 tokens and document/claim/blob
    /// signatures are byte-identical to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_binding: Option<PlatformBinding>,
    /// Self-signed genesis roster (signed by the key encoded in the DID).
    pub embedded_genesis_roster: EmbeddedGenesisRoster,
    /// Chain of wallet-signed roster mutations from genesis to current.
    pub embedded_roster_chain: Vec<EmbeddedRosterChainEntry>,
    /// The device key that signed this statement — must be in the head roster.
    pub embedded_verification_method: EmbeddedVerificationMethod,
}

/// The content to sign — raw bytes (hashed here) or a precomputed SHA-256.
#[derive(Debug, Clone, Copy)]
pub enum Content<'a> {
    /// Raw bytes; `mata-sign` computes `SHA-256` over them.
    Bytes(&'a [u8]),
    /// A precomputed 32-byte SHA-256 digest (for content already hashed
    /// upstream, or too large to pass by reference here).
    PrecomputedSha256([u8; 32]),
}

impl Content<'_> {
    /// The raw 32-byte digest for this content.
    fn digest(&self) -> [u8; 32] {
        match self {
            Content::Bytes(b) => Sha256::digest(b).into(),
            Content::PrecomputedSha256(h) => *h,
        }
    }
}

/// Inputs to [`sign_statement`].
#[derive(Debug, Clone)]
pub struct StatementInput<'a> {
    /// The content to sign (hashed, detached).
    pub content: Content<'a>,
    /// Media type recorded in the statement.
    pub content_type: String,
    /// Optional domain tag (see [`SignedStatement::context`]).
    pub context: Option<String>,
    /// Optional anti-replay nonce.
    pub nonce: Option<String>,
    /// Optional expiry, Unix seconds.
    pub exp: Option<u64>,
    /// Optional short-text preview to inline (see
    /// [`SignedStatement::content_preview`]).
    pub preview: Option<String>,
    /// Optional S1 platform binding (see [`SignedStatement::platform_binding`]).
    pub platform_binding: Option<PlatformBinding>,
}

impl<'a> StatementInput<'a> {
    /// Convenience: a minimal input over raw bytes with a media type.
    pub fn bytes(content: &'a [u8], content_type: impl Into<String>) -> Self {
        Self {
            content: Content::Bytes(content),
            content_type: content_type.into(),
            context: None,
            nonce: None,
            exp: None,
            preview: None,
            platform_binding: None,
        }
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Failure modes for [`sign_statement`].
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The [`IdentitySnapshot`] is internally inconsistent (signer VM not in
    /// the head roster, or VM controller ≠ DID).
    #[error("inconsistent identity snapshot: {0}")]
    InconsistentSnapshot(String),
    /// Serializing the statement payload to JSON failed.
    #[error("serialize statement: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The JWS signing step failed.
    #[error("jws signing: {0}")]
    Jws(#[from] mid_issuer::MidIssuerError),
}

/// Failure modes for [`verify_statement`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The token is structurally malformed (bad JWS shape, bad JSON, bad
    /// content-hash encoding).
    #[error("malformed token: {0}")]
    Malformed(String),
    /// One of the four self-contained cryptographic checks failed (reused
    /// from [`mid_verify`]).
    #[error("verification check failed: {0}")]
    Crypto(#[from] mid_verify::VerifyError),
    /// The statement has expired.
    #[error("statement expired (exp {exp} ≤ now {now})")]
    Expired {
        /// The statement's `exp`.
        exp: u64,
        /// The verifier's wall clock.
        now: u64,
    },
    /// The statement's `iat` is too far in the future (beyond allowed skew).
    #[error("statement not yet valid (iat {iat} > now {now} + skew {skew})")]
    NotYetValid {
        /// The statement's `iat`.
        iat: u64,
        /// The verifier's wall clock.
        now: u64,
        /// The allowed forward skew.
        skew: u64,
    },
    /// The statement's `context` didn't match the verifier's expectation.
    #[error("context mismatch: expected {expected:?}, got {got:?}")]
    ContextMismatch {
        /// What the verifier required.
        expected: Option<String>,
        /// What the statement carried.
        got: Option<String>,
    },
    /// The statement's `nonce` didn't match the verifier's expectation.
    #[error("nonce mismatch")]
    NonceMismatch,
}

// ─── Sign ────────────────────────────────────────────────────────────────────

/// Sign `input.content` as the DID in `snapshot`, returning a self-contained
/// JWS compact-form token (`header.payload.signature`).
///
/// `iat` is caller-supplied (read the wall clock once, pass it in) so this stays
/// a pure function. The content is signed **detached** — only its SHA-256 hash
/// goes into the token.
///
/// The caller provides a `signer` whose `device_id` corresponds to
/// `snapshot.current_verification_method`; in the app this comes from the
/// vault-loaded device key (see `packages/ui/src/services/kms_banking.rs`).
pub fn sign_statement(
    input: &StatementInput,
    snapshot: &IdentitySnapshot,
    signer: &dyn DeviceSigner,
    iat: u64,
) -> Result<String, SignError> {
    // Snapshot consistency — mirror the issuer's guards so a bad snapshot
    // fails here rather than producing an unverifiable token.
    if snapshot.current_verification_method.controller != snapshot.did {
        return Err(SignError::InconsistentSnapshot(format!(
            "current VM controller {} ≠ did {}",
            snapshot.current_verification_method.controller, snapshot.did
        )));
    }
    if !head_vm_ids(snapshot)
        .iter()
        .any(|id| id == &snapshot.current_verification_method.id)
    {
        return Err(SignError::InconsistentSnapshot(format!(
            "signer VM {} not in head roster",
            snapshot.current_verification_method.id
        )));
    }

    let statement = SignedStatement {
        iss: snapshot.did.clone(),
        iat,
        exp: input.exp,
        nonce: input.nonce.clone(),
        context: input.context.clone(),
        content_type: input.content_type.clone(),
        content_hash: URL_SAFE_NO_PAD.encode(input.content.digest()),
        content_preview: input.preview.clone(),
        platform_binding: input.platform_binding.clone(),
        embedded_genesis_roster: snapshot.genesis_roster.clone(),
        embedded_roster_chain: snapshot.roster_chain.clone(),
        embedded_verification_method: snapshot.current_verification_method.clone(),
    };

    let payload_json = serde_json::to_vec(&statement)?;
    Ok(build_jws_compact(&payload_json, signer)?)
}

/// Sign content as a **single-device** identity whose only key is `signer`,
/// constructing the genesis roster on the fly and self-signing it.
///
/// This is the path for **derived / service identities** — e.g. a per-company
/// business DID — that don't carry a persisted multi-device roster. Because the
/// DID encodes exactly one key, a one-entry genesis roster self-signed by that
/// key is a complete, self-contained proof: a verifier recovers the genesis
/// pubkey from the DID, checks the self-signature, sees an empty chain, and
/// confirms the JWS — all four checks pass with no external roster.
///
/// `did` MUST be `did:mata:<base58 SEC1-compressed pubkey>` and `multibase` the
/// `z<base58 …>` form of the **same** key (both decode to `signer`'s public
/// key). `device_id` labels the key — the VM id becomes `{did}#{device_id}`.
///
/// The genesis roster is self-signed via [`DeviceSigner::sign_prehash`] (the
/// device key *is* the genesis key here), so no separate signing primitive is
/// needed.
pub fn sign_single_device(
    did: &str,
    multibase: &str,
    device_id: &str,
    input: &StatementInput,
    signer: &dyn DeviceSigner,
    iat: u64,
) -> Result<String, SignError> {
    let vm_id = format!("{did}#{device_id}");
    let vm = VerificationMethod {
        id: vm_id.clone(),
        vm_type: VM_TYPE_P256.to_string(),
        controller: did.to_string(),
        public_key_multibase: multibase.to_string(),
    };
    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did: did.to_string(),
        verification_methods: vec![vm],
        signed_at: SINGLE_DEVICE_GENESIS_SIGNED_AT,
        self_signed_by_genesis_key: String::new(),
    };
    // Self-sign the genesis roster: the device key is the genesis key, so the
    // same `signer` produces the self-signature the DID-recovered key verifies.
    let canonical = mid_issuer::canonical::genesis_canonical_bytes(&genesis);
    let prehash: [u8; 32] = Sha256::digest(&canonical).into();
    genesis.self_signed_by_genesis_key = URL_SAFE_NO_PAD.encode(signer.sign_prehash(&prehash));

    let snapshot = IdentitySnapshot {
        did: did.to_string(),
        genesis_roster: genesis,
        roster_chain: vec![],
        current_verification_method: EmbeddedVerificationMethod {
            id: vm_id,
            vm_type: VM_TYPE_P256.to_string(),
            controller: did.to_string(),
            public_key_multibase: multibase.to_string(),
        },
        approved_claims: BTreeMap::new(),
    };
    sign_statement(input, &snapshot, signer, iat)
}

/// Verification-method IDs in the head roster (last chain entry, or genesis).
fn head_vm_ids(snapshot: &IdentitySnapshot) -> Vec<String> {
    match snapshot.roster_chain.last() {
        Some(head) => head.verification_methods.iter().map(|vm| vm.id.clone()).collect(),
        None => snapshot
            .genesis_roster
            .verification_methods
            .iter()
            .map(|vm| vm.id.clone())
            .collect(),
    }
}

// ─── IAMHUMAN proof addressing ───────────────────────────────────────────────

/// The content address (`post_id`) of an IAMHUMAN proof — frozen in
/// `docs/iamhuman/s1-platform-binding.md`.
///
/// - Unbound (pre-S1 tokens, non-platform statements):
///   `base58btc(SHA-256(text))`.
/// - Platform-bound (S1):
///   `base58btc(SHA-256("iamhuman/post/v2" ‖ 0x00 ‖ platform ‖ 0x00 ‖ text))`
///   — domain-separated (a hostname cannot contain NUL), so the same text
///   signed for two platforms is two distinct proofs. Platform only — the
///   handle lives in the signature; handles rename, addresses must not.
///
/// This is a pure function shared by `iamhuman-host` (server-side addressing)
/// and the extension background (local-first URL construction *before* the
/// host round-trip) — one implementation, so the two can never drift.
pub fn iamhuman_post_id(content: &str, platform: Option<&str>) -> String {
    let digest = match platform {
        Some(p) => {
            let mut h = Sha256::new();
            h.update(b"iamhuman/post/v2");
            h.update([0u8]);
            h.update(p.as_bytes());
            h.update([0u8]);
            h.update(content.as_bytes());
            h.finalize()
        }
        None => Sha256::digest(content.as_bytes()),
    };
    bs58::encode(digest).into_string()
}

// ─── Verify ──────────────────────────────────────────────────────────────────

/// Verifier-supplied policy for [`verify_statement`].
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// If set, the statement's `context` MUST equal this exactly.
    pub expected_context: Option<String>,
    /// If set, the statement's `nonce` MUST equal this exactly.
    pub expected_nonce: Option<String>,
    /// The verifier's current wall-clock time, Unix seconds.
    pub now_unix_secs: u64,
    /// Maximum allowed forward clock skew between the signer's `iat` and the
    /// verifier's clock, in seconds.
    pub max_iat_skew_secs: u64,
}

/// A successfully verified statement. The signature, roster chain, and freshness
/// are all confirmed; the caller still confirms the *content bytes* via
/// [`Self::matches_content`] (detached model).
#[derive(Debug, Clone)]
pub struct VerifiedStatement {
    /// The signer's DID — proven to control the signing key.
    pub did: String,
    /// The 32-byte SHA-256 the signer committed to.
    pub content_hash: [u8; 32],
    /// The media type the signer recorded.
    pub content_type: String,
    /// The head roster version (monotonic; rollback-detection signal).
    pub current_version: u64,
    /// Issued-at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds, if the signer set one.
    pub exp: Option<u64>,
    /// The domain tag the signer set, if any.
    pub context: Option<String>,
    /// The inlined short-text preview, if the signer included one.
    pub preview: Option<String>,
    /// The S1 platform binding the signer claimed, if any — where / as which
    /// account the content was signed for posting. Covered by the signature.
    pub platform_binding: Option<PlatformBinding>,
}

impl VerifiedStatement {
    /// Confirm that `content` is exactly what was signed (recomputes SHA-256
    /// and compares to the committed hash). The signature proves *who* and the
    /// hash proves *what* — call this to bind the two.
    pub fn matches_content(&self, content: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(content).into();
        digest == self.content_hash
    }
}

/// Verify a self-contained statement token: structural shape, the four
/// cryptographic checks (reused from [`mid_verify`]), then freshness + binding.
///
/// Does **not** check the content bytes — the caller does that with
/// [`VerifiedStatement::matches_content`] against the content it holds. Like
/// mID verification, this is a pure function: no I/O, no clock read, no remote
/// calls.
pub fn verify_statement(token: &str, opts: &VerifyOptions) -> Result<VerifiedStatement, VerifyError> {
    // 1. Structural: split + header.
    let parts = checks::split_jws(token)?;
    checks::validate_jws_header(&parts.header_bytes)?;
    let stmt: SignedStatement = serde_json::from_slice(&parts.payload_bytes)
        .map_err(|e| VerifyError::Malformed(format!("payload json: {e}")))?;

    // 2. Synthesize a MidJwtPayload from the identity-proof fields so the
    //    audited mID checks apply unchanged. The mID-specific fields
    //    (sub/aud/nonce/claims) are irrelevant to the four checks — check 4
    //    verifies against the ORIGINAL signing_input from `parts`, not a
    //    re-serialization of this synthetic payload.
    let synthetic = MidJwtPayload {
        iss: stmt.iss.clone(),
        sub: stmt.iss.clone(),
        aud: String::new(),
        iat: stmt.iat,
        exp: stmt.exp.unwrap_or(u64::MAX),
        nonce: String::new(),
        claims: BTreeMap::new(),
        embedded_genesis_roster: stmt.embedded_genesis_roster.clone(),
        embedded_roster_chain: stmt.embedded_roster_chain.clone(),
        embedded_verification_method: stmt.embedded_verification_method.clone(),
    };

    // 3. The four self-contained cryptographic checks.
    checks::check_genesis_self_signature(&synthetic)?;
    checks::check_roster_chain(&synthetic)?;
    checks::check_current_vm_in_head(&synthetic)?;
    checks::check_jws_signature(&synthetic, parts.signing_input, parts.signature_b64)?;

    // 4. Freshness + binding (statement-specific policy).
    if let Some(exp) = stmt.exp {
        if exp <= opts.now_unix_secs {
            return Err(VerifyError::Expired { exp, now: opts.now_unix_secs });
        }
    }
    if stmt.iat > opts.now_unix_secs.saturating_add(opts.max_iat_skew_secs) {
        return Err(VerifyError::NotYetValid {
            iat: stmt.iat,
            now: opts.now_unix_secs,
            skew: opts.max_iat_skew_secs,
        });
    }
    if let Some(want) = &opts.expected_context {
        if stmt.context.as_ref() != Some(want) {
            return Err(VerifyError::ContextMismatch {
                expected: Some(want.clone()),
                got: stmt.context.clone(),
            });
        }
    }
    if let Some(want) = &opts.expected_nonce {
        if stmt.nonce.as_ref() != Some(want) {
            return Err(VerifyError::NonceMismatch);
        }
    }

    // 5. Decode the committed content hash + head version.
    let hash_vec = URL_SAFE_NO_PAD
        .decode(&stmt.content_hash)
        .map_err(|e| VerifyError::Malformed(format!("content_hash base64: {e}")))?;
    let content_hash: [u8; 32] = hash_vec
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::Malformed(format!("content_hash is {} bytes, want 32", hash_vec.len())))?;
    let current_version = stmt
        .embedded_roster_chain
        .last()
        .map(|e| e.version)
        .unwrap_or(stmt.embedded_genesis_roster.version);

    Ok(VerifiedStatement {
        did: stmt.iss,
        content_hash,
        content_type: stmt.content_type,
        current_version,
        iat: stmt.iat,
        exp: stmt.exp,
        context: stmt.context,
        preview: stmt.content_preview,
        platform_binding: stmt.platform_binding,
    })
}
