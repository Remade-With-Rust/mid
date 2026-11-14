//! The two steps, as pure functions over records.
//!
//! A store wraps each in one transaction: load the inputs by key, call the
//! function, write back **everything** it returns. [`verify`] in particular
//! always returns the challenge to persist — attempts are counted on the
//! wrong-code path too — which is what makes the attempt limit real.

use crate::code::{Code, CodeMac};
use crate::email::{EmailIndex, NormalizedEmail};
use crate::error::FlowError;
use crate::pepper::Pepper;
use crate::policy::Policy;
use crate::records::{
    AuditEvent, AuditKind, Challenge, ChallengeId, ConsumedReason, RejectReason, TenantId, User,
    UserId,
};
use crate::seams::{CodeMessage, Entropy};

// ─── start ───────────────────────────────────────────────────────────────────

/// Inputs to [`start`].
#[derive(Debug, Clone)]
pub struct StartRequest<'a> {
    /// The tenant.
    pub tenant: &'a TenantId,
    /// The address as the user typed it; normalized here.
    pub email: &'a str,
    /// Whether a successful verify may create the user. `false` is
    /// sign-in-only (the code is still sent — start must not reveal
    /// enrollment).
    pub create_user: bool,
    /// Unix seconds.
    pub now: u64,
}

/// What [`start`] produced. The store writes `challenge` (by id and by live
/// key) and `superseded` (by id) in one transaction, appends `audit`, and
/// hands `code` to the [`Mailer`](crate::Mailer) — after the commit, so a
/// mailed code is always a stored commitment.
#[derive(Debug)]
pub struct StartOutcome {
    /// The new challenge, to persist.
    pub challenge: Challenge,
    /// The code, to mail. Never persist it.
    pub code: Code,
    /// The previously live challenge, now marked
    /// [`ConsumedReason::Superseded`], to persist by id. `None` when there
    /// was none (or it had already expired or ended).
    pub superseded: Option<Challenge>,
    /// Audit rows to append.
    pub audit: Vec<AuditEvent>,
}

impl StartOutcome {
    /// The message to hand the mailer.
    pub fn message(&self, tenant_name: impl Into<String>) -> CodeMessage {
        CodeMessage {
            to: self.challenge.email.clone(),
            tenant: self.challenge.tenant.clone(),
            tenant_name: tenant_name.into(),
            code: self.code.clone(),
            expires_in_secs: self
                .challenge
                .expires_at
                .saturating_sub(self.challenge.issued_at),
            create_user: self.challenge.create_user,
        }
    }
}

/// Issue a code for an address.
///
/// `live` is whatever the store holds under
/// [`Challenge::live_key`] for this tenant and address, if anything. A live,
/// in-cooldown challenge refuses the resend; a live one past the cooldown is
/// superseded; an expired or consumed one is ignored.
///
/// The outcome's shape does not depend on whether the address is enrolled:
/// start never reveals that.
pub fn start(
    req: &StartRequest<'_>,
    live: Option<Challenge>,
    policy: &Policy,
    pepper: &Pepper,
    entropy: &mut dyn Entropy,
) -> Result<StartOutcome, FlowError> {
    policy.validate()?;
    let email = NormalizedEmail::parse(req.email)?;
    let email_idx = EmailIndex::derive(pepper, req.tenant, &email);
    let mut audit = Vec::new();

    let superseded = match live {
        Some(mut prev) => {
            if prev.tenant != *req.tenant || prev.email_idx != email_idx {
                return Err(FlowError::ChallengeMismatch);
            }
            if prev.is_live(req.now) {
                let next_allowed = prev.issued_at.saturating_add(policy.resend_cooldown_secs);
                if req.now < next_allowed {
                    return Err(FlowError::ResendTooSoon {
                        retry_after_secs: next_allowed - req.now,
                    });
                }
                prev.consume(req.now, ConsumedReason::Superseded);
                audit.push(AuditEvent {
                    at: req.now,
                    tenant: req.tenant.clone(),
                    kind: AuditKind::ChallengeSuperseded,
                    user: None,
                    challenge: Some(prev.id),
                    email_idx: Some(email_idx),
                });
                Some(prev)
            } else {
                None
            }
        }
        None => None,
    };

    let id = ChallengeId::generate(entropy)?;
    let code = Code::generate(entropy)?;
    let code_mac = CodeMac::commit(pepper, req.tenant, &email_idx, &id, &code);
    let challenge = Challenge {
        id,
        tenant: req.tenant.clone(),
        email,
        email_idx,
        code_mac,
        create_user: req.create_user,
        issued_at: req.now,
        expires_at: req.now.saturating_add(policy.code_ttl_secs),
        max_attempts: policy.max_attempts,
        attempts: 0,
        consumed_at: None,
        consumed_reason: None,
    };
    audit.push(AuditEvent {
        at: req.now,
        tenant: req.tenant.clone(),
        kind: AuditKind::ChallengeIssued,
        user: None,
        challenge: Some(id),
        email_idx: Some(email_idx),
    });

    Ok(StartOutcome {
        challenge,
        code,
        superseded,
        audit,
    })
}

// ─── verify ──────────────────────────────────────────────────────────────────

/// Inputs to [`verify`].
#[derive(Debug, Clone)]
pub struct VerifyRequest<'a> {
    /// The tenant.
    pub tenant: &'a TenantId,
    /// The address as the user typed it; normalized here.
    pub email: &'a str,
    /// The code as the user typed it; parsed here.
    pub code: &'a str,
    /// Unix seconds.
    pub now: u64,
}

/// A successful verify.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The user, created or updated — to persist (by id and by email key).
    pub user: User,
    /// `true` iff `user` was created by this verify.
    pub user_created: bool,
    /// `true` iff this verify is the first proof of the address (always true
    /// when `user_created`; also true for an imported user whose
    /// `email_verified_at` was `None`).
    pub first_verification: bool,
}

/// Everything [`verify`] wants persisted, whichever way it went.
#[derive(Debug)]
pub struct VerifyResult {
    /// The challenge with its attempt count and consumption updated — write
    /// it back even on failure. `None` only when no challenge was supplied.
    pub challenge: Option<Challenge>,
    /// The user, or why not.
    pub outcome: Result<Verified, FlowError>,
    /// Audit rows to append.
    pub audit: Vec<AuditEvent>,
}

/// Check a presented code and sign the user up or in.
///
/// `challenge` is what the store holds under [`Challenge::live_key`] for this
/// tenant and address; `existing_user` is what it holds under
/// [`User::email_key`]. Both are optional because both may be absent; both
/// are checked to belong to this tenant and address, so a store that loads
/// the wrong row is caught rather than trusted.
///
/// Malformed input (a bad address, a non-six-digit code) is refused before
/// anything is counted — it cannot be a guess. Every well-formed guess counts
/// one attempt; the last wrong one consumes the challenge; a right one
/// consumes it too, and then creates the user (if `create_user`) or signs in
/// the existing one.
pub fn verify(
    req: &VerifyRequest<'_>,
    challenge: Option<Challenge>,
    existing_user: Option<User>,
    pepper: &Pepper,
    entropy: &mut dyn Entropy,
) -> VerifyResult {
    let mut audit = Vec::new();

    // Input validation: never counts as an attempt.
    let email = match NormalizedEmail::parse(req.email) {
        Ok(e) => e,
        Err(e) => {
            return VerifyResult {
                challenge,
                outcome: Err(e.into()),
                audit,
            }
        }
    };
    let code = match Code::parse(req.code) {
        Ok(c) => c,
        Err(e) => {
            return VerifyResult {
                challenge,
                outcome: Err(e.into()),
                audit,
            }
        }
    };
    let email_idx = EmailIndex::derive(pepper, req.tenant, &email);

    let rejected = |reason: RejectReason, challenge: Option<ChallengeId>| AuditEvent {
        at: req.now,
        tenant: req.tenant.clone(),
        kind: AuditKind::CodeRejected { reason },
        user: None,
        challenge,
        email_idx: Some(email_idx),
    };

    let Some(mut ch) = challenge else {
        audit.push(rejected(RejectReason::Missing, None));
        return VerifyResult {
            challenge: None,
            outcome: Err(FlowError::NoLiveChallenge),
            audit,
        };
    };
    if ch.tenant != *req.tenant || ch.email_idx != email_idx {
        return VerifyResult {
            challenge: Some(ch),
            outcome: Err(FlowError::ChallengeMismatch),
            audit,
        };
    }
    if ch.consumed_at.is_some() {
        audit.push(rejected(RejectReason::Consumed, Some(ch.id)));
        return VerifyResult {
            challenge: Some(ch),
            outcome: Err(FlowError::AlreadyConsumed),
            audit,
        };
    }
    if req.now >= ch.expires_at {
        audit.push(rejected(RejectReason::Expired, Some(ch.id)));
        return VerifyResult {
            challenge: Some(ch),
            outcome: Err(FlowError::Expired),
            audit,
        };
    }
    if ch.attempts >= ch.max_attempts {
        // Defensive: an exhausted challenge is consumed on its last wrong
        // guess, but a record from before that rule (or a hand-edited one)
        // must still refuse.
        ch.consume(req.now, ConsumedReason::Exhausted);
        audit.push(rejected(RejectReason::Exhausted, Some(ch.id)));
        return VerifyResult {
            challenge: Some(ch),
            outcome: Err(FlowError::AttemptsExhausted),
            audit,
        };
    }

    // A well-formed guess: count it, then check it in constant time.
    ch.attempts += 1;
    let matched = ch
        .code_mac
        .verify(pepper, req.tenant, &email_idx, &ch.id, &code);
    if !matched {
        if ch.attempts >= ch.max_attempts {
            ch.consume(req.now, ConsumedReason::Exhausted);
            audit.push(rejected(RejectReason::Exhausted, Some(ch.id)));
            return VerifyResult {
                challenge: Some(ch),
                outcome: Err(FlowError::AttemptsExhausted),
                audit,
            };
        }
        audit.push(rejected(RejectReason::Wrong, Some(ch.id)));
        let attempts_left = ch.attempts_left();
        return VerifyResult {
            challenge: Some(ch),
            outcome: Err(FlowError::WrongCode { attempts_left }),
            audit,
        };
    }

    // The right code: spend the challenge before anything else can fail.
    ch.consume(req.now, ConsumedReason::Verified);

    let outcome = match existing_user {
        Some(mut user) => {
            if user.tenant != *req.tenant || user.email_idx != email_idx {
                Err(FlowError::UserMismatch)
            } else {
                let first_verification = user.email_verified_at.is_none();
                if first_verification {
                    user.email_verified_at = Some(req.now);
                }
                user.last_sign_in_at = Some(req.now);
                audit.push(AuditEvent {
                    at: req.now,
                    tenant: req.tenant.clone(),
                    kind: AuditKind::CodeAccepted,
                    user: Some(user.id.clone()),
                    challenge: Some(ch.id),
                    email_idx: Some(email_idx),
                });
                Ok(Verified {
                    user,
                    user_created: false,
                    first_verification,
                })
            }
        }
        None if !ch.create_user => {
            audit.push(rejected(RejectReason::UnknownUser, Some(ch.id)));
            Err(FlowError::UnknownUser)
        }
        None => match UserId::generate(entropy) {
            Err(e) => Err(e.into()),
            Ok(id) => {
                let user = User {
                    id: id.clone(),
                    tenant: req.tenant.clone(),
                    email,
                    email_idx,
                    email_verified_at: Some(req.now),
                    created_at: req.now,
                    last_sign_in_at: Some(req.now),
                    linked_did: None,
                    username: None,
                    metadata: Default::default(),
                };
                audit.push(AuditEvent {
                    at: req.now,
                    tenant: req.tenant.clone(),
                    kind: AuditKind::CodeAccepted,
                    user: Some(id.clone()),
                    challenge: Some(ch.id),
                    email_idx: Some(email_idx),
                });
                audit.push(AuditEvent {
                    at: req.now,
                    tenant: req.tenant.clone(),
                    kind: AuditKind::UserCreated,
                    user: Some(id),
                    challenge: Some(ch.id),
                    email_idx: Some(email_idx),
                });
                Ok(Verified {
                    user,
                    user_created: true,
                    first_verification: true,
                })
            }
        },
    };

    VerifyResult {
        challenge: Some(ch),
        outcome,
        audit,
    }
}
