//! `mata-cap` — the shared mID capability / authorization foundation.
//!
//! Every API-first MATA control-plane tool (Maestro, **Iron Bank**, and the rest)
//! gates the *same* way: a `did:mata` (its identity verified by `kms-verifier` at the
//! HTTP edge) carries a set of scoped [`Capability`] grants; every typed request
//! declares the capability it needs ([`ApiRequest`]); and one [`authorize`] chokepoint
//! checks the two. Factoring it here means each isolated service reuses the *identical*
//! sign-in/authz primitives rather than a drifting copy.

use serde::{Deserialize, Serialize};

/// A unit of authority: `component:action`, optionally scoped to a market/region.
/// E.g. `directory:read`, `payouts:approve@us-east`, `ledger:read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub component: String,
    pub action: String,
    #[serde(default)]
    pub scope: Option<String>,
}

impl Capability {
    pub fn new(component: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            component: component.into(),
            action: action.into(),
            scope: None,
        }
    }
    pub fn scoped(
        component: impl Into<String>,
        action: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            component: component.into(),
            action: action.into(),
            scope: Some(scope.into()),
        }
    }
    /// Canonical string: `component:action` or `component:action@scope`.
    pub fn as_str(&self) -> String {
        match &self.scope {
            Some(s) => format!("{}:{}@{}", self.component, self.action, s),
            None => format!("{}:{}", self.component, self.action),
        }
    }
    /// Does *this* held grant satisfy `needed`? Same component+action, and a global
    /// grant (`scope: None`) covers any scope while a scoped grant covers only its
    /// exact scope.
    pub fn satisfies(&self, needed: &Capability) -> bool {
        self.component == needed.component
            && self.action == needed.action
            && (self.scope.is_none() || self.scope == needed.scope)
    }
}

/// The authenticated caller — operator, AI agent, buyer, or node — identified by their
/// MATA mID, carrying the capabilities granted to that mID (resolved from the roster /
/// grants store).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Caller {
    pub did: String,
    pub grants: Vec<Capability>,
}

impl Caller {
    pub fn new(did: impl Into<String>, grants: Vec<Capability>) -> Self {
        Self {
            did: did.into(),
            grants,
        }
    }
    pub fn can(&self, needed: &Capability) -> bool {
        self.grants.iter().any(|g| g.satisfies(needed))
    }
}

/// Typed API errors shared across the control-plane tools.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApiError {
    #[error("unauthorized: requires capability `{0}`")]
    Unauthorized(String),
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// Every request declares the capability it requires — so the service, the UI, and a
/// management AI all gate on the *same* rule.
pub trait ApiRequest {
    fn required_capability(&self) -> Capability;
}

/// Gate a request against the caller's mID grants. The single chokepoint every tab
/// routes through.
pub fn authorize<R: ApiRequest>(caller: &Caller, request: &R) -> Result<(), ApiError> {
    let needed = request.required_capability();
    if caller.can(&needed) {
        Ok(())
    } else {
        Err(ApiError::Unauthorized(needed.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Req(Capability);
    impl ApiRequest for Req {
        fn required_capability(&self) -> Capability {
            self.0.clone()
        }
    }

    #[test]
    fn capability_string_forms() {
        assert_eq!(Capability::new("directory", "read").as_str(), "directory:read");
        assert_eq!(
            Capability::scoped("payouts", "approve", "us-east").as_str(),
            "payouts:approve@us-east"
        );
    }

    #[test]
    fn satisfies_scope_rules() {
        let global = Capability::new("ledger", "read");
        let us = Capability::scoped("ledger", "read", "us");
        assert!(global.satisfies(&Capability::new("ledger", "read")));
        assert!(global.satisfies(&Capability::scoped("ledger", "read", "eu")));
        assert!(us.satisfies(&Capability::scoped("ledger", "read", "us")));
        assert!(!us.satisfies(&Capability::scoped("ledger", "read", "eu")));
        assert!(!us.satisfies(&Capability::new("ledger", "read")));
        assert!(!global.satisfies(&Capability::new("ledger", "admin")));
    }

    #[test]
    fn authorize_gates_on_grants() {
        let treasurer = Caller::new("did:mata:t", vec![Capability::new("ledger", "read")]);
        assert!(authorize(&treasurer, &Req(Capability::new("ledger", "read"))).is_ok());
        assert_eq!(
            authorize(&treasurer, &Req(Capability::new("payouts", "approve"))),
            Err(ApiError::Unauthorized("payouts:approve".into()))
        );
    }
}
