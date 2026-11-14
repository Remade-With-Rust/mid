//! Configuration from the environment, shared by `signupd` and operator
//! builds that wrap it (so every deployment reads the same variables).
//!
//! | Variable | Meaning |
//! |---|---|
//! | `SIGNUP_BIND` | listen address (default `0.0.0.0:8080`) |
//! | `SIGNUP_DB` | store directory (default `./signup-data`; a volume in production) |
//! | `SIGNUP_PEPPER` | **required** — 32 bytes, hex or base64url; indexes every address. Keep it off the volume. |
//! | `SIGNUP_IDENTITY_KEY` | the service DID's P-256 secret, 32 bytes; unset = `identity.key` in the store directory (created once) |
//! | `SIGNUP_OPERATORS` | comma-separated operator DIDs |
//! | `SIGNUP_IMPORT_TOKEN` | opens `POST /v1/import` while set (≥ 32 characters) |
//! | `SIGNUP_CLIENT_IP_HEADER` | trusted proxy header with the client address (e.g. `fly-client-ip`) |
//! | `SIGNUP_ISSUER` | the assertion audience/issuer name (default `mid-sovereign-signup`) |
//! | `SIGNUP_BOOTSTRAP_TENANTS` | `id|Name|origin origin;id2|Name2|…` — created at boot if absent |
//! | `SIGNUP_BOOTSTRAP_WEBHOOKS` | `tenant|format|event,event|url;…` — endpoints kept in sync at boot (format `event` or `slack`); a URL may be a credential, so set it as a secret |

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::ServerConfig;
use crate::store::{SignupStore, StoreEngine, StoreError};
use crate::{OsEntropy, Tenant, TenantId};

/// Read a 32-byte secret from `var` (64 hex chars or base64url).
/// `Ok(None)` when unset or empty.
pub fn key32(var: &str) -> Result<Option<[u8; 32]>, String> {
    let Some(raw) = std::env::var(var).ok().filter(|v| !v.trim().is_empty()) else {
        return Ok(None);
    };
    parse_key32(raw.trim())
        .map(Some)
        .map_err(|e| format!("{var}: {e}"))
}

/// Parse a 32-byte secret given as 64 hex characters or base64url.
pub fn parse_key32(raw: &str) -> Result<[u8; 32], String> {
    let bytes = if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..32)
            .map(|i| u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| format!("bad hex: {e}"))?
    } else {
        URL_SAFE_NO_PAD
            .decode(raw.trim_end_matches('='))
            .map_err(|e| format!("expected 32 bytes as hex or base64url: {e}"))?
    };
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}

/// Read a 32-byte secret file, or create it from the OS RNG (mode `0600`,
/// never overwriting).
pub fn load_or_create_key(path: &Path) -> Result<[u8; 32], String> {
    match std::fs::read(path) {
        Ok(b) => b
            .try_into()
            .map_err(|b: Vec<u8>| format!("{} is {} bytes, expected 32", path.display(), b.len())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use crate::Entropy as _;
            use std::io::Write as _;
            let mut key = [0u8; 32];
            OsEntropy.fill(&mut key).map_err(|e| e.to_string())?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(path)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            f.write_all(&key)
                .and_then(|_| f.sync_all())
                .map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(key)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// A tenant to create at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTenant {
    /// Tenant id.
    pub id: TenantId,
    /// Display name.
    pub name: String,
    /// Allowed browser origins.
    pub origins: Vec<String>,
}

/// Parse `id|Name|origin origin;id2|Name2|…`.
pub fn parse_bootstrap(raw: &str) -> Result<Vec<BootstrapTenant>, String> {
    raw.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|spec| {
            let mut parts = spec.splitn(3, '|');
            let id = parts.next().unwrap_or("").trim();
            let name = parts
                .next()
                .ok_or_else(|| format!("{spec:?}: expected id|Name|origins"))?
                .trim();
            let origins = parts
                .next()
                .unwrap_or("")
                .split_whitespace()
                .map(str::to_string)
                .collect();
            Ok(BootstrapTenant {
                id: TenantId::parse(id).map_err(|e| format!("{spec:?}: {e}"))?,
                name: name.to_string(),
                origins,
            })
        })
        .collect()
}

/// Create each bootstrap tenant that does not exist yet; log every public id.
pub fn bootstrap<E: StoreEngine>(
    store: &SignupStore<E>,
    tenants: &[BootstrapTenant],
    now: u64,
) -> Result<(), StoreError> {
    for b in tenants {
        let t = match store.tenant(&b.id)? {
            Some(t) => t,
            None => {
                let t = Tenant::new(
                    b.id.clone(),
                    b.name.clone(),
                    b.origins.clone(),
                    now,
                    &mut OsEntropy,
                )
                .map_err(crate::FlowError::from)?;
                store.create_tenant(&t)?;
                tracing::info!(tenant = %t.id, "bootstrap tenant created");
                t
            }
        };
        tracing::info!(tenant = %t.id, public_id = %t.public_id, origins = ?t.origins, "tenant ready");
    }
    Ok(())
}

/// A webhook endpoint declared in the environment.
#[derive(Clone, PartialEq, Eq)]
pub struct BootstrapWebhook {
    /// The tenant.
    pub tenant: TenantId,
    /// The body format.
    pub format: crate::WebhookFormat,
    /// Subscribed events.
    pub events: Vec<String>,
    /// Delivery URL (may be a credential: never logged).
    pub url: String,
}

impl std::fmt::Debug for BootstrapWebhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapWebhook")
            .field("tenant", &self.tenant)
            .field("format", &self.format)
            .field("events", &self.events)
            .field("url", &crate::records::url_origin(&self.url))
            .finish()
    }
}

impl BootstrapWebhook {
    /// Endpoints declared here are `wh_cfg_<hash of tenant, format, events>`:
    /// stable across URL changes (a new URL updates the endpoint in place),
    /// and distinct from API-created `wh_` ids.
    pub fn id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut events = self.events.clone();
        events.sort();
        let h = Sha256::digest(
            format!("{}|{}|{}", self.tenant, self.format.as_str(), events.join(",")).as_bytes(),
        );
        let hex: String = h.iter().take(6).map(|b| format!("{b:02x}")).collect();
        format!("{CONFIG_WEBHOOK_PREFIX}{hex}")
    }
}

/// Id prefix of endpoints owned by `SIGNUP_BOOTSTRAP_WEBHOOKS`.
pub const CONFIG_WEBHOOK_PREFIX: &str = "wh_cfg_";

/// Parse `tenant|format|event,event|url;…`.
pub fn parse_bootstrap_webhooks(raw: &str) -> Result<Vec<BootstrapWebhook>, String> {
    raw.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(n, spec)| {
            // Never echo a spec: its URL may be the credential.
            let bad = |why: &str| format!("SIGNUP_BOOTSTRAP_WEBHOOKS entry {}: {why}", n + 1);
            let parts: Vec<&str> = spec.splitn(4, '|').map(str::trim).collect();
            let [tenant, format, events, url] = parts[..] else {
                return Err(bad("expected tenant|format|events|url"));
            };
            let format = crate::WebhookFormat::parse(format)
                .ok_or_else(|| bad("format must be event or slack"))?;
            let events: Vec<String> = events
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect();
            if events.is_empty() || events.iter().any(|e| !crate::WEBHOOK_EVENTS.contains(&e.as_str())) {
                return Err(bad(&format!("events must be a non-empty subset of {:?}", crate::WEBHOOK_EVENTS)));
            }
            if !url.starts_with("https://") {
                return Err(bad("url must be https"));
            }
            Ok(BootstrapWebhook {
                tenant: TenantId::parse(tenant).map_err(|e| bad(&e.to_string()))?,
                format,
                events,
                url: url.to_string(),
            })
        })
        .collect()
}

/// Make every tenant's `wh_cfg_` endpoints exactly the declared set: create or
/// update the declared ones, remove any the configuration no longer names.
pub fn bootstrap_webhooks<E: StoreEngine>(
    store: &SignupStore<E>,
    hooks: &[BootstrapWebhook],
    now: u64,
) -> Result<(), StoreError> {
    for h in hooks {
        let changed = store.ensure_webhook(
            &h.tenant,
            &h.id(),
            &h.url,
            h.events.clone(),
            h.format,
            now,
            &mut OsEntropy,
        )?;
        tracing::info!(tenant = %h.tenant, webhook = %h.id(), format = h.format.as_str(), events = ?h.events, url = %crate::records::url_origin(&h.url), changed, "configured webhook");
    }
    for t in store.tenants()? {
        for w in &t.webhooks {
            let declared = hooks.iter().any(|h| h.tenant == t.id && h.id() == w.id);
            if w.id.starts_with(CONFIG_WEBHOOK_PREFIX) && !declared {
                store.remove_webhook(&t.id, &w.id, now)?;
                tracing::info!(tenant = %t.id, webhook = %w.id, "configured webhook removed (no longer declared)");
            }
        }
    }
    Ok(())
}

/// Everything a daemon reads from the environment.
#[derive(Debug)]
pub struct DaemonEnv {
    /// Listen address.
    pub bind: String,
    /// Store directory.
    pub db: PathBuf,
    /// The pepper bytes (wrap in [`crate::Pepper`]).
    pub pepper: [u8; 32],
    /// The service identity's secret.
    pub identity_secret: [u8; 32],
    /// Server configuration.
    pub cfg: ServerConfig,
    /// Tenants to ensure at boot.
    pub bootstrap: Vec<BootstrapTenant>,
    /// Webhook endpoints to keep in sync at boot (after the tenants).
    pub bootstrap_webhooks: Vec<BootstrapWebhook>,
}

impl DaemonEnv {
    /// Read and validate. Every error is a sentence an operator can act on.
    pub fn from_env() -> Result<Self, String> {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let db = PathBuf::from(get("SIGNUP_DB").unwrap_or_else(|| "./signup-data".into()));
        std::fs::create_dir_all(&db).map_err(|e| format!("{}: {e}", db.display()))?;
        let pepper = key32("SIGNUP_PEPPER")?.ok_or(
            "SIGNUP_PEPPER is not set — it indexes every address; generating one would orphan every existing user. Set 32 bytes (hex or base64url).",
        )?;
        let identity_secret = match key32("SIGNUP_IDENTITY_KEY")? {
            Some(k) => k,
            None => load_or_create_key(&db.join("identity.key"))?,
        };
        let import_token = match get("SIGNUP_IMPORT_TOKEN") {
            Some(t) if t.len() >= 32 => Some(t),
            Some(_) => return Err("SIGNUP_IMPORT_TOKEN must be at least 32 characters".into()),
            None => None,
        };
        let issuer = get("SIGNUP_ISSUER").unwrap_or_else(|| "mid-sovereign-signup".into());
        let operators = get("SIGNUP_OPERATORS")
            .map(|v| {
                v.split(',')
                    .map(|d| d.trim().to_string())
                    .filter(|d| !d.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            bind: get("SIGNUP_BIND").unwrap_or_else(|| "0.0.0.0:8080".into()),
            db,
            pepper,
            identity_secret,
            cfg: ServerConfig {
                operators,
                import_token,
                client_ip_header: get("SIGNUP_CLIENT_IP_HEADER").map(|h| h.to_lowercase()),
                assertion_audience: issuer.clone(),
                assertion_issuer: issuer,
                ..ServerConfig::default()
            },
            bootstrap: parse_bootstrap(&get("SIGNUP_BOOTSTRAP_TENANTS").unwrap_or_default())?,
            bootstrap_webhooks: parse_bootstrap_webhooks(
                &get("SIGNUP_BOOTSTRAP_WEBHOOKS").unwrap_or_default(),
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parse_both_encodings() {
        let hex = "00".repeat(31) + "ff";
        assert_eq!(parse_key32(&hex).unwrap()[31], 0xff);
        let b64 = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert_eq!(parse_key32(&b64).unwrap(), [7u8; 32]);
        assert!(parse_key32("short").is_err());
        assert!(parse_key32(&URL_SAFE_NO_PAD.encode([7u8; 31])).is_err());
    }

    #[test]
    fn bootstrap_specs() {
        let v =
            parse_bootstrap("mata|MATA|https://app.mata.network https://mata.network; demo|Demo|")
                .unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].origins.len(), 2);
        assert!(v[1].origins.is_empty());
        assert!(parse_bootstrap("Bad Id|x|").is_err());
        assert!(parse_bootstrap("noname").is_err());
        assert!(parse_bootstrap("").unwrap().is_empty());
    }
}
