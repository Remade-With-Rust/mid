# mid-signin

The drop-in Relying-Party kit for **Sign in with MATA** (mID). Ten lines to
production sign-in — replay-safe, rollback-checked, zero schema work, and
**zero runtime calls to MATA infrastructure** (there is no MATA server in the
protocol to call).

[`mid-verify`](https://crates.io/crates/mid-verify) does the cryptography and
deliberately stops there — it is a pure, stateless function. A production RP
still owes three duties the verifier cannot perform, and every integrator ends
up rebuilding them by hand. This crate is those duties, done once:

| Duty | Why it exists | Who enforces it |
|---|---|---|
| **Single-use nonces** | The verifier only checks nonce *equality*; without issuance + one-time consumption, a captured token replays forever | `NonceStore` (TTL + flood ceiling built in) |
| **Genesis anchoring** | A known DID must present the same genesis-roster hash every time; a different one is identity spoofing | `AnchorStore` |
| **Rollback detection** | The head-roster version must never decrease; a decrease is a stolen device presenting a pre-revocation roster | `AnchorStore` |
| **Session production** | Turning "verified token" into "this request is Alice" | **Your app** — the kit returns an `RpSession` and gets out of the way |

`Authenticator` composes the flow: **verify → consume nonce → check anchor**.
A failed verification never burns the nonce, so a legitimate retry survives.

## Quickstart (axum)

```toml
[dependencies]
mid-signin = { version = "0.1", features = ["routes", "redb-store"] }
```

```rust,ignore
use std::sync::Arc;
use mid_signin::{routes, Authenticator, MidRp, MidRpConfig, RedbStore};

// One file on disk. No schema, no migration. Nonces + anchors survive restarts.
let store = Arc::new(RedbStore::open("mata-auth.redb")?);
let auth = Authenticator::new(store.clone(), store);
let rp = Arc::new(MidRp::new(MidRpConfig::new("https://acme.com"), auth));

let app = axum::Router::new()
    .merge(routes::router(rp));
// POST /auth/mid/nonce   → {"nonce": "…"}
// POST /auth/mid/verify  → 200 {"did", "claims", "roster_version"} | 401 {"error"}
```

Frontend (any page, [`@matanetwork/sovereign-id`](https://www.npmjs.com/package/@matanetwork/sovereign-id)):

```js
import { signIn } from "@matanetwork/sovereign-id";

const { nonce } = await fetch("/auth/mid/nonce", { method: "POST" }).then(r => r.json());
const result = await signIn({
  rpOrigin: "https://acme.com",   // must equal MidRpConfig's rp_origin exactly
  nonce,
  claims: { required: ["did"], optional: ["email", "name"] },
});
const session = await fetch("/auth/mid/verify", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ jwt: result.jwt }),
}).then(r => r.json());
// session.did is the user's stable identifier.
```

That's the whole integration. No registration, no client_id, no shared secret,
no JWKS refresh, no MATA account.

## Minting your own session cookie

Pass a responder to `routes::router_with` — it runs after successful
verification and can take over the response:

```rust,ignore
let hook: routes::OnVerified = Arc::new(|session| {
    Some((
        axum::http::StatusCode::OK,
        [(axum::http::header::SET_COOKIE, my_session_cookie(&session.did))],
        "ok",
    ).into_response())
});
let app = routes::router_with(rp, hook);
```

Apps with richer needs (async session stores, custom framing) skip the router
and call the flow directly — it is one method:

```rust,ignore
let session = rp.verify_jwt(&jwt)?;   // peek nonce → verify → consume → anchor check
```

## Bolting into your own database

The stores are two small traits — implement them over your users table instead
of using redb:

```rust,ignore
impl NonceStore for MyDb {
    fn issue(&self, now: u64) -> Result<String, RpError> { /* INSERT */ }
    fn consume(&self, nonce: &str, now: u64) -> Result<bool, RpError> { /* DELETE … RETURNING */ }
}
impl AnchorStore for MyDb {
    fn check_and_update(&self, did: &str, genesis: &[u8; 32], version: u64) -> Result<(), RpError> {
        // Anchor row per DID: genesis hash immutable, version monotonic.
    }
}
```

Suggested columns on your `users` table: `did TEXT PRIMARY KEY`,
`genesis_roster_hash BYTEA`, `last_seen_roster_version BIGINT`. Guard updates
with `WHERE genesis_roster_hash = $presented` — a mismatch is an attack, not a
conflict.

## What this crate never does

- **Re-implement verification.** Every cryptographic check is
  `mid_verify::verify_mid_response` — one canonical verifier.
- **Call MATA.** No resolver, no JWKS, no revocation list, no telemetry.
  Compile-time dependency only, per the mID protocol's zero-backdoor design.
- **Invent a session format.** Cookies/tokens stay your choice.

## Features

| Feature | Adds | Default |
|---|---|---|
| _(none)_ | Traits, in-memory stores, `Authenticator` — pure core, no clock reads, no I/O | ✅ |
| `redb-store` | `RedbStore`: single-file embedded persistence (pure-Rust redb) | off |
| `routes` | `MidRp` + ready-made axum endpoints (the only impure module) | off |

## License

MIT OR Apache-2.0.
