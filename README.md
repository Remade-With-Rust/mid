### In The Wild with 3,499 Active Installs

FREE RAG Converter Online -- <a href="https://RAGconverter.com">RAGconverter.com</a>

# MATA mID

**Permissionless, self-issued identity for Rust.** A user's identity is a keypair they
hold on their own device — not a row in your database, not an account on someone's portal.
They sign in by handing your service a token signed by their own key; you verify it
**entirely locally**, with zero runtime calls to MATA or anyone else.

These are the **Rust crates**. The browser/Node side is
[`@matanetwork/sovereign-id`](https://github.com/Remade-With-Rust/sovereign-id) — same
protocol, same wire format. Use whichever fits your stack (or both: issue on one, verify
on the other).

mID is **open source** — dual-licensed **MIT OR Apache-2.0**. Embed it, run it, verify
against it: free, forever. The crates depend on nothing proprietary.

## The crates

| Crate | What it's for |
|---|---|
| [`mid-signin`](mid-signin) | **The drop-in RP kit — start here for website sign-in.** Wraps `mid-verify` with the stateful RP duties (single-use nonces, genesis anchoring, rollback detection), an embedded zero-schema store (`redb-store`), and ready-made axum routes (`routes`). Ten lines to production sign-in. |
| [`mid-sovereign-signup`](mid-sovereign-signup) | **Email + one-time-code sign-up/sign-in — for users without a DID.** Headless and pure: HMAC-committed six-digit codes under a server pepper, attempt/TTL/resend policy, tenant-scoped users with optional DID linking, and a `mata-sign` attestation any backend verifies offline. Sits next to `mid-signin`; a service can accept either proof. |
| [`mid-verify`](mid-verify) | **RP-side verifier.** Four-step local verification (genesis self-sig → roster chain → head version → JWS) of an mID sign-in token. Pure function, no I/O. The cryptographic core `mid-signin` composes. |
| [`mid-issuer`](mid-issuer) | **Wallet-side issuer.** Mints the self-issued sign-in JWT from an identity snapshot + the device signing key. |
| [`mata-sign`](mata-sign) | Sign **arbitrary** content as a `did:mata`, verifiable offline by anyone — the primitive under document signing + IAMHUMAN post signing. |
| [`mata-identity`](mata-identity) | User-owned identity keypairs (the `did:mata` root). |
| [`mata-cap`](mata-cap) | Capability / authorization foundation — one `Capability` / `Caller` / `authorize` model so every service gates the same way. |
| [`kms-types`](kms-types) | Shared envelope types (`NonceEnvelope`, `SignedAssertion`, `RosterUpdate`, `DidDocumentV2`). |
| [`kms-verifier`](kms-verifier) | Sovereign-auth verification engine over those envelopes. |
| [`kms-client`](kms-client) | Client-side: signs assertions with the device key, round-trips the verifier's nonce endpoint. `wasm32` + native. |

## Quick start — add "Sign in with MATA" to a website (the drop-in kit)

```toml
[dependencies]
mid-signin = { version = "0.1", features = ["routes", "redb-store"] }
```

```rust,ignore
use std::sync::Arc;
use mid_signin::{routes, Authenticator, MidRp, MidRpConfig, RedbStore};

// One file on disk — no schema, no migration. Nonces + anchors survive restarts.
let store = Arc::new(RedbStore::open("mata-auth.redb")?);
let rp = Arc::new(MidRp::new(
    MidRpConfig::new("https://acme.com"),
    Authenticator::new(store.clone(), store),
));
let app = axum::Router::new().merge(routes::router(rp));
// POST /auth/mid/nonce  → {"nonce"}          (page passes it to signIn())
// POST /auth/mid/verify → {"did", "claims"}  (page POSTs the wallet's JWT)
```

Pair it with [`@matanetwork/sovereign-id`](https://github.com/Remade-With-Rust/sovereign-id)
on the page: `signIn({ rpOrigin, nonce, claims })` → POST the JWT back. That is the whole
integration — replay defense, spoofing anchors, and stolen-device rollback detection
included. See the crate README for custom-database trait impls and session-cookie hooks.

## Quick start — verify a sign-in by hand (the cryptographic core)

```toml
[dependencies]
mid-verify = "0.1"
```

```rust
use mid_verify::{verify_mid_response, VerifyConfig};

// `jwt` is the mID token the wallet handed your frontend, POSTed to your backend.
let config = VerifyConfig {
    expected_audience: "https://acme.com".into(),  // your origin; must equal the token's `aud`
    expected_nonce:    session_nonce,              // the single-use nonce you issued this session
    max_iat_skew_secs: 120,                        // forward-clock-skew tolerance
    now_unix_secs:     now,                         // you supply the clock — verify stays pure
};

let verified = verify_mid_response(jwt, &config)?;

// verified.did                 — stable user id (your users-table primary key)
// verified.claims              — the values the user consented to disclose
// verified.current_version     — head roster version, for rollback detection
// verified.genesis_roster_hash — anchor; the same DID must always present the same hash

// Defeat stolen-device replay: reject a roster older than the last one you saw.
verified.check_rollback(last_seen_version)?;
```

No `client_id`, no redirect-URI allowlist, no `/token` back-channel, no JWKS endpoint, no
DID-resolver HTTP call, no MAU metering. The token carries its own resolution data and the
DID *is* its public key.

## Sign an arbitrary statement (offline-verifiable)

```rust
use mata_sign::{verify_statement, VerifyOptions};

let verified = verify_statement(token, &VerifyOptions::default())?;
// verified.signer (a did:mata) + the bound content — checked with no network at all.
```

## Building & testing

These crates are native + `wasm32`-capable. Standard:

```bash
cargo build
cargo test
```

## Open-core boundary

No `mid-*`, `kms-*`, `mata-*` crate here depends on any proprietary MATA crate — the
dependency arrow only ever points **MATA → mID**, never the reverse. That one-directional
boundary is why this set extracts into its own repository and publishes to crates.io
pulling in nothing closed. The same identity primitive runs natively in the MATA wallet,
in the browser via [`@matanetwork/sovereign-id`](https://github.com/Remade-With-Rust/sovereign-id),
and as the access layer in [SpaceDB](https://github.com/Remade-With-Rust/spacedb).

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
