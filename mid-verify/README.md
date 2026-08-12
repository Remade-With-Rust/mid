# mid-verify

**RP-side mID verifier. Start here if you are adding "Sign in with MATA" to
your backend.**

Takes a JWS compact-form mID token plus your local policy (`VerifyConfig`) and
runs the four-step verification **entirely locally** — pure Rust, no I/O, no
clock reads, and **zero runtime calls to MATA infrastructure** under any code
path. The token carries everything needed to verify it: the DID *is* the
genesis public key.

Implements [ADR 0005 Decision 1](../../docs/adr/0005-mid-protocol-v1-phase-0-spec-lockin.md).
Licensed MIT OR Apache-2.0.

> **Building a website sign-in?** You probably want
> [`mid-signin`](../mid-signin) — the drop-in kit that wraps this
> verifier with the stateful RP duties (single-use nonces, genesis anchoring,
> rollback detection) plus ready-made axum routes. This crate is the
> cryptographic core it composes.

```toml
[dependencies]
mid-verify = "0.1"
```

## Verifying a sign-in

```rust,ignore
use mid_verify::{verify_mid_response, VerifyConfig};

let config = VerifyConfig {
    expected_audience: "https://acme.com".into(), // your rpOrigin, exactly
    expected_nonce: nonce_you_issued,             // echoed in the token
    max_iat_skew_secs: 120,
    now_unix_secs: now(),                         // you supply the clock
};

let verified = verify_mid_response(&jwt, &config)?;
// verified.did                  — the user's stable identifier
// verified.claims               — disclosed claims (all self-attested in v1)
// verified.current_version      — head roster version (persist for rollback checks)
// verified.genesis_roster_hash  — persist on first sight; must never change
```

## The four checks

1. **Genesis self-signature** — decode the genesis public key *from the DID
   string itself* and verify the embedded genesis roster's self-signature
   against it. No registry, no resolver.
2. **Roster chain** — every roster mutation is signed by a key present in the
   *prior* roster; versions strictly increase. Proves the current roster
   legitimately descends from genesis.
3. **Head-roster membership** — the device key that signed this token is in
   the current roster (revoked devices fail here).
4. **JWS signature** — standard ES256 verification of the token against that
   device key, plus audience, nonce, `iat` skew, and expiry checks.

## What stays your job (or `mid-signin`'s)

This function is stateless on purpose. Cross-sign-in defenses need *your*
storage:

- **Single-use nonces** — equality is checked here; issuance + one-time
  consumption is yours.
- **Anchor on first sight** — record `(did, genesis_roster_hash)`; reject any
  future sign-in whose genesis differs.
- **Rollback detection** — record the highest `current_version` seen per DID
  and call `VerifiedMid::check_rollback(last_seen)` (or compare yourself);
  a lower version is a stolen device presenting a pre-revocation roster.

## Errors

`VerifyError` is a 16-variant enum with structured fields
(`AudienceMismatch`, `NonceMismatch`, `Expired`, `ChainVersionNotMonotonic`,
`RollbackDetected { current, last_seen }`, …) — match on it; don't parse
messages.

## Who calls it

- Any relying party backend, directly or through `mid-signin`.
- `mata-sign` — reuses the same four checks for document/post signatures.
- The `@matanetwork/sovereign-id-verify` npm package wraps this crate for
  Node/Deno/Bun backends.
