# mid-issuer

**Wallet-side mID JWT minter.**

Given a snapshot of the wallet's identity state, a relying party's sign-in
request, and the device's M5 signing key, this crate produces a JWS compact-form
mID token. Self-issued: there is no identity provider in the loop, and no server
that can mint a token on the user's behalf.

Implements [ADR 0005 Decision 1](../../docs/adr/0005-mid-protocol-v1-phase-0-spec-lockin.md).
Licensed MIT OR Apache-2.0.

```toml
[dependencies]
mid-issuer = "0.1"
```

## Issuing a token

```rust,ignore
use mid_issuer::{build_mid_jwt, snapshot::assemble_identity_snapshot};

// The wallet binds its persisted state + the consent decision into a snapshot.
let snapshot = assemble_identity_snapshot(
    did,
    genesis_roster,          // self-signed once, at signup
    roster_chain,            // every device add/remove since
    current_verification_method,
    approved_claims,         // ONLY what the user consented to disclose
)?;

let jwt = build_mid_jwt(&rp_request, &snapshot, &signer, iat)?;
```

`iat` is passed in — the wallet reads the wall clock once — so the function is
pure and byte-for-byte reproducible in tests. `exp` is `iat + 3600`: mID ships
short-lived tokens and lets the RP issue its own session cookie after the first
verify.

Before signing anything, `build_mid_jwt` refuses when:

- the current verification method's `controller` ≠ the snapshot DID
  (`DidVmMismatch`),
- the signing device is not in the **head** roster — a revoked or stale device
  (`SignerNotInHeadRoster`),
- a `required` claim from the RP is absent from `approved_claims`
  (`RequiredClaimMissing`).

## Who calls it

Both v1 issuance surfaces share this crate:

- **The MATA browser extension** — from the background worker, after the user
  approves the consent screen.
- **The MATA native app** (desktop + mobile) — from the URL-scheme handler,
  after the biometric gate unlocks.

## What this crate is *not*

- **Not the consent UI.** The caller decides whether to issue; this builds the
  token once the decision is made.
- **Not the surface dispatcher.** The `@mata/mid` JS SDK probes for the
  extension / native app; this runs after that probe succeeds.
- **Not the wallet's identity store.** The snapshot is consumed read-only.
- **Not a verifier.** RPs use [`mid-verify`](../mid-verify/).

The caller is responsible for filtering `approved_claims` to exactly what the
user consented to (no over-disclosure) and for confirming `rp_origin` matches the
real calling page — `sender.tab.url` in the extension, the verified Universal
Link / App Link payload in the native app.

## The embedded roster chain

An mID token carries its own trust path, so a verifier needs no directory lookup:

| Field | What it is |
|---|---|
| `embedded_genesis_roster` | signed **once at signup** by the key encoded in the DID itself |
| `embedded_roster_chain` | one signed entry per device add/remove, each signed by a device in the **prior** roster |
| `embedded_verification_method` | the device signing *this* token — must be in the head roster |

`bootstrap::sign_genesis_roster` mints the first; `bootstrap::sign_roster_chain_entry`
appends each mutation. Both are pure: no I/O, no clock reads, no randomness in
envelope assembly.

```rust
use kms_client::{DeviceSigner, InMemoryDeviceSigner};
use mid_issuer::bootstrap::sign_genesis_roster;

// Once, at signup: the wallet has just minted its first M5 device keypair.
let signer = InMemoryDeviceSigner::generate("dev-laptop");
let did = "did:mata:abc123".to_string();

let genesis = sign_genesis_roster(
    did.clone(),
    signer.device_id(),
    "z6MkFake".into(),   // the device pubkey, multibase-encoded
    1_700_000_000,
    &signer,
);

assert_eq!(genesis.version, 1);
assert_eq!(genesis.verification_methods[0].id, format!("{did}#dev-laptop"));
```

`snapshot::assemble_identity_snapshot` is a defensive smart constructor over the
whole thing — genesis is version 1, DIDs match everywhere, the first chain entry
is version 2, versions strictly increase, the current VM is in the head roster.
It catches wallet-side bugs (corrupted storage, stale device, missing link)
*before* a signature exists. Cryptographic verification is deliberately **not**
done here — that is the verifier's job.

## Canonical bytes

`canonical` defines the domain-separated binary form both this crate and
`mid-verify` compute. Length-prefixed, big-endian, one representation per input
— unlike JSON, which is sensitive to key order, whitespace, and number encoding.
The leading domain literals (`mid-genesis-roster-v1`, `mid-roster-chain-v1`)
mean a signature over one envelope kind can never be replayed as another.

**Both crates must agree byte-for-byte. Any change here is a wire break.**

## Cryptography

ES256 (ECDSA P-256 + SHA-256), low-s canonical, via the `DeviceSigner` trait
re-exported from [`kms-client`](../kms-client/) — so the key can live in a Secure
Enclave, StrongBox, or a software vault without this crate knowing which.

JWS compact form is implemented directly (`jws.rs`, ~50 LOC) rather than pulling
in `jsonwebtoken`: the ECDSA primitive is already behind `DeviceSigner`, and
`jsonwebtoken`'s internal key-handle abstraction cannot represent a hardware
signer uniformly. The header bytes `{"alg":"ES256","typ":"JWT"}` are a fixed
literal — committed to as prehash input, so no serializer can reorder them.

## Testing

```bash
cargo test -p mid-issuer --target aarch64-apple-darwin   # or your host triple
```

Tests are inline per module and lean on determinism: the same inputs produce a
byte-identical JWT, so round-trips can assert on exact tokens. Signers are
constructed from fixed keys rather than generated, for reproducible signatures.
