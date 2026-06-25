# Contributing to MATA mID

Thanks for your interest. mID is the open identity layer of the MATA stack —
permissionless, self-issued identity for Rust — dual-licensed **MIT OR Apache-2.0**.

## Build & test

```bash
cargo build
cargo test                  # the crates are native + wasm-aware
cargo test -p mid-verify    # the RP-side verifier
```

`cargo fmt` and `cargo clippy` should be clean before you open a PR.

## The open-core boundary — the one hard rule

mID depends on **nothing proprietary**. The dependency arrow only ever points
**MATA → mID**, never the reverse — that one-directional boundary is what lets
mID live in the open and publish to crates.io without dragging closed code along.
A `mid-*` / `kms-*` / `mata-*` crate must never depend on a closed MATA crate
(`maestro-*`, `disco*`, `iron-bank*`, …); if you need something shared, put it in
one of these crates or invert the dependency.

## Cryptography & the wire format

The token wire format and canonical-bytes serialization are consensus-critical —
the issuer and every verifier (Rust *and* the `@matanetwork/sovereign-id` JS
packages) must agree byte-for-byte.

- Any change to canonicalization, signing, or verification needs a test that
  pins the bytes; a passing round-trip is not enough on its own.
- A forged token that `verify_mid_response` wrongly accepts is the highest-severity
  bug class — add a regression test whenever you touch the verify path.

## Pull requests

- Keep PRs focused, and include tests for any behavior change.
- By submitting a contribution you agree it is dual-licensed MIT OR Apache-2.0,
  matching the project, with no additional terms.

## Security issues

Please **don't** file security vulnerabilities as public issues — see
[SECURITY.md](SECURITY.md) for private reporting.
