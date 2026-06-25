# Security Policy

mID is an **identity and authentication** library — its verification path is
load-bearing for anyone who trusts a `did:mata` sign-in. A bug in
`mid-verify` could mean impersonation or account takeover, so we take reports
seriously and want to hear about them **privately, first**.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through **GitHub's private vulnerability reporting** —
the *Security → Report a vulnerability* button on this repository. If that is
unavailable, email the maintainers at **security@mata.network**.

Please include:
- a description of the issue and the impact you believe it has,
- the crate(s) and version(s) affected,
- steps to reproduce (a failing test or proof-of-concept is ideal). A forged
  token that `verify_mid_response` wrongly accepts is the highest-severity class.

We aim to acknowledge within **3 business days** and to keep you updated as we
investigate. Once a fix is ready we'll coordinate disclosure with you and credit
you, unless you'd prefer to remain anonymous.

## Supported versions

mID is pre-1.0; security fixes land on the latest `0.x` release. Pin a version
and watch the repository for releases.

## Scope

**In scope** — the crates in this repository:
- token verification and the four-step check (`mid-verify`),
- token issuance and the JWS/canonicalization path (`mid-issuer`),
- statement signing/verification (`mata-sign`),
- the KMS envelope + verification engine (`kms-types`, `kms-verifier`, `kms-client`),
- identity keypairs and the capability model (`mata-identity`, `mata-cap`).

**Out of scope** — the proprietary MATA services and the wallet apps that embed
these crates. Report those through MATA's product security channel, not here.
