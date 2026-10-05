# mid-sovereign-signup

Headless **email + one-time-code** sign-up and sign-in for Rust services —
the open sibling of [`mid-signin`](https://crates.io/crates/mid-signin) for
users who **do not (yet) hold a MATA DID**.

`mid-signin` proves a user through a wallet-held `did:mata` key. This crate
proves a user through an inbox: send a six-digit code, check it, hand back a
user record and — if you want one — a signed attestation any backend verifies
offline. A service can accept either proof, or both: a user who signs up by
email can later link a DID, and the record carries both. Nothing here
requires a DID, a wallet, or a MATA server.

It is a **pure core**: no clock, no I/O, no store, no mail provider, no HTTP.
Those are seams you fill (or feature-gated layers that follow, the way
`mid-signin` adds `redb-store` and `routes`). Anyone can run it on their own
hardware; a hosted operator is just one adopter.

## The flow

```text
client ──start(email)──▶ core ──code──▶ Mailer ──▶ inbox
client ──verify(email, code)──▶ core ──▶ User (+ Attestation)
```

```rust
use mid_sovereign_signup::{
    start, verify, OsEntropy, Pepper, Policy, StartRequest, TenantId, VerifyRequest,
};

// Once per deployment: a 32-byte pepper, kept OUT of the store it protects.
let pepper = Pepper::from_base64url(&std::env::var("SIGNUP_PEPPER")?)?;
let tenant = TenantId::parse("acme")?;
let mut entropy = OsEntropy;
let now = unix_now(); // your clock — the core never reads one

// 1. start: mint a code, get back a challenge to store and a code to mail.
let live = store.load_live_challenge(&tenant, "alice@example.com")?; // Option<Challenge>
let out = start(
    &StartRequest { tenant: &tenant, email: "alice@example.com", create_user: true, now },
    live,
    &Policy::DEFAULT,
    &pepper,
    &mut entropy,
)?;
store.write_challenge(&out.challenge, out.superseded.as_ref(), &out.audit)?; // one transaction
mailer.send_code(out.message("Acme")).await?;                                // after the commit

// 2. verify: check the code, create or sign in the user.
let challenge = store.load_live_challenge(&tenant, "alice@example.com")?;
let existing = store.load_user_by_email(&tenant, "alice@example.com")?;
let result = verify(
    &VerifyRequest { tenant: &tenant, email: "alice@example.com", code: "123 456", now },
    challenge,
    existing,
    &pepper,
    &mut entropy,
);
store.write_verify(&result)?;              // ALWAYS — attempts are counted on failure too
let verified = result.outcome?;            // Verified { user, user_created, first_verification }
```

The store contract is small and spelled out in [`records`]: load two rows by
key, call the function, write back everything it returns in one transaction.
The key namespace (`user/{tenant}/{id}`, `user-email/{tenant}/{email_idx}`,
`challenge-live/{tenant}/{email_idx}`, …) is stable and documented, so an
operator can read a dump.

## The attestation

After a verify, sign the user with your service's DID and hand the token to
whoever needs proof — a backend, a proxy, a partner. They verify it offline:

```rust
use mid_sovereign_signup::attest::{
    sign_attestation_single_device, verify_attestation, AttestationClaims, AttestationPolicy,
};

// Service side: a single-key service identity (did + its multibase key).
let claims = AttestationClaims::for_user(&verified.user)?;
let token = sign_attestation_single_device(&did, &multibase, "signupd-1", &claims, &signer, now, 300)?;

// Anywhere else, with no network: pin the issuer, check the tenant.
let ok = verify_attestation(&token, &AttestationPolicy {
    expected_issuer: Some(&did),
    expected_tenant: Some(&tenant),
    now_unix_secs: now,
    max_iat_skew_secs: 60,
})?;
assert_eq!(ok.claims.user_id, verified.user.id);
```

The attestation is a plain [`mata-sign`](https://crates.io/crates/mata-sign)
statement with a fixed `context`; the claims ride inside it and are bound by
its content hash. It expires in minutes by design — it is proof of a
verification, not a session.

## Security properties

| Property | How |
|---|---|
| Codes are never stored | The challenge holds `HMAC-SHA256(pepper, tenant ‖ email_idx ‖ challenge_id ‖ code)`. The code exists only in transit to the mailer. |
| Brute force is bounded | 10⁶ codes, `max_attempts` guesses (default 5) within `code_ttl_secs` (default 10 min), the challenge consumed on success or exhaustion: 5 × 10⁻⁶ per challenge. Comparison is constant-time. |
| A resend kills the old code | The commitment binds the challenge id; a new challenge cannot verify the old code, structurally. |
| Addresses are indexed, not exposed | Lookups use `EmailIndex = HMAC-SHA256(pepper, tenant ‖ email)`; keys and audit rows carry the index, never the address. `Debug` on an address masks it; `Debug` on a code redacts it. |
| Start reveals nothing | Starting a challenge looks the same whether or not the address is enrolled. Enrollment is decided at verify, by whoever controls the inbox. |
| The store cannot hand over the wrong row unnoticed | Both the challenge and the user are checked against the tenant and address before anything is counted. |
| Deterministic and pure | `now` is a parameter, randomness is the `Entropy` seam, no I/O. A test vector (`tests/vector_v1.json`) pins every wire-relevant derivation. |

## What ships, what follows

| Layer | Status |
|---|---|
| Pure core (default build): normalization, codes, policy, records, flow, attestation, webhook signatures, seams | **shipped** |
| Feature `store`: `SignupStore` on SpaceDB — one redb file, every row sealed (AES-256-GCM), atomic start/verify, uniqueness indexes, send limits, sessions, a transactional webhook outbox, dump/restore, integrity check | **shipped** |
| Feature `server`: the HTTP API, sessions, attestations, signed-assertion backend routes, webhooks, the import door, `/healthz`, and the `signupd` binary | **shipped** |
| Feature `mail-ses`: code delivery through AWS SES | **shipped** |
| Feature `cli`: `signupctl` — migrate a user base in (native JSONL or a Supabase `auth.users` export), keeping ids, and prove every id landed | **shipped** |
| Feature `client`: the headless SDK (wasm32 + native) — typed calls, typed errors, a transport seam (`HttpTransport` / `MockTransport`), a session-store seam with an AES-256-GCM sealed file store | **shipped** |

## Run it

```sh
cargo install mid-sovereign-signup --features server,mail-ses --bin signupd
SIGNUP_PEPPER=$(openssl rand -hex 32) SIGNUP_BOOTSTRAP_TENANTS="acme|Acme|https://app.acme.com" signupd
# logs: tenant ready tenant=acme public_id=pub_…
```

| Caller | Proves itself with | Routes |
|---|---|---|
| A page on the tenant's site | the public id in the path + the tenant's origin allow-list + send limits | `POST /v1/p/:public_id/signup/{start,resend,verify}`, `POST /v1/p/:public_id/username/check` |
| A signed-in user | `Authorization: Bearer sess_…` (opaque, rotating, revocable) | `GET`/`PATCH /v1/p/:public_id/users/me`, `POST …/session/{refresh,logout,logout-all}`, `GET …/attestation` |
| The tenant's backend / the operator | `Authorization: Signup-Assertion <base64url JSON>` over a single-use nonce from `POST /v1/nonce`, whose purpose is the operation | `/v1/admin/tenants/…` (see `server::OPS`) |

There are no API keys. A backend is a `did:mata` — one P-256 key is enough
(`server::KeyDidResolver`) — listed as a tenant member with the grants it
needs. Webhook deliveries carry `x-signup-signature: t=…,v1=…`; verify them
with `mid_sovereign_signup::webhook::verify`.

## The client

```rust,ignore
use mid_sovereign_signup::client::{SealedFileSessionStore, SessionStore, SignupClient};

let c = SignupClient::new("https://signup.example.com/v1/p/pub_…");
c.start("alice@example.com", true).await?;                 // your UI asks for the code
let v = c.verify("alice@example.com", "123456").await?;    // user + session + attestation
let store = SealedFileSessionStore::new("session.sealed", key); // a 32-byte key you hold
store.save(&v.session)?;
let me = c.me(&v.session.token).await?;
```

Headless: there is no UI in this crate. Errors carry the server's stable
code (`wrong_code` with `attempts_left`, `rate_limited` with
`retry_after_secs`, `needs_new_code`, …) so an app can show the right
screen. `key_from_passphrase` derives a session key with Argon2id at the
wallet's parameters for apps that have a passphrase.

## Migrating in (from Supabase Auth, or anything)

```sh
signupctl supabase-sql                       # the export query; run it with psql
export SIGNUP_IMPORT_TOKEN=…                 # the server's import door is open while this is set
signupctl import --url https://signup.example.com --tenant acme   --file auth_users.jsonl --from supabase --report report.json --ids-out sent.txt
signupctl verify --url https://signup.example.com --tenant acme --expect-ids sent.txt
```

Ids are kept, so a migrated user is the same user. Re-runs are safe
(`already_present`). Unverified rows are skipped unless asked for; a taken
or malformed username is dropped and reported, not a reason to lose the
user. The report holds ids and counts, never an address.

## License

MIT OR Apache-2.0.
