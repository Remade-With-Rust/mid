# kms-client

**Client-side helpers for MATA KMS sovereign-auth.**

Turns an unsigned `NonceEnvelope` into a `SignedAssertion` that
[`kms-verifier`](../kms-verifier/) will accept, using the device's M5 signing
key. This is the wallet side of the sovereign-auth handshake: the server never
holds a secret that can impersonate the user — the device signs, the verifier
checks the user's published roster.

Builds for **native and `wasm32`**. Licensed MIT OR Apache-2.0.

```toml
[dependencies]
kms-client = "0.1"
```

## Two surfaces

### Low-level — `sign_assertion`

The pure transformation. No HTTP, no async. Use it when you already have a
nonce in hand.

```rust
use kms_client::{sign_assertion, InMemoryDeviceSigner, NonceEnvelope};

let envelope = NonceEnvelope {
    envelope_version: NonceEnvelope::CURRENT_VERSION,
    envelope_type: NonceEnvelope::TYPE.into(),
    nonce: vec![0xAB; 32],
    did: "did:mata:123456789ABCDEFGHJKLMNPQRSTUVWXY".into(),
    audience: "kms-banking".into(),
    purpose: "get_accounts".into(),
    issued_at: 1_716_583_200,
    expires_at: 1_716_583_230,
    issuer: "kms-banking-proxy".into(),
};

let signer = InMemoryDeviceSigner::generate("dev-laptop");
let assertion = sign_assertion(&signer, envelope).unwrap();
```

The envelope is **shape-validated before signing** — a malformed envelope from a
hostile server (wrong version, TTL over the cap, missing fields) cannot trick the
device into producing a signature over garbage.

`sign_roster_update` is the same discipline for roster mutations: it builds a
`RosterUpdate` at `prior_version + 1`, validates the shape, and signs the
canonical bytes. On a `StaleRosterVersion` rejection the caller re-resolves and
retries.

### High-level — `KmsClient`

The full round-trip against a remote verifier (a `kms-banking-proxy`, or a
future OIDC adapter).

```rust
use kms_client::{ClientError, DeviceSigner, KmsClient, SignedAssertion};

async fn get_accounts(
    signer: &dyn DeviceSigner,
    did: &str,
) -> Result<SignedAssertion, ClientError> {
    let client = KmsClient::new("https://banking.mata.network");
    client.request_and_sign(signer, did, "get_accounts").await
}
```

`request_nonce` POSTs `{ did, purpose }` to `<base_url>/v1/nonce` and validates
the returned envelope before it is ever handed to the signer. Build one client
per service — a wallet talking to banking and OIDC holds two, with different
base URLs. `with_http_client` takes a caller-configured `reqwest::Client` when
you need custom timeouts or middleware.

## The `DeviceSigner` trait

```rust
pub trait DeviceSigner {
    fn device_id(&self) -> &str;              // must match an entry in the user's roster
    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64];   // canonical low-s r‖s
}
```

Implementations **must** produce **low-s** ECDSA P-256 signatures. The verifier
rejects high-s as `VerifyError::SignatureInvalid` — that is the ECDSA
malleability defense, and it is not optional.

`InMemoryDeviceSigner` ships here as a test helper and bootstrap implementation
(software key in the app's encrypted vault). Production hardware-backed signers —
Secure Enclave, StrongBox, WebAuthn — live in `packages/ui`, where the
platform dependencies belong; swapping one in changes no call site, because the
trait is the contract.

`pubkey_sec1()` gives the 65-byte SEC1-uncompressed form (`0x04 ‖ x ‖ y`) to
publish when adding the device to a roster.

## Error taxonomy

`ClientError` differentiates the **local** failures a wallet can act on —
`Network`, `BadResponseBody`, `InvalidEnvelope` — while server rejections stay
opaque as `HttpStatus`. That is deliberate: the verifier returns one blanket
"invalid assertion" rather than telling an attacker *which* check failed.

## Wire format

Canonical bytes, signing rules, and the error taxonomy are specified in
[`docs/business cases/kms/envelope_spec.md`](../../docs/business%20cases/kms/envelope_spec.md).
Changing them is a wire break that must land in `kms-types` and `kms-verifier`
at the same time.

## Testing

```bash
cargo test -p kms-client --target aarch64-apple-darwin   # or your host triple
```

`tests/end_to_end.rs` is the real proof: `kms-client` signs, `kms-verifier`
verifies, in one process. It pins the four things both crates must agree on —
canonical envelope form, prehash signing, low-s canonicalization, and the SEC1
pubkey shape. Unit tests additionally cover pre-sign validation and RFC 6979
determinism (same key + same input → same signature).

HTTP-layer behavior is covered by the `kms-banking-proxy` integration tests, not
here.
