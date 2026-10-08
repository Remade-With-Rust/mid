# mid-signer

The device-signing seam of MATA mID, as a leaf crate.

Every place a device signs — `kms-client`'s assertions, `mid-issuer`'s genesis
roster, `mata-sign`'s tokens, a Janus microcontroller's capability manifest —
asks the same two things of the key: a stable device id, and a canonical
(low-s) ECDSA P-256 signature over a 32-byte prehash. That contract is the
`DeviceSigner` trait, and this crate is where it lives, so:

- a hardware-backed implementation (secure element, eFuse key, an ESP32's DS
  peripheral) depends on `mid-signer` and `p256` and nothing else — no HTTP
  client, no runtime;
- every consumer names one trait, and the software signer
  (`InMemoryDeviceSigner`) is the reference each implementation is checked
  against: same key, same prehash, same 64 bytes (RFC 6979).

`no_std` without the default `std` feature; `alloc` (implied by `std`) is what
`InMemoryDeviceSigner` needs, and without it the crate is the trait and the
low-s rule alone — a microcontroller with its key in hardware links nothing
else. `std` adds p256's std error types and the `generate` helper's OS
randomness.

```rust
use mid_signer::{DeviceSigner, InMemoryDeviceSigner};

let signer = InMemoryDeviceSigner::generate("dev-laptop");
let sig: [u8; 64] = signer.sign_prehash(&prehash); // low-s, always
```

`kms-client` re-exports both names, so existing code keeps compiling.
