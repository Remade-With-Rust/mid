//! base64url (no padding) helpers shared by the fixed-size byte newtypes.
//! One alphabet everywhere: the same one `mata-sign` uses for content hashes.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn decode_exact<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("base64url: {e}"))?;
    let got = v.len();
    v.try_into()
        .map_err(|_| format!("expected {N} bytes, got {got}"))
}
