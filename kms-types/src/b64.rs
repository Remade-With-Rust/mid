//! `base64url` (no padding) serde adapter.
//!
//! Per [envelope_spec.md](../../../docs/kms/envelope_spec.md), binary fields
//! (nonces, pubkeys, signatures) ride the wire as `base64-url no-pad` strings.
//! On the type side they are plain `Vec<u8>` so [`NonceEnvelope::canonical_bytes`]
//! and friends can operate on raw bytes without re-decoding.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
    ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
}

pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as Deserialize>::deserialize(de)?;
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}
