//! FR-8 — serialisable, versioned wire formats.
//!
//! Every object is a plain serde struct whose cryptographic fields are fixed-size
//! byte arrays. In human-readable formats (JSON) they are lowercase hex; in binary
//! formats (CBOR) they are raw byte strings. Decoding into group elements and
//! scalars is *strict* and happens only at verification time:
//!
//! * points must be canonical Ristretto encodings ([`decode_point`]);
//! * scalars must be canonical, i.e. `< q` ([`decode_scalar`]) — accepting
//!   non-canonical scalars would make proofs malleable.

use crate::error::VerifyError;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Strictly decode a canonical Ristretto255 point.
pub fn decode_point(b: &[u8; 32]) -> Result<RistrettoPoint, VerifyError> {
    CompressedRistretto(*b)
        .decompress()
        .ok_or_else(|| VerifyError::Malformed("non-canonical or invalid Ristretto point".into()))
}

/// Strictly decode a canonical scalar (< q).
pub fn decode_scalar(b: &[u8; 32]) -> Result<Scalar, VerifyError> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*b))
        .ok_or_else(|| VerifyError::Malformed("non-canonical scalar".into()))
}

/// Encode a value as CBOR.
pub fn to_cbor<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("serialising to a Vec cannot fail");
    out
}

/// Decode a value from CBOR. Never panics on arbitrary input.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
}

/// Encode as compact JSON.
pub fn to_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serialising to JSON cannot fail")
}

/// Encode as pretty JSON.
pub fn to_json_pretty<T: Serialize>(v: &T) -> String {
    serde_json::to_string_pretty(v).expect("serialising to JSON cannot fail")
}

/// Decode from JSON. Never panics on arbitrary input.
pub fn from_json<T: DeserializeOwned>(s: &str) -> Result<T, String> {
    serde_json::from_str(s).map_err(|e| e.to_string())
}

/// serde adapter for `[u8; N]`: hex in human-readable formats, bytes otherwise.
pub mod hexbytes {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    /// Serialize.
    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(v))
        } else {
            s.serialize_bytes(v)
        }
    }

    struct V<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for V<N> {
        type Value = [u8; N];
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{N} bytes as hex string or byte string")
        }
        fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
            if s.len() != 2 * N {
                return Err(E::custom(format!(
                    "expected {} hex chars, got {}",
                    2 * N,
                    s.len()
                )));
            }
            let mut out = [0u8; N];
            hex::decode_to_slice(s, &mut out).map_err(E::custom)?;
            Ok(out)
        }
        fn visit_bytes<E: de::Error>(self, b: &[u8]) -> Result<Self::Value, E> {
            b.try_into()
                .map_err(|_| E::custom(format!("expected {N} bytes, got {}", b.len())))
        }
        fn visit_byte_buf<E: de::Error>(self, b: Vec<u8>) -> Result<Self::Value, E> {
            self.visit_bytes(&b)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; N];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::custom("too many bytes"));
            }
            Ok(out)
        }
    }

    /// Deserialize.
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        if d.is_human_readable() {
            d.deserialize_str(V::<N>)
        } else {
            d.deserialize_bytes(V::<N>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncanonical_scalar() {
        assert!(decode_scalar(&[0xff; 32]).is_err());
        assert!(decode_scalar(&[0u8; 32]).is_ok());
    }

    #[test]
    fn rejects_bad_point() {
        assert!(decode_point(&[0xff; 32]).is_err());
        assert!(decode_point(&[0u8; 32]).is_ok()); // identity encodes as zeros
    }
}
