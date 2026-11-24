//! §7.7 — Fiat–Shamir transcript.
//!
//! A transcript is an append-only, unambiguous encoding of everything the verifier
//! would have seen in the interactive protocol. The challenge is derived by hashing
//! it, so changing *any* bound value — the statement, the issuer key, the nonce, a
//! single T-value — changes the challenge and breaks the proof.
//!
//! Encoding (all lengths little-endian u64):
//!
//! ```text
//! frame(label, data) = len(label) ‖ label ‖ len(data) ‖ data
//! state              = SHA-512 over frame("dom-sep", domain) ‖ frame(…) ‖ …
//! challenge(label)   = Scalar::from_bytes_mod_order_wide(SHA-512(state ‖ frame("challenge", label)))
//! ```
//!
//! Length-prefixing every field makes the encoding injective (no two different
//! sequences of appends produce the same byte string), which rules out the
//! ambiguity class of Fiat–Shamir bugs. SHA-512 provides the 512-bit output needed
//! for an unbiased reduction mod q (NFR: SHA-512 for Fiat–Shamir). The construction
//! is deliberately simple so the Python reference (`python/pramana_ref.py`) can
//! reproduce it byte-for-byte.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Domain-separated, length-prefixed SHA-512 transcript.
#[derive(Clone)]
pub struct Transcript {
    hasher: Sha512,
}

impl Transcript {
    /// Start a transcript for the given protocol domain.
    pub fn new(domain: &[u8]) -> Self {
        let mut t = Transcript {
            hasher: Sha512::new(),
        };
        t.append(b"dom-sep", domain);
        t
    }

    /// Append a labelled byte string.
    pub fn append(&mut self, label: &[u8], data: &[u8]) {
        self.hasher.update((label.len() as u64).to_le_bytes());
        self.hasher.update(label);
        self.hasher.update((data.len() as u64).to_le_bytes());
        self.hasher.update(data);
    }

    /// Append a compressed group element.
    pub fn append_point(&mut self, label: &[u8], p: &CompressedRistretto) {
        self.append(label, p.as_bytes());
    }

    /// Append a little-endian u64.
    pub fn append_u64(&mut self, label: &[u8], v: u64) {
        self.append(label, &v.to_le_bytes());
    }

    /// Append a little-endian i64.
    pub fn append_i64(&mut self, label: &[u8], v: i64) {
        self.append(label, &v.to_le_bytes());
    }

    /// Derive a challenge scalar. The challenge label is itself appended, so any
    /// subsequent challenge is independent of this one.
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Scalar {
        self.append(b"challenge", label);
        let out: [u8; 64] = self.hasher.clone().finalize().into();
        Scalar::from_bytes_mod_order_wide(&out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = Transcript::new(b"d");
        let mut b = Transcript::new(b"d");
        a.append(b"x", b"1");
        b.append(b"x", b"1");
        assert_eq!(a.challenge_scalar(b"e"), b.challenge_scalar(b"e"));
    }

    #[test]
    fn framing_is_injective() {
        // "ab"+"c" vs "a"+"bc" must differ.
        let mut a = Transcript::new(b"d");
        a.append(b"x", b"ab");
        a.append(b"y", b"c");
        let mut b = Transcript::new(b"d");
        b.append(b"x", b"a");
        b.append(b"y", b"bc");
        assert_ne!(a.challenge_scalar(b"e"), b.challenge_scalar(b"e"));
    }

    #[test]
    fn domain_separates() {
        let mut a = Transcript::new(b"d1");
        let mut b = Transcript::new(b"d2");
        assert_ne!(a.challenge_scalar(b"e"), b.challenge_scalar(b"e"));
    }
}
