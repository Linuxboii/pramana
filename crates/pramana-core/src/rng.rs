//! Randomness (T7).
//!
//! * Production proving uses a **hedged** generator: a SHA-512 counter DRBG seeded
//!   from the witness, the statement and fresh OS entropy. If the OS RNG is weak the
//!   nonces are still unpredictable to anyone not holding the witness (RFC 6979
//!   style); if the witness were somehow known, OS entropy still protects freshness.
//! * Known-answer tests use the same DRBG with a fixed seed so proofs are
//!   byte-for-byte reproducible — including by the Python reference implementation.
//!
//! Scalars are sampled as 64 uniform bytes reduced mod q (`from_bytes_mod_order_wide`),
//! which has statistical distance ≈ 2⁻²⁵⁹ from uniform.

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

/// SHA-512 counter-mode DRBG: block i = SHA-512("pramana/drbg/v1" ‖ seed ‖ u64le(i)).
pub struct HashDrbg {
    seed: [u8; 64],
    counter: u64,
    buf: [u8; 64],
    pos: usize,
}

impl HashDrbg {
    /// Create a DRBG from arbitrary seed material (hashed to 64 bytes).
    pub fn from_seed_material(material: &[u8]) -> Self {
        let mut h = Sha512::new();
        h.update(b"pramana/drbg-seed/v1");
        h.update(material);
        HashDrbg {
            seed: h.finalize().into(),
            counter: 0,
            buf: [0u8; 64],
            pos: 64,
        }
    }

    fn refill(&mut self) {
        let mut h = Sha512::new();
        h.update(b"pramana/drbg/v1");
        h.update(self.seed);
        h.update(self.counter.to_le_bytes());
        self.buf = h.finalize().into();
        self.counter += 1;
        self.pos = 0;
    }
}

impl Drop for HashDrbg {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.buf.zeroize();
    }
}

impl RngCore for HashDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut off = 0;
        while off < dest.len() {
            if self.pos == 64 {
                self.refill();
            }
            let take = (64 - self.pos).min(dest.len() - off);
            dest[off..off + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            off += take;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for HashDrbg {}

/// Uniform scalar from 64 random bytes.
pub fn random_scalar<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    let s = Scalar::from_bytes_mod_order_wide(&b);
    b.zeroize();
    s
}

/// Uniform group element (used only by the simulator and tests).
pub fn random_point<R: RngCore + CryptoRng + ?Sized>(
    rng: &mut R,
) -> curve25519_dalek::ristretto::RistrettoPoint {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drbg_is_deterministic_and_streamed() {
        let mut a = HashDrbg::from_seed_material(b"seed");
        let mut b = HashDrbg::from_seed_material(b"seed");
        let mut x = [0u8; 100];
        a.fill_bytes(&mut x);
        let mut y1 = [0u8; 37];
        let mut y2 = [0u8; 63];
        b.fill_bytes(&mut y1);
        b.fill_bytes(&mut y2);
        assert_eq!(&x[..37], &y1[..]);
        assert_eq!(&x[37..], &y2[..]);
    }
}
