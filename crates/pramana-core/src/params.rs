//! §7.1 — Setting & notation.
//!
//! We work in Ristretto255, a prime-order group of order
//! `q = 2²⁵² + 27742317777372353535851937790883648493` built over Curve25519.
//! `G` is the standard Ristretto basepoint. `H` is derived by hash-to-group from a
//! nothing-up-my-sleeve seed, so nobody knows `log_G(H)` — this is what makes
//! Pedersen commitments binding (§7.2) and is the project's one setup assumption (§8.2).

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::Sha512;

/// Seed for the NUMS generator `H = HashToGroup("pramana/H/v1")`.
pub const H_SEED: &[u8] = b"pramana/H/v1";

/// Default range width. `n = 16` bounds the slack Δ by 65 535 days ≈ 179 years (§7.6).
pub const DEFAULT_N_BITS: u8 = 16;

/// Identifier for this parameter set, recorded in credentials.
pub const PARAMS_ID: &str = "pramana/params/v1:ristretto255:H=HashToGroup(pramana/H/v1):n=16";

/// Public parameters `(G, H, n)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// The Ristretto255 basepoint.
    pub g: RistrettoPoint,
    /// NUMS second generator; `log_G(H)` is unknown to everyone.
    pub h: RistrettoPoint,
    /// Bit width of the range proof.
    pub n_bits: u8,
}

impl Params {
    /// The canonical parameter set: `G` = basepoint, `H` = hash-to-group of [`H_SEED`],
    /// `n = 16`.
    pub fn new() -> Self {
        // §7.1: H = HashToGroup("pramana/H/v1"). `hash_from_bytes::<Sha512>` is the
        // RFC 9496 one-way map: SHA-512 the seed, then the Elligator-based
        // `from_uniform_bytes`. The output is uniformly distributed and its discrete log
        // relative to G is unknown to everyone, including us.
        let h = RistrettoPoint::hash_from_bytes::<Sha512>(H_SEED);
        Params {
            g: RISTRETTO_BASEPOINT_POINT,
            h,
            n_bits: DEFAULT_N_BITS,
        }
    }

    /// Powers of two `2⁰ … 2ⁿ⁻¹` as scalars.
    pub fn powers_of_two(&self) -> Vec<curve25519_dalek::scalar::Scalar> {
        (0..self.n_bits)
            .map(|i| curve25519_dalek::scalar::Scalar::from(1u64 << i))
            .collect()
    }

    /// Largest slack value representable in `n` bits plus one, i.e. `2ⁿ`.
    pub fn range_bound(&self) -> u64 {
        1u64 << self.n_bits
    }
}

impl Default for Params {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::traits::Identity;

    #[test]
    fn h_is_not_g_and_not_identity() {
        let p = Params::new();
        assert_ne!(p.g, p.h);
        assert_ne!(p.h, RistrettoPoint::identity());
    }

    #[test]
    fn h_is_deterministic() {
        assert_eq!(Params::new().h.compress(), Params::new().h.compress());
    }
}
