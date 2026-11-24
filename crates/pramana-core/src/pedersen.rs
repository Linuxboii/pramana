//! §7.2 — Pedersen commitments: `Com(v, r) = v·G + r·H`.
//!
//! * **Perfectly hiding**: for uniform `r`, `Com(v, r)` is uniform regardless of `v`.
//! * **Computationally binding**: opening to two values reveals `log_G(H)`.
//! * **Homomorphic**: `Com(v₁,r₁) + Com(v₂,r₂) = Com(v₁+v₂, r₁+r₂)` and
//!   `a·Com(v,r) = Com(a·v, a·r)` — the verifier uses this to derive `C_Δ` (§7.6)
//!   and to recombine bit commitments (§7.5) without any secret.

use crate::params::Params;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// `v·G + r·H`. Scalar multiplication in dalek is constant-time in the scalar.
pub fn commit(p: &Params, v: &Scalar, r: &Scalar) -> RistrettoPoint {
    v * p.g + r * p.h
}

/// Convenience: commit to a small integer.
pub fn commit_u64(p: &Params, v: u64, r: &Scalar) -> RistrettoPoint {
    commit(p, &Scalar::from(v), r)
}

/// Check an opening.
pub fn opens(p: &Params, c: &RistrettoPoint, v: &Scalar, r: &Scalar) -> bool {
    commit(p, v, r) == *c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::{random_scalar, HashDrbg};

    #[test]
    fn homomorphism() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"pedersen");
        let (v1, r1, v2, r2) = (
            random_scalar(&mut rng),
            random_scalar(&mut rng),
            random_scalar(&mut rng),
            random_scalar(&mut rng),
        );
        let a = random_scalar(&mut rng);
        assert_eq!(
            commit(&p, &v1, &r1) + commit(&p, &v2, &r2),
            commit(&p, &(v1 + v2), &(r1 + r2))
        );
        assert_eq!(a * commit(&p, &v1, &r1), commit(&p, &(a * v1), &(a * r1)));
    }

    #[test]
    fn slack_commitment_derivation() {
        // §7.6: C_Δ = D*·G − C_D = (D* − D)·G + (−r)·H
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"slack");
        let r = random_scalar(&mut rng);
        let (d, dstar) = (37_000u64, 40_000u64);
        let c_d = commit_u64(&p, d, &r);
        let c_delta = Scalar::from(dstar) * p.g - c_d;
        assert_eq!(c_delta, commit_u64(&p, dstar - d, &(-r)));
    }

    #[test]
    fn hiding_differs_with_randomness() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"hide");
        let r1 = random_scalar(&mut rng);
        let r2 = random_scalar(&mut rng);
        assert_ne!(commit_u64(&p, 5, &r1), commit_u64(&p, 5, &r2));
    }
}
