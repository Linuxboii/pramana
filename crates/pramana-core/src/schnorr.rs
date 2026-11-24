//! §7.3 — Σ-protocols: the Schnorr proof of knowledge of a Pedersen opening (FR-2).
//!
//! ```text
//! Prover (knows v, r)                     Verifier (knows C)
//! a, b ← ℤq ;  T = a·G + b·H   ── T ──▸
//!                              ◂── e ──   e ← ℤq
//! z₁ = a + e·v ; z₂ = b + e·r  ─(z₁,z₂)▸  accept iff z₁·G + z₂·H == T + e·C
//! ```
//!
//! * **Completeness** — `z₁G + z₂H = (a+ev)G + (b+er)H = T + eC`.
//! * **Special soundness** — two accepting transcripts `(T,e,z)`, `(T,e',z')` with
//!   `e ≠ e'` give `v = (z₁−z₁')/(e−e')` ([`extract`]).
//! * **HVZK** — [`simulate`] picks `e, z₁, z₂` first and sets `T = z₁G + z₂H − eC`;
//!   the result is identically distributed to a real transcript.
//!
//! The non-interactive form ([`prove`] / [`verify`]) replaces `e` by a hash of the
//! full statement (§7.7).

use crate::error::VerifyError;
use crate::params::Params;
use crate::rng::random_scalar;
use crate::transcript::Transcript;
use crate::wire::{decode_point, decode_scalar, hexbytes};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"pramana/schnorr-opening/v1";

/// A (possibly non-interactive) Schnorr transcript `(T, e, z₁, z₂)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// Prover commitment `T`.
    #[serde(with = "hexbytes")]
    pub t: [u8; 32],
    /// Response `z₁ = a + e·v`.
    #[serde(with = "hexbytes")]
    pub z1: [u8; 32],
    /// Response `z₂ = b + e·r`.
    #[serde(with = "hexbytes")]
    pub z2: [u8; 32],
}

fn fs_challenge(p: &Params, c: &RistrettoPoint, t: &[u8; 32], context: &[u8]) -> Scalar {
    // §7.7 strong Fiat–Shamir: bind the generators, the statement C, any caller
    // context, and the prover's commitment T.
    let mut tr = Transcript::new(DOMAIN);
    tr.append_point(b"G", &p.g.compress());
    tr.append_point(b"H", &p.h.compress());
    tr.append_point(b"C", &c.compress());
    tr.append(b"context", context);
    tr.append(b"T", t);
    tr.challenge_scalar(b"e")
}

/// Interactive prover, move 1: returns the secret nonces `(a, b)` and `T`.
pub fn commit_phase<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    rng: &mut R,
) -> ((Scalar, Scalar), RistrettoPoint) {
    let a = random_scalar(rng);
    let b = random_scalar(rng);
    ((a, b), a * p.g + b * p.h)
}

/// Interactive prover, move 3: responses for challenge `e`.
pub fn respond(nonces: (Scalar, Scalar), v: &Scalar, r: &Scalar, e: &Scalar) -> (Scalar, Scalar) {
    (nonces.0 + e * v, nonces.1 + e * r)
}

/// Check `z₁·G + z₂·H == T + e·C` for an explicit challenge.
pub fn check(
    p: &Params,
    c: &RistrettoPoint,
    t: &RistrettoPoint,
    e: &Scalar,
    z1: &Scalar,
    z2: &Scalar,
) -> bool {
    // z₁G + z₂H − eC − T == 0
    RistrettoPoint::vartime_multiscalar_mul([*z1, *z2, -e, -Scalar::ONE], [p.g, p.h, *c, *t])
        .is_identity()
}

/// Non-interactive proof of knowledge of `(v, r)` with `C = v·G + r·H`.
pub fn prove<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    c: &RistrettoPoint,
    v: &Scalar,
    r: &Scalar,
    context: &[u8],
    rng: &mut R,
) -> SchnorrProof {
    let (nonces, t) = commit_phase(p, rng);
    let t_bytes = t.compress().to_bytes();
    let e = fs_challenge(p, c, &t_bytes, context);
    let (z1, z2) = respond(nonces, v, r, &e);
    SchnorrProof {
        t: t_bytes,
        z1: z1.to_bytes(),
        z2: z2.to_bytes(),
    }
}

/// Verify a non-interactive proof.
pub fn verify(
    p: &Params,
    c: &RistrettoPoint,
    proof: &SchnorrProof,
    context: &[u8],
) -> Result<(), VerifyError> {
    let t = decode_point(&proof.t)?;
    let z1 = decode_scalar(&proof.z1)?;
    let z2 = decode_scalar(&proof.z2)?;
    let e = fs_challenge(p, c, &proof.t, context);
    if check(p, c, &t, &e, &z1, &z2) {
        Ok(())
    } else {
        Err(VerifyError::SchnorrFailed)
    }
}

/// §7.3 HVZK simulator: an accepting transcript for challenge `e`, produced
/// **without** the witness.
pub fn simulate<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    c: &RistrettoPoint,
    e: &Scalar,
    rng: &mut R,
) -> (RistrettoPoint, Scalar, Scalar) {
    let z1 = random_scalar(rng);
    let z2 = random_scalar(rng);
    let t = z1 * p.g + z2 * p.h - e * c;
    (t, z1, z2)
}

/// §7.3 special-soundness extractor: from two accepting transcripts sharing `T`
/// with different challenges, recover the witness `(v, r)`.
pub fn extract(
    e: &Scalar,
    z: (Scalar, Scalar),
    e_prime: &Scalar,
    z_prime: (Scalar, Scalar),
) -> Option<(Scalar, Scalar)> {
    let de = e - e_prime;
    if de == Scalar::ZERO {
        return None;
    }
    let inv = de.invert();
    Some(((z.0 - z_prime.0) * inv, (z.1 - z_prime.1) * inv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::commit;
    use crate::rng::HashDrbg;

    fn setup() -> (Params, HashDrbg, Scalar, Scalar, RistrettoPoint) {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"schnorr");
        let v = random_scalar(&mut rng);
        let r = random_scalar(&mut rng);
        let c = commit(&p, &v, &r);
        (p, rng, v, r, c)
    }

    #[test]
    fn completeness_non_interactive() {
        let (p, mut rng, v, r, c) = setup();
        let pf = prove(&p, &c, &v, &r, b"ctx", &mut rng);
        assert!(verify(&p, &c, &pf, b"ctx").is_ok());
    }

    #[test]
    fn context_is_bound() {
        let (p, mut rng, v, r, c) = setup();
        let pf = prove(&p, &c, &v, &r, b"ctx", &mut rng);
        assert_eq!(
            verify(&p, &c, &pf, b"other"),
            Err(VerifyError::SchnorrFailed)
        );
    }

    #[test]
    fn wrong_witness_fails() {
        let (p, mut rng, v, r, c) = setup();
        let pf = prove(&p, &c, &(v + Scalar::ONE), &r, b"", &mut rng);
        assert!(verify(&p, &c, &pf, b"").is_err());
    }

    #[test]
    fn simulator_accepts() {
        let (p, mut rng, _v, _r, c) = setup();
        let e = random_scalar(&mut rng);
        let (t, z1, z2) = simulate(&p, &c, &e, &mut rng);
        assert!(check(&p, &c, &t, &e, &z1, &z2));
    }

    #[test]
    fn extractor_recovers_witness() {
        let (p, mut rng, v, r, c) = setup();
        let (nonces, t) = commit_phase(&p, &mut rng);
        let e1 = random_scalar(&mut rng);
        let e2 = random_scalar(&mut rng);
        let z = respond(nonces, &v, &r, &e1);
        let zp = respond(nonces, &v, &r, &e2);
        assert!(check(&p, &c, &t, &e1, &z.0, &z.1));
        assert!(check(&p, &c, &t, &e2, &zp.0, &zp.1));
        assert_eq!(extract(&e1, z, &e2, zp), Some((v, r)));
    }
}
