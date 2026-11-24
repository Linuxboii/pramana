//! §7.4 bit OR-proofs and §7.5 range proof by bit decomposition (FR-3).
//!
//! ## §7.4 — proving a commitment hides a bit
//!
//! For `Cᵢ = bᵢ·G + rᵢ·H` with `bᵢ ∈ {0,1}`, either `Y₀ = Cᵢ` or `Y₁ = Cᵢ − G` is a
//! commitment to 0, i.e. equals `rᵢ·H`. We prove the disjunction
//! "I know `x` with `Y₀ = x·H` **OR** `Y₁ = x·H`" with a Cramer–Damgård–Schoenmakers
//! OR-composition of two Schnorr proofs in base `H`:
//!
//! * the **real** branch `j = bᵢ` runs Schnorr honestly: `T_j = k·H`, later `z_j = k + e_j·rᵢ`;
//! * the **simulated** branch `s = 1 − bᵢ` uses the §7.3 simulator: choose `e_s, z_s`
//!   first, set `T_s = z_s·H − e_s·Y_s`;
//! * the global challenge splits as `e = e₀ + e₁ (mod q)`, so the prover is free to
//!   pick the simulated sub-challenge but is *forced* to answer the real one.
//!
//! The verifier checks `z₀·H == T₀ + e₀·Y₀` and `z₁·H == T₁ + e₁·Y₁` with
//! `e₁ = e − e₀`. It never learns which branch was simulated.
//!
//! **Constant time.** Branch selection uses `subtle::ConditionallySelectable`; both
//! branches are always computed, so there is no secret-dependent control flow in
//! proof construction (NFR "no secret-dependent branches", T9).
//!
//! ## §7.5 — range proof
//!
//! To show `x ∈ [0, 2ⁿ)` for `C = x·G + r·H`: commit to each bit, OR-prove each is a
//! bit, and pick the bit blindings so that `Σ 2ⁱ·rᵢ = r`. Then the *verifier itself*
//! recomputes `Σ 2ⁱ·Cᵢ` and checks it equals `C` — no extra proof needed.
//! Soundness of the range reduces to soundness of the bit proofs.
//!
//! Wire size: 6 × 32 bytes per bit; n = 16 ⇒ 3 KiB.

use crate::error::{ProveError, VerifyError};
use crate::params::Params;
use crate::rng::random_scalar;
use crate::transcript::Transcript;
use crate::wire::{decode_point, decode_scalar, hexbytes};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

/// One bit's commitment and OR-proof. `e₁` is not sent: it is `e − e₀`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitProof {
    /// Bit commitment `Cᵢ = bᵢ·G + rᵢ·H`.
    #[serde(with = "hexbytes")]
    pub c: [u8; 32],
    /// Branch-0 Schnorr commitment `T₀`.
    #[serde(with = "hexbytes")]
    pub t0: [u8; 32],
    /// Branch-1 Schnorr commitment `T₁`.
    #[serde(with = "hexbytes")]
    pub t1: [u8; 32],
    /// Branch-0 sub-challenge `e₀`.
    #[serde(with = "hexbytes")]
    pub e0: [u8; 32],
    /// Branch-0 response `z₀`.
    #[serde(with = "hexbytes")]
    pub z0: [u8; 32],
    /// Branch-1 response `z₁`.
    #[serde(with = "hexbytes")]
    pub z1: [u8; 32],
}

/// A bit proof decoded into group elements / scalars.
#[derive(Clone, Debug)]
pub struct DecodedBit {
    /// `Cᵢ`.
    pub c: RistrettoPoint,
    /// `T₀`.
    pub t0: RistrettoPoint,
    /// `T₁`.
    pub t1: RistrettoPoint,
    /// `e₀`.
    pub e0: Scalar,
    /// `z₀`.
    pub z0: Scalar,
    /// `z₁`.
    pub z1: Scalar,
}

struct BitSecret {
    b: Choice,
    r: Scalar,
    k: Scalar,
    e_s: Scalar,
    z_s: Scalar,
}

impl Drop for BitSecret {
    fn drop(&mut self) {
        self.r.zeroize();
        self.k.zeroize();
        self.e_s.zeroize();
        self.z_s.zeroize();
    }
}

/// Prover state between the commit move and the response move.
pub struct RangeCommitted {
    partial: Vec<BitProof>,
    secrets: Vec<BitSecret>,
}

impl RangeCommitted {
    /// The first-move messages (Cᵢ, T₀, T₁) per bit; e₀/z₀/z₁ are still zero.
    pub fn first_move(&self) -> &[BitProof] {
        &self.partial
    }

    /// Move 3: answer the global challenge `e`.
    pub fn respond(self, e: &Scalar) -> Vec<BitProof> {
        let RangeCommitted {
            mut partial,
            secrets,
        } = self;
        for (bp, s) in partial.iter_mut().zip(secrets.iter()) {
            // Real branch is forced: e_real = e − e_sim, z_real = k + e_real·rᵢ.
            let e_real = e - s.e_s;
            let z_real = s.k + e_real * s.r;
            // b = 0 → branch 0 real; b = 1 → branch 1 real. (select(a, b, c) = c ? b : a)
            let e0 = Scalar::conditional_select(&e_real, &s.e_s, s.b);
            let z0 = Scalar::conditional_select(&z_real, &s.z_s, s.b);
            let z1 = Scalar::conditional_select(&s.z_s, &z_real, s.b);
            bp.e0 = e0.to_bytes();
            bp.z0 = z0.to_bytes();
            bp.z1 = z1.to_bytes();
        }
        partial
    }
}

/// Split blinding `r` into `n` bit blindings with `Σ 2ⁱ·rᵢ = r` (§7.5).
fn split_blinding<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    r: &Scalar,
    rng: &mut R,
) -> Vec<Scalar> {
    let n = p.n_bits as usize;
    let pow2 = p.powers_of_two();
    let mut rs = Vec::with_capacity(n);
    let mut acc = Scalar::ZERO;
    for pw in pow2.iter().take(n - 1) {
        let ri = random_scalar(rng);
        acc += pw * ri;
        rs.push(ri);
    }
    rs.push((r - acc) * pow2[n - 1].invert());
    rs
}

/// Move 1 of the range proof for `C = x·G + r·H`.
pub fn commit_phase<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    x: u64,
    r: &Scalar,
    rng: &mut R,
) -> Result<RangeCommitted, ProveError> {
    let n = p.n_bits;
    if x >= p.range_bound() {
        return Err(ProveError::OutOfRange {
            delta: x,
            n_bits: n,
        });
    }
    let rs = split_blinding(p, r, rng);
    let mut partial = Vec::with_capacity(n as usize);
    let mut secrets = Vec::with_capacity(n as usize);
    for (i, ri) in rs.into_iter().enumerate() {
        let bit = ((x >> i) & 1) as u8;
        let b = Choice::from(bit);
        // Cᵢ = bᵢ·G + rᵢ·H  (constant-time scalar mults; bᵢ enters only as a scalar)
        let c = Scalar::from(bit as u64) * p.g + ri * p.h;
        let y0 = c;
        let y1 = c - p.g;
        let k = random_scalar(rng);
        let e_s = random_scalar(rng);
        let z_s = random_scalar(rng);
        // Simulated branch statement Y_s = (b == 0) ? Y₁ : Y₀
        let y_s = RistrettoPoint::conditional_select(&y1, &y0, b);
        let t_sim = z_s * p.h - e_s * y_s; // §7.3 simulator
        let t_real = k * p.h; // honest Schnorr commitment
        let t0 = RistrettoPoint::conditional_select(&t_real, &t_sim, b);
        let t1 = RistrettoPoint::conditional_select(&t_sim, &t_real, b);
        partial.push(BitProof {
            c: c.compress().to_bytes(),
            t0: t0.compress().to_bytes(),
            t1: t1.compress().to_bytes(),
            e0: [0u8; 32],
            z0: [0u8; 32],
            z1: [0u8; 32],
        });
        secrets.push(BitSecret {
            b,
            r: ri,
            k,
            e_s,
            z_s,
        });
    }
    Ok(RangeCommitted { partial, secrets })
}

/// §7.7: append every first-move value (Cᵢ, T₀ᵢ, T₁ᵢ) to the transcript.
pub fn append_first_move(t: &mut Transcript, bits: &[BitProof]) {
    t.append_u64(b"n", bits.len() as u64);
    for b in bits {
        t.append(b"C_i", &b.c);
        t.append(b"T0_i", &b.t0);
        t.append(b"T1_i", &b.t1);
    }
}

/// Non-interactive range proof: first move → Fiat–Shamir challenge → responses.
pub fn prove<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    t: &mut Transcript,
    x: u64,
    r: &Scalar,
    rng: &mut R,
) -> Result<Vec<BitProof>, ProveError> {
    let committed = commit_phase(p, x, r, rng)?;
    append_first_move(t, committed.first_move());
    let e = t.challenge_scalar(b"e");
    Ok(committed.respond(&e))
}

/// Strictly decode all bit proofs; checks the bit count first.
pub fn decode(p: &Params, bits: &[BitProof]) -> Result<Vec<DecodedBit>, VerifyError> {
    if bits.len() != p.n_bits as usize {
        return Err(VerifyError::WrongBitCount {
            expected: p.n_bits as usize,
            got: bits.len(),
        });
    }
    bits.iter()
        .map(|b| {
            Ok(DecodedBit {
                c: decode_point(&b.c)?,
                t0: decode_point(&b.t0)?,
                t1: decode_point(&b.t1)?,
                e0: decode_scalar(&b.e0)?,
                z0: decode_scalar(&b.z0)?,
                z1: decode_scalar(&b.z1)?,
            })
        })
        .collect()
}

/// §7.5 consistency: `Σ 2ⁱ·Cᵢ == C`, computed by the verifier from public data.
pub fn check_consistency(
    p: &Params,
    bits: &[DecodedBit],
    commitment: &RistrettoPoint,
) -> Result<(), VerifyError> {
    let pow2 = p.powers_of_two();
    let sum = RistrettoPoint::vartime_multiscalar_mul(pow2.iter(), bits.iter().map(|b| b.c));
    if sum == *commitment {
        Ok(())
    } else {
        Err(VerifyError::ConsistencyFailed)
    }
}

/// Check a single OR-proof under global challenge `e`.
pub fn check_bit(p: &Params, b: &DecodedBit, e: &Scalar) -> bool {
    let e1 = e - b.e0;
    let y0 = b.c;
    let y1 = b.c - p.g;
    // z₀·H − e₀·Y₀ − T₀ == 0  and  z₁·H − e₁·Y₁ − T₁ == 0
    let ok0 = RistrettoPoint::vartime_multiscalar_mul([b.z0, -b.e0, -Scalar::ONE], [p.h, y0, b.t0])
        .is_identity();
    let ok1 = RistrettoPoint::vartime_multiscalar_mul([b.z1, -e1, -Scalar::ONE], [p.h, y1, b.t1])
        .is_identity();
    ok0 && ok1
}

/// §7.4 check of all bits under an explicit challenge.
pub fn check_bits(p: &Params, bits: &[DecodedBit], e: &Scalar) -> Result<(), VerifyError> {
    for (i, b) in bits.iter().enumerate() {
        if !check_bit(p, b, e) {
            return Err(VerifyError::FiatShamirCheckFailed { bit: i });
        }
    }
    Ok(())
}

/// Verify a non-interactive range proof that `commitment` hides a value in `[0, 2ⁿ)`.
/// The transcript must already contain the statement (§7.7).
pub fn verify(
    p: &Params,
    t: &mut Transcript,
    commitment: &RistrettoPoint,
    bits: &[BitProof],
) -> Result<(), VerifyError> {
    let decoded = decode(p, bits)?;
    check_consistency(p, &decoded, commitment)?;
    append_first_move(t, bits);
    let e = t.challenge_scalar(b"e");
    check_bits(p, &decoded, &e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pedersen::commit_u64;
    use crate::rng::HashDrbg;

    fn run(x: u64) -> Result<(), VerifyError> {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(&x.to_le_bytes());
        let r = random_scalar(&mut rng);
        let c = commit_u64(&p, x, &r);
        let mut tp = Transcript::new(b"test");
        let bits = prove(&p, &mut tp, x, &r, &mut rng).unwrap();
        let mut tv = Transcript::new(b"test");
        verify(&p, &mut tv, &c, &bits)
    }

    #[test]
    fn edges_verify() {
        for x in [0u64, 1, 2, 3, 255, 256, 32_767, 32_768, 65_534, 65_535] {
            assert_eq!(run(x), Ok(()), "x = {x}");
        }
    }

    #[test]
    fn out_of_range_refuses() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"oor");
        let r = random_scalar(&mut rng);
        let mut t = Transcript::new(b"test");
        assert!(matches!(
            prove(&p, &mut t, 65_536, &r, &mut rng),
            Err(ProveError::OutOfRange { .. })
        ));
    }

    #[test]
    fn wrong_commitment_fails_consistency() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"wc");
        let r = random_scalar(&mut rng);
        let mut tp = Transcript::new(b"test");
        let bits = prove(&p, &mut tp, 10, &r, &mut rng).unwrap();
        let mut tv = Transcript::new(b"test");
        let other = commit_u64(&p, 11, &r);
        assert_eq!(
            verify(&p, &mut tv, &other, &bits),
            Err(VerifyError::ConsistencyFailed)
        );
    }

    #[test]
    fn different_transcript_fails() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"dt");
        let r = random_scalar(&mut rng);
        let c = commit_u64(&p, 10, &r);
        let mut tp = Transcript::new(b"A");
        let bits = prove(&p, &mut tp, 10, &r, &mut rng).unwrap();
        let mut tv = Transcript::new(b"B");
        assert!(matches!(
            verify(&p, &mut tv, &c, &bits),
            Err(VerifyError::FiatShamirCheckFailed { bit: 0 })
        ));
    }
}
