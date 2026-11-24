//! §7.3 HVZK simulator for the full age proof — the engine behind the §17 ⑤ "X-ray".
//!
//! Given only public data (`C_D`, the statement) and a verifier challenge `e`, the
//! simulator outputs bit commitments and OR-proofs that pass every verification
//! equation, **without knowing the birthdate**:
//!
//! 1. pick `C₀ … C_{n−2}` uniformly at random, then solve
//!    `C_{n−1} = 2^{−(n−1)}·(C_Δ − Σ_{i<n−1} 2ⁱ·Cᵢ)` so the §7.5 consistency holds;
//! 2. for every bit pick `e₀, z₀, z₁` at random, set `e₁ = e − e₀`, and solve
//!    `T₀ = z₀·H − e₀·Cᵢ`, `T₁ = z₁·H − e₁·(Cᵢ − G)`.
//!
//! Real transcripts (honest prover, random `e`) and simulated ones are identically
//! distributed: every `Cᵢ` is a uniform group element (Pedersen hiding), and every
//! `(e₀, z₀, z₁)` is uniform subject to the verification equations. Since anything a
//! verifier sees could have been produced without the witness, it learns nothing
//! from it — that is zero-knowledge, made tangible.

use crate::age::slack_commitment;
use crate::credential::Credential;
use crate::error::{ProveError, VerifyError};
use crate::params::Params;
use crate::range::{self, BitProof};
use crate::rng::{random_point, random_scalar};
use crate::wire::{decode_point, decode_scalar};
use crate::Statement;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// An interactive-style transcript: an explicit challenge plus bit proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InteractiveTranscript {
    /// The verifier's challenge `e` (hex).
    pub challenge: String,
    /// Bit commitments and OR-proofs.
    pub bits: Vec<BitProof>,
}

/// Simulate a range-proof transcript for `commitment` under challenge `e`.
pub fn simulate_range<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    commitment: &RistrettoPoint,
    e: &Scalar,
    rng: &mut R,
) -> Vec<BitProof> {
    let n = p.n_bits as usize;
    let pow2 = p.powers_of_two();
    let mut cs: Vec<RistrettoPoint> = (0..n - 1).map(|_| random_point(rng)).collect();
    let partial: RistrettoPoint = cs.iter().zip(pow2.iter()).map(|(c, w)| w * c).sum();
    cs.push(pow2[n - 1].invert() * (commitment - partial));
    cs.into_iter()
        .map(|c| {
            let e0 = random_scalar(rng);
            let z0 = random_scalar(rng);
            let z1 = random_scalar(rng);
            let e1 = e - e0;
            let t0 = z0 * p.h - e0 * c;
            let t1 = z1 * p.h - e1 * (c - p.g);
            BitProof {
                c: c.compress().to_bytes(),
                t0: t0.compress().to_bytes(),
                t1: t1.compress().to_bytes(),
                e0: e0.to_bytes(),
                z0: z0.to_bytes(),
                z1: z1.to_bytes(),
            }
        })
        .collect()
}

/// Simulate an age-proof transcript from public data only (no witness).
pub fn simulate_age<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    c_d: &[u8; 32],
    st: &Statement,
    rng: &mut R,
) -> Result<InteractiveTranscript, VerifyError> {
    let c_d = decode_point(c_d)?;
    let c_delta = slack_commitment(p, st.d_star(), &c_d);
    let e = random_scalar(rng);
    Ok(InteractiveTranscript {
        challenge: hex::encode(e.as_bytes()),
        bits: simulate_range(p, &c_delta, &e, rng),
    })
}

/// A *real* interactive transcript: the honest prover answers a random verifier
/// challenge (no Fiat–Shamir), for side-by-side comparison with [`simulate_age`].
pub fn real_interactive_age<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    cred: &Credential,
    st: &Statement,
    rng: &mut R,
) -> Result<InteractiveTranscript, ProveError> {
    let r = decode_scalar(&cred.r).map_err(|_| ProveError::InvalidCredential)?;
    let delta = st.d_star() - cred.d as i64;
    if delta < 0 {
        return Err(ProveError::Underage {
            days_short: delta.unsigned_abs(),
        });
    }
    let committed = range::commit_phase(p, delta as u64, &(-r), rng)?;
    let e = random_scalar(rng);
    Ok(InteractiveTranscript {
        challenge: hex::encode(e.as_bytes()),
        bits: committed.respond(&e),
    })
}

/// Check an interactive transcript against `C_Δ` derived from `c_d` and `st`.
pub fn check_interactive(
    p: &Params,
    c_d: &[u8; 32],
    st: &Statement,
    tr: &InteractiveTranscript,
) -> Result<(), VerifyError> {
    let c_d = decode_point(c_d)?;
    let c_delta = slack_commitment(p, st.d_star(), &c_d);
    let mut e_bytes = [0u8; 32];
    hex::decode_to_slice(&tr.challenge, &mut e_bytes)
        .map_err(|_| VerifyError::Malformed("bad challenge hex".into()))?;
    let e = decode_scalar(&e_bytes)?;
    let decoded = range::decode(p, &tr.bits)?;
    range::check_consistency(p, &decoded, &c_delta)?;
    range::check_bits(p, &decoded, &e)
}

/// Byte samples drawn from real and simulated transcripts, for the X-ray histogram
/// and the statistical zero-knowledge test.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DistributionSamples {
    /// First byte of every `e₀`, `z₀`, `z₁` and `Cᵢ` in real transcripts.
    pub real: Vec<u8>,
    /// Same positions in simulated transcripts.
    pub simulated: Vec<u8>,
    /// Number of transcripts sampled per side.
    pub transcripts: usize,
}

/// Collect [`DistributionSamples`] over `count` transcripts each.
pub fn sample_distributions<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    cred: &Credential,
    st: &Statement,
    count: usize,
    rng: &mut R,
) -> Result<DistributionSamples, ProveError> {
    let mut out = DistributionSamples {
        transcripts: count,
        ..Default::default()
    };
    let take = |bits: &[BitProof], v: &mut Vec<u8>| {
        for b in bits {
            v.extend_from_slice(&[b.e0[0], b.z0[0], b.z1[0], b.c[1]]);
        }
    };
    for _ in 0..count {
        let real = real_interactive_age(p, cred, st, rng)?;
        take(&real.bits, &mut out.real);
        let sim = simulate_age(p, &cred.c_d, st, rng).map_err(|_| ProveError::InvalidCredential)?;
        take(&sim.bits, &mut out.simulated);
    }
    Ok(out)
}

/// Pearson χ² statistic of byte samples against the uniform distribution on 0..=255
/// (255 degrees of freedom; the 99.9th percentile is ≈ 330.5).
pub fn chi_square_uniform(samples: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in samples {
        counts[b as usize] += 1;
    }
    let expected = samples.len() as f64 / 256.0;
    counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::IssuerKey;
    use crate::rng::HashDrbg;
    use crate::Date;

    #[test]
    fn simulated_transcript_passes_all_checks() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"sim");
        let k = IssuerKey::generate("Demo Authority", &mut rng);
        let today = Date::parse("2026-11-19").unwrap();
        // Simulation works even for an UNDER-AGE commitment: the simulator does not
        // need a witness, which is exactly why transcripts carry no information.
        let cred = k
            .issue(&p, Date::parse("2012-01-01").unwrap(), today, 0, &mut rng)
            .unwrap();
        let st = Statement::new(18, today, [1u8; 32], "example-shop.com", 0, 60);
        let sim = simulate_age(&p, &cred.c_d, &st, &mut rng).unwrap();
        assert!(check_interactive(&p, &cred.c_d, &st, &sim).is_ok());
    }

    #[test]
    fn real_interactive_transcript_passes() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"real");
        let k = IssuerKey::generate("Demo Authority", &mut rng);
        let today = Date::parse("2026-11-19").unwrap();
        let cred = k
            .issue(&p, Date::parse("2001-04-12").unwrap(), today, 0, &mut rng)
            .unwrap();
        let st = Statement::new(18, today, [1u8; 32], "example-shop.com", 0, 60);
        let real = real_interactive_age(&p, &cred, &st, &mut rng).unwrap();
        assert!(check_interactive(&p, &cred.c_d, &st, &real).is_ok());
    }
}
