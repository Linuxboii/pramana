//! Cheating provers for the §17 demonstration and the negative test-suite (§16).
//!
//! Each strategy is a *best-effort* attack that produces a well-formed [`AgeProof`]
//! the verifier must reject. They exist to make soundness and binding visible; none
//! of them can succeed except with negligible probability (§7.9).

use crate::age::{age_transcript, slack_commitment, AgeProof};
use crate::credential::{Credential, IssuerKey};
use crate::params::Params;
use crate::range::{self, append_first_move, BitProof};
use crate::rng::random_scalar;
use crate::wire::{decode_point, decode_scalar};
use crate::{Date, Statement, WIRE_VERSION};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Attack strategies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheatStrategy {
    /// §17 ② — under-age holder decomposes `Δ mod 2ⁿ` instead of the negative Δ.
    /// Every bit proof is honest, but `Σ 2ⁱ·Cᵢ ≠ C_Δ`: the §7.5 consistency check fails.
    WrapAround,
    /// §17 ② — under-age holder keeps consistency by using a non-bit top digit and
    /// fakes that digit's OR-proof by simulating *both* branches. The Fiat–Shamir
    /// challenge then fails to split: §7.4/§7.7 check fails.
    FakeDigit,
    /// §17 ③ — swap in a fresh, self-made commitment to an older birthdate while
    /// keeping the real issuer signature. The signature over `C_D` fails (T2).
    SwapCommitment,
    /// §17 ③ — mint a credential from a self-generated "issuer" key. The verifier's
    /// trust list rejects it (T8).
    RogueIssuer,
    /// §17 ③ — take an honest proof and flip one bit of one response. The OR-proof
    /// fails under the recomputed challenge.
    TamperBytes,
}

/// Build a cheating proof. `cred` is the cheater's own (possibly under-age) credential.
pub fn cheat_prove<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    cred: &Credential,
    st: &Statement,
    strategy: CheatStrategy,
    rng: &mut R,
) -> Result<AgeProof, String> {
    let d_star = st.d_star();
    let r = decode_scalar(&cred.r).map_err(|e| e.to_string())?;
    let c_d = decode_point(&cred.c_d).map_err(|e| e.to_string())?;
    let c_delta = slack_commitment(p, d_star, &c_d);
    let delta = d_star - cred.d as i64;
    let bound = p.range_bound() as i64;
    let mut t = age_transcript(
        p,
        st,
        &cred.issuer_pk,
        &cred.c_d,
        &cred.sig,
        d_star,
        &c_delta,
    );

    let wrap = |bits: Vec<BitProof>, c: &Credential| AgeProof {
        v: WIRE_VERSION,
        issuer_pk: c.issuer_pk,
        c_d: c.c_d,
        sig: c.sig,
        nonce: st.nonce,
        bits,
    };

    match strategy {
        CheatStrategy::WrapAround => {
            let x = delta.rem_euclid(bound) as u64;
            let bits = range::prove(p, &mut t, x, &(-r), rng).map_err(|e| e.to_string())?;
            Ok(wrap(bits, cred))
        }
        CheatStrategy::FakeDigit => {
            let n = p.n_bits as usize;
            let pow2 = p.powers_of_two();
            let low = delta.rem_euclid(bound) as u64;
            let delta_s = if delta >= 0 {
                Scalar::from(delta as u64)
            } else {
                -Scalar::from(delta.unsigned_abs())
            };
            // Digits: honest low bits, then whatever top "digit" makes Σ 2ⁱ·dᵢ = Δ.
            let mut digits: Vec<Scalar> =
                (0..n - 1).map(|i| Scalar::from((low >> i) & 1)).collect();
            let low_sum: Scalar = digits.iter().zip(pow2.iter()).map(|(d, w)| d * w).sum();
            digits.push((delta_s - low_sum) * pow2[n - 1].invert());
            // Blindings summing to −r, so consistency holds exactly.
            let mut rs: Vec<Scalar> = (0..n - 1).map(|_| random_scalar(rng)).collect();
            let rs_sum: Scalar = rs.iter().zip(pow2.iter()).map(|(r, w)| r * w).sum();
            rs.push((-r - rs_sum) * pow2[n - 1].invert());

            let mut bits = Vec::with_capacity(n);
            let mut secrets = Vec::with_capacity(n);
            for i in 0..n {
                let c = digits[i] * p.g + rs[i] * p.h;
                let (e_s, z_s, k) = (random_scalar(rng), random_scalar(rng), random_scalar(rng));
                let is_bit = i < n - 1;
                let b = if is_bit { ((low >> i) & 1) as u8 } else { 0 };
                let (t0, t1, e1_guess, z1_fake);
                if is_bit {
                    let (y0, y1) = (c, c - p.g);
                    if b == 0 {
                        t0 = k * p.h;
                        t1 = z_s * p.h - e_s * y1;
                    } else {
                        t0 = z_s * p.h - e_s * y0;
                        t1 = k * p.h;
                    }
                    e1_guess = Scalar::ZERO;
                    z1_fake = Scalar::ZERO;
                } else {
                    // Not a bit: no branch can be answered honestly — simulate both
                    // with independently guessed sub-challenges and hope e₀+e₁ = e.
                    let (e1g, z1f) = (random_scalar(rng), random_scalar(rng));
                    t0 = z_s * p.h - e_s * c;
                    t1 = z1f * p.h - e1g * (c - p.g);
                    e1_guess = e1g;
                    z1_fake = z1f;
                }
                bits.push(BitProof {
                    c: c.compress().to_bytes(),
                    t0: t0.compress().to_bytes(),
                    t1: t1.compress().to_bytes(),
                    e0: [0; 32],
                    z0: [0; 32],
                    z1: [0; 32],
                });
                secrets.push((b, is_bit, rs[i], k, e_s, z_s, e1_guess, z1_fake));
            }
            append_first_move(&mut t, &bits);
            let e = t.challenge_scalar(b"e");
            for (bp, (b, is_bit, ri, k, e_s, z_s, _e1g, z1f)) in bits.iter_mut().zip(secrets) {
                let (e0, z0, z1);
                if is_bit {
                    let e_real = e - e_s;
                    let z_real = k + e_real * ri;
                    if b == 0 {
                        (e0, z0, z1) = (e_real, z_real, z_s);
                    } else {
                        (e0, z0, z1) = (e_s, z_s, z_real);
                    }
                } else {
                    (e0, z0, z1) = (e_s, z_s, z1f);
                }
                bp.e0 = e0.to_bytes();
                bp.z0 = z0.to_bytes();
                bp.z1 = z1.to_bytes();
            }
            Ok(wrap(bits, cred))
        }
        CheatStrategy::SwapCommitment => {
            // Commit to a birthdate 10 years before the cutoff, keep the real sig.
            let fake_d = (d_star - 3652).max(0) as u64;
            let r2 = random_scalar(rng);
            let fake_c: RistrettoPoint = Scalar::from(fake_d) * p.g + r2 * p.h;
            let mut forged = cred.clone();
            forged.c_d = fake_c.compress().to_bytes();
            forged.d = fake_d as u32;
            forged.r = r2.to_bytes();
            crate::age::prove_age_with_rng(p, &forged, st, rng).map_err(|e| e.to_string())
        }
        CheatStrategy::RogueIssuer => {
            let rogue = IssuerKey::generate("Totally Legit Authority", rng);
            let fake_dob =
                Date::from_days_since_epoch((d_star - 3652).max(0)).map_err(|e| e.to_string())?;
            let forged = rogue
                .issue(p, fake_dob, st.today, st.issued_at, rng)
                .map_err(|e| e.to_string())?;
            crate::age::prove_age_with_rng(p, &forged, st, rng).map_err(|e| e.to_string())
        }
        CheatStrategy::TamperBytes => {
            let mut pf =
                crate::age::prove_age_with_rng(p, cred, st, rng).map_err(|e| e.to_string())?;
            let i = pf.bits.len() / 2;
            pf.bits[i].z0[0] ^= 0x01;
            Ok(pf)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::age::verify_age;
    use crate::error::VerifyError;
    use crate::rng::HashDrbg;

    fn setup(dob: &str) -> (Params, IssuerKey, Credential, Statement, HashDrbg) {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(dob.as_bytes());
        let k = IssuerKey::generate("Demo Authority", &mut rng);
        let today = Date::parse("2026-11-19").unwrap();
        let cred = k
            .issue(&p, Date::parse(dob).unwrap(), today, 100, &mut rng)
            .unwrap();
        let st = Statement::new(18, today, [3u8; 32], "example-shop.com", 100, 300);
        (p, k, cred, st, rng)
    }

    #[test]
    fn every_cheat_is_rejected() {
        let (p, k, teen, st, mut rng) = setup("2012-06-01");
        let trust = [k.public()];
        let cases = [
            (CheatStrategy::WrapAround, &teen, "consistency_failed"),
            (CheatStrategy::FakeDigit, &teen, "fiat_shamir_check_failed"),
            (CheatStrategy::SwapCommitment, &teen, "bad_signature"),
            (CheatStrategy::RogueIssuer, &teen, "untrusted_issuer"),
        ];
        for (s, cred, code) in cases {
            let pf = cheat_prove(&p, cred, &st, s, &mut rng).unwrap();
            let err = verify_age(&p, &pf, &st, &trust, 101).unwrap_err();
            assert_eq!(err.code(), code, "{s:?}");
        }
        let (p, k, adult, st, mut rng) = setup("2001-04-12");
        let pf = cheat_prove(&p, &adult, &st, CheatStrategy::TamperBytes, &mut rng).unwrap();
        assert!(matches!(
            verify_age(&p, &pf, &st, &[k.public()], 101),
            Err(VerifyError::FiatShamirCheckFailed { .. }) | Err(VerifyError::Malformed(_))
        ));
    }
}
