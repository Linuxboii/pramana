//! §7.6 the age predicate, §7.7 strong Fiat–Shamir, §9.2 proving and §9.3
//! verification (FR-4, FR-5, FR-7).
//!
//! ```text
//! D* = today − threshold years            (public; the verifier computes it)
//! age ≥ threshold  ⇔  D ≤ D*  ⇔  Δ := D* − D ≥ 0
//! C_Δ = D*·G − C_D = Δ·G + (−r)·H         (homomorphism; no new secret)
//! ```
//!
//! The prover runs the §7.5 range proof showing `C_Δ` opens to a value in `[0, 2ⁿ)`.
//! If the holder is under-age, Δ is negative — as a scalar it is `q − |Δ|`, which has
//! no n-bit decomposition — so no valid proof exists.
//!
//! The Fiat–Shamir challenge binds, in order: the suite, `G`, `H`, `n`, the issuer key,
//! `C_D`, the issuer signature, the threshold, `today`, `D*`, `C_Δ`, the verifier id,
//! the verifier nonce, the validity window, and every first-move value of every
//! OR-proof (§7.7 "hash the *whole* statement"; avoids the Frozen-Heart class of
//! weak-Fiat–Shamir bugs, T6).

use crate::credential::{verify_signature, Credential, IssuerPublicKey};
use crate::error::{ProveError, VerifyError};
use crate::params::Params;
use crate::range::{self, BitProof};
use crate::rng::HashDrbg;
use crate::transcript::Transcript;
use crate::wire::{decode_point, decode_scalar, hexbytes};
use crate::{Date, SUITE, WIRE_VERSION};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// Transcript domain for age proofs.
pub const AGE_DOMAIN: &[u8] = b"pramana/gudhapramana/age/v1";

/// Tolerated clock skew (seconds) between prover-side statement issuance and verifier.
pub const CLOCK_SKEW_SECS: u64 = 60;

/// Largest supported threshold.
pub const MAX_THRESHOLD_YEARS: u8 = 125;

/// The public statement issued by a verifier (§9.2 step 1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// Wire version.
    pub v: u8,
    /// Age threshold in years (13 / 16 / 18 / 21 in the demo).
    pub threshold_years: u8,
    /// The verifier's current date (UTC).
    pub today: Date,
    /// Fresh 256-bit verifier nonce (§7.7 replay protection).
    #[serde(with = "hexbytes")]
    pub nonce: [u8; 32],
    /// Verifier identity, e.g. `example-shop.com`.
    pub verifier_id: String,
    /// Unix time the challenge was issued.
    pub issued_at: u64,
    /// Unix time after which the challenge is void.
    pub expires_at: u64,
}

impl Statement {
    /// Build a statement.
    pub fn new(
        threshold_years: u8,
        today: Date,
        nonce: [u8; 32],
        verifier_id: impl Into<String>,
        issued_at: u64,
        ttl_secs: u64,
    ) -> Self {
        Statement {
            v: WIRE_VERSION,
            threshold_years,
            today,
            nonce,
            verifier_id: verifier_id.into(),
            issued_at,
            expires_at: issued_at + ttl_secs,
        }
    }

    /// Structural validation.
    pub fn validate(&self) -> Result<(), String> {
        if self.v != WIRE_VERSION {
            return Err(format!("unsupported statement version {}", self.v));
        }
        if self.threshold_years == 0 || self.threshold_years > MAX_THRESHOLD_YEARS {
            return Err(format!(
                "threshold {} out of range 1..={MAX_THRESHOLD_YEARS}",
                self.threshold_years
            ));
        }
        if self.verifier_id.is_empty() || self.verifier_id.len() > 255 {
            return Err("verifier_id must be 1..=255 bytes".into());
        }
        if self.verifier_id.chars().any(|c| c.is_control()) {
            return Err("verifier_id contains control characters".into());
        }
        if self.expires_at <= self.issued_at {
            return Err("expires_at must be after issued_at".into());
        }
        Ok(())
    }

    /// The cutoff birthdate: born on or before this date ⇒ old enough.
    pub fn cutoff_date(&self) -> Date {
        self.today.minus_years(self.threshold_years as u32)
    }

    /// `D*` = days since 1900-01-01 of the cutoff date (§7.6).
    pub fn d_star(&self) -> i64 {
        self.cutoff_date().days_since_epoch()
    }
}

/// The proof the wallet sends: `{C_D, sig, π}` plus the issuer key and the nonce it
/// answers (§9.2 step 5). This is *everything* the verifier receives — note what is
/// absent: no birthdate, no `D`, no `r`, no name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgeProof {
    /// Wire version.
    pub v: u8,
    /// Which issuer attested `C_D`.
    #[serde(with = "hexbytes")]
    pub issuer_pk: [u8; 32],
    /// The birthdate commitment.
    #[serde(with = "hexbytes")]
    pub c_d: [u8; 32],
    /// Issuer signature over `C_D`.
    #[serde(with = "hexbytes")]
    pub sig: [u8; 64],
    /// The verifier nonce this proof answers.
    #[serde(with = "hexbytes")]
    pub nonce: [u8; 32],
    /// One commitment + OR-proof per bit of Δ.
    pub bits: Vec<BitProof>,
}

/// Successful verification result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verified {
    /// The trusted issuer that attested the birthdate.
    pub issuer: IssuerPublicKey,
}

/// Build the §7.7 strong Fiat–Shamir transcript prefix (everything but the
/// first-move values, which [`range`] appends).
pub fn age_transcript(
    p: &Params,
    st: &Statement,
    issuer_pk: &[u8; 32],
    c_d: &[u8; 32],
    sig: &[u8; 64],
    d_star: i64,
    c_delta: &RistrettoPoint,
) -> Transcript {
    let mut t = Transcript::new(AGE_DOMAIN);
    t.append(b"suite", SUITE.as_bytes());
    t.append_point(b"G", &p.g.compress());
    t.append_point(b"H", &p.h.compress());
    t.append_u64(b"n_bits", p.n_bits as u64);
    t.append(b"issuer_pk", issuer_pk);
    t.append(b"C_D", c_d);
    t.append(b"sig", sig);
    t.append_u64(b"threshold_years", st.threshold_years as u64);
    t.append(b"today", st.today.to_string().as_bytes());
    t.append_i64(b"D_star", d_star);
    t.append_point(b"C_delta", &c_delta.compress());
    t.append(b"verifier_id", st.verifier_id.as_bytes());
    t.append(b"nonce", &st.nonce);
    t.append_u64(b"issued_at", st.issued_at);
    t.append_u64(b"expires_at", st.expires_at);
    t
}

/// `C_Δ = D*·G − C_D` (§7.6). `D*` may be any integer; negative values are mapped
/// into the scalar field.
pub fn slack_commitment(p: &Params, d_star: i64, c_d: &RistrettoPoint) -> RistrettoPoint {
    let ds = if d_star >= 0 {
        Scalar::from(d_star as u64)
    } else {
        -Scalar::from(d_star.unsigned_abs())
    };
    ds * p.g - c_d
}

/// §9.2 — prove `age ≥ threshold` with caller-supplied randomness (KATs, fuzzing).
pub fn prove_age_with_rng<R: RngCore + CryptoRng + ?Sized>(
    p: &Params,
    cred: &Credential,
    st: &Statement,
    rng: &mut R,
) -> Result<AgeProof, ProveError> {
    st.validate().map_err(ProveError::InvalidStatement)?;
    let c_d = decode_point(&cred.c_d).map_err(|_| ProveError::InvalidCredential)?;
    let r = decode_scalar(&cred.r).map_err(|_| ProveError::InvalidCredential)?;
    if crate::pedersen::commit_u64(p, cred.d as u64, &r) != c_d {
        return Err(ProveError::InvalidCredential);
    }
    // §7.6: Δ = D* − D. An under-age holder has Δ < 0 and cannot proceed.
    let d_star = st.d_star();
    let delta = d_star - cred.d as i64;
    if delta < 0 {
        return Err(ProveError::Underage {
            days_short: delta.unsigned_abs(),
        });
    }
    let c_delta = slack_commitment(p, d_star, &c_d);
    let mut t = age_transcript(
        p,
        st,
        &cred.issuer_pk,
        &cred.c_d,
        &cred.sig,
        d_star,
        &c_delta,
    );
    // C_Δ = Δ·G + (−r)·H, so the range proof's blinding is −r.
    let bits = range::prove(p, &mut t, delta as u64, &(-r), rng)?;
    Ok(AgeProof {
        v: WIRE_VERSION,
        issuer_pk: cred.issuer_pk,
        c_d: cred.c_d,
        sig: cred.sig,
        nonce: st.nonce,
        bits,
    })
}

/// §9.2 — prove with hedged randomness: SHA-512 DRBG over (witness ‖ statement ‖ OS
/// entropy), so nonces stay secret even if one of the two sources fails (T7).
pub fn prove_age(p: &Params, cred: &Credential, st: &Statement) -> Result<AgeProof, ProveError> {
    let mut os = [0u8; 32];
    OsRng.fill_bytes(&mut os);
    let mut h = Sha512::new();
    h.update(b"pramana/hedge/v1");
    h.update(cred.r);
    h.update(cred.d.to_le_bytes());
    h.update(crate::wire::to_json(st).as_bytes());
    h.update(os);
    let seed: [u8; 64] = h.finalize().into();
    let mut rng = HashDrbg::from_seed_material(&seed);
    prove_age_with_rng(p, cred, st, &mut rng)
}

/// §9.3 — verify offline. Returns the attesting issuer on success.
///
/// Check order: version → nonce → statement → issuer trust (T8) → signature (T2) →
/// validity window (T3) → decode → `C_Δ` recomputation → §7.5 consistency → §7.7
/// challenge recomputation → §7.4 per-bit OR-proofs. Accept ⇔ all pass.
pub fn verify_age(
    p: &Params,
    proof: &AgeProof,
    st: &Statement,
    trusted: &[IssuerPublicKey],
    now: u64,
) -> Result<Verified, VerifyError> {
    if proof.v != WIRE_VERSION {
        return Err(VerifyError::UnsupportedVersion(proof.v));
    }
    if proof.nonce != st.nonce {
        return Err(VerifyError::NonceMismatch);
    }
    st.validate().map_err(VerifyError::InvalidStatement)?;
    let issuer = trusted
        .iter()
        .find(|i| i.public_key == proof.issuer_pk)
        .ok_or(VerifyError::UntrustedIssuer)?;
    if !verify_signature(&proof.issuer_pk, &proof.c_d, &proof.sig) {
        return Err(VerifyError::BadSignature);
    }
    if now + CLOCK_SKEW_SECS < st.issued_at {
        return Err(VerifyError::NotYetValid);
    }
    if now > st.expires_at {
        return Err(VerifyError::Expired);
    }
    let c_d = decode_point(&proof.c_d)?;
    // §9.3 step 2: recompute D* and C_Δ independently.
    let d_star = st.d_star();
    let c_delta = slack_commitment(p, d_star, &c_d);
    let mut t = age_transcript(
        p,
        st,
        &proof.issuer_pk,
        &proof.c_d,
        &proof.sig,
        d_star,
        &c_delta,
    );
    // §9.3 step 3: every bit OR-proof and the consistency equation.
    range::verify(p, &mut t, &c_delta, &proof.bits)?;
    Ok(Verified {
        issuer: issuer.clone(),
    })
}

/// Everything the transcript inspector (§17 ⑤) shows about a proof: the values a
/// verifier derives, and the outcome of each individual check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inspection {
    /// Cutoff birthdate implied by the statement.
    pub cutoff_date: Date,
    /// `D*`.
    pub d_star: i64,
    /// `C_Δ` (hex).
    pub c_delta: String,
    /// Recomputed Fiat–Shamir challenge `e` (hex), if decodable.
    pub challenge: Option<String>,
    /// Signature check result.
    pub signature_ok: bool,
    /// §7.5 consistency check result.
    pub consistency_ok: bool,
    /// Per-bit OR-proof results.
    pub bits_ok: Vec<bool>,
    /// Serialized proof size in bytes (CBOR).
    pub cbor_bytes: usize,
    /// Serialized proof size in bytes (JSON).
    pub json_bytes: usize,
}

/// Run each verification step independently and report all results (used for
/// teaching; [`verify_age`] is the authoritative check).
pub fn inspect(p: &Params, proof: &AgeProof, st: &Statement) -> Inspection {
    let d_star = st.d_star();
    let sig_ok = verify_signature(&proof.issuer_pk, &proof.c_d, &proof.sig);
    let mut out = Inspection {
        cutoff_date: st.cutoff_date(),
        d_star,
        c_delta: String::new(),
        challenge: None,
        signature_ok: sig_ok,
        consistency_ok: false,
        bits_ok: vec![],
        cbor_bytes: crate::wire::to_cbor(proof).len(),
        json_bytes: crate::wire::to_json(proof).len(),
    };
    let Ok(c_d) = decode_point(&proof.c_d) else {
        return out;
    };
    let c_delta = slack_commitment(p, d_star, &c_d);
    out.c_delta = hex::encode(c_delta.compress().as_bytes());
    let Ok(decoded) = range::decode(p, &proof.bits) else {
        return out;
    };
    out.consistency_ok = range::check_consistency(p, &decoded, &c_delta).is_ok();
    let mut t = age_transcript(
        p,
        st,
        &proof.issuer_pk,
        &proof.c_d,
        &proof.sig,
        d_star,
        &c_delta,
    );
    range::append_first_move(&mut t, &proof.bits);
    let e = t.challenge_scalar(b"e");
    out.challenge = Some(hex::encode(e.as_bytes()));
    out.bits_ok = decoded.iter().map(|b| range::check_bit(p, b, &e)).collect();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::IssuerKey;

    fn fixture(dob: &str) -> (Params, IssuerKey, Credential, Statement) {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(dob.as_bytes());
        let k = IssuerKey::generate("Demo Authority", &mut rng);
        let today = Date::parse("2026-11-19").unwrap();
        let cred = k
            .issue(
                &p,
                Date::parse(dob).unwrap(),
                today,
                1_795_000_000,
                &mut rng,
            )
            .unwrap();
        let st = Statement::new(18, today, [7u8; 32], "example-shop.com", 1_795_000_000, 300);
        (p, k, cred, st)
    }

    #[test]
    fn honest_path() {
        let (p, k, cred, st) = fixture("2001-04-12");
        let pf = prove_age(&p, &cred, &st).unwrap();
        let v = verify_age(&p, &pf, &st, &[k.public()], st.issued_at + 1).unwrap();
        assert_eq!(v.issuer.name, "Demo Authority");
        let ins = inspect(&p, &pf, &st);
        assert!(ins.signature_ok && ins.consistency_ok && ins.bits_ok.iter().all(|b| *b));
    }

    #[test]
    fn birthday_boundary() {
        // Exactly 18 today: D == D*, Δ = 0 — must verify.
        let (p, k, cred, st) = fixture("2008-11-19");
        let pf = prove_age(&p, &cred, &st).unwrap();
        assert!(verify_age(&p, &pf, &st, &[k.public()], st.issued_at).is_ok());
        // One day short.
        let (p, _, cred, st) = fixture("2008-11-20");
        assert_eq!(
            prove_age(&p, &cred, &st),
            Err(ProveError::Underage { days_short: 1 })
        );
    }

    #[test]
    fn underage_cannot_prove() {
        let (p, _, cred, st) = fixture("2012-06-01");
        assert!(matches!(
            prove_age(&p, &cred, &st),
            Err(ProveError::Underage { .. })
        ));
    }

    #[test]
    fn replay_to_other_verifier_fails() {
        let (p, k, cred, st) = fixture("2001-04-12");
        let pf = prove_age(&p, &cred, &st).unwrap();
        let mut other = st.clone();
        other.verifier_id = "other-site.example".into();
        assert!(matches!(
            verify_age(&p, &pf, &other, &[k.public()], st.issued_at),
            Err(VerifyError::FiatShamirCheckFailed { .. })
        ));
    }

    #[test]
    fn expired_rejected() {
        let (p, k, cred, st) = fixture("2001-04-12");
        let pf = prove_age(&p, &cred, &st).unwrap();
        assert_eq!(
            verify_age(&p, &pf, &st, &[k.public()], st.expires_at + 1),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn untrusted_issuer_rejected() {
        let (p, _, cred, st) = fixture("2001-04-12");
        let pf = prove_age(&p, &cred, &st).unwrap();
        assert_eq!(
            verify_age(&p, &pf, &st, &[], st.issued_at),
            Err(VerifyError::UntrustedIssuer)
        );
    }

    #[test]
    fn proof_contains_no_birthdate() {
        let (p, _, cred, st) = fixture("2001-04-12");
        let mut rng = HashDrbg::from_seed_material(b"no-dob");
        let pf = prove_age_with_rng(&p, &cred, &st, &mut rng).unwrap();
        let json = crate::wire::to_json(&pf);
        assert!(!json.contains("2001-04-12"));
        assert!(!json.contains(&hex::encode(cred.r)));
        assert!(!json.contains(&hex::encode((-decode_scalar(&cred.r).unwrap()).to_bytes())));
        // The only top-level fields are the ones the verifier needs.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut keys: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["bits", "c_d", "issuer_pk", "nonce", "sig", "v"]);
    }
}
