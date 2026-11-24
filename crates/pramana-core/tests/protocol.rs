//! §16 Testing & verification strategy — property-based, soundness (negative),
//! zero-knowledge (distribution), replay, and fuzzing layers.

use pramana_core::adversary::{cheat_prove, CheatStrategy};
use pramana_core::rng::HashDrbg;
use pramana_core::simulator::{chi_square_uniform, sample_distributions};
use pramana_core::wire;
use pramana_core::{
    prove_age_with_rng, verify_age, AgeProof, Credential, Date, IssuerKey, Params, ProveError,
    Statement, VerifyError,
};
use proptest::prelude::*;

const NOW: u64 = 1_795_000_000;

fn issuer() -> IssuerKey {
    IssuerKey::from_secret("Demo Authority", &[0x11; 32])
}

fn issue(p: &Params, k: &IssuerKey, dob: Date, today: Date, seed: &[u8]) -> Credential {
    let mut rng = HashDrbg::from_seed_material(seed);
    k.issue(p, dob, today, NOW, &mut rng).unwrap()
}

fn statement(threshold: u8, today: Date, verifier: &str, nonce: u8) -> Statement {
    Statement::new(threshold, today, [nonce; 32], verifier, NOW, 300)
}

fn exact_age_ok(dob: Date, today: Date, threshold: u8) -> bool {
    // Independent oracle (not using days arithmetic): compare (y, m, d) tuples
    // against the cutoff with 29-Feb clamping.
    let cy = today.year() - threshold as i32;
    let leap = |y: i32| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let (cm, mut cd) = (today.month(), today.day());
    if cm == 2 && cd == 29 && !leap(cy) {
        cd = 28;
    }
    (dob.year(), dob.month(), dob.day()) <= (cy, cm, cd)
}

// ---------------------------------------------------------------- property-based

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    /// For random (D, threshold, today): the proof verifies iff age truly ≥ threshold.
    #[test]
    fn verifies_iff_old_enough(
        dob_days in 0i64..46_000,          // 1900 .. ~2025
        today_days in 40_000i64..48_000,   // ~2009 .. ~2031
        threshold in prop::sample::select(vec![13u8, 16, 18, 21]),
        seed in any::<u64>(),
    ) {
        prop_assume!(dob_days <= today_days);
        let p = Params::new();
        let k = issuer();
        let dob = Date::from_days_since_epoch(dob_days).unwrap();
        let today = Date::from_days_since_epoch(today_days).unwrap();
        let cred = issue(&p, &k, dob, today, &seed.to_le_bytes());
        let st = statement(threshold, today, "prop.example", 5);
        let mut rng = HashDrbg::from_seed_material(&seed.to_be_bytes());
        let expected = exact_age_ok(dob, today, threshold);
        match prove_age_with_rng(&p, &cred, &st, &mut rng) {
            Ok(pf) => {
                prop_assert!(expected, "proved but {dob} is under {threshold} on {today}");
                prop_assert!(verify_age(&p, &pf, &st, &[k.public()], NOW).is_ok());
            }
            Err(ProveError::Underage { .. }) => prop_assert!(!expected, "{dob} refused on {today} for {threshold}"),
            Err(e) => prop_assert!(false, "unexpected {e}"),
        }
    }

    /// Fuzzing: arbitrary bytes never panic any decoder or the verifier.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let p = Params::new();
        let st = statement(18, Date::parse("2026-11-19").unwrap(), "fuzz.example", 1);
        if let Ok(pf) = wire::from_cbor::<AgeProof>(&bytes) {
            let _ = verify_age(&p, &pf, &st, &[issuer().public()], NOW);
        }
        let _ = wire::from_cbor::<Credential>(&bytes);
        let _ = wire::from_cbor::<Statement>(&bytes);
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = wire::from_json::<AgeProof>(s);
            let _ = Credential::from_json_checked(&p, s);
        }
    }

    /// Fuzzing: single-byte mutations of a valid proof are always rejected cleanly.
    #[test]
    fn mutated_valid_proof_is_rejected(pos in 0usize..20_000, xor in 1u8..=255) {
        let p = Params::new();
        let k = issuer();
        let today = Date::parse("2026-11-19").unwrap();
        let cred = issue(&p, &k, Date::parse("2001-04-12").unwrap(), today, b"mut");
        let st = statement(18, today, "example-shop.com", 9);
        let mut rng = HashDrbg::from_seed_material(b"mut-prove");
        let pf = prove_age_with_rng(&p, &cred, &st, &mut rng).unwrap();
        let mut bytes = wire::to_cbor(&pf);
        let i = pos % bytes.len();
        bytes[i] ^= xor;
        match wire::from_cbor::<AgeProof>(&bytes) {
            Ok(m) if m == pf => {} // mutation hit an encoding-irrelevant byte (impossible in CBOR, but be safe)
            Ok(m) => prop_assert!(verify_age(&p, &m, &st, &[k.public()], NOW).is_err()),
            Err(_) => {}
        }
    }
}

// ---------------------------------------------------------------- soundness (negative)

#[test]
fn underage_witness_cannot_prove_and_cheats_are_rejected() {
    let p = Params::new();
    let k = issuer();
    let today = Date::parse("2026-11-19").unwrap();
    let teen = issue(&p, &k, Date::parse("2012-04-12").unwrap(), today, b"teen");
    let st = statement(18, today, "example-shop.com", 2);
    let mut rng = HashDrbg::from_seed_material(b"teen-prove");
    assert!(matches!(
        prove_age_with_rng(&p, &teen, &st, &mut rng),
        Err(ProveError::Underage { .. })
    ));
    for (s, code) in [
        (CheatStrategy::WrapAround, "consistency_failed"),
        (CheatStrategy::FakeDigit, "fiat_shamir_check_failed"),
        (CheatStrategy::SwapCommitment, "bad_signature"),
        (CheatStrategy::RogueIssuer, "untrusted_issuer"),
    ] {
        for trial in 0..4u8 {
            let mut rng = HashDrbg::from_seed_material(&[trial, s as u8]);
            let pf = cheat_prove(&p, &teen, &st, s, &mut rng).unwrap();
            assert_eq!(
                verify_age(&p, &pf, &st, &[k.public()], NOW)
                    .unwrap_err()
                    .code(),
                code
            );
        }
    }
}

#[test]
fn tampered_signature_or_commitment_rejected() {
    let p = Params::new();
    let k = issuer();
    let today = Date::parse("2026-11-19").unwrap();
    let cred = issue(&p, &k, Date::parse("1990-01-01").unwrap(), today, b"tamper");
    let st = statement(21, today, "example-shop.com", 4);
    let mut rng = HashDrbg::from_seed_material(b"t");
    let pf = prove_age_with_rng(&p, &cred, &st, &mut rng).unwrap();

    let mut bad_sig = pf.clone();
    bad_sig.sig[10] ^= 0x80;
    assert_eq!(
        verify_age(&p, &bad_sig, &st, &[k.public()], NOW),
        Err(VerifyError::BadSignature)
    );

    let mut bad_bit = pf.clone();
    bad_bit.bits[3].c = pf.bits[4].c;
    assert!(verify_age(&p, &bad_bit, &st, &[k.public()], NOW).is_err());

    let mut truncated = pf.clone();
    truncated.bits.pop();
    assert!(matches!(
        verify_age(&p, &truncated, &st, &[k.public()], NOW),
        Err(VerifyError::WrongBitCount { .. })
    ));

    // Raising the threshold after the fact must fail (statement is bound).
    let mut st2 = st.clone();
    st2.threshold_years = 18;
    assert!(verify_age(&p, &pf, &st2, &[k.public()], NOW).is_err());
}

// ---------------------------------------------------------------- replay / transfer

#[test]
fn replay_to_second_verifier_and_after_expiry_fails() {
    let p = Params::new();
    let k = issuer();
    let today = Date::parse("2026-11-19").unwrap();
    let cred = issue(&p, &k, Date::parse("2001-04-12").unwrap(), today, b"replay");
    let st_a = statement(18, today, "example-shop.com", 0xA1);
    let mut rng = HashDrbg::from_seed_material(b"replay-prove");
    let pf = prove_age_with_rng(&p, &cred, &st_a, &mut rng).unwrap();
    assert!(verify_age(&p, &pf, &st_a, &[k.public()], NOW).is_ok());

    // Verifier B issues its own statement; the captured proof answers A's nonce.
    let st_b = statement(18, today, "other-site.example", 0xB2);
    assert_eq!(
        verify_age(&p, &pf, &st_b, &[k.public()], NOW),
        Err(VerifyError::NonceMismatch)
    );

    // Attacker rewrites the nonce field to B's: the Fiat–Shamir hash no longer matches.
    let mut relabelled = pf.clone();
    relabelled.nonce = st_b.nonce;
    assert!(matches!(
        verify_age(&p, &relabelled, &st_b, &[k.public()], NOW),
        Err(VerifyError::FiatShamirCheckFailed { .. })
    ));

    // Same verifier id, same nonce but different verifier name → fails.
    let mut st_a_prime = st_a.clone();
    st_a_prime.verifier_id = "example-shop.com.evil".into();
    assert!(verify_age(&p, &pf, &st_a_prime, &[k.public()], NOW).is_err());

    // After expiry.
    assert_eq!(
        verify_age(&p, &pf, &st_a, &[k.public()], st_a.expires_at + 1),
        Err(VerifyError::Expired)
    );
}

// ---------------------------------------------------------------- zero-knowledge

#[test]
fn simulated_and_real_transcripts_are_statistically_indistinguishable() {
    let p = Params::new();
    let k = issuer();
    let today = Date::parse("2026-11-19").unwrap();
    let cred = issue(&p, &k, Date::parse("2001-04-12").unwrap(), today, b"zk");
    let st = statement(18, today, "example-shop.com", 7);
    let mut rng = HashDrbg::from_seed_material(b"zk-samples");
    let s = sample_distributions(&p, &cred, &st, 80, &mut rng).unwrap();
    assert_eq!(s.real.len(), s.simulated.len());
    // Each side is uniform (χ² with 255 dof; 99.99th percentile ≈ 347).
    let (cr, cs) = (
        chi_square_uniform(&s.real),
        chi_square_uniform(&s.simulated),
    );
    assert!(cr < 347.0, "real χ² = {cr}");
    assert!(cs < 347.0, "simulated χ² = {cs}");
    // Two-sample χ² homogeneity test on 16 coarse buckets (15 dof; 99.99th pct ≈ 44.3).
    let bucket = |v: &[u8]| {
        let mut b = [0f64; 16];
        for x in v {
            b[(*x >> 4) as usize] += 1.0;
        }
        b
    };
    let (br, bs) = (bucket(&s.real), bucket(&s.simulated));
    let stat: f64 = br
        .iter()
        .zip(bs.iter())
        .map(|(a, b)| (a - b) * (a - b) / (a + b))
        .sum();
    assert!(stat < 44.3, "homogeneity χ² = {stat}");
}

#[test]
fn bit_values_do_not_show_in_transcripts() {
    // Δ = 0 (all bits 0) and Δ = 65535 (all bits 1) produce identically distributed
    // first bytes of e₀ — the OR-proof hides which branch is real.
    let p = Params::new();
    let k = issuer();
    // Far-future "today" so that a Δ of 65 535 days still has a post-1900 birthdate.
    let today = Date::parse("2100-01-01").unwrap();
    let st = statement(18, today, "example-shop.com", 8);
    let zero = issue(&p, &k, st.cutoff_date(), today, b"zero");
    let ones_dob = Date::from_days_since_epoch(st.d_star() - 65_535).unwrap();
    let ones = issue(&p, &k, ones_dob, today, b"ones");
    let mut rng = HashDrbg::from_seed_material(b"bits");
    let a = sample_distributions(&p, &zero, &st, 60, &mut rng).unwrap();
    let b = sample_distributions(&p, &ones, &st, 60, &mut rng).unwrap();
    assert!(chi_square_uniform(&a.real) < 347.0);
    assert!(chi_square_uniform(&b.real) < 347.0);
}

// ---------------------------------------------------------------- wire format

#[test]
fn json_and_cbor_roundtrip_and_sizes() {
    let p = Params::new();
    let k = issuer();
    let today = Date::parse("2026-11-19").unwrap();
    let cred = issue(&p, &k, Date::parse("2001-04-12").unwrap(), today, b"wire");
    let st = statement(18, today, "example-shop.com", 6);
    let mut rng = HashDrbg::from_seed_material(b"wire-prove");
    let pf = prove_age_with_rng(&p, &cred, &st, &mut rng).unwrap();
    let cbor = wire::to_cbor(&pf);
    let json = wire::to_json(&pf);
    assert_eq!(wire::from_cbor::<AgeProof>(&cbor).unwrap(), pf);
    assert_eq!(wire::from_json::<AgeProof>(&json).unwrap(), pf);
    // NFR: "a few KB" for Tier A, n = 16.
    assert!(cbor.len() < 4 * 1024, "cbor {} bytes", cbor.len());
    let st_back: Statement = wire::from_json(&wire::to_json(&st)).unwrap();
    assert_eq!(st_back, st);
}

#[test]
fn unsupported_version_rejected() {
    let p = Params::new();
    let k = issuer();
    let today = Date::parse("2026-11-19").unwrap();
    let cred = issue(&p, &k, Date::parse("2001-04-12").unwrap(), today, b"ver");
    let st = statement(18, today, "example-shop.com", 6);
    let mut rng = HashDrbg::from_seed_material(b"ver");
    let mut pf = prove_age_with_rng(&p, &cred, &st, &mut rng).unwrap();
    pf.v = 2;
    assert_eq!(
        verify_age(&p, &pf, &st, &[k.public()], NOW),
        Err(VerifyError::UnsupportedVersion(2))
    );
}
