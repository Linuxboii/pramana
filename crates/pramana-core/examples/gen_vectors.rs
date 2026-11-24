//! Generate the known-answer test vectors in `test-vectors/v1.json` (§16 KATs).
//!
//! Every random choice comes from the SHA-512 DRBG in `pramana_core::rng` with a
//! fixed, named seed, so the output is byte-for-byte reproducible — by this crate
//! (`tests/kat.rs`) and by the independent Python reference
//! (`python/pramana_ref.py --check-vectors`).
//!
//! Usage: `cargo run -p pramana-core --example gen_vectors > test-vectors/v1.json`

use pramana_core::rng::HashDrbg;
use pramana_core::{prove_age_with_rng, Date, IssuerKey, Params, Statement};
use serde_json::json;
use sha2::{Digest, Sha256};

pub fn main() {
    print!("{}", generate());
}

pub fn generate() -> String {
    let p = Params::new();
    let issuer = IssuerKey::from_secret("Demo Authority", &[0x42; 32]);
    let cases = [
        (
            "aarav-18",
            "2001-04-12",
            "2026-11-19",
            18u8,
            "example-shop.com",
        ),
        (
            "boundary-exactly-18",
            "2008-11-19",
            "2026-11-19",
            18,
            "example-shop.com",
        ),
        (
            "leapling-not-yet-21",
            "2004-02-29",
            "2025-02-28",
            21,
            "wine.example",
        ),
        (
            "leapling-21-on-mar-1",
            "2004-02-29",
            "2025-03-01",
            21,
            "wine.example",
        ),
        ("teen-13", "2012-06-01", "2026-11-19", 13, "social.example"),
        (
            "teen-cannot-18",
            "2012-06-01",
            "2026-11-19",
            18,
            "example-shop.com",
        ),
    ];
    let mut vectors = vec![];
    for (name, dob, today, threshold, verifier) in cases {
        let today_d = Date::parse(today).unwrap();
        let mut issue_rng = HashDrbg::from_seed_material(format!("issue/{name}").as_bytes());
        let cred = issuer
            .issue(
                &p,
                Date::parse(dob).unwrap(),
                today_d,
                1_795_000_000,
                &mut issue_rng,
            )
            .unwrap();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&Sha256::digest(format!("nonce/{name}").as_bytes()));
        let st = Statement::new(threshold, today_d, nonce, verifier, 1_795_000_000, 300);
        let mut prove_rng = HashDrbg::from_seed_material(format!("prove/{name}").as_bytes());
        let (proof, proof_sha256, expect) = match prove_age_with_rng(&p, &cred, &st, &mut prove_rng)
        {
            Ok(pf) => {
                let bytes = pramana_core::wire::to_json(&pf);
                let h = hex::encode(Sha256::digest(bytes.as_bytes()));
                (
                    serde_json::to_value(&pf).unwrap(),
                    Some(h),
                    "accept".to_string(),
                )
            }
            Err(e) => (serde_json::Value::Null, None, format!("prove_error: {e}")),
        };
        vectors.push(json!({
            "name": name,
            "dob": dob,
            "issue_rng_seed": format!("issue/{name}"),
            "prove_rng_seed": format!("prove/{name}"),
            "credential": cred,
            "statement": st,
            "d_star": st.d_star(),
            "proof": proof,
            "proof_json_sha256": proof_sha256,
            "expect": expect,
        }));
    }
    let doc = json!({
        "suite": pramana_core::SUITE,
        "params": {
            "G": hex::encode(p.g.compress().as_bytes()),
            "H": hex::encode(p.h.compress().as_bytes()),
            "H_seed": String::from_utf8_lossy(pramana_core::params::H_SEED),
            "n_bits": p.n_bits,
        },
        "issuer": {
            "name": issuer.name(),
            "secret_seed": hex::encode([0x42u8; 32]),
            "public_key": hex::encode(issuer.public_key()),
        },
        "vectors": vectors,
    });
    serde_json::to_string_pretty(&doc).unwrap() + "\n"
}
