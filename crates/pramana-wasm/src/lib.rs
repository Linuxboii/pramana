//! # pramana-wasm — the in-browser holder wallet core (`pramana-wallet`, §8.1)
//!
//! The *identical* `pramana-core` proving code, compiled to WebAssembly, so proofs are
//! generated on the holder's device and the witness `(D, r)` never leaves it.
//!
//! All functions take and return JSON strings. Errors are thrown as a JSON string
//! `{"code": "...", "message": "...", ...}`.

use pramana_core::adversary::{cheat_prove, CheatStrategy};
use pramana_core::rng::HashDrbg;
use pramana_core::simulator::{self, InteractiveTranscript};
use pramana_core::{
    age, wire, AgeProof, Credential, IssuerPublicKey, Params, ProveError, Statement,
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::json;

fn fail(code: &str, message: impl std::fmt::Display) -> String {
    json!({ "code": code, "message": message.to_string() }).to_string()
}

fn parse<T: serde::de::DeserializeOwned>(what: &str, s: &str) -> Result<T, String> {
    wire::from_json(s).map_err(|e| fail("malformed", format!("{what}: {e}")))
}

fn out<T: Serialize>(v: &T) -> String {
    wire::to_json(v)
}

fn fresh_rng() -> HashDrbg {
    let mut seed = [0u8; 64];
    OsRng.fill_bytes(&mut seed);
    HashDrbg::from_seed_material(&seed)
}

fn hex32(what: &str, s: &str) -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut b)
        .map_err(|e| fail("malformed", format!("{what}: {e}")))?;
    Ok(b)
}

/// Protocol suite and public parameters.
pub fn params_info() -> String {
    let p = Params::new();
    json!({
        "suite": pramana_core::SUITE,
        "params_id": pramana_core::params::PARAMS_ID,
        "G": hex::encode(p.g.compress().as_bytes()),
        "H": hex::encode(p.h.compress().as_bytes()),
        "H_seed": "pramana/H/v1",
        "n_bits": p.n_bits,
    })
    .to_string()
}

/// Validate an imported credential (version, opening, issuer signature). Returns
/// the wallet-only summary — including the birthdate, which is shown to the holder
/// and never sent anywhere.
pub fn credential_check(credential_json: &str) -> Result<String, String> {
    let p = Params::new();
    let c = Credential::from_json_checked(&p, credential_json)
        .map_err(|e| fail("invalid_credential", e))?;
    Ok(json!({
        "ok": true,
        "issuer_name": c.issuer_name,
        "issuer_pk": hex::encode(c.issuer_pk),
        "birthdate": c.birthdate().to_string(),
        "issued_at": c.issued_at,
        "c_d": hex::encode(c.c_d),
    })
    .to_string())
}

/// §9.2 — build an age proof for a verifier's statement.
pub fn prove(credential_json: &str, statement_json: &str) -> Result<String, String> {
    let p = Params::new();
    let cred: Credential = parse("credential", credential_json)?;
    let st: Statement = parse("statement", statement_json)?;
    match age::prove_age(&p, &cred, &st) {
        Ok(pf) => Ok(out(&pf)),
        Err(ProveError::Underage { days_short }) => Err(json!({
            "code": "underage",
            "days_short": days_short,
            "message": ProveError::Underage { days_short }.to_string(),
        })
        .to_string()),
        Err(e) => Err(fail("prove_failed", e)),
    }
}

/// §17 ②③ — build a *cheating* proof (for the demonstration only).
/// `strategy` ∈ `wrap_around | fake_digit | swap_commitment | rogue_issuer | tamper_bytes`.
pub fn cheat(
    credential_json: &str,
    statement_json: &str,
    strategy: &str,
) -> Result<String, String> {
    let p = Params::new();
    let cred: Credential = parse("credential", credential_json)?;
    let st: Statement = parse("statement", statement_json)?;
    let s: CheatStrategy = serde_json::from_value(serde_json::Value::String(strategy.into()))
        .map_err(|_| fail("bad_strategy", format!("unknown strategy {strategy}")))?;
    let pf =
        cheat_prove(&p, &cred, &st, s, &mut fresh_rng()).map_err(|e| fail("cheat_failed", e))?;
    Ok(out(&pf))
}

/// Verify locally (the same code the server runs).
pub fn verify_local(
    proof_json: &str,
    statement_json: &str,
    trusted_json: &str,
    now: f64,
) -> Result<String, String> {
    let p = Params::new();
    let pf: AgeProof = parse("proof", proof_json)?;
    let st: Statement = parse("statement", statement_json)?;
    let trusted: Vec<IssuerPublicKey> = parse("trusted issuers", trusted_json)?;
    Ok(match age::verify_age(&p, &pf, &st, &trusted, now as u64) {
        Ok(v) => json!({ "ok": true, "issuer": v.issuer }).to_string(),
        Err(e) => json!({ "ok": false, "reason": e.code(), "detail": e.to_string() }).to_string(),
    })
}

/// §17 ⑤ transcript inspector: every derived value and every individual check.
pub fn inspect(proof_json: &str, statement_json: &str) -> Result<String, String> {
    let pf: AgeProof = parse("proof", proof_json)?;
    let st: Statement = parse("statement", statement_json)?;
    Ok(out(&age::inspect(&Params::new(), &pf, &st)))
}

/// Encode a proof as CBOR (hex) — the compact wire format.
pub fn proof_to_cbor_hex(proof_json: &str) -> Result<String, String> {
    let pf: AgeProof = parse("proof", proof_json)?;
    Ok(hex::encode(wire::to_cbor(&pf)))
}

/// §7.3 simulator: an accepting transcript from public data only (no witness).
pub fn simulate(c_d_hex: &str, statement_json: &str) -> Result<String, String> {
    let p = Params::new();
    let c_d = hex32("c_d", c_d_hex)?;
    let st: Statement = parse("statement", statement_json)?;
    let tr =
        simulator::simulate_age(&p, &c_d, &st, &mut fresh_rng()).map_err(|e| fail(e.code(), e))?;
    Ok(out(&tr))
}

/// A real interactive transcript (honest prover, random verifier challenge).
pub fn real_interactive(credential_json: &str, statement_json: &str) -> Result<String, String> {
    let p = Params::new();
    let cred: Credential = parse("credential", credential_json)?;
    let st: Statement = parse("statement", statement_json)?;
    let tr = simulator::real_interactive_age(&p, &cred, &st, &mut fresh_rng())
        .map_err(|e| fail("prove_failed", e))?;
    Ok(out(&tr))
}

/// Check an interactive transcript (real or simulated) with the verifier equations.
pub fn check_interactive(
    c_d_hex: &str,
    statement_json: &str,
    transcript_json: &str,
) -> Result<String, String> {
    let p = Params::new();
    let c_d = hex32("c_d", c_d_hex)?;
    let st: Statement = parse("statement", statement_json)?;
    let tr: InteractiveTranscript = parse("transcript", transcript_json)?;
    Ok(match simulator::check_interactive(&p, &c_d, &st, &tr) {
        Ok(()) => json!({ "ok": true }).to_string(),
        Err(e) => json!({ "ok": false, "reason": e.code(), "detail": e.to_string() }).to_string(),
    })
}

/// Byte samples from `count` real and `count` simulated transcripts, plus χ² stats.
pub fn zk_samples(
    credential_json: &str,
    statement_json: &str,
    count: u32,
) -> Result<String, String> {
    let p = Params::new();
    let cred: Credential = parse("credential", credential_json)?;
    let st: Statement = parse("statement", statement_json)?;
    let s =
        simulator::sample_distributions(&p, &cred, &st, count.min(400) as usize, &mut fresh_rng())
            .map_err(|e| fail("prove_failed", e))?;
    Ok(json!({
        "real": s.real,
        "simulated": s.simulated,
        "transcripts": s.transcripts,
        "chi2_real": simulator::chi_square_uniform(&s.real),
        "chi2_simulated": simulator::chi_square_uniform(&s.simulated),
    })
    .to_string())
}

/// wasm-bindgen exports: thin wrappers that throw the JSON error string.
mod exports {
    use wasm_bindgen::prelude::*;
    macro_rules! export {
        ($name:ident ( $($a:ident : $t:ty),* )) => {
            #[wasm_bindgen]
            pub fn $name($($a: $t),*) -> Result<String, JsValue> {
                super::$name($($a),*).map_err(|e| JsValue::from_str(&e))
            }
        };
    }
    #[wasm_bindgen(js_name = params_info)]
    pub fn params_info_js() -> String {
        super::params_info()
    }
    export!(credential_check(credential_json: &str));
    export!(prove(credential_json: &str, statement_json: &str));
    export!(cheat(credential_json: &str, statement_json: &str, strategy: &str));
    export!(verify_local(proof_json: &str, statement_json: &str, trusted_json: &str, now: f64));
    export!(inspect(proof_json: &str, statement_json: &str));
    export!(proof_to_cbor_hex(proof_json: &str));
    export!(simulate(c_d_hex: &str, statement_json: &str));
    export!(real_interactive(credential_json: &str, statement_json: &str));
    export!(check_interactive(c_d_hex: &str, statement_json: &str, transcript_json: &str));
    export!(zk_samples(credential_json: &str, statement_json: &str, count: u32));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pramana_core::{Date, IssuerKey};

    #[test]
    fn native_roundtrip_of_exports() {
        let p = Params::new();
        let k = IssuerKey::from_secret("Demo Authority", &[9; 32]);
        let mut rng = HashDrbg::from_seed_material(b"wasm");
        let today = Date::parse("2026-11-19").unwrap();
        let cred = k
            .issue(&p, Date::parse("2001-04-12").unwrap(), today, 0, &mut rng)
            .unwrap();
        let st = Statement::new(18, today, [1; 32], "example-shop.com", 100, 120);
        let (cj, sj) = (wire::to_json(&cred), wire::to_json(&st));
        assert!(credential_check(&cj).unwrap().contains("2001-04-12"));
        let pf = prove(&cj, &sj).unwrap();
        let trusted = wire::to_json(&vec![k.public()]);
        assert!(verify_local(&pf, &sj, &trusted, 101.0)
            .unwrap()
            .contains("\"ok\":true"));
        assert!(inspect(&pf, &sj).unwrap().contains("bits_ok"));
        let sim = simulate(&hex::encode(cred.c_d), &sj).unwrap();
        assert!(check_interactive(&hex::encode(cred.c_d), &sj, &sim)
            .unwrap()
            .contains("true"));
        let teen = k
            .issue(&p, Date::parse("2012-06-01").unwrap(), today, 0, &mut rng)
            .unwrap();
        let tj = wire::to_json(&teen);
        assert!(prove(&tj, &sj).unwrap_err().contains("underage"));
        for s in [
            "wrap_around",
            "fake_digit",
            "swap_commitment",
            "rogue_issuer",
            "tamper_bytes",
        ] {
            let who = if s == "tamper_bytes" { &cj } else { &tj };
            let bad = cheat(who, &sj, s).unwrap();
            assert!(
                verify_local(&bad, &sj, &trusted, 101.0)
                    .unwrap()
                    .contains("\"ok\":false"),
                "{s}"
            );
        }
    }
}
