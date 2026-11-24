//! §16 Known-answer tests: fixed DRBG seeds → fixed proof bytes. Guards against any
//! accidental protocol change. If you *intend* to change the protocol, bump the
//! version and regenerate:
//! `cargo run -p pramana-core --example gen_vectors > test-vectors/v1.json`

#[allow(dead_code)]
#[path = "../examples/gen_vectors.rs"]
mod gen_vectors;

use pramana_core::{verify_age, AgeProof, IssuerPublicKey, Params, Statement};

const VECTORS: &str = include_str!("../../../test-vectors/v1.json");

#[test]
fn vectors_are_reproducible() {
    let regenerated = gen_vectors::generate();
    assert!(
        regenerated.replace("\r\n", "\n") == VECTORS.replace("\r\n", "\n"),
        "test-vectors/v1.json is stale or the protocol changed; regenerate deliberately"
    );
}

#[test]
fn accept_vectors_verify_and_reject_vectors_have_no_proof() {
    let p = Params::new();
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(doc["params"]["H"], hex::encode(p.h.compress().as_bytes()));
    let mut pk = [0u8; 32];
    hex::decode_to_slice(doc["issuer"]["public_key"].as_str().unwrap(), &mut pk).unwrap();
    let trust = [IssuerPublicKey {
        name: "Demo Authority".into(),
        public_key: pk,
    }];
    for v in doc["vectors"].as_array().unwrap() {
        let st: Statement = serde_json::from_value(v["statement"].clone()).unwrap();
        if v["expect"] == "accept" {
            let pf: AgeProof = serde_json::from_value(v["proof"].clone()).unwrap();
            verify_age(&p, &pf, &st, &trust, st.issued_at)
                .unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
        } else {
            assert!(v["proof"].is_null());
            assert!(v["expect"]
                .as_str()
                .unwrap()
                .contains("under the age threshold"));
        }
    }
}
