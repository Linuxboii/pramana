//! HTTP-level tests for the verifier: honest path, single-use nonces, replay to a
//! second verifier, expiry, CBOR, malformed input, audit-log contents.

use super::*;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use pramana_core::rng::HashDrbg;
use pramana_core::{prove_age, Credential, IssuerKey};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

struct Fixture {
    clock: Arc<AtomicU64>,
    shop: Arc<Sakshi>,
    other: Arc<Sakshi>,
    adult: Credential,
    teen: Credential,
}

fn fixture() -> Fixture {
    let p = Params::new();
    let key = IssuerKey::from_secret("Demo Authority", &[5u8; 32]);
    let clock = Arc::new(AtomicU64::new(1_795_000_000));
    let c1 = clock.clone();
    let c2 = clock.clone();
    let shop = Arc::new(Sakshi::with_clock(
        VerifierConfig::new("example-shop.com", vec![key.public()]),
        Arc::new(move || c1.load(Ordering::SeqCst)),
    ));
    let other = Arc::new(Sakshi::with_clock(
        VerifierConfig::new("other-site.example", vec![key.public()]),
        Arc::new(move || c2.load(Ordering::SeqCst)),
    ));
    let today = Date::from_unix_seconds(1_795_000_000);
    let mut rng = HashDrbg::from_seed_material(b"sakshi-tests");
    let adult = key
        .issue(&p, Date::parse("2001-04-12").unwrap(), today, 0, &mut rng)
        .unwrap();
    let teen = key
        .issue(&p, Date::parse("2012-04-12").unwrap(), today, 0, &mut rng)
        .unwrap();
    Fixture {
        clock,
        shop,
        other,
        adult,
        teen,
    }
}

async fn post(app: Router, uri: &str, ct: &str, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", ct)
        .body(Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn get_json(app: Router, uri: &str) -> serde_json::Value {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    serde_json::from_slice(&res.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

async fn get_challenge(s: &Arc<Sakshi>, threshold: u8) -> Statement {
    let (status, v) = post(
        router(s.clone()),
        "/challenge",
        "application/json",
        format!("{{\"threshold_years\":{threshold}}}").into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_value(v["statement"].clone()).unwrap()
}

async fn submit(s: &Arc<Sakshi>, proof: &AgeProof) -> VerifyResponse {
    let body = serde_json::to_vec(&serde_json::json!({ "proof": proof })).unwrap();
    let (status, v) = post(router(s.clone()), "/verify", "application/json", body).await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_value(v).unwrap()
}

#[tokio::test]
async fn honest_path_then_single_use() {
    let f = fixture();
    let st = get_challenge(&f.shop, 18).await;
    assert_eq!(st.verifier_id, "example-shop.com");
    let pf = prove_age(&Params::new(), &f.adult, &st).unwrap();
    let r = submit(&f.shop, &pf).await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.issuer.unwrap().name, "Demo Authority");
    // Same proof again at the same verifier: nonce consumed.
    let r2 = submit(&f.shop, &pf).await;
    assert_eq!(r2.reason.as_deref(), Some("challenge_already_used"));
}

#[tokio::test]
async fn replay_to_second_verifier() {
    let f = fixture();
    let st = get_challenge(&f.shop, 18).await;
    let pf = prove_age(&Params::new(), &f.adult, &st).unwrap();
    // Straight replay: B never issued this nonce.
    assert_eq!(
        submit(&f.other, &pf).await.reason.as_deref(),
        Some("unknown_challenge")
    );
    // Relabelled replay: attacker answers B's real nonce with A's proof.
    let st_b = get_challenge(&f.other, 18).await;
    let mut relabelled = pf.clone();
    relabelled.nonce = st_b.nonce;
    assert_eq!(
        submit(&f.other, &relabelled).await.reason.as_deref(),
        Some("fiat_shamir_check_failed")
    );
    // The original is still good at A.
    assert!(submit(&f.shop, &pf).await.ok);
}

#[tokio::test]
async fn expiry() {
    let f = fixture();
    let st = get_challenge(&f.shop, 21).await;
    let pf = prove_age(&Params::new(), &f.adult, &st).unwrap();
    f.clock.fetch_add(121, Ordering::SeqCst);
    assert_eq!(
        submit(&f.shop, &pf).await.reason.as_deref(),
        Some("expired")
    );
}

#[tokio::test]
async fn teen_cannot_prove_and_cheats_fail() {
    use pramana_core::adversary::{cheat_prove, CheatStrategy};
    let f = fixture();
    let st = get_challenge(&f.shop, 18).await;
    assert!(prove_age(&Params::new(), &f.teen, &st).is_err());
    let mut rng = HashDrbg::from_seed_material(b"cheat");
    let pf = cheat_prove(
        &Params::new(),
        &f.teen,
        &st,
        CheatStrategy::WrapAround,
        &mut rng,
    )
    .unwrap();
    let r = submit(&f.shop, &pf).await;
    assert!(!r.ok);
    assert_eq!(r.reason.as_deref(), Some("consistency_failed"));
    // Teen CAN prove ≥ 13.
    let st13 = get_challenge(&f.shop, 13).await;
    let pf13 = prove_age(&Params::new(), &f.teen, &st13).unwrap();
    assert!(submit(&f.shop, &pf13).await.ok);
}

#[tokio::test]
async fn cbor_wire_format_accepted() {
    let f = fixture();
    let st = get_challenge(&f.shop, 16).await;
    let pf = prove_age(&Params::new(), &f.adult, &st).unwrap();
    let (status, v) = post(
        router(f.shop.clone()),
        "/verify",
        "application/cbor",
        pramana_core::wire::to_cbor(&pf),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["ok"], true);
}

#[tokio::test]
async fn malformed_and_bad_threshold() {
    let f = fixture();
    let (_, v) = post(
        router(f.shop.clone()),
        "/verify",
        "application/json",
        b"{\"proof\":42}".to_vec(),
    )
    .await;
    assert_eq!(v["ok"], false);
    assert_eq!(v["reason"], "malformed");
    let (status, v) = post(
        router(f.shop.clone()),
        "/challenge",
        "application/json",
        b"{\"threshold_years\":17}".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], "bad_threshold");
    let (status, _) = post(
        router(f.shop.clone()),
        "/verify",
        "application/json",
        vec![b'x'; MAX_BODY_BYTES + 1],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn audit_log_holds_no_pii() {
    let f = fixture();
    let st = get_challenge(&f.shop, 18).await;
    let pf = prove_age(&Params::new(), &f.adult, &st).unwrap();
    submit(&f.shop, &pf).await;
    let v = get_json(router(f.shop.clone()), "/audit").await;
    let entries = v["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let mut keys: Vec<_> = entries[0].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["issuer_pk", "reason", "result", "timestamp"]);
    let text = v.to_string();
    assert!(!text.contains("2001"));
    assert!(!text.contains(&hex::encode(pf.c_d)));
    let issuers = get_json(router(f.shop.clone()), "/issuers").await;
    assert_eq!(issuers[0]["name"], "Demo Authority");
}

#[test]
fn trust_list_parsing() {
    let l = parse_trust_list(&format!(
        "Demo Authority={},{}",
        "11".repeat(32),
        "22".repeat(32)
    ))
    .unwrap();
    assert_eq!(l.len(), 2);
    assert_eq!(l[0].name, "Demo Authority");
    assert_eq!(l[1].name, "Issuer 2");
    assert!(parse_trust_list("x=zz").is_err());
}
