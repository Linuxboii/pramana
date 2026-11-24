//! NFR timing: prove < 150 ms, verify < 30 ms for n = 16.
//! Run with `cargo bench -p pramana-core`.

use criterion::{criterion_group, criterion_main, Criterion};
use pramana_core::rng::HashDrbg;
use pramana_core::{prove_age, verify_age, Date, IssuerKey, Params, Statement};

fn bench(c: &mut Criterion) {
    let p = Params::new();
    let mut rng = HashDrbg::from_seed_material(b"bench");
    let k = IssuerKey::generate("Demo Authority", &mut rng);
    let today = Date::parse("2026-11-19").unwrap();
    let cred = k
        .issue(&p, Date::parse("2001-04-12").unwrap(), today, 0, &mut rng)
        .unwrap();
    let st = Statement::new(18, today, [9u8; 32], "example-shop.com", 0, 300);
    let trust = [k.public()];
    c.bench_function("prove_age n=16", |b| {
        b.iter(|| prove_age(&p, &cred, &st).unwrap())
    });
    let pf = prove_age(&p, &cred, &st).unwrap();
    c.bench_function("verify_age n=16", |b| {
        b.iter(|| verify_age(&p, &pf, &st, &trust, 1).unwrap())
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
