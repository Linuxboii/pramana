# API reference

## Verifier HTTP API — Sākṣī [PRD §14.2]

Served by `pramana-sakshi` at the root, and by `pramana-demo` under `/api/shop` (verifier `example-shop.com`) and `/api/other` (verifier `other-site.example`). All bodies are JSON unless noted. Errors use `{"code": "...", "error": "..."}`.

### `POST /challenge`

Request (optional body): `{"threshold_years": 18}` — one of 13, 16, 18, 21; default 18.

Response `200`:

```json
{
  "statement": {
    "v": 1, "threshold_years": 18, "today": "2026-11-24",
    "nonce": "9e18a4677eea6372…", "verifier_id": "example-shop.com",
    "issued_at": 1795564800, "expires_at": 1795564920
  },
  "nonce": "9e18a4677eea6372…",
  "verifier_id": "example-shop.com",
  "expires_at": 1795564920
}
```

Errors: `400 bad_threshold`, `503 busy` (too many outstanding challenges).

### `POST /verify`

Request: `{"proof": AgeProof}` with `Content-Type: application/json`, **or** the CBOR-encoded `AgeProof` with `Content-Type: application/cbor`. Max body 64 KiB.

Response `200` (always 200 when the request is well-formed HTTP; the verdict is in the body):

```json
{ "ok": true, "issuer": { "name": "Demo Authority", "public_key": "509f…" },
  "checked_at": 1795564803, "threshold_years": 18, "reason": null, "detail": null }
```

```json
{ "ok": false, "issuer": null, "checked_at": 1795564803, "threshold_years": null,
  "reason": "fiat_shamir_check_failed",
  "detail": "bit 0: OR-proof fails under the recomputed Fiat–Shamir challenge (§7.4/§7.7)" }
```

Rejection codes: `malformed`, `unsupported_version`, `nonce_mismatch`, `invalid_statement`, `untrusted_issuer`, `bad_signature`, `not_yet_valid`, `expired`, `wrong_bit_count`, `consistency_failed`, `fiat_shamir_check_failed`, `unknown_challenge`, `challenge_already_used`. The verifier checks the proof against **its own** stored statement for the nonce; the nonce is consumed on first use.

### `GET /issuers`

The trust list: `[{"name": "Demo Authority", "public_key": "<hex>"}]`.

### `GET /audit`

`{"verifier_id": "...", "note": "...", "entries": [{"timestamp": 1795564803, "issuer_pk": "<hex>", "result": true, "reason": null}]}` — the only artefact the verifier retains (newest last, last 200).

### `GET /health`

`{"ok": true, "verifier_id": "...", "suite": "..."}`

## Issuer HTTP API — Pramātā (demo only)

Served by `pramana-issuer serve` at the root and by `pramana-demo` under `/api/issuer`.

* `GET /info` → `{"name", "public_key", "suite", "params", "demo": true}`
* `POST /issue` with `{"dob": "YYYY-MM-DD"}` → a `Credential` (see below). `422 invalid_birthdate` for impossible, future or pre-1900 dates; `400 bad_request` for a missing body.

## Demo server extras

* `GET /api/config` → issuer, verifier ids and base paths, trust list, challenge TTL, allowed thresholds.
* `GET /api/health` → `{"ok": true}`.
* Everything else serves the web app (SPA fallback to `index.html`).

## Wire objects

### Credential (wallet only — contains the witness)

```json
{ "v": 1, "kind": "pramana-age-credential",
  "params": "pramana/params/v1:ristretto255:H=HashToGroup(pramana/H/v1):n=16",
  "issuer_name": "Demo Authority", "issuer_pk": "<32B hex>",
  "c_d": "<32B hex>", "sig": "<64B hex>",
  "d": 37356, "r": "<32B hex>", "issued_at": 1795564800 }
```

### AgeProof (what the verifier receives)

```json
{ "v": 1, "issuer_pk": "<32B>", "c_d": "<32B>", "sig": "<64B>", "nonce": "<32B>",
  "bits": [ { "c": "<32B>", "t0": "<32B>", "t1": "<32B>", "e0": "<32B>", "z0": "<32B>", "z1": "<32B>" } ] }
```

Exactly 16 entries in `bits`. See [PROTOCOL.md](PROTOCOL.md) for semantics.

## CLI [PRD §14.3]

```text
pramana-issuer keygen --out issuer.key [--name "Demo Authority"] [--force]
pramana-issuer issue  --dob 2001-04-12 --key issuer.key [--out aarav.cred]
pramana-issuer pubkey --key issuer.key
pramana-issuer serve  --key issuer.key [--addr 127.0.0.1:8081] [--cors-origins …]

pramana-sakshi --trusted-issuers "Name=<hex>,…" [--verifier-id example-shop.com]
               [--addr 127.0.0.1:8082] [--ttl-secs 120] [--cors-origins …]

pramana-demo   [--addr 0.0.0.0:8080] [--web-dir web/dist] [--issuer-key …]
               [--issuer-key-file …] [--shop-id …] [--other-id …] [--ttl-secs 120]
               [--extra-trusted "Name=<hex>,…"] [--cors-origins …] [--healthcheck]
```

Every flag also reads an environment variable; see [DEPLOYMENT.md](DEPLOYMENT.md).

## Rust library [PRD §14.1]

```rust
use pramana_core::{prove_age, verify_age, Credential, Date, IssuerKey, Params, Statement};

let p = Params::new();
let issuer = IssuerKey::generate("Demo Authority", &mut rand_core::OsRng);
let cred = issuer.issue(&p, Date::parse("2001-04-12")?, Date::parse("2026-11-19")?, now, &mut rand_core::OsRng)?;
let st = Statement::new(18, Date::parse("2026-11-19")?, nonce, "example-shop.com", now, 120);
let proof = prove_age(&p, &cred, &st)?;                       // Err(Underage) for a minor
let ok = verify_age(&p, &proof, &st, &[issuer.public()], now)?; // Verified { issuer }
```

Other modules: `pedersen`, `schnorr` (prove/verify/simulate/extract), `range` (commit phase / respond / verify), `simulator` (HVZK transcripts, distribution sampling), `adversary` (cheating provers), `wire` (JSON/CBOR, strict decoding), `rng` (hedged DRBG).

## WebAssembly wallet API

`web/src/wasm/pramana.js` (generated from `crates/pramana-wasm`). Every function takes and returns JSON strings; errors are thrown as a JSON string `{"code", "message", …}`. The typed wrapper is `web/src/lib/wallet.ts`.

| Function | Purpose |
|---|---|
| `params_info()` | suite, G, H, n |
| `credential_check(cred)` | import validation; returns the wallet-only summary (incl. birthdate) |
| `prove(cred, statement)` | build a proof; throws `{"code": "underage", "days_short"}` for a minor |
| `cheat(cred, statement, strategy)` | demo cheating provers: `wrap_around`, `fake_digit`, `swap_commitment`, `rogue_issuer`, `tamper_bytes` |
| `verify_local(proof, statement, trusted, now)` | the verifier, in the browser |
| `inspect(proof, statement)` | per-check breakdown (D*, C_Δ, e, consistency, per-bit) |
| `proof_to_cbor_hex(proof)` | compact encoding |
| `simulate(c_d, statement)` / `real_interactive(cred, statement)` / `check_interactive(c_d, statement, transcript)` | the X-ray |
| `zk_samples(cred, statement, count)` | byte samples and χ² statistics for real vs simulated transcripts |
