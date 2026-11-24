# प्रमाण Pramāṇa

**Prove you are old enough — reveal nothing more.**

Pramāṇa is a zero-knowledge age-verification protocol (codename *Gūḍhapramāṇa*, गूढप्रमाण, "concealed proof") and a complete reference implementation. Someone holding a birthdate signed by a trusted issuer generates a ~3 KB proof that their age meets a threshold (13, 16, 18 or 21). The website checks it in milliseconds and learns one bit — never the birthdate, never the name.

It is built from scratch on audited primitives: Pedersen commitments over **Ristretto255**, Schnorr and Chaum–Pedersen OR **Σ-protocols**, a bit-decomposition **range proof**, and a **strong Fiat–Shamir** transform that binds the whole statement plus the verifier's nonce and identity. No curve arithmetic is hand-rolled in the product.

> **Status:** complete per the PRD's MUST and SHOULD requirements (FR-1 … FR-10), with tests for every layer in PRD §16. The issuer is a mock authority with a self-generated key; this is a portfolio-grade reference implementation, not a certified identity product. See [Security](docs/SECURITY.md) for exactly what is and isn't claimed.

---

## What's in the box

| Component | Path | What it does |
|---|---|---|
| `pramana-core` | [`crates/pramana-core`](crates/pramana-core) | The protocol (PRD §7): commitments, Schnorr PoK, OR-proofs, range proof, age reduction, Fiat–Shamir transcript, credentials, HVZK simulator, cheating provers for the demo. Pure, deterministic given explicit randomness. |
| `pramana-issuer` | [`crates/pramana-issuer`](crates/pramana-issuer) | *Pramātā*, the mock issuing authority: CLI (`keygen`, `issue`, `pubkey`, `serve`) and HTTP service. |
| `pramana-sakshi` | [`crates/pramana-sakshi`](crates/pramana-sakshi) | *Sākṣī*, the verifier service: `POST /challenge`, `POST /verify`, `GET /issuers`, `GET /audit`. Single-use nonces, no PII stored. |
| `pramana-wasm` | [`crates/pramana-wasm`](crates/pramana-wasm) | The holder wallet: the identical core compiled to WebAssembly so proofs are made in the browser. |
| `pramana-demo` | [`crates/pramana-demo`](crates/pramana-demo) | One deployable server: demo issuer + two independent verifiers + the web app. |
| Web app | [`web/`](web) | Vite + React + TypeScript + Tailwind: wallet, relying-party shop, the five-act demonstration (PRD §17). |
| Python reference | [`python/pramana_ref.py`](python/pramana_ref.py) | Annotated, standard-library teaching implementation (incl. RFC 9496 Ristretto255) that reproduces the Rust proofs **byte for byte**. |
| Test vectors | [`test-vectors/v1.json`](test-vectors/v1.json) | Known-answer vectors shared by both implementations. |

## Quick start

### With Docker (one command)

```sh
docker compose up --build
# open http://localhost:8080
```

### From source

Requirements: Rust (stable) with the `wasm32-unknown-unknown` target, `wasm-pack` (or `wasm-bindgen-cli`), Node 20+.

```sh
# 1. Build the wallet WebAssembly into web/src/wasm
./scripts/build-wasm.sh            # or: cd web && npm run wasm

# 2. Build the web app
cd web && npm ci && npm run build && cd ..

# 3. Run everything on :8080
cargo run --release -p pramana-demo
```

For UI development with hot reload, keep the server running and in another terminal run `cd web && npm run dev` (Vite on :5173 proxies `/api` to :8080).

### The command-line tools (PRD §14.3)

```sh
cargo run -p pramana-issuer -- keygen --out issuer.key
cargo run -p pramana-issuer -- issue --dob 2001-04-12 --key issuer.key --out aarav.cred
cargo run -p pramana-issuer -- pubkey --key issuer.key

# A standalone verifier trusting that issuer
PRAMANA_TRUSTED_ISSUERS="Demo Authority=<public key hex>" cargo run -p pramana-sakshi
```

## Using the demo

The page has three parts:

1. **Try it** — a wallet (left) and an online wine shop (right). Request a credential from the demo authority, then click *Prove your age privately*. The consent screen states exactly what the shop will learn; the receipt shows the proof it received and checks that your birthdate, its day count and your secret randomness are all absent from it. Switch the shop's age rule between 13+, 16+, 18+ and 21+. A 14-year-old's wallet cannot build an 18+ proof at all.
2. **The demonstration** — the five acts of PRD §17, each run live against the real verifiers:
   1. *The honest path* — completeness and zero-knowledge.
   2. *The cheat* — a 14-year-old's honest wallet has no solution; two purpose-built cheating provers are rejected (soundness).
   3. *The forgery attempt* — flipped bytes, a swapped unsigned commitment and a rogue issuer are rejected; you can also hand-edit a proof (binding).
   4. *The replay* — a captured proof fails at a second verifier, fails when relabelled with that verifier's nonce, and fails when reused (non-transferability).
   5. *The X-ray* — a real transcript and a simulated one made **without the birthdate** side by side, both passing every check; guess which is real, then see their byte distributions overlap.
3. **How it works** — the four ideas behind the proof, with PRD section references.

The page opens with the PRD's "money shot": everything the website learns (a boolean and an issuer) beside everything an ID upload would have surrendered.

## How it works in one screen

```text
Issuance (once)      D = days since 1900-01-01 of the birthdate
                     C_D = D·G + r·H            ← Pedersen commitment, H = HashToGroup("pramana/H/v1")
                     sig = Ed25519(issuer, "pramana/credential-sig/v1" ‖ C_D)

Statement (per site) threshold, today, nonce (256-bit), verifier_id, validity window
                     D* = days(today − threshold years)       ← public
                     C_Δ = D*·G − C_D = Δ·G + (−r)·H          ← verifier derives it itself

Proof                16 bit commitments Cᵢ with Σ 2ⁱ·Cᵢ = C_Δ, each with a CDS OR-proof that it hides 0 or 1
                     e = SHA-512 transcript of (suite, G, H, n, issuer_pk, C_D, sig, threshold, today,
                         D*, C_Δ, verifier_id, nonce, window, every Cᵢ/T₀ᵢ/T₁ᵢ)

Verify               trusted issuer? signature? in window? Σ 2ⁱ·Cᵢ == C_Δ? every OR-proof holds under e?
```

An under-age holder has Δ < 0, which has no 16-bit decomposition, so no proof exists. The full specification, with encodings, is in **[docs/PROTOCOL.md](docs/PROTOCOL.md)**.

## Testing

```sh
cargo test --workspace                                           # 67 tests: unit, property, negative, ZK, replay, fuzz, KAT, HTTP
python python/pramana_ref.py --check-vectors test-vectors/v1.json  # independent re-implementation, byte-for-byte
cargo bench -p pramana-core                                      # NFR timings
cd web && node e2e/e2e.mjs                                       # browser end-to-end against a running server (19 checks)
```

| PRD §16 layer | Where |
|---|---|
| Unit — algebra | module tests in `pramana-core/src/*` (homomorphism, Schnorr completeness, extractor, transcript framing) |
| Property-based | `tests/protocol.rs::verifies_iff_old_enough` — random (D, threshold, today): verifies ⇔ truly old enough |
| Soundness (negative) | `tests/protocol.rs`, `adversary.rs` — under-age, wrap-around, fake digit, swapped commitment, rogue issuer, tampered bits/sig, truncated proofs |
| Zero-knowledge | `tests/protocol.rs` — χ² uniformity of real and simulated transcripts and a two-sample homogeneity test |
| Replay | `tests/protocol.rs`, `pramana-sakshi` tests — other verifier, relabelled nonce, reuse, expiry |
| Known-answer tests | `tests/kat.rs` + `test-vectors/v1.json` |
| Fuzzing | `tests/protocol.rs` — arbitrary bytes into every decoder, single-byte mutations of valid proofs |
| Cross-impl | `python/pramana_ref.py --check-vectors` |

Measured on a laptop (Windows, x86-64): prove **12 ms** native / **≈40 ms** in-browser WASM; verify **8 ms** (NFR: < 150 ms / < 30 ms). Proof size: **3,754 bytes** CBOR, 7,308 bytes JSON.

## Deploying

The Docker image is self-contained (≈ 134 MB, runs as non-root, built-in healthcheck). It works on any container host; ready-made configs are included for **Render** (`render.yaml`), **Fly.io** (`fly.toml`) and **Docker Compose**. Set `PRAMANA_ISSUER_KEY` (or mount `/data`) so the demo issuer key — and therefore issued credentials — survive restarts. Everything is in **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

## Documentation

| Document | Contents |
|---|---|
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | The protocol specification: parameters, encodings, transcript, proving and verification algorithms |
| [docs/SECURITY.md](docs/SECURITY.md) | Security claims and assumptions, threat model T1–T10 with mitigations, known limits |
| [docs/API.md](docs/API.md) | HTTP API, wire formats, CLI and WASM API reference |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Configuration, Docker, Render, Fly.io, standalone services, operations |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | Traceability from every PRD goal and requirement to code and tests |

## Repository layout

```text
crates/
  pramana-core/      protocol library (+ tests/, benches/, examples/gen_vectors.rs)
  pramana-issuer/    mock issuer: library, CLI, HTTP
  pramana-sakshi/    verifier: library, HTTP, standalone binary
  pramana-wasm/      wallet core → WebAssembly
  pramana-demo/      all-in-one deployable server
web/                 React app (src/), browser E2E test (e2e/)
python/              teaching reference implementation
test-vectors/        known-answer vectors
docs/                specification and operations docs
scripts/             build helpers
```

## The name

In Nyāya epistemology a *pramāṇa* is a valid means of knowledge. A zero-knowledge proof is a pramāṇa that grants knowledge by inference while withholding *pratyakṣa* — direct perception. The verifier comes to **know** you are old enough without ever **seeing** the date beneath it. The verifier service is *Sākṣī* (साक्षी), "the witness"; the issuer is *Pramātā*, the knower.

## License

MIT — see [LICENSE](LICENSE).
