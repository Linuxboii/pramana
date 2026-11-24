# Gūḍhapramāṇa protocol specification (v1)

This document specifies the protocol implemented by `pramana-core` precisely enough to re-implement it; `python/pramana_ref.py` is an independent implementation written from this text and reproduces the Rust proofs byte for byte (`test-vectors/v1.json`). Section numbers in brackets refer to the PRD.

Suite identifier: `gudhapramana/v1/tier-a/ristretto255/sha512`

## 1. Notation and parameters [§7.1]

* Group 𝔾 = **Ristretto255** (RFC 9496), prime order
  `q = 2²⁵² + 27742317777372353535851937790883648493`. Group operations are written additively.
* `G` = the Ristretto basepoint, encoding `e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76`.
* `H = from_uniform_bytes(SHA-512("pramana/H/v1"))` — the RFC 9496 one-way map applied to a nothing-up-my-sleeve seed. Encoding `b255aa2dbb993a572e294de2cef2c285754dd72fd1c4b685572113e10a3af944`. Nobody knows `log_G(H)`; this is the protocol's only setup assumption.
* `n = 16` (range width). Parameter-set id: `pramana/params/v1:ristretto255:H=HashToGroup(pramana/H/v1):n=16`.
* Scalars are integers mod `q`, encoded as 32 bytes little-endian; decoders **reject** values ≥ q.
* Points are 32-byte canonical Ristretto encodings; decoders **reject** non-canonical encodings.
* Random scalars are sampled as 64 uniform bytes reduced mod q (statistical distance ≈ 2⁻²⁵⁹).

## 2. Dates [§7.6]

A date is encoded as `D = days since 1900-01-01` in the proleptic Gregorian calendar (Hinnant's `days_from_civil`). Birthdates before 1900-01-01 or after the issuance date are rejected by the issuer.

`cutoff(today, t)` = the same month and day `t` years earlier; **29 February maps to 28 February** in non-leap years. Consequently a person born on 29 February reaches age `t` on 1 March in non-leap years (vector `leapling-not-yet-21` / `leapling-21-on-mar-1`).

`D* = days(cutoff(today, threshold))`. The holder satisfies the statement iff `D ≤ D*`, i.e. iff `Δ = D* − D ≥ 0`.

## 3. Pedersen commitments [§7.2]

`Com(v, r) = v·G + r·H`. Perfectly hiding, computationally binding (under discrete log), additively homomorphic.

## 4. Issuance [§9.1, §7.8 Tier A]

1. The issuer verifies the birthdate out of band (mocked in the demo).
2. `D ← days(dob)`, `r ← random scalar`, `C_D = Com(D, r)`.
3. `sig = Ed25519.Sign(sk, "pramana/credential-sig/v1" ‖ encode(C_D))` (RFC 8032; verifiers use strict verification).
4. The credential is `{v, kind, params, issuer_name, issuer_pk, c_d, sig, d, r, issued_at}`. `d` and `r` are the witness and never leave the wallet.

## 5. Statement [§9.2 step 1]

Issued by the verifier for every presentation:

| Field | Meaning |
|---|---|
| `v` | 1 |
| `threshold_years` | 1 … 125 (the reference verifier allows 13, 16, 18, 21) |
| `today` | verifier's UTC date, `YYYY-MM-DD` |
| `nonce` | 32 fresh random bytes |
| `verifier_id` | 1 … 255 bytes, no control characters |
| `issued_at`, `expires_at` | Unix seconds; `expires_at > issued_at` |

## 6. Fiat–Shamir transcript [§7.7]

```text
frame(label, data) = u64le(len(label)) ‖ label ‖ u64le(len(data)) ‖ data
state              = SHA-512 running hash of frame("dom-sep", domain) ‖ frame(…) ‖ …
challenge(label)   : state ‖= frame("challenge", label);  e = SHA-512(state) mod q   (64-byte wide reduction)
```

Length-prefixing makes the encoding injective. The age-proof transcript uses domain `pramana/gudhapramana/age/v1` and appends, **in this order**:

| Label | Data |
|---|---|
| `suite` | the suite identifier (ASCII) |
| `G`, `H` | encodings |
| `n_bits` | u64le(16) |
| `issuer_pk` | 32 bytes |
| `C_D` | 32 bytes |
| `sig` | 64 bytes |
| `threshold_years` | u64le |
| `today` | ASCII `YYYY-MM-DD` |
| `D_star` | i64le |
| `C_delta` | encoding of `C_Δ` |
| `verifier_id` | UTF-8 |
| `nonce` | 32 bytes |
| `issued_at`, `expires_at` | u64le each |
| `n` | u64le(number of bits) |
| `C_i`, `T0_i`, `T1_i` | for each bit i = 0 … n−1, in order |

then `e = challenge("e")`.

Binding the statement (`C_D`, `D*`, issuer key) and not only the prover's commitments avoids the weak-Fiat–Shamir ("Frozen Heart") class of bugs; binding `verifier_id`, `nonce` and the validity window makes proofs non-transferable.

## 7. Proving [§9.2]

Input: credential `(C_D, sig, issuer_pk, D, r)`, statement.

1. Check `Com(D, r) = C_D`. Compute `D*` and `Δ = D* − D`. If `Δ < 0` **stop: no proof exists** (under age). If `Δ ≥ 2ⁿ` stop (out of range).
2. `C_Δ = D*·G − C_D` (= `Δ·G + (−r)·H`).
3. Bit blindings: `r₀ … r_{n−2}` random; `r_{n−1} = (−r − Σ_{i<n−1} 2ⁱ·rᵢ) · (2^{n−1})⁻¹`, so that `Σ 2ⁱ·rᵢ = −r`. (Draw order: r₀ … r_{n−2}.)
4. For each bit `i` with `bᵢ = (Δ >> i) & 1` (draw order per bit: `k`, `e_s`, `z_s`):
   * `Cᵢ = bᵢ·G + rᵢ·H`; `Y₀ = Cᵢ`, `Y₁ = Cᵢ − G`.
   * Real branch `j = bᵢ`: `T_j = k·H`.
   * Simulated branch `s = 1 − bᵢ`: `T_s = z_s·H − e_s·Y_s`.
5. Build the transcript (§6) and derive `e`.
6. For each bit: `e_j = e − e_s`, `z_j = k + e_j·rᵢ`; output `e₀`, `z₀`, `z₁` (with `e_s, z_s` in the simulated slot).

Branch selection is done with constant-time conditional selects; both branches are always computed.

The proof object (JSON field order as serialised):

```json
{ "v": 1, "issuer_pk": "<32B>", "c_d": "<32B>", "sig": "<64B>", "nonce": "<32B>",
  "bits": [ { "c": "", "t0": "", "t1": "", "e0": "", "z0": "", "z1": "" }, … 16 … ] }
```

`e₁` is not transmitted; it is `e − e₀`. Size: 16 × 192 B + 160 B ≈ 3.2 KB raw; 3,754 B as CBOR.

## 8. Verification [§9.3]

Accept iff every check passes, in this order (the first failure is reported by code):

| # | Check | Error code |
|---|---|---|
| 1 | `v == 1` | `unsupported_version` |
| 2 | `proof.nonce == statement.nonce` | `nonce_mismatch` |
| 3 | statement well-formed | `invalid_statement` |
| 4 | `issuer_pk` on the trust list | `untrusted_issuer` |
| 5 | strict Ed25519 verify of `sig` over `SIG_DOMAIN ‖ c_d` | `bad_signature` |
| 6 | `now + 60 ≥ issued_at` | `not_yet_valid` |
| 7 | `now ≤ expires_at` | `expired` |
| 8 | canonical decoding of every point/scalar; exactly `n` bits | `malformed`, `wrong_bit_count` |
| 9 | recompute `D*`, `C_Δ = D*·G − C_D`; check `Σ 2ⁱ·Cᵢ == C_Δ` | `consistency_failed` |
| 10 | recompute `e` from the verifier's **own** statement; for every bit, with `e₁ = e − e₀`: `z₀·H == T₀ + e₀·Cᵢ` and `z₁·H == T₁ + e₁·(Cᵢ − G)` | `fiat_shamir_check_failed` |

The verifier service additionally enforces that the nonce was issued by itself (`unknown_challenge`) and has not been answered before (`challenge_already_used`); every nonce is consumed on first use, whatever the outcome.

## 9. Why it is sound and zero-knowledge [§7.9]

* **Completeness.** By construction every equation holds; `Σ 2ⁱ·Cᵢ = Δ·G + (Σ2ⁱrᵢ)·H = Δ·G − r·H = C_Δ`.
* **Soundness.** From two accepting transcripts with the same first move and different `e`, at least one branch of every OR-proof yields two Schnorr answers, which extract an opening of `Y₀` or `Y₁` to 0 in base `H` — i.e. each `Cᵢ` opens to a bit (or the prover knows `log_G H`). Then `C_Δ = Σ2ⁱCᵢ` opens to `Σ2ⁱbᵢ ∈ [0, 2ⁿ)`. Since `C_D` is signed by the issuer and binding, `D* − D ∈ [0, 2ⁿ)`, so `D ≤ D*`. Forgery probability is negligible (≈ 1/q per attempt) under discrete log in Ristretto255, in the random-oracle model for SHA-512.
* **Zero-knowledge.** Honest-verifier ZK via the simulator in `simulator.rs`: choose random `C₀ … C_{n−2}`, solve `C_{n−1}` from the consistency equation, then for each bit choose `e₀, z₀, z₁` and solve `T₀, T₁`. The output is identically distributed to real transcripts; with Fiat–Shamir this is NIZK in the random-oracle model.

These are heuristic arguments, not a machine-checked proof (PRD §7.9 honesty clause).

## 10. Wire formats [FR-8]

All objects are versioned (`v: 1`). JSON uses lowercase hex for byte fields; CBOR (RFC 8949) uses byte strings for the same fields and the same field names. The verifier accepts `POST /verify` with `Content-Type: application/json` (`{"proof": …}`) or `application/cbor` (the proof itself).

## 11. Schnorr proof of knowledge (library feature, FR-2)

`pramana_core::schnorr` implements the §7.3 three-move proof for `C = v·G + r·H` in interactive form (`commit_phase` / `respond` / `check`), non-interactive form (domain `pramana/schnorr-opening/v1`, binding `G, H, C, context, T`), the HVZK simulator, and the special-soundness extractor. It is used in tests and in teaching; the age proof does not need it, because the range proof already proves knowledge of an opening of `C_Δ`.
