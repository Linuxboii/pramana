# Security

Pramāṇa is a reference implementation built to be **honestly** secure: it states what it guarantees, under which assumptions, and where its guarantees stop. It is not a certified identity product and makes no regulatory-compliance claim.

## What is claimed [PRD §7.9]

| Property | Guarantee | Rests on |
|---|---|---|
| Completeness | An honest holder whose credential satisfies the statement always produces a proof that verifies. | Construction (tested by property tests over random dates and thresholds). |
| Soundness | A holder whose attested birthdate does not satisfy the threshold — or who has no valid credential — produces an accepting proof with probability ≈ 1/q ≈ 2⁻²⁵² per attempt. | Discrete log in Ristretto255; SHA-512 as a random oracle; Ed25519 unforgeability; the issuer attests correctly. |
| Zero-knowledge | The proof reveals nothing beyond the truth of the statement and the issuer key used. | HVZK simulator (`simulator.rs`), random-oracle model for Fiat–Shamir. Statistically tested. |
| Non-transferability | A proof verifies only for the verifier id, nonce and validity window it was made for, once. | Fiat–Shamir binding of those fields; the verifier's single-use nonce store. |

These are heuristic arguments appropriate to a portfolio project, not a machine-checked proof.

## Threat model [PRD §12]

| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | Under-age user forges "≥ 18" | Range-proof soundness: negative Δ has no n-bit decomposition | `adversary.rs` (`wrap_around`, `fake_digit`), `tests/protocol.rs`, demo act 2 |
| T2 | User commits to a fake DOB | Issuer Ed25519 signature over `C_D`, strict verification | `swap_commitment` attack → `bad_signature`; demo act 3 |
| T3 | Replay elsewhere or later | FS binds verifier id, nonce, window; nonces single-use; expiry | `replay_*` tests, sakshi tests, demo act 4 |
| T4 | Malicious verifier extracts DOB | Zero-knowledge; the verifier receives only commitments and responses | ZK distribution tests, demo act 5, receipt "Absent" checks |
| T5 | Colluding verifiers link a user | **Not mitigated in Tier A** — `C_D` and `sig` repeat across presentations. Tier B (BBS+) is future work | Documented here and in the UI |
| T6 | Weak-Fiat–Shamir malleability | Entire statement hashed (C_D, D*, issuer key, sig, threshold, date, window) | `tampered_signature_or_commitment_rejected` (raising the threshold after proving fails) |
| T7 | Bad randomness | Hedged SHA-512 DRBG seeded from witness ‖ statement ‖ OS entropy; uniform 512-bit scalar sampling | `rng.rs`, `age::prove_age` |
| T8 | Rogue issuer / key compromise | Verifier pins a trust list; unknown keys are rejected | `rogue_issuer` attack → `untrusted_issuer` |
| T9 | Timing side channels in the wallet | curve25519-dalek constant-time scalar multiplication; branch selection via `subtle` conditional selects | `range.rs`. Not formally audited — hardening item |
| T10 | Credential theft from the device | **Not mitigated in the MVP** — the browser wallet keeps the credential in `localStorage` in plain JSON | Future work: encrypt at rest under a PIN-derived key; bind to a device key |

### Out of scope for the MVP claim

Trusted-setup ceremonies for `H` beyond the nothing-up-my-sleeve derivation; hardware side channels; coercion ("prove under duress"); issuer governance and Sybil resistance; credential revocation (FR-13, explicitly *won't* now).

## Implementation notes

* **No hand-rolled curve math** in the product: group operations come from `curve25519-dalek` 4, signatures from `ed25519-dalek` 2 (`verify_strict`), hashing from `sha2`. The Python file contains an RFC 9496 implementation **for teaching and cross-checking only**; it is not constant time and must not handle real secrets.
* **Strict decoding.** Non-canonical points and scalars are rejected, so proofs are not malleable at the encoding level.
* **No secret-dependent branches** in proof construction; the only branch on the witness is the up-front "is Δ in range?" test, which decides whether a proof is produced at all and reveals nothing to the verifier (nothing is sent).
* **Zeroisation.** Range-proof bit blindings and per-bit nonces, the DRBG state and issuer key-file seeds are zeroised on drop (best effort; values copied by the compiler or held in the browser's JS heap are out of reach).
* **The verifier stores nothing personal.** Outstanding nonces live in memory until used or expired (+10 min grace); the audit log holds `{timestamp, issuer_pk, result, reason}` only, capped at 200 entries in memory.
* **DoS limits.** Request bodies are capped at 64 KiB; outstanding challenges at 10,000 per verifier.
* **HTTP hardening (demo server).** Strict Content-Security-Policy (`'self'` + `'wasm-unsafe-eval'` for the wallet), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on the API, CORS limited to configured origins, panics converted to 500s without crashing the process.

## Demo-authority caveat

The demo issuer believes whatever birthdate you type. That is deliberate: the project solves the *proof*, not identity proofing. In production the issuer would be an authority that already knows verified birthdates (PRD persona: a DigiLocker-style service).

## Reporting

This is a portfolio project. If you find a protocol or implementation flaw, please open an issue describing the class of problem.
