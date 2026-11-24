# Requirements traceability

Every goal and requirement in the PRD (v1.0, 19 Nov 2026), where it lives in the code, and what proves it works.

## Goals [§5.1]

| # | Goal | Status | Where / evidence |
|---|---|---|---|
| G1 | Configurable threshold in zero knowledge | ✅ | 13/16/18/21 selectable (`ALLOWED_THRESHOLDS`, shop's age-rule selector); verifier returns only `ok` + issuer |
| G2 | Proof bound to a trusted attestation | ✅ | Ed25519 over `C_D`, trust list; `bad_signature` / `untrusted_issuer` tests |
| G3 | Non-interactive & replay-resistant | ✅ | Single proof blob, offline `verify_age`; nonce + verifier id + window in the transcript; single-use nonces |
| G4 | Unlinkability across verifiers (stretch) | ⏭ Not in Tier A — documented | Tier A `C_D` is constant (SECURITY.md T5); Tier B is future work |
| G5 | Cryptography visible and teachable | ✅ | Five-act demonstration, transcript inspector, X-ray, Python reference |
| G6 | Honest, auditable implementation | ✅ | §7 cross-references in code, KATs, dalek/ed25519-dalek only, SECURITY.md |

## Functional requirements [§10]

| ID | Requirement | Priority | Status | Code | Tests |
|---|---|---|---|---|---|
| FR-1 | Pedersen over Ristretto255, NUMS generators | MUST | ✅ | `params.rs`, `pedersen.rs` | `pedersen::tests`, `params::tests`, Python H check |
| FR-2 | Schnorr PoK of an opening | MUST | ✅ | `schnorr.rs` (interactive, NI, simulator, extractor) | `schnorr::tests` |
| FR-3 | Bit OR-proof and bit-decomposition range proof | MUST | ✅ | `range.rs` | `range::tests`, property and negative tests |
| FR-4 | Age predicate reduction, configurable threshold & date | MUST | ✅ | `age.rs`, `date.rs` | `verifies_iff_old_enough`, boundary & leap-day tests/vectors |
| FR-5 | Strong Fiat–Shamir with full statement + nonce | MUST | ✅ | `transcript.rs`, `age::age_transcript` | replay/relabel/threshold-change tests |
| FR-6 | Issuer tool: encode, commit, sign, emit | MUST | ✅ | `pramana-issuer` CLI + HTTP | issuer tests |
| FR-7 | Verifier: signature + proof → boolean, no PII | MUST | ✅ | `pramana-sakshi` | sakshi tests incl. `audit_log_holds_no_pii` |
| FR-8 | Versioned wire formats (CBOR/JSON) | MUST | ✅ | `wire.rs`; `/verify` accepts both | `json_and_cbor_roundtrip_and_sizes`, `cbor_wire_format_accepted` |
| FR-9 | Demo website gating content on a proof | SHOULD | ✅ | `web/` "Try it" | browser E2E |
| FR-10 | Replay demonstration at a second verifier | SHOULD | ✅ | `/api/other`, demo act 4 | `replay_to_second_verifier`, browser E2E |
| FR-11 | Tier-B BBS+ unlinkable presentations | COULD | ⏭ Future work | — | — |
| FR-12 | Bulletproofs backend | COULD | ⏭ Future work | — | — |
| FR-13 | Revocation / status lists | WON'T (now) | — | — | — |

## Non-functional requirements [§11]

| Attribute | Target | Result |
|---|---|---|
| Security level | ≥ 128-bit; SHA-512 for FS and hash-to-group | Ristretto255 (~128-bit); SHA-512 transcript and `H` derivation |
| Proof size | a few KB (Tier A, n = 16) | 3,754 B CBOR / 7,308 B JSON |
| Prove time | < 150 ms laptop / WASM | 12 ms native (criterion), ≈ 40 ms in-browser WASM |
| Verify time | < 30 ms, offline | 8 ms native (criterion); no issuer contact |
| Determinism | deterministic given explicit randomness | `prove_age_with_rng` + `HashDrbg`; KATs reproduce byte-for-byte |
| Portability | same core native + WASM | `pramana-wasm` wraps `pramana-core` unchanged |
| No secret-dependent branches | rely on constant-time library | dalek scalar mults; `subtle` selects in `range.rs` |
| Auditability | §7 cross-references in code | module docs and inline comments cite §7.x |

## User stories [§6]

| # | Story | Where |
|---|---|---|
| U1 | Receive a reusable credential once | Wallet "Request credential"; CLI `issue`; credential file import/export |
| U2 | Prove ≥ 18 to a specific site without revealing DOB | "Try it" consent + receipt "Absent" checks |
| U3 | Verify offline in milliseconds | `verify_age` (8 ms), `verify_local` in WASM |
| U4 | Under-age users cannot forge | Act 2, adversary tests |
| U5 | Unlinkable proofs across sites (SHOULD) | Not in Tier A — documented limit (T5) |
| U6 | Captured proof fails when replayed | Act 4, replay tests |

## Demonstration [§17]

| Act | Implemented as | Verified by |
|---|---|---|
| ① Honest path | Act 1 + "Try it" | E2E: accepted; DOB absent |
| ② The cheat | Act 2: honest wallet refuses; `wrap_around`, `fake_digit` rejected | E2E + `every_cheat_is_rejected` |
| ③ Forgery | Act 3: `tamper_bytes`, `swap_commitment`, `rogue_issuer`, free-form hand edit | E2E (incl. one-character edit) |
| ④ Replay | Act 4: other verifier, relabelled nonce, reuse | E2E sequence Rejected/Rejected/Accepted/Rejected |
| ⑤ X-ray | Act 5: real vs simulated transcripts, guessing game, distribution histogram | E2E + ZK statistical tests |
| Money shot | Hero: site's entire view vs ID-upload specimen | visual |

## Testing strategy [§16] and definition of done

All §16 layers are implemented (see the table in the README). Definition of done: all MUST requirements implemented ✅; property and negative tests green ✅; §17 demo runs honest/cheat/replay live ✅; README states assumptions and limits plainly ✅.
