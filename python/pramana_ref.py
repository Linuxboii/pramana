#!/usr/bin/env python3
"""
pramana_ref.py — the Gūḍhapramāṇa protocol in plain, annotated Python.

This is the *teaching prototype* from PRD §13 ("Alternative — teaching prototype")
and the second implementation for the §16 cross-implementation test. It is written
for clarity, not speed or side-channel safety:

  * It is NOT constant time. Never use it with real secrets.
  * It contains a from-the-RFC Ristretto255 implementation (RFC 9496) on top of
    Python integers. The product (Rust) uses curve25519-dalek; this file exists so
    a reader can see every step, and so two independent implementations can be
    checked against each other byte-for-byte.

Run the cross-implementation check against the Rust known-answer vectors:

    python python/pramana_ref.py --check-vectors test-vectors/v1.json

Requires only the standard library, plus `cryptography` for Ed25519 signing in the
re-issuance check (verification-only checks run without it).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# §7.1 The group: Ristretto255 over Curve25519 (RFC 9496), written out longhand.
# ---------------------------------------------------------------------------

P = 2**255 - 19                                  # field modulus
L = 2**252 + 27742317777372353535851937790883648493  # group order q
D = (-121665 * pow(121666, -1, P)) % P           # Edwards d

# RFC 9496 §4.1 constants.
SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952

assert SQRT_M1 * SQRT_M1 % P == P - 1
assert SQRT_AD_MINUS_ONE**2 % P == (-D - 1) % P
assert INVSQRT_A_MINUS_D**2 * (-1 - D) % P == 1
assert ONE_MINUS_D_SQ == (1 - D * D) % P
assert D_MINUS_ONE_SQ == (D - 1) ** 2 % P


def is_negative(x: int) -> bool:
    return (x % P) & 1 == 1


def ct_abs(x: int) -> int:
    x %= P
    return (P - x) % P if is_negative(x) else x


def sqrt_ratio_m1(u: int, v: int) -> tuple[bool, int]:
    """RFC 9496 SQRT_RATIO_M1: (was_square, sqrt(u/v) or sqrt(i·u/v)), non-negative."""
    u %= P
    v %= P
    v3 = v * v % P * v % P
    v7 = v3 * v3 % P * v % P
    r = u * v3 % P * pow(u * v7 % P, (P - 5) // 8, P) % P
    check = v * r % P * r % P
    correct = check == u
    flipped = check == (-u) % P
    flipped_i = check == (-u * SQRT_M1) % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return correct or flipped, ct_abs(r)


@dataclass(frozen=True)
class Point:
    """Extended twisted-Edwards coordinates (X:Y:Z:T), a = −1."""
    X: int
    Y: int
    Z: int
    T: int

    def __add__(self, o: "Point") -> "Point":
        a = (self.Y - self.X) * (o.Y - o.X) % P
        b = (self.Y + self.X) * (o.Y + o.X) % P
        c = self.T * 2 * D * o.T % P
        d = self.Z * 2 * o.Z % P
        e, f, g, h = b - a, d - c, d + c, b + a
        return Point(e * f % P, g * h % P, f * g % P, e * h % P)

    def __neg__(self) -> "Point":
        return Point((-self.X) % P, self.Y, self.Z, (-self.T) % P)

    def __sub__(self, o: "Point") -> "Point":
        return self + (-o)

    def __rmul__(self, k: int) -> "Point":
        """Double-and-add. NOT constant time — teaching code only."""
        k %= L
        result, addend = IDENTITY, self
        while k:
            if k & 1:
                result = result + addend
            addend = addend + addend
            k >>= 1
        return result

    def __eq__(self, o: object) -> bool:  # Ristretto equality (RFC 9496 §4.3.3)
        assert isinstance(o, Point)
        return (self.X * o.Y - self.Y * o.X) % P == 0 or (self.Y * o.Y - self.X * o.X) % P == 0

    def encode(self) -> bytes:
        """RFC 9496 §4.3.2 ENCODE."""
        x0, y0, z0, t0 = self.X, self.Y, self.Z, self.T
        u1 = (z0 + y0) * (z0 - y0) % P
        u2 = x0 * y0 % P
        _, invsqrt = sqrt_ratio_m1(1, u1 * u2 * u2)
        den1 = invsqrt * u1 % P
        den2 = invsqrt * u2 % P
        z_inv = den1 * den2 % P * t0 % P
        ix0, iy0 = x0 * SQRT_M1 % P, y0 * SQRT_M1 % P
        enchanted = den1 * INVSQRT_A_MINUS_D % P
        rotate = is_negative(t0 * z_inv)
        x, y = (iy0, ix0) if rotate else (x0, y0)
        den_inv = enchanted if rotate else den2
        if is_negative(x * z_inv):
            y = (-y) % P
        s = ct_abs(den_inv * (z0 - y))
        return s.to_bytes(32, "little")

    @staticmethod
    def decode(b: bytes) -> "Point":
        """RFC 9496 §4.3.1 DECODE — strict: rejects non-canonical encodings."""
        if len(b) != 32:
            raise ValueError("point must be 32 bytes")
        s = int.from_bytes(b, "little")
        if s >= P or is_negative(s):
            raise ValueError("non-canonical point")
        ss = s * s % P
        u1, u2 = (1 - ss) % P, (1 + ss) % P
        u2_sqr = u2 * u2 % P
        v = (-(D * u1 % P * u1) - u2_sqr) % P
        was_square, invsqrt = sqrt_ratio_m1(1, v * u2_sqr)
        den_x = invsqrt * u2 % P
        den_y = invsqrt * den_x % P * v % P
        x = ct_abs(2 * s * den_x)
        y = u1 * den_y % P
        t = x * y % P
        if not was_square or is_negative(t) or y == 0:
            raise ValueError("invalid point")
        return Point(x, y, 1, t)

    @staticmethod
    def _map(t: int) -> "Point":
        """RFC 9496 §4.3.4 MAP (Elligator 2 to Ristretto)."""
        r = SQRT_M1 * t % P * t % P
        u = (r + 1) * ONE_MINUS_D_SQ % P
        v = (-1 - r * D) * (r + D) % P
        was_square, s = sqrt_ratio_m1(u, v)
        s_prime = (-ct_abs(s * t)) % P
        s = s if was_square else s_prime
        c = (P - 1) if was_square else r
        n = (c * (r - 1) % P * D_MINUS_ONE_SQ - v) % P
        w0 = 2 * s * v % P
        w1 = n * SQRT_AD_MINUS_ONE % P
        w2 = (1 - s * s) % P
        w3 = (1 + s * s) % P
        return Point(w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)

    @staticmethod
    def from_uniform_bytes(b: bytes) -> "Point":
        """RFC 9496 §4.3.4 one-way map from 64 uniform bytes."""
        assert len(b) == 64
        r0 = int.from_bytes(b[:32], "little") & ((1 << 255) - 1)
        r1 = int.from_bytes(b[32:], "little") & ((1 << 255) - 1)
        return Point._map(r0 % P) + Point._map(r1 % P)


IDENTITY = Point(0, 1, 1, 0)
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_BY = 4 * pow(5, -1, P) % P
G = Point(_BX, _BY, 1, _BX * _BY % P)                         # Ristretto basepoint
H = Point.from_uniform_bytes(hashlib.sha512(b"pramana/H/v1").digest())  # NUMS (§7.1)
N_BITS = 16

# ---------------------------------------------------------------------------
# Scalars, randomness, transcript
# ---------------------------------------------------------------------------


def scalar_from_wide(b: bytes) -> int:
    return int.from_bytes(b, "little") % L


def scalar_bytes(s: int) -> bytes:
    return (s % L).to_bytes(32, "little")


def scalar_decode(b: bytes) -> int:
    s = int.from_bytes(b, "little")
    if s >= L:
        raise ValueError("non-canonical scalar")
    return s


class HashDrbg:
    """SHA-512 counter DRBG — identical to pramana_core::rng::HashDrbg."""

    def __init__(self, material: bytes):
        self.seed = hashlib.sha512(b"pramana/drbg-seed/v1" + material).digest()
        self.counter = 0
        self.buf = b""

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf += hashlib.sha512(b"pramana/drbg/v1" + self.seed + self.counter.to_bytes(8, "little")).digest()
            self.counter += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def scalar(self) -> int:
        return scalar_from_wide(self.read(64))


class Transcript:
    """§7.7 — length-prefixed SHA-512 transcript (pramana_core::transcript)."""

    def __init__(self, domain: bytes):
        self.h = hashlib.sha512()
        self.append(b"dom-sep", domain)

    def append(self, label: bytes, data: bytes) -> None:
        self.h.update(len(label).to_bytes(8, "little") + label + len(data).to_bytes(8, "little") + data)

    def append_u64(self, label: bytes, v: int) -> None:
        self.append(label, v.to_bytes(8, "little"))

    def append_i64(self, label: bytes, v: int) -> None:
        self.append(label, v.to_bytes(8, "little", signed=True))

    def challenge(self, label: bytes) -> int:
        self.append(b"challenge", label)
        return scalar_from_wide(self.h.copy().digest())


# ---------------------------------------------------------------------------
# §7.6 Dates → integers
# ---------------------------------------------------------------------------


def days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * ((m + 9) % 12) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def days_since_1900(iso: str) -> int:
    y, m, d = map(int, iso.split("-"))
    return days_from_civil(y, m, d) - days_from_civil(1900, 1, 1)


def minus_years(iso: str, years: int) -> str:
    y, m, d = map(int, iso.split("-"))
    y -= years
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    if m == 2 and d == 29 and not leap:
        d = 28
    return f"{y:04d}-{m:02d}-{d:02d}"


# ---------------------------------------------------------------------------
# §7.2 Pedersen, §7.4 OR-proof, §7.5 range proof, §7.6–7.7 age statement
# ---------------------------------------------------------------------------

SUITE = b"gudhapramana/v1/tier-a/ristretto255/sha512"
AGE_DOMAIN = b"pramana/gudhapramana/age/v1"
SIG_DOMAIN = b"pramana/credential-sig/v1"


def commit(v: int, r: int) -> Point:
    return v * G + r * H


def age_transcript(st: dict, issuer_pk: bytes, c_d: bytes, sig: bytes, d_star: int, c_delta: Point) -> Transcript:
    t = Transcript(AGE_DOMAIN)
    t.append(b"suite", SUITE)
    t.append(b"G", G.encode())
    t.append(b"H", H.encode())
    t.append_u64(b"n_bits", N_BITS)
    t.append(b"issuer_pk", issuer_pk)
    t.append(b"C_D", c_d)
    t.append(b"sig", sig)
    t.append_u64(b"threshold_years", st["threshold_years"])
    t.append(b"today", st["today"].encode())
    t.append_i64(b"D_star", d_star)
    t.append(b"C_delta", c_delta.encode())
    t.append(b"verifier_id", st["verifier_id"].encode())
    t.append(b"nonce", bytes.fromhex(st["nonce"]))
    t.append_u64(b"issued_at", st["issued_at"])
    t.append_u64(b"expires_at", st["expires_at"])
    return t


def d_star_of(st: dict) -> int:
    return days_since_1900(minus_years(st["today"], st["threshold_years"]))


def prove_age(cred: dict, st: dict, rng: HashDrbg) -> dict:
    """§9.2. Raises ValueError for an under-age holder (no proof exists)."""
    D_ = cred["d"]
    r = scalar_decode(bytes.fromhex(cred["r"]))
    c_d = Point.decode(bytes.fromhex(cred["c_d"]))
    assert commit(D_, r) == c_d, "credential opening mismatch"
    d_star = d_star_of(st)
    delta = d_star - D_
    if delta < 0:
        raise ValueError(f"under age by {-delta} days: no 16-bit decomposition of a negative Δ")
    assert delta < 2**N_BITS
    c_delta = d_star * G - c_d
    t = age_transcript(st, bytes.fromhex(cred["issuer_pk"]), bytes.fromhex(cred["c_d"]), bytes.fromhex(cred["sig"]), d_star, c_delta)

    # §7.5: bit blindings with Σ 2^i r_i = −r (the blinding of C_Δ).
    rs = [rng.scalar() for _ in range(N_BITS - 1)]
    acc = sum((1 << i) * ri for i, ri in enumerate(rs)) % L
    rs.append((-r - acc) * pow(1 << (N_BITS - 1), -1, L) % L)

    first, secrets = [], []
    for i in range(N_BITS):
        b = (delta >> i) & 1
        c = b * G + rs[i] * H
        y = [c, c - G]                       # Y0 = C, Y1 = C − G
        k, e_s, z_s = rng.scalar(), rng.scalar(), rng.scalar()
        s = 1 - b                            # simulated branch
        t_sim = z_s * H - e_s * y[s]         # §7.3 simulator
        t_real = k * H                       # honest Schnorr commitment
        ts = [None, None]
        ts[b], ts[s] = t_real, t_sim
        first.append((c.encode(), ts[0].encode(), ts[1].encode()))
        secrets.append((b, rs[i], k, e_s, z_s))

    t.append_u64(b"n", N_BITS)
    for c, t0, t1 in first:
        t.append(b"C_i", c)
        t.append(b"T0_i", t0)
        t.append(b"T1_i", t1)
    e = t.challenge(b"e")

    bits = []
    for (c, t0, t1), (b, ri, k, e_s, z_s) in zip(first, secrets):
        e_real = (e - e_s) % L
        z_real = (k + e_real * ri) % L
        e0, z0, z1 = (e_real, z_real, z_s) if b == 0 else (e_s, z_s, z_real)
        bits.append({"c": c.hex(), "t0": t0.hex(), "t1": t1.hex(),
                     "e0": scalar_bytes(e0).hex(), "z0": scalar_bytes(z0).hex(), "z1": scalar_bytes(z1).hex()})
    return {"v": 1, "issuer_pk": cred["issuer_pk"], "c_d": cred["c_d"], "sig": cred["sig"], "nonce": st["nonce"], "bits": bits}


def ed25519_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        print("  (cryptography not installed: skipping Ed25519 check)")
        return True
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except Exception:
        return False


def verify_age(proof: dict, st: dict, trusted: list[bytes], now: int) -> tuple[bool, str]:
    """§9.3 — same check order and outcomes as pramana_core::verify_age."""
    try:
        if proof["v"] != 1:
            return False, "unsupported_version"
        if proof["nonce"] != st["nonce"]:
            return False, "nonce_mismatch"
        pk, c_d_b, sig = (bytes.fromhex(proof[k]) for k in ("issuer_pk", "c_d", "sig"))
        if pk not in trusted:
            return False, "untrusted_issuer"
        if not ed25519_verify(pk, SIG_DOMAIN + c_d_b, sig):
            return False, "bad_signature"
        if now + 60 < st["issued_at"]:
            return False, "not_yet_valid"
        if now > st["expires_at"]:
            return False, "expired"
        c_d = Point.decode(c_d_b)
        d_star = d_star_of(st)
        c_delta = d_star * G - c_d
        if len(proof["bits"]) != N_BITS:
            return False, "wrong_bit_count"
        dec = []
        for bp in proof["bits"]:
            dec.append((Point.decode(bytes.fromhex(bp["c"])), Point.decode(bytes.fromhex(bp["t0"])),
                        Point.decode(bytes.fromhex(bp["t1"])), scalar_decode(bytes.fromhex(bp["e0"])),
                        scalar_decode(bytes.fromhex(bp["z0"])), scalar_decode(bytes.fromhex(bp["z1"]))))
    except (ValueError, KeyError) as exc:
        return False, f"malformed ({exc})"
    # §7.5 consistency, computed by the verifier itself.
    acc = IDENTITY
    for i, (c, *_rest) in enumerate(dec):
        acc = acc + (1 << i) * c
    if not acc == c_delta:
        return False, "consistency_failed"
    t = age_transcript(st, pk, c_d_b, sig, d_star, c_delta)
    t.append_u64(b"n", N_BITS)
    for bp in proof["bits"]:
        t.append(b"C_i", bytes.fromhex(bp["c"]))
        t.append(b"T0_i", bytes.fromhex(bp["t0"]))
        t.append(b"T1_i", bytes.fromhex(bp["t1"]))
    e = t.challenge(b"e")
    for i, (c, t0, t1, e0, z0, z1) in enumerate(dec):
        e1 = (e - e0) % L
        if not (z0 * H == t0 + e0 * c and z1 * H == t1 + e1 * (c - G)):
            return False, "fiat_shamir_check_failed"
    return True, "ok"


# ---------------------------------------------------------------------------
# §16 Cross-implementation check
# ---------------------------------------------------------------------------


def issue_credential(secret_seed: bytes, dob: str, rng: HashDrbg, issued_at: int, name: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    sk = Ed25519PrivateKey.from_private_bytes(secret_seed)
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    d = days_since_1900(dob)
    r = rng.scalar()
    c_d = commit(d, r).encode()
    sig = sk.sign(SIG_DOMAIN + c_d)
    return {"v": 1, "kind": "pramana-age-credential",
            "params": "pramana/params/v1:ristretto255:H=HashToGroup(pramana/H/v1):n=16",
            "issuer_name": name, "issuer_pk": pk.hex(), "c_d": c_d.hex(), "sig": sig.hex(),
            "d": d, "r": scalar_bytes(r).hex(), "issued_at": issued_at}


def check_vectors(path: str) -> int:
    doc = json.load(open(path, encoding="utf-8"))
    failures = 0

    def check(cond: bool, what: str) -> None:
        nonlocal failures
        print(f"  {'PASS' if cond else 'FAIL'}  {what}")
        failures += 0 if cond else 1

    print("Parameters")
    check(G.encode().hex() == doc["params"]["G"], "G encodes to the Ristretto basepoint")
    check(H.encode().hex() == doc["params"]["H"], "H = HashToGroup('pramana/H/v1') matches Rust")
    check(Point.decode(G.encode()) == G, "decode(encode(G)) == G")

    seed = bytes.fromhex(doc["issuer"]["secret_seed"])
    trusted = [bytes.fromhex(doc["issuer"]["public_key"])]
    try:
        import cryptography  # noqa: F401
        have_crypto = True
    except ImportError:
        have_crypto = False
        print("  (cryptography not installed: re-issuance checks skipped)")

    for v in doc["vectors"]:
        print(f"Vector {v['name']}")
        st, cred = v["statement"], v["credential"]
        check(d_star_of(st) == v["d_star"], f"D* = {v['d_star']}")
        check(days_since_1900(v["dob"]) == cred["d"], "D = days since 1900")
        if have_crypto:
            mine = issue_credential(seed, v["dob"], HashDrbg(v["issue_rng_seed"].encode()), cred["issued_at"], cred["issuer_name"])
            check(mine == cred, "re-issued credential is byte-identical (C_D, r, Ed25519 sig)")
        if v["expect"] == "accept":
            ok, why = verify_age(v["proof"], st, trusted, st["issued_at"])
            check(ok, f"Python verifier accepts the Rust proof ({why})")
            mine = prove_age(cred, st, HashDrbg(v["prove_rng_seed"].encode()))
            check(mine == v["proof"], "Python prover reproduces the Rust proof byte-for-byte")
            blob = json.dumps(mine, separators=(",", ":"))
            check(hashlib.sha256(blob.encode()).hexdigest() == v["proof_json_sha256"], "proof JSON SHA-256 matches")
            # Negative cross-checks
            other = dict(st, verifier_id="other-site.example")
            check(verify_age(v["proof"], other, trusted, st["issued_at"])[1] == "fiat_shamir_check_failed",
                  "replay to another verifier id fails the Fiat–Shamir check")
            tampered = json.loads(json.dumps(v["proof"]))
            b = bytearray.fromhex(tampered["bits"][7]["z0"])
            b[0] ^= 1
            tampered["bits"][7]["z0"] = b.hex()
            check(not verify_age(tampered, st, trusted, st["issued_at"])[0], "a flipped bit is rejected")
        else:
            try:
                prove_age(cred, st, HashDrbg(v["prove_rng_seed"].encode()))
                check(False, "under-age prover must fail")
            except ValueError as exc:
                check("under age" in str(exc), f"under-age prover refuses ({exc})")
    print(f"\n{'OK' if failures == 0 else 'FAILED'}: {failures} failure(s)")
    return 1 if failures else 0


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check-vectors", metavar="PATH", help="cross-check against Rust KAT vectors")
    args = ap.parse_args()
    if args.check_vectors:
        return check_vectors(args.check_vectors)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
