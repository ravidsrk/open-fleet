#!/usr/bin/env python3
"""ed25519.py — vendored pure-Python Ed25519 (RFC 8032), dependency-free.

Why vendored, not a library: verify.py / verify-gate.sh run as a completion hook in arbitrary
sandboxes where `pip install` may not be possible, so the whole gate is stdlib-only. This is the
public-domain reference implementation (Daniel J. Bernstein et al., ed25519.cr.yp.to), ported to
Python 3 — the "slow but correct" reference, verified here against the RFC 8032 test vectors
(tests/test_ed25519.py). It is NOT constant-time; it signs/verifies a tiny dispatch-provenance
record, never bulk data or a network secret. Verification hardening beyond the bare RFC reference:
`checkvalid` rejects non-canonical `S >= L` (signature malleability), non-canonical point
encodings, and small-order/identity public keys (cofactor check) — so it is safe against the
forgery-via-attacker-key and (R, S+L) duplicate-signature classes. Remaining gaps: it is still
not constant-time, and it uses the non-cofactored verification equation (per-key and per-message
binding, but not the strict ZIP-215 / cofactored semantics). A deployment that wants a hardened
backend can swap in libsodium / `cryptography` behind the same three functions: `publickey`,
`signature`, `checkvalid`.

Used by:
  - runtime/scripts/dispatch-sign.py  (coordinator, OFF the graded worker) — sign the dispatch record
  - runtime/scripts/verify.py         (the gate) — verify the signature with the pinned public key
  - runtime/scripts/decisions.py      (human grants) — grant-keygen, sign-grant, and verifying a
                                      one-way grant's signature against .orca/human-grant-pubkey
  - runtime/scripts/inventory.py      through dispatch-sign.py — sign and verify the inventory and
                                      its retention receipt
  - runtime/scripts/run_report.py     through dispatch-sign.py's loader — verify a signed verdict
                                      transcript against the committed .orca/dispatch-pubkey
"""
from __future__ import annotations

import hashlib

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493  # group order


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]  # base point (affine)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]


def _scalarmult(P, e: int):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return bytes((y >> (8 * i)) & 0xFF for i in range(_b // 8))


def _encodepoint(P) -> bytes:
    x, y = P
    y_with_sign = y | ((x & 1) << (_b - 1))
    return _encodeint(y_with_sign)


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(0, _b))


def _isoncurve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s: bytes):
    y = sum(2 ** i * _bit(s, i) for i in range(0, _b - 1))
    if y >= _q:
        raise ValueError("decoding a non-canonical point encoding")
    x = _xrecover(y)
    if x == 0 and _bit(s, _b - 1):
        # RFC 8032 §5.1.3 step 4: x = 0 has no negative, so a set sign bit is a decoding
        # failure — flipping it would yield x = q, a non-canonical second encoding.
        raise ValueError("decoding x = 0 with the sign bit set")
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("decoding a point that is not on the curve")
    return P


def _clamp(h: bytes) -> int:
    return 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))


def _Hint(m: bytes) -> int:
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * _b))


def publickey(seed: bytes) -> bytes:
    """32-byte public key for a 32-byte secret seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _clamp(h)
    return _encodepoint(_scalarmult(_B, a))


def signature(msg: bytes, seed: bytes, pub: bytes) -> bytes:
    """64-byte Ed25519 signature over msg for secret seed (pub = publickey(seed))."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _clamp(h)
    r = _Hint(h[_b // 8:_b // 4] + msg)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + pub + msg) * a) % _L
    return _encodepoint(R) + _encodeint(S)


def checkvalid(sig: bytes, msg: bytes, pub: bytes) -> bool:
    """True iff sig is a valid Ed25519 signature of msg under public key pub."""
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pub)
    except ValueError:
        return False
    S = _decodeint(sig[32:])
    if S >= _L:
        # Non-canonical S: (R, S+L) would otherwise verify — signatures are malleable.
        return False
    if _scalarmult(A, 8) == [0, 1]:
        # Small-order/identity public key: Hint(...)*A collapses, so (sB, s) "verifies"
        # for any chosen s. Reject via the cofactor check.
        return False
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, _Hint(sig[:32] + pub + msg)))
