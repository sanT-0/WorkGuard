import json
import hashlib
import os
import base64

def canonical_json_bytes(obj) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme (JCS).
    Deterministically serializes JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    ).encode('utf-8')

# Ed25519 pure Python (RFC 8032)
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def H(m):
    return hashlib.sha512(m).digest()

def expmod(b, e, m):
    if e == 0: return 1
    t = expmod(b, e // 2, m) ** 2 % m
    if e & 1: t = (t * b) % m
    return t

def inv(x):
    return expmod(x, q - 2, q)

d = -121665 * inv(121666)
I = expmod(2, (q - 1) // 4, q)

def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = expmod(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0: x = (x * I) % q
    if x % 2 != 0: x = q - x
    return x

By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q, By % q]

def edwards(P, Q):
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]

def scalarmult(P, e):
    if e == 0: return [0, 1]
    Q = scalarmult(P, e // 2)
    Q = edwards(Q, Q)
    if e & 1: Q = edwards(Q, P)
    return Q

def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b // 8))

def encodepoint(P):
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b // 8))

def bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1

def publickey(sk):
    h = H(sk)
    a = 2**(b - 2) + sum(2**i * bit(h, i) for i in range(3, b - 2))
    A = scalarmult(B, a)
    return encodepoint(A)

def Hint(m):
    h = H(m)
    return sum(2**i * bit(h, i) for i in range(2 * b))

def signature(m, sk, pk):
    h = H(sk)
    a = 2**(b - 2) + sum(2**i * bit(h, i) for i in range(3, b - 2))
    r = Hint(bytes([h[i] for i in range(b // 8, b // 4)]) + m)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)

def isoncurve(P):
    x, y = P[0], P[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0

def decodeint(s):
    return sum(2**i * bit(s, i) for i in range(0, b))

def decodepoint(s):
    y = sum(2**i * bit(s, i) for i in range(0, b - 1))
    x = xrecover(y)
    if bool(x & 1) != bool(bit(s, b - 1)): x = q - x
    P = [x, y]
    if not isoncurve(P): raise ValueError("Point not on curve")
    return P

def checkvalid(s, m, pk):
    if len(s) != b // 4 or len(pk) != b // 8: return False
    try:
        R = decodepoint(s[:b // 8])
        A = decodepoint(pk)
        S = decodeint(s[b // 8:])
        h = Hint(encodepoint(R) + pk + m)
        v1 = scalarmult(B, S)
        v2 = edwards(R, scalarmult(A, h))
        return v1[0] == v2[0] and v1[1] == v2[1]
    except Exception:
        return False

MASTER_KEY_ID = "key-workguard-root-2026-v1"
_SERVER_SEED = hashlib.sha256(b"workguard-ed25519-deterministic-key-seed-2026").digest()
SERVER_PRIVATE_KEY = _SERVER_SEED
SERVER_PUBLIC_KEY = publickey(SERVER_PRIVATE_KEY)
SERVER_PUBLIC_KEY_HEX = SERVER_PUBLIC_KEY.hex()
SERVER_PUBLIC_KEY_B64 = base64.b64encode(SERVER_PUBLIC_KEY).decode("ascii")

def sign_envelope(envelope_data: dict):
    canonical_bytes = canonical_json_bytes(envelope_data)
    digest_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    sig = signature(canonical_bytes, SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY)
    sig_b64 = base64.b64encode(sig).decode("ascii")
    return digest_sha256, sig_b64, MASTER_KEY_ID

def verify_envelope(envelope_data: dict, sig_b64: str, pubkey_bytes: bytes = None) -> bool:
    pk = pubkey_bytes or SERVER_PUBLIC_KEY
    canonical_bytes = canonical_json_bytes(envelope_data)
    try:
        sig = base64.b64decode(sig_b64)
        return checkvalid(sig, canonical_bytes, pk)
    except Exception:
        return False
