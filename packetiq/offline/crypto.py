"""
The small, old cryptographic primitives Windows authentication still rests on.

MD4 was removed from OpenSSL 3, so `hashlib` cannot produce an NT hash any more,
and RC4 is likewise gone from the defaults. Both are reimplemented here in pure
Python: they are legacy by design (this is what the protocols use), and a
self-contained implementation keeps the offline tooling working on any install
without depending on a deprecated backend. Nothing here is used for security; it
is used to UNDO the weak protection an attacker relied on.
"""

from __future__ import annotations

import hashlib
import hmac
import struct


def md4(data: bytes) -> bytes:
    """MD4 (RFC 1320), as needed for the NT hash."""
    def lrot(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bit_len = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = a0, b0, c0, d0

        def f(x_, y_, z_):
            return (x_ & y_) | (~x_ & z_)

        def g(x_, y_, z_):
            return (x_ & y_) | (x_ & z_) | (y_ & z_)

        def h(x_, y_, z_):
            return x_ ^ y_ ^ z_

        for i in (0, 4, 8, 12):
            a = lrot(a + f(b, c, d) + x[i], 3)
            d = lrot(d + f(a, b, c) + x[i + 1], 7)
            c = lrot(c + f(d, a, b) + x[i + 2], 11)
            b = lrot(b + f(c, d, a) + x[i + 3], 19)
        for i in range(4):
            a = lrot(a + g(b, c, d) + x[i] + 0x5A827999, 3)
            d = lrot(d + g(a, b, c) + x[i + 4] + 0x5A827999, 5)
            c = lrot(c + g(d, a, b) + x[i + 8] + 0x5A827999, 9)
            b = lrot(b + g(c, d, a) + x[i + 12] + 0x5A827999, 13)
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        for i in (0, 4, 8, 12):
            a = lrot(a + h(b, c, d) + x[order[i]] + 0x6ED9EBA1, 3)
            d = lrot(d + h(a, b, c) + x[order[i + 1]] + 0x6ED9EBA1, 9)
            c = lrot(c + h(d, a, b) + x[order[i + 2]] + 0x6ED9EBA1, 11)
            b = lrot(b + h(c, d, a) + x[order[i + 3]] + 0x6ED9EBA1, 15)

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF
    return struct.pack("<4I", a0, b0, c0, d0)


class RC4:
    """A stateful RC4 keystream, so a sealed session can be decrypted message by
    message with the keystream continuing across them (what NTLM sealing does)."""

    def __init__(self, key: bytes) -> None:
        s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + s[i] + key[i % len(key)]) & 0xFF
            s[i], s[j] = s[j], s[i]
        self._s = s
        self._i = 0
        self._j = 0

    def update(self, data: bytes) -> bytes:
        s, i, j = self._s, self._i, self._j
        out = bytearray()
        for byte in data:
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out.append(byte ^ s[(s[i] + s[j]) & 0xFF])
        self._i, self._j = i, j
        return bytes(out)


def rc4(key: bytes, data: bytes) -> bytes:
    """One-shot RC4 (encrypt and decrypt are the same operation)."""
    return RC4(key).update(data)


def md5(data: bytes) -> bytes:
    return hashlib.md5(data, usedforsecurity=False).digest()


def hmac_md5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def nt_hash(password: str) -> bytes:
    """NT hash = MD4(UTF-16LE(password))."""
    return md4(password.encode("utf-16-le"))
