"""
NTLM identity extraction, shared by every protocol that carries it.

NTLM rides inside HTTP (WinRM), SMB2 session setup, and anything else that
negotiates SPNEGO. The type 3 AUTHENTICATE message names the account, the
domain and the workstation the client chose to call itself, and it does so in
clear text even when the session payload that follows is encrypted. That makes
it one of the most useful things in an enterprise capture, and it is worth
decoding once rather than once per protocol.

Two traps live here, both found by testing rather than by reading the spec:

  * scapy returns these names as ``str`` only when the client negotiated
    Unicode, and as raw ``bytes`` otherwise. ``str()`` on the bytes yields
    ``b'larry.doe'`` -- a repr in the middle of a report.
  * scapy *raises* for an NTLM field the client omitted rather than returning
    nothing, so one ``except`` around several field reads throws away the
    fields that were present. An account with no domain is what a local or
    workgroup login looks like, which is exactly the login worth noticing.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

_NTLM_MAGIC = b"NTLMSSP\x00"


@dataclass
class NTLMIdentity:
    """An account, domain and workstation lifted from an NTLM type 3 message."""

    user: str = ""
    domain: str = ""
    workstation: str = ""

    def __str__(self) -> str:
        who = f"{self.domain}\\{self.user}" if self.domain and self.user else (self.user or "?")
        return f"{who} from {self.workstation}" if self.workstation else who

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.domain.lower(), self.user.lower(), self.workstation.lower())


def _name(value) -> str:
    """Decode an NTLM name field, which may arrive as str or as raw bytes.

    scapy returns `str` when the client set NTLMSSP_NEGOTIATE_UNICODE and the
    raw `bytes` when it did not. Calling `str()` on the bytes gives "b'larry.doe'"
    -- a repr in the middle of a report, which passes every type check and is
    wrong in exactly the way nobody notices until it reaches a reader. OEM-encoded
    clients are rare but they are the ones that most warrant a second look.
    """
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        # UTF-16LE names show a NUL in every other position; OEM names do not.
        if b"\x00" in raw:
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        return raw.decode("utf-8", "replace")
    return str(value)


def _field(packet, name: str) -> str:
    """Read one NTLM name field, tolerating the ones the client did not send."""
    try:
        return _name(getattr(packet, name, None))
    except (AttributeError, ValueError, StopIteration):
        return ""


def decode_ntlm(blob: str) -> tuple[NTLMIdentity | None, bool]:
    """Decode a base64 NTLM token, returning (identity, was_an_ntlm_message).

    Only the type 3 AUTHENTICATE message names an account. Types 1 and 2 are
    still counted, because "an NTLM handshake happened here" matters even when
    this particular message carries no name.
    """
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None, False
    if not raw.startswith(_NTLM_MAGIC) or len(raw) < 12:
        return None, False

    message_type = int.from_bytes(raw[8:12], "little")
    if message_type != 3:
        return None, True

    from scapy.layers.ntlm import NTLM_AUTHENTICATE_V2

    try:
        parsed = NTLM_AUTHENTICATE_V2(raw)
    except Exception:
        return None, True

    # Each field is read on its own. scapy raises AttributeError for an NTLM
    # field the client omitted rather than returning None, so one `suppress`
    # around all three threw away a perfectly good username whenever the domain
    # was absent -- which is exactly what a local or workgroup account looks
    # like, and exactly the account worth noticing.
    identity = NTLMIdentity(
        user=_field(parsed, "UserName"),
        domain=_field(parsed, "DomainName"),
        workstation=_field(parsed, "Workstation"),
    )
    if identity.user or identity.domain or identity.workstation:
        return identity, True
    return None, True
