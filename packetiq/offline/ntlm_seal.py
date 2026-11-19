"""
NTLMv2 session-key derivation and message unsealing.

With the account's password (recovered by cracking the AS-REP roast) and the NTLM
handshake the capture carries, this reconstructs the session key the way the
client and server did, then undoes the RC4 "sealing" that protects the WinRM
message bodies. It implements exactly the pieces MS-NLMP uses for NTLMv2 with
extended session security and key exchange, which is what a Windows WinRM session
negotiates.

The session key is validated before anything is decrypted: the NTProofStr in the
AUTHENTICATE message is recomputed from the password, and a mismatch means the
password is wrong, so a wrong guess never produces confident garbage.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from packetiq.offline.crypto import RC4, hmac_md5, md5, nt_hash

NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000
_MAGIC = b"NTLMSSP\x00"
_CLIENT_SEAL = b"session key to client-to-server sealing key magic constant\x00"
_SERVER_SEAL = b"session key to server-to-client sealing key magic constant\x00"


def _field(token: bytes, offset: int) -> bytes:
    """Read a length/offset-described field from an NTLM message."""
    if offset + 8 > len(token):
        return b""
    length, _maxlen, data_offset = struct.unpack("<HHI", token[offset:offset + 8])
    return token[data_offset:data_offset + length]


def parse_challenge(token: bytes) -> tuple[bytes, int] | None:
    """(server_challenge, flags) from an NTLM CHALLENGE (type 2) message."""
    if not token.startswith(_MAGIC) or len(token) < 32:
        return None
    if struct.unpack("<I", token[8:12])[0] != 2:
        return None
    flags = struct.unpack("<I", token[20:24])[0]
    return token[24:32], flags


@dataclass
class Authenticate:
    nt_response: bytes
    domain: str
    user: str
    workstation: str
    enc_session_key: bytes
    flags: int


def parse_authenticate(token: bytes) -> Authenticate | None:
    """The fields of an NTLM AUTHENTICATE (type 3) message needed for the key."""
    if not token.startswith(_MAGIC) or len(token) < 64:
        return None
    if struct.unpack("<I", token[8:12])[0] != 3:
        return None
    nt = _field(token, 20)
    if len(nt) <= 24:            # not an NTLMv2 response
        return None
    return Authenticate(
        nt_response=nt,
        domain=_field(token, 28).decode("utf-16-le", "replace"),
        user=_field(token, 36).decode("utf-16-le", "replace"),
        workstation=_field(token, 44).decode("utf-16-le", "replace"),
        enc_session_key=_field(token, 52),
        flags=struct.unpack("<I", token[60:64])[0],
    )


def exported_session_key(password: str, auth: Authenticate,
                         server_challenge: bytes) -> bytes | None:
    """Derive the ExportedSessionKey for an NTLMv2 session, or None if `password`
    is wrong (the NTProofStr will not match)."""
    ntowfv2 = hmac_md5(nt_hash(password),
                       (auth.user.upper() + auth.domain).encode("utf-16-le"))
    nt_proof = auth.nt_response[:16]
    blob = auth.nt_response[16:]
    if hmac_md5(ntowfv2, server_challenge + blob) != nt_proof:
        return None
    session_base_key = hmac_md5(ntowfv2, nt_proof)
    if auth.flags & NTLMSSP_NEGOTIATE_KEY_EXCH and auth.enc_session_key:
        return RC4(session_base_key).update(auth.enc_session_key)
    return session_base_key


def sealing_key(exported: bytes, *, outbound_from_client: bool) -> bytes:
    """The RC4 sealing key for one direction of the session."""
    magic = _CLIENT_SEAL if outbound_from_client else _SERVER_SEAL
    return md5(exported + magic)


class Unsealer:
    """Decrypts one direction of a sealed NTLM session, keeping the RC4 keystream
    continuous across messages (which is how NTLM sealing works)."""

    def __init__(self, seal_key: bytes) -> None:
        self._rc4 = RC4(seal_key)

    def unseal(self, sealed_payload: bytes, encrypted_checksum: bytes = b"") -> bytes:
        """Return the plaintext of one sealed message. The 8-byte encrypted
        checksum from the signature is fed in so the keystream advances past it,
        exactly as the sender consumed it after sealing the message."""
        plaintext = self._rc4.update(sealed_payload)
        if encrypted_checksum:
            self._rc4.update(encrypted_checksum)
        return plaintext
