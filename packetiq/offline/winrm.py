"""
Decrypting a WinRM session, given the account password.

WinRM protects each SOAP body with NTLM sealing. With the password recovered from
the AS-REP roast, this walks the capture connection by connection (each WinRM
connection runs its own NTLM handshake and its own keystream), derives the
session key, unseals the message bodies, and reads out of them what a responder
wants: the commands that were run and anything they produced, including a flag.

A WinRM shell runs commands two ways, and both are handled: the PowerShell
Remoting protocol (PSRP), whose command text is base64 inside the SOAP, and the
plainer WS-Management Shell. The decrypted content is also run through the
artifact hunter, so a flag or secret in the command output is recovered the same
way it is anywhere else.
"""

from __future__ import annotations

import base64
import contextlib
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field

from packetiq.offline import ntlm_seal

_WINRM_PORT = 5985
_NTLM = b"NTLMSSP\x00"
_OCTET = b"application/octet-stream\r\n"

_ORIG_LEN = re.compile(rb"OriginalContent:[^\r\n]*Length=(\d+)")
_NTLM_TOKEN = re.compile(rb"(?:Authorization|WWW-Authenticate):\s*Negotiate\s+([A-Za-z0-9+/=]+)")
_CMD_VALUE = re.compile(rb'<S N="V">([^<]{1,300})</S>')
_RSP_COMMAND = re.compile(rb"<rsp:Command>([^<]{1,300})</rsp:Command>")
_RSP_ARGS = re.compile(rb"<rsp:Arguments>([A-Za-z0-9+/=]+)</rsp:Arguments>")
# Evil-WinRM runs every operator command as `Invoke-Expression <arg>` and drives
# its own prompt with `(get-location).path`; both are protocol noise, not commands.
_SHELL_NOISE = {"invoke-expression", "(get-location).path"}
_B64_IN_XML = re.compile(rb">([A-Za-z0-9+/]{8,}={0,2})<")
# Only a real CTF flag prefix — a loose `X{...}` pattern matches random braces in
# the decoded binary PSRP and floods the result with garbage.
_FLAG = re.compile(rb"(?:THM|FLAG|CTF)\{[^}\r\n]{1,120}\}", re.IGNORECASE)
_REG_SAVE = re.compile(r"reg save\s+\S+\s+(\S+)", re.IGNORECASE)
# Evil-WinRM wraps every command with an exit-code check; strip it to show the
# command the operator actually typed.
_WRAPPER = re.compile(r"[\r\n]+if \(!\$\?\).*$", re.DOTALL)


@dataclass
class WinRMResult:
    sessions: int = 0
    commands: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    exfiltrated_files: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.commands or self.flags)


def _reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    seen: set[int] = set()
    out = bytearray()
    for seq, payload in sorted(segments, key=lambda sp: sp[0]):
        if seq in seen:
            continue
        seen.add(seq)
        out += payload
    return bytes(out)


def _ntlm_tokens(stream: bytes) -> list[bytes]:
    tokens: list[bytes] = []
    for m in _NTLM_TOKEN.finditer(stream):
        blob = m.group(1)
        with contextlib.suppress(Exception):
            raw = base64.b64decode(blob + b"=" * (-len(blob) % 4))
            if raw.startswith(_NTLM):
                tokens.append(raw)
    return tokens


def _iter_sealed(stream: bytes):
    """Yield (sealed_payload, encrypted_checksum) for each sealed message."""
    pos = 0
    while True:
        m = _ORIG_LEN.search(stream, pos)
        if not m:
            return
        length = int(m.group(1))
        start = stream.find(_OCTET, m.end())
        if start == -1:
            return
        start += len(_OCTET)
        if start + 4 > len(stream):
            return
        sig_len = struct.unpack("<I", stream[start:start + 4])[0]
        sig = stream[start + 4:start + 4 + sig_len]
        sealed = stream[start + 4 + sig_len:start + 4 + sig_len + length]
        yield sealed, sig[4:12]
        pos = start + 4 + sig_len + length


def _decode_psrp(plaintext: bytes) -> bytes:
    """Concatenate every base64 PSRP fragment embedded in decrypted SOAP."""
    out = bytearray()
    for m in _B64_IN_XML.finditer(plaintext):
        blob = m.group(1)
        with contextlib.suppress(Exception):
            out += base64.b64decode(blob + b"=" * (-len(blob) % 4))
    return bytes(out)


def _unescape(text: str) -> str:
    for entity, char in (("&gt;", ">"), ("&lt;", "<"), ("&quot;", '"'), ("&amp;", "&")):
        text = text.replace(entity, char)
    return text


def _clean_command(value: str) -> str:
    return _unescape(_WRAPPER.sub("", value)).strip()


def decrypt_session(c2s: bytes, s2c: bytes, password: str) -> dict | None:
    """Decrypt one WinRM connection. Returns the commands, flags and exfiltrated
    file paths found, or None when this connection is not a decryptable session
    (no handshake, or the password does not match it)."""
    challenge = None
    for token in _ntlm_tokens(s2c):
        challenge = ntlm_seal.parse_challenge(token)
        if challenge is not None:
            break
    auth = None
    for token in _ntlm_tokens(c2s):
        auth = ntlm_seal.parse_authenticate(token)
        if auth is not None:
            break
    if challenge is None or auth is None:
        return None
    server_challenge, _flags = challenge
    exported = ntlm_seal.exported_session_key(password, auth, server_challenge)
    if exported is None:
        return None

    commands: list[str] = []
    flags: list[str] = []
    files: list[str] = []
    for stream, outbound in ((c2s, True), (s2c, False)):
        unsealer = ntlm_seal.Unsealer(
            ntlm_seal.sealing_key(exported, outbound_from_client=outbound))
        decoded_psrp = bytearray()
        for sealed, checksum in _iter_sealed(stream):
            plaintext = unsealer.unseal(sealed, checksum)
            decoded_psrp += _decode_psrp(plaintext)
            _collect_commands(plaintext, commands, files)
            _collect_flags(plaintext, flags)
        blob = bytes(decoded_psrp)
        _collect_commands(blob, commands, files)
        _collect_flags(blob, flags)

    return {"user": f"{auth.domain}\\{auth.user}", "commands": commands,
            "flags": flags, "files": files}


def _add_command(command: str, commands: list[str], files: list[str]) -> None:
    """Record one recovered command, dropping Evil-WinRM's own shell-driver noise."""
    if not command or command.lower() in _SHELL_NOISE or not any(c.isalpha() for c in command):
        return
    if command not in commands:
        commands.append(command)
    reg = _REG_SAVE.search(command)
    if reg and reg.group(1) not in files:
        files.append(reg.group(1))


def _collect_commands(data: bytes, commands: list[str], files: list[str]) -> None:
    """Pull the operator's commands out of decrypted WinRM traffic.

    Two shapes carry them: a bare ``<rsp:Command>`` (the WSMan Shell Evil-WinRM
    drives), and ``<rsp:Arguments>`` — a base64 PSRP blob whose ``<S N="V">``
    values are the real command, because Evil-WinRM runs every command as
    ``Invoke-Expression <arg>``. The ``Invoke-Expression`` wrapper and the
    ``(get-location).path`` prompt refresh it issues itself are dropped as noise,
    so what remains is what the operator actually typed. A ``<S N="V">`` taken
    from anywhere other than ``<rsp:Arguments>`` (PSRP state, pipeline metadata, a
    working-directory echo) is not a command and is deliberately left out.
    """
    for m in _RSP_COMMAND.finditer(data):
        _add_command(_clean_command(m.group(1).decode("utf-8", "replace")), commands, files)
    for am in _RSP_ARGS.finditer(data):
        try:
            decoded = base64.b64decode(am.group(1) + b"=" * (-len(am.group(1)) % 4))
        except Exception:  # noqa: BLE001 - a non-base64 arguments blob is simply skipped
            continue
        for m in _CMD_VALUE.finditer(decoded):
            _add_command(_clean_command(m.group(1).decode("utf-8", "replace")), commands, files)


def _collect_flags(data: bytes, flags: list[str]) -> None:
    for m in _FLAG.finditer(data):
        value = m.group(0).decode("ascii", "replace")
        if value not in flags:
            flags.append(value)


def _connections(pcap_path: str) -> dict[tuple, dict]:
    from scapy.layers.inet import IP, TCP
    from scapy.utils import PcapReader

    conns: dict[tuple, dict] = defaultdict(lambda: {"c2s": [], "s2c": []})
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                continue
            tcp = pkt[TCP]
            if tcp.sport != _WINRM_PORT and tcp.dport != _WINRM_PORT:
                continue
            payload = bytes(tcp.payload)
            if not payload:
                continue
            if tcp.dport == _WINRM_PORT:
                cid = (pkt[IP].src, int(tcp.sport))
                conns[cid]["c2s"].append((int(tcp.seq), payload))
            else:
                cid = (pkt[IP].dst, int(tcp.dport))
                conns[cid]["s2c"].append((int(tcp.seq), payload))
    return conns


def decrypt_capture(pcap_path: str, password: str) -> WinRMResult:
    """Decrypt every WinRM session in a capture that `password` unlocks."""
    result = WinRMResult()
    for streams in _connections(pcap_path).values():
        session = decrypt_session(_reassemble(streams["c2s"]),
                                  _reassemble(streams["s2c"]), password)
        if session is None:
            continue
        result.sessions += 1
        for command in session["commands"]:
            if command not in result.commands:
                result.commands.append(command)
        for flag in session["flags"]:
            if flag not in result.flags:
                result.flags.append(flag)
        for path in session["files"]:
            if path not in result.exfiltrated_files:
                result.exfiltrated_files.append(path)
    return result
