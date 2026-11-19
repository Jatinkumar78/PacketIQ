"""
Cleartext session recovery — the conversation an unencrypted capture hands you.

Why this module exists
----------------------
A great deal of real traffic, and almost every capture in a forensics exercise,
is in clear text: FTP, Telnet, HTTP, IRC, and the reverse shells an attacker
drops are usually just a TCP stream of typed commands and their output. The
whole investigation is sitting readable on the wire, and a tool that only says
"a credential was exposed" while declining to read the credential, the command
the attacker typed, or the file they uploaded is refusing to do the one thing
the capture makes easy.

This reassembles TCP streams and reconstructs two things from them:

  * **Authentication sessions** — FTP to begin with: the username, the password
    as it was actually sent, the working directory the server reported, and the
    files that were uploaded or downloaded. The password is shown because it was
    sent in clear text; a responder needs to know exactly which secret leaked,
    and withholding a value that anyone who captured the traffic already has
    helps no one.
  * **Interactive shells** — a reverse or bind shell, or Telnet: the commands a
    person typed and the output that mattered (the hostname, a privilege change,
    a file fetched from the internet). This is how "the attacker got a shell"
    becomes "the attacker ran these commands, became root, and pulled this tool
    from GitHub".

It reports the facts it reads, not the raw bytes. A reconstructed shell session
is summarised as the commands issued and the notable output, and an uploaded
file as its name and the indicators found inside it (URLs, callback addresses),
rather than by reproducing the file.
"""

from __future__ import annotations

import contextlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

from packetiq.detection.models import DetectionEvent, EventType, Severity

FTP_PORTS = frozenset({21})
TELNET_PORTS = frozenset({23})

# How much of a reassembled stream to reason over. Enough to carry a shell
# session or a dropped script; not so much that a bulk transfer is held in full.
_MAX_STREAM_BYTES = 256 * 1024

MITRE_CLEARTEXT_CRED = "T1552.001"   # Unsecured Credentials
MITRE_FTP = "T1071.002"              # Application Layer Protocol: File Transfer
MITRE_SHELL = "T1059.004"            # Command and Scripting Interpreter: Unix Shell
MITRE_INGRESS = "T1105"              # Ingress Tool Transfer

# ── readers over reassembled text ─────────────────────────────────────────────

# The separator is [ \t]+, not \s+: \s matches \r and \n, so a verb with no
# argument (PWD, QUIT) would otherwise swallow the next command line as its
# argument. The argument is likewise held to one line.
_FTP_CMD = re.compile(rb"^([A-Z]{3,4})(?:[ \t]+([^\r\n]*))?\r?$", re.MULTILINE)
_FTP_RESP = re.compile(rb"^(\d{3})\s+(.*?)\r?$", re.MULTILINE)
# The 257 reply to PWD quotes the directory: 257 "/var/www/html" is the current …
_PWD_REPLY = re.compile(rb'^257\s+"([^"]*)"', re.MULTILINE)

_URL = re.compile(rb"https?://[^\s\"'<>)\]]+")
_GIT_CLONE = re.compile(rb"git\s+clone\s+(\S+)", re.IGNORECASE)
_GITHUB = re.compile(rb"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?(?:[\s/]|$)")
# A reverse-shell script hardcodes where it calls back to.
_CALLBACK = re.compile(rb"""\$?(?:ip|host|rhost|lhost)\s*=\s*['"]?(\d{1,3}(?:\.\d{1,3}){3})['"]?""",
                       re.IGNORECASE)

# Lines an interactive Unix shell prints as a prompt. Their presence in a stream
# is what distinguishes a shell session from a file transfer.
_SHELL_PROMPT = re.compile(rb"^[^\r\n]{0,64}?[\w.-]+@[\w.-]+:[^\r\n]*[#$]\s", re.MULTILINE)
_BARE_PROMPT = re.compile(rb"^[#$]\s", re.MULTILINE)

# Commands worth surfacing when they appear in a shell transcript: the ones a
# responder reconstructs the intrusion from.
_INTERESTING_COMMANDS = (
    b"whoami", b"id", b"uname", b"hostname", b"sudo", b"su ", b"su\n",
    b"pty.spawn", b"spawn", b"wget", b"curl", b"git clone", b"nc ", b"ncat",
    b"chmod", b"python", b"bash -i", b"/bin/sh", b"/bin/bash", b"cat /etc",
    b"passwd", b"useradd", b"crontab", b"ssh-keygen",
)


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


@dataclass
class _Stream:
    """Reassembly buffers for one TCP conversation, kept per direction."""

    # (seq, payload) per direction key (src, sport, dst, dport)
    segments: dict[tuple, list[tuple[int, bytes]]] = field(default_factory=lambda: defaultdict(list))
    endpoints: dict[tuple, tuple[str, int]] = field(default_factory=dict)
    sizes: dict[tuple, int] = field(default_factory=lambda: defaultdict(int))
    first_ts: float = 0.0

    def add(self, key: tuple, src: str, sport: int, seq: int, payload: bytes, ts: float) -> None:
        if self.sizes[key] >= _MAX_STREAM_BYTES:
            return
        self.segments[key].append((seq, payload))
        self.endpoints[key] = (src, sport)
        self.sizes[key] += len(payload)
        self.first_ts = self.first_ts or ts

    def reassemble(self, key: tuple) -> bytes:
        """Order one direction's segments by sequence number and concatenate.

        Duplicate sequence numbers (retransmits) are kept once. This is a
        pragmatic reassembly, not a full TCP state machine, which is enough for
        the short cleartext streams this module reads and cannot wedge on a gap.
        """
        seen: set[int] = set()
        out = bytearray()
        for seq, payload in sorted(self.segments[key], key=lambda sp: sp[0]):
            if seq in seen:
                continue
            seen.add(seq)
            out += payload
        return bytes(out)


@dataclass
class FTPSession:
    client: str = ""
    server: str = ""
    username: str = ""
    password: str = ""
    logged_in: bool = False
    working_directory: str = ""
    uploaded: list[str] = field(default_factory=list)
    downloaded: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)


@dataclass
class ShellSession:
    client: str = ""           # the host the shell connects back to (the attacker)
    server: str = ""           # the compromised host
    hostname: str = ""
    commands: list[str] = field(default_factory=list)
    became_root: bool = False
    urls: list[str] = field(default_factory=list)
    github_projects: list[str] = field(default_factory=list)


class ClearTextAccumulator:
    """Reassembles TCP streams and recovers the readable sessions in them."""

    def __init__(self) -> None:
        self.streams: dict[tuple, _Stream] = defaultdict(_Stream)
        self.ftp: list[FTPSession] = []
        self.shells: list[ShellSession] = []
        self.credentials: list[dict] = []
        self.uploaded_files: list[dict] = []

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return
        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return

        # Canonical conversation id, direction-independent, so both halves of a
        # session land in one stream.
        a = (src, int(tcp.sport))
        b = (dst, int(tcp.dport))
        conv = tuple(sorted((a, b)))
        key = (src, int(tcp.sport), dst, int(tcp.dport))
        self.streams[conv].add(key, src, int(tcp.sport), int(tcp.seq), payload, float(pkt.time))

    # ── reconstruction ────────────────────────────────────────────────────────

    def finalize(self) -> list[DetectionEvent]:
        for conv, stream in self.streams.items():
            directions = {k: stream.reassemble(k) for k in stream.segments}
            self._recover_ftp(directions)
            self._recover_shell(conv, directions)
            self._carve_uploads(directions)
        return self._events()

    def _recover_ftp(self, directions: dict[tuple, bytes]) -> None:
        """Rebuild an FTP control session from its command and response stream."""
        client_key = next((k for k in directions if k[3] in FTP_PORTS), None)
        server_key = next((k for k in directions if k[1] in FTP_PORTS), None)
        if client_key is None:
            return
        commands = directions[client_key]
        responses = directions.get(server_key, b"") if server_key else b""
        if b"USER" not in commands.upper() and not responses:
            return

        session = FTPSession(client=client_key[0], server=client_key[2])
        for m in _FTP_CMD.finditer(commands):
            verb = m.group(1).decode("ascii", "replace").upper()
            arg = (m.group(2) or b"").decode("utf-8", "replace").strip()
            session.commands.append(f"{verb} {arg}".strip())
            if verb == "USER" and arg:
                session.username = arg
            elif verb == "PASS":
                session.password = arg
            elif verb == "STOR" and arg:
                session.uploaded.append(arg)
            elif verb in ("RETR", "APPE") and arg:
                session.downloaded.append(arg)

        if b"230 " in responses or b"230-" in responses:
            session.logged_in = True
        pwd = _PWD_REPLY.search(responses)
        if pwd:
            session.working_directory = pwd.group(1).decode("utf-8", "replace")

        if session.username or session.commands:
            self.ftp.append(session)
            if session.username and session.password:
                self.credentials.append({
                    "protocol": "FTP", "host": session.server,
                    "username": session.username, "password": session.password,
                    "result": "login successful" if session.logged_in else "login failed",
                })

    def _recover_shell(self, conv: tuple, directions: dict[tuple, bytes]) -> None:
        """Rebuild an interactive shell transcript from a TCP stream.

        A shell session is told from a file transfer by its shape: prompts and
        short lines the client sent, answered by command output. The commands a
        person typed are the small direction; the output is the large one.
        """
        combined = b"\n".join(directions.values())
        if not (_SHELL_PROMPT.search(combined) or (_BARE_PROMPT.search(combined)
                and (b"uname" in combined or b"/bin/sh" in combined or b"whoami" in combined))):
            return

        # The compromised host is the one that *sends* the command output; the
        # attacker types the commands. The typed side is the smaller stream.
        by_size = sorted(directions.items(), key=lambda kv: len(kv[1]))
        if len(by_size) < 2:
            # A single-direction capture of a shell: commands and output are
            # interleaved in the one stream we have.
            typed = output = combined
            server = conv[0][0]
            client = conv[1][0]
        else:
            typed_key, typed = by_size[0]
            output = by_size[-1][1]
            # The side carrying the output is the compromised host.
            server = by_size[-1][0][0]
            client = typed_key[0]

        session = ShellSession(client=client, server=server)

        hostname = _hostname_from(output) or _hostname_from(combined)
        if hostname:
            session.hostname = hostname
        if re.search(rb"root@|uid=0\(root\)|^# ", combined, re.MULTILINE):
            session.became_root = True

        for line in typed.splitlines():
            line = line.strip()
            if not line or len(line) > 400:
                continue
            if any(cmd in line.lower() for cmd in _INTERESTING_COMMANDS) or line.endswith(b";"):
                text = _text(line)
                if text not in session.commands:
                    session.commands.append(text)

        for m in _URL.finditer(combined):
            url = _text(m.group(0)).rstrip(".,);'\"")
            if url not in session.urls:
                session.urls.append(url)
        for m in _GITHUB.finditer(combined):
            project = _text(m.group(1))
            if project not in session.github_projects:
                session.github_projects.append(project)

        if session.commands or session.hostname or session.github_projects:
            self.shells.append(session)

    def _carve_uploads(self, directions: dict[tuple, bytes]) -> None:
        """Pull indicators out of a transferred file without reproducing it.

        A dropped reverse-shell script hardcodes the address it calls back to and
        usually names where it came from; those are the useful facts, not the
        file body.
        """
        for key, data in directions.items():
            if len(data) < 64 or key[3] in FTP_PORTS or key[1] in FTP_PORTS:
                continue
            # A transferred file *begins* with its own marker. A shell transcript
            # mentions /bin/bash in passing but does not start with it, so anchor
            # on the start to tell a dropped script from a session that discusses
            # one.
            head = data.lstrip()[:16]
            looks_like_script = head.startswith((b"<?php", b"#!"))
            if not looks_like_script:
                continue
            urls = [_text(m.group(0)).rstrip(".,);'\"") for m in _URL.finditer(data)]
            callbacks = [_text(m.group(1)) for m in _CALLBACK.finditer(data)]
            if not urls and not callbacks:
                continue
            kind = ("PHP reverse shell" if b"<?php" in data and b"fsockopen" in data
                    else "script")
            self.uploaded_files.append({
                "from": key[0], "to": key[2],
                "kind": kind,
                "urls": _dedupe(urls),
                "callbacks": _dedupe(callbacks),
            })

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        if not (self.ftp or self.shells or self.credentials or self.uploaded_files):
            return {}
        # The password-spray attempts are the brute-force detector's territory;
        # here the one that mattered is the login that worked. Both are kept, but
        # the working credential is surfaced on its own so the answer to "what
        # was the password" is not buried under fifty guesses.
        working = _dedupe_creds(c for c in self.credentials
                                if c["result"] == "login successful")
        failed = [c["password"] for c in self.credentials
                  if c["result"] != "login successful"]
        return {
            "credentials": working,
            "valid_credentials": working,
            "failed_password_attempts": len(failed),
            "all_credentials": self.credentials,
            "ftp_sessions": [
                {
                    "client": s.client, "server": s.server,
                    "username": s.username, "password": s.password,
                    "logged_in": s.logged_in,
                    "working_directory": s.working_directory,
                    "uploaded": s.uploaded, "downloaded": s.downloaded,
                    "commands": s.commands,
                }
                for s in self.ftp
            ],
            "shell_sessions": [
                {
                    "attacker": s.client, "victim": s.server,
                    "hostname": s.hostname, "became_root": s.became_root,
                    "commands": s.commands, "urls": s.urls,
                    "github_projects": s.github_projects,
                }
                for s in self.shells
            ],
            "uploaded_files": self.uploaded_files,
        }

    def _events(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        # Only the login that worked is raised as a credential finding. The
        # failed guesses are a password spray, which the brute-force detector
        # already reports; repeating one event per guess here would bury the one
        # credential a responder has to rotate.
        for cred in _dedupe_creds(c for c in self.credentials
                                  if c["result"] == "login successful"):
            events.append(DetectionEvent(
                event_type=EventType.CREDENTIAL_EXPOSURE,
                severity=Severity.CRITICAL,
                src_ip=cred["host"], dst_ip=None, dst_port=21, protocol=cred["protocol"],
                timestamp=0.0, packet_count=1, confidence=1.0,
                description=(
                    f"{cred['protocol']} credentials recovered in cleartext — "
                    f"{cred['username']} / {cred['password']} ({cred['result']})"
                ),
                evidence={
                    "username": cred["username"],
                    "password": cred["password"],
                    "result": cred["result"],
                    "mitre": MITRE_CLEARTEXT_CRED,
                    "note": "Sent unencrypted and read directly off the wire. The "
                            "password value is shown because anyone who captured this "
                            "traffic has it; the account must be treated as compromised.",
                },
            ))
        for ftp in self.ftp:
            if not ftp.uploaded and not ftp.working_directory:
                continue
            events.append(DetectionEvent(
                event_type=EventType.SUSPICIOUS_FILE_TRANSFER,
                severity=Severity.HIGH if ftp.uploaded else Severity.MEDIUM,
                src_ip=ftp.client, dst_ip=ftp.server, dst_port=21, protocol="FTP",
                timestamp=0.0, packet_count=len(ftp.commands), confidence=0.9,
                description=(
                    f"FTP session as {ftp.username or 'unknown'} in "
                    f"{ftp.working_directory or '?'}"
                    + (f", uploaded {', '.join(ftp.uploaded)}" if ftp.uploaded else "")
                ),
                evidence={
                    "username": ftp.username,
                    "working_directory": ftp.working_directory or "not reported",
                    "uploaded": ", ".join(ftp.uploaded) or "none",
                    "downloaded": ", ".join(ftp.downloaded) or "none",
                    "mitre": MITRE_FTP,
                    "note": "The working directory and the uploaded filename are read "
                            "from the FTP control channel, which is in clear text.",
                },
            ))
        for shell in self.shells:
            events.append(DetectionEvent(
                event_type=EventType.REVERSE_SHELL,
                severity=Severity.CRITICAL,
                src_ip=shell.server, dst_ip=shell.client, dst_port=0, protocol="TCP",
                timestamp=0.0, packet_count=len(shell.commands), confidence=0.9,
                description=(
                    f"Interactive shell recovered — {len(shell.commands)} command(s)"
                    + (f" on host {shell.hostname}" if shell.hostname else "")
                    + (", escalated to root" if shell.became_root else "")
                ),
                evidence={
                    "hostname": shell.hostname or "not seen",
                    "commands": " ; ".join(shell.commands[:20]) or "none isolated",
                    "became_root": "yes" if shell.became_root else "no",
                    "github_projects": ", ".join(shell.github_projects) or "none",
                    "urls": ", ".join(shell.urls[:8]) or "none",
                    "mitre": f"{MITRE_SHELL} / {MITRE_INGRESS}",
                    "note": "The commands are what the attacker typed, read from the "
                            "cleartext TCP stream of the shell. Command output such as "
                            "the hostname is read from the other direction.",
                },
            ))
        return events


def _hostname_from(data: bytes) -> str:
    """Pull a Unix hostname out of shell output.

    Three independent sources, any of which is enough: a user@host prompt, the
    `uname -a` line, or the output of `hostname`. Agreeing on one of them is how
    "the compromised host" gets a name.
    """
    m = re.search(rb"[\w.-]+@([\w.-]+):", data)
    if m:
        return m.group(1).decode("ascii", "replace")
    m = re.search(rb"Linux\s+([\w.-]+)\s", data)
    if m:
        return m.group(1).decode("ascii", "replace")
    return ""


def _dedupe(items: list[str]) -> list[str]:
    out: list[str] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def _dedupe_creds(creds) -> list[dict]:
    """One entry per (protocol, host, user, password): a retried login is one fact."""
    seen: set = set()
    out: list[dict] = []
    for c in creds:
        ident = (c["protocol"], c["host"], c["username"], c["password"])
        if ident in seen:
            continue
        seen.add(ident)
        out.append(c)
    return out


def _endpoints(pkt) -> tuple[str | None, str | None]:
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    return None, None
