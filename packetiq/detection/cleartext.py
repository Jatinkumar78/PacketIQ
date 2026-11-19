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

import base64
import binascii
import contextlib
import re
from collections import defaultdict
from dataclasses import dataclass, field

from packetiq.detection.models import DetectionEvent, EventType, Severity

FTP_PORTS = frozenset({21})
TELNET_PORTS = frozenset({23})
SMTP_PORTS = frozenset({25, 587})
IRC_PORTS = frozenset({6667, 6660, 6661, 6662, 6663, 6664, 6665, 6666})
_PROTO_PORTS = {"FTP": 21, "SMTP": 25, "IRC": 6667, "TELNET": 23}

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


# SMTP: the envelope and the message, read from the command stream.
_SMTP_MAIL_FROM = re.compile(rb"MAIL FROM:\s*<?([^>\r\n]+)>?", re.IGNORECASE)
_SMTP_RCPT_TO = re.compile(rb"RCPT TO:\s*<?([^>\r\n]+)>?", re.IGNORECASE)
_SMTP_SUBJECT = re.compile(rb"^Subject:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_SMTP_AUTH_LOGIN = re.compile(rb"AUTH\s+LOGIN", re.IGNORECASE)
_SMTP_AUTH_PLAIN = re.compile(rb"AUTH\s+PLAIN\s+([A-Za-z0-9+/]{4,}={0,2})", re.IGNORECASE)
_B64_LINE = re.compile(rb"^([A-Za-z0-9+/]{4,}={0,2})\r?$", re.MULTILINE)

# IRC: the nick, the channels joined, and the messages — the chat itself.
_IRC_NICK = re.compile(rb"^NICK\s+([^\r\n ]+)", re.IGNORECASE | re.MULTILINE)
_IRC_JOIN = re.compile(rb"^JOIN\s+([^\r\n ]+)", re.IGNORECASE | re.MULTILINE)
_IRC_PRIVMSG = re.compile(rb"PRIVMSG\s+([^\r\n ]+)\s+:([^\r\n]*)", re.IGNORECASE)
_IRC_PASS = re.compile(rb"^PASS\s+([^\r\n]+)", re.IGNORECASE | re.MULTILINE)

# Telnet: the login prompts a device echoes, so the credential can be read. The
# separator is [ \t]*, not \s*: \s matches \r and \n, so an empty "login: \r\n"
# prompt would otherwise swallow the next line as the username (the same trap the
# FTP command parser hit).
_TELNET_LOGIN_PROMPT = re.compile(rb"(?:login|user ?name):[ \t]*", re.IGNORECASE)
_TELNET_PASS_PROMPT = re.compile(rb"password:[ \t]*", re.IGNORECASE)


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


@dataclass
class EmailSession:
    client: str = ""
    server: str = ""
    mail_from: str = ""
    recipients: list[str] = field(default_factory=list)
    subject: str = ""
    username: str = ""
    password: str = ""


@dataclass
class IRCSession:
    client: str = ""
    server: str = ""
    nick: str = ""
    channels: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    password: str = ""


@dataclass
class TelnetLogin:
    client: str = ""
    server: str = ""
    username: str = ""
    password: str = ""


class ClearTextAccumulator:
    """Reassembles TCP streams and recovers the readable sessions in them."""

    def __init__(self) -> None:
        self.streams: dict[tuple, _Stream] = defaultdict(_Stream)
        self.ftp: list[FTPSession] = []
        self.shells: list[ShellSession] = []
        self.emails: list[EmailSession] = []
        self.irc: list[IRCSession] = []
        self.telnet_logins: list[TelnetLogin] = []
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
            self._recover_smtp(directions)
            self._recover_irc(directions)
            self._recover_telnet(directions)
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

    def _recover_smtp(self, directions: dict[tuple, bytes]) -> None:
        """Rebuild an email from the SMTP command stream: envelope, subject, login."""
        client_key = next((k for k in directions if k[3] in SMTP_PORTS), None)
        if client_key is None:
            return
        data = directions[client_key]
        if not (_SMTP_MAIL_FROM.search(data) or _SMTP_AUTH_LOGIN.search(data)
                or _SMTP_AUTH_PLAIN.search(data)):
            return

        session = EmailSession(client=client_key[0], server=client_key[2])
        mail_from = _SMTP_MAIL_FROM.search(data)
        if mail_from:
            session.mail_from = _text(mail_from.group(1)).strip()
        for m in _SMTP_RCPT_TO.finditer(data):
            rcpt = _text(m.group(1)).strip()
            if rcpt and rcpt not in session.recipients:
                session.recipients.append(rcpt)
        subject = _SMTP_SUBJECT.search(data)
        if subject:
            session.subject = _text(subject.group(1)).strip()
        auth = _smtp_auth(data)
        if auth:
            session.username, session.password = auth

        if session.mail_from or session.recipients or session.username:
            self.emails.append(session)
            if session.username and session.password:
                self.credentials.append({
                    "protocol": "SMTP", "host": session.server,
                    "username": session.username, "password": session.password,
                    "result": "login successful"})

    def _recover_irc(self, directions: dict[tuple, bytes]) -> None:
        """Recover an IRC session: the nick, the channels joined, and the messages."""
        client_key = next((k for k in directions if k[3] in IRC_PORTS), None)
        server_key = next((k for k in directions if k[1] in IRC_PORTS), None)
        if client_key is None:
            return
        client_data = directions[client_key]
        server_data = directions.get(server_key, b"") if server_key else b""
        if not (_IRC_NICK.search(client_data) or _IRC_PRIVMSG.search(client_data + server_data)):
            return

        session = IRCSession(client=client_key[0], server=client_key[2])
        nick = _IRC_NICK.search(client_data)
        if nick:
            session.nick = _text(nick.group(1))
        for m in _IRC_JOIN.finditer(client_data):
            channel = _text(m.group(1))
            if channel not in session.channels:
                session.channels.append(channel)
        for data in (client_data, server_data):
            for m in _IRC_PRIVMSG.finditer(data):
                entry = f"{_text(m.group(1))}: {_text(m.group(2))}".strip()
                if entry not in session.messages:
                    session.messages.append(entry)
        password = _IRC_PASS.search(client_data)
        if password:
            session.password = _text(password.group(1)).strip()

        if session.nick or session.messages:
            self.irc.append(session)
            if session.password:
                self.credentials.append({
                    "protocol": "IRC", "host": session.server,
                    "username": session.nick or "(none)", "password": session.password,
                    "result": "server password"})

    def _recover_telnet(self, directions: dict[tuple, bytes]) -> None:
        """Recover a Telnet login from the prompts the server echoes."""
        client_key = next((k for k in directions if k[3] in TELNET_PORTS), None)
        server_key = next((k for k in directions if k[1] in TELNET_PORTS), None)
        if client_key is None or server_key is None:
            return
        server_data = _strip_iac(directions[server_key])
        client_data = _strip_iac(directions[client_key])
        if not _TELNET_LOGIN_PROMPT.search(server_data):
            return

        username, password = _telnet_creds(server_data, client_data)
        if not (username or password):
            return
        self.telnet_logins.append(TelnetLogin(
            client=client_key[0], server=client_key[2],
            username=username, password=password))
        if username and password:
            self.credentials.append({
                "protocol": "TELNET", "host": client_key[2],
                "username": username, "password": password, "result": "login"})

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
        if not (self.ftp or self.shells or self.credentials or self.uploaded_files
                or self.emails or self.irc or self.telnet_logins):
            return {}
        # The password-spray attempts are the brute-force detector's territory;
        # here the one that mattered is the login that worked. Both are kept, but
        # the working credential is surfaced on its own so the answer to "what
        # was the password" is not buried under fifty guesses.
        working = _dedupe_creds(c for c in self.credentials
                                if c["result"] != "login failed")
        failed = [c["password"] for c in self.credentials
                  if c["result"] == "login failed"]
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
            "email_sessions": [
                {
                    "client": s.client, "server": s.server,
                    "mail_from": s.mail_from, "recipients": s.recipients,
                    "subject": s.subject, "username": s.username,
                }
                for s in self.emails
            ],
            "irc_sessions": [
                {
                    "client": s.client, "server": s.server, "nick": s.nick,
                    "channels": s.channels, "messages": s.messages,
                }
                for s in self.irc
            ],
            "telnet_logins": [
                {
                    "client": s.client, "server": s.server,
                    "username": s.username, "password": s.password,
                }
                for s in self.telnet_logins
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
                                  if c["result"] != "login failed"):
            events.append(DetectionEvent(
                event_type=EventType.CREDENTIAL_EXPOSURE,
                severity=Severity.CRITICAL,
                src_ip=cred["host"], dst_ip=None,
                dst_port=_PROTO_PORTS.get(cred["protocol"]), protocol=cred["protocol"],
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


def _b64_text(token: bytes) -> str | None:
    """Decode a base64 token to text, or None if it is not valid base64."""
    try:
        return base64.b64decode(token, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None


def _smtp_auth(data: bytes) -> tuple[str, str] | None:
    """Recover SMTP AUTH credentials: PLAIN (one blob) or LOGIN (two b64 lines)."""
    plain = _SMTP_AUTH_PLAIN.search(data)
    if plain:
        try:
            raw = base64.b64decode(plain.group(1), validate=True)
        except (binascii.Error, ValueError):
            raw = b""
        parts = raw.split(b"\x00")
        if len(parts) >= 3:
            return _text(parts[1]), _text(parts[2])
    login = _SMTP_AUTH_LOGIN.search(data)
    if login:
        tokens = _B64_LINE.findall(data[login.end():])
        if len(tokens) >= 2:
            user, password = _b64_text(tokens[0]), _b64_text(tokens[1])
            if user is not None and password is not None:
                return user, password
    return None


_IAC_RE = re.compile(rb"\xff(?:[\xfb-\xfe].|[\xf0-\xfa\xff])")


def _strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC negotiation sequences so prompts read as plain text."""
    return _IAC_RE.sub(b"", data)


def _printable(data: bytes) -> str:
    return bytes(b for b in data if 0x20 <= b < 0x7f or b == 0x09).decode("ascii", "replace")


def _telnet_creds(server_data: bytes, client_data: bytes) -> tuple[str, str]:
    """Username from the server's echo after the login prompt; password from the
    client's typed line when the server also showed a password prompt."""
    username, password = "", ""
    prompt = _TELNET_LOGIN_PROMPT.search(server_data)
    if prompt:
        username = _printable(re.split(rb"[\r\n]", server_data[prompt.end():], maxsplit=1)[0]).strip()
    if _TELNET_PASS_PROMPT.search(server_data):
        typed = [t for t in (_printable(x).strip()
                             for x in re.split(rb"[\r\n]+", client_data)) if t]
        password = next((t for t in typed if t != username), "")
    return username, password


def _endpoints(pkt) -> tuple[str | None, str | None]:
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    return None, None
