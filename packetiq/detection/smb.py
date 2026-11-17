"""
SMB detection — who connected to which share, and what they touched.

Why this module exists
----------------------
SMB is how Windows hosts move laterally. The sequence is always the same:
negotiate, authenticate, connect to a share, open a file. Each step names
something a responder needs, and PacketIQ previously reported the whole of it
as "SMB on 10.0.2.75:445 is confirmed listening".

What each step gives up
-----------------------
  * **Session setup** carries SPNEGO, and inside it the NTLM type 3 message
    that names the account, the domain and the workstation the client called
    itself. It is decoded by `packetiq.detection.ntlm`, the same code that
    reads it out of a WinRM `Authorization` header.
  * **Tree connect** names the share as a UNC path. ``ADMIN$``, ``C$`` and the
    other administrative shares are not browsed by users; connecting to one is
    an administrative act, and over SMB it is the first half of how PsExec and
    its many descendants run code on a remote host. ``IPC$`` is how named
    pipes are reached, which is the other half.
  * **Create**, **Read** and **Write** name the file and the direction. A file
    written to ``ADMIN$`` is a payload being staged; a file read from a user
    share may be the data leaving.

SMB1 is reported wherever it appears. It has been deprecated for years, carries
the EternalBlue family, and a modern client does not negotiate it by accident.
"""

from __future__ import annotations

import contextlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from packetiq import config
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.detection.ntlm import NTLMIdentity, decode_ntlm

SMB_PORTS = frozenset({445, 139})

# SMB2 command numbers (MS-SMB2 2.2.1.1).
SMB2_NEGOTIATE, SMB2_SESSION_SETUP, SMB2_LOGOFF = 0, 1, 2
SMB2_TREE_CONNECT, SMB2_TREE_DISCONNECT = 3, 4
SMB2_CREATE, SMB2_CLOSE, SMB2_READ, SMB2_WRITE, SMB2_IOCTL = 5, 6, 8, 9, 11

COMMAND_NAMES = {
    0: "Negotiate", 1: "Session Setup", 2: "Logoff", 3: "Tree Connect",
    4: "Tree Disconnect", 5: "Create", 6: "Close", 7: "Flush", 8: "Read",
    9: "Write", 10: "Lock", 11: "IOCTL", 12: "Cancel", 13: "Echo",
    14: "Query Directory", 15: "Change Notify", 16: "Query Info",
    17: "Set Info", 18: "Oplock Break",
}

# Shares Windows creates for administration, not for people. Connecting to one
# is an administrative act; the named-pipe share is how remote service control
# and scheduled tasks are reached.
ADMIN_SHARES = {"admin$", "c$", "d$", "ipc$", "print$", "sysvol", "netlogon"}
EXECUTION_SHARES = {"admin$", "c$", "ipc$"}

# Named pipes that mean remote execution rather than remote reading.
EXECUTION_PIPES = {
    "svcctl": "remote service control (PsExec and similar)",
    "atsvc": "remote scheduled task (at.exe)",
    "winreg": "remote registry",
    "samr": "SAM database access",
    "lsarpc": "LSA policy access",
    "srvsvc": "share enumeration",
    "spoolss": "print spooler (PrintNightmare surface)",
}

MITRE_SMB_SHARE = "T1021.002"   # Remote Services: SMB/Windows Admin Shares
MITRE_SMB_EXEC  = "T1569.002"   # System Services: Service Execution
MITRE_TRANSFER  = "T1570"       # Lateral Tool Transfer
MITRE_SMB1      = "T1210"       # Exploitation of Remote Services


def _buffer_value(packet, name: str) -> object | None:
    """Pull one named entry out of scapy's SMB2 ``Buffer`` list.

    scapy models the variable-length tail of an SMB2 message as a list of
    ``(name, value)`` pairs rather than as attributes, so the share path and
    the filename are not where attribute access would look for them.
    """
    with contextlib.suppress(Exception):
        for entry in getattr(packet, "Buffer", None) or []:
            if isinstance(entry, (tuple, list)) and len(entry) == 2 and entry[0] == name:
                return entry[1]
    return None


def _text(value) -> str:
    """Decode an SMB2 string field, which arrives as UTF-16LE bytes or as str."""
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if b"\x00" in raw:
            return raw.decode("utf-16-le", "replace").rstrip("\x00")
        return raw.decode("utf-8", "replace")
    return str(value)


def share_name(path: str) -> str:
    """``\\\\ADSERVER\\ADMIN$`` -> ``ADMIN$``; a bare name is returned as-is."""
    return path.replace("/", "\\").rstrip("\\").rpartition("\\")[2] or path


@dataclass
class SMBOperation:
    ts: float
    src: str
    dst: str
    dst_port: int
    command: int
    name: str = ""
    share: str = ""
    filename: str = ""
    dialect: str = "SMB2"
    identity: NTLMIdentity | None = None
    anonymous: bool = False
    bytes_moved: int = 0


@dataclass
class _SessionState:
    operations: int = 0
    commands: Counter = field(default_factory=Counter)
    shares: Counter = field(default_factory=Counter)
    files_opened: Counter = field(default_factory=Counter)
    pipes: dict[str, str] = field(default_factory=dict)
    identities: dict[tuple[str, str, str], NTLMIdentity] = field(default_factory=dict)
    bytes_read: int = 0
    bytes_written: int = 0
    anonymous_sessions: int = 0
    smb1: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0
    dst_port: int = 445

    @property
    def duration(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)

    def admin_shares(self) -> list[str]:
        return sorted(s for s in self.shares if share_name(s).lower() in ADMIN_SHARES)

    def execution_shares(self) -> list[str]:
        return sorted(s for s in self.shares if share_name(s).lower() in EXECUTION_SHARES)


class SMBAccumulator:
    """Collects SMB operations over one PCAP pass."""

    def __init__(self) -> None:
        self.operations: list[SMBOperation] = []
        self.sessions: dict[tuple[str, str], _SessionState] = defaultdict(_SessionState)

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.smb import SMB_Header
        from scapy.layers.smb2 import SMB2_Header

        is_smb2 = pkt.haslayer(SMB2_Header)
        is_smb1 = pkt.haslayer(SMB_Header)
        if not is_smb2 and not is_smb1:
            return
        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return
        port = _server_port(pkt)
        if port is None:
            return

        try:
            operation = (self._decode_smb2(pkt, src, dst, port) if is_smb2
                         else SMBOperation(ts=float(pkt.time), src=src, dst=dst,
                                           dst_port=port, command=-1,
                                           name="SMB1", dialect="SMB1"))
        except Exception:
            return

        self.operations.append(operation)
        self._absorb(operation)

    def _decode_smb2(self, pkt, src, dst, port) -> SMBOperation:
        from scapy.layers.smb2 import SMB2_Header

        header = pkt[SMB2_Header]
        command = int(header.Command)
        operation = SMBOperation(
            ts=float(pkt.time), src=src, dst=dst, dst_port=port,
            command=command, name=COMMAND_NAMES.get(command, f"command {command}"),
        )
        body = header.payload

        if command == SMB2_TREE_CONNECT:
            operation.share = _text(_buffer_value(body, "Path"))
        elif command == SMB2_CREATE:
            operation.filename = _text(_buffer_value(body, "Name"))
        elif command == SMB2_SESSION_SETUP:
            blob = _buffer_value(body, "SecurityBlob")
            operation.identity, operation.anonymous = _authentication_from_blob(blob)
        elif command == SMB2_READ:
            # A Read request states how many bytes it wants in `Length`.
            operation.bytes_moved = int(getattr(body, "Length", 0) or 0)
        elif command == SMB2_WRITE:
            # A Write request carries the data, and its size is `DataLen`, not
            # `Length` -- the two SMB2 structures name the same idea differently,
            # and reading the wrong one silently counted every write as zero.
            operation.bytes_moved = int(getattr(body, "DataLen", 0) or 0)
        return operation

    def _absorb(self, operation: SMBOperation) -> None:
        state = self.sessions[(operation.src, operation.dst)]
        state.operations += 1
        state.first_ts = state.first_ts or operation.ts
        state.last_ts = operation.ts
        state.dst_port = operation.dst_port
        state.commands[operation.name] += 1

        if operation.dialect == "SMB1":
            state.smb1 = True
        if operation.share:
            state.shares[operation.share] += 1
        if operation.filename:
            state.files_opened[operation.filename] += 1
            pipe = operation.filename.strip("\\").lower()
            if pipe in EXECUTION_PIPES:
                state.pipes[pipe] = EXECUTION_PIPES[pipe]
        if operation.identity is not None:
            state.identities[operation.identity.key] = operation.identity
        if operation.anonymous:
            state.anonymous_sessions += 1
        if operation.command == SMB2_READ:
            state.bytes_read += operation.bytes_moved
        elif operation.command == SMB2_WRITE:
            state.bytes_written += operation.bytes_moved

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        if not self.operations:
            return {}

        commands: Counter = Counter()
        shares: Counter = Counter()
        files: Counter = Counter()
        pipes: dict[str, str] = {}
        identities: dict[tuple[str, str, str], NTLMIdentity] = {}
        for state in self.sessions.values():
            commands.update(state.commands)
            shares.update(state.shares)
            files.update(state.files_opened)
            pipes.update(state.pipes)
            identities.update(state.identities)

        return {
            "operations": len(self.operations),
            "sessions": len(self.sessions),
            "clients": sorted({src for src, _ in self.sessions}),
            "servers": sorted({dst for _, dst in self.sessions}),
            "commands": dict(commands.most_common()),
            "shares": dict(shares.most_common(20)),
            "files": dict(files.most_common(25)),
            "named_pipes": pipes,
            "accounts": [
                {"user": i.user, "domain": i.domain, "workstation": i.workstation}
                for i in identities.values()
            ],
            "bytes_read": sum(s.bytes_read for s in self.sessions.values()),
            "bytes_written": sum(s.bytes_written for s in self.sessions.values()),
            "anonymous_sessions": sum(s.anonymous_sessions for s in self.sessions.values()),
            "smb1_seen": any(s.smb1 for s in self.sessions.values()),
        }

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        min_ops = config.get("smb", "session_min_operations", 3)

        for (src, dst), state in self.sessions.items():
            events.extend(self._lateral_movement(src, dst, state))
            events.extend(self._file_activity(src, dst, state, min_ops))
            events.extend(self._identity(src, dst, state))
            events.extend(self._protocol_concerns(src, dst, state))
        return events

    def _lateral_movement(self, src, dst, state) -> list[DetectionEvent]:
        """A connection to an administrative share, and what was reached through it."""
        admin = state.execution_shares()
        if not admin and not state.pipes:
            return []

        who = sorted(str(i) for i in state.identities.values())
        pipes = sorted(state.pipes)
        severity = Severity.CRITICAL if state.pipes else Severity.HIGH
        return [DetectionEvent(
            event_type=EventType.SMB_LATERAL_MOVEMENT,
            severity=severity,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="SMB",
            timestamp=state.first_ts,
            packet_count=state.operations,
            confidence=0.9,
            description=(
                "SMB administrative access — "
                + (f"connected to {', '.join(share_name(s) for s in admin)}" if admin
                   else "named-pipe access")
                + (f", opened {', '.join(pipes)}" if pipes else "")
                + (f", as {who[0]}" if who else "")
            ),
            evidence={
                "admin_shares": ", ".join(admin) or "none",
                "named_pipes": "; ".join(f"{p} = {state.pipes[p]}" for p in pipes) or "none",
                "authenticated_as": ", ".join(who) if who else "not observed",
                "all_shares": ", ".join(state.shares) or "none seen",
                "files_opened": ", ".join(list(state.files_opened)[:10]) or "none",
                "mitre": f"{MITRE_SMB_SHARE} / {MITRE_SMB_EXEC}",
                "note": "Administrative shares are not browsed by users. A named "
                        "pipe such as svcctl or atsvc is how a remote service or "
                        "scheduled task is created, which is remote code execution.",
            },
        )]

    def _file_activity(self, src, dst, state, min_ops) -> list[DetectionEvent]:
        """Files opened over SMB, and how much data moved in each direction."""
        if not state.files_opened or state.operations < min_ops:
            return []
        # A pipe is not a file; lateral movement already reports those.
        files = [f for f in state.files_opened if f.strip("\\").lower() not in EXECUTION_PIPES]
        if not files:
            return []

        moved = state.bytes_read + state.bytes_written
        return [DetectionEvent(
            event_type=EventType.SMB_FILE_ACCESS,
            severity=Severity.HIGH if state.bytes_written else Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="SMB",
            timestamp=state.first_ts,
            packet_count=state.operations,
            confidence=0.85,
            description=(
                f"SMB file activity — {len(files)} file(s) opened, "
                f"{state.bytes_written:,} bytes written and {state.bytes_read:,} read"
            ),
            evidence={
                "files": ", ".join(files[:12]),
                "file_count": len(files),
                "shares": ", ".join(state.shares) or "not seen",
                "bytes_written": state.bytes_written,
                "bytes_read": state.bytes_read,
                "bytes_total": moved,
                "direction": ("written to the server" if state.bytes_written > state.bytes_read
                              else "read from the server"),
                "mitre": MITRE_TRANSFER,
                "note": "A write to an administrative share is a payload being "
                        "staged; a large read from a user share may be the data "
                        "leaving. Both are named here rather than summarised.",
            },
        )]

    def _identity(self, src, dst, state) -> list[DetectionEvent]:
        """The account that authenticated, lifted from SPNEGO in session setup."""
        if not state.identities:
            return []
        who = sorted(str(i) for i in state.identities.values())
        workstations = sorted({i.workstation for i in state.identities.values() if i.workstation})
        return [DetectionEvent(
            event_type=EventType.NTLM_AUTHENTICATION,
            severity=Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="SMB",
            timestamp=state.first_ts,
            packet_count=len(state.identities),
            confidence=1.0,
            description=f"NTLM authentication over SMB — {', '.join(who)}",
            evidence={
                "accounts": ", ".join(who),
                "workstations_claimed": ", ".join(workstations) or "not sent",
                "shares_reached": ", ".join(state.shares) or "none",
                "mitre": "T1021.002",
                "note": "Read from the NTLM type 3 message inside the SPNEGO blob "
                        "of an SMB2 session setup. The workstation name is what the "
                        "client called itself, not proof of the machine's identity.",
            },
        )]

    def _protocol_concerns(self, src, dst, state) -> list[DetectionEvent]:
        """SMB used in ways a domain member does not use it."""
        events: list[DetectionEvent] = []
        events.extend(self._null_session(src, dst, state))
        events.extend(self._legacy_dialect(src, dst, state))
        return events

    def _null_session(self, src, dst, state) -> list[DetectionEvent]:
        """An NTLM type 3 that names nobody: an anonymous SMB session.

        Every name length and the NT response length are zero. That is not a
        failed logon, it is a deliberate unauthenticated bind, and it is what a
        scanner sends to fingerprint a host or to try enumerating shares and
        accounts without credentials.
        """
        if not state.anonymous_sessions:
            return []
        return [DetectionEvent(
            event_type=EventType.PROTOCOL_MISUSE,
            severity=Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="SMB",
            timestamp=state.first_ts,
            packet_count=state.anonymous_sessions,
            confidence=0.9,
            description=(
                f"Anonymous SMB session (null session) — {state.anonymous_sessions} "
                f"session setup(s) authenticated as nobody"
            ),
            evidence={
                "anonymous_session_setups": state.anonymous_sessions,
                "shares_reached": ", ".join(state.shares) or "none",
                "mitre": "T1087 / T1135",
                "note": "The NTLM message carried no username, domain, workstation "
                        "or NT response: a deliberate unauthenticated bind rather "
                        "than a failed logon. It is how a host is fingerprinted and "
                        "how shares and accounts are enumerated without credentials.",
            },
        )]

    def _legacy_dialect(self, src, dst, state) -> list[DetectionEvent]:
        """SMB1 on the wire in a year when nothing should be speaking it."""
        if not state.smb1:
            return []
        return [DetectionEvent(
            event_type=EventType.PROTOCOL_MISUSE,
            severity=Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="SMB1",
            timestamp=state.first_ts,
            packet_count=state.commands.get("SMB1", 1),
            confidence=0.8,
            description=(
                "SMB1 negotiated — a dialect deprecated since 2014 and the one the "
                "EternalBlue family targets"
            ),
            evidence={
                "dialect": "SMB1 / CIFS",
                "mitre": MITRE_SMB1,
                "note": "A current Windows client does not negotiate SMB1 unless it "
                        "was deliberately re-enabled, or unless the client is not "
                        "Windows. Scanners negotiate it to fingerprint the host.",
            },
        )]


def _authentication_from_blob(blob) -> tuple[NTLMIdentity | None, bool]:
    """Read the SPNEGO blob of a session setup: (identity, was_anonymous).

    The blob is a GSSAPI structure with NTLM nested somewhere inside it, and
    which layer holds it varies by client. Searching the serialised bytes for
    the NTLMSSP signature is both simpler and more tolerant than walking a
    structure that different clients nest differently.

    A type 3 message that names nobody is not a parse failure, it is an
    anonymous session, so the two cases are returned separately rather than
    both collapsing to None.
    """
    if blob is None:
        return None, False
    with contextlib.suppress(Exception):
        import base64

        raw = bytes(blob)
        start = raw.find(b"NTLMSSP\x00")
        if start < 0:
            return None, False
        token = raw[start:]
        identity, is_ntlm = decode_ntlm(base64.b64encode(token).decode("ascii"))
        if identity is not None:
            return identity, False
        # Type 3 with no identity at all is the null-session signature.
        anonymous = is_ntlm and len(token) >= 12 and \
            int.from_bytes(token[8:12], "little") == 3
        return None, anonymous
    return None, False


def _server_port(pkt) -> int | None:
    with contextlib.suppress(Exception):
        from scapy.layers.inet import TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            for port in (tcp.dport, tcp.sport):
                if port in SMB_PORTS:
                    return int(port)
    return None


def _endpoints(pkt) -> tuple[str | None, str | None]:
    """Client and server addresses, oriented so the server is the SMB side."""
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None, None
        if pkt.haslayer(TCP) and pkt[TCP].sport in SMB_PORTS:
            return dst, src
        return src, dst
    return None, None
