"""
WinRM / PowerShell Remoting detection, and the NTLM identity that rides it.

Why this module exists
----------------------
On the Active Directory capture that prompted the Kerberos work, 792 of the
1,823 HTTP requests were POSTs to ``/wsman`` on port 5985. That is Windows
Remote Management: the channel an operator, or an intruder, runs commands
through. PacketIQ classified one of them as a generic "Suspicious HTTP
User-Agent" and said nothing about the other 791, so the single most important
fact in the capture -- somebody had a remote shell on the domain controller --
was never stated.

What is readable, and what is not
---------------------------------
PowerShell Remoting wraps its payload in
``multipart/encrypted; protocol="application/HTTP-SPNEGO-session-encrypted"``,
so the commands themselves are not recoverable from the packets, and this
module does not pretend otherwise. What stays in clear text is everything
around them, and it is enough to answer the questions a responder asks:

  * the ``Authorization: Negotiate`` header, whose NTLM type 3 message carries
    the **account**, the **domain** and the **workstation name the client chose
    to send**, all unencrypted,
  * the ``User-Agent``, which distinguishes a Windows admin host from tooling:
    Microsoft's own client announces itself, and ``Ruby WinRM Client`` or
    ``Python PSRP Client`` does not run on a domain-joined workstation by
    accident,
  * the volume and duration of the exchange, which separates one management
    action from a sustained session.

On the source capture that yields: account ``larry.doe``, domain
``directory.thm``, workstation ``KALI``. The same ``larry.doe`` the Kerberos
module had already flagged as AS-REP roastable, which is the whole attack
written out in two protocols.
"""

from __future__ import annotations

import contextlib
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from packetiq import config
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.detection.ntlm import NTLMIdentity, decode_ntlm

WINRM_PORTS = frozenset({5985, 5986})
WINRM_HTTPS_PORT = 5986

# The endpoint every WS-Management request is addressed to.
WSMAN_PATH = "/wsman"

# PowerShell Remoting names this resource URI in its SOAP envelope; WMI/CIM over
# WinRM names a different one. Only visible while the envelope is in clear text,
# which it is until session encryption is negotiated.
PSRP_RESOURCE = "powershell/microsoft.powershell"
WMI_RESOURCE = "wbem/wsman"

# WS-Management actions worth naming, lower-cased for matching.
SHELL_ACTIONS = {
    "transfer/create": "opened a shell",
    "shell/command": "ran a command",
    "shell/receive": "read command output",
    "shell/send": "sent input to a command",
    "shell/signal": "signalled a command",
    "transfer/delete": "closed a shell",
}

# Microsoft's own client identifies itself. Anything else driving WS-Management
# is a deliberate choice of tooling, and these are the ones that show up.
MICROSOFT_CLIENT = "microsoft winrm client"
TOOLING_AGENTS = (
    "ruby winrm",
    "python psrp",
    "python-requests",
    "pypsrp",
    "winrm-cli",
    "evil-winrm",
    "go-winrm",
    "curl/",
)

MITRE_WINRM = "T1021.006"      # Remote Services: Windows Remote Management
MITRE_NTLM  = "T1557.001"      # Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay
MITRE_EXEC  = "T1059.001"      # Command and Scripting Interpreter: PowerShell

_REQUEST_LINE = re.compile(rb"^([A-Z]{3,10}) (\S+) HTTP/1\.[01]\r\n")
_NTLM_SCHEME = re.compile(r"^(?:Negotiate|NTLM)\s+(\S+)$", re.IGNORECASE)
_NTLM_MAGIC = b"NTLMSSP\x00"


@dataclass
class WinRMRequest:
    """One WS-Management request, reduced to what survives encryption."""

    ts: float
    src: str
    dst: str
    dst_port: int
    method: str = ""
    path: str = ""
    user_agent: str = ""
    content_type: str = ""
    auth_scheme: str = ""
    action: str = ""
    resource: str = ""
    encrypted: bool = False
    body_bytes: int = 0


@dataclass
class _SessionState:
    """One client talking WS-Management to one server."""

    requests: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    dst_port: int = 5985
    agents: Counter = field(default_factory=Counter)
    content_types: Counter = field(default_factory=Counter)
    actions: Counter = field(default_factory=Counter)
    identities: dict[tuple[str, str, str], NTLMIdentity] = field(default_factory=dict)
    ntlm_messages: int = 0
    encrypted_requests: int = 0
    cleartext_requests: int = 0
    psrp: bool = False
    wmi: bool = False
    body_bytes: int = 0

    @property
    def duration(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)

    def tooling_agents(self) -> list[str]:
        """User-Agents that are not Microsoft's WS-Management client."""
        return sorted(
            agent for agent in self.agents
            if agent and MICROSOFT_CLIENT not in agent.lower()
            and any(marker in agent.lower() for marker in TOOLING_AGENTS)
        )


def _parse_head(payload: bytes) -> tuple[str, str, dict[str, str], int] | None:
    """Split an HTTP request into (method, path, headers, body length).

    Hand-parsed rather than handed to scapy's HTTP layer, which binds to port 80
    and would need rebinding per port; WS-Management runs on 5985 and 5986, and
    a request head is a few lines of ASCII either way.
    """
    match = _REQUEST_LINE.match(payload)
    if match is None:
        return None
    method = match.group(1).decode("ascii")
    path = match.group(2).decode("ascii", "replace")

    head, sep, body = payload.partition(b"\r\n\r\n")
    headers: dict[str, str] = {}
    for line in head.split(b"\r\n")[1:]:
        name, colon, value = line.partition(b":")
        if colon:
            headers[name.decode("ascii", "replace").strip().lower()] = \
                value.decode("utf-8", "replace").strip()
    return method, path, headers, len(body) if sep else 0


class WinRMAccumulator:
    """Collects WS-Management requests over one PCAP pass.

    ``feed(pkt)`` filters internally so this shares the engine's existing
    raw-packet loop with the Kerberos, TLS and file-carving accumulators.
    """

    def __init__(self) -> None:
        self.requests: list[WinRMRequest] = []
        self.sessions: dict[tuple[str, str], _SessionState] = defaultdict(_SessionState)

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        if tcp.dport not in WINRM_PORTS:
            return
        payload = bytes(tcp.payload)
        if not payload:
            return
        parsed = _parse_head(payload)
        if parsed is None:
            return

        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return

        method, path, headers, body_len = parsed
        request = WinRMRequest(
            ts=float(pkt.time), src=src, dst=dst, dst_port=int(tcp.dport),
            method=method, path=path,
            user_agent=headers.get("user-agent", ""),
            content_type=headers.get("content-type", ""),
            body_bytes=body_len,
        )
        request.encrypted = "encrypted" in request.content_type.lower()

        identity = None
        auth = headers.get("authorization", "")
        scheme = _NTLM_SCHEME.match(auth)
        if scheme:
            request.auth_scheme = auth.split()[0]
            identity, is_ntlm = decode_ntlm(scheme.group(1))
            if not is_ntlm:
                identity = None
        elif auth:
            request.auth_scheme = auth.split()[0]

        body = payload.partition(b"\r\n\r\n")[2]
        self._read_envelope(request, body)

        self.requests.append(request)
        self._absorb(request, identity, bool(scheme and request.auth_scheme))

    def _read_envelope(self, request: WinRMRequest, body: bytes) -> None:
        """Pull the action and resource URI out of a SOAP envelope still in clear.

        Only possible before session encryption is negotiated, which is why the
        first few requests of a session are worth reading and the rest are not.
        """
        if request.encrypted or not body:
            return
        text = body[:4096].decode("utf-8", "replace").lower()
        for marker, phrase in SHELL_ACTIONS.items():
            if marker in text:
                request.action = phrase
                break
        if PSRP_RESOURCE in text:
            request.resource = "PowerShell Remoting"
        elif WMI_RESOURCE in text:
            request.resource = "WMI over WinRM"

    def _absorb(self, request: WinRMRequest, identity: NTLMIdentity | None,
                saw_ntlm: bool) -> None:
        state = self.sessions[(request.src, request.dst)]
        state.requests += 1
        state.dst_port = request.dst_port
        state.first_ts = state.first_ts or request.ts
        state.last_ts = request.ts
        state.body_bytes += request.body_bytes
        if request.user_agent:
            state.agents[request.user_agent] += 1
        if request.content_type:
            state.content_types[request.content_type.split(";")[0].strip()] += 1
        if request.action:
            state.actions[request.action] += 1
        if request.resource == "PowerShell Remoting":
            state.psrp = True
        elif request.resource == "WMI over WinRM":
            state.wmi = True
        if request.encrypted:
            state.encrypted_requests += 1
        else:
            state.cleartext_requests += 1
        if saw_ntlm:
            state.ntlm_messages += 1
        if identity is not None:
            state.identities[identity.key] = identity

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Structured WS-Management facts for the report, the UI and the copilot."""
        if not self.requests:
            return {}

        agents: Counter = Counter()
        actions: Counter = Counter()
        identities: dict[tuple[str, str, str], NTLMIdentity] = {}
        targets: set[str] = set()
        for (_src, dst), state in self.sessions.items():
            agents.update(state.agents)
            actions.update(state.actions)
            identities.update(state.identities)
            targets.add(dst)

        return {
            "requests": len(self.requests),
            "sessions": len(self.sessions),
            "targets": sorted(targets),
            "clients": sorted({src for src, _dst in self.sessions}),
            "user_agents": dict(agents.most_common()),
            "accounts": [
                {"user": i.user, "domain": i.domain, "workstation": i.workstation}
                for i in identities.values()
            ],
            "actions_seen": dict(actions.most_common()),
            "encrypted_requests": sum(s.encrypted_requests for s in self.sessions.values()),
            "cleartext_requests": sum(s.cleartext_requests for s in self.sessions.values()),
            "payload_bytes": sum(s.body_bytes for s in self.sessions.values()),
            "note": "Payloads are wrapped in SPNEGO session encryption, so the "
                    "commands themselves are not recoverable from the capture. "
                    "The account, workstation and client software are not "
                    "encrypted and are read directly from the request headers.",
        }

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        min_requests = config.get("winrm", "session_min_requests", 5)

        for (src, dst), state in self.sessions.items():
            events.extend(self._execution(src, dst, state, min_requests))
            events.extend(self._identity(src, dst, state))
        return events

    def _execution(self, src, dst, state, min_requests) -> list[DetectionEvent]:
        """A remote-management channel, graded by how much went through it."""
        if state.requests < min_requests:
            return []

        tooling = state.tooling_agents()
        who = sorted(str(i) for i in state.identities.values())
        channel = ("PowerShell Remoting" if state.psrp
                   else "WMI over WinRM" if state.wmi
                   else "WS-Management")

        # Tooling on the client, or a long sustained session, is what separates
        # an intrusion from an administrator doing their job.
        severity = Severity.HIGH if (tooling or state.requests >= 100) else Severity.MEDIUM
        if tooling and state.requests >= 100:
            severity = Severity.CRITICAL

        desc = (
            f"{channel} session — {state.requests} request(s) to {WSMAN_PATH} over "
            f"{round(state.duration)}s"
            + (f", authenticated as {who[0]}" if who else "")
            + (f", client is {tooling[0]}" if tooling else "")
        )
        return [DetectionEvent(
            event_type=EventType.WINRM_EXECUTION,
            severity=severity,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="WINRM",
            timestamp=state.first_ts,
            packet_count=state.requests,
            confidence=0.95 if tooling else 0.75,
            description=desc,
            evidence={
                "channel": channel,
                "requests": state.requests,
                "duration_secs": round(state.duration, 2),
                "authenticated_as": ", ".join(who) if who else "not observed",
                "client_software": ", ".join(sorted(state.agents)) or "not sent",
                "non_windows_client": ", ".join(tooling) if tooling else "no",
                "transport": ("HTTPS (5986)" if state.dst_port == WINRM_HTTPS_PORT
                              else "HTTP (5985), payload encrypted by SPNEGO"),
                "encrypted_requests": state.encrypted_requests,
                "payload_bytes": state.body_bytes,
                "actions_observed": ", ".join(state.actions) or "none in clear text",
                "mitre": f"{MITRE_WINRM} / {MITRE_EXEC}",
                "note": "Command text is inside SPNEGO session encryption and is not "
                        "recoverable from this capture. The account, workstation and "
                        "client software below are read from unencrypted headers.",
            },
        )]

    def _identity(self, src, dst, state) -> list[DetectionEvent]:
        """An account name and a workstation name, sent in clear over the network."""
        if not state.identities:
            return []

        over_http = state.dst_port != WINRM_HTTPS_PORT
        who = sorted(str(i) for i in state.identities.values())
        workstations = sorted({i.workstation for i in state.identities.values() if i.workstation})
        return [DetectionEvent(
            event_type=EventType.NTLM_AUTHENTICATION,
            severity=Severity.HIGH if over_http else Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="NTLM",
            timestamp=state.first_ts,
            packet_count=state.ntlm_messages,
            confidence=1.0,
            description=(
                f"NTLM authentication observed — {', '.join(who)}"
                + (" (over HTTP, so the challenge/response is on the wire)"
                   if over_http else "")
            ),
            evidence={
                "accounts": ", ".join(who),
                "workstations_claimed": ", ".join(workstations) or "not sent",
                "ntlm_messages": state.ntlm_messages,
                "transport": "HTTP (5985)" if over_http else "HTTPS (5986)",
                "mitre": MITRE_NTLM,
                "note": "Read from the Authorization header's NTLM type 3 message, "
                        "which carries the account, domain and the workstation name "
                        "the client chose to send. The workstation name is supplied "
                        "by the client and is therefore evidence of what the client "
                        "called itself, not proof of the machine's identity.",
            },
        )]


def _endpoints(pkt) -> tuple[str | None, str | None]:
    """Source and destination addresses, IPv4 or IPv6."""
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    return None, None
