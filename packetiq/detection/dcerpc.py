"""
DCERPC detection — which remote procedure interface an attacker reached for.

Why this module exists
----------------------
A great deal of what an intruder does on a Windows network is a remote
procedure call. Creating a service to run a payload is the Service Control
Manager interface (svcctl, the engine inside PsExec). Scheduling a task is the
task-scheduler interface (atsvc). Pulling every account's password hash out of
the domain is a replication call (drsuapi, the DCSync attack). None of these
look alike on a port number; they are told apart by the interface UUID named in
the DCERPC bind, which is in clear text even when the call that follows is not.

So this reads the bind. The UUID says which service was asked for, and that is
most of the finding: a bind to drsuapi from something that is not a domain
controller is a DCSync attempt and very little else.

What the capture this was built from actually shows
---------------------------------------------------
Honesty first, because it shapes what this reports. The Active Directory
capture that drove this work contains almost no DCERPC: a single rejected bind
on the endpoint mapper, and TCP connections to port 135 and 593 that were
opened and refused. The attacker ran code over WinRM, not over an RPC named
pipe. So on that capture this module reports endpoint-mapper probing and a
refused bind as reconnaissance of the RPC surface, and nothing more, because
nothing more happened. The execution detections below are for the many real
captures that do carry svcctl or atsvc, verified against binds built for the
tests rather than against traffic that is not in this one capture.
"""

from __future__ import annotations

import contextlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from packetiq.detection.models import DetectionEvent, EventType, Severity

RPC_PORTS = frozenset({135, 593})          # endpoint mapper, and RPC-over-HTTP
EPM_PORT = 135

# DCERPC v5 PDU types (MS-RPCE 2.2.2.3) that this module reasons about.
PTYPE_REQUEST = 0
PTYPE_BIND = 11
PTYPE_BIND_ACK = 12
PTYPE_BIND_NAK = 13
PTYPE_ALTER_CONTEXT = 14

# Well-known interface UUIDs, lower-cased. Each entry is (name, meaning,
# category), where the category drives the severity and the MITRE mapping. The
# UUIDs are stable parts of Windows and are the single most reliable thing in a
# DCERPC conversation: the call arguments may be encrypted, but the bind names
# what was asked for.
INTERFACES: dict[str, tuple[str, str, str]] = {
    "367abb81-9844-35f1-ad32-98f038001003":
        ("svcctl", "Service Control Manager — creates and starts services (PsExec)", "execution"),
    "1ff70682-0a51-30e8-076d-740be8cee98b":
        ("atsvc", "Task Scheduler (AT) — schedules remote tasks", "execution"),
    "86d35949-83c9-4044-b424-db363231fd0c":
        ("ITaskSchedulerService", "Task Scheduler 2.0 — schedules remote tasks", "execution"),
    "338cd001-2244-31f1-aaaa-900038001003":
        ("winreg", "Remote Registry — reads and writes the registry remotely", "execution"),
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2":
        ("drsuapi", "Directory Replication — DCSync pulls password hashes from the domain",
         "credential_access"),
    "12345678-1234-abcd-ef00-01234567cffb":
        ("netlogon", "Netlogon — the Zerologon privilege-escalation surface", "credential_access"),
    "12345778-1234-abcd-ef00-0123456789ac":
        ("samr", "SAM Remote — enumerates domain users and groups", "discovery"),
    "12345778-1234-abcd-ef00-0123456789ab":
        ("lsarpc", "LSA Remote — enumerates policy, trusts and SIDs", "discovery"),
    "4b324fc8-1670-01d3-1278-5a47bf6ee188":
        ("srvsvc", "Server Service — enumerates shares and sessions", "discovery"),
    "6bffd098-a112-3610-9833-46c3f87e345a":
        ("wkssvc", "Workstation Service — enumerates logged-on users", "discovery"),
    "c681d488-d850-11d0-8c52-00c04fd90f7e":
        ("efsrpc", "Encrypting File System Remote — the PetitPotam coercion surface",
         "credential_access"),
    "12345678-1234-abcd-ef00-0123456789ab":
        ("spoolss", "Print System Remote — the PrintNightmare surface", "execution"),
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa":
        ("epmapper", "Endpoint Mapper — resolves which port an RPC interface listens on",
         "reconnaissance"),
}

# Operations worth naming when the request itself is readable. drsuapi opnum 3
# is DRSGetNCChanges, the exact call DCSync makes.
NOTABLE_OPERATIONS = {
    ("drsuapi", 3): "DRSGetNCChanges (DCSync — replicating secrets out of the domain)",
    ("svcctl", 12): "CreateServiceW (installing a service to run a payload)",
    ("svcctl", 19): "StartServiceW (starting the installed service)",
    ("atsvc", 0): "NetrJobAdd (scheduling a task)",
}

CATEGORY_SEVERITY = {
    "credential_access": Severity.CRITICAL,
    "execution": Severity.HIGH,
    "discovery": Severity.MEDIUM,
    "reconnaissance": Severity.LOW,
}

CATEGORY_MITRE = {
    "credential_access": "T1003.006",   # OS Credential Dumping: DCSync
    "execution": "T1021.003",           # Remote Services: Distributed Component Object Model
    "discovery": "T1087.002",           # Account Discovery: Domain Account
    "reconnaissance": "T1135",          # Network Share Discovery / RPC surface mapping
}

MITRE_SVCCTL = "T1569.002"              # System Services: Service Execution
MITRE_ATSVC = "T1053.005"              # Scheduled Task/Job: Scheduled Task
MITRE_DCSYNC = "T1003.006"


@dataclass
class DCERPCBind:
    """One DCERPC bind, reduced to the interface it asked for."""

    ts: float
    src: str
    dst: str
    dst_port: int
    uuid: str = ""
    name: str = ""
    meaning: str = ""
    category: str = ""
    accepted: bool | None = None       # from the matching bind_ack / bind_nak
    operations: tuple[str, ...] = ()


@dataclass
class _SessionState:
    binds: list[DCERPCBind] = field(default_factory=list)
    interfaces: dict[str, DCERPCBind] = field(default_factory=dict)
    epm_requests: int = 0
    rejected_binds: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    dst_port: int = 135

    @property
    def duration(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)


def _uuid_of(context) -> str:
    """Pull the abstract-syntax interface UUID out of one bind context element."""
    with contextlib.suppress(Exception):
        syntax = getattr(context, "abstract_syntax", None)
        uuid_val = getattr(syntax, "if_uuid", None)
        if uuid_val is not None:
            return str(uuid_val).lower()
    return ""


class DCERPCAccumulator:
    """Collects DCERPC binds over one PCAP pass."""

    def __init__(self) -> None:
        self.binds: list[DCERPCBind] = []
        self.sessions: dict[tuple[str, str], _SessionState] = defaultdict(_SessionState)

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        if tcp.dport not in RPC_PORTS and tcp.sport not in RPC_PORTS:
            return
        payload = bytes(tcp.payload)
        # A DCERPC v5 PDU begins with version 5, then minor, then the PDU type.
        if len(payload) < 16 or payload[0] != 5:
            return

        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return
        port = tcp.dport if tcp.dport in RPC_PORTS else int(tcp.sport)

        try:
            self._decode(payload, float(pkt.time), src, dst, port)
        except Exception:
            return

    def _decode(self, payload: bytes, ts: float, src: str, dst: str, port: int) -> None:
        from scapy.layers.dcerpc import DceRpc5

        ptype = payload[2]
        pdu = DceRpc5(payload)
        body = pdu.payload
        # Orient so the server (the RPC side) is the destination of a request.
        is_reply = ptype in (PTYPE_BIND_ACK, PTYPE_BIND_NAK)
        client, server = (dst, src) if is_reply else (src, dst)
        state = self.sessions[(client, server)]
        state.first_ts = state.first_ts or ts
        state.last_ts = ts
        state.dst_port = port

        if ptype in (PTYPE_BIND, PTYPE_ALTER_CONTEXT):
            # scapy always materialises context_elem as a list, even for a bind
            # that proposes a single interface, so no single-value case to guard.
            contexts = getattr(body, "context_elem", None) or []
            for context in contexts:
                uuid = _uuid_of(context)
                if not uuid:
                    continue
                name, meaning, category = INTERFACES.get(
                    uuid, (f"unknown ({uuid})", "an interface this tool does not recognise",
                           "reconnaissance"))
                bind = DCERPCBind(ts=ts, src=client, dst=server, dst_port=port,
                                  uuid=uuid, name=name, meaning=meaning, category=category)
                state.binds.append(bind)
                state.interfaces[uuid] = bind
                self.binds.append(bind)
                if name == "epmapper":
                    state.epm_requests += 1
        elif ptype == PTYPE_BIND_NAK:
            state.rejected_binds += 1
            for bind in state.interfaces.values():
                bind.accepted = False
        elif ptype == PTYPE_BIND_ACK:
            for bind in state.interfaces.values():
                if bind.accepted is None:
                    bind.accepted = True
        elif ptype == PTYPE_REQUEST and state.interfaces:
            opnum = getattr(body, "opnum", None)
            if opnum is not None:
                self._note_operation(state, int(opnum))

    def _note_operation(self, state: _SessionState, opnum: int) -> None:
        """Attach a readable operation name to the interface it was called on."""
        for bind in state.interfaces.values():
            label = NOTABLE_OPERATIONS.get((bind.name, opnum))
            if label and label not in bind.operations:
                bind.operations = (*bind.operations, label)

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        if not self.sessions:
            return {}

        interfaces: dict[str, str] = {}
        categories: Counter = Counter()
        operations: list[str] = []
        epm = rejected = 0
        for state in self.sessions.values():
            epm += state.epm_requests
            rejected += state.rejected_binds
            for bind in state.interfaces.values():
                interfaces[bind.name] = bind.meaning
                categories[bind.category] += 1
                operations.extend(bind.operations)

        return {
            "binds": len(self.binds),
            "sessions": len(self.sessions),
            "clients": sorted({src for src, _ in self.sessions}),
            "servers": sorted({dst for _, dst in self.sessions}),
            "interfaces": interfaces,
            "operations": sorted(set(operations)),
            "categories": dict(categories),
            "endpoint_mapper_requests": epm,
            "rejected_binds": rejected,
        }

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        for (src, dst), state in self.sessions.items():
            events.extend(self._interface_findings(src, dst, state))
            events.extend(self._recon(src, dst, state))
        return events

    def _interface_findings(self, src, dst, state) -> list[DetectionEvent]:
        """One finding per meaningful interface an attacker bound to."""
        events: list[DetectionEvent] = []
        for bind in state.interfaces.values():
            if bind.category == "reconnaissance":
                continue        # epmapper and unknowns are handled as recon below
            severity = CATEGORY_SEVERITY[bind.category]
            events.append(DetectionEvent(
                event_type=EventType.DCERPC_SUSPECT_BIND,
                severity=severity,
                src_ip=src, dst_ip=dst, dst_port=bind.dst_port, protocol="DCERPC",
                timestamp=bind.ts,
                packet_count=1,
                confidence=0.9 if bind.accepted else 0.7,
                description=(
                    f"DCERPC bind to {bind.name} — {bind.meaning}"
                    + ("" if bind.accepted is None
                       else ", accepted" if bind.accepted else ", rejected by the server")
                    + (f"; observed {', '.join(bind.operations)}" if bind.operations else "")
                ),
                evidence={
                    "interface": bind.name,
                    "uuid": bind.uuid,
                    "meaning": bind.meaning,
                    "category": bind.category,
                    "operations": ", ".join(bind.operations) or "none in clear text",
                    "bind_result": ("accepted" if bind.accepted
                                    else "rejected" if bind.accepted is False
                                    else "not observed"),
                    "mitre": _mitre_for(bind),
                    "note": "The interface UUID in the bind says which RPC service was "
                            "asked for; it is in clear text even when the call that "
                            "follows is encrypted. A bind to this interface from a host "
                            "that is not its legitimate client is the signal.",
                },
            ))
        return events

    def _recon(self, src, dst, state) -> list[DetectionEvent]:
        """Endpoint-mapper probing and rejected binds: mapping the RPC surface.

        This is what the source capture actually contains, and it is a real
        reconnaissance signal in its own right: an attacker asking the endpoint
        mapper what is available, or having binds refused, is enumerating the
        host's RPC services before choosing one.
        """
        if not state.epm_requests and not state.rejected_binds:
            return []
        return [DetectionEvent(
            event_type=EventType.DCERPC_RECON,
            severity=Severity.LOW,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="DCERPC",
            timestamp=state.first_ts,
            packet_count=state.epm_requests + state.rejected_binds,
            confidence=0.7,
            description=(
                "RPC endpoint-mapper activity — "
                + (f"{state.epm_requests} endpoint-mapper bind(s)" if state.epm_requests else "")
                + (" and " if state.epm_requests and state.rejected_binds else "")
                + (f"{state.rejected_binds} rejected bind(s)" if state.rejected_binds else "")
                + ", the RPC surface being mapped before a service is chosen"
            ),
            evidence={
                "endpoint_mapper_binds": state.epm_requests,
                "rejected_binds": state.rejected_binds,
                "mitre": "T1135",
                "note": "Probing the endpoint mapper, or having binds refused, is how "
                        "an RPC attack surface is enumerated. On its own it is "
                        "reconnaissance, not execution, and is reported as such.",
            },
        )]


def _mitre_for(bind: DCERPCBind) -> str:
    if bind.name == "svcctl":
        return MITRE_SVCCTL
    if bind.name in ("atsvc", "ITaskSchedulerService"):
        return MITRE_ATSVC
    if bind.name == "drsuapi":
        return MITRE_DCSYNC
    return CATEGORY_MITRE.get(bind.category, "T1021.003")


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
