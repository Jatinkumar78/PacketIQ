"""
LDAP detection — what an attacker asks a domain controller, and how they ask it.

Why this module exists
----------------------
LDAP is how Active Directory is read. Before an intruder moves anywhere they
ask the directory what exists: which domain, which naming contexts, which
users, which groups, which accounts have a service principal name worth
roasting. All of it is an ordinary LDAP search, and on an unencrypted port all
of it is in clear text.

On the capture that drove this work, the attacker opened with two RootDSE
queries -- ``baseObject`` empty, filter ``(objectClass=*)`` -- which is the
textbook first step: it is the one search you can run before you know anything,
and it returns the naming contexts you need to run every search after it.
PacketIQ saw 12 LDAP frames and reported them as "LDAP 43 packets, 0.4%".

What this reads
---------------
  * **Bind requests.** A simple bind carries the distinguished name and the
    password as bytes on the wire. On port 389 with no StartTLS that is a
    credential disclosure, not a risk of one.
  * **Search requests.** The base object, the filter and the attributes asked
    for, which together say what the client was looking for. A filter of
    ``(objectClass=*)`` against an empty base is RootDSE discovery; a filter
    naming ``servicePrincipalName`` is looking for roastable accounts; one
    naming ``userAccountControl`` is usually looking for accounts with
    pre-authentication disabled.
  * **StartTLS**, so a session that upgraded is not reported as cleartext for
    the rest of its life.

Nothing here infers intent from a port. Each finding names the searches it saw.
"""

from __future__ import annotations

import contextlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from packetiq import config
from packetiq.detection.models import DetectionEvent, EventType, Severity

# The cleartext ports only. LDAPS on 636 and 3269 is TLS from the first byte,
# so there is nothing to parse there and no finding this module can honestly
# make about it: a capture of LDAPS shows that a connection happened and
# nothing about what was asked. Encryption reached through StartTLS on 389 is
# tracked separately, because those sessions begin in clear and we see the
# upgrade happen.
LDAP_PORTS = frozenset({389, 3268})          # LDAP and the Global Catalog
STARTTLS_OID = "1.3.6.1.4.1.1466.20037"

# Attributes whose appearance in a filter or attribute list says what the
# client was hunting for. Every one of these is a legitimate attribute that
# administration tools also read; it is the combination with a broad search
# that makes it worth reporting, so these are used to describe a finding rather
# than to raise one on their own.
TELLING_ATTRIBUTES = {
    "serviceprincipalname": "accounts with an SPN (kerberoastable)",
    "useraccountcontrol": "account flags (pre-auth disabled, delegation)",
    "msds-allowedtodelegateto": "constrained delegation targets",
    "admincount": "accounts in protected groups",
    "ntsecuritydescriptor": "object permissions (ACL enumeration)",
    "msds-managedpassword": "group managed service account passwords",
    "unicodepwd": "password material",
    "memberof": "group membership",
    "lastlogon": "account activity",
    "mail": "user mail addresses",
}

# A search with an empty base and a present-filter is RootDSE discovery.
ROOTDSE_FILTER = "objectclass"

MITRE_LDAP_DISCOVERY = "T1087.002"   # Account Discovery: Domain Account
MITRE_DOMAIN_TRUST   = "T1482"       # Domain Trust Discovery
MITRE_CLEARTEXT      = "T1552.001"   # Unsecured Credentials: Credentials In Files


def _text(value) -> str:
    """Unwrap a scapy ASN.1 value to a plain string.

    Same trap as everywhere else in this codebase: ``str()`` on the wrapper
    gives a repr, and bytes are only sometimes decoded for you.
    """
    value = getattr(value, "val", value)
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def render_filter(node, depth: int = 0) -> str:
    """Render an LDAP filter back into the string an operator would have typed.

    Reported in its written form because that is how it is recognised: a
    responder who sees ``(&(objectClass=user)(servicePrincipalName=*))`` knows
    immediately what it was for, where "LDAP_FilterAnd with two children" tells
    them nothing. Depth-limited, because a filter is attacker-supplied input
    and nesting it deeply is a cheap way to make a parser work forever.
    """
    if node is None or depth > 8:
        return ""
    inner = getattr(node, "filter", None)
    if inner is not None and type(node).__name__ == "LDAP_Filter":
        return render_filter(inner, depth + 1)

    name = type(node).__name__
    if name == "LDAP_FilterPresent":
        return f"({_text(getattr(node, 'present', None))}=*)"
    if name == "LDAP_FilterEqual":
        return (f"({_text(getattr(node, 'attributeType', None))}="
                f"{_text(getattr(node, 'attributeValue', None))})")
    if name == "LDAP_FilterGreaterOrEqual":
        return (f"({_text(getattr(node, 'attributeType', None))}>="
                f"{_text(getattr(node, 'attributeValue', None))})")
    if name == "LDAP_FilterLessOrEqual":
        return (f"({_text(getattr(node, 'attributeType', None))}<="
                f"{_text(getattr(node, 'attributeValue', None))})")
    if name in ("LDAP_FilterAnd", "LDAP_FilterOr"):
        joiner = "&" if name == "LDAP_FilterAnd" else "|"
        parts = "".join(render_filter(v, depth + 1) for v in (getattr(node, "vals", None) or []))
        return f"({joiner}{parts})"
    if name == "LDAP_FilterNot":
        # scapy names this child `val`, not `filter` like every other node.
        return f"(!{render_filter(getattr(node, 'val', None), depth + 1)})"
    return f"({name})"


@dataclass
class LDAPOperation:
    """One LDAP request or response, reduced to what a responder reads."""

    ts: float
    src: str
    dst: str
    dst_port: int
    kind: str = ""
    base_object: str = ""
    filter_text: str = ""
    attributes: tuple[str, ...] = ()
    bind_name: str = ""
    bind_method: str = ""
    cleartext_password: bool = False
    result_code: int | None = None


@dataclass
class _ClientState:
    searches: int = 0
    rootdse_searches: int = 0
    base_objects: Counter = field(default_factory=Counter)
    filters: Counter = field(default_factory=Counter)
    attributes: Counter = field(default_factory=Counter)
    binds: list[LDAPOperation] = field(default_factory=list)
    anonymous_binds: int = 0
    starttls: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0
    dst_port: int = 389

    @property
    def duration(self) -> float:
        return max(self.last_ts - self.first_ts, 0.0)

    def telling(self) -> dict[str, str]:
        """Attributes asked for that describe what the search was hunting."""
        found = {}
        asked = {a.lower() for a in self.attributes}
        asked.update(
            word.strip("()=*<>!&|")
            for text in self.filters
            for word in text.lower().replace("(", " ").replace(")", " ").split("=")
        )
        for attribute, meaning in TELLING_ATTRIBUTES.items():
            if any(attribute in a for a in asked):
                found[attribute] = meaning
        return found


class LDAPAccumulator:
    """Collects LDAP operations over one PCAP pass."""

    def __init__(self) -> None:
        self.operations: list[LDAPOperation] = []
        self.clients: dict[tuple[str, str], _ClientState] = defaultdict(_ClientState)

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.ldap import LDAP

        if not pkt.haslayer(LDAP):
            return
        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return
        # scapy binds LDAP over TCP only, so a packet that reached here is on a
        # port this module watches: there is no "LDAP on an unknown port" case
        # to guard against.
        port = _server_port(pkt)

        try:
            operation = self._decode(pkt, src, dst, port)
        except Exception:
            return
        if operation is None:
            return

        self.operations.append(operation)
        self._absorb(operation)

    def _decode(self, pkt, src, dst, port) -> LDAPOperation | None:
        from scapy.layers.ldap import LDAP

        # scapy always materialises a protocolOp, defaulting to a SearchRequest,
        # so there is no None case here either.
        op = pkt[LDAP].protocolOp
        name = type(op).__name__
        ts = float(pkt.time)
        base = LDAPOperation(ts=ts, src=src, dst=dst, dst_port=port)

        if name == "LDAP_SearchRequest":
            base.kind = "search"
            base.base_object = _text(getattr(op, "baseObject", None))
            base.filter_text = render_filter(getattr(op, "filter", None))
            # Each entry is an LDAP_SearchRequestAttribute wrapping `type`, so
            # unwrapping the entry itself yields the class name rather than the
            # attribute. That would have put "LDAP_SearchRequestAttribute" where
            # "servicePrincipalName" belongs, in the one field that says what
            # the search was hunting for.
            base.attributes = tuple(
                _text(getattr(a, "type", a))
                for a in (getattr(op, "attributes", None) or [])
            )
            return base

        if name == "LDAP_BindRequest":
            base.kind = "bind"
            base.bind_name = _text(getattr(op, "bind_name", None))
            auth = getattr(op, "authentication", None)
            auth_name = type(auth).__name__ if auth is not None else ""
            if auth_name == "LDAP_Authentication_simple":
                base.bind_method = "simple"
                # A simple bind sends the password as-is. An empty one is an
                # anonymous bind, which is a different finding.
                base.cleartext_password = bool(_text(auth))
            elif auth_name:
                base.bind_method = auth_name.replace("LDAP_Authentication_", "")
            return base

        if name in ("LDAP_ExtendedRequest", "LDAP_ExtendedResponse"):
            oid = _text(getattr(op, "requestName", None) or getattr(op, "responseName", None))
            if oid == STARTTLS_OID:
                base.kind = "starttls"
                return base
            return None

        return None

    def _absorb(self, operation: LDAPOperation) -> None:
        state = self.clients[(operation.src, operation.dst)]
        state.first_ts = state.first_ts or operation.ts
        state.last_ts = operation.ts
        state.dst_port = operation.dst_port

        if operation.kind == "search":
            state.searches += 1
            if operation.base_object:
                state.base_objects[operation.base_object] += 1
            else:
                # Empty base plus a present-filter is RootDSE discovery: the one
                # query you can run before you know the directory's own names.
                if ROOTDSE_FILTER in operation.filter_text.lower():
                    state.rootdse_searches += 1
            if operation.filter_text:
                state.filters[operation.filter_text] += 1
            for attribute in operation.attributes:
                state.attributes[attribute] += 1
        elif operation.kind == "bind":
            state.binds.append(operation)
            if not operation.bind_name and not operation.cleartext_password:
                state.anonymous_binds += 1
        elif operation.kind == "starttls":
            state.starttls = True

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        if not self.operations:
            return {}

        filters: Counter = Counter()
        attributes: Counter = Counter()
        bases: Counter = Counter()
        binds: list[str] = []
        telling: dict[str, str] = {}
        for state in self.clients.values():
            filters.update(state.filters)
            attributes.update(state.attributes)
            bases.update(state.base_objects)
            telling.update(state.telling())
            binds.extend(
                f"{b.bind_name or '(anonymous)'} [{b.bind_method or 'unspecified'}]"
                for b in state.binds
            )

        return {
            "operations": len(self.operations),
            "searches": sum(s.searches for s in self.clients.values()),
            "rootdse_searches": sum(s.rootdse_searches for s in self.clients.values()),
            "clients": sorted({src for src, _ in self.clients}),
            "servers": sorted({dst for _, dst in self.clients}),
            "filters": dict(filters.most_common(20)),
            "base_objects": dict(bases.most_common(10)),
            "attributes_requested": dict(attributes.most_common(25)),
            "binds": sorted(set(binds)),
            "notable_attributes": telling,
            "starttls": any(s.starttls for s in self.clients.values()),
        }

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        min_searches = config.get("ldap", "enum_min_searches", 2)

        for (src, dst), state in self.clients.items():
            events.extend(self._enumeration(src, dst, state, min_searches))
            events.extend(self._cleartext_bind(src, dst, state))
        return events

    def _enumeration(self, src, dst, state, min_searches) -> list[DetectionEvent]:
        """Reading the directory, graded by how much was read and what was asked for."""
        if state.searches < min_searches:
            return []

        telling = state.telling()
        encrypted = state.starttls
        severity = Severity.HIGH if telling else Severity.MEDIUM

        what = (f"RootDSE discovery and {state.searches} search(es)"
                if state.rootdse_searches else f"{state.searches} search(es)")
        return [DetectionEvent(
            event_type=EventType.LDAP_ENUMERATION,
            severity=severity,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="LDAP",
            timestamp=state.first_ts,
            packet_count=state.searches,
            confidence=0.9 if telling else 0.6,
            description=(
                f"Directory enumeration over LDAP — {what} against {dst}"
                + (f", asking for {', '.join(sorted(telling))}" if telling else "")
            ),
            evidence={
                "searches": state.searches,
                "rootdse_queries": state.rootdse_searches,
                "filters": " | ".join(list(state.filters)[:6]) or "none decoded",
                "base_objects": " | ".join(list(state.base_objects)[:4]) or "(RootDSE)",
                "attributes_requested": ", ".join(list(state.attributes)[:15]) or "all",
                "notable": "; ".join(f"{k} = {v}" for k, v in telling.items()) or "none",
                "transport": ("upgraded to TLS by StartTLS mid-session" if encrypted
                              else f"cleartext on port {state.dst_port}"),
                "duration_secs": round(state.duration, 2),
                "mitre": f"{MITRE_LDAP_DISCOVERY} / {MITRE_DOMAIN_TRUST}",
                "note": "Directory reads are also normal administration. What is "
                        "reported here is what was asked for, so it can be compared "
                        "against what this client has any business asking.",
            },
        )]

    def _cleartext_bind(self, src, dst, state) -> list[DetectionEvent]:
        """A simple bind on an unencrypted port puts the password on the wire."""
        exposed = [b for b in state.binds if b.cleartext_password]
        if not exposed or state.starttls:
            return []

        names = sorted({b.bind_name for b in exposed if b.bind_name})
        return [DetectionEvent(
            event_type=EventType.CREDENTIAL_EXPOSURE,
            severity=Severity.CRITICAL,
            src_ip=src, dst_ip=dst, dst_port=state.dst_port, protocol="LDAP",
            timestamp=exposed[0].ts,
            packet_count=len(exposed),
            confidence=1.0,
            description=(
                f"LDAP simple bind over cleartext — {len(exposed)} bind(s) sent a "
                f"password unencrypted on port {state.dst_port}"
                + (f" as {names[0]}" if names else "")
            ),
            evidence={
                "bind_dns": ", ".join(names) or "(not sent)",
                "binds": len(exposed),
                "transport": f"cleartext on port {state.dst_port}, no StartTLS observed",
                "mitre": MITRE_CLEARTEXT,
                "note": "A simple bind sends the password as bytes. Anyone who "
                        "captured this traffic has it; the password value itself is "
                        "deliberately not reproduced in this report.",
            },
        )]


def _server_port(pkt) -> int:
    """The LDAP port this conversation is on, whichever side we are looking at."""
    with contextlib.suppress(Exception):
        from scapy.layers.inet import TCP
        tcp = pkt[TCP]
        for port in (tcp.dport, tcp.sport):
            if port in LDAP_PORTS:
                return int(port)
    return 389


def _endpoints(pkt) -> tuple[str | None, str | None]:
    """Client and server addresses, oriented so the server is the LDAP side."""
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None, None
        # A response travels server -> client; attribute it to the same pair as
        # the request so one conversation does not become two.
        if pkt.haslayer(TCP) and pkt[TCP].sport in LDAP_PORTS:
            return dst, src
        return src, dst
    return None, None
