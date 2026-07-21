"""
Triage layer — false-positive reduction and per-finding explainability.

This module does two things, both central to PacketIQ being trustworthy in the
real world:

1. **Explainability.** For every detection it produces a plain-English account of
   *what* was seen, *why* it was flagged, the concrete evidence behind it, the
   MITRE technique, and a recommended response. Nothing here is invented — the
   explanation is generated deterministically from the detector's own evidence.

2. **False-positive reduction.** Each finding is graded for *precision*
   (Confirmed / High / Probable / Tentative) based on whether it rests on
   observed fact (e.g. a real OSINT feed hit, cleartext credentials) or on a
   heuristic. An optional, user-controlled allow-list and confidence floor
   (configured in packetiq.toml) suppress known-good noise — conservatively, so
   genuine attacks are never silently dropped (defaults change nothing).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from packetiq import config
from packetiq.correlation.mitre import kill_chain_phase, techniques_for_event
from packetiq.detection.models import EventType

# ── Plain-English rationale per finding type ─────────────────────────────────
# what: one line on the behaviour · why: why it is suspicious · action: response
_RATIONALE: dict = {
    EventType.BRUTE_FORCE: {
        "what": "Many authentication attempts to a service in a short window.",
        "why": "A high rate of login attempts from one source is the signature of password guessing / credential stuffing.",
        "action": "Verify whether the source is authorised; rate-limit or block it; enforce MFA and check for any successful login after the burst.",
    },
    EventType.PORT_SCAN: {
        "what": "One source touched many ports on a single host.",
        "why": "Sweeping a host's ports is classic service-discovery reconnaissance that precedes targeted exploitation.",
        "action": "Confirm the source isn't an approved scanner (vuln scan/asset mgmt); if not, block it and review what services were exposed.",
    },
    EventType.HOST_SCAN: {
        "what": "One source probed the same port across many hosts.",
        "why": "Horizontal sweeps map which hosts run a given service — reconnaissance or worm-style spread.",
        "action": "Validate the source; if unexpected, isolate it and check the targeted service for exposure.",
    },
    EventType.ARP_SCAN: {
        "what": "One host sent ARP 'who-has' requests for many addresses across the local subnet.",
        "why": "Sweeping the subnet with ARP is layer-2 host discovery — how nmap/arp-scan enumerate live hosts before targeting them. It leaves no IP-layer trace.",
        "action": "Confirm the source isn't an approved asset-management/vuln scanner; if not, locate the device on the switch port and isolate it.",
    },
    EventType.ARP_SPOOFING: {
        "what": "A single IP address was claimed by more than one MAC address on the wire.",
        "why": "An IP→MAC conflict is the signature of ARP cache poisoning — an on-path attacker redirecting a victim's traffic to intercept or alter it (man-in-the-middle).",
        "action": "Identify both MACs; if one is unauthorised, isolate it. Consider dynamic ARP inspection (DAI) and port security on the switch. (Rule out legitimate HA/VRRP failover first.)",
    },
    EventType.DNS_ANOMALY: {
        "what": "Unusual DNS behaviour (high-entropy or excessive queries).",
        "why": "Algorithmically generated domains and query floods are associated with malware C2 and data staging.",
        "action": "Review the domains/resolver; if algorithmic, treat the querying host as potentially infected.",
    },
    EventType.DNS_TUNNELING: {
        "what": "Abnormally long/structured DNS labels carrying data.",
        "why": "Encoding payloads inside DNS queries is a covert channel used to exfiltrate data or tunnel C2 past firewalls.",
        "action": "Inspect the resolver and querying host; block the domain; treat as possible exfiltration.",
    },
    EventType.CREDENTIAL_EXPOSURE: {
        "what": "Credentials observed in cleartext on the wire.",
        "why": "Plaintext credentials (HTTP Basic, FTP, Telnet, etc.) can be trivially captured and reused by any on-path attacker.",
        "action": "Rotate the exposed credentials immediately and move the service to an encrypted protocol (HTTPS/SFTP/SSH).",
    },
    EventType.PROTOCOL_MISUSE: {
        "what": "A protocol used in an unexpected or non-standard way.",
        "why": "Protocol misuse often indicates evasion, tunnelling, or a service running on a non-standard port.",
        "action": "Confirm the service is legitimate; investigate the endpoints involved.",
    },
    EventType.ICMP_TUNNELING: {
        "what": "Large or sustained data volume carried over ICMP.",
        "why": "ICMP normally carries tiny control messages; bulk data in ICMP is a covert exfiltration/C2 channel.",
        "action": "Block/limit ICMP payloads at the egress and investigate the host generating them.",
    },
    EventType.SUSPICIOUS_FLAGS: {
        "what": "TCP packets with abnormal flag combinations.",
        "why": "Illegal flag sets (NULL/XMAS/FIN) are used to fingerprint hosts and evade simple filters during scanning.",
        "action": "Correlate with other scan activity from the same source; block if confirmed.",
    },
    EventType.C2_BEACON: {
        "what": "Regular, periodic connections to an external host.",
        "why": "Beaconing at a fixed cadence (even when jittered) is how implants check in with command-and-control infrastructure.",
        "action": "Treat the internal host as potentially compromised; block the destination and triage the endpoint.",
    },
    EventType.JA3_ANOMALY: {
        "what": "A TLS client fingerprint (JA3) matching a known-bad list.",
        "why": "Malware families have distinctive TLS handshakes; a JA3 match to abuse.ch's SSLBL ties the flow to known malicious tooling.",
        "action": "Investigate the internal host's TLS client; block the destination; hunt for the associated malware.",
    },
    EventType.IOC_MATCH: {
        "what": "An observed IP/domain matched a real threat-intel feed.",
        "why": "The indicator appears on a current OSINT blocklist (abuse.ch / Spamhaus / Tor), tying this traffic to known-bad infrastructure.",
        "action": "Block the indicator and investigate every host that communicated with it.",
    },
    EventType.MALICIOUS_FILE: {
        "what": "A carved file's hash matched a known-malware database.",
        "why": "The SHA-256 is listed in MalwareBazaar — the exact sample is confirmed malicious, not merely suspicious.",
        "action": "Quarantine the file, isolate the receiving host, and begin incident response.",
    },
    EventType.HTTP_ATTACK: {
        "what": "An HTTP request containing an exploitation pattern.",
        "why": "Payloads such as SQLi, XSS, path traversal or Log4Shell in the URI/headers indicate active exploitation attempts.",
        "action": "Confirm whether the target responded as exploited; patch/virtual-patch the app; block the source.",
    },
    EventType.TLS_ANOMALY: {
        "what": "A TLS certificate with a risky property.",
        "why": "Self-signed, expired or abnormally long-lived certs are common on C2 and interception infrastructure.",
        "action": "Verify the endpoint's legitimacy; treat unknown self-signed external certs as suspicious.",
    },
}

# Findings that rest on observed fact (a feed hit / cleartext data), not a
# heuristic threshold — these are graded "Confirmed" regardless of a CV/score.
_EVIDENCE_BACKED = {
    EventType.IOC_MATCH, EventType.MALICIOUS_FILE,
    EventType.CREDENTIAL_EXPOSURE, EventType.JA3_ANOMALY,
}

_PRECISION_STYLE = {
    "Confirmed": "ok", "High": "ok", "Probable": "warn", "Tentative": "muted",
}


def precision(event) -> str:
    """Grade how much to trust a finding (independent of its severity)."""
    if event.event_type in _EVIDENCE_BACKED:
        return "Confirmed"
    conf = float(getattr(event, "confidence", 1.0) or 0.0)
    if conf >= 0.85:
        return "High"
    if conf >= 0.6:
        return "Probable"
    return "Tentative"


def precision_style(label: str) -> str:
    return _PRECISION_STYLE.get(label, "muted")


def _evidence_points(evidence: dict) -> list:
    """Turn the evidence dict into readable 'Label: value' strings."""
    out = []
    for k, v in (evidence or {}).items():
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in list(v)[:8])
        label = k.replace("_", " ").capitalize()
        out.append(f"{label}: {v}")
    return out[:12]


def explain(event) -> dict:
    """Deterministic, grounded explanation of a single finding."""
    et = event.event_type
    r = _RATIONALE.get(et, {"what": event.description, "why": "Flagged by a PacketIQ detector.",
                            "action": "Investigate the endpoints involved."})
    techs = techniques_for_event(et)
    label = precision(event)
    return {
        "what": r["what"],
        "why": r["why"],
        "recommendation": r["action"],
        "evidence_points": _evidence_points(getattr(event, "evidence", {})),
        "mitre": [{"id": t.technique_id, "name": t.technique_name,
                   "tactic": t.tactic_name} for t in techs],
        "kill_chain_phase": kill_chain_phase(et),
        "precision": label,
        "precision_style": precision_style(label),
        "confidence_pct": round(float(getattr(event, "confidence", 1.0) or 0.0) * 100),
    }


# ── Allow-list / suppression (user-controlled false-positive reduction) ──────

@dataclass
class Allowlist:
    ips: set = field(default_factory=set)
    cidrs: list = field(default_factory=list)        # list[ip_network]
    domains: set = field(default_factory=set)
    ja3: set = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.ips or self.cidrs or self.domains or self.ja3)


def load_allowlist() -> Allowlist:
    """Read the optional [allowlist] section from packetiq.toml (all optional)."""
    al = Allowlist()
    al.ips = {str(x).strip() for x in config.get("allowlist", "ips", []) if str(x).strip()}
    for c in config.get("allowlist", "cidrs", []) or []:
        try:
            al.cidrs.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            continue
    al.domains = {str(x).strip().lower().rstrip(".") for x in config.get("allowlist", "domains", []) if str(x).strip()}
    al.ja3 = {str(x).strip().lower() for x in config.get("allowlist", "ja3", []) if str(x).strip()}
    return al


def _ip_in_cidrs(ip: str, cidrs: list) -> bool:
    if not ip or not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in cidrs)


def is_allowlisted(event, al: Allowlist):
    """Return (suppress: bool, reason: str) for a finding against the allow-list."""
    if not al:
        return False, ""
    for ip in (event.src_ip, event.dst_ip):
        if ip and ip in al.ips:
            return True, f"{ip} is on the allow-list"
        if _ip_in_cidrs(ip, al.cidrs):
            return True, f"{ip} is within an allow-listed network"
    ev = getattr(event, "evidence", {}) or {}
    for key in ("domain", "qname", "indicator", "host"):
        d = str(ev.get(key, "")).lower().rstrip(".")
        if d and d in al.domains:
            return True, f"domain {d} is on the allow-list"
    ja3 = str(ev.get("ja3", "")).lower()
    if ja3 and ja3 in al.ja3:
        return True, "JA3 fingerprint is on the allow-list"
    return False, ""


def apply_suppression(events: list, min_confidence: float | None = None):
    """
    Return (kept, suppressed) where `suppressed` is a list of (event, reason).

    Conservative by design: with the default config (empty allow-list,
    min_confidence = 0) nothing is suppressed, so detection recall is unchanged.
    """
    al = load_allowlist()
    floor = min_confidence if min_confidence is not None else float(config.get("triage", "min_confidence", 0.0) or 0.0)
    kept, suppressed = [], []
    for e in events:
        hit, reason = is_allowlisted(e, al)
        if hit:
            suppressed.append((e, reason))
            continue
        if float(getattr(e, "confidence", 1.0) or 0.0) < floor:
            suppressed.append((e, f"below confidence floor ({floor:.0%})"))
            continue
        kept.append(e)
    return kept, suppressed
