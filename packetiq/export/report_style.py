"""
Shared house style for every PacketIQ report surface — the PDF, the HTML export
and the AI-written incident report — so all three carry the same identity,
section structure and honesty statements.

Nothing here renders anything. It is the single place that decides what a
PacketIQ report is *called*, how its sections are numbered, and what it claims
(and refuses to claim) about its own findings.
"""

from __future__ import annotations

import hashlib
from datetime import datetime

BRAND = "PacketIQ"
DOC_TITLE = "Network Forensics & Incident Report"
CLASSIFICATION = "CONFIDENTIAL — Handle in accordance with your organisation's policy"
CLASSIFICATION_SHORT = "CONFIDENTIAL"   # page furniture, where space is tight

# Canonical section order, shared by the PDF, the HTML report and the AI prompt.
SECTIONS: tuple = (
    "Executive Summary",
    "Scope & Methodology",
    "Capture Overview",
    "Risk Assessment",
    "Detection Findings",
    "Finding Details",
    "Attack Chain Analysis",
    "MITRE ATT&CK Coverage",
    "Network Activity",
    "Indicators of Compromise",
    "Recommended Actions",
    "Limitations & Assurance",
)

# ── Palette (hex, shared with the HTML report) ────────────────────────────────
INK      = "#0B1F3A"     # headings, table header fill
ACCENT   = "#1E4E79"     # section numbers / rules
BODY     = "#1F2937"     # body copy
SLATE    = "#475569"     # secondary copy
MUTED    = "#6B7280"     # captions, footnotes
RULE     = "#D7DEE8"     # hairlines
BG_ALT   = "#F5F8FB"     # zebra row fill

SEVERITY_COLOURS = {
    "CRITICAL": "#A4123F",
    "HIGH":     "#C2410C",
    "MEDIUM":   "#A16207",
    "LOW":      "#15803D",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ── Standing text ─────────────────────────────────────────────────────────────

METHODOLOGY = (
    "The capture was parsed packet-by-packet and reduced to flows, protocol "
    "statistics and application-layer artefacts. Deterministic detectors were then "
    "applied for scanning, brute force, beaconing, DNS tunnelling, credential "
    "exposure, protocol misuse and file transfer, alongside reputation lookups "
    "against the threat-intelligence snapshots bundled with the tool. Related "
    "findings were correlated into attack chains and mapped to MITRE ATT&CK "
    "techniques. Every figure in this report is derived from the capture itself; "
    "no value is estimated, inferred by a language model, or supplied from outside "
    "the evidence."
)

LIMITATIONS = (
    "Findings are produced by heuristic detectors and by matching against "
    "threat-intelligence snapshots that were current when this build was packaged. "
    "A confidence value expresses a detector's certainty in its own pattern match; "
    "it is not proof of compromise, and it is not a probability of malice. "
    "Encrypted payloads are not decrypted, so activity inside TLS sessions is "
    "characterised only by its metadata. This report reflects a single capture from "
    "a single vantage point and cannot show activity that was never on the wire. "
    "Passive fingerprints such as TTL-derived operating-system hints and payload "
    "entropy are indicators, not identifications. Corroborate high-impact findings "
    "against your own endpoint and log telemetry before acting on them."
)

ATTRIBUTION_CAVEAT = (
    "Technique overlap with a named threat actor indicates similarity of observed "
    "behaviour only. It is not attribution and must not be reported as such."
)


def generated_at() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def report_id(filename: str, sha256: str = "") -> str:
    """A stable, human-quotable identifier for a report on a given capture."""
    seed = (sha256 or "").strip() or hashlib.sha256(filename.encode("utf-8", "replace")).hexdigest()
    return f"PIQ-{datetime.now().strftime('%Y%m%d')}-{seed[:8].upper()}"


def tool_version() -> str:
    try:
        from packetiq import __version__
        return str(__version__)
    except Exception:
        return "1.0.0"


# Tokens that must stay upper-case when an event type is turned into prose —
# str.title() would otherwise produce "Ioc Match" and "Dns Tunneling".
_ACRONYMS = {"IOC", "DNS", "HTTP", "HTTPS", "TLS", "SSL", "ICMP", "SMB", "FTP", "SMTP",
             "RDP", "ARP", "TCP", "UDP", "SSH", "JA3", "C2", "DGA", "NTP", "LDAP",
             "SNMP", "YARA", "URL", "URI", "IP"}


def event_title(event_type: str) -> str:
    """'DNS_TUNNELING' → 'DNS Tunneling'; 'IOC_MATCH' → 'IOC Match'."""
    words = []
    for token in str(event_type or "").split("_"):
        if not token:
            continue
        words.append(token.upper() if token.upper() in _ACRONYMS else token.capitalize())
    return " ".join(words)


def sort_events(events: list) -> list:
    """Findings, most severe first, then most confident."""
    return sorted(events or [],
                  key=lambda e: (SEVERITY_ORDER.get(e.get("severity", ""), 9),
                                 -int(e.get("confidence", 0) or 0)))


def recommendations(events: list) -> list:
    """Unique analyst recommendations attached to findings, severity-ordered.
    These come from the triage layer — they are not invented for the report."""
    seen: set = set()
    out: list = []
    for e in sort_events(events):
        rec = (e.get("recommendation") or "").strip()
        if rec and rec.lower() not in seen:
            seen.add(rec.lower())
            out.append(rec)
    return out


def iocs(res: dict) -> list:
    """Grouped indicators, drawn only from what the analysis actually observed."""
    events = res.get("events", []) or []

    intel: list = []
    for match in res.get("threat_intel_matches", []) or []:
        for hit in match.get("matches", [])[:20]:
            ind = hit.get("indicator")
            if ind:
                intel.append(str(ind))

    hosts: list = []
    for e in events:
        for ip in (e.get("src_ip"), e.get("dst_ip")):
            if ip:
                hosts.append(ip)

    domains = [d for d, _c in (res.get("dns_top", []) or [])][:25]

    groups = [
        ("Threat-intelligence matches", _dedup(intel)),
        ("Hosts named in findings", _dedup(hosts)),
        ("Domains queried (DNS)", _dedup(domains)),
    ]
    return [(label, vals) for label, vals in groups if vals]


def mitre_rows(res: dict) -> list:
    """Flatten MITRE coverage to (tactic, technique id, name, count, severity)."""
    rows = []
    for t in res.get("attack_coverage", []) or []:
        rows.append((t.get("tactic", "—"), t.get("id", ""), t.get("name", ""),
                     t.get("count", 0), t.get("severity", "")))
    rows.sort(key=lambda r: (r[0], r[1]))
    return rows


def protocol_mix(res: dict, limit: int = 8) -> list:
    """(protocol, packets, percent) ordered by volume."""
    protos = res.get("protocols", {}) or {}
    total = sum(protos.values()) or 1
    top = sorted(protos.items(), key=lambda kv: -kv[1])[:limit]
    return [(name, count, 100.0 * count / total) for name, count in top]


def _dedup(items) -> list:
    seen: set = set()
    out: list = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out
