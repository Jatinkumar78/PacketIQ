"""
STIX 2.1 export — turn detected indicators into a standards-compliant STIX
bundle that can be imported into MISP, OpenCTI, or any TAXII/STIX consumer.

Pure Python / stdlib only (no `stix2` dependency required). Produces a
`bundle` containing `indicator` SDOs with proper STIX patterns.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone

from packetiq.detection.models import EventType


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _is_ip(value: str) -> str | None:
    try:
        addr = ipaddress.ip_address(value)
        return "ipv4-addr" if addr.version == 4 else "ipv6-addr"
    except ValueError:
        return None


def _pattern(value: str) -> tuple[str, str]:
    """Return (stix_pattern, observable_kind) for an indicator value."""
    iptype = _is_ip(value)
    if iptype:
        return f"[{iptype}:value = '{value}']", iptype
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return f"[file:hashes.'SHA-256' = '{value.lower()}']", "file"
    return f"[domain-name:value = '{value}']", "domain-name"


def _indicator(value: str, name: str, description: str, created: str) -> dict:
    pattern, _kind = _pattern(value)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": name,
        "description": description,
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
    }


def _collect_indicators(events) -> dict:
    """value -> (name, description). Deduplicated, highest-signal description wins."""
    out: dict = {}

    def add(value, name, desc):
        if value and value not in out:
            out[value] = (name, desc)

    for e in events:
        ev = e.evidence or {}
        et = e.event_type

        if et == EventType.IOC_MATCH:
            ind = ev.get("indicator")
            add(ind, f"{ev.get('label', 'Threat-intel match')}",
                f"{ev.get('source', 'feed')}: {ev.get('label', '')} — {e.description}")
        elif et == EventType.MALICIOUS_FILE:
            add(ev.get("sha256"), "Malware file (MalwareBazaar)", e.description)
        elif et == EventType.C2_BEACON:
            add(e.dst_ip, "C2 beacon destination", e.description)
        elif et == EventType.JA3_ANOMALY:
            add(e.dst_ip, f"Malicious TLS endpoint ({ev.get('malware', 'JA3 match')})", e.description)
        elif et in (EventType.DNS_TUNNELING, EventType.DNS_ANOMALY):
            add(ev.get("domain"), "Suspicious domain", e.description)
        elif et in (EventType.BRUTE_FORCE, EventType.PORT_SCAN, EventType.HOST_SCAN):
            add(e.src_ip, f"Attacker source ({et.value.lower()})", e.description)

    return out


def to_stix_bundle(events, chains=None) -> dict:
    """Build a STIX 2.1 bundle dict from detection events."""
    created = _now()
    indicators = _collect_indicators(events)
    objects = [
        _indicator(value, name, desc, created)
        for value, (name, desc) in sorted(indicators.items())
    ]
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
