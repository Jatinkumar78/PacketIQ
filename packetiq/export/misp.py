"""
MISP integration — build a MISP Event from detected indicators and push it to a
MISP instance via the REST API.

Pure stdlib + requests (no `pymisp` dependency). Credentials come from args or
the environment: MISP_URL, MISP_KEY (and optional MISP_VERIFY_TLS=0 to skip cert
verification for self-signed lab instances).
"""

from __future__ import annotations

import os

import requests

from packetiq.export.stix_export import _collect_indicators, _is_ip

_TIMEOUT = 30


def _attr_type(value: str) -> str:
    if _is_ip(value):
        return "ip-dst"
    if len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower()):
        return "sha256"
    return "domain"


def to_misp_event(events, info: str | None = None, threat_level_id: str = "2") -> dict:
    """
    Build a MISP Event JSON payload from detection events.
    threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined.
    """
    indicators = _collect_indicators(events)
    attributes = []
    for value, (name, desc) in sorted(indicators.items()):
        atype = _attr_type(value)
        category = "Payload delivery" if atype == "sha256" else "Network activity"
        attributes.append({
            "type": atype,
            "category": category,
            "value": value,
            "to_ids": True,
            "comment": (name or desc or "")[:255],
        })

    return {
        "Event": {
            "info": info or "PacketIQ — automated PCAP analysis indicators",
            "distribution": "0",          # your organisation only
            "threat_level_id": threat_level_id,
            "analysis": "1",              # ongoing
            "Attribute": attributes,
        }
    }


def push_to_misp(event: dict, url: str | None = None, key: str | None = None,
                 verify_tls: bool | None = None) -> tuple[bool, str]:
    """POST a MISP Event to {url}/events. Returns (ok, message/event_id)."""
    url = (url or os.environ.get("MISP_URL") or "").rstrip("/")
    key = key or os.environ.get("MISP_KEY")
    if verify_tls is None:
        verify_tls = os.environ.get("MISP_VERIFY_TLS", "1") not in ("0", "false", "False")
    if not url or not key:
        return False, "MISP_URL and MISP_KEY are required (args or environment)."

    if not event.get("Event", {}).get("Attribute"):
        return False, "No indicators to push."

    try:
        resp = requests.post(
            f"{url}/events",
            headers={"Authorization": key, "Accept": "application/json",
                     "Content-Type": "application/json"},
            json=event, timeout=_TIMEOUT, verify=verify_tls,
        )
    except Exception as e:  # noqa: BLE001
        return False, f"Request failed: {e}"

    if resp.status_code in (200, 201):
        try:
            eid = resp.json().get("Event", {}).get("id", "?")
        except Exception:
            eid = "?"
        return True, f"Created MISP event id={eid}"
    return False, f"HTTP {resp.status_code}: {resp.text[:200]}"
