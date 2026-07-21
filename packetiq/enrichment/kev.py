"""
CISA KEV (Known Exploited Vulnerabilities) cross-reference.

NVD tells us *which* CVEs affect a piece of software; CISA's KEV catalogue tells
us which of those are being **actively exploited in the wild** — the single most
important real-world prioritisation signal for a SOC. This module fetches the
official KEV JSON (free, no key), caches it locally, and lets PacketIQ flag any
CVE that appears in it. Everything is real CISA data; nothing is invented, and if
there's no network/cache the cross-reference simply returns "unknown" (False).

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import contextlib
import json
import time
from functools import lru_cache

import requests

from packetiq.enrichment.feeds import cache_dir

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_NAME = "cisa_kev.json"
_MAX_AGE = 7 * 24 * 3600  # refresh weekly


def _cache_path():
    return cache_dir() / _CACHE_NAME


def refresh(timeout: int = 25) -> int:
    """Download the live KEV catalogue into the cache. Returns the entry count."""
    resp = requests.get(KEV_URL, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    load.cache_clear()
    return len(data.get("vulnerabilities", []))


@lru_cache(maxsize=1)
def load() -> dict:
    """
    Return {cve_id: entry}. Uses the cached copy; if it's missing or stale it
    tries one live refresh. Never raises — returns {} when unavailable.
    """
    path = _cache_path()
    fresh = path.is_file() and (time.time() - path.stat().st_mtime) < _MAX_AGE
    if not fresh:
        # offline / blocked — fall back to any cached copy below
        with contextlib.suppress(Exception):
            refresh()
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out = {}
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if cid:
            out[cid] = {
                "cve": cid,
                "name": v.get("vulnerabilityName", ""),
                "date_added": v.get("dateAdded", ""),
                "action": v.get("requiredAction", ""),
                "due": v.get("dueDate", ""),
                "ransomware": (v.get("knownRansomwareCampaignUse", "") or "").lower() == "known",
            }
    return out


def is_kev(cve_id: str) -> bool:
    """True if the CVE is on CISA's actively-exploited list."""
    return (cve_id or "").upper() in load()


def kev_info(cve_id: str):
    """Return the KEV entry for a CVE, or None."""
    return load().get((cve_id or "").upper())


def count() -> int:
    return len(load())


def available() -> bool:
    return bool(load())
