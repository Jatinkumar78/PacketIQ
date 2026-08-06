"""
NVD (National Vulnerability Database) CVE lookup.

PacketIQ reads *real* software banners from a capture — HTTP `Server` response
headers and `User-Agent` request headers — and queries NIST's official NVD REST
API 2.0 for matching CVEs. Every CVE returned here comes straight from NVD: IDs,
CVSS scores, descriptions and publish dates are never invented. If no banners are
observed, or there's no network / API key, the result is empty with a clear note
(no fabricated vulnerabilities).

An API key is optional but recommended — it raises NVD's rate limit from ~5 to
~50 requests per 30 s. Set `NVD_API_KEY` in your `.env` (get one free at
https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# User-Agent tokens that are browsers/OS noise, not a single CVE-searchable product.
_UA_NOISE = re.compile(r"\b(mozilla|applewebkit|gecko|khtml|like|windows|macintosh|"
                       r"x11|linux|android|iphone|ipad|safari|version)\b", re.I)
_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}")


def get_api_key() -> str | None:
    """Resolve the NVD API key from the environment or a local .env file."""
    key = os.environ.get("NVD_API_KEY")
    if key and key.strip():
        return key.strip()
    for path in (".", ".."):
        env_file = Path(path) / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line.startswith("NVD_API_KEY") and "=" in line:
                    v = line.partition("=")[2].strip().strip('"').strip("'")
                    return v or None
            break
    return None


def parse_banner(value: str) -> tuple[str, str]:
    """
    Best-effort (product, version) from a banner like:
      'Apache/2.4.49 (Unix)'   -> ('Apache', '2.4.49')
      'nginx/1.18.0'           -> ('nginx', '1.18.0')
      'Microsoft-IIS/10.0'     -> ('Microsoft-IIS', '10.0')
      'curl/7.68.0'            -> ('curl', '7.68.0')
    Returns ('', '') when nothing product-like can be extracted.
    """
    value = (value or "").strip()
    if not value:
        return "", ""
    token = value.split()[0]
    product, _, version = token.partition("/")
    product = product.strip()
    version = version.strip()
    if not _VERSION_RE.match(version):
        version = ""
    # Drop obvious browser/OS noise tokens that don't map to a single product.
    if _UA_NOISE.search(product):
        return "", ""
    return product, version


def keyword_for(banner: dict) -> str:
    """Build the NVD keyword search string for an observed banner."""
    product, version = parse_banner(banner.get("value", ""))
    if not product:
        return ""
    return f"{product} {version}".strip()


def _best_cvss(metrics: dict) -> tuple[float | None, str]:
    """Pick the most authoritative CVSS (v3.1 > v3.0 > v2) -> (score, severity)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            data = arr[0].get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity", "")
    arr = metrics.get("cvssMetricV2") or []
    if arr:
        data = arr[0].get("cvssData", {})
        return data.get("baseScore"), arr[0].get("baseSeverity", "")
    return None, ""


def _parse_cve(item: dict) -> dict:
    cve = item.get("cve", {})
    cid = cve.get("id", "")
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"),
                descs[0]["value"] if descs else "")
    score, severity = _best_cvss(cve.get("metrics", {}))
    return {
        "id": cid,
        "description": desc,
        "cvss": score,
        "severity": (severity or "").upper(),
        "published": cve.get("published", "")[:10],
        "url": f"https://nvd.nist.gov/vuln/detail/{cid}" if cid else "",
    }


class NVDClient:
    """Thin client over the official NVD REST API 2.0."""

    def __init__(self, api_key: str | None = None, timeout: int = 25):
        self.api_key = api_key or get_api_key()
        self.timeout = timeout

    def search(self, keyword: str, limit: int = 8) -> list[dict]:
        """Return real CVEs whose NVD record matches `keyword`. Raises on HTTP error."""
        if not keyword.strip():
            return []
        params: dict[str, str | int] = {
            "keywordSearch": keyword,
            "resultsPerPage": max(1, min(limit, 20)),
        }
        headers = {"apiKey": self.api_key} if self.api_key else {}
        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=self.timeout)
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        data = resp.json()
        cves = [_parse_cve(v) for v in data.get("vulnerabilities", [])]
        # Highest CVSS first (None last)
        cves.sort(key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)))
        return cves


def lookup_banners(banners: list[dict], api_key: str | None = None,
                   max_products: int = 8, per_product: int = 6) -> dict:
    """
    Query NVD for each distinct, version-bearing software banner observed in a
    capture. Returns a structured, JSON-serialisable result.

    {
      "available": bool,           # was an API key present?
      "queried": [keyword, ...],
      "results": [ {product, version, source, ips, keyword, cves: [...] } ],
      "note": str,                 # human explanation (esp. when empty)
      "error": str | None,
    }
    """
    key = api_key or get_api_key()
    client = NVDClient(api_key=key)

    # Distinct, version-bearing products (most CVE-relevant), server software first.
    seen: set[str] = set()
    targets: list[dict] = []
    for b in banners or []:
        product, version = parse_banner(b.get("value", ""))
        if not product or not version:        # need a version for a meaningful CVE match
            continue
        kw = f"{product} {version}"
        norm = kw.lower()
        if norm in seen:
            continue
        seen.add(norm)
        targets.append({"product": product, "version": version, "keyword": kw,
                        "source": b.get("source", ""), "ips": b.get("ips", [])})
        if len(targets) >= max_products:
            break

    if not targets:
        return {"available": bool(key), "queried": [], "results": [],
                "note": ("No version-bearing software banners were observed in this capture "
                         "(e.g. HTTP Server / User-Agent headers). Encrypted (HTTPS) traffic "
                         "does not expose these, so there is nothing to look up — by design, "
                         "PacketIQ never invents software or CVEs."),
                "error": None}

    results: list[dict] = []
    error = None
    for i, t in enumerate(targets):
        try:
            cves = client.search(t["keyword"], limit=per_product)
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            break
        results.append({**t, "cves": cves})
        # Be polite to NVD: ~6 req/30s without a key, ~50/30s with one.
        if i < len(targets) - 1:
            time.sleep(0.7 if key else 6.0)

    total = sum(len(r["cves"]) for r in results)
    note = (f"Matched {total} CVE(s) across {len(results)} product(s) from real NVD data."
            if total else "No NVD CVEs matched the observed software versions.")
    if not key:
        note += " (No NVD_API_KEY set — using the lower anonymous rate limit.)"
    return {"available": bool(key), "queried": [t["keyword"] for t in targets],
            "results": results, "note": note, "error": error}


# ── CPE-based, version-aware vulnerability assessment (the "perfect map") ─────

CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# Observed exploit signatures (from the HTTP attack detector) → the specific CVE
# they target. Only deterministic 1:1 mappings are listed; generic classes
# (SQLi/XSS) have no single CVE and are left out.
EXPLOIT_SIGNATURE_CVE = {
    "Log4Shell / JNDI": {"cves": ["CVE-2021-44228", "CVE-2021-45046"],
                         "name": "Apache Log4j 2 RCE (Log4Shell)"},
}


def cvss_to_severity(score) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def resolve_cpe(product: str, version: str, api_key: str | None = None, timeout: int = 25):
    """
    Resolve an observed product+version to an official CPE 2.3 name via NVD's CPE
    dictionary. Returns the best matching cpeName (application CPEs preferred,
    deprecated excluded) or None. This is what makes the CVE match version-aware
    rather than a fuzzy keyword search.
    """
    kw = f"{product} {version}".strip()
    if not kw:
        return None
    key = api_key or get_api_key()
    headers = {"apiKey": key} if key else {}
    try:
        cpe_params: dict[str, str | int] = {"keywordSearch": kw, "resultsPerPage": 30}
        resp = requests.get(CPE_URL, params=cpe_params, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return None
        prods = resp.json().get("products", [])
    except Exception:
        return None
    versioned: list[str] = []
    fallback: list[str] = []
    for p in prods:
        c = p.get("cpe", {})
        name = c.get("cpeName", "")
        if not name or c.get("deprecated"):
            continue
        (versioned if version in name else fallback).append(name)
    cands = versioned or fallback
    # prefer application CPEs (cpe:2.3:a:)
    cands.sort(key=lambda n: (":a:" not in n, len(n)))
    return cands[0] if cands else None


def _cves_by_cpe(client: NVDClient, cpe_name: str, fetch: int = 200) -> list:
    """Fetch CVEs whose NVD configuration matches this exact CPE (version-aware).
    Fetches a full page so high-severity CVEs aren't lost to NVD's default order."""
    params: dict[str, str | int] = {"cpeName": cpe_name, "resultsPerPage": max(1, min(fetch, 2000))}
    headers = {"apiKey": client.api_key} if client.api_key else {}
    resp = requests.get(NVD_URL, params=params, headers=headers, timeout=client.timeout)
    if resp.status_code != 200:
        return []
    cves = [_parse_cve(v) for v in resp.json().get("vulnerabilities", [])]
    cves.sort(key=lambda c: (c["cvss"] is None, -(c["cvss"] or 0)))
    return cves


def assess_vulnerabilities(banners: list, http_attacks: list | None = None,
                           api_key: str | None = None, max_products: int = 8,
                           per_product: int = 8) -> dict:
    """
    Build a real, per-host vulnerability picture from observed software:
      observed banner → CPE → NVD CVEs (version-aware) → CVSS severity →
      CISA-KEV (actively-exploited) cross-reference, plus correlation of any
      observed exploit attempts against the target's actual vulnerable software.

    All data is real (NVD + CISA). Returns a JSON-serialisable structure used by
    the Vulnerabilities panel, the CLI and the report.
    """
    from packetiq.enrichment import kev

    key = api_key or get_api_key()
    client = NVDClient(api_key=key)

    # distinct, version-bearing products (server software first)
    seen: set = set()
    targets = []
    for b in banners or []:
        product, version = parse_banner(b.get("value", ""))
        if not product or not version:
            continue
        norm = f"{product} {version}".lower()
        if norm in seen:
            continue
        seen.add(norm)
        targets.append({"product": product, "version": version,
                        "source": b.get("source", ""), "ips": b.get("ips", []) or []})
        if len(targets) >= max_products:
            break

    products, error = [], None
    for i, t in enumerate(targets):
        try:
            cpe = resolve_cpe(t["product"], t["version"], api_key=key)
            cves = _cves_by_cpe(client, cpe) if cpe else client.search(
                f"{t['product']} {t['version']}", limit=20)
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
            break
        for c in cves:
            info = kev.kev_info(c["id"])
            c["kev"] = info is not None
            c["ransomware"] = bool(info and info.get("ransomware"))
            c["severity"] = c.get("severity") or cvss_to_severity(c.get("cvss"))
            if info:
                c["kev_action"] = info.get("action", "")
        # actively-exploited (KEV) first, then by CVSS — keep the most important
        cves.sort(key=lambda c: (not c["kev"], c["cvss"] is None, -(c["cvss"] or 0)))
        cves = cves[:per_product]
        products.append({**t, "cpe": cpe, "cves": cves,
                         "max_cvss": max([c["cvss"] for c in cves if c["cvss"] is not None], default=None),
                         "kev_count": sum(1 for c in cves if c["kev"])})
        if i < len(targets) - 1:
            time.sleep(0.4 if key else 6.0)

    # per-host roll-up (attack surface)
    hosts: dict = {}
    for p in products:
        for ip in p["ips"]:
            h = hosts.setdefault(ip, {"ip": ip, "products": [], "cve_count": 0,
                                      "kev_count": 0, "max_cvss": None})
            h["products"].append(f"{p['product']} {p['version']}")
            h["cve_count"] += len(p["cves"])
            h["kev_count"] += p["kev_count"]
            if p["max_cvss"] is not None:
                h["max_cvss"] = max(h["max_cvss"] or 0, p["max_cvss"])
    host_list = sorted(hosts.values(), key=lambda h: (-(h["kev_count"]), -(h["max_cvss"] or 0)))

    # exploit-attempt ↔ CVE correlation (attack seen + target vulnerable)
    correlations = []
    vuln_versions = {ip: [f"{p['product']} {p['version']}" for p in products if ip in p["ips"]]
                     for ip in hosts}
    for a in http_attacks or []:
        label = a.get("attack_type", "")
        target = a.get("dst_ip", "")
        m = EXPLOIT_SIGNATURE_CVE.get(label)
        if not m:
            continue
        kev_cves = [cid for cid in m["cves"] if kev.is_kev(cid)]
        correlations.append({
            "attack": label, "name": m["name"], "target": target,
            "cves": m["cves"], "kev": bool(kev_cves),
            "target_software": vuln_versions.get(target, []),
        })

    # vulnerability risk score (0-100) from peak CVSS + KEV presence
    all_cvss = [c["cvss"] for p in products for c in p["cves"] if c["cvss"] is not None]
    any_kev = any(p["kev_count"] for p in products)
    vscore = int(max(all_cvss) * 10) if all_cvss else 0
    if any_kev:
        vscore = max(vscore, 90)
    vscore = min(100, vscore)
    vtier = "CRITICAL" if vscore >= 90 else "HIGH" if vscore >= 70 else "MEDIUM" if vscore >= 40 else "LOW" if vscore else "NONE"

    total_cves = sum(len(p["cves"]) for p in products)
    total_kev = sum(p["kev_count"] for p in products)
    if not targets:
        note = ("No version-bearing software banners were observed (encrypted traffic exposes none). "
                "PacketIQ never invents software or CVEs.")
    elif total_cves:
        note = (f"{total_cves} CVE(s) across {len(products)} product(s); "
                f"{total_kev} actively exploited (CISA KEV). All data from NVD + CISA.")
    else:
        note = "Observed software resolved to CPE but no current CVEs matched."
    if not key:
        note += " (No NVD_API_KEY — anonymous rate limit.)"

    return {
        "available": bool(key),
        "products": products,
        "hosts": host_list,
        "correlations": correlations,
        "risk": {"score": vscore, "tier": vtier},
        "totals": {"cves": total_cves, "kev": total_kev, "products": len(products),
                   "kev_catalog": kev.count()},
        "note": note,
        "error": error,
    }
