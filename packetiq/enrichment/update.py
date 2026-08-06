"""
Feed refresher — downloads fresh OSINT feeds and writes normalized snapshots
into the user cache dir (the same filenames/format the loader reads, so a
refresh transparently overrides the bundled snapshots).

Used by:  packetiq feeds update
All downloads are best-effort; a failed feed leaves the previous copy intact.
"""

import csv
import datetime
import io
import json

import requests

from packetiq.enrichment.feeds import cache_dir

_UA = {"User-Agent": "PacketIQ/1.0 (+threat-intel refresh)"}
_TIMEOUT = 30


def _stamp_header(name: str, source: str, fmt: str) -> str:
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"# PacketIQ feed: {name}\n"
        f"# Source : {source}\n"
        f"# Format : {fmt}\n"
        f"# Refreshed: {ts}\n"
        f"# Lines starting with '#' are ignored.\n"
    )


# Each entry: (output filename, url, header tuple, normalizer(text) -> list[str])
def _norm_feodo(text: str) -> list[str]:
    rows = []
    for r in csv.reader(io.StringIO(text)):
        if not r or r[0].startswith("#") or r[0] == "first_seen_utc":
            continue
        if len(r) >= 6 and r[1].count(".") == 3:
            rows.append(f"{r[1]},{r[5]}")
    return rows


def _norm_tor(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")]


def _norm_drop(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            if o.get("cidr"):
                out.append(o["cidr"])
        except Exception:  # nosec B112 # skip a malformed feed line, keep parsing the rest
            continue
    return out


def _norm_malwarebazaar(text: str) -> list[str]:
    return [l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#") and len(l.strip()) == 64]


def _norm_threatfox(text: str) -> list[str]:
    out = []
    for r in csv.reader(io.StringIO(text)):
        if not r or r[0].strip().startswith("#"):
            continue
        cells = [c.strip().strip('"').strip() for c in r]
        if len(cells) < 8:
            continue
        ioc, itype, malware = cells[2], cells[3], (cells[7] or cells[5])
        if itype in ("ip:port", "domain", "url") and ioc:
            out.append(f"{ioc}\t{itype}\t{malware}")
    return out


FEEDS = {
    "feodo_c2.csv": (
        "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        ("Feodo Tracker C2 IPs", "abuse.ch Feodo Tracker", "ip,malware"),
        _norm_feodo,
    ),
    "threatfox.tsv": (
        "https://threatfox.abuse.ch/export/csv/recent/",
        ("ThreatFox IOCs (recent)", "abuse.ch ThreatFox", "ioc<TAB>type<TAB>malware"),
        _norm_threatfox,
    ),
    "tor_exits.txt": (
        "https://check.torproject.org/torbulkexitlist",
        ("Tor exit nodes", "Tor Project", "one IP per line"),
        _norm_tor,
    ),
    "spamhaus_drop.txt": (
        "https://www.spamhaus.org/drop/drop_v4.json",
        ("Spamhaus DROP", "Spamhaus", "one CIDR per line"),
        _norm_drop,
    ),
    "malwarebazaar_sha256.txt": (
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        ("MalwareBazaar recent SHA-256", "abuse.ch MalwareBazaar", "one sha256 per line"),
        _norm_malwarebazaar,
    ),
}


def update_feeds(progress=None) -> dict:
    """
    Download and normalize all feeds into the cache dir.
    Returns {filename: count_or_error_string}. `progress` is an optional
    callable(name:str) for UI updates.
    """
    out_dir = cache_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    results: dict = {}

    for filename, (url, header, normalizer) in FEEDS.items():
        if progress:
            progress(filename)
        try:
            resp = requests.get(url, headers=_UA, timeout=_TIMEOUT)
            resp.raise_for_status()
            rows = normalizer(resp.text)
            if not rows:
                results[filename] = "error: feed returned no usable rows"
                continue
            body = _stamp_header(*header) + "\n".join(rows) + "\n"
            (out_dir / filename).write_text(body, encoding="utf-8")
            results[filename] = len(rows)
        except Exception as exc:  # noqa: BLE001 — best-effort, report per feed
            results[filename] = f"error: {type(exc).__name__}: {exc}"

    return results
