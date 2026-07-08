"""
Threat-intel feed loading and the in-memory IOC store.

Feeds are resolved from (later overrides earlier):
  1. packetiq/enrichment/data/   — bundled real snapshots
  2. $PACKETIQ_FEED_DIR or ~/.packetiq/feeds/  — refreshed by `packetiq feeds update`

Each feed is a small text/CSV file; lines starting with '#' are ignored.
If a feed file is missing, that source is simply skipped (never fabricated).
"""

import ipaddress
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from packetiq.detection.models import Severity

_BUNDLED_DIR = Path(__file__).parent / "data"

# Multi-tenant hosting / CDN / paste services. A ThreatFox *URL* IOC on one of
# these (e.g. https://drive.google.com/uc?...=<id> — malware staged on Drive)
# identifies one malicious *path*, not the whole domain, which billions of people
# use legitimately. Collapsing such a URL to its bare host and blocklisting it
# would raise a CRITICAL alert for every user of the service — a false positive.
# We therefore never derive a *domain* IOC for these front-door hosts from a URL.
# (A dedicated-but-shared subdomain, e.g. evil-bucket.s3.amazonaws.com, is unique
# per tenant and is NOT suppressed — only the shared front doors are.)
_SHARED_HOSTERS = frozenset({
    "drive.google.com", "docs.google.com", "sites.google.com", "google.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com",
    "dropboxusercontent.com", "onedrive.live.com", "1drv.ms",
    "github.com", "raw.githubusercontent.com", "githubusercontent.com",
    "objects.githubusercontent.com", "gitlab.com", "bitbucket.org",
    "cdn.discordapp.com", "media.discordapp.net", "discord.com", "discordapp.com",
    "pastebin.com", "paste.ee", "hastebin.com", "controlc.com",
    "t.me", "telegram.me", "telegram.org",
    "s3.amazonaws.com", "amazonaws.com", "cloudfront.net",
    "archive.org", "blogspot.com", "wordpress.com", "sourceforge.net",
    "mediafire.com", "mega.nz", "sendspace.com", "wetransfer.com", "anonfiles.com",
})


def _is_shared_hoster(host: str) -> bool:
    """True for a shared front-door host that must never become a domain IOC."""
    return host in _SHARED_HOSTERS


def cache_dir() -> Path:
    """User-writable feed cache (where `feeds update` writes fresh snapshots)."""
    env = os.environ.get("PACKETIQ_FEED_DIR")
    return Path(env) if env else (Path.home() / ".packetiq" / "feeds")


def _feed_paths(filename: str) -> list[Path]:
    """Bundled first, then cache (cache wins on lookup since we load it last)."""
    return [_BUNDLED_DIR / filename, cache_dir() / filename]


def _read_lines(filename: str):
    """Yield non-comment, non-empty stripped lines from the first existing copy
    in the cache dir, else the bundled copy (cache takes precedence)."""
    for base in (cache_dir(), _BUNDLED_DIR):
        p = base / filename
        if p.is_file():
            with open(p, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        yield line
            return


@dataclass
class IOCHit:
    indicator: str
    kind:      str        # "ip" | "cidr" | "domain" | "hash"
    source:    str        # feed name
    label:     str        # malware family / reason
    severity:  Severity


@dataclass
class IOCStore:
    bad_ips:     dict = field(default_factory=dict)   # ip -> IOCHit
    bad_domains: dict = field(default_factory=dict)   # domain -> IOCHit
    bad_hashes:  dict = field(default_factory=dict)   # sha256 -> IOCHit
    bad_cidrs:   list = field(default_factory=list)   # list[(ip_network, IOCHit)]
    counts:      dict = field(default_factory=dict)   # feed -> entry count

    # ── lookups ──────────────────────────────────────────────────────────────
    def lookup_ip(self, ip: str) -> Optional[IOCHit]:
        hit = self.bad_ips.get(ip)
        if hit:
            return hit
        if self.bad_cidrs:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, chit in self.bad_cidrs:
                if addr in net:
                    return chit
        return None

    def lookup_domain(self, domain: str) -> Optional[IOCHit]:
        d = (domain or "").rstrip(".").lower()
        if not d:
            return None
        if d in self.bad_domains:
            return self.bad_domains[d]
        # match parent domains too (sub.evil.com matches evil.com)
        parts = d.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.bad_domains:
                return self.bad_domains[parent]
        return None

    def lookup_hash(self, sha256: str) -> Optional[IOCHit]:
        return self.bad_hashes.get((sha256 or "").lower())

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _sev(label: str) -> Severity:
    low = label.lower()
    if "tor exit" in low:
        return Severity.MEDIUM
    if "drop" in low or "spamhaus" in low:
        return Severity.HIGH
    return Severity.CRITICAL   # named malware / C2 / botnet


@lru_cache(maxsize=1)
def load_store() -> IOCStore:
    """Build the IOC store from all available feeds (cached)."""
    store = IOCStore()

    # Feodo Tracker C2 IPs:  ip,malware
    n = 0
    for line in _read_lines("feodo_c2.csv"):
        parts = [c.strip() for c in line.split(",")]
        ip = parts[0]
        malware = parts[1] if len(parts) > 1 else "C2"
        label = f"{malware} C2 (Feodo Tracker)"
        store.bad_ips[ip] = IOCHit(ip, "ip", "Feodo Tracker", label, Severity.CRITICAL)
        n += 1
    if n:
        store.counts["Feodo Tracker (C2 IPs)"] = n

    # ThreatFox IOCs:  ioc<TAB>type<TAB>malware
    n = 0
    for line in _read_lines("threatfox.tsv"):
        cells = line.split("\t")
        if len(cells) < 2:
            continue
        ioc, itype = cells[0].strip(), cells[1].strip()
        malware = cells[2].strip() if len(cells) > 2 and cells[2].strip() else "malware"
        label = f"{malware} (ThreatFox)"
        if itype == "ip:port":
            ip = ioc.split(":")[0]
            store.bad_ips.setdefault(ip, IOCHit(ip, "ip", "ThreatFox", label, Severity.CRITICAL))
        elif itype == "domain":
            d = ioc.rstrip(".").lower()
            if d and not _is_shared_hoster(d):
                store.bad_domains.setdefault(d, IOCHit(d, "domain", "ThreatFox", label, Severity.CRITICAL))
        elif itype == "url":
            host = ioc.split("://", 1)[-1].split("/", 1)[0].split(":")[0].rstrip(".").lower()
            # A URL IOC pins one malicious path; only blocklist its host as a domain
            # when that host isn't a shared hoster (else we'd flag every legit user).
            if host and not _is_shared_hoster(host):
                store.bad_domains.setdefault(host, IOCHit(host, "domain", "ThreatFox", label, Severity.CRITICAL))
        n += 1
    if n:
        store.counts["ThreatFox (IOCs)"] = n

    # Tor exit nodes:  one IP per line
    n = 0
    for ip in _read_lines("tor_exits.txt"):
        store.bad_ips.setdefault(ip, IOCHit(ip, "ip", "Tor Project", "Tor exit node", Severity.MEDIUM))
        n += 1
    if n:
        store.counts["Tor exit nodes"] = n

    # Spamhaus DROP:  one CIDR per line
    n = 0
    for cidr in _read_lines("spamhaus_drop.txt"):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        store.bad_cidrs.append(
            (net, IOCHit(cidr, "cidr", "Spamhaus DROP", "Listed netblock (Spamhaus DROP)", Severity.HIGH))
        )
        n += 1
    if n:
        store.counts["Spamhaus DROP (netblocks)"] = n

    # MalwareBazaar SHA-256 (used by file carving):  one hash per line
    n = 0
    for h in _read_lines("malwarebazaar_sha256.txt"):
        h = h.lower()
        if len(h) == 64:
            store.bad_hashes[h] = IOCHit(h, "hash", "MalwareBazaar", "Known malware sample (MalwareBazaar)", Severity.CRITICAL)
            n += 1
    if n:
        store.counts["MalwareBazaar (file hashes)"] = n

    return store


def feed_summary() -> dict:
    """Return {feed_name: entry_count} for `packetiq feeds status`."""
    return dict(load_store().counts)


# Per-feed provenance metadata (real sources). Keyed by file; count_key maps to
# the live indicator counts in load_store().counts.
_FEED_META = [
    {"file": "feodo_c2.csv", "count_key": "Feodo Tracker (C2 IPs)",
     "name": "Feodo Tracker", "provider": "abuse.ch", "category": "Botnet C2",
     "kind": "IPv4", "severity": "CRITICAL", "url": "https://feodotracker.abuse.ch/",
     "desc": "Active botnet command-and-control servers (Dridex, Emotet, TrickBot, QakBot…)."},
    {"file": "threatfox.tsv", "count_key": "ThreatFox (IOCs)",
     "name": "ThreatFox", "provider": "abuse.ch", "category": "Mixed IOCs",
     "kind": "IP · domain · URL", "severity": "CRITICAL", "url": "https://threatfox.abuse.ch/",
     "desc": "Community IOC exchange — indicators tied to currently active malware."},
    {"file": "tor_exits.txt", "count_key": "Tor exit nodes",
     "name": "Tor Exit Nodes", "provider": "The Tor Project", "category": "Anonymiser",
     "kind": "IPv4", "severity": "MEDIUM", "url": "https://check.torproject.org/torbulkexitlist",
     "desc": "Current Tor exit relays — anonymised ingress/egress traffic."},
    {"file": "spamhaus_drop.txt", "count_key": "Spamhaus DROP (netblocks)",
     "name": "Spamhaus DROP", "provider": "Spamhaus", "category": "Hijacked netblocks",
     "kind": "CIDR", "severity": "HIGH", "url": "https://www.spamhaus.org/drop/",
     "desc": "Don't Route Or Peer — netblocks controlled by threat actors / hijackers."},
    {"file": "malwarebazaar_sha256.txt", "count_key": "MalwareBazaar (file hashes)",
     "name": "MalwareBazaar", "provider": "abuse.ch", "category": "Malware samples",
     "kind": "SHA-256", "severity": "CRITICAL", "url": "https://bazaar.abuse.ch/",
     "desc": "Hashes of known malware samples — matched against carved files."},
]


def _resolve(filename: str):
    """Return (path, origin) for the copy actually used: refreshed cache wins."""
    for base, origin in ((cache_dir(), "refreshed"), (_BUNDLED_DIR, "bundled")):
        p = base / filename
        if p.is_file():
            return p, origin
    return None, None


def feed_details() -> list:
    """
    Rich, real per-feed provenance for the GUI: provider, category, indicator
    kind, severity, live count, on-disk last-updated time and freshness. No
    values are fabricated — counts come from the loaded store and timestamps
    from the actual files on disk.
    """
    import time as _t

    counts = load_store().counts
    now = _t.time()
    out = []
    for m in _FEED_META:
        path, origin = _resolve(m["file"])
        if not path:
            continue
        mtime = path.stat().st_mtime
        age_days = max(0, (now - mtime) / 86400.0)
        out.append({
            "name": m["name"], "provider": m["provider"], "category": m["category"],
            "kind": m["kind"], "severity": m["severity"], "url": m["url"], "desc": m["desc"],
            "count": int(counts.get(m["count_key"], 0)),
            "updated_epoch": mtime,
            "updated_iso": _t.strftime("%Y-%m-%d %H:%M", _t.localtime(mtime)),
            "age_days": round(age_days, 1),
            "origin": origin,   # "refreshed" (from feeds update) or "bundled" (shipped snapshot)
        })
    out.sort(key=lambda f: -f["count"])
    return out
