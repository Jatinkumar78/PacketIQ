"""
DNS Anomaly Detector.

Detects:
  1. DGA-like domains      — high Shannon entropy + unusual length patterns
  2. DNS tunneling          — excessively long query names (data exfil via DNS)
  3. Excessive query rate   — same domain queried abnormally often
  4. Non-standard resolvers — DNS to unexpected IPs (not common public resolvers)
  5. Rare TLD usage         — queries to suspicious/uncommon TLDs

Uses: ExtractionResult.dns_queries
"""

import math
from collections import Counter, defaultdict

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# ── Thresholds ────────────────────────────────────────────────────────────────
DGA_ENTROPY_THRESHOLD   = 3.8   # Raised from 3.5 — reduces legitimate domain false positives
DGA_MIN_LENGTH          = 12    # Raised from 10 — short labels are rarely DGA
TUNNEL_LABEL_LENGTH     = 50    # query name characters → tunneling suspicion
EXCESSIVE_QUERY_COUNT   = 20    # same domain queried more than N times
RATE_WINDOW_SECS        = 60.0
RATE_THRESHOLD          = 15    # queries to same domain in RATE_WINDOW_SECS

# Well-known public resolvers — DNS to these is normal
KNOWN_RESOLVERS = {
    "8.8.8.8", "8.8.4.4",           # Google
    "1.1.1.1", "1.0.0.1",           # Cloudflare
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "4.2.2.1", "4.2.2.2",           # Level3
    "64.6.64.6", "64.6.65.6",       # Verisign
    "185.228.168.9", "185.228.169.9", # CleanBrowsing
}

# mDNS multicast addresses — always legitimate, never flag
MDNS_MULTICAST = {
    "224.0.0.251",   # IPv4 mDNS (Bonjour/Avahi)
    "ff02::fb",      # IPv6 mDNS
    "ff02::1:3",     # IPv6 LLMNR
    "224.0.0.252",   # IPv4 LLMNR
}

# TLDs that are frequently abused for C2 / fast-flux / phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".info", ".biz",
    ".tk",  ".ml",  ".ga",  ".cf",  ".gq",   # Freenom gTLDs
    ".ru",  ".pw",  ".cc",  ".su",
}

# ── Trusted domain suffixes ───────────────────────────────────────────────────
# Domains whose registered name (sld.tld) is known-good — never flag for DGA.
# Match against the full FQDN with `fqdn.endswith(suffix)` or `fqdn == suffix`.
TRUSTED_DOMAIN_SUFFIXES: set[str] = {
    # CDNs
    "cloudflare.com", "cloudflare.net", "cloudflare-relay.net",
    "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaihd.net",
    "akamaitechnologies.com", "edgesuite.net", "edgekey.net",
    "fastly.net", "fastly.com", "fastlylb.net",
    "llnwd.net", "llnwi.net",          # Limelight
    "cdn.ampproject.org",
    "googleusercontent.com",
    # Google
    "google.com", "google-analytics.com", "googletagmanager.com",
    "googleapis.com", "gstatic.com", "googlesyndication.com",
    "doubleclick.net", "googleadservices.com", "google.co.uk",
    "gmail.com", "youtube.com", "ytimg.com",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "azure.com", "azureedge.net",
    "windows.net", "live.com", "msn.com", "office.com", "office365.com",
    "bing.com", "linkedin.com", "skype.com", "sharepoint.com",
    # Amazon / AWS
    "amazonaws.com", "amazon.com", "awsstatic.com",
    # Apple
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    # Meta / Social
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "twitter.com", "twimg.com", "t.co",
    # Advertising / Analytics (legitimate)
    "adnxs.com", "criteo.com", "outbrain.com", "taboola.com",
    "hotjar.com", "mixpanel.com", "segment.com", "segment.io",
    # Telemetry / Update services
    "digicert.com", "letsencrypt.org", "ocsp.verisign.net",
    "usertrust.com", "comodoca.com",
    # Common SaaS
    "salesforce.com", "hubspot.com", "zendesk.com", "intercom.io",
    "cloudinary.com", "stripe.com", "twilio.com", "sendgrid.net",
    # Akamai / CDN aliases
    "akam.net",
}


def _is_trusted_domain(fqdn: str) -> bool:
    """Return True if the FQDN ends with a known-good registered domain."""
    fqdn = fqdn.rstrip(".").lower()
    for suffix in TRUSTED_DOMAIN_SUFFIXES:
        if fqdn == suffix or fqdn.endswith("." + suffix):
            return True
    return False


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    events.extend(_dga_detection(result))
    events.extend(_tunneling_detection(result))
    events.extend(_excessive_queries(result))
    events.extend(_non_standard_resolver(result))
    events.extend(_suspicious_tld(result))
    return events


# ── DGA Detection ─────────────────────────────────────────────────────────────

def _dga_detection(result: ExtractionResult) -> list[DetectionEvent]:
    """
    Flag domains where the second-level domain label has high Shannon entropy
    (characteristic of algorithmically generated names) and sufficient length.
    Trusted CDN/analytics/cloud domains are explicitly excluded.
    """
    from packetiq import config
    entropy_threshold = config.get("dns", "dga_entropy_threshold", DGA_ENTROPY_THRESHOLD)
    min_length = config.get("dns", "dga_min_length", DGA_MIN_LENGTH)
    events: list[DetectionEvent] = []
    flagged: set[str] = set()

    for q in result.dns_queries:
        qname = q.get("qname", "") or ""
        if not qname:
            continue

        # Skip known-good domains before any entropy calculation
        if _is_trusted_domain(qname):
            continue

        sld = _extract_sld(qname)
        if not sld or sld in flagged:
            continue
        if len(sld) < min_length:
            continue

        entropy = _shannon_entropy(sld)
        if entropy < entropy_threshold:
            continue

        # Additional sanity check: real DGA domains rarely contain hyphens in
        # structured patterns (like "google-analytics"). Skip if it looks like
        # a compound word (has 1-2 hyphens with reasonable sub-word lengths).
        if _looks_like_compound_word(sld):
            continue

        flagged.add(sld)
        events.append(DetectionEvent(
            event_type   = EventType.DNS_ANOMALY,
            severity     = Severity.HIGH,
            src_ip       = q.get("src", ""),
            dst_ip       = q.get("dst"),
            dst_port     = 53,
            protocol     = "DNS",
            description  = f"Potential DGA domain queried: {qname}",
            timestamp    = q.get("ts", 0.0),
            packet_count = 1,
            confidence   = min(1.0, (entropy - DGA_ENTROPY_THRESHOLD) / 1.0),
            evidence     = {
                "domain":           qname,
                "sld":              sld,
                "entropy":          round(entropy, 3),
                "entropy_threshold": DGA_ENTROPY_THRESHOLD,
                "sld_length":       len(sld),
            },
        ))

    return events


def _looks_like_compound_word(sld: str) -> bool:
    """
    Heuristic: legitimate compound names like 'google-analytics' or
    'amazon-cloudfront' have 1-3 hyphens where each segment is ≥ 3 chars.
    Real DGA output rarely has this structured hyphen pattern.
    """
    if "-" not in sld:
        return False
    parts = sld.split("-")
    # All parts have at least 3 chars → likely a human-readable compound name
    if all(len(p) >= 3 for p in parts) and len(parts) <= 4:
        return True
    return False


# ── DNS Tunneling ──────────────────────────────────────────────────────────────

def _tunneling_detection(result: ExtractionResult) -> list[DetectionEvent]:
    """
    DNS tunneling tools (dnscat2, iodine) encode data in query names,
    producing unusually long subdomain labels. Flag queries where the
    full FQDN exceeds TUNNEL_LABEL_LENGTH characters.
    """
    events: list[DetectionEvent] = []
    seen_sources: set[str] = set()

    for q in result.dns_queries:
        qname = q.get("qname", "") or ""
        if len(qname) < TUNNEL_LABEL_LENGTH:
            continue

        # Trusted CDNs with long names (CDN tokens, signed URLs) → skip
        if _is_trusted_domain(qname):
            continue

        src = q.get("src", "")
        if src in seen_sources:
            continue
        seen_sources.add(src)

        long_count = sum(
            1 for x in result.dns_queries
            if x.get("src") == src and len(x.get("qname", "") or "") >= TUNNEL_LABEL_LENGTH
            and not _is_trusted_domain(x.get("qname", "") or "")
        )

        severity = Severity.CRITICAL if long_count >= 5 else Severity.HIGH
        events.append(DetectionEvent(
            event_type   = EventType.DNS_TUNNELING,
            severity     = severity,
            src_ip       = src,
            dst_ip       = q.get("dst"),
            dst_port     = 53,
            protocol     = "DNS",
            description  = (
                f"DNS tunneling suspected — {long_count} oversized "
                f"query names from {src} (longest: {len(qname)} chars)"
            ),
            timestamp    = q.get("ts", 0.0),
            packet_count = long_count,
            confidence   = min(1.0, long_count / 10),
            evidence     = {
                "long_query_count":  long_count,
                "length_threshold":  TUNNEL_LABEL_LENGTH,
                "sample_query":      qname[:80] + ("…" if len(qname) > 80 else ""),
                "sample_length":     len(qname),
            },
        ))

    return events


# ── Excessive Query Rate ───────────────────────────────────────────────────────

def _excessive_queries(result: ExtractionResult) -> list[DetectionEvent]:
    """
    Flag domains queried more than EXCESSIVE_QUERY_COUNT times total,
    and flag sources that hit the same domain very fast (beaconing pattern).
    """
    events: list[DetectionEvent] = []

    domain_counts: Counter = Counter(
        q.get("qname", "") for q in result.dns_queries if q.get("qname")
    )

    for domain, count in domain_counts.items():
        if count < EXCESSIVE_QUERY_COUNT:
            continue

        # Don't flag high-volume queries to known CDN/analytics domains —
        # browsers legitimately hammer these hundreds of times per session.
        if _is_trusted_domain(domain):
            continue

        srcs = list({q["src"] for q in result.dns_queries if q.get("qname") == domain})
        ts_list = sorted(q["ts"] for q in result.dns_queries if q.get("qname") == domain)
        max_rate = _max_window_count(ts_list, RATE_WINDOW_SECS)

        severity = Severity.HIGH if max_rate >= RATE_THRESHOLD else Severity.MEDIUM
        events.append(DetectionEvent(
            event_type   = EventType.DNS_ANOMALY,
            severity     = severity,
            src_ip       = srcs[0] if len(srcs) == 1 else f"{len(srcs)} sources",
            dst_port     = 53,
            protocol     = "DNS",
            description  = (
                f"Excessive DNS queries — {domain!r} queried {count}× "
                f"(max {max_rate} in {int(RATE_WINDOW_SECS)}s)"
            ),
            packet_count = count,
            confidence   = min(1.0, count / 100),
            evidence     = {
                "domain":           domain,
                "total_queries":    count,
                "max_in_window":    max_rate,
                "window_secs":      RATE_WINDOW_SECS,
                "source_ips":       srcs[:5],
                "pattern":          "beaconing" if max_rate >= RATE_THRESHOLD else "high_volume",
            },
        ))

    return events


# ── Non-standard Resolver ──────────────────────────────────────────────────────

def _non_standard_resolver(result: ExtractionResult) -> list[DetectionEvent]:
    """
    DNS queries going to IPs that are NOT known public resolvers or
    the local RFC1918 range may indicate DNS hijacking or rogue resolver use.
    mDNS/LLMNR multicast addresses are excluded — they are always legitimate.
    """
    events: list[DetectionEvent] = []
    from packetiq.utils.helpers import is_private_ip
    flagged: set[tuple] = set()

    for q in result.dns_queries:
        dst = q.get("dst", "") or ""
        if not dst:
            continue
        if dst in KNOWN_RESOLVERS:
            continue
        # mDNS and LLMNR multicast — completely normal link-local protocol
        if dst in MDNS_MULTICAST:
            continue
        # Strip port if present (e.g. "224.0.0.251:53" → "224.0.0.251")
        dst_host = dst.split(":")[0] if ":" in dst and not dst.startswith("[") else dst
        dst_host = dst_host.strip("[]")
        if dst_host in MDNS_MULTICAST:
            continue
        # Any multicast address (224.x.x.x or ff00::/8) is link-local protocol traffic
        if dst_host.startswith("224.") or dst_host.startswith("239.") \
                or dst_host.lower().startswith("ff0") or dst_host.lower().startswith("ff2"):
            continue
        if is_private_ip(dst_host):
            continue

        key = (q.get("src", ""), dst)
        if key in flagged:
            continue
        flagged.add(key)

        events.append(DetectionEvent(
            event_type   = EventType.DNS_ANOMALY,
            severity     = Severity.MEDIUM,
            src_ip       = q.get("src", ""),
            dst_ip       = dst,
            dst_port     = 53,
            protocol     = "DNS",
            description  = f"DNS query to non-standard public resolver: {dst}",
            timestamp    = q.get("ts", 0.0),
            packet_count = 1,
            confidence   = 0.6,
            evidence     = {
                "resolver_ip": dst,
                "known_resolvers": list(KNOWN_RESOLVERS),
            },
        ))

    return events


# ── Suspicious TLD ─────────────────────────────────────────────────────────────

def _suspicious_tld(result: ExtractionResult) -> list[DetectionEvent]:
    """Flag queries to known-abused TLDs."""
    events: list[DetectionEvent] = []
    tld_groups: dict[str, list[dict]] = defaultdict(list)

    for q in result.dns_queries:
        qname = (q.get("qname") or "").lower()
        if _is_trusted_domain(qname):
            continue
        for tld in SUSPICIOUS_TLDS:
            if qname.endswith(tld):
                tld_groups[tld].append(q)
                break

    for tld, queries in tld_groups.items():
        srcs = list({q["src"] for q in queries if q.get("src")})
        domains = list({q["qname"] for q in queries if q.get("qname")})
        events.append(DetectionEvent(
            event_type   = EventType.DNS_ANOMALY,
            severity     = Severity.LOW,
            src_ip       = srcs[0] if len(srcs) == 1 else f"{len(srcs)} sources",
            dst_port     = 53,
            protocol     = "DNS",
            description  = (
                f"Queries to suspicious TLD {tld!r} — "
                f"{len(queries)} queries, {len(domains)} unique domains"
            ),
            packet_count = len(queries),
            confidence   = 0.5,
            evidence     = {
                "tld":             tld,
                "query_count":     len(queries),
                "unique_domains":  len(domains),
                "sample_domains":  domains[:5],
                "source_ips":      srcs[:5],
            },
        ))

    return events


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not text:
        return 0.0
    freq = Counter(text.lower())
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _extract_sld(fqdn: str) -> str:
    """Extract second-level domain label from FQDN (e.g. 'google' from 'www.google.com')."""
    parts = fqdn.rstrip(".").lower().split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else ""


def _max_window_count(sorted_ts: list[float], window: float) -> int:
    """Sliding window maximum — O(n) two-pointer."""
    if not sorted_ts:
        return 0
    left = 0
    best = 0
    for right in range(len(sorted_ts)):
        while sorted_ts[right] - sorted_ts[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best
