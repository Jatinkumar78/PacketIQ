"""
Tests for threat-intel IOC enrichment against the bundled real feeds.
"""

from packetiq.detection.models import EventType
from packetiq.enrichment import enrich, feed_details, feed_summary
from packetiq.enrichment.feeds import load_store
from packetiq.extractor.data_extractor import ExtractionResult


def test_bundled_feeds_load():
    summary = feed_summary()
    assert summary, "bundled feeds should load"
    # Tor + Spamhaus DROP + ThreatFox are sizeable real snapshots
    assert sum(summary.values()) > 1000


def test_feed_details_provenance():
    """Rich per-feed metadata must be real and well-formed."""
    det = feed_details()
    assert det, "feed_details should return loaded feeds"
    required = {"name", "provider", "category", "kind", "severity",
                "url", "count", "updated_iso", "age_days", "origin"}
    for f in det:
        assert required <= set(f), f"missing keys in {f.get('name')}"
        assert f["count"] > 0
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert f["origin"] in {"bundled", "refreshed"}
        assert f["url"].startswith("http")
    names = {f["name"] for f in det}
    assert {"Feodo Tracker", "ThreatFox", "Spamhaus DROP"} <= names


def test_ip_match_against_real_feed():
    store = load_store()
    # take a real Tor exit IP from the loaded store
    tor_ip = next(ip for ip, hit in store.bad_ips.items() if "Tor exit" in hit.label)
    res = ExtractionResult()
    res.external_ips = {tor_ip}
    res.ip_dst_counts = {tor_ip: 3}
    events = enrich(res, store)
    assert any(e.event_type == EventType.IOC_MATCH and e.dst_ip == tor_ip for e in events)


def test_cidr_match_against_spamhaus():
    store = load_store()
    assert store.bad_cidrs, "Spamhaus DROP CIDRs should load"
    net = store.bad_cidrs[0][0]
    ip_in_range = str(next(iter(net.hosts())))
    res = ExtractionResult()
    res.external_ips = {ip_in_range}
    events = enrich(res, store)
    assert any(e.dst_ip == ip_in_range for e in events)


def test_clean_capture_has_no_ioc_matches():
    """A capture that only touches benign infrastructure must not match."""
    res = ExtractionResult()
    res.external_ips = {"8.8.8.8"}              # google DNS, not in feeds as bad
    res.ip_dst_counts = {"8.8.8.8": 10}
    res.dns_queries = [{"ts": 1.0, "src": "10.0.0.1", "dst": "8.8.8.8", "qname": "google.com"}]
    events = enrich(res, store=load_store())
    # 8.8.8.8 / google.com should not be on any blocklist
    assert all(e.dst_ip not in ("8.8.8.8",) or e.evidence.get("indicator") != "8.8.8.8" for e in events)


def test_empty_store_returns_no_events():
    from packetiq.enrichment.feeds import IOCStore
    res = ExtractionResult()
    res.external_ips = {"1.2.3.4"}
    assert enrich(res, IOCStore()) == []


def test_shared_hosters_never_blocklisted_from_url_iocs():
    """Regression: ThreatFox lists malicious *URLs* staged on shared services
    (e.g. https://drive.google.com/uc?...). Collapsing such a URL to its bare host
    used to blocklist the whole domain — a CRITICAL false alarm for every legit
    user of Google Drive / Discord CDN / pastebin / t.me / GitHub raw / …. The
    shared front doors must never become domain IOCs."""
    from packetiq.enrichment.feeds import _SHARED_HOSTERS, load_store
    load_store.cache_clear()
    store = load_store()
    for host in _SHARED_HOSTERS:
        assert store.lookup_domain(host) is None, f"{host} wrongly flagged as IOC"
    # A real DNS query for a shared hoster must not raise an IOC_MATCH.
    res = ExtractionResult()
    res.dns_queries = [{"ts": 1.0, "src": "10.0.0.1", "dst": "8.8.8.8",
                        "qname": "drive.google.com"}]
    assert all(e.event_type != EventType.IOC_MATCH for e in enrich(res, store))
