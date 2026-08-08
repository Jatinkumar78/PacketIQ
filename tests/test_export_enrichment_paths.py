"""Export formats and threat-intel enrichment: the branches nothing else reaches.

These modules turn findings into things other systems consume — STIX bundles,
MISP events, sliced pcaps, ATT&CK coverage. A wrong branch here does not crash;
it produces a bundle that a downstream platform silently rejects, or a slice
missing the packets an analyst asked for.
"""

import json
import types

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.enrichment.feeds import IOCHit, IOCStore
from packetiq.export import attack_navigator, misp, pcap_slicer, report_style, stix_export
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats

TS = 1700000000.0


def _event(etype, severity=Severity.HIGH, src="45.33.32.156", dst="185.199.108.153",
           evidence=None, description="finding"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=443,
                          timestamp=TS, evidence=evidence or {})


# ── STIX ─────────────────────────────────────────────────────────────────────

def test_a_sha256_indicator_becomes_a_file_hash_pattern():
    """Hashes, IPs and domains each need their own STIX pattern grammar.

    A hash emitted as `domain-name:value` is a bundle a TIP will accept and
    then never match on.
    """
    digest = "a" * 64
    pattern, kind = stix_export._pattern(digest)

    assert kind == "file"
    assert pattern == f"[file:hashes.'SHA-256' = '{digest}']"


def test_an_uppercase_hash_is_normalised():
    pattern, _ = stix_export._pattern("A" * 64)
    assert "a" * 64 in pattern


@pytest.mark.parametrize("value,kind", [
    ("185.199.108.153", "ipv4-addr"),
    ("2606:4700::1111", "ipv6-addr"),
    ("evil.example.com", "domain-name"),
    ("b" * 63, "domain-name"),          # one short of a hash — still a domain
])
def test_indicator_kinds_are_distinguished(value, kind):
    assert stix_export._pattern(value)[1] == kind


def test_a_ja3_finding_exports_its_tls_endpoint():
    """The JA3 arm names the malware family in the indicator, when the feed gave one."""
    events = [_event(EventType.JA3_ANOMALY, evidence={"malware": "Emotet",
                                                      "ja3_hash": "0" * 32})]
    bundle = stix_export.to_stix_bundle(events)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]

    assert len(indicators) == 1
    assert "Emotet" in indicators[0]["name"]
    assert "185.199.108.153" in indicators[0]["pattern"]


def test_a_ja3_finding_without_a_family_still_exports():
    events = [_event(EventType.JA3_ANOMALY, evidence={"ja3_hash": "0" * 32})]
    indicators = [o for o in stix_export.to_stix_bundle(events)["objects"]
                  if o["type"] == "indicator"]

    assert "JA3 match" in indicators[0]["name"]


# ── ATT&CK Navigator coverage ────────────────────────────────────────────────

def test_a_technique_with_no_id_is_skipped():
    """Serialized events from older runs can carry a name with no technique id.

    Counting it would put an unnamed cell in the coverage matrix.
    """
    events = [{"severity": "HIGH", "mitre": [{"id": "", "name": "Unknown",
                                              "tactic": "Discovery"}]}]
    assert attack_navigator.coverage(events) == []


def test_repeated_techniques_are_counted_not_duplicated():
    ev = {"severity": "HIGH", "mitre": [{"id": "T1046",
                                         "name": "Network Service Discovery",
                                         "tactic": "Discovery"}]}
    rows = attack_navigator.coverage([ev, ev, ev])

    assert len(rows) == 1
    assert rows[0]["count"] == 3
    assert rows[0]["id"] == "T1046"


def test_no_events_yields_no_coverage():
    assert attack_navigator.coverage([]) == []
    assert attack_navigator.coverage(None) == []


# ── Report style helpers ─────────────────────────────────────────────────────

def test_the_tool_version_is_read_from_the_package():
    assert report_style.tool_version() == "1.0.0"


def test_the_tool_version_falls_back_when_the_package_metadata_is_missing(monkeypatch):
    """Reports must still carry a version string if the import fails.

    A report header reading `None` is worse than a slightly stale constant.
    """
    import builtins
    real_import = builtins.__import__

    def no_packetiq(name, *a, **kw):
        if name == "packetiq" and a and "__version__" in (a[2] or ()):
            raise ImportError("metadata unavailable")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_packetiq)
    assert report_style.tool_version() == "1.0.0"


def test_a_report_id_is_stable_for_the_same_capture():
    a = report_style.report_id("attack.pcap", "ab" * 32)
    b = report_style.report_id("attack.pcap", "ab" * 32)
    assert a == b and a.startswith("PIQ-")


def test_a_report_id_falls_back_to_the_filename_when_there_is_no_hash():
    assert report_style.report_id("attack.pcap") != report_style.report_id("other.pcap")


# ── MISP push ────────────────────────────────────────────────────────────────

def _misp_event():
    return {"Event": {"info": "PacketIQ", "Attribute": [
        {"type": "ip-dst", "value": "185.199.108.153"}]}}


def test_a_misp_push_reports_the_new_event_id(monkeypatch):
    monkeypatch.setattr(misp, "requests", types.SimpleNamespace(
        post=lambda *a, **kw: types.SimpleNamespace(
            status_code=200, json=lambda: {"Event": {"id": "4211"}}, text="")))

    ok, msg = misp.push_to_misp(_misp_event(), url="https://misp.local", key="k")
    assert ok is True and "4211" in msg


def test_a_misp_push_survives_a_success_response_it_cannot_parse(monkeypatch):
    """Some MISP deployments sit behind a proxy that rewrites the body.

    The push did succeed; reporting it as a failure would make the operator
    push again and create a duplicate event.
    """
    def post(*a, **kw):
        return types.SimpleNamespace(
            status_code=201,
            json=lambda: (_ for _ in ()).throw(ValueError("not json")),
            text="<html>ok</html>")

    monkeypatch.setattr(misp, "requests", types.SimpleNamespace(post=post))

    ok, msg = misp.push_to_misp(_misp_event(), url="https://misp.local", key="k")
    assert ok is True
    assert "id=?" in msg


def test_an_unreachable_misp_server_is_reported_not_raised(monkeypatch):
    def post(*a, **kw):
        raise ConnectionError("name resolution failed")

    monkeypatch.setattr(misp, "requests", types.SimpleNamespace(post=post))

    ok, msg = misp.push_to_misp(_misp_event(), url="https://misp.local", key="k")
    assert ok is False
    assert "Request failed" in msg and "name resolution failed" in msg


def test_a_rejected_misp_push_surfaces_the_status_and_body(monkeypatch):
    monkeypatch.setattr(misp, "requests", types.SimpleNamespace(
        post=lambda *a, **kw: types.SimpleNamespace(
            status_code=403, json=lambda: {}, text="Authentication failed")))

    ok, msg = misp.push_to_misp(_misp_event(), url="https://misp.local", key="k")
    assert ok is False
    assert "403" in msg and "Authentication failed" in msg


def test_a_push_with_no_indicators_is_refused_before_the_network(monkeypatch):
    monkeypatch.setattr(misp, "requests", types.SimpleNamespace(
        post=lambda *a, **kw: pytest.fail("must not reach the network")))

    ok, msg = misp.push_to_misp({"Event": {"Attribute": []}},
                                url="https://misp.local", key="k")
    assert ok is False and "No indicators" in msg


# ── PCAP slicing ─────────────────────────────────────────────────────────────

def _pkt(src="192.168.1.50", dst="185.199.108.153", sport=51000, dport=443, ts=TS, v6=False):
    layer = IPv6(src=src, dst=dst) if v6 else IP(src=src, dst=dst)
    p = Ether() / layer / TCP(sport=sport, dport=dport)
    p.time = ts
    return p


def test_a_packet_after_the_window_is_excluded():
    """Both edges of the time window matter — an analyst slicing 'the first
    minute' must not get the whole capture back."""
    f = pcap_slicer.PcapFilter(start_ts=TS, end_ts=TS + 60)

    assert f.matches(_pkt(ts=TS + 30)) is True
    assert f.matches(_pkt(ts=TS + 600)) is False
    assert f.matches(_pkt(ts=TS - 600)) is False


def test_an_ipv6_packet_is_matched_on_its_addresses():
    f = pcap_slicer.PcapFilter(ips={"2606:4700::1111"})

    assert f.matches(_pkt(src="fd00::50", dst="2606:4700::1111", v6=True)) is True
    assert f.matches(_pkt(src="fd00::50", dst="2606:4700::2222", v6=True)) is False


def test_a_udp_packet_is_matched_on_its_ports():
    f = pcap_slicer.PcapFilter(ports={53})
    p = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=33000, dport=53)
    p.time = TS

    assert f.matches(p) is True


def test_a_packet_with_no_addresses_never_matches_an_ip_filter():
    f = pcap_slicer.PcapFilter(ips={"192.168.1.50"})
    p = Ether() / ARP()
    p.time = TS

    assert f.matches(p) is False


def test_slicing_skips_a_packet_it_cannot_read(tmp_path, monkeypatch):
    """One malformed packet must not abandon the rest of the slice.

    A truncated capture is exactly when an analyst most needs whatever can be
    recovered from it.
    """
    src = tmp_path / "in.pcap"
    wrpcap(str(src), [_pkt(sport=51000 + i) for i in range(5)])

    calls = {"n": 0}
    real_matches = pcap_slicer.PcapFilter.matches

    def flaky(self, pkt):
        calls["n"] += 1
        if calls["n"] == 3:
            raise ValueError("malformed packet")
        return real_matches(self, pkt)

    monkeypatch.setattr(pcap_slicer.PcapFilter, "matches", flaky)

    out = tmp_path / "out.pcap"
    written = pcap_slicer.slice_pcap(str(src), str(out),
                                     pcap_slicer.PcapFilter(ips={"192.168.1.50"}))

    assert written == 4, "four readable packets survive the one bad packet"


def test_slicing_an_unreadable_capture_writes_nothing(tmp_path):
    bad = tmp_path / "broken.pcap"
    bad.write_bytes(b"not a pcap")
    out = tmp_path / "out.pcap"

    assert pcap_slicer.slice_pcap(str(bad), str(out), pcap_slicer.PcapFilter()) == 0


# ── Threat-intel enrichment ──────────────────────────────────────────────────

def _store_with(ips=None, domains=None):
    store = IOCStore()
    for ip in ips or []:
        store.bad_ips[ip] = IOCHit(indicator=ip, kind="ip", source="Feodo",
                                   label="Dridex C2", severity=Severity.CRITICAL)
    for d in domains or []:
        store.bad_domains[d] = IOCHit(indicator=d, kind="domain", source="URLhaus",
                                      label="Malware distribution", severity=Severity.HIGH)
    store.counts["test"] = len(store.bad_ips) + len(store.bad_domains)
    return store


def test_a_flow_missing_an_endpoint_is_skipped():
    """Half-populated flows appear when a capture starts mid-conversation."""
    from packetiq.enrichment.engine import enrich

    result = ExtractionResult()
    result.flows = {"a": FlowStats(src_ip="192.168.1.50", dst_ip="", src_port=51000,
                                   dst_port=443, protocol="TCP", service="https")}
    result.external_ips = {"185.199.108.153"}

    assert enrich(result, store=_store_with(ips=["185.199.108.153"]))


def test_a_listed_ip_is_reported_once_even_when_seen_in_both_directions():
    from packetiq.enrichment.engine import enrich

    result = ExtractionResult()
    result.external_ips = {"185.199.108.153"}
    result.ip_src_counts = {"185.199.108.153": 10}
    result.ip_dst_counts = {"185.199.108.153": 12}
    result.flows = {"a": FlowStats(src_ip="192.168.1.50", dst_ip="185.199.108.153",
                                   src_port=51000, dst_port=443, protocol="TCP",
                                   service="https", last_seen=TS)}

    events = enrich(result, store=_store_with(ips=["185.199.108.153"]))

    assert len(events) == 1
    assert events[0].event_type == EventType.IOC_MATCH
    assert events[0].src_ip == "192.168.1.50", "the internal peer gives the finding context"
    assert events[0].packet_count == 22


def test_a_listed_domain_is_reported_once_per_name():
    from packetiq.enrichment.engine import enrich

    result = ExtractionResult()
    result.dns_queries = [
        {"ts": TS, "src": "192.168.1.50", "dst": "8.8.8.8", "qname": "evil.example.com."},
        {"ts": TS + 1, "src": "192.168.1.50", "dst": "8.8.8.8", "qname": "EVIL.example.com"},
        {"ts": TS + 2, "src": "192.168.1.50", "dst": "8.8.8.8", "qname": ""},
    ]

    events = enrich(result, store=_store_with(domains=["evil.example.com"]))

    assert len(events) == 1, "the trailing dot and the casing are the same name"
    assert events[0].protocol == "DNS"


def test_no_feed_data_means_no_enrichment():
    from packetiq.enrichment.engine import enrich

    result = ExtractionResult()
    result.external_ips = {"185.199.108.153"}
    assert enrich(result, store=IOCStore()) == []


# ── CISA KEV cache ───────────────────────────────────────────────────────────

def _kev_cache(tmp_path, monkeypatch, content=None):
    from packetiq.enrichment import kev
    path = tmp_path / "kev.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(kev, "_cache_path", lambda: path)
    monkeypatch.setattr(kev, "refresh", lambda: None)
    kev.load.cache_clear()
    return kev


def test_no_kev_cache_and_no_network_yields_nothing(tmp_path, monkeypatch):
    """Never raise, never guess — an unavailable KEV list is simply empty."""
    kev = _kev_cache(tmp_path, monkeypatch)
    try:
        assert kev.load() == {}
        assert kev.available() is False
        assert kev.count() == 0
        assert kev.is_kev("CVE-2021-44228") is False
        assert kev.kev_info("CVE-2021-44228") is None
    finally:
        kev.load.cache_clear()


def test_a_corrupt_kev_cache_is_treated_as_absent(tmp_path, monkeypatch):
    kev = _kev_cache(tmp_path, monkeypatch, content="{ truncated json")
    try:
        assert kev.load() == {}
    finally:
        kev.load.cache_clear()


def test_a_valid_kev_cache_is_indexed_by_cve(tmp_path, monkeypatch):
    payload = json.dumps({"vulnerabilities": [
        {"cveID": "cve-2021-44228", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "requiredAction": "Patch",
         "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "", "vulnerabilityName": "no id"},
    ]})
    kev = _kev_cache(tmp_path, monkeypatch, content=payload)
    try:
        assert kev.available() is True
        assert kev.count() == 1
        assert kev.is_kev("CVE-2021-44228") is True
        assert kev.is_kev("cve-2021-44228") is True, "lookup must be case-insensitive"
        info = kev.kev_info("CVE-2021-44228")
        assert info["name"] == "Log4Shell"
        assert info["ransomware"] is True
    finally:
        kev.load.cache_clear()


# ── Feed normalisers ─────────────────────────────────────────────────────────

def test_a_malformed_line_in_the_drop_feed_is_skipped():
    """Spamhaus DROP is newline-delimited JSON with a metadata header line.

    Aborting on the first non-JSON line would discard the whole feed.
    """
    from packetiq.enrichment.update import _norm_drop

    text = "\n".join([
        '{"type":"metadata","sources":["SBL"]}',
        '{"cidr":"1.2.3.0/24","sblid":"SBL1"}',
        "not json at all",
        "",
        '{"cidr":"5.6.7.0/24","sblid":"SBL2"}',
    ])

    assert _norm_drop(text) == ["1.2.3.0/24", "5.6.7.0/24"]
