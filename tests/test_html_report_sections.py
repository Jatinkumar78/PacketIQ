"""HTML report section builders, driven from realistic ExtractionResult shapes.

The end-to-end report test renders one capture, which leaves the interesting
branches cold: an address-less switch on the segment, a same-chassis inference
note, an mDNS-only capture, a vulnerability assessment, and the truncation
messages that appear only on large captures. These are exactly the sections a
reader judges the report by.
"""

import pytest

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.export import html_report as hr
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats

TS = 1700000000.0


def _event(etype=EventType.PORT_SCAN, severity=Severity.HIGH, src="45.33.32.156",
           dst="192.168.1.50", evidence=None, description="scan"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=445,
                          protocol="TCP", timestamp=TS, packet_count=10,
                          evidence=evidence or {})


# ── Passive OS hint ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("ttl,expect", [
    (64, "Linux/Unix/macOS"),
    (58, "Linux/Unix/macOS"),
    (128, "Windows"),
    (120, "Windows"),
    (255, "Router/appliance"),
    (250, "Router/appliance"),
])
def test_the_ttl_bucket_names_an_os_family(ttl, expect):
    assert expect in hr._os_hint(ttl)


@pytest.mark.parametrize("ttl", [None, 0, "", "not-a-number", object()])
def test_an_unusable_ttl_renders_as_a_dash(ttl):
    """The report must print a dash, not raise, when the capture had no TTL."""
    assert hr._os_hint(ttl) == "—"


# ── Graphable-endpoint filter ────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "0.0.0.0", "255.255.255.255", "::", "::1",
    "224.0.0.251",           # IPv4 multicast
    "239.255.255.250",       # IPv4 multicast
    "192.168.1.255",         # subnet broadcast
    "ff02::fb",              # IPv6 multicast
    "",
])
def test_pseudo_hosts_are_kept_out_of_the_graph(ip):
    """These addresses are not devices. Drawing them invents hosts on the map."""
    assert hr._graphable(ip) is False


@pytest.mark.parametrize("ip", ["192.168.1.50", "185.199.108.153", "2606:4700::1111",
                                "fd00::50"])
def test_real_endpoints_are_graphable(ip):
    assert hr._graphable(ip) is True


def test_a_malformed_dotted_quad_is_not_rejected_outright():
    """A parse failure must not silently drop a host from the topology."""
    assert hr._graphable("10.0.0.x") is True


# ── Network graph ────────────────────────────────────────────────────────────

def _graph_result(devices=None, chassis_groups=None, arp_targets=None):
    r = ExtractionResult()
    r.ip_src_counts = {"192.168.1.50": 100, "192.168.1.51": 80, "45.33.32.156": 60}
    r.ip_dst_counts = {"192.168.1.50": 50, "45.33.32.156": 20}
    r.transmitted_ips = {"192.168.1.50", "192.168.1.51", "45.33.32.156"}
    r.flows = {
        "a": FlowStats(src_ip="45.33.32.156", dst_ip="192.168.1.50", src_port=40000,
                       dst_port=445, protocol="TCP", service="smb", bytes_total=5000),
    }
    r.devices = devices or []
    r.chassis_groups = chassis_groups or []
    r.arp_request_targets = arp_targets or {}
    return r


def test_a_single_device_capture_says_there_is_nothing_to_graph():
    r = ExtractionResult()
    r.ip_src_counts = {"192.168.1.50": 10}
    r.transmitted_ips = {"192.168.1.50"}

    svg = hr._network_svg(r, [])
    assert "no host-to-host connections" in svg
    assert "<svg" not in svg


def test_an_address_less_switch_is_drawn_as_infrastructure():
    """A switch doing STP/CDP transmits frames but holds no IP.

    Leaving it out would draw a segment with no segment — the hosts would appear
    to be connected to nothing.
    """
    devices = [{"id": "aa:bb:cc:dd:ee:01", "mac": "aa:bb:cc:dd:ee:01", "ips": [],
                "kind": "infrastructure", "protocols": ["STP"], "packets": 40}]
    svg = hr._network_svg(_graph_result(devices=devices), [])

    assert "<rect" in svg, "infrastructure is a square, not a circle"
    assert "Switch" in svg or "switch" in svg
    assert "L2 segment" in svg


def test_an_address_less_host_is_labelled_by_how_it_was_seen():
    devices = [{"id": "aa:bb:cc:dd:ee:02", "mac": "aa:bb:cc:dd:ee:02", "ips": [],
                "kind": "host", "protocols": ["DHCP"], "packets": 6}]
    svg = hr._network_svg(_graph_result(devices=devices), [])

    assert "(DHCP)" in svg


def test_an_address_less_host_with_no_dhcp_is_labelled_as_having_no_ip():
    devices = [{"id": "aa:bb:cc:dd:ee:03", "mac": "aa:bb:cc:dd:ee:03", "ips": [],
                "kind": "host", "protocols": ["ARP"], "packets": 3}]
    svg = hr._network_svg(_graph_result(devices=devices), [])

    assert "(no IP)" in svg


def test_a_device_that_already_has_an_ip_is_not_drawn_twice():
    devices = [{"id": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:04",
                "ips": ["192.168.1.50"], "kind": "host", "protocols": [], "packets": 100}]
    svg = hr._network_svg(_graph_result(devices=devices), [])

    assert svg.count("192.168.1.50") == 1


def test_an_arp_sweep_annotates_how_many_hosts_answered():
    """`scanned N · M live` is the honest summary: probing 254 addresses and
    finding 3 devices is a very different finding from 254 live hosts."""
    events = [_event(EventType.ARP_SCAN, src="192.168.1.51", dst=None)]
    r = _graph_result(arp_targets={
        "192.168.1.51": {"192.168.1.50", "192.168.1.99", "192.168.1.100"},
    })

    svg = hr._network_svg(r, events)
    assert "scanned 3" in svg
    assert "1 live" in svg, "only one of the three probed addresses transmitted"


def test_an_attack_edge_is_drawn_differently_from_a_flow_edge():
    svg = hr._network_svg(_graph_result(), [_event(EventType.PORT_SCAN)])

    assert "url(#ah)" in svg, "attack edges carry the red arrowhead marker"
    assert "#dc2626" in svg


# ── Device inventory ─────────────────────────────────────────────────────────

def test_a_same_chassis_group_is_reported_as_an_inference_not_a_merge():
    """Two NICs on one OUI are probably one switch — but the packets prove two
    MACs, so the report says so rather than silently merging them."""
    r = ExtractionResult()
    r.devices = [
        {"id": "aa:bb:cc:00:00:01", "mac": "aa:bb:cc:00:00:01", "ips": [],
         "kind": "infrastructure", "protocols": ["STP"], "packets": 20},
        {"id": "aa:bb:cc:00:00:02", "mac": "aa:bb:cc:00:00:02", "ips": ["10.0.0.1"],
         "kind": "host", "protocols": ["DHCP"], "packets": 8},
    ]
    r.chassis_groups = [{"oui": "aa:bb:cc",
                         "macs": ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]}]

    html = hr._device_inventory_table(r)
    assert "share OUI" in html
    assert "likely the same physical switch" in html
    assert "does not merge them on" in html


def test_no_host_activity_is_stated_plainly():
    assert "No host activity recorded" in hr._top_talkers_table(ExtractionResult())


# ── DNS section ──────────────────────────────────────────────────────────────

def test_an_mdns_only_capture_says_no_unicast_dns_was_seen():
    """Otherwise a reader sees 'DNS activity' and assumes name resolution to a
    resolver happened, which changes what the capture means."""
    r = ExtractionResult()
    r.dns_queries = [
        {"ts": TS, "src": "192.168.1.50", "dst": "224.0.0.251",
         "qname": "printer.local", "kind": "mDNS"},
        {"ts": TS, "src": "192.168.1.50", "dst": "224.0.0.252",
         "qname": "wpad", "kind": "LLMNR"},
        "not a dict",
        {"ts": TS, "src": "192.168.1.50", "dst": "224.0.0.251", "qname": ""},
    ]

    html = hr._dns_table(r)
    assert "local service discovery" in html
    assert "no unicast DNS" in html


def test_a_unicast_dns_capture_gets_no_such_note():
    r = ExtractionResult()
    r.dns_queries = [{"ts": TS, "src": "192.168.1.50", "dst": "8.8.8.8",
                      "qname": "example.com", "kind": "DNS"}]

    html = hr._dns_table(r)
    assert "local service discovery" not in html
    assert "example.com" in html


def test_a_capture_with_no_names_renders_no_dns_section():
    assert hr._dns_table(ExtractionResult()) == ""


# ── HTTP and software sections ───────────────────────────────────────────────

def test_the_http_table_is_truncated_with_a_count_of_the_rest():
    r = ExtractionResult()
    r.http_requests = [{"ts": TS, "src": "192.168.1.50", "method": "GET",
                        "host": "example.com", "path": f"/{i}"} for i in range(40)]
    r.http_requests.append("not a dict")

    html = hr._http_table(r)
    assert "and 16 more request(s)" in html   # 41 recorded, 25 shown


def test_the_software_table_skips_malformed_entries():
    r = ExtractionResult()
    r.software_banners = ["not a dict",
                          {"source": "http-server", "value": "Apache/2.4.49",
                           "ips": ["192.168.1.10"]}]

    html = hr._software_table(r)
    assert "Apache/2.4.49" in html
    assert "Nothing is inferred" in html


def test_no_banners_renders_no_software_section():
    assert hr._software_table(ExtractionResult()) == ""


# ── Findings detail truncation ───────────────────────────────────────────────

def test_the_findings_detail_is_capped_and_says_how_many_were_left_out():
    """A 500-finding capture would otherwise produce an unreadable document —
    but the count has to be stated, not silently dropped."""
    events = [_event(src=f"45.33.32.{i}") for i in range(45)]
    html = hr._findings_detail(events)

    assert "and 5 more finding(s)" in html


def test_no_findings_is_stated_rather_than_left_blank():
    assert "No findings to detail" in hr._findings_detail([])


# ── Indicators ───────────────────────────────────────────────────────────────

def test_indicators_cover_domains_hashes_and_macs():
    events = [
        _event(EventType.DNS_TUNNELING, evidence={"domain": "exfil.example.xyz"}),
        _event(EventType.MALICIOUS_FILE, evidence={"sha256": "a" * 64}),
        _event(EventType.ARP_SPOOFING, src="192.168.1.99", dst=None,
               evidence={"sender_mac": "aa:bb:cc:dd:ee:ff"}),
    ]
    html = hr._iocs_html(events, ExtractionResult())

    assert "exfil.example.xyz" in html and "Domain" in html
    assert "a" * 64 in html and "File hash" in html
    assert "aa:bb:cc:dd:ee:ff" in html and "MAC address" in html


def test_the_same_indicator_from_two_findings_is_listed_once():
    events = [_event(EventType.DNS_TUNNELING, evidence={"domain": "exfil.example.xyz"})
              for _ in range(3)]
    html = hr._iocs_html(events, ExtractionResult())

    assert html.count("exfil.example.xyz") == 1


def test_an_internal_only_scan_still_produces_indicators():
    """An internal pentest has no external IPs. Reporting 'no IOCs' there would
    be actively misleading."""
    events = [_event(EventType.PORT_SCAN, src="192.168.1.99", dst="192.168.1.50")]
    html = hr._iocs_html(events, ExtractionResult())

    assert "Internal host (attacker)" in html
    assert "192.168.1.99" in html


def test_findings_that_carry_no_indicators_say_so():
    events = [_event(EventType.PROTOCOL_MISUSE, src="192.168.1.10", dst="192.168.1.20",
                     evidence={})]
    assert "No indicators extracted" in hr._iocs_html(events, ExtractionResult())


def test_no_findings_means_no_indicators():
    assert "No indicators extracted" in hr._iocs_html([], ExtractionResult())


# ── Vulnerability section ────────────────────────────────────────────────────

def test_no_assessment_renders_no_vulnerability_section():
    """The section requires a network lookup, so its absence is normal."""
    assert hr._vulns_html({}) == ""
    assert hr._vulns_html(None) == ""
    assert hr._vulns_html({"products": []}) == ""


def test_the_vulnerability_section_reports_cves_kev_and_correlations():
    vulns = {
        "risk": {"score": 98, "tier": "CRITICAL"},
        "totals": {"cves": 2, "kev": 1},
        "correlations": [{"attack": "Log4Shell", "name": "Log4Shell RCE",
                          "cves": ["CVE-2021-44228"], "target": "192.168.1.10",
                          "target_software": ["Apache 2.4.49"], "kev": True}],
        "products": [{
            "product": "Apache", "version": "2.4.49", "source": "http-server",
            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "ips": ["192.168.1.10"],
            "cves": [{"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL",
                      "kev": True, "ransomware": True},
                     {"id": "CVE-2020-9999", "cvss": 5.3, "severity": "MEDIUM",
                      "kev": False}],
        }],
    }

    html = hr._vulns_html(vulns)
    assert "98/100" in html and "CRITICAL" in html
    assert "actively exploited (CISA KEV)" in html
    assert "Log4Shell RCE" in html and "runs Apache 2.4.49" in html
    assert "CVE-2021-44228" in html
    assert "ransomware" in html


def test_a_product_with_no_cves_says_so_in_its_table():
    vulns = {"risk": {"score": 0, "tier": "NONE"}, "totals": {"cves": 0, "kev": 0},
             "products": [{"product": "nginx", "version": "1.27.0", "source": "http-server",
                           "cpe": None, "ips": [], "cves": []}]}

    html = hr._vulns_html(vulns)
    assert "No CVEs." in html
    assert "CPE n/a" in html


def test_multicast_chatter_never_becomes_a_node():
    """Multicast appears in the packet counts of almost every real capture.

    `exists()` re-checks graphability there, so an mDNS group address counted as
    a busy talker still does not get drawn as a host.
    """
    r = _graph_result()
    r.ip_src_counts["224.0.0.251"] = 5000      # busiest "talker" in the capture
    r.transmitted_ips.add("224.0.0.251")

    svg = hr._network_svg(r, [])
    assert "224.0.0.251" not in svg


def test_a_quiet_attacker_is_added_to_the_graph_despite_its_packet_count():
    """The top-N ring is chosen by volume, but a slow scanner is the whole point
    of the picture — it has to be added even though it is not a top talker."""
    r = _graph_result()
    r.ip_src_counts = {f"192.168.1.{i}": 1000 - i for i in range(2, 24)}
    r.ip_src_counts["45.33.32.156"] = 3        # three packets, but it is the scanner
    r.ip_dst_counts = {}
    r.transmitted_ips = set(r.ip_src_counts)
    r.flows = {}

    svg = hr._network_svg(r, [_event(EventType.PORT_SCAN, src="45.33.32.156",
                                     dst="192.168.1.2")])
    assert "45.33.32.156" in svg


def test_attack_edges_are_dropped_for_sources_that_did_not_fit_the_graph():
    """The ring is hard-capped at 20 nodes. An edge from a node that was cut has
    no coordinates to draw from — it is skipped, not drawn at the origin."""
    r = _graph_result()
    r.ip_src_counts = {f"45.33.32.{i}": 100 for i in range(1, 40)}
    r.ip_dst_counts = {"192.168.1.50": 500}
    r.transmitted_ips = set(r.ip_src_counts) | {"192.168.1.50"}
    r.flows = {}
    events = [_event(EventType.PORT_SCAN, src=f"45.33.32.{i}", dst="192.168.1.50")
              for i in range(1, 40)]

    svg = hr._network_svg(r, events)
    assert "<svg" in svg, "the graph still renders with the nodes that did fit"


def test_the_http_table_skips_a_malformed_entry_among_the_first_rows():
    r = ExtractionResult()
    r.http_requests = ["not a dict"] + [
        {"ts": TS, "src": "192.168.1.50", "method": "GET",
         "host": "example.com", "path": f"/{i}"} for i in range(3)]

    html = hr._http_table(r)
    assert "example.com" in html
    assert "HTTP activity (4 request(s))" in html
