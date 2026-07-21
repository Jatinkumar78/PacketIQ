"""Tests for accurate protocol composition + coordinated-recon detection.

Covers the gaps a vantage-limited pentest capture exposed: the parser must name
link-layer/UDP application protocols (not collapse them to 802.3/UDP), and a host
that ARP-sweeps then TCP-probes must be flagged even below the standalone
scan thresholds.
"""

from packetiq.detection import port_scan
from packetiq.detection.models import EventType, Severity
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser


def test_display_protocol_names_udp_apps(tmp_path):
    """DHCP and mDNS must appear as themselves in the composition, not 'UDP'."""
    from scapy.all import BOOTP, DHCP, DNS, DNSQR, IP, UDP, Ether, wrpcap
    pkts = []
    t0 = 1700000000.0
    dhcp = (Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[("message-type", "discover"), "end"]))
    dhcp.time = t0
    mdns = (Ether() / IP(src="192.168.1.5", dst="224.0.0.251")
            / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_x._tcp.local")))
    mdns.time = t0 + 1
    pkts += [dhcp, mdns]
    p = str(tmp_path / "c.pcap")
    wrpcap(p, pkts)

    ex = DataExtractor()
    for r in PCAPParser(p).stream():
        ex.feed(r)
    res = ex.finalize()
    assert res.protocol_counts.get("DHCP") == 1
    assert res.protocol_counts.get("mDNS") == 1
    assert "UDP" not in res.protocol_counts   # both were resolved to app protocols


def test_display_protocol_names_arp(tmp_path):
    from scapy.all import ARP, Ether, wrpcap
    p = str(tmp_path / "a.pcap")
    pk = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2")
    pk.time = 1700000000.0
    wrpcap(p, [pk])
    ex = DataExtractor()
    for r in PCAPParser(p).stream():
        ex.feed(r)
    assert ex.finalize().protocol_counts.get("ARP") == 1


def test_coordinated_recon_detected():
    """ARP sweeper + a few TCP probes = a coordinated-recon PORT_SCAN, even though
    3 ports is below the standalone vertical/horizontal thresholds."""
    from packetiq.extractor.data_extractor import ExtractionResult
    r = ExtractionResult()
    r.arp_request_targets = {"192.168.1.200": {f"192.168.1.{i}" for i in range(1, 60)}}
    r.tcp_syn_pairs = {
        ("192.168.1.200", "192.168.1.100", 80): [1.0],
        ("192.168.1.200", "192.168.1.202", 80): [2.0, 2.1],
        ("192.168.1.200", "192.168.1.202", 443): [2.2, 2.3],
    }
    events = port_scan.detect(r)
    recon = [e for e in events if e.event_type == EventType.PORT_SCAN
             and e.evidence.get("scan_type") == "coordinated_recon"]
    assert len(recon) == 1
    assert recon[0].src_ip == "192.168.1.200"
    assert recon[0].severity == Severity.MEDIUM
    assert recon[0].evidence["probes"] == 3


def test_no_coordinated_recon_without_arp_sweep():
    """The same few TCP probes WITHOUT an ARP sweep must not fire (low FP)."""
    from packetiq.extractor.data_extractor import ExtractionResult
    r = ExtractionResult()
    r.tcp_syn_pairs = {
        ("10.0.0.5", "10.0.0.9", 80): [1.0],
        ("10.0.0.5", "10.0.0.9", 443): [2.0],
    }
    events = port_scan.detect(r)
    assert not [e for e in events if e.evidence.get("scan_type") == "coordinated_recon"]


def test_reconnaissance_progression_chain():
    """ARP scan + port scan from one host correlate into a recon campaign chain."""
    from packetiq.correlation import rules
    from packetiq.detection.models import DetectionEvent
    arp = DetectionEvent(event_type=EventType.ARP_SCAN, severity=Severity.HIGH,
                         src_ip="192.168.1.200", description="arp sweep")
    scan = DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.MEDIUM,
                          src_ip="192.168.1.200", description="tcp probe", dst_ip="192.168.1.100")
    chains = rules.reconnaissance_progression([arp, scan])
    assert len(chains) == 1
    assert "192.168.1.200" in chains[0].attacker_ips
    assert "Reconnaissance" in chains[0].kill_chain_phases
