"""
Basic tests for the PCAP parser and extractor.
Run with: python -m pytest tests/
"""


import pytest
from scapy.all import IP, TCP, UDP, Ether, wrpcap
from scapy.layers.dns import DNS, DNSQR

from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser


@pytest.fixture
def sample_pcap(tmp_path):
    """Create a minimal synthetic PCAP for testing."""
    packets = [
        # TCP SYN from 192.168.1.10 to 10.0.0.1:80
        Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="S"),
        # TCP SYN-ACK reply
        Ether() / IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=54321, flags="SA"),
        # UDP DNS query
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="example.com")),
        # ICMP ping
        Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / "ICMP payload",
    ]
    pcap_file = tmp_path / "test.pcap"
    wrpcap(str(pcap_file), packets)
    return str(pcap_file)


def test_parser_streams_records(sample_pcap):
    parser = PCAPParser(sample_pcap)
    records = list(parser.stream())
    assert len(records) >= 3  # at least 3 parseable packets


def test_parser_extracts_ips(sample_pcap):
    parser = PCAPParser(sample_pcap)
    records = list(parser.stream())
    src_ips = {r.src_ip for r in records if r.src_ip}
    assert "192.168.1.10" in src_ips


def test_extractor_protocol_counts(sample_pcap):
    parser = PCAPParser(sample_pcap)
    extractor = DataExtractor()
    for record in parser.stream():
        extractor.feed(record)
    result = extractor.finalize()
    assert result.total_packets > 0
    assert "TCP" in result.protocol_counts or "UDP" in result.protocol_counts


def test_extractor_dns_capture(sample_pcap):
    parser = PCAPParser(sample_pcap)
    extractor = DataExtractor()
    for record in parser.stream():
        extractor.feed(record)
    result = extractor.finalize()
    domains = [q["qname"] for q in result.dns_queries]
    assert any("example.com" in d for d in domains)


def test_file_not_found():
    with pytest.raises(FileNotFoundError):
        PCAPParser("/nonexistent/path/file.pcap")
