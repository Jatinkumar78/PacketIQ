"""
Shared pytest fixtures for PacketIQ tests.

Builds a deterministic synthetic attack PCAP that exercises every detector,
then runs the full analysis pipeline once and exposes the results.
"""

import random

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR

from packetiq.correlation.engine import CorrelationEngine
from packetiq.detection.engine import DetectionEngine
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser

ATTACKER = "45.33.32.156"      # external
VICTIM   = "192.168.1.50"      # internal
C2       = "185.199.108.153"   # external
FTP_SRV  = "193.122.6.168"     # external
ICMP_DST = "188.114.96.3"      # external
RESOLVER = "8.8.8.8"


def _build_attack_pcap(path: str):
    random.seed(7)
    pkts = []
    t = 1700000000.0

    def add(p, ts):
        p.time = ts
        pkts.append(p)

    # SSH brute force
    for i in range(40):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + i, dport=22, flags="S"), t + i)
    t += 70
    # Vertical port scan
    for i, port in enumerate(range(1, 70)):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=50000 + i, dport=port, flags="S"), t + i * 0.1)
    t += 30
    # Horizontal host scan on 445
    for i in range(25):
        add(Ether() / IP(src=ATTACKER, dst=f"192.168.1.{100 + i}") / TCP(sport=51000 + i, dport=445, flags="S"), t + i * 0.1)
    t += 30
    # XMAS scan (FIN+PSH+URG)
    for i in range(3):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=54000 + i, dport=81 + i, flags="FPU"), t + i * 0.1)
    t += 10
    # C2 beacon to external every 30s
    for i in range(16):
        add(Ether() / IP(src=VICTIM, dst=C2) / TCP(sport=52000, dport=443, flags="S"), t + i * 30 + random.uniform(-0.3, 0.3))
    t += 16 * 30 + 10
    # DNS tunneling (oversized names)
    for i in range(6):
        label = "".join(random.choice("0123456789abcdef") for _ in range(60))
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=33000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example-evil.xyz")), t + i * 2)
    t += 20
    # Normal DNS (must not be flagged as DGA)
    for d in ("google.com", "github.com", "cloudflare.com"):
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=35000, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=d)), t)
        t += 1
    # ICMP tunneling
    for i in range(130):
        add(Ether() / IP(src=VICTIM, dst=ICMP_DST) / ICMP() / Raw(load=b"X" * 1000), t + i * 0.2)
    t += 30
    # Cleartext FTP creds to external
    add(Ether() / IP(src=VICTIM, dst=FTP_SRV) / TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"), t); t += 1
    add(Ether() / IP(src=VICTIM, dst=FTP_SRV) / TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"PASS hunter2\r\n"), t); t += 1

    wrpcap(path, pkts)
    return path


@pytest.fixture(scope="session")
def attack_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcaps") / "attack.pcap"
    return _build_attack_pcap(str(path))


@pytest.fixture(scope="session")
def pipeline(attack_pcap):
    """Run the full pipeline once and return (result, events, risk, chains)."""
    parser = PCAPParser(attack_pcap)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    result = extractor.finalize()
    events, risk, fps = DetectionEngine().run(result, attack_pcap)
    chains = CorrelationEngine().correlate(events)
    return {"result": result, "events": events, "risk": risk, "chains": chains, "fps": fps}
