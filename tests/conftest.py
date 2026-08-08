"""
Shared pytest fixtures for PacketIQ tests.

Builds a deterministic synthetic attack PCAP that exercises every detector,
then runs the full analysis pipeline once and exposes the results.
"""

import random
import socket

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


@pytest.fixture(autouse=True)
def isolate_analysis_history(tmp_path, monkeypatch):
    """Give every test its own analysis-history database.

    `storage._db_path()` falls back to ``~/.packetiq/history.db``, so any test that
    recorded an analysis without overriding ``PACKETIQ_DB`` wrote into the developer's
    real history — a full run added six fixture rows named `attack.pcap` to it. The
    same leak made coverage irreproducible: the web app renders a different branch once
    history is non-empty, so `webapp/app.py` swung by 14 statements between consecutive
    runs depending on what the previous run had left behind.

    Isolation is the default now rather than something each test has to remember. Tests
    that need a specific path still just set ``PACKETIQ_DB`` themselves; monkeypatch
    applies theirs after this one.
    """
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "history.db"))


@pytest.fixture(autouse=True)
def no_outbound_network(monkeypatch):
    """Turn any escape to the internet into a failed test.

    Deleting ``TELEGRAM_BOT_TOKEN`` from the environment does not unconfigure
    alerting: ``telegram.load_credentials`` also scans ``./.env`` and ``../.env``,
    so the "does not send without configuration" test found the developer's real
    bot token and POSTed the findings to a real chat on every local run. Nothing
    failed, because sending worked. The same silence made the coverage number
    machine-dependent — that request was the only thing exercising the alert
    formatter's MITRE block, which is why CI came up short.

    Blocking at ``connect`` rather than at ``requests`` catches every client
    (requests, httpx, urllib, raw sockets) and every credential source. Loopback
    stays open for the local Ollama endpoint, and AF_UNIX for anything that talks
    to a socket file; a test that wants a remote call still stubs it and never
    gets here.
    """
    real_connect = socket.socket.connect

    def guarded_connect(self, address, *args, **kwargs):
        if self.family != getattr(socket, "AF_UNIX", object()):
            host = address[0] if isinstance(address, tuple) else address
            if host not in ("127.0.0.1", "::1", "localhost", "0.0.0.0", ""):
                raise AssertionError(
                    f"test attempted an outbound connection to {host!r}; stub the "
                    "client at its boundary instead"
                )
        return real_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)


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
