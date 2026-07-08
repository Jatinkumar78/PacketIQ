"""Tests for evidence PCAP slicing, STIX export, and alert channels."""

from scapy.all import IP, TCP, Ether, wrpcap

from packetiq.alerts import channels
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.export.pcap_slicer import PcapFilter, slice_pcap
from packetiq.export.stix_export import to_stix_bundle


def test_pcap_slice_by_ip(tmp_path):
    pkts = []
    for i in range(5):
        p = Ether() / IP(src="45.33.32.156", dst="10.0.0.5") / TCP(dport=443)
        p.time = 1000 + i
        pkts.append(p)
    for i in range(5):
        p = Ether() / IP(src="10.0.0.9", dst="10.0.0.10") / TCP(dport=80)
        p.time = 1000 + i
        pkts.append(p)
    src = tmp_path / "in.pcap"
    out = tmp_path / "evidence.pcap"
    wrpcap(str(src), pkts)

    n = slice_pcap(str(src), str(out), PcapFilter(ips={"45.33.32.156"}))
    assert n == 5


def test_pcap_slice_by_port(tmp_path):
    pkts = []
    for i in range(3):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=22)
        p.time = 1000 + i
        pkts.append(p)
    p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=443)
    p.time = 1010
    pkts.append(p)
    src = tmp_path / "in.pcap"
    out = tmp_path / "out.pcap"
    wrpcap(str(src), pkts)
    assert slice_pcap(str(src), str(out), PcapFilter(ports={22})) == 3


def test_stix_bundle_structure():
    events = [
        DetectionEvent(
            event_type=EventType.IOC_MATCH, severity=Severity.CRITICAL,
            src_ip="10.0.0.5", dst_ip="45.33.32.156",
            description="known C2",
            evidence={"indicator": "45.33.32.156", "source": "Feodo Tracker", "label": "QakBot C2"},
        ),
        DetectionEvent(
            event_type=EventType.DNS_TUNNELING, severity=Severity.HIGH,
            src_ip="10.0.0.5", description="dns tunnel",
            evidence={"domain": "evil.example.xyz"},
        ),
    ]
    bundle = to_stix_bundle(events)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    patterns = [o["pattern"] for o in bundle["objects"]]
    assert any("ipv4-addr:value = '45.33.32.156'" in p for p in patterns)
    assert any("domain-name:value = 'evil.example.xyz'" in p for p in patterns)
    for obj in bundle["objects"]:
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert obj["pattern_type"] == "stix"


def test_channels_none_configured(monkeypatch, tmp_path):
    for var in ("SLACK_WEBHOOK_URL", "ALERT_WEBHOOK_URL", "SMTP_HOST", "ALERT_EMAIL_TO"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)   # no .env present here
    assert channels.configured_channels() == []
    assert channels.broadcast("subj", "body") == {}


def test_channels_slack_detected(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/x")
    assert "slack" in channels.configured_channels()
