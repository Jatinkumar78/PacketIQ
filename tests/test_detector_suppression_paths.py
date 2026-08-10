"""The guards that decide *not* to report something.

Suppression logic is the least-exercised and highest-consequence code in a
detector: a broken de-duplication buries a report under repeats, and a broken
"this is intra-LAN" check turns every campus file share into a CRITICAL finding.
Neither shows up as a crash. These tests pin the negative cases.
"""

import pytest

from packetiq.detection import beacon, protocol_misuse
from packetiq.detection.credential import _check_telnet, _safe_b64, scan_record
from packetiq.detection.models import EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats
from packetiq.parser.pcap_parser import RawPacketRecord


def _rec(payload: bytes, dport=80, sport=51000, src="192.168.1.10", dst="93.184.216.34"):
    return RawPacketRecord(
        index=0, timestamp=1700000000.0, size=len(payload) + 54,
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        protocol="TCP", raw_payload=payload, payload_size=len(payload),
    )


def _flow(src, dst, sport, dport, **kw):
    f = FlowStats(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                  protocol="TCP", service="unknown")
    for k, v in kw.items():
        setattr(f, k, v)
    return f


def _scan(*records):
    events: list = []
    seen: set = set()
    for r in records:
        scan_record(r, seen, events)
    return events


# ── Credential handlers: one finding per credential, not per packet ──────────
#
# A retransmitted or re-sent auth packet is completely routine. Without the
# `seen` guard a single re-typed password becomes dozens of CRITICAL findings.

@pytest.mark.parametrize("payload,dport,label", [
    (b"GET /admin HTTP/1.1\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n",
     80, "HTTP Basic"),
    (b"AUTH LOGIN dXNlcg==\r\n", 25, "SMTP AUTH"),
    (b"a1 LOGIN alice s3cret\r\n", 143, "IMAP LOGIN"),
    (b"PASS hunter2\r\n", 110, "POP3 PASS"),
])
def test_a_repeated_credential_packet_is_reported_once(payload, dport, label):
    once = _scan(_rec(payload, dport=dport))
    twice = _scan(_rec(payload, dport=dport), _rec(payload, dport=dport))

    assert len(once) >= 1, f"{label} should be detected at all"
    assert len(twice) == len(once), f"{label} was reported {len(twice)}x for a repeat"


def test_the_same_credential_to_a_different_server_is_reported_again():
    """Dedup keys on (src, dst, port, kind) — a second victim is a second finding."""
    payload = b"GET / HTTP/1.1\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n"
    events = _scan(_rec(payload), _rec(payload, dst="203.0.113.77"))

    assert len({e.dst_ip for e in events}) == 2


# ── Telnet: the two ways a packet is judged "not user data" ──────────────────

def test_a_one_byte_telnet_packet_is_not_a_session():
    events: list = []
    _check_telnet(_rec(b"\xff", dport=23), "10.0.0.1", "10.0.0.2", set(), events)
    assert events == []


def test_telnet_option_negotiation_is_not_a_session():
    """IAC DO/WILL bytes are control traffic, not keystrokes.

    Flagging them would make every Telnet TCP handshake a CRITICAL credential
    exposure, including ones where the session is refused immediately.
    """
    events: list = []
    negotiation = bytes([0xFF, 0xFB, 0x01, 0xFF, 0xFD, 0x03, 0xFF, 0xFB, 0x03])
    _check_telnet(_rec(negotiation, dport=23), "10.0.0.1", "10.0.0.2", set(), events)
    assert events == []


def test_actual_telnet_keystrokes_are_a_session():
    events: list = []
    _check_telnet(_rec(b"login: admin\r\npassword: hunter2\r\n", dport=23),
                  "10.0.0.1", "10.0.0.2", set(), events)
    assert len(events) == 1
    assert events[0].severity == Severity.CRITICAL


def test_a_repeated_telnet_session_packet_is_reported_once():
    seen: set = set()
    events: list = []
    for _ in range(3):
        _check_telnet(_rec(b"admin\r\nhunter2\r\n", dport=23),
                      "10.0.0.1", "10.0.0.2", seen, events)
    assert len(events) == 1


# ── base64 helper ────────────────────────────────────────────────────────────

def test_safe_b64_accepts_a_string_as_well_as_bytes():
    """The regexes hand it bytes, but SMTP AUTH can arrive already decoded."""
    assert _safe_b64("aHVudGVyMg") == "hunter2"
    assert _safe_b64(b"aHVudGVyMg") == "hunter2"


def test_safe_b64_returns_none_rather_than_raising_on_garbage():
    assert _safe_b64(b"!!!not base64!!!") is None


# ── TCP flag scans ───────────────────────────────────────────────────────────

def test_a_fin_only_flow_is_a_fin_scan():
    """Nmap -sF. Distinct from XMAS, and previously only XMAS had a test."""
    res = ExtractionResult()
    f = _flow("45.33.32.156", "10.0.0.5", 40000, 80)
    f.tcp_flags_seen = {"FIN"}
    res.flows = {"a": f}

    events = protocol_misuse._suspicious_tcp_flags(res)
    assert [e.evidence.get("scan_type") for e in events] == ["FIN_ONLY"]


def test_a_normal_fin_ack_teardown_is_not_a_scan():
    """Every closed connection ends in FIN+ACK; only a bare FIN is a probe."""
    res = ExtractionResult()
    f = _flow("10.0.0.5", "93.184.216.34", 51000, 443)
    f.tcp_flags_seen = {"FINACK", "SYN", "ACK"}
    res.flows = {"a": f}

    assert protocol_misuse._suspicious_tcp_flags(res) == []


# ── SMB exposure guards ──────────────────────────────────────────────────────

def test_smb_between_two_private_hosts_is_normal_file_sharing():
    res = ExtractionResult()
    res.flows = {"a": _flow("192.168.1.10", "192.168.1.20", 50000, 445)}
    assert protocol_misuse._smb_to_internet(res) == []


def test_smb_inside_one_public_campus_block_is_not_internet_facing():
    """A university /16 is public but still one organisation's LAN.

    This is the guard that keeps CTU-13-style captures from producing a CRITICAL
    'SMB exposed to the internet' finding for ordinary intra-campus traffic.
    """
    res = ExtractionResult()
    res.flows = {"a": _flow("147.32.84.10", "147.32.84.20", 50000, 445)}
    assert protocol_misuse._smb_to_internet(res) == []


def test_smb_crossing_the_network_boundary_is_still_reported_once():
    # A genuinely routable address. The RFC 5737 documentation ranges
    # (192.0.2/24, 198.51.100/24, 203.0.113/24) are all `is_private` to Python's
    # ipaddress module, so using one here would silently test nothing.
    res = ExtractionResult()
    res.flows = {
        "a": _flow("192.168.1.10", "185.199.108.153", 50000, 445),
        "b": _flow("192.168.1.10", "185.199.108.153", 50001, 445),
    }
    events = protocol_misuse._smb_to_internet(res)
    assert len(events) == 1, "two flows to one server are one exposure"
    assert events[0].severity == Severity.CRITICAL


# ── Cleartext-protocol guards ────────────────────────────────────────────────

def test_a_flow_with_no_destination_address_is_skipped():
    res = ExtractionResult()
    res.flows = {"a": _flow("192.168.1.10", "", 50000, 21)}
    assert protocol_misuse._cleartext_to_internet(res) == []


def test_cleartext_ftp_inside_one_public_campus_block_is_not_flagged():
    res = ExtractionResult()
    res.flows = {"a": _flow("147.32.84.10", "147.32.84.99", 50000, 21)}
    assert protocol_misuse._cleartext_to_internet(res) == []


def test_cleartext_ftp_to_the_internet_is_reported_once_per_server():
    res = ExtractionResult()
    res.flows = {
        "a": _flow("192.168.1.10", "193.122.6.168", 50000, 21),
        "b": _flow("192.168.1.10", "193.122.6.168", 50001, 21),
    }
    events = protocol_misuse._cleartext_to_internet(res)
    assert len(events) == 1
    assert events[0].severity == Severity.HIGH


# ── Beacon statistics ────────────────────────────────────────────────────────

def _beacon_cfg(tmp_path, monkeypatch, body: str):
    from packetiq import config
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    return config


@pytest.fixture(autouse=True)
def _restore_config():
    from packetiq import config
    yield
    config.reload()


def test_too_few_connections_is_not_a_beacon():
    det = beacon.BeaconDetector()
    assert det._analyse("10.0.0.9", "185.199.108.153", 443,
                        [i * 30.0 for i in range(4)], "TCP", set()) is None


def test_perfectly_regular_traffic_inside_one_campus_block_is_not_c2():
    """Both endpoints public, both in 147.32.0.0/16 — one organisation's LAN.

    Timing this regular is a health check or a sync client. Calling it C2 because
    the addresses happen to be routable is the false positive the same-org guard
    exists to prevent, and RFC1918 alone would not catch it.
    """
    det = beacon.BeaconDetector()
    assert det._analyse("147.32.84.10", "147.32.84.99", 443,
                        [i * 30.0 for i in range(16)], "TCP", set()) is None


def test_the_same_regular_traffic_across_organisations_is_c2():
    """The control for the test above: identical timing, different /16."""
    det = beacon.BeaconDetector()
    ev = det._analyse("147.32.84.10", "185.199.108.153", 443,
                      [i * 30.0 for i in range(16)], "TCP", set())
    assert ev is not None and ev.event_type == EventType.C2_BEACON


def test_irregular_intervals_are_not_a_beacon():
    """Human browsing. CV is high and the intervals do not cluster around a median."""
    det = beacon.BeaconDetector()
    ts, t = [], 0.0
    for gap in (7, 240, 15, 500, 33, 90, 600, 12, 310, 45, 180, 8, 420, 60, 25):
        t += gap
        ts.append(t)

    assert det._analyse("10.0.0.9", "185.199.108.153", 443, ts, "TCP", set()) is None


def test_a_metronomic_beacon_is_critical():
    det = beacon.BeaconDetector()
    ts = [i * 30.0 for i in range(16)]
    ev = det._analyse("10.0.0.9", "185.199.108.153", 443, ts, "TCP", set())

    assert ev is not None and ev.severity == Severity.CRITICAL
    assert ev.evidence["cv"] < 0.10


def test_a_lightly_jittered_beacon_is_high_not_critical():
    """CV lands between the CRITICAL and MEDIUM thresholds: regular, but not a metronome."""
    det = beacon.BeaconDetector()
    offsets = [0, 4, -4, 3, -3, 5, -5, 2, -2, 4, -4, 3, -3, 5, -5, 0]
    ts, t = [], 0.0
    for i, off in enumerate(offsets):
        t = i * 30.0 + off
        ts.append(t)
    ev = det._analyse("10.0.0.9", "185.199.108.153", 443, ts, "TCP", set())

    assert ev is not None, "a lightly jittered beacon must still be caught"
    assert ev.severity == Severity.HIGH
    assert 0.10 <= ev.evidence["cv"] < 0.25


def test_a_heavily_jittered_but_periodic_beacon_is_medium():
    """Deliberate evasion jitter: CV above the 'regular' line, but most intervals
    still sit near the median.

    Ten 60-second intervals and four 150-second ones put CV at 0.49 — inside the
    jitter band, well outside 'regular' — while 71% of intervals stay within 30%
    of the median. That combination is the whole point of the secondary
    periodicity signal: a pure-CV check waves this traffic through.
    """
    deltas = [60, 150, 60, 60, 150, 60, 60, 60, 150, 60, 60, 150, 60, 60]
    ts, t = [0.0], 0.0
    for d in deltas:
        t += d
        ts.append(t)

    ev = beacon.BeaconDetector()._analyse("10.0.0.9", "185.199.108.153", 443,
                                          ts, "TCP", set())
    assert ev is not None, "a jittered but periodic beacon must not be missed"
    assert ev.severity == Severity.MEDIUM
    assert 0.25 <= ev.evidence["cv"] < 0.50


def test_a_single_usable_interval_cannot_have_a_standard_deviation(tmp_path, monkeypatch):
    """statistics.stdev needs two points. With min_connections tuned down to 2 a
    lone interval reaches it, and the StatisticsError guard is what stops the
    whole detection pass from dying on one odd flow."""
    _beacon_cfg(tmp_path, monkeypatch, "[beacon]\nmin_connections = 2\n")
    det = beacon.BeaconDetector()

    assert det._analyse("10.0.0.9", "185.199.108.153", 443,
                        [0.0, 30.0], "TCP", set()) is None


def test_intervals_below_the_floor_average_out_below_it(tmp_path, monkeypatch):
    """With min_interval lowered, sub-second bursts pass the per-delta filter but
    their mean is still under the module floor — retransmits, not a beacon."""
    _beacon_cfg(tmp_path, monkeypatch,
                "[beacon]\nmin_connections = 4\nmin_interval = 0.01\n")
    det = beacon.BeaconDetector()

    assert det._analyse("10.0.0.9", "185.199.108.153", 443,
                        [i * 0.5 for i in range(12)], "TCP", set()) is None


def test_a_periodic_http_beacon_to_an_external_host_is_reported():
    """The HTTP grouping arm of detect(), which the SYN arm does not exercise."""
    res = ExtractionResult()
    res.http_requests = [
        {"ts": i * 60.0, "src": "192.168.1.50", "dst": "185.199.108.153",
         "host": "cdn.example-evil.xyz", "path": "/x", "method": "GET", "port": 8443}
        for i in range(16)
    ]
    events = beacon.BeaconDetector().detect(res)

    assert [e.event_type for e in events] == [EventType.C2_BEACON]
    assert events[0].evidence["protocol"] == "HTTP"
    assert events[0].dst_port == 8443, "the real server port must survive into the finding"


@pytest.mark.parametrize("secs,expect", [(12.5, "s"), (450.0, "min"), (7200.0, "hr")])
def test_interval_formatting_scales_to_the_magnitude(secs, expect):
    assert beacon._fmt(secs).endswith(expect)
