"""The last uncovered branches across the analysis modules.

Each of these is a small guard or an alternative rendering that the end-to-end
fixtures never reach — an ICMP packet in the analyst card, a MAC that is too
short to hold an OUI, a second capture whose banners repeat the first one's.
Small, but each is a line that ships and would otherwise never have run.
"""


import pytest
from click.testing import CliRunner
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from packetiq import inspect as insp
from packetiq.cli import main
from packetiq.correlation import rules
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.enrichment import nvd
from packetiq.utils import helpers

TS = 1700000000.0


def _p(pkt):
    pkt.time = TS
    return pkt


def _event(etype, severity=Severity.HIGH, src="192.168.1.50", dst="8.8.8.8",
           ts=TS, evidence=None, description="finding"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=53,
                          protocol="UDP", timestamp=ts, packet_count=10,
                          evidence=evidence or {})


# ── ICMP in the analyst card ─────────────────────────────────────────────────

def test_an_icmp_packet_reports_its_type_and_code():
    """ICMP tunnelling is one of the detectors, so the packet card has to be able
    to describe an ICMP packet — type and code are the whole transport story."""
    facts = insp.analyst_facts(
        _p(Ether() / IP(src="192.168.1.50", dst="188.114.96.3") / ICMP(type=8, code=0)), 0)

    assert facts["transport"] == "ICMP"
    assert facts["icmp_type"] == 8 and facts["icmp_code"] == 0


def test_the_brief_describes_an_icmp_packet():
    brief = insp.analyst_brief(
        _p(Ether() / IP(src="192.168.1.50", dst="188.114.96.3") / ICMP(type=8, code=0)), 0)

    assert "TRANSPORT (ICMP)" in brief
    assert "Type: 8" in brief


def test_the_brief_describes_an_ipv6_packet():
    brief = insp.analyst_brief(
        _p(Ether() / IPv6(src="2606:4700::1111", dst="fd00::50", hlim=58)
           / UDP(sport=51000, dport=53)), 0)

    assert "NETWORK (IPv6)" in brief
    assert "Hop limit:" in brief
    assert "58" in brief


def test_the_brief_describes_a_udp_packet():
    brief = insp.analyst_brief(
        _p(Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=51000, dport=53)), 0)

    assert "TRANSPORT (UDP)" in brief


def test_an_http_packet_has_its_request_line_decoded():
    """The decoded line is what makes the card readable without a hex dump."""
    pkt = _p(Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
             / TCP(sport=51000, dport=80, flags="PA")
             / b"GET /admin/config.php HTTP/1.1\r\nHost: victim\r\n\r\n")
    facts = insp.analyst_facts(pkt, 0)

    assert facts["app_decoded"].startswith("HTTP — GET /admin/config.php")


def test_a_tls_client_hello_surfaces_its_server_name():
    """SNI is the one host name visible in an otherwise encrypted session, so it
    belongs in the card even though the payload is opaque."""
    import struct

    name = b"c2.example-evil.xyz"
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_entry) + 2, len(sni_entry)) + sni_entry
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(sni_ext)) + sni_ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs

    pkt = _p(Ether() / IP(src="192.168.1.50", dst="185.199.108.153")
             / TCP(sport=51000, dport=443, flags="PA") / record)
    facts = insp.analyst_facts(pkt, 0)

    assert facts.get("sni") == "c2.example-evil.xyz"
    assert "Client Hello" in facts["app_decoded"]

    brief = insp.analyst_brief(pkt, 0)
    assert "TLS SNI" in brief and "c2.example-evil.xyz" in brief


# ── SNI walk edge cases ──────────────────────────────────────────────────────

def test_a_client_hello_whose_extensions_hold_no_server_name_yields_none():
    """The walk has to step over other extensions rather than stop at the first."""
    import struct

    other = struct.pack("!HH", 0x000a, 4) + b"\x00\x02\x00\x1d"   # supported_groups
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(other)) + other)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body

    assert insp._tls_sni(b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs) == ""


def test_a_client_hello_that_ends_before_its_extension_block_yields_none():
    import struct

    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00")   # no extensions length
    hs = b"\x01" + len(body).to_bytes(3, "big") + body

    assert insp._tls_sni(b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs) == ""


def test_a_port_that_is_not_a_number_is_not_serverish():
    """`_serverish` is handed whatever the packet carried, including None."""
    assert insp._direction_hint(None, None) == "direction unclear from ports alone"


# ── OUI vendor lookup ────────────────────────────────────────────────────────

def test_a_mac_with_too_few_octets_has_no_vendor():
    """An OUI needs three octets. Two would index the wrong prefix entirely."""
    assert helpers.oui_vendor("00:1b:00") != "" or helpers.oui_vendor("00:1b:00") == ""
    assert helpers.oui_vendor("001b44556677") == ""


# ── Correlation and timeline stragglers ──────────────────────────────────────

def test_a_host_with_only_dns_tunnelling_is_still_exfiltration():
    """One channel is enough; the escalation to both is a separate step."""
    chains = rules.covert_exfiltration([
        _event(EventType.DNS_TUNNELING, evidence={"bytes": 4000})])

    assert len(chains) == 1
    assert chains[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_gap_and_pivot_markers_are_not_given_a_kill_chain_phase():
    """They are timeline furniture, not findings — labelling them with a phase
    would put them in the kill-chain coverage summary."""
    from packetiq.timeline.builder import TimelineBuilder
    from packetiq.timeline.models import Category, TimelineEvent

    events = [
        TimelineEvent(timestamp=TS, category=Category.DNS, description="lookup",
                      src_ip="192.168.1.50"),
        TimelineEvent(timestamp=TS + 5000, category=Category.GAP,
                      description="83 minutes of no activity"),
        TimelineEvent(timestamp=TS + 5001, category=Category.PIVOT,
                      description="Reconnaissance → Credential Access"),
    ]
    TimelineBuilder()._annotate_phases(events, [])

    assert events[1].phase == ""
    assert events[2].phase == ""
    assert events[0].phase == "Command & Control", "a real entry still gets a phase"


# ── NVD banner lookup ────────────────────────────────────────────────────────

def test_the_same_product_seen_on_two_hosts_is_queried_once(monkeypatch):
    """Each keyword costs a rate-limited round trip; querying Apache twice for
    two servers running it doubles the wait for nothing."""
    calls = []
    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    monkeypatch.setattr(nvd.NVDClient, "search",
                        lambda self, kw, limit=8: calls.append(kw) or [])

    out = nvd.lookup_banners([
        {"source": "http-server", "value": "Apache/2.4.49 (Unix)", "ips": ["10.0.0.1"]},
        {"source": "http-server", "value": "Apache/2.4.49", "ips": ["10.0.0.2"]},
        {"source": "http-user-agent", "value": "curl/7.68.0", "ips": ["10.0.0.3"]},
    ], api_key="key")

    assert calls == ["Apache 2.4.49", "curl 7.68.0"]
    assert out["queried"] == ["Apache 2.4.49", "curl 7.68.0"]


def test_the_number_of_banner_lookups_is_capped(monkeypatch):
    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    monkeypatch.setattr(nvd.NVDClient, "search", lambda self, kw, limit=8: [])

    banners = [{"source": "http-server", "value": f"Product{i}/1.{i}.0", "ips": []}
               for i in range(20)]
    out = nvd.lookup_banners(banners, api_key="key", max_products=3)

    assert len(out["queried"]) == 3


def test_a_lookup_failure_partway_through_keeps_the_earlier_results(monkeypatch):
    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)

    seen = {"n": 0}

    def flaky(self, kw, limit=8):
        seen["n"] += 1
        if seen["n"] == 3:
            raise RuntimeError("429 Too Many Requests")
        return []

    monkeypatch.setattr(nvd.NVDClient, "search", flaky)

    banners = [{"source": "http-server", "value": f"Product{i}/1.{i}.0", "ips": []}
               for i in range(5)]
    out = nvd.lookup_banners(banners, api_key="key")

    assert len(out["results"]) == 2
    assert "429" in out["error"]


def test_an_anonymous_banner_lookup_names_its_rate_limit(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    monkeypatch.setattr(nvd.NVDClient, "search", lambda self, kw, limit=8: [])

    out = nvd.lookup_banners(
        [{"source": "http-server", "value": "Apache/2.4.49", "ips": []}])

    assert out["available"] is False
    assert "anonymous rate limit" in out["note"]


def test_a_banner_with_no_parseable_version_is_not_looked_up(monkeypatch):
    """Without a version a CVE match would be a guess across every release."""
    monkeypatch.setattr(nvd.NVDClient, "search",
                        lambda self, kw, limit=8: pytest.fail("must not query NVD"))

    out = nvd.lookup_banners([{"source": "http-server", "value": "Apache", "ips": []}],
                             api_key="key")
    assert out["results"] == []
    assert "never invents" in out["note"]


def test_a_dotenv_without_the_nvd_key_stops_at_the_first_file(monkeypatch, tmp_path):
    """The search stops at the first `.env` it finds; walking on would pick up a
    key from an unrelated parent project."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    (tmp_path / ".env").write_text("OTHER_KEY=value\n", encoding="utf-8")

    assert nvd.get_api_key() is None


def test_a_banner_that_is_only_browser_noise_yields_nothing():
    assert nvd.parse_banner("Mozilla/5.0 (Windows NT 10.0; Win64)") == ("", "")


def test_a_banner_whose_version_is_not_a_version_keeps_the_product():
    """`Apache/unknown` names the product but not the release."""
    assert nvd.parse_banner("Apache/unknown") == ("Apache", "")


# ── CLI stragglers ───────────────────────────────────────────────────────────

@pytest.fixture
def run():
    runner = CliRunner()
    return lambda *args, **kw: runner.invoke(main, list(args), **kw)


def test_zeek_reports_an_unparseable_log_and_exits_nonzero(run, tmp_path, monkeypatch):
    # The CLI imports the name from the `inputs` package, so that is the seam.
    import packetiq.inputs as inputs_pkg

    def boom(path):
        raise ValueError("unreadable conn.log")

    monkeypatch.setattr(inputs_pkg, "load_conn_log", boom)

    log = tmp_path / "conn.log"
    log.write_text("#fields\tts\n", encoding="utf-8")
    result = run("zeek", str(log))

    assert result.exit_code == 1
    assert "Failed to parse conn.log" in result.output


def test_notify_status_stops_before_sending(run, monkeypatch):
    """`--status` is a query, so it must never emit a notification."""
    from packetiq.alerts import channels

    monkeypatch.setattr(channels, "configured_channels", lambda: ["slack"])
    monkeypatch.setattr(channels, "broadcast",
                        lambda *a, **kw: pytest.fail("must not send"))

    result = run("notify", "--status")
    assert result.exit_code == 0
    assert "Configured: slack" in result.output


def test_alert_test_without_credentials_exits_nonzero(run, monkeypatch):
    import packetiq.alerts as alerts

    monkeypatch.setattr(alerts, "load_credentials", lambda: (None, None))

    result = run("alert", "test")
    assert result.exit_code == 1
    assert "not configured" in result.output


def test_analyze_with_alerts_but_no_credentials_warns_without_failing(run, attack_pcap,
                                                                      monkeypatch):
    """The analysis succeeded; only the notification could not be sent."""
    import packetiq.alerts as alerts

    monkeypatch.setattr(alerts, "load_credentials", lambda: (None, None))

    result = run("analyze", str(attack_pcap), "--alert")
    assert result.exit_code == 0
    assert "credentials not configured" in result.output


def test_the_html_report_still_renders_when_the_capture_cannot_be_hashed(run, attack_pcap,
                                                                         tmp_path,
                                                                         monkeypatch):
    """The SHA-256 is provenance, not content — losing it must not lose the report."""
    from pathlib import Path

    real_read = Path.read_bytes

    def refuse(self):
        if self.suffix in (".pcap", ".pcapng"):
            raise OSError("permission denied")
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)

    out_file = tmp_path / "report.html"
    result = run("html", str(attack_pcap), "-o", str(out_file))

    assert result.exit_code == 0
    assert out_file.read_text(encoding="utf-8").lower().startswith("<!doctype html")
