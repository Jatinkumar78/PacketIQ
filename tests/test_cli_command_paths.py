"""CLI branches the happy-path command suite never reaches.

Every test drives a real command through Click's runner. What is stubbed is only
the boundary — the network, the blocking server, the Telegram transport — so the
command's own branching, formatting and exit codes run for real.

These are the paths a user hits when something is missing or wrong: no API key,
no interfaces, no credentials, an unreadable capture. Those are exactly the
moments when a bad message or a wrong exit code costs the most.
"""

import json
import types

import pytest
from click.testing import CliRunner

from packetiq import cli as cli_mod
from packetiq import net_interfaces
from packetiq.cli import main


@pytest.fixture
def run():
    runner = CliRunner()
    return lambda *args, **kw: runner.invoke(main, list(args), **kw)


def _ok(result):
    if result.exit_code != 0:
        raise AssertionError(
            f"exit={result.exit_code}\n--- output ---\n{result.output}\n"
            f"--- exception ---\n{result.exception!r}")
    return result.output


# ── Pipeline entry ───────────────────────────────────────────────────────────

def test_a_capture_that_disappears_mid_run_exits_with_a_message(run, tmp_path,
                                                                monkeypatch):
    """Click checks the path exists; the file can still vanish before the parser
    opens it. The user needs the reason, not a traceback."""
    from packetiq.parser.pcap_parser import PCAPParser

    def missing(self, path):
        raise FileNotFoundError(f"PCAP not found: {path}")

    monkeypatch.setattr(PCAPParser, "__init__", missing)

    pcap = tmp_path / "gone.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    result = run("analyze", str(pcap))

    assert result.exit_code == 1
    assert "PCAP not found" in result.output


def test_the_progress_line_updates_on_a_large_capture(run, tmp_path):
    """The counter only refreshes every 1000 packets, so a small fixture never
    exercises it — and a broken format string there would abort a real run."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pkts = []
    for i in range(1200):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000 + (i % 500),
                                                               dport=443)
        p.time = 1700000000.0 + i * 0.01
        pkts.append(p)
    pcap = tmp_path / "big.pcap"
    wrpcap(str(pcap), pkts)

    out = _ok(run("analyze", str(pcap)))
    assert "1,200" in out or "1200" in out


# ── analyze: quiet-capture and rendering branches ────────────────────────────

def test_a_capture_with_no_findings_says_so(run, tmp_path):
    """Ordinary traffic must produce a clean bill of health, not an empty page."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pkts = []
    for i in range(20):
        p = Ether() / IP(src="192.168.1.50", dst="192.168.1.60") / TCP(sport=51000 + i,
                                                                       dport=443)
        p.time = 1700000000.0 + i
        pkts.append(p)
    pcap = tmp_path / "benign.pcap"
    wrpcap(str(pcap), pkts)

    out = _ok(run("analyze", str(pcap)))
    assert "No threats detected" in out
    assert "No multi-stage attack chains correlated" in out


def test_analyze_reports_http_activity_when_the_capture_has_any(run, tmp_path):
    from scapy.layers.http import HTTP, HTTPRequest
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pkts = []
    for i in range(3):
        p = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
             / TCP(sport=51000 + i, dport=80, flags="PA")
             / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com",
                                    Path=f"/page{i}".encode(), User_Agent=b"curl/8"))
        p.time = 1700000000.0 + i
        pkts.append(p)
    pcap = tmp_path / "http.pcap"
    wrpcap(str(pcap), pkts)

    out = _ok(run("analyze", str(pcap)))
    assert "HTTP ACTIVITY" in out
    assert "example.com" in out


# ── cve ──────────────────────────────────────────────────────────────────────

def _http_banner_pcap(tmp_path, name="banner.pcap"):
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    req = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=80, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/",
                                  User_Agent=b"curl/7.68.0"))
    resp = (Ether() / IP(src="93.184.216.34", dst="192.168.1.50")
            / TCP(sport=80, dport=51000, flags="PA")
            / HTTP() / HTTPResponse(Status_Code=b"200", Server=b"Apache/2.4.49 (Unix)"))
    for i, p in enumerate((req, resp)):
        p.time = 1700000000.0 + i
    path = tmp_path / name
    wrpcap(str(path), [req, resp])
    return path


_FAKE_CVE = {"id": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL",
             "description": "Path traversal in Apache 2.4.49." * 6,
             "published": "2021-10-05", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"}


def test_cve_prints_the_observed_banners_and_the_matching_cves(run, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd, "lookup_banners", lambda banners, **kw: {
        "available": True, "queried": ["Apache 2.4.49"],
        "results": [{"product": "Apache", "version": "2.4.49", "source": "http-server",
                     "ips": ["93.184.216.34"], "cves": [_FAKE_CVE]}],
        "note": "Matched 1 CVE(s) across 1 product(s) from real NVD data.",
        "error": None})

    out = _ok(run("cve", str(_http_banner_pcap(tmp_path))))

    assert "software banner(s)" in out
    assert "Apache/2.4.49" in out
    assert "CVE-2021-41773" in out
    assert "9.8" in out
    assert "nvd.nist.gov" in out


def test_cve_warns_when_no_api_key_is_configured(run, tmp_path, monkeypatch):
    """Anonymous NVD access is heavily rate-limited — silently taking six seconds
    per product looks like a hang."""
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "get_api_key", lambda: None)
    monkeypatch.setattr(nvd, "lookup_banners", lambda banners, **kw: {
        "available": False, "queried": [], "results": [],
        "note": "No NVD CVEs matched the observed software versions.", "error": None})

    out = _ok(run("cve", str(_http_banner_pcap(tmp_path))))
    assert "No NVD_API_KEY set" in out


def test_cve_surfaces_an_nvd_error_and_an_empty_result(run, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd, "lookup_banners", lambda banners, **kw: {
        "available": True, "queried": ["Apache 2.4.49"], "results": [],
        "note": "No CVEs matched.", "error": "HTTPError: 503"})

    out = _ok(run("cve", str(_http_banner_pcap(tmp_path))))
    assert "NVD error" in out and "503" in out
    assert "No CVEs matched" in out


def test_cve_reports_a_product_with_no_matches_without_claiming_it_is_safe(run, tmp_path,
                                                                           monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd, "lookup_banners", lambda banners, **kw: {
        "available": True, "queried": ["Apache 2.4.49"],
        "results": [{"product": "Apache", "version": "2.4.49", "source": "http-server",
                     "ips": [], "cves": []}],
        "note": "No NVD CVEs matched the observed software versions.", "error": None})

    out = _ok(run("cve", str(_http_banner_pcap(tmp_path))))
    assert "No CVEs matched this version in NVD" in out


# ── vulns ────────────────────────────────────────────────────────────────────

def test_vulns_prints_the_risk_products_and_exploit_correlations(run, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd, "assess_vulnerabilities", lambda banners, attacks=None, **kw: {
        "available": True,
        "products": [{"product": "Apache", "version": "2.4.49", "source": "http-server",
                      "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                      "ips": ["93.184.216.34"],
                      "cves": [{**_FAKE_CVE, "kev": True, "ransomware": True}]},
                     {"product": "nginx", "version": "1.27.0", "source": "http-server",
                      "cpe": None, "ips": [], "cves": []}],
        "hosts": [], "correlations": [
            {"attack": "Log4Shell", "name": "Log4Shell RCE", "cves": ["CVE-2021-44228"],
             "target": "93.184.216.34", "target_software": ["Apache 2.4.49"], "kev": True}],
        "risk": {"score": 98, "tier": "CRITICAL"},
        "totals": {"cves": 1, "kev": 1, "products": 2, "kev_catalog": 1200},
        "note": "1 CVE(s) across 2 product(s).", "error": None})

    out = _ok(run("vulns", str(_http_banner_pcap(tmp_path))))

    assert "98/100" in out and "CRITICAL" in out
    assert "CVE-2021-41773" in out
    assert "KEV" in out and "RANSOMWARE" in out
    assert "No current CVEs matched this version" in out
    assert "Exploit attempt for Log4Shell RCE" in out
    assert "93.184.216.34" in out
    assert "CISA KEV" in out


def test_vulns_warns_about_the_anonymous_rate_limit_and_surfaces_errors(run, tmp_path,
                                                                        monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "get_api_key", lambda: None)
    monkeypatch.setattr(nvd, "assess_vulnerabilities", lambda banners, attacks=None, **kw: {
        "available": False, "products": [], "hosts": [], "correlations": [],
        "risk": {"score": 0, "tier": "NONE"},
        "totals": {"cves": 0, "kev": 0, "products": 0, "kev_catalog": 0},
        "note": "n/a", "error": "Timeout: nvd.nist.gov"})

    out = _ok(run("vulns", str(_http_banner_pcap(tmp_path))))
    assert "No NVD_API_KEY set" in out
    assert "NVD error" in out and "Timeout" in out


# ── live ─────────────────────────────────────────────────────────────────────

def test_live_lists_interfaces_with_link_state(run, monkeypatch):
    monkeypatch.setattr(net_interfaces, "list_interfaces", lambda: [
        {"name": "en0", "label": "Wi-Fi", "ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:01",
         "kind": "wifi", "up": True, "is_default": True, "recommended": True},
        {"name": "en1", "label": "Ethernet", "ip": "", "mac": "", "kind": "ethernet",
         "up": False, "is_default": False, "recommended": False},
        {"name": "lo0", "label": "Loopback", "ip": "127.0.0.1", "mac": "",
         "kind": "loopback", "up": None, "is_default": False, "recommended": False},
    ])

    out = _ok(run("live", "--list"))
    assert "en0" in out and "Wi-Fi" in out
    assert "up" in out and "down" in out
    assert "sudo packetiq live" in out


def test_live_with_no_interfaces_says_so(run, monkeypatch):
    monkeypatch.setattr(net_interfaces, "list_interfaces", lambda: [])

    out = _ok(run("live", "--list"))
    assert "No capture interfaces found" in out


def test_live_without_an_interface_lists_them_and_fails(run, monkeypatch):
    """Exiting 1 matters — a script that forgets -i must not look successful."""
    monkeypatch.setattr(net_interfaces, "list_interfaces", lambda: [
        {"name": "en0", "label": "Wi-Fi", "ip": "192.168.1.50", "mac": "", "kind": "wifi",
         "up": True, "is_default": True, "recommended": True}])

    result = run("live")
    assert result.exit_code == 1
    assert "Provide -i/--interface" in result.output
    assert "en0" in result.output


def test_live_reports_a_permission_failure_and_exits_nonzero(run, monkeypatch):
    from packetiq import live as live_mod

    def denied(*a, **kw):
        raise RuntimeError("Permission denied opening the interface. Run with sudo.")

    monkeypatch.setattr(live_mod, "sniff_live", denied)

    result = run("live", "-i", "en0")
    assert result.exit_code == 1
    assert "sudo" in result.output


def test_a_live_replay_prints_each_alert_as_it_fires(run, attack_pcap):
    out = _ok(run("live", "--read", str(attack_pcap), "--threshold", "HIGH"))

    assert "Replay complete" in out
    assert "alert(s) raised" in out
    # Each alert prints as `HH:MM:SS SEVERITY EVENT_TYPE src → dst`.
    assert any(sev in out for sev in ("CRITICAL", "HIGH")), out


def test_a_live_replay_can_also_broadcast_to_other_channels(run, attack_pcap, monkeypatch):
    sent = []
    from packetiq.alerts import channels

    monkeypatch.setattr(channels, "broadcast",
                        lambda subject, text, payload=None: sent.append(subject) or {})

    _ok(run("live", "--read", str(attack_pcap), "--alert"))
    assert sent, "the --alert flag must reach the channel broadcaster"


# ── zeek / netflow tables ────────────────────────────────────────────────────

def test_zeek_reports_an_unreadable_log_without_a_traceback(run, tmp_path):
    log = tmp_path / "conn.log"
    log.write_bytes(b"\x00\xff\xfe binary garbage")

    result = run("zeek", str(log))
    assert result.exit_code in (0, 1)
    assert "Traceback" not in result.output


def test_zeek_prints_the_top_conversation_table(run, tmp_path):
    log = tmp_path / "conn.log"
    rows = "\n".join(
        f"1700000{i:03d}.0\t192.168.1.50\t{51000 + i}\t193.122.6.168\t21\ttcp\t1.0\t500\t9000"
        for i in range(5))
    log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration"
        "\torig_bytes\tresp_bytes\n" + rows + "\n", encoding="utf-8")

    out = _ok(run("zeek", str(log)))
    assert "Detection Events" in out
    assert "PROTOCOL MISUSE" in out


def test_netflow_prints_the_top_conversation_table(run, tmp_path):
    import ipaddress
    import struct

    def _v5(records):
        hdr = struct.pack("!HHIIIIBBH", 5, len(records), 100000, 1700000000, 0, 0, 0, 0, 0)
        body = b""
        for i, (src, dst, sp, dp, proto, pkts, octets) in enumerate(records):
            body += struct.pack(
                "!IIIHHIIIIHHBBBBHHBBH",
                int(ipaddress.IPv4Address(src)), int(ipaddress.IPv4Address(dst)),
                0, 0, 0, pkts, octets, 95000 + i, 95010 + i, sp, dp, 0, 0, proto,
                0, 0, 0, 0, 0, 0)
        return hdr + body

    flows = tmp_path / "flows.netflow"
    flows.write_bytes(_v5([("192.168.1.50", "193.122.6.168", 44000 + i, 21, 6, 5, 4000)
                           for i in range(5)]))

    out = _ok(run("netflow", str(flows)))
    assert "Detection Events" in out
    assert "PROTOCOL MISUSE" in out


# ── notify / misp / html / history ───────────────────────────────────────────

def test_notify_sends_to_each_configured_channel(run, monkeypatch):
    from packetiq.alerts import channels

    monkeypatch.setattr(channels, "configured_channels", lambda: ["slack", "webhook"])
    monkeypatch.setattr(channels, "broadcast", lambda subject, text, payload=None: {
        "slack": (True, ""), "webhook": (False, "HTTP 500")})

    out = _ok(run("notify", "something happened"))
    assert "Configured: slack, webhook" in out
    assert "slack: sent" in out
    assert "webhook: FAILED" in out and "HTTP 500" in out


def test_misp_with_no_indicators_does_not_push(run, tmp_path, monkeypatch):
    from packetiq.export import misp as misp_mod

    monkeypatch.setattr(misp_mod, "requests",
                        types.SimpleNamespace(post=lambda *a, **kw: pytest.fail("pushed")))

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    pkts = []
    for i in range(5):
        p = Ether() / IP(src="192.168.1.50", dst="192.168.1.60") / TCP(sport=51000 + i,
                                                                       dport=443)
        p.time = 1700000000.0 + i
        pkts.append(p)
    pcap = tmp_path / "benign.pcap"
    wrpcap(str(pcap), pkts)

    out = _ok(run("misp", str(pcap)))
    assert "No indicators to push" in out


def test_a_failed_misp_push_exits_nonzero(run, attack_pcap, monkeypatch):
    import packetiq.export as export_pkg

    monkeypatch.setattr(export_pkg, "push_to_misp", lambda *a, **kw: (False, "HTTP 403"))

    result = run("misp", str(attack_pcap), "--url", "https://misp.local", "--key", "k")
    assert result.exit_code == 1
    assert "403" in result.output


def test_html_can_include_a_vulnerability_assessment(run, attack_pcap, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "assess_vulnerabilities", lambda banners, attacks=None, **kw: {
        "available": True,
        "products": [{"product": "Apache", "version": "2.4.49", "source": "http-server",
                      "cpe": None, "ips": [], "cves": []}],
        "hosts": [], "correlations": [], "risk": {"score": 10, "tier": "LOW"},
        "totals": {"cves": 0, "kev": 0, "products": 1, "kev_catalog": 0},
        "note": "n/a", "error": None})

    out_file = tmp_path / "report.html"
    _ok(run("html", str(attack_pcap), "-o", str(out_file), "--vulns"))

    html = out_file.read_text(encoding="utf-8")
    assert "Apache" in html


def test_history_renders_the_recorded_analyses(run, monkeypatch):
    from packetiq import storage

    monkeypatch.setattr(storage, "recent", lambda limit: [
        {"analyzed_at": "2026-08-08T12:00:00", "filename": "attack.pcap",
         "risk_score": 88, "risk_tier": "CRITICAL", "event_count": 12, "chain_count": 3},
    ])

    out = _ok(run("history"))
    assert "attack.pcap" in out
    assert "88/100" in out
    assert "CRITICAL" in out


# ── setup-capture / feeds ────────────────────────────────────────────────────

def test_setup_capture_applies_the_fix_when_privileges_are_missing(run, monkeypatch):
    from packetiq import capture_setup

    monkeypatch.setattr(capture_setup, "status", lambda: (False, "linux", "no CAP_NET_RAW"))
    monkeypatch.setattr(capture_setup, "setup", lambda: (True, "Granted CAP_NET_RAW."))

    out = _ok(run("setup-capture"))
    assert "Applying one-time capture-privilege setup" in out
    assert "Granted CAP_NET_RAW" in out


def test_setup_capture_does_nothing_when_capture_already_works(run, monkeypatch):
    """The machine this was first run on already had capture enabled, so this
    early return was covered locally and absent on the CI runner, where the probe
    says no. Assert the command stops rather than re-applying a fix nobody needs.
    """
    from packetiq import capture_setup

    monkeypatch.setattr(capture_setup, "status", lambda: (True, "mac", "member of access_bpf"))
    monkeypatch.setattr(capture_setup, "setup",
                        lambda: pytest.fail("setup must not run when capture already works"))

    out = _ok(run("setup-capture"))
    assert "already enabled" in out
    assert "Applying one-time capture-privilege setup" not in out


def test_a_failed_capture_setup_exits_nonzero(run, monkeypatch):
    from packetiq import capture_setup

    monkeypatch.setattr(capture_setup, "status", lambda: (False, "linux", "no CAP_NET_RAW"))
    monkeypatch.setattr(capture_setup, "setup", lambda: (False, "setcap not found"))

    result = run("setup-capture")
    assert result.exit_code == 1
    assert "setcap not found" in result.output


def test_feeds_status_with_no_feeds_points_at_the_update_command(run, monkeypatch):
    import packetiq.enrichment as enrichment_pkg
    from packetiq.detection import ja3

    monkeypatch.setattr(enrichment_pkg, "feed_summary", lambda: {})
    monkeypatch.setattr(ja3, "load_blocklist", lambda *a, **kw: {})

    out = _ok(run("feeds", "status"))
    assert "No feeds loaded" in out
    assert "feeds update" in out


# ── alert group ──────────────────────────────────────────────────────────────

def test_alert_setup_without_a_token_exits_with_where_to_get_one(run, monkeypatch):
    import packetiq.alerts as alerts

    monkeypatch.setattr(alerts, "load_credentials", lambda: (None, None))

    result = run("alert", "setup")
    assert result.exit_code == 1
    assert "TELEGRAM_BOT_TOKEN not found" in result.output
    assert "BotFather" in result.output


def test_alert_setup_without_a_chat_id_explains_how_to_find_one(run, monkeypatch):
    import packetiq.alerts as alerts

    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, None))

    result = run("alert", "setup")
    assert result.exit_code == 1
    assert "TELEGRAM_CHAT_ID not found" in result.output
    assert "getUpdates" in result.output


def test_alert_setup_masks_the_token_and_confirms_a_working_connection(run, monkeypatch):
    import packetiq.alerts as alerts

    token = "123456789:" + "A" * 25
    monkeypatch.setattr(alerts, "load_credentials", lambda: (token, "-100123"))
    monkeypatch.setattr(alerts.TelegramSender, "test_connection",
                        lambda self: (True, "Connected as @packetiq_bot"))

    out = _ok(run("alert", "setup"))
    assert "A" * 25 not in out, "the secret half of the token must not be printed"
    assert "123456789:AA" in out
    assert "Connection OK" in out
    assert "test message has been sent" in out


def test_a_failing_alert_setup_exits_nonzero(run, monkeypatch):
    import packetiq.alerts as alerts

    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))
    monkeypatch.setattr(alerts.TelegramSender, "test_connection",
                        lambda self: (False, "chat not found"))

    result = run("alert", "setup")
    assert result.exit_code == 1
    assert "Connection FAILED" in result.output and "chat not found" in result.output


def test_alert_test_sends_the_message(run, monkeypatch):
    import packetiq.alerts as alerts

    sent = []
    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))
    monkeypatch.setattr(alerts.TelegramSender, "send",
                        lambda self, text, **kw: (sent.append(text), (True, ""))[1])

    out = _ok(run("alert", "test", "custom message"))
    assert "sent successfully" in out
    assert "custom message" in sent[0]


def test_a_failing_alert_test_exits_nonzero(run, monkeypatch):
    import packetiq.alerts as alerts

    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))
    monkeypatch.setattr(alerts.TelegramSender, "send",
                        lambda self, text, **kw: (False, "network unreachable"))

    result = run("alert", "test")
    assert result.exit_code == 1
    assert "Send failed" in result.output


# ── Telegram dispatch from analyze ───────────────────────────────────────────

def test_analyze_with_alerts_dispatches_and_summarises(run, attack_pcap, monkeypatch):
    import packetiq.alerts as alerts
    from packetiq.alerts.dispatcher import DispatchResult

    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))
    monkeypatch.setattr(alerts.AlertDispatcher, "dispatch",
                        lambda self, **kw: DispatchResult(sent=4, skipped=1))

    out = _ok(run("analyze", str(attack_pcap), "--alert"))
    assert "Alerts sent: 4 message(s) | 1 skipped" in out


def test_a_partial_alert_dispatch_is_reported_with_its_errors(run, attack_pcap, monkeypatch):
    import packetiq.alerts as alerts
    from packetiq.alerts.dispatcher import DispatchResult

    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))
    monkeypatch.setattr(alerts.AlertDispatcher, "dispatch",
                        lambda self, **kw: DispatchResult(
                            sent=2, failed=2, errors=["chat not found", "rate limited"]))

    out = _ok(run("analyze", str(attack_pcap), "--alert"))
    assert "Alert dispatch partial: 2 sent, 2 failed" in out
    assert "chat not found" in out


def test_an_unknown_alert_threshold_falls_back_to_high(run, attack_pcap, monkeypatch):
    """Click validates the CLI choice, but the helper is also called internally."""
    import packetiq.alerts as alerts
    from packetiq.detection.models import Severity

    captured = {}
    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))

    class Recorder:
        def __init__(self, sender, threshold=None):
            captured["threshold"] = threshold

        def dispatch(self, **kw):
            from packetiq.alerts.dispatcher import DispatchResult
            return DispatchResult(sent=1)

    monkeypatch.setattr(alerts, "AlertDispatcher", Recorder)

    from pathlib import Path

    from packetiq.detection.risk_scorer import RiskReport
    from packetiq.extractor.data_extractor import ExtractionResult

    cli_mod._send_telegram_alerts(
        Path("attack.pcap"), ExtractionResult(), [], [],
        RiskReport(score=10, tier="LOW", color="green", summary="", event_count=0,
                   by_severity={}, by_type={}, top_sources=[], top_targets=[]),
        threshold="NOT-A-LEVEL")

    assert captured["threshold"] == Severity.HIGH


# ── webapp binding ───────────────────────────────────────────────────────────

def test_binding_to_all_interfaces_warns_and_widens_the_host_allow_list(run, monkeypatch):
    import os

    started = {}
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: started.update(kw))
    # setenv (not delenv): monkeypatch only records a variable it can see, so
    # delenv on an unset name restores nothing and the command's own write would
    # leak `*` into every later test — including the DNS-rebinding guard's.
    monkeypatch.setenv("PACKETIQ_ALLOWED_HOSTS", "127.0.0.1")

    out = _ok(run("webapp", "--host", "0.0.0.0", "--no-browser"))

    assert "SECURITY" in out and "no authentication" in out
    assert os.environ["PACKETIQ_ALLOWED_HOSTS"] == "*"
    assert started["host"] == "0.0.0.0"


def test_binding_to_a_named_host_allow_lists_exactly_that_host(run, monkeypatch):
    import os

    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    monkeypatch.setenv("PACKETIQ_ALLOWED_HOSTS", "127.0.0.1")

    _ok(run("webapp", "--host", "192.168.1.50", "--no-browser"))
    assert os.environ["PACKETIQ_ALLOWED_HOSTS"] == "192.168.1.50"


def test_the_browser_is_opened_in_the_background_unless_suppressed(run, monkeypatch):
    import threading
    import webbrowser

    import uvicorn

    opened = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: None)
    monkeypatch.setattr(webbrowser, "open", opened.append)

    class ImmediateThread:
        def __init__(self, target=None, daemon=None):
            self._target = target

        def start(self):
            self._target()

    monkeypatch.setattr(threading, "Thread", ImmediateThread)
    monkeypatch.setattr("time.sleep", lambda s: None)

    _ok(run("webapp"))
    assert opened and opened[0].startswith("http://127.0.0.1:8080/")


# ── Remaining analyze / report / fuse / slice branches ───────────────────────

def test_analyze_prints_the_same_chassis_inference(run, attack_pcap, monkeypatch):
    """Two NICs on one OUI are probably one switch. The CLI says so as an
    inference and keeps the NICs separate, matching the HTML report."""
    from packetiq.extractor.data_extractor import DataExtractor

    real_finalize = DataExtractor.finalize

    def with_chassis(self):
        result = real_finalize(self)
        result.devices = list(result.devices) + [
            {"id": "aa:bb:cc:00:00:01", "mac": "aa:bb:cc:00:00:01", "ips": [],
             "kind": "infrastructure", "protocols": ["STP"], "packets": 20},
        ]
        result.chassis_groups = [{"oui": "aa:bb:cc",
                                  "macs": ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]}]
        return result

    monkeypatch.setattr(DataExtractor, "finalize", with_chassis)

    out = _ok(run("analyze", str(attack_pcap)))
    assert "share OUI aa:bb:cc" in out
    assert "distinct MACs" in out


def test_a_broken_forecast_does_not_take_the_analysis_down(run, attack_pcap, monkeypatch):
    """The forecast is the last, most speculative section. Everything before it
    is evidence, and must survive it failing."""
    from packetiq import prediction

    def boom(result, events):
        raise RuntimeError("forecast unavailable")

    monkeypatch.setattr(prediction, "predict", boom)

    out = _ok(run("analyze", str(attack_pcap)))
    assert "DETECTION EVENTS" in out or "BRUTE" in out.upper()
    assert "THREAT FORECAST" not in out


def test_a_failed_report_generation_exits_nonzero(run, attack_pcap, monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setattr(MultiProviderClient, "available", lambda self: True)
    monkeypatch.setattr(MultiProviderClient, "model_label", "stub-model")
    monkeypatch.setattr(MultiProviderClient, "load_context", lambda self, ctx: None)
    monkeypatch.setattr(MultiProviderClient, "single_message",
                        lambda self, prompt: (_ for _ in ()).throw(
                            RuntimeError("all providers exhausted")))

    result = run("report", str(attack_pcap))
    assert result.exit_code == 1
    assert "Report generation failed" in result.output
    assert "all providers exhausted" in result.output


def test_report_names_the_file_after_the_capture_and_the_time(run, attack_pcap,
                                                              tmp_path, monkeypatch):
    """With no -o the report lands beside the capture with a timestamp, so two
    runs never overwrite each other."""
    import shutil

    from packetiq.copilot.multi_provider import MultiProviderClient

    local_pcap = tmp_path / "incident.pcap"
    shutil.copy(attack_pcap, local_pcap)

    monkeypatch.setattr(MultiProviderClient, "available", lambda self: True)
    monkeypatch.setattr(MultiProviderClient, "model_label", "stub-model")
    monkeypatch.setattr(MultiProviderClient, "load_context", lambda self, ctx: None)
    monkeypatch.setattr(MultiProviderClient, "single_message",
                        lambda self, prompt: "# SOC Report\n\nBody.")

    _ok(run("report", str(local_pcap)))

    written = list(tmp_path.glob("report_incident_*.md"))
    assert len(written) == 1
    assert written[0].read_text(encoding="utf-8").startswith("# SOC Report")


def test_report_can_also_dispatch_the_alerts(run, attack_pcap, tmp_path, monkeypatch):
    import packetiq.alerts as alerts
    from packetiq.alerts.dispatcher import DispatchResult
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setattr(MultiProviderClient, "available", lambda self: True)
    monkeypatch.setattr(MultiProviderClient, "model_label", "stub-model")
    monkeypatch.setattr(MultiProviderClient, "load_context", lambda self, ctx: None)
    monkeypatch.setattr(MultiProviderClient, "single_message",
                        lambda self, prompt: "# SOC Report")
    monkeypatch.setattr(alerts, "load_credentials",
                        lambda: ("123456789:" + "A" * 25, "-100123"))

    captured = {}

    def dispatch(self, **kw):
        captured.update(kw)
        return DispatchResult(sent=3)

    monkeypatch.setattr(alerts.AlertDispatcher, "dispatch", dispatch)

    out = _ok(run("report", str(attack_pcap), "-o", str(tmp_path / "r.md"), "--alert"))

    assert "Alerts sent: 3" in out
    assert captured["report_path"] is not None, "the written report is attached"


def test_chat_without_any_provider_exits_with_setup_guidance(run, attack_pcap, monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setattr(MultiProviderClient, "available", lambda self: False)

    result = run("chat", str(attack_pcap))
    assert result.exit_code == 1
    assert "No AI provider available" in result.output
    assert "GEMINI_API_KEY" in result.output and "Ollama" in result.output


def test_fuse_needs_at_least_two_captures(run, attack_pcap):
    out = _ok(run("fuse", str(attack_pcap)))
    assert "at least 2 PCAP files" in out


def test_fuse_reports_a_capture_it_could_not_read_and_carries_on(run, attack_pcap,
                                                                 tmp_path):
    """One corrupt file in a batch must not abandon the campaign correlation."""
    broken = tmp_path / "broken.pcap"
    broken.write_bytes(b"not a pcap at all, truncated mid-header")

    result = run("fuse", str(attack_pcap), str(broken))
    assert "broken.pcap" in result.output
    assert "CAMPAIGN FUSION" in result.output


def test_slice_reports_when_nothing_matched(run, attack_pcap, tmp_path):
    out_file = tmp_path / "slice.pcap"
    out = _ok(run("slice", str(attack_pcap), "--ip", "203.0.113.199",
                  "-o", str(out_file)))

    assert "No packets matched the filter" in out


# ── Machine-readable output ──────────────────────────────────────────────────

def test_cve_json_is_a_parseable_document(run, tmp_path, monkeypatch, capsys):
    from packetiq.enrichment import nvd

    payload = {"available": True, "queried": ["Apache 2.4.49"],
               "results": [{"product": "Apache", "version": "2.4.49",
                            "source": "http-server", "ips": [], "cves": [_FAKE_CVE]}],
               "note": "ok", "error": None}
    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd, "lookup_banners", lambda banners, **kw: payload)

    from packetiq.cli import main as cli_main

    pcap = _http_banner_pcap(tmp_path, "json.pcap")
    with pytest.raises(SystemExit):
        cli_main(["cve", str(pcap), "--json"], standalone_mode=True)

    out = capsys.readouterr().out
    body = out[out.index("{"):out.rindex("}") + 1]
    assert json.loads(body)["results"][0]["cves"][0]["id"] == "CVE-2021-41773"


def test_vulns_json_is_a_parseable_document(run, tmp_path, monkeypatch, capsys):
    from packetiq.enrichment import nvd

    payload = {"available": True, "products": [], "hosts": [], "correlations": [],
               "risk": {"score": 0, "tier": "NONE"},
               "totals": {"cves": 0, "kev": 0, "products": 0, "kev_catalog": 0},
               "note": "ok", "error": None}
    monkeypatch.setattr(nvd, "get_api_key", lambda: "key")
    monkeypatch.setattr(nvd, "assess_vulnerabilities",
                        lambda banners, attacks=None, **kw: payload)

    from packetiq.cli import main as cli_main

    pcap = _http_banner_pcap(tmp_path, "json2.pcap")
    with pytest.raises(SystemExit):
        cli_main(["vulns", str(pcap), "--json"], standalone_mode=True)

    out = capsys.readouterr().out
    body = out[out.index("{"):out.rindex("}") + 1]
    assert json.loads(body)["risk"]["tier"] == "NONE"
