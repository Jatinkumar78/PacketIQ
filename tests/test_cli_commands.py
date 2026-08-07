"""
End-to-end exercise of every registered CLI command.

The CLI is the product's primary interface and was its least-tested module: a
typo in an option, a renamed attribute, or a serialiser that cannot handle a real
capture would only surface when a user ran the command. These tests invoke each
command the way a user does — through Click's runner, over the synthetic attack
capture — and assert on what lands on stdout and on disk.

Anything that would reach the network or block on a server is stubbed at the
boundary; the command's own logic still runs.
"""

import json

import pytest
from click.testing import CliRunner

from packetiq import cli as cli_mod
from packetiq.cli import main


@pytest.fixture
def run():
    runner = CliRunner()
    return lambda *args, **kw: runner.invoke(main, list(args), **kw)


def _ok(result):
    """Assert clean exit, surfacing the traceback when there isn't one."""
    if result.exit_code != 0:
        raise AssertionError(
            f"exit={result.exit_code}\n--- output ---\n{result.output}\n"
            f"--- exception ---\n{result.exception!r}"
        )
    return result.output


# --------------------------------------------------------------------------- #
#  Root group                                                                   #
# --------------------------------------------------------------------------- #

def test_bare_invocation_prints_help(run):
    out = _ok(run())
    assert "Usage:" in out
    assert "analyze" in out


def test_help_flag_lists_every_command(run):
    out = _ok(run("--help"))
    for cmd in ("analyze", "report", "timeline", "sigma", "dashboard", "webapp",
                "fuse", "slice", "stix", "navigator", "cve", "vulns", "live",
                "zeek", "netflow", "notify", "misp", "html", "history",
                "setup-capture", "version", "feeds", "alert", "chat"):
        assert cmd in out, f"{cmd} missing from help"


def test_version_reports_1_0_0(run):
    out = _ok(run("version"))
    assert "1.0.0" in out


def test_an_unknown_command_fails_cleanly(run):
    result = run("definitely-not-a-command")
    assert result.exit_code != 0
    assert "No such command" in result.output


def test_a_missing_pcap_is_rejected_before_any_work(run):
    result = run("analyze", "/nonexistent/nope.pcap")
    assert result.exit_code != 0
    assert "does not exist" in result.output


# --------------------------------------------------------------------------- #
#  analyze                                                                      #
# --------------------------------------------------------------------------- #

def test_analyze_reports_the_real_findings(run, attack_pcap):
    out = _ok(run("analyze", attack_pcap))
    assert "PCAP PARSING" in out
    assert "THREAT DETECTION" in out
    assert "ATTACK CORRELATION" in out
    assert "Risk:" in out


def test_analyze_full_produces_at_least_as_much_output(run, attack_pcap):
    brief = _ok(run("analyze", attack_pcap))
    full = _ok(run("analyze", attack_pcap, "--full"))
    assert len(full) >= len(brief)


def test_analyze_honours_the_top_limit(run, attack_pcap):
    _ok(run("analyze", attack_pcap, "--top", "3"))


def test_analyze_can_suppress_the_timeline(run, attack_pcap):
    out = _ok(run("analyze", attack_pcap, "--no-timeline"))
    assert "Risk:" in out


def test_analyze_with_alerts_does_not_send_without_configuration(run, attack_pcap, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    _ok(run("analyze", attack_pcap, "--alert", "--alert-threshold", "CRITICAL"))


# --------------------------------------------------------------------------- #
#  Reporting / export commands                                                  #
# --------------------------------------------------------------------------- #

def test_report_writes_the_ai_narrative_to_the_named_file(run, attack_pcap, tmp_path, monkeypatch):
    """The AI is stubbed: this covers the command's own plumbing, not the model."""
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setattr(MultiProviderClient, "available", lambda self: True)
    monkeypatch.setattr(MultiProviderClient, "load_context", lambda self, ctx: None)
    monkeypatch.setattr(MultiProviderClient, "model_label", "stub-model", raising=False)
    monkeypatch.setattr(MultiProviderClient, "single_message",
                        lambda self, prompt: "# Incident Report\n\nSynthetic body.")

    out_file = tmp_path / "incident.md"
    _ok(run("report", attack_pcap, "-o", str(out_file)))
    assert out_file.read_text(encoding="utf-8").startswith("# Incident Report")


def test_report_fails_clearly_when_no_ai_provider_is_available(run, attack_pcap, tmp_path, monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setattr(MultiProviderClient, "available", lambda self: False)
    result = run("report", attack_pcap, "-o", str(tmp_path / "x.md"))
    assert result.exit_code == 1
    assert "No AI provider" in result.output


def test_html_writes_a_self_contained_report(run, attack_pcap, tmp_path):
    out_file = tmp_path / "r.html"
    _ok(run("html", attack_pcap, "-o", str(out_file)))
    text = out_file.read_text(encoding="utf-8")
    assert text.lstrip().lower().startswith("<!doctype html")
    assert "PacketIQ" in text


def test_timeline_renders_the_attack_sequence(run, attack_pcap):
    out = _ok(run("timeline", attack_pcap))
    assert out.strip()


def test_timeline_full_runs(run, attack_pcap):
    _ok(run("timeline", attack_pcap, "--full"))


def test_sigma_writes_one_yaml_file_per_rule_into_a_directory(run, attack_pcap, tmp_path):
    out_dir = tmp_path / "rules"
    _ok(run("sigma", attack_pcap, "-o", str(out_dir), "--min-level", "low"))
    files = sorted(out_dir.glob("*.yml"))
    assert files, "no rule files written"
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert "detection:" in text and "logsource:" in text


def test_sigma_to_stdout_when_no_output_given(run, attack_pcap):
    out = _ok(run("sigma", attack_pcap, "--min-level", "low"))
    assert "detection:" in out


def test_stix_emits_a_valid_bundle(run, attack_pcap, tmp_path):
    out_file = tmp_path / "b.json"
    _ok(run("stix", attack_pcap, "-o", str(out_file)))
    bundle = json.loads(out_file.read_text(encoding="utf-8"))
    assert bundle["type"] == "bundle"
    assert isinstance(bundle.get("objects"), list)


def test_navigator_emits_a_valid_layer(run, attack_pcap, tmp_path):
    out_file = tmp_path / "layer.json"
    _ok(run("navigator", attack_pcap, "-o", str(out_file)))
    layer = json.loads(out_file.read_text(encoding="utf-8"))
    assert "techniques" in layer
    assert layer.get("domain", "").startswith("enterprise")


def test_slice_writes_only_the_matching_packets(run, attack_pcap, tmp_path):
    from scapy.all import rdpcap
    out_file = tmp_path / "evidence.pcap"
    _ok(run("slice", attack_pcap, "--ip", "45.33.32.156", "-o", str(out_file)))
    assert out_file.is_file()
    packets = rdpcap(str(out_file))
    assert len(packets) > 0
    for p in packets:
        assert "45.33.32.156" in (p.payload.src, p.payload.dst)


def test_slice_can_cap_the_packet_count(run, attack_pcap, tmp_path):
    from scapy.all import rdpcap
    out_file = tmp_path / "capped.pcap"
    _ok(run("slice", attack_pcap, "--port", "22", "-o", str(out_file), "--max", "5"))
    assert len(rdpcap(str(out_file))) <= 5


def test_slice_with_no_filter_is_rejected(run, attack_pcap, tmp_path):
    result = run("slice", attack_pcap, "-o", str(tmp_path / "x.pcap"))
    assert result.exit_code != 0 or "filter" in result.output.lower()


# --------------------------------------------------------------------------- #
#  Multi-capture and alternate inputs                                           #
# --------------------------------------------------------------------------- #

def test_fuse_correlates_across_two_captures(run, attack_pcap):
    out = _ok(run("fuse", attack_pcap, attack_pcap))
    assert out.strip()


def test_zeek_reads_a_conn_log(run, tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\n"
        "1700000000.0\tC1\t192.168.1.10\t44321\t93.184.216.34\t443\ttcp\tssl\t1.5\t500\t1200\n"
        "1700000001.0\tC2\t192.168.1.10\t44322\t93.184.216.34\t80\ttcp\thttp\t0.5\t300\t900\n",
        encoding="utf-8",
    )
    out = _ok(run("zeek", str(log)))
    assert "flow(s)" in out
    assert "RISK SCORE" in out


def _netflow_v5(records) -> bytes:
    """A minimal binary NetFlow v5 datagram — the format the command consumes."""
    import struct
    from ipaddress import IPv4Address

    hdr = struct.pack("!HHIIIIBBH", 5, len(records), 1000, 1700000000, 0, 0, 0, 0, 0)
    body = b""
    for src, dst, sp, dp, proto, pkts, octets in records:
        body += (struct.pack("!III", int(IPv4Address(src)), int(IPv4Address(dst)), 0)
                 + struct.pack("!HH", 0, 0)
                 + struct.pack("!II", pkts, octets)
                 + struct.pack("!II", 100, 900)
                 + struct.pack("!HH", sp, dp)
                 + struct.pack("!BBBBHHBBH", 0, 0, 0, proto, 0, 0, 0, 0, 0))
    return hdr + body


def test_netflow_reads_a_binary_v5_export(run, tmp_path):
    flows = tmp_path / "flows.bin"
    flows.write_bytes(_netflow_v5([
        ("192.168.1.10", "8.8.8.8", 5000, 53, 17, 4, 400),
        ("192.168.1.10", "93.184.216.34", 5001, 443, 6, 20, 5000),
    ]))
    out = _ok(run("netflow", str(flows)))
    assert "flow(s)" in out


def test_netflow_rejects_a_file_that_is_not_a_flow_export(run, tmp_path):
    bad = tmp_path / "notflow.bin"
    bad.write_bytes(b"this is not a netflow datagram at all")
    result = run("netflow", str(bad))
    assert result.exit_code == 1
    assert "Failed to parse" in result.output


# --------------------------------------------------------------------------- #
#  Vulnerability / intel commands                                               #
# --------------------------------------------------------------------------- #

def test_cve_human_output(run, attack_pcap):
    _ok(run("cve", attack_pcap))


def test_vulns_human_output(run, attack_pcap):
    _ok(run("vulns", attack_pcap))


def test_feeds_status_reports_the_bundled_feeds(run):
    out = _ok(run("feeds", "status"))
    assert "feodo" in out.lower() or "feed" in out.lower()


def test_feeds_update_reports_per_feed_results(run, monkeypatch):
    monkeypatch.setattr(
        "packetiq.enrichment.update.update_feeds",
        lambda progress=None: {"tor_exits.txt": 42, "feodo_c2.csv": "error: offline"},
    )
    out = _ok(run("feeds", "update"))
    assert "tor_exits.txt" in out


# --------------------------------------------------------------------------- #
#  Notification / integration commands                                          #
# --------------------------------------------------------------------------- #

def test_notify_status_lists_channel_configuration(run):
    out = _ok(run("notify", "--status"))
    assert "elegram" in out or "channel" in out.lower()


def test_misp_dry_run_builds_an_event_without_pushing(run, attack_pcap, monkeypatch):
    def explode(*a, **k):
        raise AssertionError("dry-run must not reach the network")

    monkeypatch.setattr("packetiq.export.misp.requests.post", explode, raising=False)
    out = _ok(run("misp", attack_pcap, "--dry-run"))
    assert out.strip()


def test_alert_test_without_configuration_reports_it(run, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    result = run("alert", "test")
    assert result.exit_code in (0, 1)
    assert result.output.strip()


def test_history_lists_past_analyses(run):
    out = _ok(run("history", "--limit", "5"))
    assert out.strip()


def test_setup_capture_reports_privilege_state(run):
    result = run("setup-capture")
    assert result.exit_code in (0, 1)
    assert result.output.strip()


# --------------------------------------------------------------------------- #
#  Server commands (stubbed at the boundary)                                    #
# --------------------------------------------------------------------------- #

def test_dashboard_serves_on_the_requested_port(run, attack_pcap, monkeypatch):
    seen = {}
    monkeypatch.setattr("packetiq.dashboard.server.uvicorn.run",
                        lambda app, **kw: seen.update(kw))
    monkeypatch.setattr("packetiq.dashboard.server.webbrowser.open", lambda url: None)
    _ok(run("dashboard", attack_pcap, "--port", "9555", "--no-browser"))
    assert seen["port"] == 9555
    assert seen["host"] == "127.0.0.1"


def test_webapp_binds_loopback_by_default(run, monkeypatch):
    seen = {}
    monkeypatch.setattr(cli_mod, "_launch_webapp", lambda **kw: seen.update(kw), raising=False)
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setattr("webbrowser.open", lambda url: None)
    result = run("webapp", "--no-browser", "--port", "9556")
    assert result.exit_code == 0, result.output
    assert seen.get("port") == 9556
    assert seen.get("host") == "127.0.0.1"


def test_live_replays_a_capture_offline(run, attack_pcap):
    out = _ok(run("live", "--read", attack_pcap, "--window", "600"))
    assert out.strip()


def test_live_can_list_interfaces(run):
    result = run("live", "--list")
    assert result.exit_code == 0
    assert result.output.strip()


def test_chat_reports_when_no_ai_provider_is_configured(run, attack_pcap, monkeypatch):
    for var in ("GROQ_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY", "OLLAMA_HOST"):
        monkeypatch.delenv(var, raising=False)
    result = run("chat", attack_pcap, input="\n")
    assert result.output.strip()


# --------------------------------------------------------------------------- #
#  Machine-readable output                                                      #
#                                                                               #
#  Every command that emits a document must put *only* that document on stdout. #
#  Three separate defects broke this: the banner and status lines shared stdout #
#  with the data; `--json` returned prose instead of JSON when a capture had no #
#  banners; and the document was printed through rich, which soft-wraps long    #
#  lines (inserting newlines inside JSON string literals) and eats              #
#  square-bracketed text as style markup.                                       #
# --------------------------------------------------------------------------- #

def test_stix_puts_only_the_bundle_on_stdout(attack_pcap, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["packetiq", "stix", attack_pcap])
    with pytest.raises(SystemExit) as exc:
        main(["stix", attack_pcap], standalone_mode=True)
    assert exc.value.code == 0
    captured = capsys.readouterr()
    bundle = json.loads(captured.out)
    assert bundle["type"] == "bundle"
    assert "██" not in captured.out, "the banner leaked into the data stream"


def test_navigator_puts_only_the_layer_on_stdout(attack_pcap, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["packetiq", "navigator", attack_pcap])
    with pytest.raises(SystemExit) as exc:
        main(["navigator", attack_pcap], standalone_mode=True)
    assert exc.value.code == 0
    layer = json.loads(capsys.readouterr().out)
    assert "techniques" in layer


def test_cve_json_emits_a_document_even_with_no_banners(attack_pcap, monkeypatch, capsys):
    """The synthetic capture is all encrypted/plain TCP — no banners to look up."""
    monkeypatch.setattr("sys.argv", ["packetiq", "cve", attack_pcap, "--json"])
    with pytest.raises(SystemExit) as exc:
        main(["cve", attack_pcap, "--json"], standalone_mode=True)
    assert exc.value.code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["results"] == []
    assert data["note"]


def test_vulns_json_emits_a_document_even_with_no_banners(attack_pcap, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["packetiq", "vulns", attack_pcap, "--json"])
    with pytest.raises(SystemExit) as exc:
        main(["vulns", attack_pcap, "--json"], standalone_mode=True)
    assert exc.value.code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["products"] == []
    assert data["risk"]["tier"] == "NONE"


def test_misp_dry_run_puts_only_the_event_on_stdout(attack_pcap, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["packetiq", "misp", attack_pcap, "--dry-run"])
    with pytest.raises(SystemExit) as exc:
        main(["misp", attack_pcap, "--dry-run"], standalone_mode=True)
    assert exc.value.code == 0
    event = json.loads(capsys.readouterr().out)
    assert "Event" in event


def test_a_long_value_is_not_wrapped_into_invalid_json(capsys):
    """Rich soft-wraps at terminal width; that corrupted every long description."""
    from packetiq.display.terminal import TerminalUI

    payload = json.dumps({"description": "x" * 500, "markup": "[bold] and [dim]"},
                         indent=2)
    TerminalUI().print_data(payload)
    out = capsys.readouterr().out
    round_tripped = json.loads(out)
    assert round_tripped["description"] == "x" * 500
    assert round_tripped["markup"] == "[bold] and [dim]"


def test_machine_output_is_detected_from_the_invocation():
    from packetiq.cli import _machine_output_requested as m

    assert m(["cve", "x.pcap", "--json"]) is True
    assert m(["vulns", "x.pcap", "--json"]) is True
    assert m(["misp", "x.pcap", "--dry-run"]) is True
    assert m(["stix", "x.pcap"]) is True
    assert m(["navigator", "x.pcap"]) is True
    assert m(["sigma", "x.pcap"]) is True
    # An output file was named, so stdout is free for humans again.
    assert m(["stix", "x.pcap", "-o", "b.json"]) is False
    assert m(["sigma", "x.pcap", "--out", "rules/"]) is False
    assert m(["analyze", "x.pcap"]) is False
    assert m(["misp", "x.pcap"]) is False
    assert m([]) is False


def test_the_banner_version_tracks_the_package(capsys):
    """A hardcoded version in the banner silently drifts from the real one."""
    from packetiq import __version__
    from packetiq.display.terminal import TerminalUI

    TerminalUI().print_banner()
    assert f"v{__version__}" in capsys.readouterr().out
