"""Web-app internals: serialisers, the graph builder, the grounding redactor,
env persistence, and the live-capture session.

These are module-level helpers rather than endpoints, so they are driven
directly. Several are the last line of defence against a bad analysis taking the
whole request down — a serialiser that raises would turn a completed analysis
into a 500 with the results already in memory.
"""


import pytest

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats
from packetiq.webapp import app as webapp

TS = 1700000000.0


def _event(etype=EventType.PORT_SCAN, severity=Severity.HIGH, src="45.33.32.156",
           dst="192.168.1.50", evidence=None, description="finding"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=445,
                          protocol="TCP", timestamp=TS, packet_count=10,
                          evidence=evidence or {})


# ── Host allow-list ──────────────────────────────────────────────────────────

def test_the_host_allow_list_always_includes_loopback(monkeypatch):
    monkeypatch.delenv("PACKETIQ_ALLOWED_HOSTS", raising=False)
    hosts = webapp._allowed_hosts()

    assert {"localhost", "127.0.0.1", "::1"} <= hosts


def test_extra_hosts_are_added_and_normalised(monkeypatch):
    """The launcher writes whatever the operator passed to --host; brackets and
    casing must not create an entry that never matches."""
    monkeypatch.setenv("PACKETIQ_ALLOWED_HOSTS", " [FD00::50] , Analyst.Local ,, ")
    hosts = webapp._allowed_hosts()

    assert "fd00::50" in hosts
    assert "analyst.local" in hosts
    assert "" not in hosts


# ── Upload streaming ─────────────────────────────────────────────────────────

class _FakeUpload:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, size):
        return self._chunks.pop(0) if self._chunks else b""


def test_an_upload_that_cannot_be_read_is_a_bad_request_and_leaves_no_file(tmp_path):
    """A dropped connection mid-upload must not leave a partial capture behind
    for the analyser to choke on later."""
    import asyncio

    from fastapi import HTTPException

    class Broken:
        async def read(self, size):
            raise ConnectionResetError("client went away")

    dest = tmp_path / "partial.pcap"
    dest.write_bytes(b"leftover")

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(webapp._stream_upload_to(Broken(), str(dest)))

    assert excinfo.value.status_code == 400
    assert "Could not read upload" in excinfo.value.detail
    assert not dest.exists()


def test_an_upload_over_the_cap_is_rejected_and_cleaned_up(tmp_path):
    import asyncio

    from fastapi import HTTPException

    dest = tmp_path / "big.pcap"
    upload = _FakeUpload([b"x" * (1 << 20)] * 3)

    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(webapp._stream_upload_to(upload, str(dest), max_mb=1))

    assert excinfo.value.status_code == 413
    assert not dest.exists()


def test_an_upload_within_the_cap_is_written_whole(tmp_path):
    import asyncio

    dest = tmp_path / "ok.pcap"
    written = asyncio.run(webapp._stream_upload_to(
        _FakeUpload([b"abc", b"def"]), str(dest), max_mb=1))

    assert written == 6
    assert dest.read_bytes() == b"abcdef"


# ── Serialisers ──────────────────────────────────────────────────────────────

def test_hashing_a_capture_that_cannot_be_read_yields_an_empty_digest(tmp_path):
    """The digest is provenance. Losing it must not lose the analysis."""
    assert webapp._sha256_file(str(tmp_path / "absent.pcap")) == ""


def test_a_capture_is_hashed(tmp_path):
    path = tmp_path / "x.bin"
    path.write_bytes(b"hello")
    import hashlib
    assert webapp._sha256_file(str(path)) == hashlib.sha256(b"hello").hexdigest()


def test_an_event_still_serialises_when_triage_cannot_explain_it(monkeypatch):
    """The explanation is enrichment; the finding itself must always reach the UI."""
    from packetiq import triage

    def boom(event):
        raise RuntimeError("explanation unavailable")

    monkeypatch.setattr(triage, "explain", boom)

    rec = webapp._ser_event(_event())
    assert rec["event_type"] == "PORT_SCAN"
    assert rec["src_ip"] == "45.33.32.156"


def test_a_broken_forecast_serialises_to_an_empty_list(monkeypatch):
    from packetiq import prediction

    def boom(result, events):
        raise RuntimeError("forecast unavailable")

    monkeypatch.setattr(prediction, "predict", boom)
    assert webapp._predictions_for(ExtractionResult(), []) == []


def test_a_broken_attack_coverage_serialises_to_an_empty_list(monkeypatch):
    import packetiq.export as export_pkg

    def boom(events):
        raise RuntimeError("coverage unavailable")

    monkeypatch.setattr(export_pkg, "attack_coverage", boom)
    assert webapp._attack_coverage([_event()]) == []


def test_the_intel_panel_reports_the_worst_severity_seen_per_feed():
    """Two hits from one feed at different severities must show the worse of the
    two — showing the first would understate the finding."""
    events = [
        _event(EventType.IOC_MATCH, severity=Severity.MEDIUM,
               evidence={"source": "Feodo Tracker", "indicator": "1.2.3.4",
                         "label": "Tor exit"}),
        _event(EventType.IOC_MATCH, severity=Severity.CRITICAL,
               evidence={"source": "Feodo Tracker", "indicator": "5.6.7.8",
                         "label": "Dridex C2"}),
    ]
    rows = webapp._threat_intel_matches(events)

    assert len(rows) == 1
    assert rows[0]["count"] == 2
    assert rows[0]["severity"] == "CRITICAL"


def test_findings_that_are_not_intel_hits_are_not_in_the_intel_panel():
    assert webapp._threat_intel_matches([_event(EventType.PORT_SCAN)]) == []


# ── Graphable hosts ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "0.0.0.0", "255.255.255.255", "::", "::1",
    "224.0.0.251", "239.255.255.250", "192.168.1.255", "ff02::fb", "",
])
def test_pseudo_hosts_are_not_graphable(ip):
    assert webapp._is_graphable_host(ip) is False


@pytest.mark.parametrize("ip", ["192.168.1.50", "185.199.108.153", "fd00::50"])
def test_real_endpoints_are_graphable(ip):
    assert webapp._is_graphable_host(ip) is True


def test_a_dotted_string_that_is_not_a_number_is_kept_rather_than_dropped():
    """Better to draw an odd node than to silently lose a host from the map."""
    assert webapp._is_graphable_host("10.0.0.x") is True


# ── Device labels in the graph ───────────────────────────────────────────────

def _graph(devices, flows=None, counts=None):
    r = ExtractionResult()
    r.ip_src_counts = counts or {"192.168.1.50": 100, "192.168.1.51": 80}
    r.ip_dst_counts = {}
    r.transmitted_ips = set(r.ip_src_counts)
    r.flows = flows or {}
    r.devices = devices
    return webapp._build_graph(r, [])


def test_an_address_less_host_is_labelled_by_how_it_was_seen():
    graph = _graph([{"id": "aa:bb:cc:dd:ee:02", "mac": "aa:bb:cc:dd:ee:02", "ips": [],
                     "kind": "host", "protocols": ["DHCP"], "packets": 6}])
    labels = [n["label"] for n in graph["nodes"]]

    assert any("(DHCP)" in lbl for lbl in labels)


def test_an_address_less_host_with_no_dhcp_is_labelled_as_having_no_ip():
    graph = _graph([{"id": "aa:bb:cc:dd:ee:03", "mac": "aa:bb:cc:dd:ee:03", "ips": [],
                     "kind": "host", "protocols": ["ARP"], "packets": 3}])
    labels = [n["label"] for n in graph["nodes"]]

    assert any("(no IP)" in lbl for lbl in labels)


def test_a_device_with_an_address_that_missed_the_node_budget_is_not_redrawn():
    """A device that holds an IP is an IP node or it is nothing.

    Only the busiest hosts get drawn, so a quiet machine with an address can fall
    outside that set. Redrawing it as a MAC-only node in the L2 segment would put
    the same machine on the map twice under two identities.
    """
    graph = _graph([{"id": "192.168.1.77", "mac": "aa:bb:cc:dd:ee:05",
                     "ips": ["192.168.1.77"], "kind": "host", "protocols": [],
                     "packets": 0}])

    assert not [n for n in graph["nodes"] if n["id"] == "192.168.1.77"]
    assert not [n for n in graph["nodes"] if n.get("mac") == "aa:bb:cc:dd:ee:05"]


def test_an_attacker_that_never_transmitted_is_not_drawn():
    """A scan can be attributed to an address that sent no frame of its own — a
    spoofed source, or one seen only inside someone else's payload.

    Drawing it would invent a host, so the event is dropped: no attacker node and
    no attack edge.
    """
    r = ExtractionResult()
    r.ip_src_counts = {"192.168.1.50": 100, "192.168.1.51": 80}
    r.ip_dst_counts = {}
    r.transmitted_ips = set(r.ip_src_counts)
    r.flows = {}
    r.devices = []

    graph = webapp._build_graph(r, [_event(src="203.0.113.9", dst="192.168.1.50")])

    assert not [n for n in graph["nodes"] if n["id"] == "203.0.113.9"]
    assert not [e for e in graph["edges"] if "203.0.113.9" in (e["source"], e["target"])]


def test_the_node_budget_keeps_the_flagged_hosts(monkeypatch):
    """The cap fills by priority, so a quiet attacker is never the one dropped."""
    r = ExtractionResult()
    r.ip_src_counts = {f"10.0.0.{i}": 1000 - i for i in range(1, 90)}
    r.ip_dst_counts = {}
    r.transmitted_ips = set(r.ip_src_counts) | {"45.33.32.156"}
    r.ip_src_counts["45.33.32.156"] = 1
    r.flows = {}
    r.devices = []

    graph = webapp._build_graph(r, [_event(src="45.33.32.156", dst="10.0.0.1")])

    assert len(graph["nodes"]) <= 60
    assert any(n["id"] == "45.33.32.156" for n in graph["nodes"])


def test_the_edge_budget_is_capped():
    """A dense capture would otherwise render an unreadable hairball."""
    r = ExtractionResult()
    r.ip_src_counts = {f"10.0.0.{i}": 100 for i in range(1, 40)}
    r.ip_dst_counts = {"10.0.0.99": 5000}
    r.transmitted_ips = set(r.ip_src_counts) | {"10.0.0.99"}
    r.devices = []
    r.flows = {
        (i, j): FlowStats(src_ip=f"10.0.0.{i}", dst_ip=f"10.0.0.{j}", src_port=51000,
                          dst_port=443, protocol="TCP", service="https",
                          bytes_total=1000 + i)
        for i in range(1, 20) for j in range(20, 39)
    }

    graph = webapp._build_graph(r, [])
    assert len(graph["edges"]) <= 90


# ── .env persistence ─────────────────────────────────────────────────────────

def test_a_new_key_is_appended_to_the_env_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("EXISTING=1\n# a comment\n", encoding="utf-8")

    webapp._env_upsert("GROQ_API_KEY", "abc123")

    body = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "GROQ_API_KEY=abc123" in body
    assert "EXISTING=1" in body
    assert "# a comment" in body


def test_an_existing_key_is_replaced_in_place(tmp_path, monkeypatch):
    """Appending a second line would leave the old key shadowing the new one."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "# keys\nGROQ_API_KEY=old\nOTHER=2\n", encoding="utf-8")

    webapp._env_upsert("GROQ_API_KEY", "new")

    body = (tmp_path / ".env").read_text(encoding="utf-8")
    assert body.count("GROQ_API_KEY=") == 1
    assert "GROQ_API_KEY=new" in body
    assert "OTHER=2" in body


def test_an_exported_key_is_also_replaced(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("export GROQ_API_KEY=old\n", encoding="utf-8")

    webapp._env_upsert("GROQ_API_KEY", "new")

    body = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "GROQ_API_KEY=new" in body
    assert "old" not in body


def test_writing_to_an_env_file_with_no_prior_file_creates_one(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    webapp._env_upsert("GEMINI_API_KEY", "k")

    assert (tmp_path / ".env").read_text(encoding="utf-8").strip() == "GEMINI_API_KEY=k"


# ── Ollama configuration ─────────────────────────────────────────────────────

def test_the_context_window_falls_back_when_the_override_is_not_a_number(monkeypatch):
    """A typo in OLLAMA_NUM_CTX must not crash every local-model request."""
    monkeypatch.setenv("OLLAMA_NUM_CTX", "very-large")
    assert webapp._ollama_num_ctx(1000, 512) > 0


def test_the_context_window_grows_with_the_prompt(monkeypatch):
    monkeypatch.setenv("OLLAMA_NUM_CTX", "32768")
    small = webapp._ollama_num_ctx(1000, 256)
    large = webapp._ollama_num_ctx(60000, 2048)

    assert large > small


def test_the_ollama_provider_key_carries_the_daemon_host():
    """Ollama has no API key; downstream code needs a truthy value to route on."""
    assert webapp._provider_key("ollama") == webapp._ollama_host()


def test_an_unknown_provider_has_no_key():
    assert webapp._provider_key("not-a-provider") is None


def test_a_retry_delay_that_is_not_a_number_falls_back_to_the_default():
    assert webapp._retry_after_seconds("retry in abcs") == 60.0


def test_a_provider_with_no_model_candidates_left_falls_back_to_its_default(monkeypatch):
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setattr(webapp, "_model_alive", lambda p, m: False)

    assert webapp._model_for("groq")


def test_an_unknown_provider_has_no_model(monkeypatch):
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    assert webapp._model_for("not-a-provider") == ""


# ── Grounding guard ──────────────────────────────────────────────────────────

def test_dotted_numbers_that_are_not_addresses_are_not_treated_as_ips():
    """The regex matches any four dotted numbers; only the ones that parse as a
    real address count, so an out-of-range quad is not treated as an IP the model
    invented — and not redacted as one."""
    assert webapp._gg_valid_ips("build 999.999.999.999 and 256.1.1.1") == set()
    assert webapp._gg_valid_ips("host 192.168.1.50 answered") == {"192.168.1.50"}


def test_the_streaming_redactor_flushes_a_long_line_at_a_word_boundary():
    """A model that writes a long paragraph with no newline would otherwise stall
    the stream — the UI would look frozen mid-answer."""
    redactor = webapp._GroundingFilter({"ips": set(), "domains": set(), "hashes": set(),
                                       "techniques": set(), "cves": set()})
    out = redactor.feed("word " * 60)

    assert out, "a long unterminated line must still emit text"
    assert not out.endswith("wor"), "the flush must land on a word boundary"


def test_the_streaming_redactor_emits_whole_lines_as_they_complete():
    redactor = webapp._GroundingFilter({"ips": {"192.168.1.50"}, "domains": set(),
                                       "hashes": set(), "techniques": set(),
                                       "cves": set()})
    assert redactor.feed("host 192.168.1.50 was scanned\n").strip()
    assert redactor.feed("no newline yet") == ""
    assert "no newline yet" in redactor.flush()


def test_an_address_the_capture_never_contained_is_removed():
    """This is the anti-hallucination guard: an IP the model invented is struck
    from the answer rather than shown to an analyst as evidence."""
    redactor = webapp._GroundingFilter({"ips": {"192.168.1.50"}, "domains": set(),
                                       "hashes": set(), "techniques": set(),
                                       "cves": set()})
    out = redactor.feed("Traffic went to 203.0.113.77 and 192.168.1.50.\n")

    assert "192.168.1.50" in out
    assert "203.0.113.77" not in out


# ── Verdict parsing ──────────────────────────────────────────────────────────

def test_a_verdict_the_model_phrased_freely_still_yields_a_short_badge():
    """The badge is a fixed-width UI element; an unrecognised verdict has to be
    truncated to something that fits rather than overflowing the card."""
    label, reason = webapp._split_verdict(
        "Almost certainly a scan from an automated tool. It probed 60 ports.")

    assert label and len(label) <= 40
    assert reason == ""


def test_a_known_verdict_is_split_from_its_justification():
    for label in webapp._VERDICTS:
        parsed, reason = webapp._split_verdict(f"{label}: it probed 60 ports")
        assert parsed.lower() == label
        assert "probed 60 ports" in reason
        break


# ── Provider failure wording ─────────────────────────────────────────────────

def test_the_all_exhausted_message_names_the_offline_option():
    out = webapp._friendly_ai_error("Gemini", "429 Too Many Requests", exhausted=True)

    assert "rate limits" in out
    assert "Ollama" in out


def test_a_rejected_key_message_mentions_the_shell_override():
    """An exported key silently beats .env — the single most common confusion."""
    out = webapp._friendly_ai_error("Groq", "401 invalid_api_key", exhausted=False)

    assert "rejected its API key" in out
    assert "shell" in out


def test_any_other_failure_is_reported_with_its_text():
    out = webapp._friendly_ai_error("Groq", "connection reset by peer", exhausted=False)
    assert "connection reset by peer" in out


# ── Live capture session ─────────────────────────────────────────────────────

def test_a_live_session_records_an_alert():
    session = webapp._LiveSession("lo0", "HIGH")
    session._on_alert(_event())

    assert len(session.alerts) == 1
    assert session.alerts[0]["event_type"] == "PORT_SCAN"


def test_a_live_session_that_cannot_open_its_pcap_still_captures(monkeypatch):
    """The recording is a convenience; losing it must not lose the live detection."""
    import scapy.all as scapy_all

    class NoWriter:
        def __init__(self, *a, **kw):
            raise OSError("read-only filesystem")

    class FakeSniffer:
        def __init__(self, *a, **kw):
            pass

        def start(self):
            pass

    monkeypatch.setattr(scapy_all, "PcapWriter", NoWriter)
    monkeypatch.setattr(scapy_all, "AsyncSniffer", FakeSniffer)

    session = webapp._LiveSession("lo0", "HIGH")
    session.start()

    assert session._writer is None
    assert session.sniffer is not None
