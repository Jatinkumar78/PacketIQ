"""Remaining web-app endpoints: AI report, packet explain, chat, MISP, Telegram setup.

These all sit behind a completed analysis and a working AI provider or outbound
credential, which is why they were uncovered. The AI and transport boundaries are
stubbed; the endpoint's own guards, wiring and response shapes run for real.
"""

import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

TS = 1700000000.0
UNKNOWN = "00000000-0000-0000-0000-000000000000"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture()
def with_ai(monkeypatch):
    """A configured provider whose answer is fixed and never leaves the process."""
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "ollama", "key": None,
                                           "model": "packetiq-net"})

    async def collect(system, context, messages, max_tokens=2048):
        return ("## Assessment\nA host on the monitored network was scanned "
                "from 45.33.32.156.\n\n## Recommended action\nBlock the source.")

    monkeypatch.setattr(webapp, "_collect_ai_with_fallback", collect)


@pytest.fixture()
def no_ai(monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": None, "key": None, "model": None})


def _pcap(tmp_path, name="bf.pcap"):
    pkts = []
    for i in range(40):
        p = (Ether() / IP(src="45.33.32.156", dst="192.168.1.50")
             / TCP(sport=40000 + i, dport=22, flags="S"))
        p.time = TS + i
        pkts.append(p)
    for i in range(6):
        p = (Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=33000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=f"{'f' * 60}.{i}.exfil.example.xyz")))
        p.time = TS + 100 + i
        pkts.append(p)
    path = tmp_path / name
    wrpcap(str(path), pkts)
    return path


def _analyze(client, path, name="bf.pcap"):
    with open(path, "rb") as f:
        r = client.post("/api/upload",
                        files={"file": (name, f, "application/octet-stream")})
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    for _ in range(120):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


# ── AI SOC report ────────────────────────────────────────────────────────────

def test_the_ai_report_is_returned_as_a_downloadable_markdown_file(client, tmp_path,
                                                                    with_ai):
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/report/{job}/ai")

    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "attachment" in r.headers["content-disposition"]
    assert "bf.pcap" in r.headers["content-disposition"]
    assert "Recommended action" in r.text


def test_the_ai_report_needs_a_completed_analysis(client, with_ai):
    r = client.post(f"/api/report/{UNKNOWN}/ai")
    assert r.status_code == 404


def test_the_ai_report_says_so_when_no_provider_is_configured(client, tmp_path, no_ai):
    """503 with setup guidance, not a 500 — the analysis itself is fine."""
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/report/{job}/ai")

    assert r.status_code == 503
    assert "GEMINI_API_KEY" in r.json()["detail"] or "Ollama" in r.json()["detail"]


def test_an_ai_failure_during_the_report_is_a_bad_gateway(client, tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "groq", "key": "k", "model": "m"})

    async def boom(system, context, messages, max_tokens=2048):
        raise RuntimeError("All configured AI providers have hit their rate limits.")

    monkeypatch.setattr(webapp, "_collect_ai_with_fallback", boom)

    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/report/{job}/ai")

    assert r.status_code == 502
    assert "rate limits" in r.json()["detail"]


# ── Packet explanation ───────────────────────────────────────────────────────

def test_a_packet_explanation_carries_the_model_text_and_the_hard_facts(client, tmp_path,
                                                                        with_ai):
    """`facts` comes straight from the packet and never from the model — it is
    the evidence panel a reader checks the narrative against."""
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/packets/{job}/0/explain")

    assert r.status_code == 200
    body = r.json()
    assert "Assessment" in body["explanation"]
    assert body["sections"]
    assert body["facts"]["src"] == "45.33.32.156"
    assert body["summary"]["proto"]


def test_explaining_a_packet_that_does_not_exist_is_a_not_found(client, tmp_path, with_ai):
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/packets/{job}/99999/explain")

    assert r.status_code == 404
    assert "Packet not found" in r.json()["detail"]


def test_explaining_a_packet_without_a_provider_says_so(client, tmp_path, no_ai):
    job = _analyze(client, _pcap(tmp_path))
    assert client.post(f"/api/packets/{job}/0/explain").status_code == 503


def test_an_ai_failure_during_a_packet_explanation_is_a_bad_gateway(client, tmp_path,
                                                                    monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "groq", "key": "k", "model": "m"})

    async def boom(system, context, messages, max_tokens=2048):
        raise RuntimeError("AI request failed: connection reset")

    monkeypatch.setattr(webapp, "_collect_ai_with_fallback", boom)

    job = _analyze(client, _pcap(tmp_path))
    assert client.post(f"/api/packets/{job}/0/explain").status_code == 502


# ── Chat ─────────────────────────────────────────────────────────────────────

def test_chat_status_reports_the_active_provider(client, tmp_path, with_ai):
    job = _analyze(client, _pcap(tmp_path))
    body = client.get(f"/api/chat/{job}/status").json()

    assert body["available"] is True
    assert body["provider"] == "ollama"
    assert body["model"] == "packetiq-net"


def test_chat_status_reports_when_no_provider_is_configured(client, tmp_path, no_ai):
    job = _analyze(client, _pcap(tmp_path))
    body = client.get(f"/api/chat/{job}/status").json()

    assert body["available"] is False
    assert body["provider"] is None


def test_chat_status_needs_a_completed_analysis(client, with_ai):
    assert client.get(f"/api/chat/{UNKNOWN}/status").status_code == 404


def test_chat_requires_a_non_empty_message(client, tmp_path, with_ai):
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/chat/{job}", json={"message": "   "})

    assert r.status_code == 400
    assert "message is required" in r.json()["detail"]


def test_chat_without_a_provider_says_so(client, tmp_path, no_ai):
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/chat/{job}", json={"message": "what happened?"})

    assert r.status_code == 503


def test_chat_streams_the_answer_back(client, tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "ollama", "key": None,
                                           "model": "packetiq-net"})

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        for chunk in ("The host ", "was scanned."):
            yield chunk

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/chat/{job}", json={"message": "what happened?"})

    assert r.status_code == 200
    assert "was scanned" in r.text


def test_chat_carries_the_prior_turns_into_the_request(client, tmp_path, monkeypatch):
    """A follow-up question is meaningless without the turns before it."""
    captured = {}
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "ollama", "key": None, "model": "m"})

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        captured["messages"] = messages
        yield "ok"

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    job = _analyze(client, _pcap(tmp_path))
    client.post(f"/api/chat/{job}", json={
        "message": "and the second host?",
        "history": [{"role": "user", "content": "which host was scanned?"},
                    {"role": "assistant", "content": "192.168.1.50"}]})

    assert [m["role"] for m in captured["messages"]] == ["user", "assistant", "user"]
    assert captured["messages"][-1]["content"] == "and the second host?"


# ── MISP push ────────────────────────────────────────────────────────────────

def test_pushing_to_misp_requires_a_url_and_a_key(client, tmp_path):
    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/misp/{job}", json={"url": "", "key": ""})

    assert r.status_code == 400
    assert "url and key are required" in r.json()["detail"]


def test_a_successful_misp_push_reports_the_indicator_count(client, tmp_path, monkeypatch):
    from packetiq.export import misp as misp_mod

    monkeypatch.setattr(misp_mod, "push_to_misp",
                        lambda event, url=None, key=None, verify_tls=True:
                        (True, "Created MISP event id=4211"))

    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/misp/{job}",
                    json={"url": "https://misp.local", "key": "k"})

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "4211" in body["message"]
    assert body["indicator_count"] >= 1


def test_a_rejected_misp_push_is_a_bad_gateway(client, tmp_path, monkeypatch):
    from packetiq.export import misp as misp_mod

    monkeypatch.setattr(misp_mod, "push_to_misp",
                        lambda event, url=None, key=None, verify_tls=True:
                        (False, "HTTP 403: Authentication failed"))

    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/misp/{job}",
                    json={"url": "https://misp.local", "key": "bad"})

    assert r.status_code == 502
    assert "403" in r.json()["detail"]


def test_a_capture_with_no_indicators_is_not_pushed(client, tmp_path, monkeypatch):
    from packetiq.export import misp as misp_mod

    monkeypatch.setattr(misp_mod, "push_to_misp",
                        lambda *a, **kw: pytest.fail("must not reach the network"))

    quiet = []
    for i in range(10):
        p = (Ether() / IP(src="192.168.1.50", dst="192.168.1.60")
             / TCP(sport=51000 + i, dport=443))
        p.time = TS + i
        quiet.append(p)
    path = tmp_path / "quiet.pcap"
    wrpcap(str(path), quiet)

    job = _analyze(client, path, "quiet.pcap")
    r = client.post(f"/api/misp/{job}", json={"url": "https://misp.local", "key": "k"})

    assert r.status_code == 400
    assert "No indicators to push" in r.json()["detail"]


# ── SIGMA download ───────────────────────────────────────────────────────────

def test_sigma_rules_download_as_a_zip_of_yaml_files(client, tmp_path):
    job = _analyze(client, _pcap(tmp_path))
    r = client.get(f"/api/sigma/{job}/rules.zip")

    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"

    import io as _io
    with zipfile.ZipFile(_io.BytesIO(r.content)) as zf:
        names = zf.namelist()
        assert names and all(n.endswith(".yml") for n in names)
        assert "title:" in zf.read(names[0]).decode("utf-8")


def test_a_capture_with_no_rules_reports_that_rather_than_an_empty_zip(client, tmp_path):
    job = _analyze(client, _pcap(tmp_path))
    webapp._jobs[job]["result"]["sigma_rules"] = []

    r = client.get(f"/api/sigma/{job}/rules.zip")
    assert r.status_code == 404
    assert "No SIGMA rules" in r.json()["detail"]


def test_sigma_download_needs_a_completed_analysis(client):
    assert client.get(f"/api/sigma/{UNKNOWN}/rules.zip").status_code == 404


# ── Feed refresh ─────────────────────────────────────────────────────────────

def test_refreshing_the_feeds_reports_per_feed_results(client, monkeypatch):
    """The GUI shows a row per feed; a raised exception has to become a string,
    not a 500."""
    from packetiq.enrichment import update as update_mod

    monkeypatch.setattr(update_mod, "update_feeds", lambda progress=None: {
        "Feodo Tracker": 1200,
        "ThreatFox": 45000,
        "Spamhaus DROP": OSError("network unreachable"),
    })

    r = client.post("/api/feeds/update")
    assert r.status_code == 200

    body = r.json()
    assert body["updated"] == 2 and body["total"] == 3
    assert body["results"]["Feodo Tracker"] == 1200
    assert "network unreachable" in body["results"]["Spamhaus DROP"]


# ── Telegram guided setup ────────────────────────────────────────────────────

def test_detecting_chats_needs_a_bot_token_first(client, monkeypatch):
    from packetiq.alerts import telegram

    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))

    r = client.post("/api/notify/telegram/detect", json={"token": ""})
    assert r.status_code == 400
    assert "BotFather" in r.json()["detail"]


def test_detecting_chats_returns_what_the_bot_has_seen(client, monkeypatch):
    from packetiq.alerts import telegram

    monkeypatch.setattr(telegram, "detect_chat_ids",
                        lambda token: (True, [{"id": "-1001234567890", "name": "SOC"}]))

    r = client.post("/api/notify/telegram/detect",
                    json={"token": "123456789:" + "A" * 25})

    assert r.status_code == 200
    assert r.json()["chats"][0]["name"] == "SOC"


def test_detecting_chats_before_the_bot_has_any_explains_the_next_step(client, monkeypatch):
    from packetiq.alerts import telegram

    monkeypatch.setattr(telegram, "detect_chat_ids", lambda token: (True, []))

    r = client.post("/api/notify/telegram/detect",
                    json={"token": "123456789:" + "A" * 25})

    assert r.status_code == 404
    assert "send your bot any" in r.json()["detail"]


def test_a_detect_failure_is_surfaced(client, monkeypatch):
    from packetiq.alerts import telegram

    monkeypatch.setattr(telegram, "detect_chat_ids",
                        lambda token: (False, "Invalid bot token"))

    r = client.post("/api/notify/telegram/detect",
                    json={"token": "123456789:" + "A" * 25})

    assert r.status_code == 400
    assert "Invalid bot token" in r.json()["detail"]


@pytest.mark.parametrize("payload,fragment", [
    ({"token": "nonsense", "chat_id": "123"}, "BotFather"),
    ({"token": "123456789:" + "A" * 25, "chat_id": "not-a-chat"}, "chat ID"),
])
def test_saving_telegram_credentials_validates_both_fields(client, monkeypatch,
                                                            payload, fragment):
    from packetiq.alerts import telegram

    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))

    r = client.post("/api/notify/telegram", json=payload)
    assert r.status_code == 400
    assert fragment in r.json()["detail"]


def test_saving_telegram_credentials_masks_the_token_in_the_response(client, monkeypatch,
                                                                     tmp_path):
    """The response goes back to a browser; echoing the whole bot token there
    would put it in the page and in any screenshot of it."""
    from packetiq.alerts import telegram

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))
    monkeypatch.setattr(telegram.TelegramSender, "test_connection",
                        lambda self: (True, "Connected as @packetiq_bot"))

    token = "123456789:" + "A" * 21 + "WXYZ"
    r = client.post("/api/notify/telegram",
                    json={"token": token, "chat_id": "-1001234567890"})

    assert r.status_code == 200
    body = r.json()
    assert body["configured"] is True
    assert body["token_hint"] == "…WXYZ"
    assert token not in json.dumps(body)
    assert body["tested"] is True


def test_saving_telegram_credentials_can_skip_the_test_message(client, monkeypatch,
                                                                tmp_path):
    from packetiq.alerts import telegram

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))
    monkeypatch.setattr(telegram.TelegramSender, "test_connection",
                        lambda self: pytest.fail("must not send a test message"))

    r = client.post("/api/notify/telegram",
                    json={"token": "123456789:" + "A" * 25, "chat_id": "123456789",
                          "test": False, "persist": False})

    assert r.status_code == 200
    assert "tested" not in r.json()


def test_clearing_telegram_credentials_removes_them(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:" + "A" * 25)
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "-100123")

    r = client.request("DELETE", "/api/notify/telegram")

    assert r.status_code == 200
    assert r.json()["configured"] is False
    import os
    assert "TELEGRAM_BOT_TOKEN" not in os.environ


# ── Live capture setup ───────────────────────────────────────────────────────

def test_the_capture_setup_endpoint_reports_a_failure_without_crashing(client,
                                                                       monkeypatch):
    from packetiq import capture_setup

    def boom():
        raise RuntimeError("osascript cancelled by the user")

    monkeypatch.setattr(capture_setup, "setup", boom)

    r = client.post("/api/live/setup-capture")
    assert r.status_code in (200, 400, 500)
    assert "Traceback" not in r.text


def test_the_capture_setup_endpoint_reports_success(client, monkeypatch):
    from packetiq import capture_setup

    monkeypatch.setattr(capture_setup, "setup",
                        lambda: (True, "Granted capture access to /dev/bpf*."))

    r = client.post("/api/live/setup-capture")
    assert r.status_code == 200
    assert "Granted capture access" in r.text


def test_the_interface_list_degrades_to_scapy_when_the_rich_helper_fails(client,
                                                                         monkeypatch):
    """Losing the friendly names must not lose the ability to pick an interface."""
    from packetiq import net_interfaces

    def boom():
        raise RuntimeError("enumeration failed")

    monkeypatch.setattr(net_interfaces, "list_interfaces", boom)

    r = client.get("/api/live/interfaces")
    assert r.status_code == 200
    body = r.json()
    assert body["details"] == []
    assert isinstance(body["interfaces"], list)
