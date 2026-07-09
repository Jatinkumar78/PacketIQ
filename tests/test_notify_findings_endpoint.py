"""End-to-end: the 'Send report + PDF' endpoint must build the professional
findings message AND a real PDF, and hand both to Telegram — verified with a
stubbed sender (no network), the PDF rendered for real by ReportLab.
"""

import time

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetiq.webapp import create_app

_SENT = {"messages": [], "documents": []}


class _StubSender:
    def __init__(self, token, chat_id, timeout=15):
        self.token, self.chat_id = token, chat_id

    def send(self, text, disable_preview=True):
        _SENT["messages"].append(text)
        return True, ""

    def send_document(self, filepath, caption=""):
        with open(filepath, "rb") as f:
            head = f.read(5)
        _SENT["documents"].append({"path": filepath, "caption": caption, "head": head})
        return True, ""


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "nf.db"))
    # Configure Telegram via env and neutralise the real sender (no network).
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123456789:AAděfGhIjKlMnOpQrStUvWxYz012345678")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "987654321")
    import packetiq.alerts.telegram as tg
    monkeypatch.setattr(tg, "TelegramSender", _StubSender)
    _SENT["messages"].clear(); _SENT["documents"].clear()
    with TestClient(create_app()) as c:
        yield c


def _scan_pcap(tmp_path):
    pkts = []
    for i in range(40):
        p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = 1700000000.0 + i
        pkts.append(p)
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), pkts)
    return path


def _analyze(client, path):
    with open(path, "rb") as f:
        job = client.post("/api/upload",
                          files={"file": ("scan.pcap", f, "application/octet-stream")}).json()["job_id"]
    for _ in range(80):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


def test_send_findings_delivers_message_and_pdf(client, tmp_path):
    job = _analyze(client, _scan_pcap(tmp_path))
    r = client.post(f"/api/notify/{job}/send")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"].get("telegram") is True
    assert body["results"].get("telegram_pdf") is True

    # A professional brief was sent…
    assert _SENT["messages"], "no Telegram message was sent"
    msg = _SENT["messages"][0]
    assert "PacketIQ Security Report" in msg
    assert "PDF" in msg

    # …and a real PDF was attached.
    assert _SENT["documents"], "no PDF document was attached"
    doc = _SENT["documents"][0]
    assert doc["head"] == b"%PDF-"
    assert doc["path"].endswith(".pdf")
    assert "PacketIQ SOC Report" in doc["caption"]
