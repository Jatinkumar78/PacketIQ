"""Tests for MISP event building and push (HTTP mocked)."""

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.export import misp


def _events():
    return [
        DetectionEvent(event_type=EventType.IOC_MATCH, severity=Severity.CRITICAL,
                       src_ip="10.0.0.5", dst_ip="45.33.32.156", description="known C2",
                       evidence={"indicator": "45.33.32.156", "source": "Feodo", "label": "QakBot C2"}),
        DetectionEvent(event_type=EventType.DNS_TUNNELING, severity=Severity.HIGH,
                       src_ip="10.0.0.5", description="dns tunnel",
                       evidence={"domain": "evil.example.xyz"}),
        DetectionEvent(event_type=EventType.MALICIOUS_FILE, severity=Severity.CRITICAL,
                       src_ip="10.0.0.5", dst_ip="45.33.32.156", description="malware dl",
                       evidence={"sha256": "a" * 64}),
    ]


def test_to_misp_event_builds_attributes():
    event = misp.to_misp_event(_events())
    attrs = event["Event"]["Attribute"]
    types = {a["type"] for a in attrs}
    values = {a["value"] for a in attrs}
    assert "ip-dst" in types
    assert "domain" in types
    assert "sha256" in types
    assert "45.33.32.156" in values
    assert "evil.example.xyz" in values
    assert "a" * 64 in values
    for a in attrs:
        assert a["to_ids"] is True
        assert a["category"] in ("Network activity", "Payload delivery")


def test_push_requires_credentials():
    ok, msg = misp.push_to_misp(misp.to_misp_event(_events()), url=None, key=None)
    assert not ok and "required" in msg.lower()


def test_push_success_mocked(monkeypatch):
    class _Resp:
        status_code = 201
        def json(self):
            return {"Event": {"id": "42"}}

    captured = {}

    def _fake_post(url, headers=None, json=None, timeout=None, verify=None):
        captured["url"] = url
        captured["auth"] = headers.get("Authorization")
        captured["attrs"] = len(json["Event"]["Attribute"])
        return _Resp()

    monkeypatch.setattr(misp.requests, "post", _fake_post)
    ok, msg = misp.push_to_misp(misp.to_misp_event(_events()),
                                url="https://misp.local/", key="SECRET")
    assert ok and "id=42" in msg
    assert captured["url"] == "https://misp.local/events"
    assert captured["auth"] == "SECRET"
    assert captured["attrs"] >= 3


def test_push_empty_no_indicators():
    from packetiq.export.misp import push_to_misp, to_misp_event
    ok, msg = push_to_misp(to_misp_event([]), url="https://x", key="k")
    assert not ok and "no indicators" in msg.lower()
