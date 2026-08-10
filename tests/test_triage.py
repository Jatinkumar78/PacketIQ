"""Tests for the triage layer (explainability + precision + FP suppression)."""


from packetiq import config, triage
from packetiq.detection.models import DetectionEvent, EventType, Severity


def _ev(et, sev=Severity.HIGH, conf=0.8, src="10.0.0.9", dst="10.0.0.1", **ev):
    return DetectionEvent(et, sev, src, "test", dst_ip=dst, confidence=conf, evidence=ev)


def test_precision_grades():
    # evidence-backed types are Confirmed regardless of confidence
    assert triage.precision(_ev(EventType.IOC_MATCH, conf=0.5)) == "Confirmed"
    assert triage.precision(_ev(EventType.MALICIOUS_FILE, conf=0.1)) == "Confirmed"
    # heuristic types graded by confidence
    assert triage.precision(_ev(EventType.PORT_SCAN, conf=0.9)) == "High"
    assert triage.precision(_ev(EventType.PORT_SCAN, conf=0.7)) == "Probable"
    assert triage.precision(_ev(EventType.PORT_SCAN, conf=0.3)) == "Tentative"


def test_explain_is_grounded_and_complete():
    e = _ev(EventType.BRUTE_FORCE, indicator="1.2.3.4", attempts=50)
    x = triage.explain(e)
    assert x["what"] and x["why"] and x["recommendation"]
    assert x["precision"] in {"Confirmed", "High", "Probable", "Tentative"}
    assert any("Attempts" in p for p in x["evidence_points"])
    assert x["mitre"] and x["mitre"][0]["id"].startswith("T")
    assert x["kill_chain_phase"]


def test_default_suppression_is_noop():
    config.reload()
    evs = [_ev(EventType.PORT_SCAN, conf=0.3), _ev(EventType.IOC_MATCH, conf=1.0)]
    kept, supp = triage.apply_suppression(evs)
    assert len(kept) == 2 and supp == []   # defaults must never drop findings


def test_confidence_floor_suppresses():
    evs = [_ev(EventType.PORT_SCAN, conf=0.3), _ev(EventType.PORT_SCAN, conf=0.9)]
    kept, supp = triage.apply_suppression(evs, min_confidence=0.5)
    assert len(kept) == 1 and len(supp) == 1
    assert "confidence floor" in supp[0][1]


def test_allowlist_suppression(tmp_path, monkeypatch):
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text(
        "[allowlist]\n"
        'ips = ["203.0.113.7"]\n'
        'cidrs = ["198.51.100.0/24"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        al = triage.load_allowlist()
        assert bool(al)
        # exact IP allow-listed
        hit, reason = triage.is_allowlisted(_ev(EventType.IOC_MATCH, dst="203.0.113.7"), al)
        assert hit and "203.0.113.7" in reason
        # CIDR allow-listed
        hit2, _ = triage.is_allowlisted(_ev(EventType.PORT_SCAN, dst="198.51.100.50"), al)
        assert hit2
        # unrelated IP not suppressed
        hit3, _ = triage.is_allowlisted(_ev(EventType.PORT_SCAN, dst="8.8.8.8"), al)
        assert not hit3
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()
