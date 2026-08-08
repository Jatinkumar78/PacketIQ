"""The detection engine must survive a detector that cannot start.

Three optional subsystems are constructed inside try/except: TLS certificate
analysis (needs `cryptography`), file carving (needs the reputation feed), and
triage suppression. If any of them raises during setup the engine is supposed to
carry on without it — losing one detector, not the whole analysis. That
behaviour had never been tested, so a regression there would have surfaced as a
crashed run on a user's machine and a clean run on ours.
"""


from packetiq.detection import file_carver, tls_inspect
from packetiq.detection.engine import DetectionEngine
from packetiq.detection.models import EventType


def _boom(*args, **kwargs):
    raise RuntimeError("subsystem unavailable")


def _run(pipeline_pcap):
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser

    parser = PCAPParser(pipeline_pcap)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    return DetectionEngine().run(extractor.finalize(), pipeline_pcap)


def test_the_run_completes_when_tls_inspection_cannot_start(monkeypatch, attack_pcap):
    """`make_accumulator` raising is what a broken cryptography install looks like."""
    monkeypatch.setattr(tls_inspect, "make_accumulator", _boom)

    events, risk, fingerprints = _run(attack_pcap)

    assert events, "the other detectors must still report"
    assert risk.tier == "CRITICAL"


def test_the_run_completes_when_the_file_carver_cannot_start(monkeypatch, attack_pcap):
    monkeypatch.setattr(file_carver, "FileCarverAccumulator", _boom)

    events, risk, _ = _run(attack_pcap)

    assert EventType.BRUTE_FORCE in {e.event_type for e in events}


def test_the_run_completes_when_triage_fails(monkeypatch, attack_pcap):
    """Suppression is a filter over findings. If it breaks, report everything
    rather than nothing — a failed filter must never look like a clean capture."""
    from packetiq import triage
    monkeypatch.setattr(triage, "apply_suppression", _boom)

    engine = DetectionEngine()
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser

    parser = PCAPParser(attack_pcap)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    events, risk, _ = engine.run(extractor.finalize(), attack_pcap)

    assert events, "findings must survive a triage failure"
    assert engine.suppressed == [], "nothing can be claimed as suppressed"


def test_all_three_failing_at_once_still_produces_a_verdict(monkeypatch, attack_pcap):
    from packetiq import triage
    monkeypatch.setattr(tls_inspect, "make_accumulator", _boom)
    monkeypatch.setattr(file_carver, "FileCarverAccumulator", _boom)
    monkeypatch.setattr(triage, "apply_suppression", _boom)

    events, risk, _ = _run(attack_pcap)

    assert events
    assert 0 <= risk.score <= 100


def test_progress_callbacks_name_every_stage(attack_pcap):
    """The CLI and web UI both drive their progress bars off these names."""
    seen: list = []
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser

    parser = PCAPParser(attack_pcap)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    DetectionEngine().run(extractor.finalize(), attack_pcap,
                          progress_callback=seen.append)

    assert {"brute_force", "port_scan", "tls_inspection",
            "file_carving", "triage"} <= set(seen)
