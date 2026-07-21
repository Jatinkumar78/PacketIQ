"""Tests for the grounded attack-prediction (threat-forecast) engine.

Predictions must be derived only from observed evidence and framed as *possible*
attacks — never fabricated. These fixtures exercise the service-exposure and
behavioural-trajectory paths.
"""

from packetiq import prediction
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats


def _flow(dst_ip, dport, service, responded=True, proto="TCP"):
    return FlowStats(src_ip="192.168.1.202", dst_ip=dst_ip, src_port=50000, dst_port=dport,
                     protocol=proto, service=service, packets=6, bytes_total=600,
                     first_seen=1.0, last_seen=2.0,
                     tcp_flags_seen=({"SYN", "SYNACK", "ACK"} if responded else {"SYN"}))


def _result(*flows):
    r = ExtractionResult()
    r.flows = {(str(i),): f for i, f in enumerate(flows)}
    return r


def test_smb_exposure_predicts_lateral_movement():
    r = _result(_flow("192.168.1.100", 445, "SMB"))
    preds = prediction.predict(r, [])
    smb = [p for p in preds if "SMB" in p.attack or "ransomware" in p.attack.lower()]
    assert smb, "exposed SMB must forecast lateral movement / ransomware"
    assert any("T1210" in m for m in smb[0].mitre)
    assert smb[0].affected  # names the host:port
    assert smb[0].evidence


def test_cleartext_ftp_flags_sniffing():
    r = _result(_flow("192.168.1.100", 21, "FTP"))
    preds = prediction.predict(r, [])
    ftp = [p for p in preds if "FTP" in p.attack]
    assert ftp and any("cleartext" in e.lower() for e in ftp[0].evidence)


def test_scan_event_predicts_targeted_exploitation():
    r = _result(_flow("192.168.1.100", 80, "HTTP"))
    scan = DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.HIGH,
                          src_ip="10.0.0.9", description="scan", dst_ip="192.168.1.100")
    preds = prediction.predict(r, [scan])
    assert any("exploitation of discovered services" in p.attack.lower() for p in preds)


def test_dos_event_predicts_outage():
    r = ExtractionResult()
    dos = DetectionEvent(event_type=EventType.DOS_FLOOD, severity=Severity.HIGH,
                         src_ip="192.168.1.202", dst_ip="4.207.44.64", dst_port=443,
                         description="syn flood")
    preds = prediction.predict(r, [dos])
    assert any("outage" in p.attack.lower() or "flood" in p.attack.lower() for p in preds)


def test_predictions_sorted_and_grounded():
    r = _result(_flow("192.168.1.100", 445, "SMB"), _flow("192.168.1.100", 3389, "RDP"),
                _flow("192.168.1.100", 80, "HTTP"))
    preds = prediction.predict(r, [])
    assert preds
    # sorted by (severity, likelihood) — first is at least as severe as last
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    assert order[preds[0].severity] <= order[preds[-1].severity]
    # every prediction cites at least one concrete piece of evidence
    assert all(p.evidence for p in preds)


def test_empty_capture_no_predictions():
    assert prediction.predict(ExtractionResult(), []) == []


def test_unmapped_service_is_ignored():
    """A service with no known threat mapping must not invent a prediction."""
    r = _result(_flow("192.168.1.100", 12345, "12345"))
    assert prediction.predict(r, []) == []
