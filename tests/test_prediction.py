"""Tests for the grounded attack-prediction (threat-forecast) engine.

Predictions must be derived only from observed evidence and framed as *possible*
attacks — never fabricated. The forecast rests on two hard rules, and most of
these tests exist to hold those rules in place:

1. **Proven-open only.** A port that answers a SYN with RST is proven *closed*;
   a port that never answers is *filtered*. Neither is attack surface.
2. **Your network only.** Only a service running on a host inside the monitored
   network is your exposure. A client of ours browsing an external web server
   does not make that server our attack surface.

Violating either rule was the source of the real bug this suite pins down:
ordinary benign captures produced a page full of confident "possible attacks".
"""

from packetiq import prediction
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import DataExtractor, ExtractionResult
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.utils.helpers import monitored_network

MAC_CLIENT = "00:e0:4c:36:14:02"
MAC_SERVER = "00:e0:4c:68:01:74"
MAC_ROUTER = "00:1b:d4:c7:4b:89"

LOCAL_CLIENT = "192.168.1.200"
LOCAL_SERVER = "192.168.1.202"
EXTERNAL_WEB = "93.184.216.34"


def _analyse(path: str):
    """Run the real pipeline over a capture — no hand-built fixtures."""
    parser = PCAPParser(path)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    return extractor.finalize()


def _handshake(pkts, t, cmac, cip, smac, sip, sport, dport):
    """A completed TCP handshake — the proof that a service is listening."""
    from scapy.all import IP, TCP, Ether
    syn = (Ether(src=cmac, dst=smac) / IP(src=cip, dst=sip)
           / TCP(sport=sport, dport=dport, flags="S"))
    sak = (Ether(src=smac, dst=cmac) / IP(src=sip, dst=cip)
           / TCP(sport=dport, dport=sport, flags="SA"))
    ack = (Ether(src=cmac, dst=smac) / IP(src=cip, dst=sip)
           / TCP(sport=sport, dport=dport, flags="A"))
    for p in (syn, sak, ack):
        p.time = t
        t += 0.01
        pkts.append(p)
    return t


def _refused(pkts, t, cmac, cip, smac, sip, sport, dport):
    """A SYN answered with RST-ACK — positive proof the port is CLOSED."""
    from scapy.all import IP, TCP, Ether
    syn = (Ether(src=cmac, dst=smac) / IP(src=cip, dst=sip)
           / TCP(sport=sport, dport=dport, flags="S"))
    rst = (Ether(src=smac, dst=cmac) / IP(src=sip, dst=cip)
           / TCP(sport=dport, dport=sport, flags="RA"))
    for p in (syn, rst):
        p.time = t
        t += 0.01
        pkts.append(p)
    return t


# ── Exposure: only a proven-open service on one of our hosts is forecast ──────

def test_open_smb_on_local_host_predicts_lateral_movement(tmp_path):
    """SMB that completes a handshake on our own host IS attack surface."""
    from scapy.all import wrpcap
    pkts: list = []
    t = 1700000000.0
    for sport in range(40000, 40004):
        t = _handshake(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_SERVER, LOCAL_SERVER,
                       sport, 445)
    path = str(tmp_path / "smb.pcap")
    wrpcap(path, pkts)

    preds = prediction.predict(_analyse(path), [])
    smb = [p for p in preds if "SMB" in p.attack or "ransomware" in p.attack.lower()]
    assert smb, "an SMB service proven listening on our host must be forecast"
    assert any("T1210" in m for m in smb[0].mitre)
    assert any(LOCAL_SERVER in a for a in smb[0].affected)
    assert any("confirmed listening" in e for e in smb[0].evidence)


def test_closed_port_is_never_forecast(tmp_path):
    """The packets prove nothing is listening — forecasting an attack on it is
    the exact false positive this rule exists to prevent."""
    from scapy.all import wrpcap
    pkts: list = []
    t = 1700000000.0
    for sport, dport in ((40001, 445), (40002, 21), (40003, 3389), (40004, 1433)):
        t = _refused(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_SERVER, LOCAL_SERVER,
                     sport, dport)
    path = str(tmp_path / "closed.pcap")
    wrpcap(path, pkts)

    result = _analyse(path)
    assert all(v["state"] == "closed" for v in result.service_exposure.values())
    assert prediction.predict(result, []) == []


def test_external_server_we_browse_is_not_our_attack_surface(tmp_path):
    """Our client fetching an external website must not make that website's
    server our exposed HTTP attack surface."""
    from scapy.all import wrpcap
    pkts: list = []
    t = 1700000000.0
    for sport in range(50000, 50004):
        # Routed traffic: the external server's frames carry the ROUTER's MAC.
        t = _handshake(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_ROUTER, EXTERNAL_WEB,
                       sport, 80)
    path = str(tmp_path / "browse.pcap")
    wrpcap(path, pkts)

    result = _analyse(path)
    # The service is genuinely open — but it is not ours: it was reached through
    # the router, so it is outside the monitored network.
    assert result.service_exposure[(EXTERNAL_WEB, 80, "TCP")]["state"] == "open"
    scope = monitored_network(result)
    assert LOCAL_CLIENT in scope
    assert EXTERNAL_WEB not in scope
    assert prediction.predict(result, []) == [], (
        "an external web server we browsed is not our attack surface"
    )


def test_cleartext_open_service_flags_sniffing(tmp_path):
    from scapy.all import wrpcap
    pkts: list = []
    t = 1700000000.0
    for sport in range(40000, 40003):
        t = _handshake(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_SERVER, LOCAL_SERVER,
                       sport, 21)
    path = str(tmp_path / "ftp.pcap")
    wrpcap(path, pkts)

    preds = prediction.predict(_analyse(path), [])
    ftp = [p for p in preds if "FTP" in p.attack]
    assert ftp and any("cleartext" in e.lower() for e in ftp[0].evidence)


def test_predictions_sorted_and_grounded(tmp_path):
    from scapy.all import wrpcap
    pkts: list = []
    t = 1700000000.0
    for dport in (445, 3389, 80):
        for sport in range(40000, 40003):
            t = _handshake(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_SERVER,
                           LOCAL_SERVER, sport + dport, dport)
    path = str(tmp_path / "multi.pcap")
    wrpcap(path, pkts)

    preds = prediction.predict(_analyse(path), [])
    assert preds
    # sorted by (severity, likelihood) — first is at least as severe as last
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    assert order[preds[0].severity] <= order[preds[-1].severity]
    # every prediction cites at least one concrete piece of evidence
    assert all(p.evidence for p in preds)


def test_unmapped_service_is_ignored(tmp_path):
    """A service with no known threat mapping must not invent a prediction."""
    from scapy.all import wrpcap
    pkts: list = []
    t = 1700000000.0
    for sport in range(40000, 40003):
        t = _handshake(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_SERVER, LOCAL_SERVER,
                       sport, 12345)
    path = str(tmp_path / "odd.pcap")
    wrpcap(path, pkts)
    assert prediction.predict(_analyse(path), []) == []


def test_empty_capture_no_predictions():
    assert prediction.predict(ExtractionResult(), []) == []


# ── Behavioural trajectory: driven by, and quoting, real detections ───────────

def test_scan_event_predicts_targeted_exploitation():
    r = ExtractionResult()
    scan = DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.HIGH,
                          src_ip="10.0.0.9", description="Stealth SYN scan — 40 half-open",
                          dst_ip=LOCAL_SERVER)
    preds = prediction.predict(r, [scan])
    hit = [p for p in preds if "exploitation of discovered services" in p.attack.lower()]
    assert hit
    # It must quote the detection it follows from, not a canned phrase.
    assert any("Stealth SYN scan" in e for e in hit[0].evidence)
    # Nothing was open, and the forecast must say so rather than imply exposure.
    assert any("found nothing open" in e for e in hit[0].evidence)
    assert hit[0].likelihood == "Low"


def test_dos_event_predicts_outage():
    r = ExtractionResult()
    dos = DetectionEvent(event_type=EventType.DOS_FLOOD, severity=Severity.HIGH,
                         src_ip=LOCAL_CLIENT, dst_ip="4.207.44.64", dst_port=443,
                         description="SYN flood — 8,000 half-open connections")
    preds = prediction.predict(r, [dos])
    hit = [p for p in preds if "outage" in p.attack.lower() or "flood" in p.attack.lower()]
    assert hit
    assert any("SYN flood" in e for e in hit[0].evidence)


def test_benign_client_only_capture_predicts_nothing(tmp_path):
    """The reported bug, end to end: a capture of a client doing ordinary work
    (DNS lookups and an outbound web fetch) must forecast NO attacks at all."""
    from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether, wrpcap
    pkts: list = []
    t = 1700000000.0
    for i in range(6):
        q = (Ether(src=MAC_CLIENT, dst=MAC_ROUTER) / IP(src=LOCAL_CLIENT, dst="8.8.8.8")
             / UDP(sport=51000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname="example.com")))
        a = (Ether(src=MAC_ROUTER, dst=MAC_CLIENT) / IP(src="8.8.8.8", dst=LOCAL_CLIENT)
             / UDP(sport=53, dport=51000 + i)
             / DNS(qr=1, qd=DNSQR(qname="example.com"),
                   an=DNSRR(rrname="example.com", rdata=EXTERNAL_WEB)))
        for p in (q, a):
            p.time = t
            t += 0.01
            pkts.append(p)
    for sport in range(50000, 50003):
        t = _handshake(pkts, t, MAC_CLIENT, LOCAL_CLIENT, MAC_ROUTER, EXTERNAL_WEB,
                       sport, 443)
    path = str(tmp_path / "benign.pcap")
    wrpcap(path, pkts)

    assert prediction.predict(_analyse(path), []) == []
