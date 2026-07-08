"""Test the web network-graph data builder."""

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats
from packetiq.webapp.app import _build_graph


def test_build_graph_nodes_edges_and_flagging():
    r = ExtractionResult()
    r.ip_src_counts = {"192.168.1.50": 60, "45.33.32.156": 40}
    r.ip_dst_counts = {"45.33.32.156": 40, "192.168.1.50": 60}
    r.flows = {
        ("a", "b", "tcp"): FlowStats(src_ip="192.168.1.50", dst_ip="45.33.32.156",
                                     src_port=5000, dst_port=443, protocol="TCP",
                                     service="HTTPS", packets=40, bytes_total=40000,
                                     first_seen=1.0, last_seen=61.0),
    }
    events = [DetectionEvent(event_type=EventType.IOC_MATCH, severity=Severity.CRITICAL,
                             src_ip="192.168.1.50", dst_ip="45.33.32.156", description="C2",
                             evidence={"indicator": "45.33.32.156"})]
    g = _build_graph(r, events)
    ids = {n["id"] for n in g["nodes"]}
    assert {"192.168.1.50", "45.33.32.156"} <= ids
    assert any(n["id"] == "45.33.32.156" and n["flagged"] for n in g["nodes"])
    assert any(n["id"] == "192.168.1.50" and n["internal"] for n in g["nodes"])
    assert any(e["source"] == "192.168.1.50" and e["target"] == "45.33.32.156" for e in g["edges"])
