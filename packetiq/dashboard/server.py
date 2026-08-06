"""
PacketIQ Interactive Dashboard — FastAPI web server.

Runs the full analysis pipeline on startup, then serves a 3D hacker-terminal
web dashboard at http://localhost:<port>/ with live JSON API endpoints.

Usage:
    from packetiq.dashboard.server import launch_dashboard
    launch_dashboard(pcap_path="capture.pcap", port=8080)
"""

import json
import threading
import webbrowser
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse

from packetiq.attribution.engine import AttributionEngine
from packetiq.correlation.engine import CorrelationEngine
from packetiq.detection.engine import DetectionEngine
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.sigma.generator import SigmaGenerator
from packetiq.timeline.builder import TimelineBuilder
from packetiq.utils.helpers import format_bytes, format_duration, ts_to_str

TEMPLATE_PATH = Path(__file__).parent / "templates" / "index.html"


def launch_dashboard(pcap_path: str, port: int = 8080, open_browser: bool = True):
    """Run analysis and serve the interactive web dashboard."""
    print(f"  [PacketIQ] Analysing {pcap_path}…")
    data = _run_and_serialize(pcap_path)

    app = _build_app(data)

    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(f"http://127.0.0.1:{port}/")).start()

    print(f"  [PacketIQ] Dashboard → http://127.0.0.1:{port}/  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


def _build_app(data: dict) -> FastAPI:
    app = FastAPI(title="PacketIQ Dashboard", docs_url=None, redoc_url=None)
    html_template = TEMPLATE_PATH.read_text(encoding="utf-8")

    @app.get("/", response_class=HTMLResponse)
    def index():
        # Inject serialized analysis data directly into the HTML
        injected = html_template.replace(
            "__PACKETIQ_DATA__",
            json.dumps(data, ensure_ascii=False),
        )
        return HTMLResponse(injected)

    @app.get("/api/data")
    def api_data():
        return JSONResponse(data)

    return app


def _run_and_serialize(pcap_path: str) -> dict:
    """Full pipeline → JSON-serialisable dict."""
    import os
    file_size = os.path.getsize(pcap_path)

    parser    = PCAPParser(pcap_path)
    extractor = DataExtractor()
    for record in parser.stream():
        extractor.feed(record)
    result = extractor.finalize()

    engine             = DetectionEngine()
    events, risk, fps  = engine.run(result, pcap_path)

    corr   = CorrelationEngine()
    chains = corr.correlate(events)

    tl_builder = TimelineBuilder()
    timeline   = tl_builder.build(result, events, chains)

    sigma_gen = SigmaGenerator()
    sigma_rules = sigma_gen.generate(events, chains)

    attr_engine  = AttributionEngine()
    attributions = attr_engine.attribute(events, chains)

    meta = DataExtractor.capture_metadata(result)
    dur  = max(0.0, result.capture_end - result.capture_start)

    return {
        "meta": {
            "pcap_file":      os.path.basename(pcap_path),
            "file_size":      format_bytes(file_size),
            "capture_start":  ts_to_str(result.capture_start),
            "capture_end":    ts_to_str(result.capture_end),
            "duration":       format_duration(dur),
            "total_packets":  result.total_packets,
            "total_bytes":    result.total_bytes,
            "unique_src_ips": len(result.unique_src_ips),
            "unique_dst_ips": len(result.unique_dst_ips),
            "unique_flows":   len(result.flows),
            "dns_queries":    len(result.dns_queries),
            "http_requests":  len(result.http_requests),
        },
        "risk": {
            "score":     risk.score,
            "tier":      risk.tier,
            "breakdown": risk.by_severity,
        },
        "protocols": result.protocol_counts,
        "top_ports": [
            {"port": p, "count": c}
            for p, c in sorted(result.dst_port_counts.items(), key=lambda x: -x[1])[:20]
        ],
        "top_src_ips": [
            {"ip": ip, "count": c}
            for ip, c in sorted(result.ip_src_counts.items(), key=lambda x: -x[1])[:15]
        ],
        "events": [_ser_event(e) for e in events],
        "chains": [_ser_chain(c) for c in chains],
        "timeline": [_ser_tl_event(e) for e in timeline.events],
        "activity_bar": {
            "buckets":     timeline.activity_bar.buckets if timeline.activity_bar else [],
            "bucket_secs": timeline.activity_bar.bucket_secs if timeline.activity_bar else 0,
            "total":       timeline.activity_bar.total_events if timeline.activity_bar else 0,
        },
        "phases_seen": timeline.phases_seen,
        "fingerprints": [_ser_fp(f) for f in fps],
        "sigma_rules": [{"title": r.title, "level": r.level, "yaml": r.raw_yaml} for r in sigma_rules],
        "attributions": [_ser_attr(a) for a in attributions],
    }


# ── Serializers ───────────────────────────────────────────────────────────────

def _ser_event(e) -> dict:
    return {
        "event_type":   e.event_type.value,
        "severity":     e.severity.value,
        "src_ip":       e.src_ip or "",
        "dst_ip":       e.dst_ip or "",
        "dst_port":     e.dst_port or 0,
        "protocol":     e.protocol or "",
        "timestamp":    e.timestamp,
        "ts_str":       ts_to_str(e.timestamp) if e.timestamp else "",
        "packet_count": e.packet_count,
        "confidence":   e.confidence,
        "description":  e.description,
        "evidence":     e.evidence,
    }


def _ser_chain(c) -> dict:
    return {
        "chain_id":       c.chain_id,
        "name":           c.name,
        "description":    c.description,
        "severity":       c.severity.value,
        "confidence":     c.confidence,
        "attacker_ips":   sorted(c.attacker_ips),
        "target_ips":     sorted(c.target_ips),
        "event_count":    len(c.events),
        "first_seen":     ts_to_str(c.first_seen) if c.first_seen else "",
        "last_seen":      ts_to_str(c.last_seen) if c.last_seen else "",
        "phases":         list(c.kill_chain_phases),
        "mitre":          [{"id": t.technique_id, "name": t.technique_name} for t in c.mitre_techniques],
    }


def _ser_tl_event(e) -> dict:
    return {
        "ts":          e.timestamp,
        "ts_str":      e.ts_str[11:23] if len(e.ts_str) > 11 else e.ts_str,
        "category":    e.category,
        "phase":       e.phase or "",
        "description": e.description,
        "src_ip":      e.src_ip or "",
        "dst_ip":      e.dst_ip or "",
        "severity":    e.severity.value if e.severity else "",
        "mitre_id":    e.mitre_id or "",
    }


def _ser_fp(f) -> dict:
    return {
        "src_ip":       f.src_ip,
        "os_guess":     f.os_guess,
        "observed_ttl": f.observed_ttl,
        "initial_ttl":  f.initial_ttl,
        "hops":         f.hops,
        "is_external":  f.is_external,
    }


def _ser_attr(a) -> dict:
    return {
        "name":           a.actor_name,
        "aliases":        a.aliases[:3],
        "origin":         a.origin,
        "motivation":     a.motivation,
        "confidence":     round(a.confidence * 100),   # TTP-overlap score, not attribution confidence
        "matched_ttps":   a.matched_ttps,
        "phases":         list(a.phases),
        "description":    a.description,
        "color":          a.color,
        "mitre_group":    a.mitre_group,
        "target_sectors": a.target_sectors,
        "disclaimer":     getattr(a, "disclaimer", ""),
    }
