"""
PacketIQ Web Application — FastAPI backend.

Provides:
  POST /api/upload          — upload a PCAP file, returns job_id
  WS   /ws/{job_id}         — real-time analysis progress stream
  GET  /api/results/{job_id}— complete analysis results as JSON
  GET  /api/sigma/{job_id}/rules.zip — download SIGMA rules bundle
  GET  /                    — serve the single-page application
"""

import asyncio
import io
import ipaddress
import json
import os
import re
import struct
import tempfile
import threading
import uuid
import zipfile
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

# Cross-platform temp dir (works on Windows/macOS/Linux — never hardcode /tmp).
# Uploaded captures can contain sensitive traffic, so restrict the directory to
# the owner (0700) on shared/multi-user hosts (CWE-377/CWE-732).
UPLOAD_DIR = Path(tempfile.gettempdir()) / "packetiq_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(UPLOAD_DIR, 0o700)
except Exception:
    pass
# Bounded upload size (env-overridable). Streamed to disk with an early abort so
# a large/malicious upload cannot exhaust server memory (CWE-400).
MAX_UPLOAD_MB = int(os.environ.get("PACKETIQ_MAX_UPLOAD_MB", "10240"))  # default 10 GB


# Host allow-list for the DNS-rebinding / CSRF guard. Loopback + the TestClient
# host by default; the launcher adds the bound host (or "*") for non-loopback binds.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "testserver"}


def _allowed_hosts() -> set:
    hosts = set(_LOOPBACK_HOSTS)
    for h in os.environ.get("PACKETIQ_ALLOWED_HOSTS", "").split(","):
        h = h.strip().strip("[]").lower()
        if h:
            hosts.add(h)
    return hosts


async def _stream_upload_to(file, dest, max_mb: int = None) -> int:
    """Stream an UploadFile to `dest` in chunks, aborting if it exceeds the cap.
    Returns the number of bytes written. Raises HTTPException(413) when over."""
    cap = (max_mb if max_mb is not None else MAX_UPLOAD_MB) * 1024 * 1024
    written = 0
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = await file.read(1 << 20)   # 1 MiB
                if not chunk:
                    break
                written += len(chunk)
                if written > cap:
                    out.close()
                    Path(dest).unlink(missing_ok=True)
                    raise HTTPException(413, f"File too large. Max {MAX_UPLOAD_MB} MB "
                                             "(set PACKETIQ_MAX_UPLOAD_MB to change).")
                out.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        Path(dest).unlink(missing_ok=True)
        raise HTTPException(400, f"Could not read upload: {exc}") from exc
    return written

# In-memory job registry
# job = {status, queue, result, error, filename, size_mb, pcap_path}
_jobs: dict[str, dict] = {}

TEMPLATE = Path(__file__).parent / "templates" / "index.html"
STATIC_DIR = Path(__file__).parent / "static"
# Front-end libraries are vendored (not loaded from a CDN) so the web app works
# with no internet at all. Served from /static/vendor via an allow-listed route.
_VENDOR_ASSETS = {
    "chart.umd.min.js": "application/javascript",
    "marked.min.js": "application/javascript",
}


# ── Serialisers ───────────────────────────────────────────────────────────────

def _sha256_file(path) -> str:
    """SHA-256 of a capture file for the report's chain-of-custody header."""
    import hashlib
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _ser_event(e) -> dict:
    from packetiq.utils.helpers import ts_to_str
    try:
        from packetiq import triage
        ex = triage.explain(e)
    except Exception:
        ex = {}
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
        "confidence":   round(float(e.confidence) * 100),
        "description":  e.description,
        "evidence":     e.evidence,
        # explainability + precision (false-positive context)
        "precision":      ex.get("precision", ""),
        "precision_style": ex.get("precision_style", "muted"),
        "why":            ex.get("why", ""),
        "what":           ex.get("what", ""),
        "recommendation": ex.get("recommendation", ""),
        "evidence_points": ex.get("evidence_points", []),
        "kill_chain_phase": ex.get("kill_chain_phase", ""),
        "mitre":          ex.get("mitre", []),
    }


def _attack_coverage(events) -> list:
    try:
        from packetiq.export import attack_coverage
        return attack_coverage(events)
    except Exception:
        return []


# Findings that come from a threat-intel feed match (vs a behavioural heuristic).
_INTEL_TYPES = {"IOC_MATCH": "OSINT IOC feed", "JA3_ANOMALY": "SSLBL JA3 (TLS)",
                "MALICIOUS_FILE": "MalwareBazaar (file hash)"}


def _threat_intel_matches(events) -> list:
    """Per-capture threat-intel hits — which feeds actually matched THIS pcap,
    grouped by source, so the Threat Intel panel is dynamic (not static counts)."""
    by_source: dict = {}
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for e in events:
        et = e.event_type.value
        if et not in _INTEL_TYPES:
            continue
        ev = e.evidence or {}
        source = ev.get("source") or _INTEL_TYPES[et]
        indicator = (ev.get("indicator") or ev.get("ja3") or ev.get("sha256")
                     or e.dst_ip or e.src_ip or "")
        rec = by_source.setdefault(source, {"source": source, "kind": et, "count": 0,
                                            "severity": e.severity.value, "matches": []})
        rec["count"] += 1
        if sev_rank.get(e.severity.value, 9) < sev_rank.get(rec["severity"], 9):
            rec["severity"] = e.severity.value
        if len(rec["matches"]) < 50:
            rec["matches"].append({
                "indicator": indicator, "label": ev.get("label") or e.description,
                "src_ip": e.src_ip or "", "dst_ip": e.dst_ip or "", "severity": e.severity.value,
            })
    return sorted(by_source.values(), key=lambda x: -x["count"])


def _ser_chain(c) -> dict:
    from packetiq.utils.helpers import ts_to_str
    return {
        "chain_id":     c.chain_id,
        "name":         c.name,
        "description":  c.description,
        "severity":     c.severity.value,
        "confidence":   round(c.confidence * 100),
        "attacker_ips": sorted(c.attacker_ips),
        "target_ips":   sorted(c.target_ips),
        "event_count":  c.event_count,
        "first_seen":   ts_to_str(c.first_seen) if c.first_seen else "",
        "last_seen":    ts_to_str(c.last_seen)  if c.last_seen  else "",
        "phases":       list(c.kill_chain_phases),
        "mitre":        [{"id": t.technique_id, "name": t.technique_name, "tactic": t.tactic_name}
                         for t in c.mitre_techniques],
    }


def _ser_tl(e) -> dict:
    ts = e.ts_str
    return {
        "ts":          e.timestamp,
        "ts_str":      ts[11:23] if len(ts) > 11 else ts,
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
        "os_icon":      f.os_icon,
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
        "description":    a.description,
        "icon":           a.icon,
        "color":          a.color,
        "mitre_group":    a.mitre_group,
        "target_sectors": a.target_sectors,
        "disclaimer":     getattr(a, "disclaimer", ""),
    }


def _build_graph(result, events) -> dict:
    """Nodes/edges for the interactive network graph (top talkers + flows)."""
    from packetiq.utils.helpers import is_private_ip

    counts: dict = {}
    for ip, c in result.ip_src_counts.items():
        counts[ip] = counts.get(ip, 0) + c
    for ip, c in result.ip_dst_counts.items():
        counts[ip] = counts.get(ip, 0) + c
    flagged = {e.dst_ip for e in events if e.dst_ip} | {e.src_ip for e in events if e.src_ip}

    top = {ip for ip, _ in sorted(counts.items(), key=lambda x: -x[1])[:40]}
    top |= {ip for ip in flagged if ip}     # always include flagged hosts
    top = set(list(top)[:60])

    nodes = [
        {"id": ip, "packets": counts.get(ip, 0),
         "internal": is_private_ip(ip), "flagged": ip in flagged}
        for ip in top
    ]
    edges = []
    seen = set()
    for fl in sorted(result.flows.values(), key=lambda f: -f.bytes_total):
        if fl.src_ip in top and fl.dst_ip in top:
            k = (fl.src_ip, fl.dst_ip)
            if k in seen:
                continue
            seen.add(k)
            edges.append({"source": fl.src_ip, "target": fl.dst_ip, "bytes": fl.bytes_total})
            if len(edges) >= 90:
                break
    return {"nodes": nodes, "edges": edges}


# ── Live capture sessions ─────────────────────────────────────────────────────

_live_sessions: dict = {}


class _LiveSession:
    """A running interface capture that feeds the rolling-window detectors."""

    _MAX_PKTS = 300_000   # cap recorded packets to bound disk usage

    def __init__(self, interface: str, threshold: str):
        import threading
        from collections import deque

        from packetiq.live import LiveMonitor
        from packetiq.parser.pcap_parser import PCAPParser

        self.interface = interface
        self.threshold = threshold
        self.alerts: list = []
        self.status = "running"
        self.error = None
        self.packets = 0
        self._i = 0
        self._lock = threading.RLock()
        self._parser = object.__new__(PCAPParser)   # reuse _parse_packet without a file
        self.monitor = LiveMonitor(window_secs=180.0, threshold=threshold, on_alert=self._on_alert)
        self.sniffer = None
        self._last_scan = 0.0
        import time as _t
        self.started = _t.time()
        # record every captured packet to a pcap so it can feed the full pipeline
        self.pcap_path = str(UPLOAD_DIR / f"live_{uuid.uuid4().hex[:8]}.pcap")
        self._writer = None
        # rolling buffer of recent per-packet summaries for the live "all packets" view
        self.pkt_summaries = deque(maxlen=4000)

    def _on_alert(self, e):
        self.alerts.append(_ser_event(e))

    def _cb(self, pkt):
        try:
            idx = self._i
            if self._writer is not None and self.packets < self._MAX_PKTS:
                try:
                    self._writer.write(pkt)
                except Exception:
                    pass
            rec = self._parser._parse_packet(pkt, idx)
            self._i += 1
            self.packets += 1
            try:
                from packetiq import inspect as _ins
                self.pkt_summaries.append(_ins.summarize(pkt, idx))
            except Exception:
                pass
            if rec:
                with self._lock:
                    self.monitor.feed(rec)
        except Exception:
            pass

    def flush(self):
        with self._lock:
            try:
                if self._writer is not None and getattr(self._writer, "f", None):
                    self._writer.f.flush()
            except Exception:
                pass

    def start(self):
        from scapy.all import AsyncSniffer, PcapWriter
        from scapy.config import conf
        # macOS native BPF can't set promiscuous mode (BIOCPROMISC → "Operation not
        # supported"), which otherwise kills the sniffer on real interfaces. We don't
        # need promisc to see this host's traffic, so disable it.
        conf.sniff_promisc = False
        try:
            self._writer = PcapWriter(self.pcap_path, append=False, sync=False)
        except Exception:
            self._writer = None
        self.sniffer = AsyncSniffer(iface=self.interface, prn=self._cb, store=False, promisc=False)
        self.sniffer.start()

    def alive(self) -> bool:
        t = getattr(self.sniffer, "thread", None)
        return bool(t and t.is_alive())

    def maybe_scan(self):
        import time as _t
        now = _t.time()
        if now - self._last_scan >= 2.0:
            self._last_scan = now
            with self._lock:
                try:
                    self.monitor.trim(now)
                    self.monitor.scan()
                except Exception:
                    pass

    def stop(self):
        self.status = "stopped"
        try:
            self.sniffer.stop()
        except Exception:
            pass
        with self._lock:
            try:
                if self._writer is not None:
                    self._writer.close()
            except Exception:
                pass
            self._writer = None


# ── Shared result builder (used by single-capture AND campaign/fuse) ──────────

def _build_result_data(job_id, file_meta, result, events, risk, chains, fps, progress=None):
    """Build timeline/sigma/attrs/exports + the serialised result dict."""
    from packetiq.attribution.engine import AttributionEngine
    from packetiq.export import build_html, to_stix_bundle
    from packetiq.export.misp import to_misp_event
    from packetiq.sigma.generator import SigmaGenerator
    from packetiq.timeline.builder import TimelineBuilder
    from packetiq.utils.helpers import format_bytes, format_duration, ts_to_str

    def _p(step, pct, label):
        if progress:
            progress(step, pct, label)

    _p("timeline", 87, "Reconstructing kill-chain timeline…")
    tl = TimelineBuilder().build(result, events, chains)
    _p("sigma", 91, "Generating SIGMA detection rules…")
    sigma = SigmaGenerator().generate(events, chains)
    _p("attribution", 95, "Threat-actor TTP overlap…")
    attrs = AttributionEngine().attribute(events, chains)

    fname = _jobs[job_id]["filename"]
    stix_bundle = to_stix_bundle(events, chains)
    misp_event = to_misp_event(events, info=f"PacketIQ — {fname}")
    html_report = build_html(file_meta, result, events, chains, risk, attrs,
                             pcap_sha256=file_meta.get("sha256"))

    try:
        from packetiq import storage
        storage.record(
            filename=fname, packets=result.total_packets,
            risk_score=risk.score, risk_tier=risk.tier,
            event_count=len(events), chain_count=len(chains),
            top_attacker=(risk.top_sources[0] if risk.top_sources else ""),
        )
    except Exception:
        pass

    _p("finalize", 99, "Finalising results…")
    dur = max(0.0, result.capture_end - result.capture_start)
    dns_counts: dict = {}
    for q in result.dns_queries:
        d = q.get("qname", "")
        dns_counts[d] = dns_counts.get(d, 0) + 1

    return {
        "meta": {
            "filename":      fname,
            "size_mb":       _jobs[job_id].get("size_mb", 0),
            "total_packets": result.total_packets,
            "total_bytes":   result.total_bytes,
            "bytes_fmt":     format_bytes(result.total_bytes),
            "capture_start": ts_to_str(result.capture_start),
            "capture_end":   ts_to_str(result.capture_end),
            "duration":      format_duration(dur),
            "unique_flows":  len(result.flows),
            "unique_src":    len(result.unique_src_ips),
            "unique_dst":    len(result.unique_dst_ips),
            "dns_queries":   len(result.dns_queries),
            "http_requests": len(result.http_requests),
            "external_ips":  len(result.external_ips),
            "campaign":      _jobs[job_id].get("campaign", False),
            "sha256":        file_meta.get("sha256", ""),
            "suppressed":    file_meta.get("suppressed", []),
        },
        "risk": {
            "score": risk.score, "tier": risk.tier, "summary": risk.summary,
            "breakdown": risk.by_severity, "event_count": risk.event_count,
            "top_sources": risk.top_sources[:5], "top_targets": risk.top_targets[:5],
        },
        "protocols":    result.protocol_counts,
        "top_ports":    [{"port": p, "count": c} for p, c in sorted(result.dst_port_counts.items(), key=lambda x: -x[1])[:20]],
        "top_src_ips":  [{"ip": ip, "count": c} for ip, c in sorted(result.ip_src_counts.items(), key=lambda x: -x[1])[:15]],
        "top_dst_ips":  [{"ip": ip, "count": c} for ip, c in sorted(result.ip_dst_counts.items(), key=lambda x: -x[1])[:15]],
        "dns_top":      sorted(dns_counts.items(), key=lambda x: -x[1])[:50],
        "http_requests":[{"method": r.get("method", ""), "host": r.get("host", ""),
                          "path": r.get("path", ""), "src": r.get("src", "")} for r in result.http_requests[:100]],
        "software_banners": getattr(result, "software_banners", []),
        "events":       [_ser_event(e) for e in events],
        "chains":       [_ser_chain(c) for c in chains],
        "timeline":     [_ser_tl(e) for e in tl.events[:400]],
        "activity_bar": {
            "buckets":     tl.activity_bar.buckets if tl.activity_bar else [],
            "bucket_secs": round(tl.activity_bar.bucket_secs, 2) if tl.activity_bar else 0,
            "total":       tl.activity_bar.total_events if tl.activity_bar else 0,
        },
        "phases_seen":   tl.phases_seen,
        "attack_coverage": _attack_coverage(events),
        "threat_intel_matches": _threat_intel_matches(events),
        "fingerprints":  [_ser_fp(f) for f in fps],
        "sigma_rules":   [{"title": r.title, "level": r.level, "yaml": r.raw_yaml} for r in sigma],
        "attributions":  [_ser_attr(a) for a in attrs],
        "graph":         _build_graph(result, events),
        "stix":          stix_bundle,
        "misp":          misp_event,
        "html_report":   html_report,
    }


def _merge_results(results: list):
    """Merge several ExtractionResults into one (for campaign/fuse analysis)."""
    from packetiq.extractor.data_extractor import ExtractionResult
    m = ExtractionResult()
    starts, ends = [], []
    for r in results:
        m.total_packets += r.total_packets
        m.total_bytes += r.total_bytes
        for d, src in ((m.protocol_counts, r.protocol_counts),
                       (m.dst_port_counts, r.dst_port_counts),
                       (m.src_port_counts, r.src_port_counts),
                       (m.ip_src_counts, r.ip_src_counts),
                       (m.ip_dst_counts, r.ip_dst_counts)):
            for k, v in src.items():
                d[k] = d.get(k, 0) + v
        m.unique_src_ips |= r.unique_src_ips
        m.unique_dst_ips |= r.unique_dst_ips
        m.external_ips |= r.external_ips
        m.flows.update(r.flows)
        m.dns_queries.extend(r.dns_queries)
        m.http_requests.extend(r.http_requests)
        m.software_banners.extend(getattr(r, "software_banners", []))
        m.tcp_syn_pairs.update(r.tcp_syn_pairs)
        m.src_ip_ttl.update(r.src_ip_ttl)
        if r.capture_start:
            starts.append(r.capture_start)
        if r.capture_end:
            ends.append(r.capture_end)
    m.capture_start = min(starts) if starts else 0.0
    m.capture_end = max(ends) if ends else 0.0
    return m


def _run_fuse(job_id: str, pcap_paths: list, loop: asyncio.AbstractEventLoop) -> Optional[dict]:
    """Campaign analysis across multiple captures — dedup events, merge, re-correlate."""
    from packetiq.correlation.engine import CorrelationEngine
    from packetiq.detection.engine import DetectionEngine
    from packetiq.detection.risk_scorer import score as risk_score
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser

    queue = _jobs[job_id]["queue"]

    def progress(step, pct, label):
        asyncio.run_coroutine_threadsafe(queue.put({"type": "progress", "step": step, "percent": pct, "label": label}), loop)

    try:
        all_events, results, fps_all = [], [], []
        n = len(pcap_paths)
        for i, path in enumerate(pcap_paths):
            progress("parse", int(5 + (i / max(n, 1)) * 60), f"Analysing capture {i+1}/{n}…")
            parser = PCAPParser(path)
            extractor = DataExtractor()
            for rec in parser.stream():
                extractor.feed(rec)
            res = extractor.finalize()
            batch, _risk, fps = DetectionEngine().run(res, path)
            all_events.extend(batch)
            results.append(res)
            fps_all.extend(fps)

        progress("correlate", 70, "Deduplicating events across the campaign…")
        seen, deduped = set(), []
        for ev in sorted(all_events, key=lambda e: e.timestamp):
            k = (ev.event_type, ev.src_ip, ev.dst_ip, ev.dst_port)
            if k not in seen:
                seen.add(k)
                deduped.append(ev)

        merged = _merge_results(results)
        chains = CorrelationEngine().correlate(deduped)
        risk = risk_score(deduped)
        # dedup fingerprints by src_ip
        seen_fp, fps = set(), []
        for f in fps_all:
            if f.src_ip not in seen_fp:
                seen_fp.add(f.src_ip)
                fps.append(f)

        file_meta = {"filename": _jobs[job_id]["filename"], "filesize": _jobs[job_id].get("filesize", 0)}
        data = _build_result_data(job_id, file_meta, merged, deduped, risk, chains, fps, progress=progress)
        asyncio.run_coroutine_threadsafe(queue.put({"type": "complete"}), loop)
        return data
    except Exception as exc:  # noqa: BLE001
        import traceback
        asyncio.run_coroutine_threadsafe(queue.put({"type": "error", "message": f"{type(exc).__name__}: {exc}",
                                                    "traceback": traceback.format_exc()}), loop)
        return None


# ── Core analysis (runs in thread pool) ──────────────────────────────────────

# File types the web pipeline accepts: packet captures, Zeek conn.logs, and raw
# NetFlow/IPFIX exports (parity with the CLI). A NetFlow export is also recognised
# by its version word (see _looks_like_netflow), so an unfamiliar extension works.
SUPPORTED_UPLOAD_EXT = (".pcap", ".pcapng", ".cap", ".log", ".tsv", ".json",
                        ".netflow", ".nfcapd", ".nf", ".ipfix", ".flows")


def _looks_like_netflow(path: str) -> bool:
    """True if the file's first two bytes are a NetFlow/IPFIX version word (5, 9 or
    10). PCAP (0xA1B2…) and PCAPNG (0x0A0D…) magic never start with 0x0005/0x0009/
    0x000A, so this cannot misclassify a capture. Lets the web app accept a raw
    flow export even when it has an unfamiliar extension."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
    except OSError:
        return False
    if len(head) < 2:
        return False
    return struct.unpack("!H", head)[0] in (5, 9, 10)


def _run_analysis(job_id: str, pcap_path: str, loop: asyncio.AbstractEventLoop) -> Optional[dict]:
    """Full PacketIQ pipeline — blocking, call via run_in_executor."""
    from packetiq.correlation.engine import CorrelationEngine
    from packetiq.detection.engine import DetectionEngine
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser

    queue = _jobs[job_id]["queue"]

    def push(**kwargs):
        asyncio.run_coroutine_threadsafe(queue.put(kwargs), loop)

    def progress(step: str, pct: int, label: str):
        push(type="progress", step=step, percent=pct, label=label)

    fname = _jobs[job_id].get("filename", "")
    lower = fname.lower()
    is_netflow = lower.endswith((".netflow", ".nfcapd", ".nf", ".ipfix", ".flows")) or _looks_like_netflow(pcap_path)
    is_zeek = lower.endswith((".log", ".tsv")) or "conn" in lower and lower.endswith(".json")

    try:
        # ── Parse ──────────────────────────────────────────────────────
        if is_netflow:
            progress("parse", 5, "Parsing NetFlow / IPFIX export…")
            from packetiq.inputs import load_netflow
            result = load_netflow(pcap_path)
            count = result.total_packets
            file_meta = {"filename": fname, "filesize": os.path.getsize(pcap_path),
                         "packet_count": count, "sha256": _sha256_file(pcap_path)}
            progress("parse", 30, f"Loaded {len(result.flows):,} flow(s) from NetFlow export.")
        elif is_zeek:
            progress("parse", 5, "Parsing Zeek conn.log…")
            from packetiq.inputs import load_conn_log
            result = load_conn_log(pcap_path)
            count = result.total_packets
            file_meta = {"filename": fname, "filesize": os.path.getsize(pcap_path), "packet_count": count}
            progress("parse", 30, f"Loaded {len(result.flows):,} flow(s) from conn.log.")
        else:
            progress("parse", 5, "Parsing PCAP packets…")
            parser    = PCAPParser(pcap_path)
            extractor = DataExtractor()
            count     = 0
            for rec in parser.stream():
                extractor.feed(rec)
                count += 1
                if count % 10_000 == 0:
                    pct = min(28, 5 + count // 5_000)
                    progress("parse", pct, f"Parsed {count:,} packets…")

            result    = extractor.finalize()
            file_meta = parser.file_summary()
            # file_summary() names the file as it sits on disk — an internal temp
            # name for an upload. The report's chain of custody must cite the
            # evidence file the analyst actually submitted.
            file_meta["filename"] = fname or file_meta.get("filename", "")
            file_meta["sha256"] = _sha256_file(pcap_path)   # chain-of-custody
            progress("parse", 30, f"Parsed {count:,} packets — extraction complete.")

        # ── Detect ─────────────────────────────────────────────────────
        STEP_MAP = {
            "brute_force":        (34, "Brute-force detector…"),
            "port_scan":          (39, "Port-scan detector…"),
            "dns_anomaly":        (44, "DNS anomaly analysis…"),
            "protocol_misuse":    (49, "Protocol misuse detector…"),
            "beacon_analysis":    (54, "C2 beacon periodicity analysis…"),
            "http_inspection":    (57, "HTTP deep inspection…"),
            "credential_exposure":(60, "Credential exposure scan…"),
            "ja3_fingerprinting": (63, "JA3/JA4 TLS fingerprinting…"),
            "tls_inspection":     (66, "TLS certificate inspection…"),
            "file_carving":       (68, "File carving + hash reputation…"),
            "ioc_enrichment":     (70, "Threat-intel IOC enrichment…"),
            "os_fingerprinting":  (72, "Passive OS fingerprinting…"),
            "risk_scoring":       (75, "Computing risk score…"),
        }

        def cb(step: str):
            if step in STEP_MAP:
                progress(step, *STEP_MAP[step])

        engine             = DetectionEngine()
        events, risk, fps  = engine.run(result, pcap_path, progress_callback=cb)
        # transparency: surface anything the allow-list / confidence floor suppressed
        file_meta["suppressed"] = [
            {"event_type": e.event_type.value, "src_ip": e.src_ip, "dst_ip": e.dst_ip, "reason": reason}
            for e, reason in getattr(engine, "suppressed", []) or []
        ]
        progress("detect_done", 76, f"{len(events)} threat event(s) detected.")

        # ── Correlate ──────────────────────────────────────────────────
        progress("correlate", 82, "Correlating attack chains…")
        chains = CorrelationEngine().correlate(events)
        progress("correlate", 84, f"{len(chains)} attack chain(s) identified.")

        # ── Timeline / SIGMA / attribution / exports + serialise ────────
        data = _build_result_data(job_id, file_meta, result, events, risk, chains, fps, progress=progress)
        push(type="complete")
        return data

    except Exception as exc:
        import traceback
        push(type="error", message=f"{type(exc).__name__}: {exc}",
             traceback=traceback.format_exc())
        return None


# ── Background coroutine ──────────────────────────────────────────────────────

async def _analyze_task(job_id: str, pcap_path: str):
    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, _run_analysis, job_id, pcap_path, loop)
    _jobs[job_id]["result"] = data
    _jobs[job_id]["status"] = "complete" if data is not None else "error"
    # NOTE: the capture file is retained (not deleted) so the user can download
    # evidence sub-captures for findings from the GUI. _evict_old_jobs() prunes
    # old uploads to bound disk usage.
    _evict_old_jobs()


def _capture_privilege() -> tuple:
    """(capture_ok, platform) — single source of truth in packetiq.capture_setup."""
    try:
        from packetiq import capture_setup
        ok, plat, _ = capture_setup.status()
        return ok, plat
    except Exception:
        return False, "other"


def _job_pcap_paths(job_id: str) -> list:
    """Existing capture file(s) for a job (single or campaign)."""
    if job_id not in _jobs:
        return []
    paths = _jobs[job_id].get("pcap_paths") or [_jobs[job_id].get("pcap_path")]
    return [p for p in paths if p and Path(p).is_file()]


def _iter_packets(paths: list, max_scan: int = 200_000):
    """Yield (global_index, packet) across one or more pcaps."""
    from scapy.all import PcapReader
    idx = 0
    for path in paths:
        try:
            with PcapReader(path) as rd:
                for pkt in rd:
                    yield idx, pkt
                    idx += 1
                    if idx >= max_scan:
                        return
        except Exception:
            continue


def _evict_old_jobs(max_jobs: int = 12):
    """Keep disk/memory bounded: drop the oldest finished jobs and their PCAPs."""
    finished = [j for j in _jobs if _jobs[j].get("status") in ("complete", "error")]
    if len(finished) <= max_jobs:
        return
    for job_id in finished[:-max_jobs]:
        paths = _jobs[job_id].get("pcap_paths") or [_jobs[job_id].get("pcap_path")]
        for p in paths:
            if p:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass
        _jobs.pop(job_id, None)


# ── Chat helpers ──────────────────────────────────────────────────────────────

_CHAT_SYSTEM = """You are PacketIQ Copilot, an expert AI assistant embedded in a \
network forensics and SOC (Security Operations Centre) analysis platform.

Your expertise covers:
- Network protocol analysis (TCP/IP, DNS, HTTP, SMB, FTP, SMTP, ICMP)
- Threat hunting and incident response
- MITRE ATT&CK framework and kill chain analysis
- Malware indicators: C2 beaconing, DGA, data exfiltration techniques
- Brute force, port scanning, lateral movement detection

Communication style:
- Direct, technical, and actionable — no filler text
- Use SOC terminology precisely (IOC, TTP, TTL, lateral movement, C2, etc.)
- Prioritise findings by business risk and severity
- When uncertain, say so explicitly — analysts rely on accurate confidence levels
- Always end threat assessments with prioritised immediate actions
- Format responses with **bold**, bullet lists, and headers for readability

You have been loaded with the complete automated analysis of a PCAP capture file.
The context contains: capture metadata, protocol stats, top IPs/ports, all detection
events with evidence, correlated attack chains with MITRE mappings, DNS intelligence,
HTTP activity, threat actor attribution, and pre-computed IOCs.

━━━ GROUNDING RULES (these override the style guide above) ━━━
1. Answer ONLY from the <pcap_analysis> evidence provided. Treat it as the sole
   source of truth about this capture.
2. Every specific claim — an IP address, domain, port, MITRE technique ID, CVE,
   file hash, or detection — MUST appear verbatim in the evidence. Never invent
   or guess one, and never add "typical", "related" or "commonly seen" indicators
   that aren't present.
2a. When you LIST technique IDs, CVEs, or IOCs, copy ONLY the exact IDs written
   in the evidence above. Do NOT supplement the list from your own knowledge of
   what usually accompanies these attacks — if an ID is not literally in the
   evidence, it must not appear in your answer.
3. The detectors decide what was found, not you. Do not upgrade, downgrade, or
   invent findings. If asked about something with no supporting evidence, say
   plainly: "That is not present in this capture."
4. If the evidence is insufficient to answer, say so instead of speculating.
5. You may explain, prioritise and give response actions for what IS in the
   evidence — that is your job. Just keep every factual claim traceable to it.

Answer as a senior SOC analyst who has reviewed this capture in full — precise,
evidence-bound, and honest about the limits of what the capture shows."""


def _build_chat_context(result: dict) -> str:
    """Build a structured text context from the serialised result dict for Claude."""
    m = result.get("meta", {})
    r = result.get("risk", {})
    events = result.get("events", [])
    chains = result.get("chains", [])
    attrs  = result.get("attributions", [])

    lines = []

    # Header
    lines += [
        "=== PACKETIQ ANALYSIS CONTEXT ===",
        f"File        : {m.get('filename', '?')}",
        f"Size        : {m.get('bytes_fmt', '?')}  ({m.get('size_mb', 0):.2f} MB)",
        f"Packets     : {m.get('total_packets', 0):,}",
        f"Duration    : {m.get('duration', '?')}",
        f"Capture     : {m.get('capture_start', '?')} → {m.get('capture_end', '?')}",
        f"Risk Score  : {r.get('score', 0)}/100  [{r.get('tier', '?')}]",
        f"Risk Summary: {r.get('summary', '')}",
    ]

    # Capture stats
    lines += [
        "\n=== CAPTURE STATISTICS ===",
        f"Unique Source IPs  : {m.get('unique_src', 0)}",
        f"Unique Dest IPs    : {m.get('unique_dst', 0)}",
        f"External IPs       : {m.get('external_ips', 0)}",
        f"Unique Flows       : {m.get('unique_flows', 0)}",
        f"DNS Queries        : {m.get('dns_queries', 0)}",
        f"HTTP Requests      : {m.get('http_requests', 0)}",
    ]

    # Severity breakdown
    brk = r.get("breakdown", {})
    if brk:
        lines.append("\n=== SEVERITY BREAKDOWN ===")
        for sev, cnt in brk.items():
            lines.append(f"  {sev}: {cnt}")

    # Protocol distribution
    protos = result.get("protocols", {})
    if protos:
        lines.append("\n=== PROTOCOL DISTRIBUTION ===")
        for p, cnt in sorted(protos.items(), key=lambda x: -x[1])[:12]:
            lines.append(f"  {p:<12} {cnt:>8,}")

    # Top source / dest IPs
    top_src = result.get("top_src_ips", [])
    if top_src:
        lines.append("\n=== TOP SOURCE IPs ===")
        for item in top_src[:15]:
            lines.append(f"  {item['ip']:<22} {item['count']:>8,} pkts")

    top_dst = result.get("top_dst_ips", [])
    if top_dst:
        lines.append("\n=== TOP DESTINATION IPs ===")
        for item in top_dst[:15]:
            lines.append(f"  {item['ip']:<22} {item['count']:>8,} pkts")

    # Top ports
    top_ports = result.get("top_ports", [])
    if top_ports:
        lines.append("\n=== TOP DESTINATION PORTS ===")
        for item in top_ports[:15]:
            lines.append(f"  Port {item['port']:<8} {item['count']:>8,} pkts")

    # Detection events
    lines.append(f"\n=== DETECTION EVENTS ({len(events)} total) ===")
    if not events:
        lines.append("  None detected.")
    for i, e in enumerate(events[:60], 1):
        dst = f"{e.get('dst_ip','')}:{e.get('dst_port','')}" if e.get('dst_ip') else "—"
        lines += [
            f"\n[{i}] [{e.get('severity','')}] {e.get('event_type','')}",
            f"    Source      : {e.get('src_ip','—')}",
            f"    Destination : {dst}",
            f"    Protocol    : {e.get('protocol','—')}",
            f"    Confidence  : {e.get('confidence',0)}%",
            f"    Description : {e.get('description','')}",
            f"    Time        : {e.get('ts_str','')}",
        ]
        ev = e.get("evidence", {})
        if ev:
            for k, v in list(ev.items())[:4]:
                lines.append(f"    {k:<16}: {v}")

    # Attack chains
    lines.append(f"\n=== ATTACK CHAINS ({len(chains)} identified) ===")
    if not chains:
        lines.append("  No multi-stage chains correlated.")
    for i, c in enumerate(chains, 1):
        mitre = ", ".join(f"{t['id']} {t['name']}" for t in c.get("mitre", []))
        lines += [
            f"\n[CHAIN {i}] {c.get('name','')}",
            f"  Severity    : {c.get('severity','')}",
            f"  Confidence  : {c.get('confidence',0)}%",
            f"  Events      : {c.get('event_count',0)}",
            f"  Attackers   : {', '.join(c.get('attacker_ips',[]))}",
            f"  Targets     : {', '.join(c.get('target_ips',[]))}",
            f"  Kill Chain  : {' → '.join(c.get('phases',[]))}",
            f"  MITRE       : {mitre}",
            f"  Description : {c.get('description','')}",
        ]

    # DNS top queries
    dns_top = result.get("dns_top", [])
    if dns_top:
        lines.append("\n=== TOP DNS QUERIES ===")
        for name, cnt in dns_top[:25]:
            lines.append(f"  {name:<50} {cnt}x")

    # HTTP activity
    http = result.get("http_requests", [])
    if http:
        lines.append(f"\n=== HTTP REQUESTS (first {min(len(http),30)}) ===")
        for req in http[:30]:
            lines.append(f"  {req.get('method','?'):<6} {req.get('src','?'):<18} → {req.get('host','')}{req.get('path','')}")

    # Threat attribution
    if attrs:
        lines.append("\n=== THREAT ACTOR ATTRIBUTION ===")
        for a in attrs:
            lines += [
                f"\n  Actor       : {a.get('name','')}",
                f"  Confidence  : {a.get('confidence',0)}%",
                f"  Origin      : {a.get('origin','')}",
                f"  Motivation  : {a.get('motivation','')}",
                f"  Matched TTPs: {', '.join(a.get('matched_ttps',[]))}",
            ]

    return "\n".join(lines)


def _read_env() -> dict:
    """Read all key=value pairs from .env files."""
    env: dict = {}
    for path in (".", ".."):
        env_file = Path(path) / ".env"
        if env_file.is_file():
            for line in env_file.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip().strip('"').strip("'")
            break
    return env


def _env_upsert(key: str, value: str) -> None:
    """Persist KEY=value into ./.env, replacing an existing line or appending —
    other content and comments are preserved. Lets a key entered in the web UI
    survive a restart. Best-effort; the caller ignores OSError."""
    env_path = Path(".env")
    lines = env_path.read_text().splitlines() if env_path.is_file() else []
    pre, epre = f"{key}=", f"export {key}="
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith(pre) or s.startswith(epre):
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n")


def _env_remove(key: str) -> None:
    """Delete any KEY= line from ./.env (best-effort)."""
    env_path = Path(".env")
    if not env_path.is_file():
        return
    pre, epre = f"{key}=", f"export {key}="
    kept = [ln for ln in env_path.read_text().splitlines()
            if not (ln.strip().startswith(pre) or ln.strip().startswith(epre))]
    env_path.write_text("\n".join(kept) + ("\n" if kept else ""))


# Provider priority + their env var and default model. `ollama` is the local,
# offline runtime — it has no API key (its "env var" is the optional model
# override) and is treated as configured when its daemon is reachable. It sits
# last so cloud keys win when present, but it is always there as an offline
# fallback with no rate limits and no data leaving the machine.
_PROVIDER_SPECS = [
    ("gemini",    "GEMINI_API_KEY",    "gemini-2.0-flash"),
    ("groq",      "GROQ_API_KEY",      "llama-3.3-70b-versatile"),
    ("anthropic", "ANTHROPIC_API_KEY", "claude-sonnet-4-6"),
    ("ollama",    "OLLAMA_MODEL",      "qwen2.5:7b-instruct"),
]

# Google grants free-tier quota *per model*, not per key. A project can therefore
# hold a perfectly valid key that answers `limit: 0` for gemini-2.0-flash while
# newer models reply normally. That is a wrong-model problem, not a dead-provider
# problem, so we walk a candidate list instead of benching Gemini for an hour.
# Order = preference; the first entry is the documented free-tier model.
_MODEL_CANDIDATES = {
    "gemini": ["gemini-2.0-flash", "gemini-flash-lite-latest", "gemini-3-flash-preview"],
}
# "provider:model" pairs this process has proven unusable — never retried.
_MODEL_DEAD: set = set()
# Manual override from the GUI: None => fully automatic.
_AI_FORCED: dict = {"provider": None}
# Sticky auto-switch memory: provider name -> epoch time it's healthy again.
_AI_COOLDOWN: dict = {}
# Grounding: low temperature keeps explanations tied to the evidence, not creative.
_AI_TEMPERATURE = float(os.environ.get("PACKETIQ_AI_TEMPERATURE", "0.15"))

# ── Local Ollama runtime (offline copilot; no API key needed) ────────────────
# Instruction-tuned by default — grounding depends on the model obeying the
# evidence-only rules, and qwen2.5-7b-instruct follows instructions well and is
# strong at the structured extraction the copilot needs (IOC lists, MITRE tables).
_OLLAMA_DEFAULT_MODEL = "qwen2.5:7b-instruct"
# Any fixed value works; what matters is that it does not change between runs.
_OLLAMA_DEFAULT_SEED = 42
# Cached reachability probe so we don't hit the daemon on every request.
_OLLAMA_PROBE: dict = {"at": 0.0, "up": False, "models": []}
# Models we've already fired a warm-up load for (once per process, per model).
_OLLAMA_WARMED: set = set()


def _ollama_host() -> str:
    env = _read_env()
    return (os.environ.get("OLLAMA_HOST") or env.get("OLLAMA_HOST")
            or "http://localhost:11434").rstrip("/")


def _ollama_enabled() -> bool:
    """The local provider can be turned off with PACKETIQ_ENABLE_OLLAMA=0."""
    env = _read_env()
    flag = (os.environ.get("PACKETIQ_ENABLE_OLLAMA")
            or env.get("PACKETIQ_ENABLE_OLLAMA") or "1").strip().lower()
    return flag not in ("0", "false", "no", "off")


def _ollama_probe(force: bool = False) -> dict:
    """Reachability + installed-model probe of the local Ollama daemon (30s cache)."""
    import time
    now = time.time()
    if not force and (now - _OLLAMA_PROBE["at"]) < 30 and _OLLAMA_PROBE["at"]:
        return _OLLAMA_PROBE
    up, models = False, []
    if _ollama_enabled():
        try:
            import httpx
            r = httpx.get(_ollama_host() + "/api/tags", timeout=1.5)
            if r.status_code == 200:
                up = True
                models = [m.get("name", "") for m in (r.json().get("models") or []) if m.get("name")]
        except Exception:  # noqa: BLE001 — daemon down / not installed
            up, models = False, []
    _OLLAMA_PROBE.update(at=now, up=up, models=models)
    return _OLLAMA_PROBE


def _ollama_available() -> bool:
    return _ollama_probe()["up"]


def _ollama_model() -> str:
    """Resolve the model to use: OLLAMA_MODEL if set (and honoured even if the
    probe list is stale), else the default if pulled, else the first pulled model."""
    env = _read_env()
    want = (os.environ.get("OLLAMA_MODEL") or env.get("OLLAMA_MODEL") or "").strip()
    models = _ollama_probe().get("models") or []
    if want:
        return want
    if _OLLAMA_DEFAULT_MODEL in models:
        return _OLLAMA_DEFAULT_MODEL
    return models[0] if models else _OLLAMA_DEFAULT_MODEL


def _ollama_keep_alive() -> str:
    """How long Ollama keeps the model resident after a request. The default of
    5 minutes makes every occasional query pay a multi-second cold reload of a
    7B model; keeping it warm for 30m is the single biggest latency win for the
    local copilot. Override with OLLAMA_KEEP_ALIVE (e.g. '5m', '-1' = forever)."""
    env = _read_env()
    return (os.environ.get("OLLAMA_KEEP_ALIVE") or env.get("OLLAMA_KEEP_ALIVE")
            or "30m").strip()


def _ollama_seed() -> Optional[int]:
    """Fixed sampling seed so identical evidence yields identical prose.

    Ollama seeds randomly by default, so re-running the same analysis reworded
    the answer every time. For an evidence-handling tool that is a liability: a
    report the analyst cannot regenerate verbatim is hard to defend. Pinning the
    seed makes the local copilot reproducible. `OLLAMA_SEED=random` opts out.
    """
    env = _read_env()
    raw = (os.environ.get("OLLAMA_SEED") or env.get("OLLAMA_SEED") or "").strip().lower()
    if raw in ("random", "none", "off"):
        return None
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return _OLLAMA_DEFAULT_SEED


def _ollama_num_ctx(prompt_chars: int, reply_tokens: int) -> int:
    """Pick a context window that fits the prompt without wasting memory.

    Ollama's default context is small (2048 tokens on many builds), so a large
    grounded PCAP context gets silently truncated — that *drops evidence* and is
    a real accuracy bug for the local model, not just a speed one. We size the
    window to the actual prompt (≈4 chars/token) plus headroom for the reply,
    snapped to a sane ladder and capped so a 7B model still fits on a laptop.
    Override the cap with OLLAMA_NUM_CTX."""
    est = (prompt_chars // 4) + reply_tokens + 256
    env = _read_env()
    try:
        cap = int((os.environ.get("OLLAMA_NUM_CTX") or env.get("OLLAMA_NUM_CTX") or "8192").strip())
    except ValueError:
        cap = 8192
    for size in (2048, 4096, 8192, 16384, 32768):
        if est <= size:
            return min(size, cap)
    return cap


def _ollama_should_warm() -> bool:
    """Only preload the local model when it's actually the provider that will
    serve requests — i.e. Ollama is force-selected, or no cloud key is present.
    Checks env directly (never _detect_provider) to avoid probe recursion."""
    forced = _AI_FORCED.get("provider")
    if forced == "ollama":
        return True
    if forced in ("gemini", "groq", "anthropic"):
        return False
    env = _read_env()
    for n, envname, _ in _PROVIDER_SPECS:
        if n != "ollama" and (os.environ.get(envname) or env.get(envname)):
            return False
    return True


def _ollama_warm(model: str, host: str) -> None:
    """Fire-and-forget preload so the *first* real query isn't slow. Loads the
    model into memory with the configured keep-alive; runs once per model per
    process and swallows every error (a down daemon just means no warm-up)."""
    if not model or model in _OLLAMA_WARMED:
        return
    _OLLAMA_WARMED.add(model)

    def _run() -> None:
        try:
            import httpx
            httpx.post(
                host.rstrip("/") + "/api/chat",
                json={
                    "model":      model,
                    "messages":   [{"role": "user", "content": "hi"}],
                    "stream":     False,
                    "keep_alive": _ollama_keep_alive(),
                    "options":    {"num_predict": 1},
                },
                timeout=httpx.Timeout(120.0, connect=5.0),
            )
        except Exception:  # noqa: BLE001 — best-effort warm-up
            pass

    threading.Thread(target=_run, daemon=True).start()


def _provider_key(name: str) -> Optional[str]:
    if name == "ollama":
        # No API key — carry the daemon host so downstream code has a truthy value.
        return _ollama_host()
    env = _read_env()
    for n, envname, _ in _PROVIDER_SPECS:
        if n == name:
            return os.environ.get(envname) or env.get(envname)
    return None


def _configured_providers() -> list:
    """Provider names usable right now, in priority order. Cloud providers need
    an API key; the local Ollama provider needs its daemon reachable."""
    env = _read_env()
    out = []
    for n, envname, _ in _PROVIDER_SPECS:
        if n == "ollama":
            if _ollama_available():
                out.append(n)
        elif os.environ.get(envname) or env.get(envname):
            out.append(n)
    return out


def _cooldown_left(name: str) -> int:
    import time
    return max(0, round(_AI_COOLDOWN.get(name, 0) - time.time()))


_MAX_COOLDOWN_SECS = 600.0          # ordinary per-minute throttling
_LONG_COOLDOWN_SECS = 3600.0        # a quota that won't come back this hour


def _mark_cooldown(name: str, seconds: float, max_secs: float = _MAX_COOLDOWN_SECS) -> None:
    """Put a provider on cooldown so auto-switch stops retrying it."""
    import time
    _AI_COOLDOWN[name] = time.time() + max(5.0, min(float(seconds), max_secs))


def _retry_after_seconds(msg: str, default: float = 60.0) -> float:
    m = re.search(r"retry in ([\d.]+)s", msg) or re.search(r"retryDelay'?\s*[:=]\s*'?(\d+)\s*s", msg)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return default


def _model_for(name: str) -> str:
    """The model id to call `name` with.

    `<PROVIDER>_MODEL` in the environment or .env always wins — without it there
    was no way to move off a model whose free-tier quota Google had zeroed short
    of editing this file. Otherwise use the first candidate not already proven
    unusable, falling back to the provider's declared default.
    """
    env = _read_env()
    envname = f"{name.upper()}_MODEL"
    override = (os.environ.get(envname) or env.get(envname) or "").strip()
    if override:
        return override
    for model in _MODEL_CANDIDATES.get(name, []):
        if _model_alive(name, model):
            return model
    for n, _, model in _PROVIDER_SPECS:
        if n == name:
            return model
    return ""


def _model_alive(provider: str, model: str) -> bool:
    return f"{provider}:{model}" not in _MODEL_DEAD


def _mark_model_dead(provider: str, model: str) -> None:
    _MODEL_DEAD.add(f"{provider}:{model}")


def _next_model(provider: str, current: str) -> str:
    """Another model of the same provider worth trying, or '' if none is left."""
    for model in _MODEL_CANDIDATES.get(provider, []):
        if model != current and _model_alive(provider, model):
            return model
    return ""


def _detect_provider(skip: Optional[set] = None) -> dict:
    """
    Pick the AI provider to use. Honours a manual GUI override (_AI_FORCED) and,
    in automatic mode, performs *sticky* switching: providers that recently
    rate-limited are skipped (cooldown) so we don't keep retrying a dead key.
    Returns {"provider": str|None, "key": str|None, "model": str}.
    Pass skip={"gemini"} to force-fall-through to the next provider.
    """
    skip = skip or set()
    configured = _configured_providers()

    def make(name: str) -> dict:
        if name == "ollama":
            return {"provider": name, "key": _ollama_host(), "model": _ollama_model()}
        return {"provider": name, "key": _provider_key(name), "model": _model_for(name)}

    # Manual override wins (unless it just failed and was added to `skip`).
    forced = _AI_FORCED.get("provider")
    if forced and forced in configured and forced not in skip:
        return make(forced)

    # Automatic: first configured provider that isn't skipped or on cooldown.
    for name in configured:
        if name in skip or _cooldown_left(name) > 0:
            continue
        return make(name)
    # Everything left is on cooldown — try anyway rather than give up.
    for name in configured:
        if name not in skip:
            return make(name)
    return {"provider": None, "key": None, "model": ""}


def _key_hint(name: str) -> str:
    """Masked tail of a configured key, for the settings UI (never the full key)."""
    if name == "ollama":
        return ""
    key = _provider_key(name)
    if not key:
        return ""
    return "…" + key[-4:] if len(key) > 4 else "set"


def _ai_status_payload() -> dict:
    """Current AI provider state for the GUI control (incl. offline Ollama)."""
    configured = _configured_providers()
    active = _detect_provider()
    probe = _ollama_probe()
    # If the local model is what we'll actually use, preload it now (once) so the
    # user's first query doesn't wait on a cold model load.
    if probe["up"] and _ollama_should_warm():
        _ollama_warm(_ollama_model(), _ollama_host())
    return {
        "available": bool(configured),
        "mode": "auto" if not _AI_FORCED.get("provider") else "manual",
        "forced": _AI_FORCED.get("provider"),
        "active": active["provider"],
        "providers": [
            {"name": n, "label": _AI_LABEL.get(n, n),
             "configured": n in configured, "cooldown": _cooldown_left(n),
             "needs_key": n != "ollama", "key_hint": _key_hint(n)}
            for n, _, _ in _PROVIDER_SPECS
        ],
        # Offline local-LLM status so the UI can guide the user without a key.
        "ollama": {
            "available": probe["up"],
            "host": _ollama_host(),
            "models": probe.get("models", []),
            "model": _ollama_model() if probe["up"] else _OLLAMA_DEFAULT_MODEL,
        },
    }


# ── Grounding guardrail ──────────────────────────────────────────────────────
# The copilot's evidence (IPs, MITRE technique IDs, CVEs, domains, file hashes) is
# deterministic and real. The one place a hallucination can enter is the LLM's
# prose — a small local model, in particular, likes to *pad* MITRE lists, invent a
# CVE, or name a plausible-sounding C2 domain that was never in the capture. The
# prompt asks it not to; this guardrail *guarantees* it. Every specific claim the
# model streams is checked against the exact evidence it was given, and any IP /
# technique ID / CVE / domain / file hash that is not grounded is redacted before
# it reaches the user. It is a deterministic post-filter, not a second model — it
# can only ever remove an invented entity, never add or alter a real one, so a
# faithful answer passes through byte-for-byte. This is what lets even a local
# model hit 0 hallucinations.
_GG_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_GG_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_GG_CVE_RE  = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GG_LIST_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")
# MD5 (32) / SHA-1 (40) / SHA-256 (64) hex digests — longest alternative first so
# the whole digest is consumed, with \b anchors so a 64-hex isn't split into a 32.
_GG_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_GG_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
# Only treat a dotted token as a *domain* when its last label is a real TLD. This
# keeps the redactor off file names (app.py, index.html), Wireshark-style field
# references (tcp.port), version strings and abbreviations (e.g., i.e.) — none of
# which are domains — while still catching an invented C2 like "evil-c2.top".
# Deliberately EXCLUDES the ccTLDs id/in/it: those collide with code identifiers
# (session.id, sign.in) far more often than they name a real C2. An invented C2
# almost always uses a common gTLD (.com/.net/.top/.xyz/...), all still covered.
_GG_TLDS = frozenset("""
com net org io co info biz xyz top online site club shop app dev me tv cc ws
ru cn uk de fr nl eu us ca au jp kr br es pl se no fi dk ch at be cz sk
ua ro gr pt hu tr ir za mx ar cl hk tw sg my th vn ph pk ng ke gov edu mil
int pro name mobi asia tel cat live icu vip work link click pw su cf gq ml ga
""".split())


def _gg_enabled() -> bool:
    """Grounding guardrail is on by default; PACKETIQ_GROUNDING_GUARD=0 disables it
    (used only to measure the raw model, e.g. in the evaluation harness)."""
    env = _read_env()
    flag = (os.environ.get("PACKETIQ_GROUNDING_GUARD")
            or env.get("PACKETIQ_GROUNDING_GUARD") or "1").strip().lower()
    return flag not in ("0", "false", "no", "off")


def _gg_valid_ips(text: str) -> set:
    out = set()
    for m in _GG_IP_RE.findall(text or ""):
        try:
            ipaddress.ip_address(m)   # reject dotted numbers that aren't real IPs
            out.add(m)
        except ValueError:
            pass
    return out


def _gg_domains(text: str) -> set:
    """Domains (lowercased) whose final label is a real TLD — the TLD gate keeps
    file names / field references out of the entity set (see _GG_TLDS)."""
    out = set()
    for m in _GG_DOMAIN_RE.findall(text or ""):
        d = m.lower()
        if d.rsplit(".", 1)[-1] in _GG_TLDS:
            out.add(d)
    return out


def _gg_hashes(text: str) -> set:
    return {h.lower() for h in _GG_HASH_RE.findall(text or "")}


def _grounding_allowed(context: str, messages: list) -> dict:
    """The set of specific entities the copilot is allowed to state: everything in
    the evidence context PLUS anything in the analyst's own questions (referencing
    what you were asked about is legitimate — inventing new entities is not). This
    mirrors exactly how the faithfulness harness defines 'grounded'."""
    txt = context or ""
    for m in messages or []:
        if isinstance(m, dict) and m.get("role") == "user":
            txt += "\n" + str(m.get("content", ""))
    return {
        "ips":        _gg_valid_ips(txt),
        "techniques": {t.upper() for t in _GG_TECH_RE.findall(txt)},
        "cves":       {c.upper() for c in _GG_CVE_RE.findall(txt)},
        "domains":    _gg_domains(txt),
        "hashes":     _gg_hashes(txt),
    }


class _GroundingFilter:
    """Streaming redactor. Fed the model's chunks; yields the same text with any
    ungrounded IP / technique ID / CVE removed. Entities never span whitespace, so
    it flushes on line boundaries (and, for long unbroken prose, at the last
    whitespace) — a token is only ever scrubbed once it has fully arrived, so an
    entity can never be split across a redaction point."""

    def __init__(self, allowed: dict):
        self.allowed = allowed
        self.buf = ""

    def feed(self, chunk: str) -> str:
        self.buf += chunk
        out = []
        while True:
            nl = self.buf.find("\n")
            if nl == -1:
                break
            line, self.buf = self.buf[:nl + 1], self.buf[nl + 1:]
            out.append(self._scrub_line(line))
        # Safety valve: don't stall the stream on a very long line with no newline
        # yet — flush a whole-token prefix (up to the last whitespace) meanwhile.
        if len(self.buf) > 160:
            ws = max(self.buf.rfind(" "), self.buf.rfind("\t"))
            if ws > 0:
                seg, self.buf = self.buf[:ws + 1], self.buf[ws + 1:]
                out.append(self._redact(seg)[0])
        return "".join(out)

    def flush(self) -> str:
        seg, self.buf = self.buf, ""
        return self._scrub_line(seg) if seg else ""

    def _scrub_line(self, line: str) -> str:
        new, removed = self._redact(line)
        if not removed:
            return line                      # faithful line passes through untouched
        # Drop a list item ONLY when its every specific claim was invented; if a
        # grounded entity survives in it, keep the item (never hide real evidence).
        if _GG_LIST_RE.match(line) and not self._has_entity(new):
            return ""
        new = re.sub(r"[ \t]{2,}", " ", new)
        new = re.sub(r"\(\s*\)", "", new)          # empty parens left by removal
        new = re.sub(r"[ \t]+([,.;:])", r"\1", new)  # space before punctuation
        return new

    @staticmethod
    def _has_entity(text: str) -> bool:
        """Any specific claim still present after redaction — by construction it can
        only be a grounded one (ungrounded entities are already gone). Uses the same
        validated/TLD-gated extractors as the allowed-set, so prose like 'app.py'
        never counts as an entity."""
        return bool(_GG_TECH_RE.search(text) or _GG_CVE_RE.search(text)
                    or _GG_HASH_RE.search(text) or _gg_valid_ips(text)
                    or _gg_domains(text))

    def _redact(self, text: str):
        removed = False

        def ip_sub(m):
            nonlocal removed
            tok = m.group(0)
            try:
                ipaddress.ip_address(tok)
            except ValueError:
                return tok                   # not a real IP — leave it be
            if tok in self.allowed["ips"]:
                return tok
            removed = True
            return ""

        def tech_sub(m):
            nonlocal removed
            tok = m.group(0)
            if tok.upper() in self.allowed["techniques"]:
                return tok
            removed = True
            return ""

        def cve_sub(m):
            nonlocal removed
            tok = m.group(0)
            if tok.upper() in self.allowed["cves"]:
                return tok
            removed = True
            return ""

        def hash_sub(m):
            nonlocal removed
            tok = m.group(0)
            if tok.lower() in self.allowed["hashes"]:
                return tok
            removed = True
            return ""

        def domain_sub(m):
            nonlocal removed
            tok = m.group(0)
            low = tok.lower()
            if low.rsplit(".", 1)[-1] not in _GG_TLDS:
                return tok               # last label isn't a TLD → not a domain
            allowed = self.allowed["domains"]
            # exact match, or the registrable parent of an observed FQDN (evidence
            # a.b.evil.com lets the model say evil.com) — but not an invented child.
            if low in allowed or any(e == low or e.endswith("." + low) for e in allowed):
                return tok
            removed = True
            return ""

        text = _GG_IP_RE.sub(ip_sub, text)
        text = _GG_TECH_RE.sub(tech_sub, text)
        text = _GG_CVE_RE.sub(cve_sub, text)
        text = _GG_HASH_RE.sub(hash_sub, text)
        text = _GG_DOMAIN_RE.sub(domain_sub, text)
        return text, removed


async def _stream_ai(provider: str, key: str, model: str,
                     system: str, context: str,
                     messages: list, max_tokens: int = 2048) -> "AsyncGenerator[str, None]":
    """Unified async streaming across all providers, with the grounding guardrail
    applied so no ungrounded IP/technique/CVE ever reaches the caller."""
    if not _gg_enabled():
        async for chunk in _stream_ai_raw(provider, key, model, system, context, messages, max_tokens):
            yield chunk
        return
    gf = _GroundingFilter(_grounding_allowed(context, messages))
    async for chunk in _stream_ai_raw(provider, key, model, system, context, messages, max_tokens):
        out = gf.feed(chunk)
        if out:
            yield out
    tail = gf.flush()
    if tail:
        yield tail


async def _stream_ai_raw(provider: str, key: str, model: str,
                         system: str, context: str,
                         messages: list, max_tokens: int = 2048) -> "AsyncGenerator[str, None]":
    """Unified async streaming across all providers. Yields raw text chunks.
    `max_tokens` caps the reply length; keep it small for short tasks (e.g. a
    single-packet explanation) so generation — the slow part on a local model —
    stays fast."""
    import warnings

    if provider == "gemini":
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from google import genai as _genai
            from google.genai import types as _gtypes
        client = _genai.Client(api_key=key)
        system_full = system + "\n\n<pcap_analysis>\n" + context + "\n</pcap_analysis>"
        gemini_msgs = [
            _gtypes.Content(
                role="user" if m["role"] == "user" else "model",
                parts=[_gtypes.Part(text=m["content"])]
            )
            for m in messages
        ]
        async for chunk in await client.aio.models.generate_content_stream(
            model   = model,
            contents= gemini_msgs,
            config  = _gtypes.GenerateContentConfig(
                system_instruction = system_full,
                max_output_tokens  = max_tokens,
                temperature        = _AI_TEMPERATURE,
            ),
        ):
            if chunk.text:
                yield chunk.text

    elif provider == "groq":
        from groq import AsyncGroq
        client = AsyncGroq(api_key=key)
        groq_messages = [
            {"role": "system", "content": system + "\n\n<pcap_analysis>\n" + context + "\n</pcap_analysis>"}
        ] + messages
        stream = await client.chat.completions.create(
            model      = model,
            messages   = groq_messages,
            max_tokens = max_tokens,
            temperature= _AI_TEMPERATURE,
            stream     = True,
        )
        async for chunk in stream:
            text = chunk.choices[0].delta.content or ""
            if text:
                yield text

    elif provider == "anthropic":
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=key)
        system_blocks = [
            {"type": "text", "text": system},
            {"type": "text", "text": f"<pcap_analysis>\n{context}\n</pcap_analysis>",
             "cache_control": {"type": "ephemeral"}},
        ]
        async with client.messages.stream(
            model       = model,
            max_tokens  = max_tokens,
            temperature = _AI_TEMPERATURE,
            system      = system_blocks,
            messages    = messages,
        ) as stream:
            async for chunk in stream.text_stream:
                yield chunk

    elif provider == "ollama":
        # Local, offline runtime. Native /api/chat with NDJSON streaming.
        # `key` carries the daemon host (set by _detect_provider for ollama).
        import json as _json

        import httpx
        host = (key or _ollama_host()).rstrip("/")
        sys_full = system + "\n\n<pcap_analysis>\n" + context + "\n</pcap_analysis>"
        ollama_messages = [{"role": "system", "content": sys_full}] + messages
        prompt_chars = len(sys_full) + sum(len(m.get("content", "")) for m in messages)
        options: dict = {
            "temperature": _AI_TEMPERATURE,
            "num_predict": max_tokens,
            # Size the window to the prompt so grounding isn't truncated.
            "num_ctx":     _ollama_num_ctx(prompt_chars, max_tokens),
        }
        seed = _ollama_seed()
        if seed is not None:
            # Same evidence in, same words out — the copilot's prose is part of a
            # forensic report and must survive being regenerated.
            options["seed"] = seed
        payload = {
            "model":      model,
            "messages":   ollama_messages,
            "stream":     True,
            # Keep the model resident between requests — avoids the cold-reload
            # that makes an idle local copilot feel slow.
            "keep_alive": _ollama_keep_alive(),
            "options":    options,
        }
        timeout = httpx.Timeout(300.0, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout) as hc:
            async with hc.stream("POST", host + "/api/chat", json=payload) as resp:
                if resp.status_code != 200:
                    body = (await resp.aread()).decode("utf-8", "replace")[:300]
                    if resp.status_code == 404:
                        raise RuntimeError(
                            f"Ollama model '{model}' not found. Pull it first: "
                            f"`ollama pull {model}`")
                    raise RuntimeError(f"Ollama HTTP {resp.status_code}: {body}")
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        obj = _json.loads(line)
                    except ValueError:
                        continue
                    if obj.get("error"):
                        raise RuntimeError(f"Ollama error: {obj['error']}")
                    piece = (obj.get("message") or {}).get("content", "")
                    if piece:
                        yield piece
                    if obj.get("done"):
                        break


_AI_LABEL = {"gemini": "Google Gemini", "groq": "Groq", "anthropic": "Anthropic",
             "ollama": "Local (Ollama)"}

# System prompt for the per-packet AI explainer. The packet arrives as a decoded
# analyst fact sheet (see inspect.analyst_brief), so the model reasons like a
# senior network-forensics analyst instead of paraphrasing raw scapy fields.
# It must answer plain text in five labelled sections — the UI renders those into
# a styled triage card, so any Markdown the model emitted would leak as literal
# asterisks. _parse_explanation() still strips stray Markdown defensively.
_PACKET_EXPLAIN_SYSTEM = (
    "You are PacketIQ Copilot, a senior network-forensics analyst writing a triage note on ONE "
    "packet for a SOC colleague. You are given a decoded fact sheet for that packet.\n\n"
    "OUTPUT FORMAT — plain text only. Emit exactly these six labels, each starting a new line, "
    "in this order. Do NOT use Markdown: no asterisks, no bold, no headings, no numbering.\n\n"
    "VERDICT: exactly one of Benign, Informational, Worth a look, or Suspicious. Write the label, "
    "then a dash and at most eight words saying why. Nothing more.\n"
    "SUMMARY: one or two sentences stating what this packet is and what the two endpoints are "
    "doing, naming the protocol and the service involved.\n"
    "ORIGIN: one or two sentences on where it came from and where it is going — which side is "
    "internal and which is external, which is the client and which is the server, and what the TTL "
    "suggests about the sender's operating system and how many hops away it is.\n"
    "KEY POINTS: three to six bullets, each on its own line beginning with '- '. Start each bullet "
    "with a short label, then a colon, then one concise fact. Cover only what is present: host "
    "roles, ports and direction, TTL and OS hint, TCP flags or handshake state, payload entropy "
    "(encrypted, compressed or plaintext), and any decoded name such as a TLS SNI, HTTP host or "
    "DNS query. Keep each bullet to one line.\n"
    "ASSESSMENT: two or three sentences on whether this is suspicious and why or why not, citing "
    "the concrete evidence — encrypted versus cleartext, payload entropy, whether the port matches "
    "the protocol, exposure to an external host, handshake state. Say plainly if it is ordinary "
    "traffic.\n"
    "ACTION: one concrete next step for the analyst. If nothing is wrong, say 'No action — normal "
    "traffic' and name the single check that would confirm it.\n\n"
    "RULES: Use ONLY facts from the fact sheet. Never invent IP addresses, ports, domains, payload "
    "or intent the data does not support. Refer to ports by number. TTL and entropy are hints — say "
    "'consistent with', never 'is'. Write full sentences in precise SOC language: no filler, no "
    "restating the sheet verbatim. One packet in isolation is usually normal — do not manufacture "
    "threat where there is none.")

# Canonical section keys, plus the aliases a model may drift to. Longest alias is
# matched first so "KEY FIELDS THAT MATTER" wins over "KEY FIELDS".
_EXPLAIN_ALIASES = {
    "VERDICT": "verdict",
    "SUMMARY": "summary",
    "WHAT THIS PACKET IS": "summary",
    "ORIGIN": "origin",
    "WHERE IT COMES FROM": "origin",
    "KEY POINTS": "key_points",
    "KEY FIELDS THAT MATTER": "key_points",
    "KEY FIELDS": "key_points",
    "ASSESSMENT": "assessment",
    "IS IT SUSPICIOUS": "assessment",
    "INDICATORS & CONTEXT": "assessment",
    "INDICATORS AND CONTEXT": "assessment",
    "INDICATORS": "assessment",
    "ACTION": "action",
    "RECOMMENDED NEXT STEP": "action",
    "RECOMMENDED ACTION": "action",
}
# A label may be followed by a separator and text, or stand alone on its own line
# (models often write a bare heading, then the content beneath it).
_EXPLAIN_LABEL_RE = re.compile(
    r"^\s*[#*\-•\s]*(?:\*\*)?\s*("
    + "|".join(re.escape(a) for a in sorted(_EXPLAIN_ALIASES, key=len, reverse=True))
    + r")\s*\??\s*[*_]*\s*(?:[:\-–—]\s*(.*))?$",
    re.IGNORECASE)
_BULLET_RE = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+(.*)$")
# Sections that make a parsed answer worth rendering as a card at all.
_SUBSTANTIVE_SECTIONS = {"summary", "origin", "key_points", "assessment", "action"}
_VERDICT_REASON_MAX = 120
# Verdict labels, longest first so "worth a look" beats a bare prefix match.
_VERDICTS = ("informational", "worth a look", "suspicious", "malicious", "benign")
_VERDICT_KEYS = {"benign": "benign", "informational": "informational",
                 "worth a look": "review", "suspicious": "suspicious",
                 "malicious": "suspicious"}


def _strip_markdown(s: str) -> str:
    """Remove Markdown decoration a model may add despite the plain-text rule."""
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    s = re.sub(r"[*_`]{1,3}", "", s)
    s = re.sub(r"^\s*[#>\-•]+\s*", "", s, flags=re.MULTILINE)
    return " ".join(s.split()).strip()


def _verdict_key(verdict: str) -> str:
    low = (verdict or "").strip().lower()
    for label in sorted(_VERDICTS, key=len, reverse=True):
        if low.startswith(label):
            return _VERDICT_KEYS[label]
    return "informational"


def _split_verdict(raw: str) -> tuple:
    """Separate the verdict label from any reason the model appended, so the UI can
    show a clean badge ('Worth a look') beside its justification."""
    txt = _strip_markdown(raw)
    low = txt.lower()
    for label in sorted(_VERDICTS, key=len, reverse=True):
        if low.startswith(label):
            reason = txt[len(label):].lstrip(" :;,.–—-").strip()
            return txt[:len(label)], reason
    return (txt.split(".")[0][:40].strip(), "")


def _bullets(lines: list) -> list:
    """Turn the KEY POINTS block into a clean list, whether or not the model used
    bullet characters."""
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _BULLET_RE.match(line)
        text = _strip_markdown(m.group(1) if m else line)
        if text:
            out.append(text)
    return out


def _parse_explanation(text: str) -> dict:
    """Split the model's labelled triage note into sections the UI can style.
    Returns {} if the model ignored the format, so callers can fall back to prose."""
    sections: dict = {}
    current = None
    buf: list = []

    def flush():
        if not current:
            return
        if current == "key_points":
            pts = _bullets(buf)
            if pts:
                sections["key_points"] = pts
        else:
            val = _strip_markdown(" ".join(buf))
            if val:
                sections[current] = val

    for line in (text or "").splitlines():
        m = _EXPLAIN_LABEL_RE.match(line)
        if m:
            flush()
            current = _EXPLAIN_ALIASES[m.group(1).upper()]
            buf = [m.group(2) or ""]        # bare heading → content starts next line
        elif current:
            buf.append(line)
    flush()

    if sections.get("verdict"):
        label, reason = _split_verdict(sections["verdict"])
        sections["verdict"] = label
        sections["verdict_key"] = _verdict_key(label)
        if reason:
            # The badge line takes a short phrase. Anything longer is really the
            # summary (a model that ran its whole answer onto one line) — keep the
            # content rather than stretching the header.
            if len(reason) <= _VERDICT_REASON_MAX:
                sections["verdict_reason"] = reason
            elif "summary" not in sections:
                sections["summary"] = reason

    # A lone verdict with no substance isn't a structured answer — let the caller
    # fall back to rendering the model's prose properly.
    if not _SUBSTANTIVE_SECTIONS & set(sections):
        return {}
    return sections

# Shown when no provider is usable — covers both the cloud-key and local-LLM paths.
_NO_PROVIDER_HINT = (
    "No AI provider available. Either add a free API key (GEMINI_API_KEY or "
    "GROQ_API_KEY) to your .env, or run a local model with Ollama (no key, fully "
    "offline): install Ollama, `ollama pull qwen2.5:7b-instruct`, then `ollama serve`.")


def _is_rate_limit(msg: str) -> bool:
    m = msg.lower()
    return "429" in msg or "resource_exhausted" in m or "quota" in m or "rate limit" in m


# A rejected key does not fix itself in a few seconds, so bench that provider for
# a while rather than re-failing on every single message.
_AUTH_COOLDOWN_SECS = 300.0
_AUTH_MARKERS = ("401", "403", "api key not valid", "api_key_invalid", "invalid api key",
                 "invalid_api_key", "unauthorized", "permission denied", "authentication")


def _is_auth_error(msg: str) -> bool:
    """A credential problem — wrong, revoked or unauthorised key."""
    m = (msg or "").lower()
    return any(marker in m for marker in _AUTH_MARKERS)


def _is_exhausted_quota(msg: str) -> bool:
    """A quota that will not recover in the next few seconds — a *per-day* limit, or
    a free tier of literally zero. Google reports 'Please retry in 8s' even in this
    case, so honouring its retryDelay makes us re-fail on every single message."""
    m = (msg or "").lower()
    return "perday" in m.replace(" ", "") or "limit: 0" in m or "limit:0" in m


def _is_model_unusable(msg: str) -> bool:
    """The failure is specific to the *model*, so another model of the same
    provider may well work: a zero free-tier allowance (`limit: 0`, which Google
    reports per model), or a model id this key cannot address at all."""
    m = (msg or "").lower()
    if "limit: 0" in m or "limit:0" in m:
        return True
    if "not_found" in m or ("404" in m and "model" in m):
        return True
    return "is not found for api version" in m or "does not exist" in m


def _note_provider_failure(name: str, msg: str) -> None:
    """Record why a provider failed so the next request skips it instead of
    repeating the same doomed call. Transient/unknown errors are not cooled down."""
    if _is_rate_limit(msg):
        if _is_exhausted_quota(msg):
            _mark_cooldown(name, _LONG_COOLDOWN_SECS, _LONG_COOLDOWN_SECS)
        else:
            _mark_cooldown(name, _retry_after_seconds(msg))
    elif _is_auth_error(msg):
        _mark_cooldown(name, _AUTH_COOLDOWN_SECS)


def _failure_reason(msg: str) -> str:
    """A short phrase for the switch notice, e.g. 'Google Gemini quota reached'."""
    if _is_rate_limit(msg):
        return "daily quota used up" if _is_exhausted_quota(msg) else "quota reached"
    if _is_auth_error(msg):
        return "key rejected"
    return "unavailable"


def _friendly_ai_error(label: str, msg: str, exhausted: bool) -> str:
    """The message shown once *every* provider has failed."""
    if exhausted and _is_rate_limit(msg):
        return ("**All AI providers have hit their rate limits.**\n\n"
                "Wait a minute and try again, or add another key in `.env`. "
                "A local Ollama model has no rate limit at all.")
    if _is_auth_error(msg):
        return (f"**{label} rejected its API key.**\n\n"
                "Check the key in `.env` — and note that a key exported in your shell "
                "overrides `.env`. Restart the server after fixing it.")
    return f"**AI error ({label}):** {msg[:200]}"


async def _collect_ai_with_fallback(system: str, context: str, messages: list,
                                    max_tokens: int = 2048) -> str:
    """
    Collect a full (non-streamed) AI response, automatically falling back across
    configured providers (Gemini → Groq → Anthropic) when one is rate-limited or
    errors. Raises RuntimeError with a friendly message if all providers fail or
    none is configured.
    """
    current = _detect_provider()
    if not current["provider"]:
        raise RuntimeError(_NO_PROVIDER_HINT)
    skipped: set = set()
    last_err = ""
    while current["provider"]:
        try:
            text = ""
            async for chunk in _stream_ai(current["provider"], current["key"],
                                          current["model"], system, context, messages,
                                          max_tokens):
                text += chunk
            if text.strip():
                return text
            last_err = f"{_AI_LABEL.get(current['provider'])} returned an empty response."
        except Exception as exc:  # noqa: BLE001
            last_err = str(exc)
            # A model-scoped failure means "wrong model", not "dead provider":
            # retry the same provider on its next candidate before giving up on it.
            if _is_model_unusable(last_err):
                _mark_model_dead(current["provider"], current["model"])
                alt = _next_model(current["provider"], current["model"])
                if alt:
                    current = {**current, "model": alt}
                    continue
            # Sticky auto-switch: remember this provider is exhausted or its key was
            # rejected, so the next request goes straight to a healthy one.
            _note_provider_failure(current["provider"], last_err)
        # try the next configured provider
        skipped.add(current["provider"])
        current = _detect_provider(skip=skipped)

    if _is_rate_limit(last_err):
        raise RuntimeError("All configured AI providers have hit their rate limits. "
                           "Wait a minute and try again, add another key (GROQ_API_KEY is "
                           "free), or run a local model with Ollama (no rate limits).")
    if "401" in last_err or "invalid" in last_err.lower() or "authentication" in last_err.lower():
        raise RuntimeError("An AI API key appears invalid. Check your keys in .env and restart.")
    raise RuntimeError(f"AI request failed: {last_err[:300]}")


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(title="PacketIQ", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def _security_guard(request: Request, call_next):
        """Defends the local server against DNS-rebinding (Host-header check) and
        cross-site request forgery (Origin check on state-changing methods).
        A malicious web page must not be able to drive this API from the user's
        browser. The allow-list is loopback by default; the launcher widens it
        when the operator deliberately binds to a non-loopback address."""
        allowed = _allowed_hosts()
        wild = "*" in allowed
        host = request.headers.get("host", "").rsplit(":", 1)[0].strip("[]").lower()
        if not wild and host and host not in allowed:
            return JSONResponse({"detail": "Invalid Host header (possible DNS-rebinding)."}, status_code=400)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and not wild:
                from urllib.parse import urlparse
                oh = (urlparse(origin).hostname or "").lower()
                if oh and oh not in allowed:
                    return JSONResponse({"detail": "Cross-origin request blocked (CSRF)."}, status_code=403)
        return await call_next(request)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        # Inject the real upload cap so the page's hint text and client-side size
        # guard always match the server (which enforces MAX_UPLOAD_MB, env-overridable)
        # — never a hard-coded figure that could drift from the backend.
        label = (f"{MAX_UPLOAD_MB // 1024} GB" if MAX_UPLOAD_MB >= 1024 and MAX_UPLOAD_MB % 1024 == 0
                 else f"{MAX_UPLOAD_MB / 1024:.1f} GB" if MAX_UPLOAD_MB >= 1024
                 else f"{MAX_UPLOAD_MB} MB")
        html = (TEMPLATE.read_text(encoding="utf-8")
                .replace("__MAX_UPLOAD_MB__", str(MAX_UPLOAD_MB))
                .replace("__MAX_UPLOAD_LABEL__", label))
        return HTMLResponse(html)

    @app.get("/static/vendor/{name}")
    async def vendor_asset(name: str):
        """Serve the bundled front-end libraries (Chart.js, marked) locally so the
        app needs no CDN and runs fully offline. Allow-listed — no path traversal."""
        media = _VENDOR_ASSETS.get(name)
        if media is None:
            raise HTTPException(404, "Unknown asset.")
        path = STATIC_DIR / "vendor" / name
        if not path.is_file():
            raise HTTPException(404, "Asset not bundled.")
        return Response(path.read_bytes(), media_type=media,
                        headers={"Cache-Control": "public, max-age=86400"})

    @app.post("/api/upload")
    async def upload(file: UploadFile = File(...)):
        fname = os.path.basename(file.filename or "upload.pcap")   # strip any path components
        if not fname.lower().endswith(SUPPORTED_UPLOAD_EXT):
            raise HTTPException(400, "Upload a packet capture (.pcap/.pcapng/.cap), a Zeek conn.log "
                                     "(.log/.tsv/.json), or a NetFlow/IPFIX export (.netflow/.nfcapd/.ipfix).")

        job_id    = str(uuid.uuid4())
        pcap_path = UPLOAD_DIR / f"{job_id}.pcap"
        # Stream to disk with a hard byte cap so a huge upload can't exhaust RAM
        # or fill the disk (the size check happens DURING the read, not after).
        written = await _stream_upload_to(file, pcap_path)
        if written < 24:
            pcap_path.unlink(missing_ok=True)
            raise HTTPException(400, "File is too small to be a valid capture.")
        size_mb = written / (1024 * 1024)

        _jobs[job_id] = {
            "status":    "running",
            "queue":     asyncio.Queue(),
            "result":    None,
            "error":     None,
            "filename":  fname,
            "size_mb":   round(size_mb, 2),
            "pcap_path": str(pcap_path),
        }

        asyncio.create_task(_analyze_task(job_id, str(pcap_path)))
        return {"job_id": job_id, "filename": fname, "size_mb": round(size_mb, 2)}

    @app.post("/api/fuse")
    async def fuse_upload(files: list[UploadFile] = File(...)):
        """Campaign analysis across multiple captures (the GUI form of `packetiq fuse`)."""
        caps = [f for f in files if (f.filename or "").lower().endswith((".pcap", ".pcapng", ".cap"))]
        if len(caps) < 2:
            raise HTTPException(400, "Select at least 2 packet captures to fuse into a campaign.")
        if len(caps) > 50:
            raise HTTPException(400, "Too many captures (max 50 per campaign).")
        job_id = str(uuid.uuid4())
        paths, names, total = [], [], 0
        for i, f in enumerate(caps):
            p = UPLOAD_DIR / f"{job_id}_{i}.pcap"
            total += await _stream_upload_to(f, p)   # bounded, streamed (no full read into RAM)
            paths.append(str(p))
            names.append(os.path.basename(f.filename or f"capture_{i}.pcap"))
        _jobs[job_id] = {
            "status": "running", "queue": asyncio.Queue(), "result": None, "error": None,
            "filename": f"Campaign ({len(caps)} captures)", "size_mb": round(total / (1024 * 1024), 2),
            "campaign": True, "pcap_paths": paths, "pcap_path": paths[0], "source_names": names,
        }

        async def _task():
            loop = asyncio.get_event_loop()
            data = await loop.run_in_executor(None, _run_fuse, job_id, paths, loop)
            _jobs[job_id]["result"] = data
            _jobs[job_id]["status"] = "complete" if data is not None else "error"
            _evict_old_jobs()

        asyncio.create_task(_task())
        return {"job_id": job_id, "filename": _jobs[job_id]["filename"], "files": names}

    @app.websocket("/ws/{job_id}")
    async def ws_progress(websocket: WebSocket, job_id: str):
        if job_id not in _jobs:
            await websocket.close(1008)
            return
        await websocket.accept()
        job = _jobs[job_id]

        # Already finished before WS connected
        if job["status"] == "complete":
            await websocket.send_text(json.dumps({"type": "complete"}))
            await websocket.close()
            return
        if job["status"] == "error":
            await websocket.send_text(json.dumps({"type": "error", "message": job.get("error", "Unknown error")}))
            await websocket.close()
            return

        queue = job["queue"]
        try:
            while True:
                msg = await asyncio.wait_for(queue.get(), timeout=600)
                await websocket.send_text(json.dumps(msg))
                if msg.get("type") in ("complete", "error"):
                    break
        except (asyncio.TimeoutError, WebSocketDisconnect):
            pass
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    @app.get("/api/results/{job_id}")
    async def results(job_id: str):
        if job_id not in _jobs:
            raise HTTPException(404, "Job not found.")
        job = _jobs[job_id]
        if job["status"] == "error":
            raise HTTPException(500, job.get("error") or "Analysis failed.")
        if job["status"] != "complete" or job["result"] is None:
            raise HTTPException(202, "Analysis still in progress.")
        # Exclude large blobs — they have dedicated endpoints
        payload = {k: v for k, v in job["result"].items() if k not in ("html_report", "misp")}
        return JSONResponse(payload)

    @app.post("/api/analyze")
    async def analyze_sync(file: UploadFile = File(...)):
        """Synchronous REST endpoint: upload a PCAP, get the full analysis JSON.
        Intended for scripts / CI (no WebSocket needed)."""
        fname = file.filename or "upload.pcap"
        content = await file.read()
        is_flow_magic = len(content) >= 2 and struct.unpack("!H", content[:2])[0] in (5, 9, 10)
        if not (fname.lower().endswith(SUPPORTED_UPLOAD_EXT) or is_flow_magic):
            raise HTTPException(400, "Upload a PCAP/PCAPNG/CAP, a Zeek conn.log, or a NetFlow/IPFIX export.")
        if len(content) < 24:
            raise HTTPException(400, "File is too small to be a valid capture.")

        job_id = str(uuid.uuid4())
        pcap_path = UPLOAD_DIR / f"{job_id}.pcap"
        pcap_path.write_bytes(content)
        _jobs[job_id] = {
            "status": "running", "queue": asyncio.Queue(), "result": None,
            "error": None, "filename": fname,
            "size_mb": round(len(content) / (1024 * 1024), 2), "pcap_path": str(pcap_path),
        }
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, _run_analysis, job_id, str(pcap_path), loop)
        _jobs[job_id]["result"] = data
        _jobs[job_id]["status"] = "complete" if data else "error"
        # retain the pcap (packet browser / evidence); _evict_old_jobs prunes old ones
        _evict_old_jobs()
        if data is None:
            raise HTTPException(500, "Analysis failed.")
        return JSONResponse({"job_id": job_id, **data})

    @app.get("/api/report/{job_id}.html")
    async def html_report(job_id: str, print: int = 0):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        report = _jobs[job_id]["result"].get("html_report", "<h1>No report</h1>")
        if print:
            # auto-open the browser print dialog → "Save as PDF"
            report = report.replace("</body>", "<script>window.onload=function(){setTimeout(function(){window.print();},400);};</script></body>")
        return HTMLResponse(report)

    @app.get("/api/history")
    async def history(limit: int = 50):
        from packetiq.storage import recent
        return {"analyses": recent(limit)}

    @app.delete("/api/history")
    async def history_clear():
        from packetiq.storage import clear
        return {"cleared": clear()}

    @app.delete("/api/history/{analysis_id}")
    async def history_delete(analysis_id: int):
        from packetiq.storage import delete
        return {"deleted": delete(analysis_id)}

    # ── Packet browser (every packet, search, drill-down) ───────────────
    @app.get("/api/packets/{job_id}")
    async def packets_list(job_id: str, offset: int = 0, limit: int = 200, q: str = ""):
        paths = _job_pcap_paths(job_id)
        if not paths:
            raise HTTPException(410, "The capture for this job is no longer available.")
        from packetiq.inspect import matches, summarize
        limit = max(1, min(limit, 1000))

        def _collect():
            out, matched = [], 0
            for idx, pkt in _iter_packets(paths):
                s = summarize(pkt, idx)
                if matches(s, q):
                    if matched >= offset and len(out) < limit:
                        out.append(s)
                    matched += 1
                    if not q and matched >= offset + limit:
                        # no search: we have the page; total comes from meta
                        return out, matched, True
            return out, matched, matched > offset + limit

        loop = asyncio.get_event_loop()
        rows, matched, has_more = await loop.run_in_executor(None, _collect)
        meta_total = None
        if not q and _jobs[job_id].get("result"):
            meta_total = _jobs[job_id]["result"].get("meta", {}).get("total_packets")
        return {"packets": rows, "offset": offset, "limit": limit,
                "matched": matched, "total": meta_total, "has_more": has_more}

    @app.get("/api/packets/{job_id}/{index}")
    async def packet_detail(job_id: str, index: int):
        paths = _job_pcap_paths(job_id)
        if not paths:
            raise HTTPException(410, "The capture for this job is no longer available.")
        from packetiq.inspect import dissect

        def _find():
            for idx, pkt in _iter_packets(paths):
                if idx == index:
                    return dissect(pkt, idx)
            return None

        loop = asyncio.get_event_loop()
        d = await loop.run_in_executor(None, _find)
        if d is None:
            raise HTTPException(404, "Packet not found.")
        return d

    @app.post("/api/packets/{job_id}/{index}/explain")
    async def packet_explain(job_id: str, index: int):
        paths = _job_pcap_paths(job_id)
        if not paths:
            raise HTTPException(410, "The capture for this job is no longer available.")
        if not _detect_provider()["provider"]:
            raise HTTPException(503, _NO_PROVIDER_HINT)
        from packetiq.inspect import analyst_brief, analyst_facts, summarize

        def _find():
            for idx, pkt in _iter_packets(paths):
                if idx == index:
                    return analyst_brief(pkt, idx), analyst_facts(pkt, idx), summarize(pkt, idx)
            return None

        loop = asyncio.get_event_loop()
        found = await loop.run_in_executor(None, _find)
        if found is None:
            raise HTTPException(404, "Packet not found.")
        pkt_text, facts, summary = found
        try:
            text = await _collect_ai_with_fallback(
                _PACKET_EXPLAIN_SYSTEM, pkt_text,
                [{"role": "user", "content": "Analyse this packet:\n\n" + pkt_text}],
                max_tokens=900)
        except RuntimeError as exc:
            raise HTTPException(502, str(exc)) from exc
        # `sections` drives the styled triage card; `facts` is the deterministic
        # evidence panel (straight from the packet, never from the model).
        return {"explanation": text, "sections": _parse_explanation(text),
                "facts": facts, "summary": summary}

    # ── Live capture ────────────────────────────────────────────────────
    @app.get("/api/live/interfaces")
    async def live_interfaces():
        default = None
        try:
            from scapy.all import get_if_list
            from scapy.config import conf
            ifs = list(get_if_list())
            default = str(conf.iface) if conf.iface else None
            # surface the active interface first so users don't default to lo0
            if default in ifs:
                ifs = [default] + [i for i in ifs if i != default]
        except Exception:
            ifs = []
        capture_ok, plat = _capture_privilege()
        return {"interfaces": ifs, "default": default, "platform": plat,
                "elevated": capture_ok, "capture_ok": capture_ok}

    @app.post("/api/live/setup-capture")
    async def live_setup_capture():
        """One-time, OS-native setup so live capture works without per-run sudo.
        On macOS this triggers a GUI admin-password prompt (ChmodBPF, like
        Wireshark); on Linux it runs setcap; on Windows it reports Npcap status."""
        from packetiq import capture_setup
        loop = asyncio.get_event_loop()
        try:
            ok, msg = await loop.run_in_executor(None, capture_setup.setup)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(500, f"Capture setup failed: {exc}") from exc
        capture_ok, plat = _capture_privilege()
        return {"ok": ok, "message": msg, "platform": plat, "capture_ok": capture_ok}

    @app.post("/api/live/start")
    async def live_start(request: Request):
        body = await request.json()
        iface = (body.get("interface") or "").strip()
        threshold = (body.get("threshold") or "HIGH").upper()
        if not iface:
            raise HTTPException(400, "An interface is required.")
        sess = _LiveSession(iface, threshold)
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, sess.start)
        except (PermissionError, OSError) as exc:
            raise HTTPException(403,
                f"Could not open {iface}: {exc}. Live capture needs capture privileges — "
                "click \"Enable live capture (one-time)\" above (or run `packetiq setup-capture`), "
                "then try again.") from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(500, f"Could not start capture: {exc}") from exc
        await asyncio.sleep(0.7)
        if not sess.alive():
            sess.stop()
            raise HTTPException(403,
                f"Capture on {iface} stopped immediately — this is almost always a permissions issue. "
                "Click \"Enable live capture (one-time)\" above (or run `packetiq setup-capture`) to fix it.")
        sid = str(uuid.uuid4())
        _live_sessions[sid] = sess
        return {"session_id": sid, "interface": iface, "threshold": threshold, "status": "running"}

    @app.get("/api/live/{sid}")
    async def live_poll(sid: str, since: int = 0):
        s = _live_sessions.get(sid)
        if not s:
            raise HTTPException(404, "Live session not found.")
        s.maybe_scan()
        with s._lock:
            new = s.alerts[since:]
            total = len(s.alerts)
        import time as _t
        uptime = round(_t.time() - s.started)
        # Health hint: capture alive but zero packets after a few seconds usually
        # means missing privileges (BPF/root) or a quiet interface.
        hint = ""
        if s.status == "running":
            if not s.alive():
                hint = ("Capture stopped unexpectedly (likely a permissions issue — click "
                        "\"Enable live capture (one-time)\" or run `packetiq setup-capture`).")
            elif s.packets == 0 and uptime >= 6:
                hint = ("No packets captured yet. If this persists, click \"Enable live capture (one-time)\" "
                        "(or run `packetiq setup-capture`), or pick an active interface.")
        return {"status": s.status, "packets": s.packets, "total": total,
                "events": new, "uptime": uptime, "alive": s.alive(), "hint": hint}

    @app.post("/api/live/{sid}/stop")
    async def live_stop(sid: str):
        s = _live_sessions.get(sid)
        if not s:
            raise HTTPException(404, "Live session not found.")
        s.stop()
        return {"status": "stopped", "total": len(s.alerts), "packets": s.packets}

    @app.post("/api/live/{sid}/analyze")
    async def live_analyze(sid: str):
        """Stop the live capture and run the FULL pipeline on what was recorded,
        so it populates every section (Analysis / Network / Events / Timeline…)."""
        s = _live_sessions.get(sid)
        if not s:
            raise HTTPException(404, "Live session not found.")
        s.stop()
        if not Path(s.pcap_path).is_file() or s.packets == 0:
            raise HTTPException(400, "No packets were captured to analyse. "
                                     "Capture some traffic first (and ensure PacketIQ has capture privileges).")
        job_id = str(uuid.uuid4())
        size_mb = round(Path(s.pcap_path).stat().st_size / (1024 * 1024), 2)
        _jobs[job_id] = {
            "status": "running", "queue": asyncio.Queue(), "result": None, "error": None,
            "filename": f"Live capture · {s.interface}", "size_mb": size_mb,
            "pcap_path": s.pcap_path,
        }
        asyncio.create_task(_analyze_task(job_id, s.pcap_path))
        return {"job_id": job_id, "filename": _jobs[job_id]["filename"], "packets": s.packets}

    @app.get("/api/live/{sid}/packets")
    async def live_packets(sid: str, since: int = 0):
        """Every packet seen by the live capture (rolling window), for the live list."""
        s = _live_sessions.get(sid)
        if not s:
            raise HTTPException(404, "Live session not found.")
        with s._lock:
            rows = [p for p in s.pkt_summaries if p.get("no", 0) >= since]
        last = rows[-1]["no"] if rows else (since - 1)
        return {"packets": rows[-500:], "total": s.packets, "last": last}

    @app.get("/api/live/{sid}/pcap")
    async def live_pcap(sid: str):
        s = _live_sessions.get(sid)
        if not s:
            raise HTTPException(404, "Live session not found.")
        s.flush()
        if not Path(s.pcap_path).is_file():
            raise HTTPException(404, "No capture file yet.")
        return Response(
            content=Path(s.pcap_path).read_bytes(),
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="live_{s.interface}_{sid[:8]}.pcap"'},
        )

    # ── Notifications / alert channels ──────────────────────────────────
    def _notify_channels() -> list:
        from packetiq.alerts import channels
        from packetiq.alerts.telegram import load_credentials
        chans = channels.configured_channels()
        tok, cid = load_credentials()
        if tok and cid:
            chans.append("telegram")
        return chans

    @app.get("/api/notify/status")
    async def notify_status():
        return {"channels": _notify_channels()}

    def _send_all(subject: str, text: str) -> dict:
        from packetiq.alerts import channels
        from packetiq.alerts.telegram import TelegramSender, load_credentials
        results = {}
        for chan, (ok, _err) in channels.broadcast(subject, text).items():
            results[chan] = bool(ok)
        tok, cid = load_credentials()
        if tok and cid:
            ok, _ = TelegramSender(tok, cid).send(f"🔔 <b>{subject}</b>\n\n{text}")
            results["telegram"] = bool(ok)
        return results

    def _send_findings(res: dict) -> dict:
        """Send a professional findings brief across all channels and attach a
        full PDF SOC report to Telegram. Telegram gets rich HTML; Slack/e-mail
        get the same content tag-stripped to plain text."""
        import os
        import re
        import shutil
        import tempfile

        from packetiq.alerts import channels, formatter
        from packetiq.alerts.telegram import TelegramSender, esc, load_credentials
        from packetiq.export import build_pdf

        meta = res.get("meta", {}) or {}
        fname = meta.get("filename", "capture")
        rich = formatter.format_webapp_findings(res)
        plain = re.sub(r"<[^>]+>", "", rich)             # HTML → plain for other channels
        subject = f"PacketIQ findings — {fname}"

        results: dict = {}
        for chan, (ok, _err) in channels.broadcast(subject, plain).items():
            results[chan] = bool(ok)

        tok, cid = load_credentials()
        if tok and cid:
            sender = TelegramSender(tok, cid)
            ok, _ = sender.send(rich)
            results["telegram"] = bool(ok)
            # Build + attach a professional PDF report (best-effort).
            tmpdir = tempfile.mkdtemp(prefix="packetiq_")
            try:
                safe = (re.sub(r"[^A-Za-z0-9_.-]+", "_", str(fname)).rsplit(".", 1)[0]
                        or "capture")[:60]
                pdf_path = os.path.join(tmpdir, f"PacketIQ_Report_{safe}.pdf")
                if build_pdf(pdf_path, res):
                    risk = res.get("risk", {}) or {}
                    caption = (f"📄 <b>PacketIQ SOC Report</b> — {esc(fname)}\n"
                               f"Risk {esc(risk.get('score', 0))}/100 "
                               f"[{esc(risk.get('tier', ''))}] · "
                               f"{len(res.get('events', []))} findings")
                    dok, _ = sender.send_document(pdf_path, caption)
                    results["telegram_pdf"] = bool(dok)
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        return results

    @app.post("/api/notify/test")
    async def notify_test():
        if not _notify_channels():
            raise HTTPException(400, "No channels configured. Add SLACK_WEBHOOK_URL / SMTP_* / "
                                     "TELEGRAM_* to your .env.")
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, _send_all, "PacketIQ test", "This is a PacketIQ test notification.")
        return {"results": results}

    @app.post("/api/notify/{job_id}/send")
    async def notify_send(job_id: str):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        if not _notify_channels():
            raise HTTPException(400, "No channels configured.")
        res = _jobs[job_id]["result"]
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, _send_findings, res)
        return {"results": results, "sent_for": res["meta"]["filename"]}

    # ── Telegram guided setup (token + chat-id in the web UI) ────────────
    @app.get("/api/notify/telegram")
    async def telegram_status():
        """Current Telegram config for the setup panel (token is masked)."""
        from packetiq.alerts.telegram import load_credentials
        tok, cid = load_credentials()
        return {
            "configured": bool(tok and cid),
            "has_token":  bool(tok),
            "token_hint": ("…" + tok[-4:]) if tok and len(tok) > 4 else ("set" if tok else ""),
            "chat_id":    cid or "",
        }

    @app.post("/api/notify/telegram/detect")
    async def telegram_detect(request: Request):
        """Given the bot token, list chats that have messaged the bot so the user
        can pick their chat ID instead of hunting for it manually."""
        from packetiq.alerts.telegram import detect_chat_ids, load_credentials, valid_token
        body = await request.json()
        token = (body.get("token") or "").strip()
        if not valid_token(token):                       # fall back to a saved token
            token = (load_credentials()[0] or "").strip()
        if not valid_token(token):
            raise HTTPException(400, "Paste your bot token first — get one from @BotFather "
                                     "(it looks like 123456789:AA…).")
        loop = asyncio.get_event_loop()
        ok, res = await loop.run_in_executor(None, detect_chat_ids, token)
        if not ok:
            raise HTTPException(400, str(res))
        if not res:
            raise HTTPException(404, "No chats found yet. Open Telegram, send your bot any "
                                     "message (e.g. “hi”), then click Detect again.")
        return {"chats": res}

    @app.post("/api/notify/telegram")
    async def telegram_save(request: Request):
        """Save Telegram token + chat ID from the web UI. Applies immediately and,
        unless persist=false, is written to ./.env. Optionally sends a test message."""
        from packetiq.alerts.telegram import TelegramSender, load_credentials, valid_chat_id, valid_token
        body = await request.json()
        token = (body.get("token") or "").strip()
        chat_id = str(body.get("chat_id") or "").strip()
        persist = body.get("persist", True)
        do_test = body.get("test", True)
        saved_tok, saved_cid = load_credentials()        # keep a field the user left blank
        token = token or (saved_tok or "")
        chat_id = chat_id or (saved_cid or "")
        if not valid_token(token):
            raise HTTPException(400, "That bot token doesn't look right. Copy it from @BotFather "
                                     "(format: 123456789:AA…).")
        if not valid_chat_id(chat_id):
            raise HTTPException(400, "Enter a chat ID — a number like 123456789, a group like "
                                     "-1001234567890, or use Detect to fill it in automatically.")
        os.environ["TELEGRAM_BOT_TOKEN"] = token
        os.environ["TELEGRAM_CHAT_ID"] = chat_id
        if persist:
            try:
                _env_upsert("TELEGRAM_BOT_TOKEN", token)
                _env_upsert("TELEGRAM_CHAT_ID", chat_id)
            except OSError:
                pass                                     # runtime config still works this session
        out = {"configured": True, "chat_id": chat_id, "token_hint": "…" + token[-4:]}
        if do_test:
            loop = asyncio.get_event_loop()
            ok, desc = await loop.run_in_executor(None, TelegramSender(token, chat_id).test_connection)
            out["tested"] = bool(ok)
            out["message"] = desc
        return out

    @app.delete("/api/notify/telegram")
    async def telegram_clear():
        """Remove the Telegram token + chat ID (from this process and ./.env)."""
        for var in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
            os.environ.pop(var, None)
            try:
                _env_remove(var)
            except OSError:
                pass
        return {"configured": False}

    # ── AI SOC report (markdown) ────────────────────────────────────────
    @app.post("/api/report/{job_id}/ai")
    async def ai_report(job_id: str):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        if not _detect_provider()["provider"]:
            raise HTTPException(503, _NO_PROVIDER_HINT)
        from packetiq.copilot.prompts import SLASH_PROMPTS
        context = _build_chat_context(_jobs[job_id]["result"])
        try:
            text = await _collect_ai_with_fallback(
                _CHAT_SYSTEM, context,
                [{"role": "user", "content": SLASH_PROMPTS["report"]}])
        except RuntimeError as exc:
            raise HTTPException(502, str(exc)) from exc
        fn = _jobs[job_id]["result"]["meta"]["filename"]
        return Response(content=text, media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="report_{fn}.md"'})

    # ── AI provider control (auto-switch + manual override) ─────────────
    @app.get("/api/ai/status")
    async def ai_status_global():
        return _ai_status_payload()

    @app.post("/api/ai/provider")
    async def ai_set_provider(request: Request):
        body = await request.json()
        prov = (body.get("provider") or "auto").strip().lower()
        names = [n for n, _, _ in _PROVIDER_SPECS]
        if prov in ("auto", "", "none"):
            _AI_FORCED["provider"] = None
        elif prov in names:
            if prov not in _configured_providers():
                if prov == "ollama":
                    raise HTTPException(400, "The local Ollama daemon isn't reachable. "
                                             "Install Ollama, `ollama pull qwen2.5:7b-instruct`, "
                                             "then `ollama serve`.")
                raise HTTPException(400, f"{_AI_LABEL.get(prov, prov)} has no API key in your .env.")
            _AI_FORCED["provider"] = prov
            _AI_COOLDOWN.pop(prov, None)   # user explicitly chose it — clear any cooldown
        else:
            raise HTTPException(400, f"Unknown provider '{prov}'. Use auto/{'/'.join(names)}.")
        return _ai_status_payload()

    @app.post("/api/ai/key")
    async def ai_set_key(request: Request):
        """Set a cloud provider's API key from the web UI. Applies immediately
        (no restart) and, unless persist=false, is saved to ./.env so it survives
        a restart. The local Ollama provider needs no key."""
        body = await request.json()
        prov = (body.get("provider") or "").strip().lower()
        key = (body.get("key") or "").strip()
        persist = body.get("persist", True)
        envname = {n: e for n, e, _ in _PROVIDER_SPECS}.get(prov)
        if prov == "ollama" or envname is None:
            raise HTTPException(400, "Enter a key for Gemini, Groq, or Anthropic. "
                                     "The local Ollama provider needs no API key.")
        if not key or len(key) > 500 or "\n" in key or "\r" in key:
            raise HTTPException(400, "That does not look like a valid API key.")
        os.environ[envname] = key          # picked up instantly by every key lookup
        if persist:
            try:
                _env_upsert(envname, key)
            except OSError:
                pass                        # runtime key still works for this session
        _AI_COOLDOWN.pop(prov, None)
        _AI_FORCED["provider"] = prov       # a key just entered → use it
        return _ai_status_payload()

    @app.delete("/api/ai/key/{provider}")
    async def ai_clear_key(provider: str):
        """Remove a stored API key (from this process and ./.env)."""
        prov = provider.strip().lower()
        envname = {n: e for n, e, _ in _PROVIDER_SPECS}.get(prov)
        if prov == "ollama" or envname is None:
            raise HTTPException(400, "Unknown provider.")
        os.environ.pop(envname, None)
        try:
            _env_remove(envname)
        except OSError:
            pass
        if _AI_FORCED.get("provider") == prov:
            _AI_FORCED["provider"] = None   # don't stay forced on a now-keyless provider
        return _ai_status_payload()

    # ── NVD CVE lookup (real software banners → NIST NVD) ────────────────
    @app.get("/api/cve/{job_id}")
    async def cve_lookup(job_id: str):
        """Query NIST's NVD for CVEs matching the software banners actually
        observed in this capture (HTTP Server / User-Agent). All CVE data is
        real and comes straight from NVD; nothing is invented."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        from packetiq.enrichment import nvd
        banners = _jobs[job_id]["result"].get("software_banners", [])
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, lambda: nvd.lookup_banners(banners))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(502, f"NVD lookup failed: {exc}") from exc
        data["banners_observed"] = banners
        return data

    @app.get("/api/vulns/{job_id}")
    async def vuln_assessment(job_id: str):
        """Version-aware vulnerability assessment of the software observed in this
        capture: observed banner → CPE → NVD CVEs → CVSS → CISA-KEV (actively
        exploited), plus correlation of observed exploit attempts against the
        target's real software. All data is from NVD + CISA; nothing is invented."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        from packetiq.enrichment import nvd
        res = _jobs[job_id]["result"]
        banners = res.get("software_banners", [])
        attacks = [{"attack_type": e.get("evidence", {}).get("attack_type", ""),
                    "dst_ip": e.get("dst_ip", "")}
                   for e in res.get("events", []) if e.get("event_type") == "HTTP_ATTACK"]
        loop = asyncio.get_event_loop()
        try:
            data = await loop.run_in_executor(None, lambda: nvd.assess_vulnerabilities(banners, attacks))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(502, f"Vulnerability assessment failed: {exc}") from exc
        data["banners_observed"] = banners
        return data

    # ── Threat-intel feeds ──────────────────────────────────────────────
    @app.get("/api/feeds")
    async def feeds_status():
        import time as _t
        from pathlib import Path as _P

        from packetiq.detection.ja3 import load_blocklist
        from packetiq.enrichment import feed_details, feed_summary
        from packetiq.enrichment.feeds import cache_dir

        summary = feed_details()

        # JA3/JA3S TLS blocklist lives under detection/data — add it with real metadata.
        ja3 = load_blocklist()
        if ja3:
            ja3_path = _P(__file__).resolve().parents[1] / "detection" / "data" / "ja3_blocklist.csv"
            mtime = ja3_path.stat().st_mtime if ja3_path.is_file() else _t.time()
            summary.append({
                "name": "SSLBL JA3", "provider": "abuse.ch", "category": "TLS fingerprints",
                "kind": "JA3 hash", "severity": "HIGH", "url": "https://sslbl.abuse.ch/ja3-fingerprints/",
                "desc": "JA3 TLS client fingerprints associated with malware C2.",
                "count": len(ja3), "updated_epoch": mtime,
                "updated_iso": _t.strftime("%Y-%m-%d %H:%M", _t.localtime(mtime)),
                "age_days": round(max(0, (_t.time() - mtime) / 86400.0), 1),
                "origin": "bundled" if ja3_path.is_file() else "unknown",
            })

        legacy = feed_summary()
        if ja3:
            legacy = {**legacy, "SSLBL JA3 (TLS)": len(ja3)}
        return {
            "feeds": legacy,                                   # backward-compatible {name: count}
            "detailed": summary,                               # rich per-feed provenance
            "total": sum(f["count"] for f in summary),
            "sources": len({f["provider"] for f in summary}),
            "feed_count": len(summary),
            "checked_at": _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime()),
            "cache_dir": str(cache_dir()),
        }

    @app.post("/api/feeds/update")
    async def feeds_update():
        from packetiq.detection.ja3 import load_blocklist
        from packetiq.enrichment.feeds import feed_summary, load_store
        from packetiq.enrichment.update import update_feeds
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, update_feeds)
        load_store.cache_clear()
        load_blocklist.cache_clear()
        ok = sum(1 for v in results.values() if isinstance(v, int))
        return {"results": {k: (v if isinstance(v, int) else str(v)) for k, v in results.items()},
                "updated": ok, "total": len(results), "feeds": feed_summary()}

    # ── MISP push ───────────────────────────────────────────────────────
    @app.post("/api/misp/{job_id}")
    async def misp_push(job_id: str, request: Request):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        body = await request.json()
        url = body.get("url"); key = body.get("key")
        if not url or not key:
            raise HTTPException(400, "MISP url and key are required.")
        event = _jobs[job_id]["result"].get("misp", {"Event": {"Attribute": []}})
        if not event.get("Event", {}).get("Attribute"):
            raise HTTPException(400, "No indicators to push.")
        from packetiq.export.misp import push_to_misp
        verify = bool(body.get("verify_tls", True))
        loop = asyncio.get_event_loop()
        ok, msg = await loop.run_in_executor(None, lambda: push_to_misp(event, url=url, key=key, verify_tls=verify))
        if not ok:
            raise HTTPException(502, msg)
        return {"ok": True, "message": msg,
                "indicator_count": len(event["Event"]["Attribute"])}

    # ── Evidence PCAP slicing ───────────────────────────────────────────
    @app.get("/api/evidence/{job_id}")
    async def evidence(job_id: str, ip: str = "", port: int = 0):
        if job_id not in _jobs:
            raise HTTPException(404, "Job not found.")
        # campaign jobs carry multiple captures; single jobs carry one
        paths = _jobs[job_id].get("pcap_paths") or [_jobs[job_id].get("pcap_path")]
        paths = [p for p in paths if p and Path(p).is_file()]
        if not paths:
            raise HTTPException(410, "The capture for this job is no longer available.")
        if not ip and not port:
            raise HTTPException(400, "Provide ip and/or port to filter on.")
        # Validate inputs: `ip` must be a real IP (it is also used only for set
        # membership, never a BPF string) and `port` a valid port. Crucially the
        # output filename is built from server-controlled values ONLY — never the
        # raw `ip` — to prevent path traversal / arbitrary file write (CWE-22).
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError as exc:
                raise HTTPException(400, "Invalid IP address.") from exc
        if port and not (0 < port < 65536):
            raise HTTPException(400, "Invalid port.")
        from packetiq.export.pcap_slicer import PcapFilter, slice_pcap
        pf = PcapFilter(ips={ip} if ip else set(), ports={port} if port else set())
        out = UPLOAD_DIR / f"evidence_{job_id[:8]}_{uuid.uuid4().hex[:8]}.pcap"

        def _slice_all():
            total, tmp = 0, str(out)
            # slice each capture; for campaigns, concatenate matches
            from scapy.all import PcapWriter
            w = PcapWriter(tmp, append=False, sync=True)
            try:
                for src in paths:
                    part = str(out) + ".part"
                    cnt = slice_pcap(src, part, pf)
                    if cnt:
                        from scapy.all import PcapReader
                        with PcapReader(part) as rd:
                            for pk in rd:
                                w.write(pk)
                        total += cnt
                    Path(part).unlink(missing_ok=True)
            finally:
                w.close()
            return total

        loop = asyncio.get_event_loop()
        n = await loop.run_in_executor(None, _slice_all)
        if not n:
            raise HTTPException(404, "No packets matched that filter.")
        return Response(
            content=out.read_bytes(), media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="{out.name}"'},
        )

    @app.get("/api/stix/{job_id}")
    async def stix_download(job_id: str):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        bundle = _jobs[job_id]["result"].get("stix", {"type": "bundle", "objects": []})
        return Response(
            content=json.dumps(bundle, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="packetiq_iocs_{job_id[:8]}.stix.json"'},
        )

    @app.get("/api/navigator/{job_id}")
    async def navigator_download(job_id: str):
        """Download a real MITRE ATT&CK Navigator layer of the detected techniques."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        from packetiq.export import build_navigator_layer
        res = _jobs[job_id]["result"]
        fn = res.get("meta", {}).get("filename", "capture")
        layer = build_navigator_layer(res.get("events", []),
                                      name=f"PacketIQ — {fn}",
                                      description=f"ATT&CK techniques observed by PacketIQ in {fn}.")
        return Response(
            content=json.dumps(layer, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="packetiq_attack_{job_id[:8]}.json"'},
        )

    @app.get("/api/sigma/{job_id}/rules.zip")
    async def sigma_download(job_id: str):
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Results not found.")
        rules = _jobs[job_id]["result"].get("sigma_rules", [])
        if not rules:
            raise HTTPException(404, "No SIGMA rules generated.")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i, r in enumerate(rules):
                zf.writestr(f"rule_{i:03d}_{r['level']}.yml", r["yaml"])
        buf.seek(0)
        return Response(
            content=buf.read(),
            media_type="application/zip",
            headers={"Content-Disposition":
                     f'attachment; filename="packetiq_sigma_{job_id[:8]}.zip"'},
        )

    @app.get("/api/chat/{job_id}/status")
    async def chat_status(job_id: str):
        """Check whether AI chat is available and which provider is active."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Job not found or not complete.")
        p = _detect_provider()
        return {
            "available": p["provider"] is not None,
            "provider":  p["provider"],
            "model":     p["model"],
        }

    @app.post("/api/chat/{job_id}")
    async def chat_endpoint(job_id: str, request: Request):
        """Stream an AI response for a chat message about the PCAP analysis."""
        if job_id not in _jobs or not _jobs[job_id].get("result"):
            raise HTTPException(404, "Job not found or not complete.")

        p = _detect_provider()
        if not p["provider"]:
            raise HTTPException(503, _NO_PROVIDER_HINT)

        body = await request.json()
        message: str = body.get("message", "").strip()
        history: list = body.get("history", [])
        if not message:
            raise HTTPException(400, "message is required.")

        result  = _jobs[job_id]["result"]
        context = _build_chat_context(result)
        messages = history + [{"role": "user", "content": message}]

        _LABEL = _AI_LABEL

        async def event_stream():
            skipped: set[str] = set()
            current = p

            while current["provider"]:
                label = _LABEL.get(current["provider"], current["provider"])
                try:
                    async for chunk in _stream_ai(
                        current["provider"], current["key"], current["model"],
                        _CHAT_SYSTEM, context, messages
                    ):
                        yield f"data: {json.dumps({'text': chunk})}\n\n"
                    yield "data: [DONE]\n\n"
                    return
                except Exception as exc:
                    # Any failure — exhausted quota, a rejected key, a missing SDK,
                    # a network blip — means "try the next provider", exactly as the
                    # non-streaming path does. Giving up here would strand the user
                    # even when a working provider (e.g. the local Ollama model) is
                    # sitting right there.
                    msg = str(exc)
                    # A model-scoped failure (zero free-tier quota for that model,
                    # or an unaddressable model id) means the provider is fine and
                    # only the model is wrong. Switch model silently and retry —
                    # no cooldown, no notice, because nothing the analyst cares
                    # about has actually changed.
                    if _is_model_unusable(msg):
                        _mark_model_dead(current["provider"], current["model"])
                        alt = _next_model(current["provider"], current["model"])
                        if alt:
                            current = {**current, "model": alt}
                            continue
                    _note_provider_failure(current["provider"], msg)
                    skipped.add(current["provider"])
                    fallback = _detect_provider(skip=skipped)
                    if fallback["provider"]:
                        fallback_label = _LABEL.get(fallback["provider"], fallback["provider"])
                        # A `notice`, not `text`: the UI shows it as a quiet status line
                        # so it never lands inside the answer the analyst reads or copies.
                        notice = (f"{label} {_failure_reason(msg)} — answered by "
                                  f"{fallback_label}")
                        yield f"data: {json.dumps({'notice': notice})}\n\n"
                        current = fallback
                        continue
                    # Every configured provider has now failed.
                    friendly = _friendly_ai_error(label, msg, exhausted=True)
                    yield f"data: {json.dumps({'error': friendly})}\n\n"
                    return

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app
