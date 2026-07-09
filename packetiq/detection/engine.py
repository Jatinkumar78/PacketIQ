"""
Detection Engine — orchestrates all detectors and produces a unified
list of DetectionEvents + a RiskReport.

Two-pass design:
  Pass 1 (flow-based): runs on ExtractionResult — brute force, port scan,
                        DNS anomaly, protocol misuse.
  Pass 2 (payload-based): streams packets a second time — credential exposure.

Usage:
    engine = DetectionEngine()
    events, risk, fingerprints = engine.run(extraction_result, pcap_path)
"""

from packetiq.detection import (
    beacon,
    brute_force,
    credential,
    dns_anomaly,
    http_inspect,
    ja3,
    port_scan,
    protocol_misuse,
    risk_scorer,
)
from packetiq.detection.fingerprint import Fingerprint
from packetiq.detection.fingerprint import detect as fingerprint_detect
from packetiq.detection.models import DetectionEvent
from packetiq.detection.risk_scorer import RiskReport
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.parser.pcap_parser import PCAPParser


class DetectionEngine:

    def run(
        self,
        result: ExtractionResult,
        pcap_path: str,
        *,
        progress_callback=None,
    ) -> tuple[list[DetectionEvent], RiskReport, list[Fingerprint]]:
        """
        Run all detectors and return (events, risk_report).

        progress_callback: optional callable(step_name: str) for UI updates.
        """
        events: list[DetectionEvent] = []

        def _step(name: str):
            if progress_callback:
                progress_callback(name)

        # ── Pass 1: Flow-based detectors ─────────────────────────────────
        _step("brute_force")
        events.extend(brute_force.detect(result))

        _step("port_scan")
        events.extend(port_scan.detect(result))

        _step("dns_anomaly")
        events.extend(dns_anomaly.detect(result))

        _step("protocol_misuse")
        events.extend(protocol_misuse.detect(result))

        _step("beacon_analysis")
        events.extend(beacon.BeaconDetector().detect(result))

        _step("http_inspection")
        events.extend(http_inspect.detect(result))

        # ── Pass 2: RawPacketRecord detectors — ONE shared PCAP stream ───
        # credential exposure + JA3 both consume RawPacketRecord, so we parse the
        # capture once and feed both, instead of parsing it twice.
        _step("credential_exposure")
        cred_events: list[DetectionEvent] = []
        cred_seen: set = set()
        ja3_det = ja3.JA3Detector().begin()
        try:
            for record in PCAPParser(pcap_path).stream():
                credential.scan_record(record, cred_seen, cred_events)
                ja3_det.feed(record)
            events.extend(cred_events)
        except Exception:
            pass

        _step("ja3_fingerprinting")
        try:
            events.extend(ja3_det.finalize())
        except Exception:
            pass

        # ── Pass 3: Raw-packet detectors — ONE shared scapy stream ───────
        # TLS certificate inspection + file carving both stream raw packets;
        # share a single PcapReader pass rather than reading the file twice.
        _step("tls_inspection")
        try:
            from packetiq.detection import tls_inspect
            tls_acc = tls_inspect.make_accumulator()
        except Exception:
            tls_acc = None
        _step("file_carving")
        try:
            from packetiq.detection import file_carver
            carver_acc = file_carver.FileCarverAccumulator()
        except Exception:
            carver_acc = None
        try:
            from scapy.all import PcapReader
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    if tls_acc is not None:
                        tls_acc.feed(pkt)
                    if carver_acc is not None:
                        carver_acc.feed(pkt)
        except Exception:
            pass
        if tls_acc is not None:
            try:
                events.extend(tls_acc.finalize())
            except Exception:
                pass
        if carver_acc is not None:
            try:
                events.extend(carver_acc.finalize())
            except Exception:
                pass

        # ── Threat-intel enrichment (real OSINT feeds) ───────────────────
        _step("ioc_enrichment")
        try:
            from packetiq.enrichment import enrich as ioc_enrich
            events.extend(ioc_enrich(result))
        except Exception:
            pass

        # ── False-positive reduction (allow-list + confidence floor) ──────
        # Conservative: with default config nothing is suppressed, so detection
        # recall is unchanged. Risk is then scored on the kept findings.
        _step("triage")
        try:
            from packetiq import triage
            events, suppressed = triage.apply_suppression(events)
            self.suppressed = suppressed
        except Exception:
            self.suppressed = []

        # ── Passive OS fingerprinting (informational) ─────────────────────
        _step("os_fingerprinting")
        fingerprints = fingerprint_detect(result)

        # ── Risk scoring ──────────────────────────────────────────────────
        _step("risk_scoring")
        risk = risk_scorer.score(events)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        events.sort(key=lambda e: (severity_order.get(e.severity.value, 9), e.timestamp))

        return events, risk, fingerprints
