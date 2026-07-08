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

        # ── Pass 2: Payload-based detectors (second PCAP stream) ─────────
        _step("credential_exposure")
        try:
            parser = PCAPParser(pcap_path)
            events.extend(credential.detect_from_stream(parser.stream()))
        except Exception:
            pass

        _step("ja3_fingerprinting")
        try:
            parser2 = PCAPParser(pcap_path)
            events.extend(ja3.JA3Detector().detect_from_stream(parser2.stream()))
        except Exception:
            pass

        _step("tls_inspection")
        try:
            from packetiq.detection import tls_inspect
            events.extend(tls_inspect.analyze(pcap_path))
        except Exception:
            pass

        _step("file_carving")
        try:
            from packetiq.detection import file_carver
            events.extend(file_carver.analyze(pcap_path))
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
