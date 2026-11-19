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

import contextlib

from packetiq.detection import (
    arp_scan,
    beacon,
    brute_force,
    credential,
    dns_anomaly,
    dos_flood,
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

        _step("arp_scan")
        events.extend(arp_scan.detect(result))

        _step("dos_flood")
        events.extend(dos_flood.detect(result))

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
        with contextlib.suppress(Exception):
            for record in PCAPParser(pcap_path).stream():
                credential.scan_record(record, cred_seen, cred_events)
                ja3_det.feed(record)
            events.extend(cred_events)

        _step("ja3_fingerprinting")
        with contextlib.suppress(Exception):
            events.extend(ja3_det.finalize())

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
        # Kerberos rides the same pass. It needs scapy's decoded layers, which
        # the lighter RawPacketRecord of pass 2 does not carry, and reading an
        # 85 MB capture a fourth time to get them would be wasteful.
        _step("kerberos_analysis")
        # No defensive try/except around this one: it imports nothing optional,
        # and a bare constructor that cannot fail does not need a fallback that
        # the suite can never reach.
        from packetiq.detection import kerberos as kerberos_detect
        krb_acc = kerberos_detect.KerberosAccumulator()
        # WS-Management joins the same pass: it reads TCP payload headers, which
        # the flow-level ExtractionResult does not retain.
        _step("winrm_analysis")
        from packetiq.detection import winrm as winrm_detect
        winrm_acc = winrm_detect.WinRMAccumulator()
        _step("ldap_analysis")
        from packetiq.detection import ldap as ldap_detect
        ldap_acc = ldap_detect.LDAPAccumulator()
        _step("smb_analysis")
        from packetiq.detection import smb as smb_detect
        smb_acc = smb_detect.SMBAccumulator()
        _step("dcerpc_analysis")
        from packetiq.detection import dcerpc as dcerpc_detect
        dcerpc_acc = dcerpc_detect.DCERPCAccumulator()
        _step("cleartext_recovery")
        from packetiq.detection import cleartext as cleartext_detect
        cleartext_acc = cleartext_detect.ClearTextAccumulator()
        # Deep artifact hunting rides the same pass: it reassembles the streams
        # and peels encodings / XOR off them, which needs the full payloads this
        # scapy loop carries but the flow-level ExtractionResult does not.
        _step("artifact_hunting")
        from packetiq.detection import artifact_hunter as artifact_detect
        artifact_acc = artifact_detect.ArtifactHunterAccumulator()
        # HTTP deep inspection rides the same pass: it reassembles the request and
        # response streams to read POST bodies, cookies, headers and decompressed
        # response bodies, none of which the flow-level ExtractionResult retains.
        _step("http_forensics")
        from packetiq.detection import http_forensics as http_deep
        http_acc = http_deep.HTTPForensicsAccumulator()
        with contextlib.suppress(Exception):
            from scapy.all import PcapReader
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    if tls_acc is not None:
                        tls_acc.feed(pkt)
                    if carver_acc is not None:
                        carver_acc.feed(pkt)
                    krb_acc.feed(pkt)
                    winrm_acc.feed(pkt)
                    ldap_acc.feed(pkt)
                    smb_acc.feed(pkt)
                    dcerpc_acc.feed(pkt)
                    cleartext_acc.feed(pkt)
                    artifact_acc.feed(pkt)
                    http_acc.feed(pkt)
        with contextlib.suppress(Exception):
            events.extend(krb_acc.finalize())
            # Published even when nothing fired: a responder asking "which
            # accounts exist in this realm?" needs the messages, not just
            # the alerts.
            result.kerberos = krb_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(winrm_acc.finalize())
            result.winrm = winrm_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(ldap_acc.finalize())
            result.ldap = ldap_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(smb_acc.finalize())
            result.smb = smb_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(dcerpc_acc.finalize())
            result.dcerpc = dcerpc_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(cleartext_acc.finalize())
            result.cleartext = cleartext_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(artifact_acc.finalize())
            result.artifacts = artifact_acc.summary()
        with contextlib.suppress(Exception):
            events.extend(http_acc.finalize())
            result.http_forensics = http_acc.summary()
        if tls_acc is not None:
            with contextlib.suppress(Exception):
                events.extend(tls_acc.finalize())
        if carver_acc is not None:
            with contextlib.suppress(Exception):
                events.extend(carver_acc.finalize())

        # ── Threat-intel enrichment (real OSINT feeds) ───────────────────
        _step("ioc_enrichment")
        with contextlib.suppress(Exception):
            from packetiq.enrichment import enrich as ioc_enrich
            events.extend(ioc_enrich(result))

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
