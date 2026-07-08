"""
Live capture mode — turn PacketIQ from forensics into lightweight monitoring.

Sniffs an interface in real time, keeps a rolling window of packets, periodically
runs the flow-based detectors + threat-intel enrichment, and fires a callback for
each *new* finding above a severity threshold.

For testing or for users without root, `replay()` runs the exact same detection
loop over a PCAP file (no privileges required).
"""

import time
from collections import deque

from packetiq.detection import (
    beacon,
    brute_force,
    dns_anomaly,
    http_inspect,
    port_scan,
    protocol_misuse,
)
from packetiq.detection.models import Severity
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser

_SEV = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def _detect(records: list) -> list:
    """Run the windowed, flow-based detectors over a list of packet records."""
    ex = DataExtractor()
    for r in records:
        ex.feed(r)
    res = ex.finalize()

    events = []
    for fn in (brute_force.detect, port_scan.detect, dns_anomaly.detect, protocol_misuse.detect):
        try:
            events.extend(fn(res))
        except Exception:
            pass
    try:
        events.extend(beacon.BeaconDetector().detect(res))
    except Exception:
        pass
    try:
        events.extend(http_inspect.detect(res))
    except Exception:
        pass
    try:
        from packetiq.enrichment import enrich
        events.extend(enrich(res))
    except Exception:
        pass
    return events


def _key(e) -> tuple:
    return (e.event_type, e.src_ip, e.dst_ip, e.dst_port)


class LiveMonitor:
    """Rolling-window detector with de-duplicated alerting."""

    def __init__(self, window_secs: float, threshold: str, on_alert):
        self.window = window_secs
        self.threshold = _SEV[Severity[threshold.upper()]]
        self.on_alert = on_alert
        self.buf: deque = deque()        # (ts, record)
        self.seen: set = set()
        self.alert_count = 0

    def feed(self, record):
        self.buf.append((record.timestamp, record))

    def trim(self, now: float):
        while self.buf and (now - self.buf[0][0]) > self.window:
            self.buf.popleft()

    def scan(self):
        records = [r for _, r in self.buf]
        for e in _detect(records):
            if _SEV.get(e.severity, 9) <= self.threshold and _key(e) not in self.seen:
                self.seen.add(_key(e))
                self.alert_count += 1
                self.on_alert(e)


def replay(pcap_path: str, on_alert, window_secs: float = 300.0,
           scan_every: int = 200, threshold: str = "HIGH") -> LiveMonitor:
    """Replay a PCAP through the live detection loop (no root required)."""
    mon = LiveMonitor(window_secs, threshold, on_alert)
    parser = PCAPParser(pcap_path)
    n = 0
    for rec in parser.stream():
        mon.feed(rec)
        mon.trim(rec.timestamp)
        n += 1
        if n % scan_every == 0:
            mon.scan()
    mon.scan()
    return mon


def sniff_live(interface: str, on_alert, window_secs: float = 300.0,
               interval_secs: float = 10.0, threshold: str = "HIGH") -> LiveMonitor:
    """
    Sniff `interface` and run detection every `interval_secs`. Blocks until
    interrupted. Requires privileges to capture (run with sudo / CAP_NET_RAW).
    """
    try:
        from scapy.all import AsyncSniffer
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"scapy sniffing unavailable: {exc}") from exc

    mon = LiveMonitor(window_secs, threshold, on_alert)
    parser = object.__new__(PCAPParser)   # reuse _parse_packet without a file
    counter = {"i": 0}

    def _cb(pkt):
        rec = parser._parse_packet(pkt, counter["i"])
        counter["i"] += 1
        if rec:
            mon.feed(rec)

    try:
        from scapy.config import conf
        conf.sniff_promisc = False   # macOS BPF can't set promisc on real ifaces; not needed
        sniffer = AsyncSniffer(iface=interface, prn=_cb, store=False, promisc=False)
        sniffer.start()
    except PermissionError as exc:
        raise RuntimeError(
            "Permission denied opening the interface. Run with sudo or grant CAP_NET_RAW."
        ) from exc

    try:
        while True:
            time.sleep(interval_secs)
            mon.trim(time.time())
            mon.scan()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
    return mon
