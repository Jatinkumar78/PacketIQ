"""
Alert Dispatcher — orchestrates the full alert sequence for one analysis run.

Sends in this order:
  1. Summary alert        (always, if threshold is met)
  2. Chain alerts         (one per chain that meets threshold)
  3. Orphan event alerts  (HIGH+ events not covered by any chain, up to MAX_ORPHANS)
  4. Report file          (optional, if report_path is provided)

Deduplication:
  Tracks sent (chain_id, event description) across the session to avoid
  duplicate alerts if the same PCAP is analysed multiple times in one run.

Usage:
    sender     = TelegramSender(token, chat_id)
    dispatcher = AlertDispatcher(sender, threshold="HIGH")
    results    = dispatcher.dispatch(file_name, risk, events, chains, result)
"""

from dataclasses import dataclass, field
from typing import Optional

from packetiq.alerts import formatter
from packetiq.alerts.telegram import TelegramSender
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, Severity
from packetiq.detection.risk_scorer import RiskReport
from packetiq.extractor.data_extractor import ExtractionResult

# Minimum severity to generate alerts (can be overridden at runtime)
DEFAULT_THRESHOLD = Severity.HIGH
MAX_ORPHANS       = 5   # max individual-event alerts if no chains cover them


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
}


@dataclass
class DispatchResult:
    """Summary of the alert dispatch run."""
    sent:   int = 0
    failed: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0


class AlertDispatcher:

    def __init__(
        self,
        sender:    TelegramSender,
        threshold: Severity = DEFAULT_THRESHOLD,
    ):
        self.sender    = sender
        self.threshold = threshold
        self._sent_ids: set[str] = set()   # dedup keys

    # ── Public ────────────────────────────────────────────────────────────────

    def dispatch(
        self,
        file_name:   str,
        risk:        RiskReport,
        events:      list[DetectionEvent],
        chains:      list[AttackChain],
        result:      ExtractionResult,
        report_path: Optional[str] = None,
    ) -> DispatchResult:
        """
        Send the full alert sequence. Returns a DispatchResult.
        """
        dr = DispatchResult()

        # Filter chains and events to threshold level
        alert_chains  = [c for c in chains  if _meets_threshold(c.severity, self.threshold)]
        alert_events  = [e for e in events  if _meets_threshold(e.severity, self.threshold)]

        # Skip entire dispatch if nothing meets the bar
        if not alert_chains and not alert_events:
            dr.skipped = len(events)
            return dr

        # ── 1. Summary ────────────────────────────────────────────────
        duration = max(0.0, result.capture_end - result.capture_start)
        summary  = formatter.format_summary(
            file_name       = file_name,
            risk            = risk,
            events          = alert_events,
            chains          = alert_chains,
            capture_start   = result.capture_start,
            capture_duration= duration,
        )
        self._send(summary, dr)

        # ── 2. Chain alerts ───────────────────────────────────────────
        for i, chain in enumerate(alert_chains, 1):
            dedup_key = f"chain:{chain.chain_id}"
            if dedup_key in self._sent_ids:
                dr.skipped += 1
                continue

            msg = formatter.format_chain_alert(chain, i, len(alert_chains))
            if self._send(msg, dr):
                self._sent_ids.add(dedup_key)

        # ── 3. Orphan events (not covered by any chain) ───────────────
        chained_event_ids = {
            id(e) for chain in alert_chains for e in chain.events
        }
        orphans = [
            e for e in alert_events
            if id(e) not in chained_event_ids
        ][:MAX_ORPHANS]

        for i, event in enumerate(orphans, 1):
            dedup_key = f"event:{event.src_ip}:{event.event_type}:{event.dst_ip}:{event.dst_port}"
            if dedup_key in self._sent_ids:
                dr.skipped += 1
                continue

            msg = formatter.format_orphan_event(event, i, len(orphans))
            if self._send(msg, dr):
                self._sent_ids.add(dedup_key)

        # ── 4. Optional: attach report file ──────────────────────────
        if report_path:
            caption = (
                f"📋 PacketIQ SOC Report\n"
                f"📁 {file_name} | 🎯 Risk: {risk.score}/100 [{risk.tier}]"
            )
            ok, err = self.sender.send_document(report_path, caption)
            if ok:
                dr.sent += 1
            else:
                dr.failed += 1
                dr.errors.append(f"Report upload failed: {err}")

        return dr

    def dispatch_clean(self, file_name: str) -> DispatchResult:
        """Send a 'no threats found' notification."""
        dr  = DispatchResult()
        msg = formatter.format_clean_scan(file_name)
        self._send(msg, dr)
        return dr

    # ── Internal ──────────────────────────────────────────────────────────────

    def _send(self, text: str, dr: DispatchResult) -> bool:
        ok, err = self.sender.send(text)
        if ok:
            dr.sent += 1
        else:
            dr.failed += 1
            dr.errors.append(err)
        return ok


def _meets_threshold(severity: Severity, threshold: Severity) -> bool:
    return _SEVERITY_ORDER.get(severity, 9) <= _SEVERITY_ORDER.get(threshold, 9)
