"""The alert dispatch sequence: what gets sent, what is suppressed, what is retried.

This is the last stage before a finding leaves the machine. Two failure modes
matter and neither raises: sending nothing when something needed sending, and
sending the same alert repeatedly. The severity threshold, the per-chain and
per-event dedup keys, and the report-upload arm all decide that, and none of
them had direct coverage.
"""


from packetiq.alerts import formatter
from packetiq.alerts.dispatcher import MAX_ORPHANS, AlertDispatcher
from packetiq.correlation.models import AttackChain, MitreTechnique
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.detection.risk_scorer import RiskReport
from packetiq.extractor.data_extractor import ExtractionResult


class FakeSender:
    """Records what would have gone to Telegram. Never touches the network."""

    def __init__(self, send_ok=True, doc_ok=True, doc_err="upload rejected"):
        self.messages: list = []
        self.documents: list = []
        self.send_ok = send_ok
        self.doc_ok = doc_ok
        self.doc_err = doc_err

    def send(self, text, disable_preview=True):
        self.messages.append(text)
        return (True, "") if self.send_ok else (False, "chat not found")

    def send_document(self, path, caption=""):
        self.documents.append((path, caption))
        return (True, "") if self.doc_ok else (False, self.doc_err)


def _event(severity=Severity.HIGH, src="45.33.32.156", dst="192.168.1.50",
           port=22, etype=EventType.BRUTE_FORCE, **kw):
    base = dict(event_type=etype, severity=severity, src_ip=src,
                description="SSH brute force burst", dst_ip=dst, dst_port=port,
                protocol="TCP", timestamp=1700000000.0, packet_count=40,
                confidence=0.9, evidence={"attempts": 40})
    base.update(kw)
    return DetectionEvent(**base)


def _chain(events=None, severity=Severity.CRITICAL, chain_id="ABCD1234", **kw):
    base = dict(chain_id=chain_id, name="SSH brute force into C2",
                description="Recon, then credential access, then beaconing.",
                attacker_ips={"45.33.32.156"}, target_ips={"192.168.1.50"},
                events=events or [], severity=severity, confidence=0.85,
                first_seen=1700000000.0, last_seen=1700000600.0,
                kill_chain_phases=["Reconnaissance", "Credential Access"],
                primary_phase="Credential Access")
    base.update(kw)
    return AttackChain(**base)


def _risk(score=88, tier="CRITICAL"):
    return RiskReport(score=score, tier=tier, color="bold red",
                      summary="Multi-stage intrusion.", event_count=6,
                      by_severity={"CRITICAL": 2, "HIGH": 4}, by_type={},
                      top_sources=["45.33.32.156"], top_targets=["192.168.1.50"])


def _result():
    r = ExtractionResult()
    r.capture_start = 1700000000.0
    r.capture_end = 1700000600.0
    return r


def _dispatch(sender, events, chains, **kw):
    return AlertDispatcher(sender).dispatch("attack.pcap", _risk(), events, chains,
                                            _result(), **kw)


# ── Threshold ────────────────────────────────────────────────────────────────

def test_nothing_below_the_threshold_is_sent_at_all():
    """A capture of only LOW/MEDIUM findings must not page anyone.

    The count is reported as skipped rather than sent so the caller can still
    tell the difference between "quiet" and "nothing was analysed".
    """
    sender = FakeSender()
    dr = _dispatch(sender, [_event(Severity.LOW), _event(Severity.MEDIUM)], [])

    assert sender.messages == []
    assert (dr.sent, dr.skipped) == (0, 2)
    assert dr.ok is True


def test_a_high_finding_sends_a_summary():
    sender = FakeSender()
    dr = _dispatch(sender, [_event(Severity.HIGH)], [])

    assert dr.sent >= 1
    assert "attack.pcap" in sender.messages[0]


def test_a_medium_finding_alongside_a_high_one_is_not_alerted_separately():
    sender = FakeSender()
    _dispatch(sender, [_event(Severity.HIGH), _event(Severity.MEDIUM, src="10.0.0.9")], [])

    assert not any("10.0.0.9" in m for m in sender.messages)


# ── Chains and orphans ───────────────────────────────────────────────────────

def test_a_chain_is_alerted_once_per_dispatch():
    sender = FakeSender()
    ev = _event(Severity.CRITICAL)
    dr = _dispatch(sender, [ev], [_chain(events=[ev])])

    assert dr.sent == 2, "one summary plus one chain alert"
    assert any("SSH brute force into C2" in m for m in sender.messages)


def test_the_same_chain_in_a_second_dispatch_is_skipped():
    """Re-analysing one capture in a session must not re-page on the same chain."""
    sender = FakeSender()
    dispatcher = AlertDispatcher(sender)
    ev = _event(Severity.CRITICAL)
    chain = _chain(events=[ev])

    first = dispatcher.dispatch("attack.pcap", _risk(), [ev], [chain], _result())
    second = dispatcher.dispatch("attack.pcap", _risk(), [ev], [chain], _result())

    assert first.sent == 2
    assert second.skipped == 1, "the chain alert must be deduplicated"
    assert second.sent == 1, "the summary still goes out"


def test_an_event_covered_by_a_chain_is_not_also_sent_on_its_own():
    """Otherwise the analyst gets the same finding twice, in two shapes."""
    sender = FakeSender()
    ev = _event(Severity.CRITICAL)
    _dispatch(sender, [ev], [_chain(events=[ev])])

    assert len(sender.messages) == 2


def test_an_uncorrelated_event_gets_its_own_alert():
    sender = FakeSender()
    chained = _event(Severity.CRITICAL)
    orphan = _event(Severity.HIGH, src="203.0.113.5", etype=EventType.PORT_SCAN)

    _dispatch(sender, [chained, orphan], [_chain(events=[chained])])

    assert any("203.0.113.5" in m for m in sender.messages)


def test_the_same_orphan_event_in_a_second_dispatch_is_skipped():
    sender = FakeSender()
    dispatcher = AlertDispatcher(sender)
    orphan = _event(Severity.HIGH)

    dispatcher.dispatch("a.pcap", _risk(), [orphan], [], _result())
    second = dispatcher.dispatch("a.pcap", _risk(), [orphan], [], _result())

    assert second.skipped == 1
    assert second.sent == 1


def test_a_flood_of_orphan_events_is_capped():
    """Twenty findings must not become twenty messages — Telegram rate-limits,
    and an analyst stops reading long before that anyway."""
    sender = FakeSender()
    events = [_event(Severity.HIGH, src=f"45.33.32.{i}") for i in range(20)]

    _dispatch(sender, events, [])

    assert len(sender.messages) == 1 + MAX_ORPHANS


# ── Report upload ────────────────────────────────────────────────────────────

def test_a_report_file_is_uploaded_with_a_caption(tmp_path):
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF-1.4")
    sender = FakeSender()

    dr = _dispatch(sender, [_event(Severity.HIGH)], [], report_path=str(report))

    assert len(sender.documents) == 1
    path, caption = sender.documents[0]
    assert path == str(report)
    assert "attack.pcap" in caption and "88/100" in caption
    assert dr.failed == 0


def test_a_failed_report_upload_is_recorded_without_losing_the_alerts(tmp_path):
    report = tmp_path / "report.pdf"
    report.write_bytes(b"%PDF-1.4")
    sender = FakeSender(doc_ok=False, doc_err="file too large")

    dr = _dispatch(sender, [_event(Severity.HIGH)], [], report_path=str(report))

    assert dr.sent >= 1, "the text alerts still went out"
    assert dr.failed == 1
    assert any("file too large" in e for e in dr.errors)
    assert dr.ok is False


def test_no_report_path_means_no_upload_attempt():
    sender = FakeSender()
    _dispatch(sender, [_event(Severity.HIGH)], [])
    assert sender.documents == []


# ── Send failures and the clean-scan path ────────────────────────────────────

def test_a_failed_send_is_counted_and_its_reason_kept():
    sender = FakeSender(send_ok=False)
    dr = _dispatch(sender, [_event(Severity.HIGH)], [])

    assert dr.sent == 0
    assert dr.failed >= 1
    assert "chat not found" in dr.errors[0]
    assert dr.ok is False


def test_a_failed_chain_send_is_not_marked_as_delivered():
    """The dedup key is only recorded on success, so a retry can still get through."""
    sender = FakeSender(send_ok=False)
    dispatcher = AlertDispatcher(sender)
    ev = _event(Severity.CRITICAL)
    chain = _chain(events=[ev])

    dispatcher.dispatch("a.pcap", _risk(), [ev], [chain], _result())
    sender.send_ok = True
    second = dispatcher.dispatch("a.pcap", _risk(), [ev], [chain], _result())

    assert second.skipped == 0, "a failed alert must not be treated as sent"
    assert second.sent == 2


def test_a_clean_scan_sends_one_reassuring_message():
    sender = FakeSender()
    dr = AlertDispatcher(sender).dispatch_clean("benign.pcap")

    assert dr.sent == 1
    assert "benign.pcap" in sender.messages[0]
    assert "Clean Scan" in sender.messages[0]


def test_a_clean_scan_send_failure_is_reported():
    dr = AlertDispatcher(FakeSender(send_ok=False)).dispatch_clean("benign.pcap")
    assert (dr.sent, dr.failed) == (0, 1)


# ── Message formatting ───────────────────────────────────────────────────────

def test_an_orphan_event_message_carries_the_facts_an_analyst_needs():
    ev = _event(Severity.CRITICAL, etype=EventType.C2_BEACON,
                evidence={"cv": 0.03, "interval": "30.0s",
                          "note": "internal", "a": 1, "b": 2, "c": 3, "d": 4, "e": 5})
    msg = formatter.format_orphan_event(ev, 2, 5)

    assert "[2/5]" in msg
    assert "45.33.32.156" in msg and "192.168.1.50:22" in msg
    assert "TCP" in msg
    assert "90%" in msg          # confidence
    assert "40" in msg           # packet count
    assert "note" not in msg, "the internal note field must not be published"


def test_an_orphan_event_message_caps_the_evidence_it_prints():
    """Telegram truncates long messages; the useful fields have to fit."""
    ev = _event(evidence={f"field_{i}": i for i in range(20)})
    msg = formatter.format_orphan_event(ev, 1, 1)

    assert sum(1 for line in msg.splitlines() if line.startswith("  •")) == 5


def test_an_orphan_event_message_handles_a_missing_destination():
    ev = _event(dst=None, port=None, protocol=None, timestamp=0.0)
    msg = formatter.format_orphan_event(ev, 1, 1)

    assert "—" in msg
    assert "Protocol:" not in msg
    assert "Time:" not in msg


def test_a_list_valued_evidence_field_is_rendered_inline():
    ev = _event(evidence={"ports": [22, 23, 80, 443, 445, 3389, 8080]})
    msg = formatter.format_orphan_event(ev, 1, 1)

    assert "22, 23, 80, 443, 445" in msg
    assert "8080" not in msg, "only the first five entries are shown"


def test_markup_in_an_event_description_is_escaped():
    """Descriptions quote attacker-controlled strings; raw `<` breaks the parse."""
    ev = _event(description="GET /<script>alert(1)</script>")
    msg = formatter.format_orphan_event(ev, 1, 1)

    assert "<script>" not in msg
    assert "&lt;script&gt;" in msg


def test_a_long_analyst_note_is_trimmed_with_an_ellipsis():
    chain = _chain(events=[_event()], analyst_note="A" * 900)
    msg = formatter.format_chain_alert(chain, 1, 1)

    assert "…" in msg
    assert "A" * 600 not in msg


def test_a_short_analyst_note_is_printed_whole():
    chain = _chain(events=[_event()], analyst_note="Escalate to IR.")
    msg = formatter.format_chain_alert(chain, 1, 1)

    assert "Escalate to IR." in msg
    assert "…" not in msg


def test_a_chain_alert_lists_the_mitre_techniques():
    """Every other chain here carries no techniques, so this block was reached
    only by a CLI test that had picked real Telegram credentials out of the
    developer's .env — which is why it was covered on a workstation and missing
    on the CI runner.
    """
    chain = _chain(events=[_event()], mitre_techniques=[
        MitreTechnique("TA0043", "Reconnaissance", "T1046", "Network Service Discovery"),
        MitreTechnique("TA0006", "Credential Access", "T1110", "Brute Force"),
    ])
    msg = formatter.format_chain_alert(chain, 1, 1)

    assert "<b>MITRE:</b>" in msg
    assert "<code>T1046</code>" in msg
    assert "<code>T1110</code>" in msg


def test_a_chain_alert_prints_at_most_six_techniques():
    """A long chain can map to a dozen techniques; Telegram messages are capped,
    and the header is not the place to spend that budget."""
    chain = _chain(events=[_event()], mitre_techniques=[
        MitreTechnique("TA0043", "Reconnaissance", f"T10{i:02d}", f"Technique {i}")
        for i in range(9)
    ])
    msg = formatter.format_chain_alert(chain, 1, 1)

    assert "<code>T1000</code>" in msg
    assert "<code>T1005</code>" in msg
    assert "<code>T1006</code>" not in msg


def test_a_clean_scan_message_names_the_file_and_stays_honest():
    msg = formatter.format_clean_scan("benign.pcap")

    assert "benign.pcap" in msg
    assert "No HIGH or CRITICAL" in msg
    assert "Low/Medium findings may still exist" in msg
