"""
Alert Formatter — converts PacketIQ analysis data into HTML-formatted
Telegram messages.

Message hierarchy:
  1. Summary alert    — sent first, always; one per analysis run
  2. Chain alerts     — one per CRITICAL/HIGH attack chain
  3. Orphan alerts    — HIGH+ events not covered by any chain (up to 5)

All output is HTML-safe (uses esc() from telegram.py).
"""

from datetime import datetime

from packetiq.alerts.telegram import esc
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent
from packetiq.detection.risk_scorer import RiskReport
from packetiq.utils.helpers import format_duration, ts_to_str

# ── Severity labels ───────────────────────────────────────────────────────────
# Plain text, no emoji: these messages are read as security reporting, and a
# named severity survives every client, log, and copy-paste that a coloured
# circle does not.

_SEV_LABEL = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
}


def sev_tag(severity: str) -> str:
    """Bracketed severity tag, e.g. '[HIGH]'. Unknown severities read '[—]'."""
    return f"[{_SEV_LABEL.get(str(severity).upper(), '—')}]"


# ── Public formatters ─────────────────────────────────────────────────────────

def format_summary(
    file_name: str,
    risk: RiskReport,
    events: list[DetectionEvent],
    chains: list[AttackChain],
    capture_start: float = 0.0,
    capture_duration: float = 0.0,
) -> str:
    """
    Top-level summary message. Sent once at the start of an alert batch.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_str = ts_to_str(capture_start) if capture_start else "N/A"

    lines = [
        f"<b>PacketIQ Security Alert {sev_tag(risk.tier)}</b>",
        "",
        f"<b>File:</b> <code>{esc(file_name)}</code>",
        f"<b>Capture:</b> {esc(start_str)} ({esc(format_duration(capture_duration))})",
        f"<b>Analysed:</b> {now}",
        "",
        "──────────────────────────",
        f"<b>Risk Score: {risk.score}/100 [{esc(risk.tier)}]</b>",
        "──────────────────────────",
        "",
    ]

    # Severity breakdown
    lines.append("<b>Findings:</b>")
    for sev, label in (("CRITICAL", "Critical"), ("HIGH", "High"),
                       ("MEDIUM", "Medium"), ("LOW", "Low")):
        if risk.by_severity.get(sev, 0):
            lines.append(f"  {label + ':':<10} <b>{risk.by_severity[sev]}</b>")
    lines.append(f"  {'Chains:':<10} <b>{len(chains)}</b>")

    # Top attackers
    if risk.top_sources:
        lines.append("")
        lines.append("<b>Top Attacker IPs:</b>")
        for ip in risk.top_sources[:5]:
            lines.append(f"  • <code>{esc(ip)}</code>")

    # Top targets
    if risk.top_targets:
        lines.append("")
        lines.append("<b>Top Target IPs:</b>")
        for ip in risk.top_targets[:5]:
            lines.append(f"  • <code>{esc(ip)}</code>")

    if chains:
        lines.append("")
        lines.append(f"<b>Attack Chain{'s' if len(chains) > 1 else ''} Detected ({len(chains)}):</b>")
        for chain in chains[:5]:
            lines.append(f"  {sev_tag(chain.severity.value)} {esc(chain.name)}")

    lines.append("")
    lines.append("<i>Full details in subsequent messages.</i>")

    return "\n".join(lines)


def format_webapp_findings(res: dict) -> str:
    """
    Professional Telegram summary built from the web app's *serialised* analysis
    result (plain dicts), so it needs no domain objects. This is what the
    "Notify" button sends — a proper SOC brief (risk, severity breakdown, top
    talkers, attack chains with MITRE, and the key findings with evidence),
    instead of a two-line list. A full PDF report is attached separately.
    """
    meta = res.get("meta", {}) or {}
    risk = res.get("risk", {}) or {}
    events = res.get("events", []) or []
    chains = res.get("chains", []) or []
    bd = risk.get("breakdown", {}) or {}
    tier = str(risk.get("tier", "—")).upper()
    fname = meta.get("filename", "capture")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        f"<b>PacketIQ Security Report {sev_tag(tier)}</b>",
        "",
        f"<b>File:</b> <code>{esc(fname)}</code>",
        f"<b>Risk:</b> <b>{esc(risk.get('score', 0))}/100 [{esc(tier)}]</b>",
        f"<b>Analysed:</b> {now}",
        "──────────────────────────",
    ]
    if risk.get("summary"):
        lines += [f"<i>{esc(risk['summary'])}</i>", ""]

    # Severity breakdown (single compact line)
    brk = "  ".join(
        f"{s.title()} {bd.get(s, 0)}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if bd.get(s, 0)
    ) or "none"
    lines.append(f"<b>Findings:</b> {len(events)}  ({brk})  ·  <b>{len(chains)}</b> chain(s)")

    # Capture context
    lines.append(
        f"{esc(meta.get('total_packets', 0))} pkts · "
        f"{esc(meta.get('bytes_fmt', '—'))} · {esc(meta.get('duration', '—'))} · "
        f"{esc(meta.get('external_ips', 0))} external IPs"
    )

    # Top talkers
    top_src = res.get("top_src_ips", [])[:3]
    if top_src:
        lines.append("")
        lines.append("<b>Top sources:</b> " + ", ".join(
            f"<code>{esc(s.get('ip', ''))}</code>" for s in top_src))

    # Attack chains (with MITRE)
    if chains:
        lines.append("")
        lines.append(f"<b>Attack chain{'s' if len(chains) > 1 else ''}:</b>")
        for c in sorted(chains, key=lambda c: len(c.get("target_ips", [])), reverse=True)[:4]:
            atk = ", ".join(c.get("attacker_ips", [])[:2]) or "?"
            tgt = ", ".join(c.get("target_ips", [])[:2]) or "?"
            lines.append(f"  {sev_tag(c.get('severity', ''))} <b>{esc(c.get('name', 'Chain'))}</b>")
            lines.append(f"     <code>{esc(atk)}</code> → <code>{esc(tgt)}</code>")
            mitre = c.get("mitre", []) or []
            if mitre:
                ids = ", ".join(m.get("id", "") for m in mitre[:5] if m.get("id"))
                if ids:
                    lines.append(f"     MITRE: {esc(ids)}")

    # Key findings (CRITICAL/HIGH first, with one-line evidence)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    ranked = sorted(events, key=lambda e: (order.get(e.get("severity", ""), 9),
                                          -int(e.get("confidence", 0) or 0)))
    top = [e for e in ranked if e.get("severity") in ("CRITICAL", "HIGH")][:6] or ranked[:4]
    if top:
        lines.append("")
        lines.append("<b>Key findings:</b>")
        for e in top:
            sev = str(e.get("severity", "")).upper()
            name = str(e.get("event_type", "")).replace("_", " ")
            dst = esc(e.get("dst_ip", "") or "—")
            if e.get("dst_port"):
                dst += f":{esc(e['dst_port'])}"
            lines.append(
                f"  <b>[{esc(sev)}] {esc(name)}</b> "
                f"({esc(e.get('confidence', 0))}%)")
            lines.append(f"     <code>{esc(e.get('src_ip', '') or '?')}</code> → <code>{dst}</code>")
            desc = (e.get("description", "") or "")[:140]
            if desc:
                lines.append(f"     <i>{esc(desc)}</i>")

    lines.append("")
    lines.append("<b>Full SOC report attached as PDF.</b>")
    return "\n".join(lines)


def format_chain_alert(chain: AttackChain, index: int, total: int) -> str:
    """
    Detailed alert for a single attack chain.
    """
    conf_pct  = f"{chain.confidence * 100:.0f}%"

    lines = [
        f"<b>Attack Chain {index}/{total}</b>",
        f"{sev_tag(chain.severity.value)} <b>{esc(chain.name)}</b>",
        f"Confidence: <b>{conf_pct}</b> | Events: <b>{chain.event_count}</b>",
        "",
    ]

    # Attacker → Targets
    if chain.attacker_ips:
        attackers = ", ".join(f"<code>{esc(ip)}</code>" for ip in sorted(chain.attacker_ips))
        lines.append(f"<b>Attacker:</b> {attackers}")
    if chain.target_ips:
        targets = ", ".join(f"<code>{esc(ip)}</code>" for ip in sorted(chain.target_ips))
        lines.append(f"<b>Targets:</b> {targets}")

    # Kill chain phases
    if chain.kill_chain_phases:
        phase_str = " → ".join(esc(p) for p in chain.kill_chain_phases)
        lines.append(f"<b>Kill Chain:</b> {phase_str}")

    # MITRE
    if chain.mitre_techniques:
        techs = ", ".join(
            f"<code>{esc(t.technique_id)}</code>"
            for t in chain.mitre_techniques[:6]
        )
        lines.append(f"<b>MITRE:</b> {techs}")

    # Duration
    if chain.duration > 0:
        lines.append(f"<b>Duration:</b> {esc(format_duration(chain.duration))}")

    # Description
    lines.append("")
    lines.append(f"<i>{esc(chain.description)}</i>")

    # Analyst note (highlighted)
    if chain.analyst_note:
        lines.append("")
        lines.append("<b>Analyst Note:</b>")
        # Trim note to 500 chars for Telegram
        note = chain.analyst_note[:500]
        if len(chain.analyst_note) > 500:
            note += "…"
        lines.append(f"<i>{esc(note)}</i>")

    # Linked events summary
    if chain.events:
        lines.append("")
        lines.append("<b>Linked Events:</b>")
        for e in chain.events[:8]:
            dst = (
                f"{esc(e.dst_ip)}:{e.dst_port}"
                if e.dst_ip and e.dst_port
                else esc(e.dst_ip or "—")
            )
            lines.append(
                f"  {sev_tag(e.severity.value)} <code>{esc(e.src_ip or '?')}</code> → "
                f"<code>{dst}</code>"
            )
            # Short description truncated
            desc = e.description[:100] + ("…" if len(e.description) > 100 else "")
            lines.append(f"     <i>{esc(desc)}</i>")

    return "\n".join(lines)


def format_orphan_event(event: DetectionEvent, index: int, total: int) -> str:
    """
    Alert for a HIGH/CRITICAL event that is not part of any chain.
    """
    event_name = event.event_type.value.replace("_", " ")

    dst = (
        f"{esc(event.dst_ip)}:{event.dst_port}"
        if event.dst_ip and event.dst_port
        else esc(event.dst_ip or "—")
    )

    lines = [
        f"<b>{esc(event.severity.value)}: {esc(event_name)}</b>"
        f"  [{index}/{total}]",
        "",
        f"<b>Source:</b> <code>{esc(event.src_ip or '?')}</code>",
        f"<b>Target:</b> <code>{dst}</code>",
    ]

    if event.protocol:
        lines.append(f"<b>Protocol:</b> {esc(event.protocol)}")

    lines.append(f"<b>Confidence:</b> {event.confidence * 100:.0f}%")
    lines.append(f"<b>Packets:</b> {event.packet_count:,}")

    if event.timestamp:
        lines.append(f"<b>Time:</b> {esc(ts_to_str(event.timestamp))}")

    lines.append("")
    lines.append("<b>Description:</b>")
    lines.append(f"<i>{esc(event.description)}</i>")

    # Key evidence fields
    evidence_shown = 0
    for k, v in event.evidence.items():
        if k == "note" or evidence_shown >= 5:
            continue
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v[:5])
        lines.append(f"  • <b>{esc(str(k))}:</b> <code>{esc(str(v))}</code>")
        evidence_shown += 1

    return "\n".join(lines)


def format_clean_scan(file_name: str) -> str:
    """Message sent when no threats are detected."""
    return (
        "<b>PacketIQ — Clean Scan</b>\n\n"
        f"<b>File:</b> <code>{esc(file_name)}</code>\n"
        f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "No HIGH or CRITICAL threats detected in this capture.\n"
        "<i>Low/Medium findings may still exist — run packetiq analyze for full details.</i>"
    )
