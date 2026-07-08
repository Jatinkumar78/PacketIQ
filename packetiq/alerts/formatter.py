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

# ── Severity cosmetics ────────────────────────────────────────────────────────

SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

EVENT_EMOJI = {
    "BRUTE_FORCE":        "🔨",
    "PORT_SCAN":          "🔍",
    "HOST_SCAN":          "🌐",
    "DNS_ANOMALY":        "🔮",
    "DNS_TUNNELING":      "🕳",
    "CREDENTIAL_EXPOSURE":"🔑",
    "PROTOCOL_MISUSE":    "⚠️",
    "ICMP_TUNNELING":     "📡",
    "SUSPICIOUS_FLAGS":   "🚩",
}

PHASE_EMOJI = {
    "Reconnaissance":      "🔍",
    "Weaponization":       "⚙️",
    "Delivery":            "📦",
    "Exploitation":        "💥",
    "Installation":        "🛠",
    "Command & Control":   "📡",
    "Actions on Objectives":"🎯",
}


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
    sev_emoji = SEV_EMOJI.get(risk.tier, "⚪")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_str = ts_to_str(capture_start) if capture_start else "N/A"

    lines = [
        f"{sev_emoji} <b>PacketIQ Security Alert</b>",
        "",
        f"📁 <b>File:</b> <code>{esc(file_name)}</code>",
        f"🕐 <b>Capture:</b> {esc(start_str)} ({esc(format_duration(capture_duration))})",
        f"📅 <b>Analysed:</b> {now}",
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"<b>🎯 Risk Score: {risk.score}/100 [{esc(risk.tier)}]</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
    ]

    # Severity breakdown
    lines.append("📊 <b>Findings:</b>")
    if risk.by_severity.get("CRITICAL", 0):
        lines.append(f"  🔴 Critical: <b>{risk.by_severity['CRITICAL']}</b>")
    if risk.by_severity.get("HIGH", 0):
        lines.append(f"  🟠 High:     <b>{risk.by_severity['HIGH']}</b>")
    if risk.by_severity.get("MEDIUM", 0):
        lines.append(f"  🟡 Medium:   {risk.by_severity['MEDIUM']}")
    if risk.by_severity.get("LOW", 0):
        lines.append(f"  🟢 Low:      {risk.by_severity['LOW']}")
    lines.append(f"  ⛓  Chains:   <b>{len(chains)}</b>")

    # Top attackers
    if risk.top_sources:
        lines.append("")
        lines.append("🕵 <b>Top Attacker IPs:</b>")
        for ip in risk.top_sources[:5]:
            lines.append(f"  • <code>{esc(ip)}</code>")

    # Top targets
    if risk.top_targets:
        lines.append("")
        lines.append("🎯 <b>Top Target IPs:</b>")
        for ip in risk.top_targets[:5]:
            lines.append(f"  • <code>{esc(ip)}</code>")

    if chains:
        lines.append("")
        lines.append(f"⛓ <b>Attack Chain{'s' if len(chains) > 1 else ''} Detected ({len(chains)}):</b>")
        for chain in chains[:5]:
            sev_e = SEV_EMOJI.get(chain.severity.value, "⚪")
            lines.append(f"  {sev_e} {esc(chain.name)}")

    lines.append("")
    lines.append("<i>Full details in subsequent messages ↓</i>")

    return "\n".join(lines)


def format_chain_alert(chain: AttackChain, index: int, total: int) -> str:
    """
    Detailed alert for a single attack chain.
    """
    sev_emoji = SEV_EMOJI.get(chain.severity.value, "⚪")
    conf_pct  = f"{chain.confidence * 100:.0f}%"

    lines = [
        f"⛓ <b>Attack Chain {index}/{total}</b>",
        f"{sev_emoji} <b>{esc(chain.name)}</b>",
        f"Confidence: <b>{conf_pct}</b> | Events: <b>{chain.event_count}</b>",
        "",
    ]

    # Attacker → Targets
    if chain.attacker_ips:
        attackers = ", ".join(f"<code>{esc(ip)}</code>" for ip in sorted(chain.attacker_ips))
        lines.append(f"🕵 <b>Attacker:</b> {attackers}")
    if chain.target_ips:
        targets = ", ".join(f"<code>{esc(ip)}</code>" for ip in sorted(chain.target_ips))
        lines.append(f"🎯 <b>Targets:</b> {targets}")

    # Kill chain phases
    if chain.kill_chain_phases:
        phase_str = " → ".join(
            f"{PHASE_EMOJI.get(p, '')} {esc(p)}"
            for p in chain.kill_chain_phases
        )
        lines.append(f"🔗 <b>Kill Chain:</b> {phase_str}")

    # MITRE
    if chain.mitre_techniques:
        techs = ", ".join(
            f"<code>{esc(t.technique_id)}</code>"
            for t in chain.mitre_techniques[:6]
        )
        lines.append(f"🛡 <b>MITRE:</b> {techs}")

    # Duration
    if chain.duration > 0:
        lines.append(f"⏱ <b>Duration:</b> {esc(format_duration(chain.duration))}")

    # Description
    lines.append("")
    lines.append(f"<i>{esc(chain.description)}</i>")

    # Analyst note (highlighted)
    if chain.analyst_note:
        lines.append("")
        lines.append("💡 <b>Analyst Note:</b>")
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
            ev_emoji = EVENT_EMOJI.get(e.event_type.value, "•")
            sev_e    = SEV_EMOJI.get(e.severity.value, "")
            dst = (
                f"{esc(e.dst_ip)}:{e.dst_port}"
                if e.dst_ip and e.dst_port
                else esc(e.dst_ip or "—")
            )
            lines.append(
                f"  {sev_e}{ev_emoji} <code>{esc(e.src_ip or '?')}</code> → "
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
    sev_emoji  = SEV_EMOJI.get(event.severity.value, "⚪")
    ev_emoji   = EVENT_EMOJI.get(event.event_type.value, "•")
    event_name = event.event_type.value.replace("_", " ")

    dst = (
        f"{esc(event.dst_ip)}:{event.dst_port}"
        if event.dst_ip and event.dst_port
        else esc(event.dst_ip or "—")
    )

    lines = [
        f"{sev_emoji}{ev_emoji} <b>{esc(event.severity.value)}: {esc(event_name)}</b>"
        f"  [{index}/{total}]",
        "",
        f"🕵 <b>Source:</b> <code>{esc(event.src_ip or '?')}</code>",
        f"🎯 <b>Target:</b> <code>{dst}</code>",
    ]

    if event.protocol:
        lines.append(f"📡 <b>Protocol:</b> {esc(event.protocol)}")

    lines.append(f"🔍 <b>Confidence:</b> {event.confidence * 100:.0f}%")
    lines.append(f"📦 <b>Packets:</b> {event.packet_count:,}")

    if event.timestamp:
        lines.append(f"🕐 <b>Time:</b> {esc(ts_to_str(event.timestamp))}")

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
        "🟢 <b>PacketIQ — Clean Scan</b>\n\n"
        f"📁 <b>File:</b> <code>{esc(file_name)}</code>\n"
        f"📅 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        "✅ No HIGH or CRITICAL threats detected in this capture.\n"
        "<i>Low/Medium findings may still exist — run packetiq analyze for full details.</i>"
    )
