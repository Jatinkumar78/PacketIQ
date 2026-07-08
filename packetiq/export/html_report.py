"""
Standalone HTML report generator.

Produces a single self-contained .html file (inline CSS + an inline SVG network
graph — no external assets, no internet) from a completed analysis. Deterministic
and AI-free, so it works offline and in CI.

The report is "court-ready": it carries a chain-of-custody header (capture file
name/size/SHA-256, analysis time, tool version), an executive summary, MITRE
ATT&CK coverage, per-finding explainability (why each finding was raised and the
recommended action), and a print stylesheet so "Save as PDF" produces a clean,
paginated, light-on-white document.
"""

from __future__ import annotations

import html
import math
from datetime import datetime

from packetiq.utils.helpers import format_bytes, format_duration, is_private_ip

_SEV_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#f59e0b", "MEDIUM": "#06b6d4", "LOW": "#22c55e"}
_PREC_COLOR = {"Confirmed": "#16a34a", "High": "#16a34a", "Probable": "#d97706", "Tentative": "#64748b"}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _network_svg(result, events) -> str:
    """Simple force-free circular network graph of the top talkers + flows."""
    counts = {}
    for ip, c in result.ip_src_counts.items():
        counts[ip] = counts.get(ip, 0) + c
    for ip, c in result.ip_dst_counts.items():
        counts[ip] = counts.get(ip, 0) + c
    top = [ip for ip, _ in sorted(counts.items(), key=lambda x: -x[1])[:14]]
    if len(top) < 2:
        return "<p class='muted'>Not enough hosts to graph.</p>"

    bad = {e.dst_ip for e in events if e.dst_ip} | {e.src_ip for e in events if e.src_ip}

    W = H = 560
    cx = cy = W / 2
    R = 210
    pos = {}
    n = len(top)
    for i, ip in enumerate(top):
        ang = 2 * math.pi * i / n - math.pi / 2
        pos[ip] = (cx + R * math.cos(ang), cy + R * math.sin(ang))

    edges = []
    flows = sorted(result.flows.values(), key=lambda f: -f.bytes_total)
    for fl in flows:
        if fl.src_ip in pos and fl.dst_ip in pos and len(edges) < 40:
            edges.append((fl.src_ip, fl.dst_ip))

    parts = [f'<svg viewBox="0 0 {W} {H}" width="100%" style="max-width:620px">']
    for a, b in edges:
        x1, y1 = pos[a]; x2, y2 = pos[b]
        parts.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="#94a3b888" stroke-width="1"/>')
    for ip, (x, y) in pos.items():
        if ip in bad:
            fill = "#dc2626"
        elif is_private_ip(ip):
            fill = "#3b82f6"
        else:
            fill = "#f59e0b"
        r = 6 + min(12, math.log10(max(counts.get(ip, 1), 1)) * 4)
        parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r:.0f}" fill="{fill}" opacity="0.85"/>')
        parts.append(f'<text x="{x:.0f}" y="{y - r - 4:.0f}" font-size="10" fill="#475569" '
                     f'text-anchor="middle">{_esc(ip)}</text>')
    parts.append("</svg>")
    parts.append('<div class="legend"><span class="dot" style="background:#3b82f6"></span>internal '
                 '<span class="dot" style="background:#f59e0b"></span>external '
                 '<span class="dot" style="background:#dc2626"></span>flagged</div>')
    return "".join(parts)


def _events_rows(events) -> str:
    from packetiq import triage
    rows = []
    for e in events:
        c = _SEV_COLOR.get(e.severity.value, "#94a3b8")
        prec = triage.precision(e)
        pc = _PREC_COLOR.get(prec, "#64748b")
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        rows.append(
            f"<tr><td><span class='badge' style='background:{c}'>{_esc(e.severity.value)}</span></td>"
            f"<td><span class='pill' style='color:{pc};border-color:{pc}'>{_esc(prec)}</span></td>"
            f"<td>{_esc(e.event_type.value.replace('_',' '))}</td>"
            f"<td>{_esc(e.src_ip or '—')}</td><td>{_esc(dst)}</td>"
            f"<td>{int(round(float(e.confidence or 0)*100))}%</td>"
            f"<td>{_esc(e.description)}</td></tr>"
        )
    return "\n".join(rows) or "<tr><td colspan='7' class='muted'>No threats detected.</td></tr>"


def _findings_detail(events) -> str:
    """Per-finding explainability — why it was raised + recommended action."""
    from packetiq import triage
    if not events:
        return "<p class='muted'>No findings to detail.</p>"
    out = []
    for i, e in enumerate(events[:40], 1):
        ex = triage.explain(e)
        c = _SEV_COLOR.get(e.severity.value, "#94a3b8")
        pc = _PREC_COLOR.get(ex["precision"], "#64748b")
        evp = "".join(f"<li>{_esc(p)}</li>" for p in ex["evidence_points"])
        mitre = ", ".join(f"{m['id']} {m['name']}" for m in ex["mitre"])
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        out.append(
            f"<div class='finding'>"
            f"<h3>{i}. {_esc(e.event_type.value.replace('_',' '))} "
            f"<span class='badge' style='background:{c}'>{_esc(e.severity.value)}</span> "
            f"<span class='pill' style='color:{pc};border-color:{pc}'>{_esc(ex['precision'])} · {ex['confidence_pct']}%</span></h3>"
            f"<p class='muted'>{_esc(e.src_ip or '—')} → {_esc(dst)} · {_esc(ex['kill_chain_phase'])}</p>"
            f"<p><b>What:</b> {_esc(ex['what'])}</p>"
            f"<p><b>Why it matters:</b> {_esc(ex['why'])}</p>"
            + (f"<p><b>Evidence:</b></p><ul>{evp}</ul>" if evp else "")
            + f"<p class='rec'><b>Recommended action:</b> {_esc(ex['recommendation'])}</p>"
            + (f"<p class='muted'>MITRE: {_esc(mitre)}</p>" if mitre else "")
            + "</div>"
        )
    if len(events) > 40:
        out.append(f"<p class='muted'>… and {len(events) - 40} more finding(s) in the events table above.</p>")
    return "\n".join(out)


def _attack_coverage_html(events) -> str:
    from packetiq.export.attack_navigator import coverage
    cov = coverage(events)
    if not cov:
        return "<p class='muted'>No ATT&CK techniques mapped.</p>"
    by_tactic: dict = {}
    for t in cov:
        by_tactic.setdefault(t["tactic"], []).append(t)
    cols = []
    for tactic, techs in by_tactic.items():
        cells = "".join(
            f"<div class='tcell' style='border-left:3px solid {_SEV_COLOR.get(t['severity'],'#888')}'>"
            f"<b>{_esc(t['id'])}</b> <span class='muted'>×{t['count']}</span><br>{_esc(t['name'])}</div>"
            for t in techs
        )
        cols.append(f"<div class='tcol'><div class='thead'>{_esc(tactic)}</div>{cells}</div>")
    return f"<div class='matrix'>{''.join(cols)}</div>"


def _chains_html(chains) -> str:
    if not chains:
        return "<p class='muted'>No multi-stage attack chains correlated.</p>"
    out = []
    for i, c in enumerate(chains, 1):
        techs = ", ".join(f"{t.technique_id}" for t in c.mitre_techniques[:8])
        phases = " → ".join(c.kill_chain_phases) if c.kill_chain_phases else "—"
        out.append(
            f"<div class='chain'><h3>{i}. {_esc(c.name)} "
            f"<span class='pill'>{_esc(c.severity.value)}</span> "
            f"<span class='pill'>{int(c.confidence*100)}%</span></h3>"
            f"<p>{_esc(c.description)}</p>"
            f"<p class='muted'>Kill chain: {_esc(phases)}<br>MITRE: {_esc(techs)}</p>"
            + (f"<p class='note'>{_esc(c.analyst_note)}</p>" if c.analyst_note else "")
            + "</div>"
        )
    return "\n".join(out)


def _iocs_html(events, result) -> str:
    ips = sorted({e.dst_ip for e in events if e.dst_ip and not is_private_ip(e.dst_ip)})
    domains = sorted({e.evidence.get("domain") or e.evidence.get("indicator")
                      for e in events if (e.evidence.get("domain") or
                                          (e.evidence.get("kind") == "domain" and e.evidence.get("indicator")))})
    domains = [d for d in domains if d]
    parts = []
    if ips:
        parts.append("<b>IP indicators</b><ul>" + "".join(f"<li>{_esc(i)}</li>" for i in ips) + "</ul>")
    if domains:
        parts.append("<b>Domain indicators</b><ul>" + "".join(f"<li>{_esc(d)}</li>" for d in domains) + "</ul>")
    return "".join(parts) or "<p class='muted'>No external IOCs extracted.</p>"


def _exec_summary(file_meta, result, events, chains, risk) -> str:
    sev = risk.by_severity or {}
    from collections import Counter
    top_types = Counter(e.event_type.value.replace("_", " ") for e in events
                        if e.severity.value in ("CRITICAL", "HIGH"))
    top = ", ".join(t for t, _ in top_types.most_common(3)) or "no high-severity findings"
    return (
        f"PacketIQ analysed <b>{_esc(file_meta.get('filename',''))}</b> "
        f"({result.total_packets:,} packets over {format_duration(max(0.0, result.capture_end - result.capture_start))}). "
        f"The overall risk is <b>{risk.score}/100 ({_esc(risk.tier)})</b>. "
        f"A total of <b>{len(events)} finding(s)</b> were raised "
        f"({sev.get('CRITICAL',0)} critical, {sev.get('HIGH',0)} high, "
        f"{sev.get('MEDIUM',0)} medium, {sev.get('LOW',0)} low), correlated into "
        f"<b>{len(chains)} attack chain(s)</b>. Principal concerns: <b>{_esc(top)}</b>. "
        f"Every finding below is evidence-backed and graded for precision; see the "
        f"detailed analysis for the reasoning and recommended actions."
    )


def _vulns_html(vulns: dict) -> str:
    """Optional vulnerability section (NVD CPE + CVSS + CISA KEV) — only rendered
    when an assessment is supplied (it requires a network lookup)."""
    if not vulns or not vulns.get("products"):
        return ""
    rk = vulns.get("risk", {})
    tot = vulns.get("totals", {})
    out = [f"<p><b>Vulnerability risk:</b> {rk.get('score', 0)}/100 ({_esc(rk.get('tier', ''))}) · "
           f"{tot.get('cves', 0)} CVE(s), {tot.get('kev', 0)} actively exploited (CISA KEV).</p>"]
    for c in vulns.get("correlations", []):
        out.append(f"<p class='note'>⚡ Exploit attempt for {_esc(c.get('name'))} "
                   f"({_esc(', '.join(c.get('cves', [])))}) → target {_esc(c.get('target'))}"
                   + (f" — runs {_esc(', '.join(c.get('target_software', [])))}" if c.get("target_software") else "") + "</p>")
    for p in vulns["products"]:
        rows = "".join(
            f"<tr><td>{_esc(c['id'])}</td><td>{_esc(c['cvss'])}</td><td>{_esc(c['severity'])}</td>"
            f"<td>{'KEV' if c.get('kev') else ''}{' · ransomware' if c.get('ransomware') else ''}</td></tr>"
            for c in p.get("cves", [])) or "<tr><td colspan='4' class='muted'>No CVEs.</td></tr>"
        out.append(
            f"<div class='finding'><h3>{_esc(p['product'])} {_esc(p['version'])} "
            f"<span class='pill'>{len(p.get('cves', []))} CVE(s)</span></h3>"
            f"<p class='muted'>{_esc(p.get('source', ''))} · CPE {_esc(p.get('cpe') or 'n/a')} · "
            f"hosts {_esc(', '.join(p.get('ips', [])))}</p>"
            f"<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Status</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>")
    return "\n".join(out)


def build_html(file_meta: dict, result, events, chains, risk, attrs=None,
               *, pcap_sha256: str | None = None, tool_version: str = "1.0.0",
               analyst: str | None = None, vulns: dict | None = None) -> str:
    risk_color = _SEV_COLOR.get(risk.tier, "#94a3b8")
    dur = max(0.0, result.capture_end - result.capture_start)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    sev_counts = risk.by_severity or {}

    def stat(label, val):
        return f"<div class='stat'><div class='v'>{_esc(val)}</div><div class='l'>{label}</div></div>"

    stats = "".join([
        stat("Packets", f"{result.total_packets:,}"),
        stat("Bytes", format_bytes(result.total_bytes)),
        stat("Duration", format_duration(dur)),
        stat("Flows", f"{len(result.flows):,}"),
        stat("External IPs", len(result.external_ips)),
        stat("Events", len(events)),
        stat("Chains", len(chains)),
    ])

    def coc(label, val):
        return f"<tr><td class='cl'>{_esc(label)}</td><td class='cv'>{val}</td></tr>"

    custody = "".join([
        coc("Capture file", _esc(file_meta.get("filename", "—"))),
        coc("File size", _esc(format_bytes(result.total_bytes))),
        coc("SHA-256", f"<code>{_esc(pcap_sha256)}</code>" if pcap_sha256 else "<span class='muted'>not computed</span>"),
        coc("Capture window", f"{_esc(datetime.fromtimestamp(result.capture_start).strftime('%Y-%m-%d %H:%M:%S')) if result.capture_start else '—'} → "
                              f"{_esc(datetime.fromtimestamp(result.capture_end).strftime('%Y-%m-%d %H:%M:%S')) if result.capture_end else '—'}"),
        coc("Analysed", _esc(generated)),
        coc("Analyst", _esc(analyst) if analyst else "<span class='muted'>—</span>"),
        coc("Tool", f"PacketIQ v{_esc(tool_version)}"),
    ])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PacketIQ Report — {_esc(file_meta.get('filename',''))}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0; background:#0b0f1a; color:#e2e8f0; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 24px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  h2 {{ font-size: 16px; margin: 28px 0 10px; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }}
  h3 {{ font-size: 14px; margin: 0 0 6px; }}
  .muted {{ color:#94a3b8; }} .note {{ color:#fbbf24; font-size:13px; }} .rec {{ color:#34d399; }}
  .risk {{ display:inline-block; padding:6px 14px; border-radius:8px; font-weight:700; color:#fff; background:{risk_color}; }}
  .summary {{ background:#111827; border:1px solid #1e293b; border-left:4px solid {risk_color}; border-radius:10px; padding:14px 16px; margin:14px 0; font-size:13px; line-height:1.5; }}
  .custody {{ background:#0d1424; border:1px solid #1e293b; border-radius:10px; padding:6px 14px; margin:12px 0; }}
  .custody td {{ padding:5px 8px; border-bottom:1px solid #16203400; font-size:12px; }}
  .custody .cl {{ color:#94a3b8; width:140px; }} .custody .cv {{ color:#e2e8f0; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:12px; margin:16px 0; }}
  .stat {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:12px 16px; min-width:90px; }}
  .stat .v {{ font-size:20px; font-weight:700; }} .stat .l {{ font-size:11px; color:#94a3b8; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:7px 8px; border-bottom:1px solid #1e293b; vertical-align:top; }}
  th {{ color:#94a3b8; font-weight:600; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; }}
  .pill {{ background:#1e293b; color:#cbd5e1; padding:2px 8px; border-radius:10px; font-size:11px; border:1px solid #334155; }}
  .chain, .finding {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:12px 16px; margin-bottom:10px; }}
  .finding p {{ margin:5px 0; font-size:13px; }} .finding ul {{ margin:4px 0 4px 18px; color:#cbd5e1; font-size:12px; }}
  .matrix {{ display:flex; gap:8px; overflow-x:auto; }}
  .tcol {{ min-width:150px; flex:1; }}
  .thead {{ font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:.04em; padding-bottom:6px; border-bottom:1px solid #1e293b; margin-bottom:6px; }}
  .tcell {{ background:#111827; border:1px solid #1e293b; border-radius:5px; padding:6px 8px; margin-bottom:5px; font-size:11px; }}
  .legend {{ font-size:11px; color:#94a3b8; margin-top:6px; }}
  .legend .dot {{ display:inline-block; width:9px; height:9px; border-radius:50%; margin:0 4px 0 10px; vertical-align:middle; }}
  .foot {{ margin-top:30px; color:#64748b; font-size:11px; }}
  /* Print / Save-as-PDF: clean light document with sensible page breaks */
  @media print {{
    :root {{ color-scheme: light; }}
    body {{ background:#fff; color:#0f172a; }}
    .wrap {{ max-width:none; padding:0 6px; }}
    h2 {{ page-break-after:avoid; border-bottom:1px solid #cbd5e1; }}
    .summary, .custody, .stat, .chain, .finding, .tcell {{ background:#fff !important; border-color:#cbd5e1 !important; }}
    .custody .cv, .finding p, td, h1, h2, h3 {{ color:#0f172a !important; }}
    .muted {{ color:#475569 !important; }} .rec {{ color:#047857 !important; }}
    .pill {{ background:#f1f5f9; color:#0f172a; }}
    .finding, .chain {{ page-break-inside:avoid; }}
    a {{ color:#1d4ed8; text-decoration:none; }}
    .no-print {{ display:none !important; }}
  }}
</style></head>
<body><div class="wrap">
  <h1>PacketIQ — SOC Analysis Report</h1>
  <p class="muted">{_esc(file_meta.get('filename',''))} · generated {generated}</p>
  <p><span class="risk">RISK {risk.score}/100 · {_esc(risk.tier)}</span>
     &nbsp;<span class="muted">{_esc(risk.summary)}</span></p>

  <h2>Executive summary</h2>
  <div class="summary">{_exec_summary(file_meta, result, events, chains, risk)}</div>

  <h2>Chain of custody</h2>
  <div class="custody"><table>{custody}</table></div>

  <div class="stats">{stats}</div>

  <h2>Severity breakdown</h2>
  <p>{"".join(f"<span class='pill' style='border-left:4px solid {_SEV_COLOR.get(s,'#888')}'>&nbsp;{_esc(s)}: {sev_counts.get(s,0)}&nbsp;</span> " for s in ('CRITICAL','HIGH','MEDIUM','LOW'))}</p>

  <h2>MITRE ATT&CK coverage</h2>
  {_attack_coverage_html(events)}

  {("<h2>Vulnerability assessment (NVD + CISA KEV)</h2>" + _vulns_html(vulns)) if vulns and vulns.get("products") else ""}

  <h2>Network graph (top talkers)</h2>
  {_network_svg(result, events)}

  <h2>Detection events ({len(events)})</h2>
  <table><thead><tr><th>Severity</th><th>Precision</th><th>Type</th><th>Source</th><th>Destination</th><th>Conf.</th><th>Description</th></tr></thead>
  <tbody>{_events_rows(events)}</tbody></table>

  <h2>Finding analysis (why &amp; recommended actions)</h2>
  {_findings_detail(events)}

  <h2>Attack chains ({len(chains)})</h2>
  {_chains_html(chains)}

  <h2>Indicators of compromise</h2>
  {_iocs_html(events, result)}

  <p class="foot">Generated by PacketIQ v{_esc(tool_version)} · behavioural + threat-intel analysis ·
     all findings are derived from the captured evidence and should be validated against the raw capture.
     Precision grades indicate detection confidence, not legal certainty.</p>
</div></body></html>"""
