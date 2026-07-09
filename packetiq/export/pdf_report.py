"""
Professional SOC report as a PDF — built from the serialised analysis result the
web app already holds, so it needs no re-parsing of the capture. Used to attach a
polished, shareable report to Telegram alerts (and downloadable from the web UI).

Rendered with ReportLab (pure-Python, offline, no system libraries). If ReportLab
isn't installed, build_pdf() returns False and callers fall back to text-only.

Every value in the PDF comes from the deterministic analysis — no figure is
invented here. The report only presents what the detectors and extractors found.
"""

from __future__ import annotations

from datetime import datetime

# Severity ordering + palette, shared by the tables below.
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_SEV_HEX = {"CRITICAL": "#b3163b", "HIGH": "#c65402", "MEDIUM": "#8a6d00", "LOW": "#2f7d32"}


def available() -> bool:
    """True when ReportLab is importable (so a real PDF can be produced)."""
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:
        return False


def build_pdf(out_path: str, res: dict) -> bool:
    """Render the analysis result dict to a professional PDF at out_path.
    Returns True on success, False if ReportLab is unavailable or rendering fails."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except Exception:
        return False

    try:
        meta = res.get("meta", {}) or {}
        risk = res.get("risk", {}) or {}
        events = list(res.get("events", []) or [])
        chains = list(res.get("chains", []) or [])
        fname = meta.get("filename", "capture")

        styles = getSampleStyleSheet()
        h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=15, spaceBefore=10,
                            spaceAfter=5, textColor=colors.HexColor("#0b1f3a"))
        h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=11.5, spaceBefore=12,
                            spaceAfter=4, textColor=colors.HexColor("#12325c"))
        body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=8.7, leading=12,
                              alignment=TA_LEFT)
        small = ParagraphStyle("small", parent=body, fontSize=7.8, leading=10,
                               textColor=colors.HexColor("#333333"))
        cell = ParagraphStyle("cell", parent=body, fontSize=7.9, leading=10)
        muted = ParagraphStyle("muted", parent=small, textColor=colors.HexColor("#6b7280"))

        def esc(v) -> str:
            import html
            return html.escape(str(v), quote=False)

        story: list = []

        # ── Title band ────────────────────────────────────────────────────────
        story.append(Paragraph("PacketIQ — Network Forensics &amp; SOC Report", h1))
        story.append(Paragraph(
            f"Capture: <b>{esc(fname)}</b> &nbsp;·&nbsp; Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", small))
        if meta.get("sha256"):
            story.append(Paragraph(f"SHA-256: <font face='Courier'>{esc(meta['sha256'])}</font>", muted))
        story.append(Spacer(1, 4))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#c9d4e5")))

        # ── Risk banner ───────────────────────────────────────────────────────
        tier = str(risk.get("tier", "—")).upper()
        score = risk.get("score", 0)
        banner_c = colors.HexColor(_SEV_HEX.get(tier, "#334155"))
        banner = Table(
            [[Paragraph(f"<font color='white'><b>RISK {esc(score)}/100</b></font>", h2),
              Paragraph(f"<font color='white'><b>{esc(tier)}</b></font>", h2)]],
            colWidths=[70 * mm, 105 * mm])
        banner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), banner_c),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Spacer(1, 8))
        story.append(banner)
        if risk.get("summary"):
            story.append(Spacer(1, 4))
            story.append(Paragraph(esc(risk["summary"]), body))

        # ── 1. Executive summary ──────────────────────────────────────────────
        bd = risk.get("breakdown", {}) or {}
        crit, high = bd.get("CRITICAL", 0), bd.get("HIGH", 0)
        story.append(Paragraph("1. Executive Summary", h2))
        story.append(Paragraph(
            f"This report summarises the automated analysis of <b>{esc(fname)}</b> "
            f"({esc(meta.get('total_packets', 0)):}&nbsp;packets, "
            f"{esc(meta.get('bytes_fmt', '—'))} over {esc(meta.get('duration', '—'))}). "
            f"PacketIQ raised <b>{len(events)}</b> finding(s) — "
            f"<b>{crit}</b> critical, <b>{high}</b> high — correlated into "
            f"<b>{len(chains)}</b> attack chain(s). Overall risk is "
            f"<b>{esc(score)}/100 [{esc(tier)}]</b>.", body))

        # ── 2. Capture overview ───────────────────────────────────────────────
        story.append(Paragraph("2. Capture Overview", h2))
        ov = [
            ["Packets", f"{meta.get('total_packets', 0):,}" if isinstance(meta.get('total_packets'), int) else meta.get('total_packets', '—'),
             "Unique flows", meta.get("unique_flows", "—")],
            ["Total bytes", meta.get("bytes_fmt", "—"), "Source hosts", meta.get("unique_src", "—")],
            ["Capture start", meta.get("capture_start", "—"), "Destination hosts", meta.get("unique_dst", "—")],
            ["Duration", meta.get("duration", "—"), "External IPs", meta.get("external_ips", "—")],
            ["DNS queries", meta.get("dns_queries", "—"), "HTTP requests", meta.get("http_requests", "—")],
        ]
        t = Table([[Paragraph(f"<b>{esc(a)}</b>", cell), Paragraph(esc(b), cell),
                    Paragraph(f"<b>{esc(c)}</b>", cell), Paragraph(esc(d), cell)] for a, b, c, d in ov],
                  colWidths=[32 * mm, 55 * mm, 33 * mm, 55 * mm])
        t.setStyle(_grid(colors))
        story.append(t)

        # ── 3. Findings by severity ───────────────────────────────────────────
        story.append(Paragraph("3. Findings by Severity", h2))
        sev_rows = [[Paragraph("<b>Severity</b>", cell), Paragraph("<b>Count</b>", cell)]]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_rows.append([_sev_chip(sev, colors, Paragraph, cell), Paragraph(str(bd.get(sev, 0)), cell)])
        sev_rows.append([Paragraph("<b>Attack chains</b>", cell), Paragraph(str(len(chains)), cell)])
        t = Table(sev_rows, colWidths=[60 * mm, 30 * mm])
        t.setStyle(_grid(colors))
        story.append(t)

        # ── 4. Top talkers ────────────────────────────────────────────────────
        top_src = res.get("top_src_ips", [])[:8]
        top_dst = res.get("top_dst_ips", [])[:8]
        if top_src or top_dst:
            story.append(Paragraph("4. Top Talkers", h2))
            rows = [[Paragraph("<b>Top sources</b>", cell), Paragraph("<b>Pkts</b>", cell),
                     Paragraph("<b>Top destinations</b>", cell), Paragraph("<b>Pkts</b>", cell)]]
            for i in range(max(len(top_src), len(top_dst))):
                s = top_src[i] if i < len(top_src) else {"ip": "", "count": ""}
                dd = top_dst[i] if i < len(top_dst) else {"ip": "", "count": ""}
                rows.append([Paragraph(esc(s.get("ip", "")), cell), Paragraph(str(s.get("count", "")), cell),
                             Paragraph(esc(dd.get("ip", "")), cell), Paragraph(str(dd.get("count", "")), cell)])
            t = Table(rows, colWidths=[62 * mm, 20 * mm, 62 * mm, 20 * mm])
            t.setStyle(_grid(colors))
            story.append(t)

        # ── 5. Detection findings ─────────────────────────────────────────────
        story.append(Paragraph("5. Detection Findings", h2))
        if events:
            ev_sorted = sorted(events, key=lambda e: (_SEV_ORDER.get(e.get("severity", ""), 9),
                                                      -int(e.get("confidence", 0) or 0)))
            rows = [[Paragraph("<b>Sev</b>", cell), Paragraph("<b>Type</b>", cell),
                     Paragraph("<b>Source → Destination</b>", cell), Paragraph("<b>Conf</b>", cell),
                     Paragraph("<b>Detail</b>", cell)]]
            for e in ev_sorted[:40]:
                dst = esc(e.get("dst_ip", ""))
                if e.get("dst_port"):
                    dst += f":{esc(e['dst_port'])}"
                flow = f"{esc(e.get('src_ip', '') or '—')} → {dst or '—'}"
                rows.append([
                    _sev_chip(e.get("severity", ""), colors, Paragraph, cell),
                    Paragraph(esc(e.get("event_type", "").replace("_", " ")), cell),
                    Paragraph(flow, cell),
                    Paragraph(f"{esc(e.get('confidence', 0))}%", cell),
                    Paragraph(esc((e.get("description", "") or "")[:180]), cell),
                ])
            t = Table(rows, colWidths=[16 * mm, 30 * mm, 55 * mm, 12 * mm, 62 * mm], repeatRows=1)
            t.setStyle(_grid(colors, header=True))
            story.append(t)
            if len(ev_sorted) > 40:
                story.append(Paragraph(f"… and {len(ev_sorted) - 40} more finding(s). "
                                       "See the full HTML report for the complete list.", muted))
        else:
            story.append(Paragraph("No detection findings were raised for this capture.", body))

        # ── 6. Attack chains ──────────────────────────────────────────────────
        if chains:
            story.append(Paragraph("6. Attack Chain Analysis", h2))
            for i, c in enumerate(sorted(chains, key=lambda c: _SEV_ORDER.get(c.get("severity", ""), 9)), 1):
                story.append(Paragraph(
                    f"<b>{i}. {esc(c.get('name', 'Chain'))}</b> "
                    f"[{esc(c.get('severity', ''))}, {esc(c.get('confidence', 0))}% confidence]", body))
                atk = ", ".join(c.get("attacker_ips", [])[:5]) or "—"
                tgt = ", ".join(c.get("target_ips", [])[:5]) or "—"
                story.append(Paragraph(f"Attacker(s): <b>{esc(atk)}</b> → Target(s): <b>{esc(tgt)}</b>", small))
                if c.get("phases"):
                    story.append(Paragraph("Kill chain: " + esc(" → ".join(c["phases"])), small))
                mitre = c.get("mitre", []) or []
                if mitre:
                    ids = ", ".join(f"{m.get('id', '')} {m.get('name', '')}".strip() for m in mitre[:8])
                    story.append(Paragraph("MITRE ATT&amp;CK: " + esc(ids), small))
                if c.get("description"):
                    story.append(Paragraph("<i>" + esc(c["description"][:400]) + "</i>", small))
                story.append(Spacer(1, 4))

        # ── 7. Indicators of compromise ───────────────────────────────────────
        iocs = _collect_iocs(res)
        if iocs:
            story.append(Paragraph("7. Indicators of Compromise", h2))
            for label, values in iocs:
                if values:
                    story.append(Paragraph(
                        f"<b>{esc(label)}:</b> " + esc(", ".join(values[:20])), small))

        # ── 8. Recommended actions ────────────────────────────────────────────
        recs = _collect_recommendations(events)
        if recs:
            story.append(Paragraph("8. Recommended Actions", h2))
            for i, r in enumerate(recs[:10], 1):
                story.append(Paragraph(f"{i}. {esc(r)}", small))

        # ── Footer / methodology ──────────────────────────────────────────────
        story.append(Spacer(1, 10))
        story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#c9d4e5")))
        story.append(Paragraph(
            "Generated by PacketIQ. Findings come from deterministic detectors and threat-intel "
            "feeds bundled with the tool; confidence values reflect detector certainty, not proof. "
            "Validate high-impact findings against your own telemetry before acting.", muted))

        doc = SimpleDocTemplate(out_path, pagesize=A4,
                                leftMargin=16 * mm, rightMargin=14 * mm,
                                topMargin=14 * mm, bottomMargin=14 * mm,
                                title=f"PacketIQ Report — {fname}", author="PacketIQ")
        doc.build(story)
        return True
    except Exception:
        return False


# ── Internal helpers ──────────────────────────────────────────────────────────

def _grid(colors, header: bool = False):
    from reportlab.platypus import TableStyle
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5deeb")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f4f7fb")]),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e7edf6")))
    return TableStyle(style)


def _sev_chip(sev, colors, Paragraph, style):
    c = _SEV_HEX.get(str(sev).upper(), "#475569")
    return Paragraph(f"<font color='{c}'><b>{sev or '—'}</b></font>", style)


def _collect_iocs(res: dict):
    """Group real IOCs from the analysis: threat-intel matches, external
    destinations touched by findings, and DNS names queried."""
    events = res.get("events", []) or []
    intel: list[str] = []
    for m in res.get("threat_intel_matches", []) or []:
        for hit in m.get("matches", [])[:10]:
            ind = hit.get("indicator")
            if ind:
                intel.append(str(ind))
    ext_ips: list[str] = []
    for e in events:
        for ip in (e.get("dst_ip"), e.get("src_ip")):
            if ip and ip not in ext_ips:
                ext_ips.append(ip)
    domains = [d for d, _c in (res.get("dns_top", []) or [])][:20]
    out = []
    if intel:
        out.append(("Threat-intel matches", _dedup(intel)))
    if ext_ips:
        out.append(("IPs in findings", _dedup(ext_ips)))
    if domains:
        out.append(("Domains queried (DNS)", _dedup(domains)))
    return out


def _collect_recommendations(events: list) -> list:
    """Unique, non-empty analyst recommendations attached to findings (real,
    from the triage layer — not invented)."""
    seen: set = set()
    out: list = []
    for e in sorted(events, key=lambda e: _SEV_ORDER.get(e.get("severity", ""), 9)):
        rec = (e.get("recommendation") or "").strip()
        if rec and rec.lower() not in seen:
            seen.add(rec.lower())
            out.append(rec)
    return out


def _dedup(items) -> list:
    seen: set = set()
    out: list = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def build_pdf_bytes(res: dict) -> bytes | None:
    """Convenience: render to a temp file and return the PDF bytes, or None."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    try:
        if not build_pdf(path, res):
            return None
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
