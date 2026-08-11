"""
The PacketIQ incident report as a print-ready PDF.

Built from the serialised analysis result the web app already holds, so it needs
no re-parsing of the capture. Rendered with ReportLab (pure-Python, offline, no
system libraries); if ReportLab isn't installed, build_pdf() returns False and
callers fall back to text-only.

Structure, palette and standing text come from packetiq.export.report_style, so
this document, the HTML export and the AI-written report stay one house style.
Every figure is taken from the deterministic analysis — nothing is invented here.
"""

from __future__ import annotations

from packetiq.export import report_style as st


def available() -> bool:
    """True when ReportLab is importable (so a real PDF can be produced)."""
    try:
        import reportlab  # noqa: F401
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Page furniture: running header, footer, and "Page X of Y" (needs a second pass,
# so the total is only known once every page has been laid out).
# ──────────────────────────────────────────────────────────────────────────────

def _numbered_canvas(meta: dict):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    page_w, page_h = A4
    left, right = 18 * mm, page_w - 14 * mm

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages: list = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for index, state in enumerate(self._pages, start=1):
                self.__dict__.update(state)
                if index > 1:                      # the cover carries no furniture
                    self._header()
                    self._footer(index, total)
                super().showPage()
            super().save()

        def _header(self):
            y = page_h - 12 * mm
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor(st.INK))
            self.drawString(left, y, f"{st.BRAND.upper()}  ·  {st.DOC_TITLE.upper()}")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor(st.MUTED))
            self.drawRightString(right, y, meta["filename"][:60])
            self.setStrokeColor(colors.HexColor(st.RULE))
            self.setLineWidth(0.5)
            self.line(left, y - 2.6 * mm, right, y - 2.6 * mm)

        def _footer(self, index, total):
            y = 12 * mm
            self.setStrokeColor(colors.HexColor(st.RULE))
            self.setLineWidth(0.5)
            self.line(left, y + 4 * mm, right, y + 4 * mm)
            self.setFont("Helvetica-Bold", 6.8)
            self.setFillColor(colors.HexColor(st.MUTED))
            self.drawString(left, y, st.CLASSIFICATION_SHORT)
            self.setFont("Helvetica", 6.8)
            self.drawCentredString((left + right) / 2, y, meta["report_id"])
            self.drawRightString(right, y, f"Page {index - 1} of {total - 1}")

    return NumberedCanvas


def build_pdf(out_path: str, res: dict) -> bool:
    """Render the analysis result to a professional PDF at out_path.
    Returns True on success, False if ReportLab is unavailable or rendering fails."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            PageBreak,
            SimpleDocTemplate,
            Spacer,
        )
    except Exception:
        return False

    try:
        meta = res.get("meta", {}) or {}
        risk = res.get("risk", {}) or {}
        events = list(res.get("events", []) or [])
        chains = list(res.get("chains", []) or [])
        fname = meta.get("filename", "capture")
        rid = st.report_id(fname, meta.get("sha256", ""))

        S = _styles(colors)
        story: list = []
        story += _cover(res, rid, S, colors, mm)
        story.append(PageBreak())

        n = _Counter()
        story += _s_executive(n, res, S)
        story += _s_methodology(n, res, S)
        story += _s_capture(n, meta, S, colors, mm)
        story += _s_risk(n, risk, chains, S, colors, mm)
        story += _s_findings(n, events, S, colors, mm)
        story += _s_finding_details(n, events, S, colors, mm, KeepTogether, Spacer)
        story += _s_chains(n, chains, S, Spacer, KeepTogether)
        story += _s_mitre(n, res, S, colors, mm)
        story += _s_network(n, res, S, colors, mm)
        story += _s_iocs(n, res, S, colors, mm)
        story += _s_actions(n, events, S)
        story += _s_limitations(n, res, S)

        doc = SimpleDocTemplate(
            out_path, pagesize=A4,
            leftMargin=18 * mm, rightMargin=14 * mm,
            topMargin=20 * mm, bottomMargin=20 * mm,
            title=f"{st.BRAND} {st.DOC_TITLE} — {fname}",
            author=st.BRAND, subject=rid,
        )
        doc.build(story, canvasmaker=_numbered_canvas({"filename": fname, "report_id": rid}))
        return True
    except Exception:
        return False


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles(colors):
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    base = getSampleStyleSheet()
    ink, accent, body, slate, muted = (colors.HexColor(c) for c in
                                       (st.INK, st.ACCENT, st.BODY, st.SLATE, st.MUTED))
    return {
        "cover_brand": ParagraphStyle("cb", parent=base["Normal"], fontName="Helvetica-Bold",
                                      fontSize=9, leading=12, textColor=accent, spaceAfter=2),
        "cover_title": ParagraphStyle("ct", parent=base["Normal"], fontName="Helvetica-Bold",
                                      fontSize=24, leading=28, textColor=ink, spaceAfter=4),
        "cover_sub": ParagraphStyle("cs", parent=base["Normal"], fontName="Helvetica",
                                    fontSize=11, leading=15, textColor=slate),
        "h1": ParagraphStyle("h1", parent=base["Normal"], fontName="Helvetica-Bold",
                             fontSize=12, leading=15, textColor=ink,
                             spaceBefore=15, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base["Normal"], fontName="Helvetica-Bold",
                             fontSize=9.4, leading=12.5, textColor=ink,
                             spaceBefore=8, spaceAfter=2),
        "body": ParagraphStyle("b", parent=base["Normal"], fontName="Helvetica",
                               fontSize=9.2, leading=13.6, textColor=body, spaceAfter=4),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontName="Helvetica",
                                fontSize=8.2, leading=11.8, textColor=slate),
        "muted": ParagraphStyle("mu", parent=base["Normal"], fontName="Helvetica",
                                fontSize=7.4, leading=10.5, textColor=muted),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontName="Helvetica",
                               fontSize=8, leading=10.8, textColor=body),
        "cellb": ParagraphStyle("cb2", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=8, leading=10.8, textColor=body),
        "cellh": ParagraphStyle("ch", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=7.8, leading=10.4, textColor=colors.white),
        "mono": ParagraphStyle("mo", parent=base["Normal"], fontName="Courier",
                               fontSize=7.6, leading=10.4, textColor=body),
        # Risk band: each line needs its own leading or the large figure collides
        # with its caption.
        "band_label": ParagraphStyle("bl", parent=base["Normal"], fontName="Helvetica-Bold",
                                     fontSize=7.4, leading=10, textColor=colors.white),
        "band_value": ParagraphStyle("bv", parent=base["Normal"], fontName="Helvetica-Bold",
                                     fontSize=23, leading=26, textColor=colors.white),
    }


class _Counter:
    """Hands out section numbers in the canonical order."""

    def __init__(self):
        self.i = 0

    def next(self) -> str:
        title = st.SECTIONS[self.i] if self.i < len(st.SECTIONS) else ""
        self.i += 1
        return f"{self.i}. {title}"


def _esc(v) -> str:
    import html
    return html.escape(str(v), quote=False)


def _heading(n, S):
    from reportlab.lib import colors
    from reportlab.platypus import HRFlowable, Paragraph
    return [Paragraph(_esc(n.next()), S["h1"]),
            HRFlowable(width="100%", thickness=0.9, color=colors.HexColor(st.ACCENT),
                       spaceBefore=1, spaceAfter=7)]


def _table(rows, widths, colors, mm, header=True, align_left=True):
    from reportlab.platypus import Table, TableStyle
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor(st.RULE)),
        ("LINEBEFORE", (0, 0), (0, -1), 0.4, colors.HexColor(st.RULE)),
        ("LINEAFTER", (-1, 0), (-1, -1), 0.4, colors.HexColor(st.RULE)),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(st.INK)),
            ("TOPPADDING", (0, 0), (-1, 0), 5),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor(st.BG_ALT)]),
        ]
    else:
        style.append(("ROWBACKGROUNDS", (0, 0), (-1, -1),
                      [colors.white, colors.HexColor(st.BG_ALT)]))
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT" if align_left else "CENTER")
    t.setStyle(TableStyle(style))
    return t


def _sev(sev, S):
    from reportlab.platypus import Paragraph
    c = st.SEVERITY_COLOURS.get(str(sev).upper(), st.SLATE)
    return Paragraph(f"<font color='{c}'><b>{_esc(sev or '—')}</b></font>", S["cell"])


# ── Cover ─────────────────────────────────────────────────────────────────────

def _cover(res, rid, S, colors, mm):
    from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle
    meta = res.get("meta", {}) or {}
    risk = res.get("risk", {}) or {}
    events = res.get("events", []) or []
    chains = res.get("chains", []) or []
    tier = str(risk.get("tier", "—")).upper()
    tier_c = colors.HexColor(st.SEVERITY_COLOURS.get(tier, st.SLATE))

    out = [
        HRFlowable(width="100%", thickness=3, color=colors.HexColor(st.ACCENT), spaceAfter=14),
        Paragraph(st.BRAND.upper(), S["cover_brand"]),
        Paragraph(_esc(st.DOC_TITLE), S["cover_title"]),
        Paragraph(_esc(meta.get("filename", "capture")), S["cover_sub"]),
        Spacer(1, 22),
    ]

    # Risk verdict panel — each caption/figure pair is stacked as separate flowables
    # so the large figure keeps its own leading.
    def _stat(label, value):
        return [Paragraph(label, S["band_label"]), Paragraph(value, S["band_value"])]

    band = Table([[
        _stat("OVERALL RISK", f"{_esc(risk.get('score', 0))}<font size='11'>/100</font>"),
        _stat("SEVERITY TIER", f"<font size='19'>{_esc(tier)}</font>"),
        _stat("FINDINGS", f"{len(events)}"
                          f"<font size='9'>&nbsp; in {len(chains)} chain(s)</font>"),
    ]], colWidths=[58 * mm, 58 * mm, 62 * mm])
    band.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), tier_c),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
    ]))
    out += [band, Spacer(1, 8)]
    if risk.get("summary"):
        out += [Paragraph(_esc(risk["summary"]), S["small"]), Spacer(1, 18)]
    else:
        out.append(Spacer(1, 14))

    # Document metadata
    def row(k, v):
        return [Paragraph(_esc(k), S["cellb"]), Paragraph(v, S["cell"])]

    sha = meta.get("sha256", "")
    rows = [
        row("Report reference", f"<font face='Courier'>{_esc(rid)}</font>"),
        row("Generated", _esc(st.generated_at())),
        row("Evidence file", f"<font face='Courier'>{_esc(meta.get('filename', 'capture'))}</font>"),
        row("Evidence SHA-256", f"<font face='Courier' size='7'>{_esc(sha)}</font>" if sha
            else "<i>not recorded</i>"),
        row("Capture window", f"{_esc(meta.get('capture_start', '—'))} "
                              f"(duration {_esc(meta.get('duration', '—'))})"),
        row("Produced by", f"{_esc(st.BRAND)} v{_esc(st.tool_version())} — automated analysis"),
        row("Classification", _esc(st.CLASSIFICATION)),
    ]
    tbl = _table(rows, [42 * mm, 136 * mm], colors, mm, header=False)
    out += [Paragraph("DOCUMENT DETAILS", S["h2"]), Spacer(1, 3), tbl, Spacer(1, 16)]

    out += [
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor(st.RULE), spaceAfter=6),
        Paragraph(
            "This document was generated automatically from the named evidence file. "
            "The findings it contains are the output of deterministic detectors and "
            "reputation lookups; they require analyst validation before they are relied "
            "upon. See <b>Limitations &amp; Assurance</b> at the end of this report.",
            S["muted"]),
    ]
    return out


# ── Sections ──────────────────────────────────────────────────────────────────

def _s_executive(n, res, S):
    from reportlab.platypus import Paragraph
    meta, risk = res.get("meta", {}) or {}, res.get("risk", {}) or {}
    events, chains = res.get("events", []) or [], res.get("chains", []) or []
    bd = risk.get("breakdown", {}) or {}
    crit, high = bd.get("CRITICAL", 0), bd.get("HIGH", 0)
    tier = str(risk.get("tier", "—")).upper()
    pkts = meta.get("total_packets", 0)
    pkts_s = f"{pkts:,}" if isinstance(pkts, int) else str(pkts)

    if crit or high:
        lead = (f"The capture contains activity that warrants analyst attention: "
                f"<b>{crit}</b> critical and <b>{high}</b> high-severity finding(s) were raised.")
    elif events:
        lead = ("No critical or high-severity activity was identified. The findings below are "
                "informational and are provided for completeness.")
    else:
        lead = "No detector raised a finding against this capture."

    out = [
        *_heading(n, S),
        Paragraph(
            f"This report presents the automated analysis of the packet capture "
            f"<b>{_esc(meta.get('filename', 'capture'))}</b>, comprising {pkts_s} packets "
            f"({_esc(meta.get('bytes_fmt', '—'))}) observed over {_esc(meta.get('duration', '—'))}. "
            f"{lead}", S["body"]),
        Paragraph(
            f"In total, <b>{len(events)}</b> finding(s) were correlated into "
            f"<b>{len(chains)}</b> attack chain(s), producing an overall risk score of "
            f"<b>{_esc(risk.get('score', 0))} out of 100</b>, which places this capture in the "
            f"<b>{_esc(tier)}</b> tier. The sections that follow set out the evidence for that "
            f"assessment, the techniques observed, and the actions recommended.", S["body"]),
    ]
    if risk.get("summary"):
        out.append(Paragraph(f"<i>{_esc(risk['summary'])}</i>", S["small"]))
    return out


def _s_methodology(n, res, S):
    from reportlab.platypus import Paragraph
    meta = res.get("meta", {}) or {}
    scope = (f"The analysis was performed against a single evidence file, "
             f"<b>{_esc(meta.get('filename', 'capture'))}</b>")
    if meta.get("sha256"):
        scope += ", whose SHA-256 digest is recorded on the cover of this report"
    scope += (". No traffic was generated, no host was interrogated, and no payload was "
              "decrypted during the analysis.")
    return [
        *_heading(n, S),
        Paragraph("<b>Scope.</b> " + scope, S["body"]),
        # The standing text contains literal "&" (MITRE ATT&CK) — escape it, or
        # ReportLab reads it as the start of an XML entity.
        Paragraph("<b>Method.</b> " + _esc(st.METHODOLOGY), S["body"]),
    ]


def _s_capture(n, meta, S, colors, mm):
    from reportlab.platypus import Paragraph
    pkts = meta.get("total_packets", 0)
    pairs = [
        ("Packets analysed", f"{pkts:,}" if isinstance(pkts, int) else pkts),
        ("Total volume", meta.get("bytes_fmt", "—")),
        ("Capture start", meta.get("capture_start", "—")),
        ("Capture end", meta.get("capture_end", "—")),
        ("Duration", meta.get("duration", "—")),
        ("Unique flows", meta.get("unique_flows", "—")),
        ("Source hosts", meta.get("unique_src", "—")),
        ("Destination hosts", meta.get("unique_dst", "—")),
        ("External addresses", meta.get("external_ips", "—")),
        ("DNS queries", meta.get("dns_queries", "—")),
        ("HTTP requests", meta.get("http_requests", "—")),
    ]
    rows = [[Paragraph("<b>Property</b>", S["cellh"]), Paragraph("<b>Value</b>", S["cellh"]),
             Paragraph("<b>Property</b>", S["cellh"]), Paragraph("<b>Value</b>", S["cellh"])]]
    for i in range(0, len(pairs), 2):
        left = pairs[i]
        right = pairs[i + 1] if i + 1 < len(pairs) else ("", "")
        rows.append([Paragraph(_esc(left[0]), S["cellb"]), Paragraph(_esc(left[1]), S["cell"]),
                     Paragraph(_esc(right[0]), S["cellb"]), Paragraph(_esc(right[1]), S["cell"])])
    return [*_heading(n, S), _table(rows, [38 * mm, 51 * mm, 38 * mm, 51 * mm], colors, mm)]


def _s_risk(n, risk, chains, S, colors, mm):
    from reportlab.platypus import Paragraph, Spacer
    bd = risk.get("breakdown", {}) or {}
    total = sum(bd.get(s, 0) for s in st.SEVERITY_ORDER) or 0
    rows = [[Paragraph("<b>Severity</b>", S["cellh"]), Paragraph("<b>Findings</b>", S["cellh"]),
             Paragraph("<b>Share</b>", S["cellh"]), Paragraph("<b>Interpretation</b>", S["cellh"])]]
    meaning = {
        "CRITICAL": "Confirmed-malicious indicator or successful compromise pattern.",
        "HIGH":     "Strong behavioural evidence of attack activity.",
        "MEDIUM":   "Anomalous or policy-violating activity worth review.",
        "LOW":      "Informational; retained for completeness.",
    }
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = bd.get(sev, 0)
        share = f"{(100.0 * count / total):.0f}%" if total else "—"
        rows.append([_sev(sev, S), Paragraph(str(count), S["cell"]),
                     Paragraph(share, S["cell"]), Paragraph(meaning[sev], S["cell"])])
    rows.append([Paragraph("<b>Total</b>", S["cellb"]), Paragraph(f"<b>{total}</b>", S["cellb"]),
                 Paragraph("", S["cell"]),
                 Paragraph(f"Correlated into <b>{len(chains)}</b> attack chain(s).", S["cell"])])

    out = [*_heading(n, S),
           Paragraph(f"The composite risk score is <b>{_esc(risk.get('score', 0))}/100</b> "
                     f"(<b>{_esc(str(risk.get('tier', '—')).upper())}</b>), derived from the "
                     f"severity, confidence and breadth of the findings below.", S["body"]),
           Spacer(1, 2),
           _table(rows, [30 * mm, 22 * mm, 20 * mm, 106 * mm], colors, mm)]
    top_src = risk.get("top_sources") or []
    top_dst = risk.get("top_targets") or []
    if top_src or top_dst:
        out.append(Spacer(1, 6))
        out.append(Paragraph(
            f"<b>Principal source(s):</b> {_esc(', '.join(top_src[:5]) or '—')}<br/>"
            f"<b>Principal target(s):</b> {_esc(', '.join(top_dst[:5]) or '—')}", S["small"]))
    return out


def _s_findings(n, events, S, colors, mm):
    from reportlab.platypus import Paragraph
    out = _heading(n, S)
    if not events:
        out.append(Paragraph("No detection findings were raised against this capture.", S["body"]))
        return out
    ordered = st.sort_events(events)
    rows = [[Paragraph("<b>#</b>", S["cellh"]), Paragraph("<b>Severity</b>", S["cellh"]),
             Paragraph("<b>Finding</b>", S["cellh"]), Paragraph("<b>Source → Destination</b>", S["cellh"]),
             Paragraph("<b>Conf.</b>", S["cellh"]), Paragraph("<b>First seen</b>", S["cellh"])]]
    for i, e in enumerate(ordered[:45], 1):
        dst = _esc(e.get("dst_ip", "") or "—")
        if e.get("dst_port"):
            dst += f":{_esc(e['dst_port'])}"
        rows.append([
            Paragraph(str(i), S["cell"]),
            _sev(e.get("severity", ""), S),
            Paragraph(_esc(st.event_title(e.get("event_type", ""))), S["cell"]),
            Paragraph(f"<font face='Courier' size='7.2'>{_esc(e.get('src_ip', '') or '—')} → {dst}</font>", S["cell"]),
            Paragraph(f"{_esc(e.get('confidence', 0))}%", S["cell"]),
            Paragraph(_esc(e.get("ts_str", "") or "—"), S["cell"]),
        ])
    out.append(_table(rows, [9 * mm, 22 * mm, 40 * mm, 62 * mm, 16 * mm, 29 * mm], colors, mm))
    if len(ordered) > 45:
        out.append(Paragraph(f"A further {len(ordered) - 45} finding(s) are omitted from this "
                             f"table; the complete set is available in the HTML export.", S["muted"]))
    return out


def _s_finding_details(n, events, S, colors, mm, KeepTogether, Spacer):
    from reportlab.platypus import Paragraph
    out = _heading(n, S)
    detail = [e for e in st.sort_events(events) if e.get("severity") in ("CRITICAL", "HIGH")][:10]
    if not detail:
        out.append(Paragraph("No critical or high-severity findings require detailed treatment.",
                             S["body"]))
        return out
    out.append(Paragraph("Each critical and high-severity finding is set out below with the "
                         "evidence that produced it and the detector's own precision note.", S["body"]))
    for i, e in enumerate(detail, 1):
        dst = _esc(e.get("dst_ip", "") or "—")
        if e.get("dst_port"):
            dst += f":{_esc(e['dst_port'])}"
        sev = str(e.get("severity", "")).upper()
        c = st.SEVERITY_COLOURS.get(sev, st.SLATE)
        block = [
            Paragraph(f"<font color='{c}'><b>{_esc(sev)}</b></font> &nbsp; "
                      f"<b>{i}. {_esc(st.event_title(e.get('event_type', '')))}</b>",
                      S["h2"]),
            Paragraph(f"<font face='Courier' size='7.6'>{_esc(e.get('src_ip', '') or '—')} → {dst}</font>"
                      f" &nbsp;·&nbsp; {_esc(e.get('protocol', '') or '—')}"
                      f" &nbsp;·&nbsp; {_esc(e.get('packet_count', 0))} packet(s)"
                      f" &nbsp;·&nbsp; confidence {_esc(e.get('confidence', 0))}%"
                      f" &nbsp;·&nbsp; {_esc(e.get('ts_str', '') or 'time not recorded')}", S["muted"]),
            Spacer(1, 3),
        ]
        if e.get("description"):
            block.append(Paragraph(_esc(e["description"]), S["small"]))
        if e.get("what"):
            block.append(Paragraph(f"<b>What this is.</b> {_esc(e['what'])}", S["small"]))
        if e.get("why"):
            block.append(Paragraph(f"<b>Why it was flagged.</b> {_esc(e['why'])}", S["small"]))
        pts = e.get("evidence_points") or []
        if pts:
            block.append(Paragraph("<b>Evidence.</b> " + "; ".join(_esc(p) for p in pts[:6]), S["small"]))
        tech = _tech_ids(e)
        if tech:
            block.append(Paragraph(f"<b>ATT&amp;CK.</b> {_esc(tech)}", S["small"]))
        if e.get("precision"):
            block.append(Paragraph(f"<b>Detector precision.</b> {_esc(e['precision'])}", S["muted"]))
        if e.get("recommendation"):
            block.append(Paragraph(f"<b>Recommended response.</b> {_esc(e['recommendation'])}", S["small"]))
        block.append(Spacer(1, 9))
        out.append(KeepTogether(block))
    return out


def _tech_ids(e) -> str:
    ids = []
    for t in e.get("mitre") or []:
        if isinstance(t, dict) and t.get("id"):
            ids.append(f"{t['id']} {t.get('name', '')}".strip())
        elif isinstance(t, str):
            ids.append(t)
    return ", ".join(ids[:6])


def _s_chains(n, chains, S, Spacer, KeepTogether):
    from reportlab.platypus import Paragraph
    out = _heading(n, S)
    if not chains:
        out.append(Paragraph("No findings correlated into a multi-stage attack chain.", S["body"]))
        return out
    out.append(Paragraph("Findings that share actors, targets and timing are grouped into chains, "
                         "each mapped to the kill-chain phases it spans.", S["body"]))
    for i, c in enumerate(sorted(chains, key=lambda c: st.SEVERITY_ORDER.get(c.get("severity", ""), 9)), 1):
        sev = str(c.get("severity", "")).upper()
        col = st.SEVERITY_COLOURS.get(sev, st.SLATE)
        block = [
            Paragraph(f"<b>{i}. {_esc(c.get('name', 'Attack chain'))}</b> &nbsp; "
                      f"<font color='{col}'><b>{_esc(sev)}</b></font> "
                      f"<font size='8'>· {_esc(c.get('confidence', 0))}% confidence "
                      f"· {_esc(c.get('event_count', 0))} event(s)</font>", S["h2"]),
            Paragraph(f"<b>Attacker(s):</b> {_esc(', '.join(c.get('attacker_ips', [])[:5]) or '—')} "
                      f"&nbsp;<b>Target(s):</b> {_esc(', '.join(c.get('target_ips', [])[:5]) or '—')}",
                      S["small"]),
        ]
        if c.get("phases"):
            block.append(Paragraph(f"<b>Kill chain:</b> {_esc(' → '.join(c['phases']))}", S["small"]))
        mitre = c.get("mitre") or []
        if mitre:
            ids = ", ".join(f"{m.get('id', '')} {m.get('name', '')}".strip() for m in mitre[:8])
            block.append(Paragraph(f"<b>ATT&amp;CK:</b> {_esc(ids)}", S["small"]))
        if c.get("first_seen") or c.get("last_seen"):
            block.append(Paragraph(f"<b>Observed:</b> {_esc(c.get('first_seen', '—'))} to "
                                   f"{_esc(c.get('last_seen', '—'))}", S["small"]))
        if c.get("description"):
            block.append(Paragraph(f"<i>{_esc(c['description'][:500])}</i>", S["small"]))
        block.append(Spacer(1, 8))
        out.append(KeepTogether(block))
    return out


def _s_mitre(n, res, S, colors, mm):
    from reportlab.platypus import Paragraph
    out = _heading(n, S)
    rows_data = st.mitre_rows(res)
    if not rows_data:
        out.append(Paragraph("No findings mapped to a MITRE ATT&amp;CK technique.", S["body"]))
        return out
    out.append(Paragraph("Techniques observed in this capture, as mapped by the detectors that "
                         "raised each finding.", S["body"]))
    rows = [[Paragraph("<b>Tactic</b>", S["cellh"]), Paragraph("<b>Technique</b>", S["cellh"]),
             Paragraph("<b>Name</b>", S["cellh"]), Paragraph("<b>Findings</b>", S["cellh"]),
             Paragraph("<b>Highest severity</b>", S["cellh"])]]
    for tactic, tid, name, count, sev in rows_data:
        rows.append([Paragraph(_esc(tactic), S["cell"]),
                     Paragraph(f"<font face='Courier' size='7.4'>{_esc(tid)}</font>", S["cell"]),
                     Paragraph(_esc(name), S["cell"]),
                     Paragraph(str(count), S["cell"]),
                     _sev(sev, S)])
    out.append(_table(rows, [40 * mm, 24 * mm, 60 * mm, 20 * mm, 34 * mm], colors, mm))
    return out


def _count(v) -> str:
    """Thousands-separated when numeric, passed through otherwise."""
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return _esc(v)


def _s_network(n, res, S, colors, mm):
    from reportlab.platypus import KeepTogether, Paragraph, Spacer
    out = _heading(n, S)
    mix = st.protocol_mix(res)
    if mix:
        rows = [[Paragraph("<b>Protocol</b>", S["cellh"]), Paragraph("<b>Packets</b>", S["cellh"]),
                 Paragraph("<b>Share of capture</b>", S["cellh"])]]
        for name, count, pct in mix:
            rows.append([Paragraph(_esc(name), S["cell"]),
                         Paragraph(_count(count), S["cell"]),
                         Paragraph(f"{pct:.1f}%", S["cell"])])
        # Keep each sub-heading with its table so neither is orphaned at a page break.
        out += [KeepTogether([Paragraph("Protocol composition", S["h2"]), Spacer(1, 2),
                              _table(rows, [50 * mm, 40 * mm, 44 * mm], colors, mm)]),
                Spacer(1, 8)]

    top_src = res.get("top_src_ips", [])[:8]
    top_dst = res.get("top_dst_ips", [])[:8]
    if top_src or top_dst:
        rows = [[Paragraph("<b>Top sources</b>", S["cellh"]), Paragraph("<b>Packets</b>", S["cellh"]),
                 Paragraph("<b>Top destinations</b>", S["cellh"]), Paragraph("<b>Packets</b>", S["cellh"])]]
        for i in range(max(len(top_src), len(top_dst))):
            s = top_src[i] if i < len(top_src) else {"ip": "", "count": ""}
            d = top_dst[i] if i < len(top_dst) else {"ip": "", "count": ""}
            rows.append([
                Paragraph(f"<font face='Courier' size='7.4'>{_esc(s.get('ip', ''))}</font>", S["cell"]),
                Paragraph(_count(s.get("count", "")), S["cell"]),
                Paragraph(f"<font face='Courier' size='7.4'>{_esc(d.get('ip', ''))}</font>", S["cell"]),
                Paragraph(_count(d.get("count", "")), S["cell"])])
        out.append(KeepTogether([Paragraph("Principal hosts by volume", S["h2"]), Spacer(1, 2),
                                 _table(rows, [55 * mm, 22 * mm, 55 * mm, 22 * mm], colors, mm)]))
    if not mix and not (top_src or top_dst):
        out.append(Paragraph("No network activity statistics are available for this capture.", S["body"]))
    return out


def _s_iocs(n, res, S, colors, mm):
    from reportlab.platypus import Paragraph
    out = _heading(n, S)
    groups = st.iocs(res)
    if not groups:
        out.append(Paragraph("No indicators of compromise were extracted from this capture.", S["body"]))
        return out
    out.append(Paragraph("Indicators observed in this capture, for use in hunting and blocking. "
                         "Presence in this list reflects observation, not confirmed malice.", S["body"]))
    rows = [[Paragraph("<b>Category</b>", S["cellh"]), Paragraph("<b>Count</b>", S["cellh"]),
             Paragraph("<b>Indicators</b>", S["cellh"])]]
    for label, vals in groups:
        rows.append([Paragraph(_esc(label), S["cellb"]), Paragraph(str(len(vals)), S["cell"]),
                     Paragraph("<font face='Courier' size='7'>"
                               + _esc(", ".join(vals[:24]))
                               + ("…" if len(vals) > 24 else "") + "</font>", S["cell"])])
    out.append(_table(rows, [42 * mm, 16 * mm, 120 * mm], colors, mm))
    return out


def _s_actions(n, events, S):
    from reportlab.platypus import Paragraph
    out = _heading(n, S)
    recs = st.recommendations(events)
    if not recs:
        out.append(Paragraph("No response actions are recommended for this capture.", S["body"]))
        return out
    out.append(Paragraph("Actions are ordered by the severity of the finding that produced them. "
                         "They are the detectors' standing guidance, not a substitute for your "
                         "incident-response procedure.", S["body"]))
    for i, r in enumerate(recs[:12], 1):
        out.append(Paragraph(f"<b>{i}.</b>&nbsp;&nbsp;{_esc(r)}", S["small"]))
    return out


def _s_limitations(n, res, S):
    from reportlab.platypus import Paragraph
    out = [*_heading(n, S), Paragraph(_esc(st.LIMITATIONS), S["body"])]
    if res.get("attributions"):
        out.append(Paragraph(_esc(st.ATTRIBUTION_CAVEAT), S["body"]))
    out.append(Paragraph(
        f"Report {_esc(st.report_id(res.get('meta', {}).get('filename', 'capture'), res.get('meta', {}).get('sha256', '')))} "
        f"· generated {_esc(st.generated_at())} by {_esc(st.BRAND)} v{_esc(st.tool_version())}. "
        f"{_esc(st.CLASSIFICATION)}.", S["muted"]))
    return out

