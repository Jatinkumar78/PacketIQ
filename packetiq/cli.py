"""
PacketIQ CLI — Entry point for all commands.

Usage:
    packetiq analyze <file.pcap>
    packetiq report  <file.pcap>
    packetiq chat    <file.pcap>
    packetiq version
"""

import sys
from pathlib import Path

import click

from packetiq.correlation.engine import CorrelationEngine
from packetiq.detection.engine import DetectionEngine
from packetiq.detection.models import Severity
from packetiq.display.terminal import TerminalUI
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.utils.helpers import format_bytes, format_duration


def _run_pipeline(pcap_path: Path, ui: TerminalUI, quiet: bool = False) -> tuple:
    """
    Shared parse → extract → detect → correlate pipeline.
    Returns (file_meta, result, events, risk, chains, fingerprints).
    quiet=True suppresses section headers (used by fuse command).
    """
    if not quiet:
        ui.print_status(f"Target: {pcap_path}", status="info")
        ui.print_status(f"Size:   {format_bytes(pcap_path.stat().st_size)}", status="info")

    # ── Parse ─────────────────────────────────────────────────
    if not quiet:
        ui.print_section("PCAP PARSING", "layer 1 — packet ingestion")
    try:
        parser = PCAPParser(str(pcap_path))
    except FileNotFoundError as e:
        ui.print_status(str(e), status="error")
        sys.exit(1)

    extractor = DataExtractor()
    packet_count = 0

    with ui.make_progress("Parsing packets...") as progress:
        task = progress.add_task("Parsing packets...", total=None)
        for record in parser.stream():
            extractor.feed(record)
            packet_count += 1
            if packet_count % 1000 == 0:
                progress.update(task, description=f"Parsed {packet_count:,} packets...")

    result = extractor.finalize()
    file_meta = parser.file_summary()
    file_meta["packet_count"] = packet_count
    if not quiet:
        ui.print_status(f"Parsed {packet_count:,} packets successfully.", status="ok")

    # ── Detect ────────────────────────────────────────────────
    if not quiet:
        ui.print_section("THREAT DETECTION", "running all detectors")
    engine = DetectionEngine()
    detection_steps = {
        "brute_force":        "Brute force detector...",
        "port_scan":          "Port scan detector...",
        "dns_anomaly":        "DNS anomaly detector...",
        "protocol_misuse":    "Protocol misuse detector...",
        "beacon_analysis":    "Beacon periodicity analysis...",
        "http_inspection":    "HTTP deep inspection...",
        "credential_exposure":"Credential exposure scan...",
        "ja3_fingerprinting": "JA3/JA4 TLS fingerprinting...",
        "tls_inspection":     "TLS certificate inspection...",
        "file_carving":       "File carving + hash reputation...",
        "ioc_enrichment":     "Threat-intel IOC enrichment...",
        "os_fingerprinting":  "Passive OS fingerprinting...",
        "risk_scoring":       "Computing risk score...",
    }
    with ui.make_progress() as progress:
        task = progress.add_task("Running detectors...", total=len(detection_steps))

        def _cb(step_name: str):
            label = detection_steps.get(step_name, step_name)
            progress.update(task, description=label, advance=1)

        events, risk, fingerprints = engine.run(result, str(pcap_path), progress_callback=_cb)

    if not quiet:
        ui.print_status(
            f"{len(events)} event(s) | Risk: {risk.score}/100 [{risk.tier}]",
            status="warn" if events else "ok",
        )

    # ── Correlate ─────────────────────────────────────────────
    if not quiet:
        ui.print_section("ATTACK CORRELATION", "linking events into chains")
    correlator = CorrelationEngine()
    chains = correlator.correlate(events)
    if not quiet:
        ui.print_status(
            f"{len(chains)} attack chain(s) identified.",
            status="warn" if chains else "ok",
        )

    return file_meta, result, events, risk, chains, fingerprints


ui = TerminalUI()


# ──────────────────────────────────────────────────────────────────────────────
# Root group
# ──────────────────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def main(ctx):
    """
    \b
    PacketIQ — AI PCAP Forensics & SOC Copilot
    Defensive network intelligence for SOC analysts.
    """
    ui.print_banner()
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ──────────────────────────────────────────────────────────────────────────────
# analyze command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("analyze")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--top", "-t", default=10, show_default=True,
              help="Number of top entries to show in each table.")
@click.option("--full", is_flag=True, default=False,
              help="Show all rows (no truncation).")
@click.option("--alert/--no-alert", default=False,
              help="Send Telegram alerts for HIGH/CRITICAL findings.")
@click.option("--alert-threshold",
              type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
              default="HIGH", show_default=True,
              help="Minimum severity level to alert on.")
@click.option("--timeline/--no-timeline", default=True, show_default=True,
              help="Show attack timeline reconstruction.")
def analyze(pcap_file: str, top: int, full: bool, alert: bool, alert_threshold: str, timeline: bool):
    """
    Parse and analyze a PCAP file.

    \b
    Example:
        packetiq analyze capture.pcap
        packetiq analyze capture.pcap --top 20
        packetiq analyze capture.pcap --alert
        packetiq analyze capture.pcap --alert --alert-threshold CRITICAL
    """
    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    # ── Summary panel ──────────────────────────────────────────────────
    ui.print_section("CAPTURE SUMMARY")
    meta = DataExtractor.capture_metadata(result)
    ui.print_summary_panel("CAPTURE METADATA", meta)

    # ── Protocol distribution ──────────────────────────────────────────
    ui.print_section("PROTOCOL DISTRIBUTION")
    proto_rows = sorted(result.protocol_counts.items(), key=lambda x: x[1], reverse=True)
    total_pkts = result.total_packets or 1
    proto_table_rows = [
        [proto, f"{cnt:,}", f"{(cnt/total_pkts)*100:.1f}%"]
        for proto, cnt in proto_rows
    ]
    ui.print_table(
        "Protocol Breakdown",
        columns=[
            ("Protocol",   "bold green",  "left"),
            ("Packets",    "cyan",        "right"),
            ("% of Total", "dim white",   "right"),
        ],
        rows=proto_table_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top talkers (source IPs) ───────────────────────────────────────
    ui.print_section("TOP TALKERS", "source IPs by packet volume")
    talkers = DataExtractor.top_talkers(result, n=top)
    talker_rows = [
        [t["ip"], f"{t['packets']:,}", f"{(t['packets']/total_pkts)*100:.1f}%",
         "INTERNAL" if _is_private(t["ip"]) else "EXTERNAL"]
        for t in talkers
    ]
    ui.print_table(
        f"Top {top} Source IPs",
        columns=[
            ("IP Address",  "bold green", "left"),
            ("Packets",     "cyan",       "right"),
            ("% Traffic",   "dim white",  "right"),
            ("Scope",       "yellow",     "center"),
        ],
        rows=talker_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top destinations ───────────────────────────────────────────────
    ui.print_section("TOP DESTINATIONS", "destination IPs by packet volume")
    dests = DataExtractor.top_destinations(result, n=top)
    dest_rows = [
        [d["ip"], f"{d['packets']:,}", "INTERNAL" if _is_private(d["ip"]) else "EXTERNAL"]
        for d in dests
    ]
    ui.print_table(
        f"Top {top} Destination IPs",
        columns=[
            ("IP Address", "bold green", "left"),
            ("Packets",    "cyan",       "right"),
            ("Scope",      "yellow",     "center"),
        ],
        rows=dest_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top destination ports ──────────────────────────────────────────
    ui.print_section("PORT ACTIVITY", "destination ports by packet count")
    ports = DataExtractor.top_ports(result, n=top)
    port_rows = [
        [str(p["port"]), p["service"], f"{p['packets']:,}"]
        for p in ports
    ]
    ui.print_table(
        f"Top {top} Destination Ports",
        columns=[
            ("Port",    "bold green", "right"),
            ("Service", "cyan",       "left"),
            ("Packets", "dim white",  "right"),
        ],
        rows=port_rows,
        max_rows=top if not full else 9999,
    )

    # ── Top flows ─────────────────────────────────────────────────────
    ui.print_section("TOP FLOWS", "bidirectional sessions by byte volume")
    flows = DataExtractor.top_flows(result, n=top)
    flow_rows = [
        [
            fl.src_ip,
            str(fl.src_port or "*"),
            fl.dst_ip,
            str(fl.dst_port or "*"),
            fl.protocol,
            fl.service,
            f"{fl.packets:,}",
            format_bytes(fl.bytes_total),
            format_duration(fl.duration),
        ]
        for fl in flows
    ]
    ui.print_table(
        f"Top {top} Flows",
        columns=[
            ("Src IP",    "green",     "left"),
            ("Sport",     "dim white", "right"),
            ("Dst IP",    "cyan",      "left"),
            ("Dport",     "dim white", "right"),
            ("Proto",     "yellow",    "center"),
            ("Service",   "magenta",   "left"),
            ("Pkts",      "dim white", "right"),
            ("Bytes",     "bold cyan", "right"),
            ("Duration",  "dim white", "right"),
        ],
        rows=flow_rows,
        max_rows=top if not full else 9999,
    )

    # ── DNS summary ───────────────────────────────────────────────────
    if result.dns_queries:
        ui.print_section("DNS ACTIVITY", f"{len(result.dns_queries)} queries captured")
        # Deduplicate and count
        dns_counts: dict = {}
        for q in result.dns_queries:
            dns_counts[q["qname"]] = dns_counts.get(q["qname"], 0) + 1
        dns_rows = sorted(dns_counts.items(), key=lambda x: x[1], reverse=True)
        ui.print_table(
            "DNS Query Names",
            columns=[
                ("Domain",  "bold green", "left"),
                ("Queries", "cyan",       "right"),
            ],
            rows=[[d, str(c)] for d, c in dns_rows],
            max_rows=top if not full else 9999,
        )

    # ── HTTP summary ──────────────────────────────────────────────────
    if result.http_requests:
        ui.print_section("HTTP ACTIVITY", f"{len(result.http_requests)} requests captured")
        http_rows = [
            [
                r["method"] or "?",
                r["host"]   or "?",
                r["path"]   or "/",
                r["src"]    or "?",
            ]
            for r in result.http_requests[:top]
        ]
        ui.print_table(
            "HTTP Requests",
            columns=[
                ("Method", "bold yellow", "center"),
                ("Host",   "bold green",  "left"),
                ("Path",   "cyan",        "left"),
                ("From",   "dim white",   "left"),
            ],
            rows=http_rows,
            max_rows=top if not full else 9999,
        )

    # ── External IPs note ─────────────────────────────────────────────
    if result.external_ips:
        ui.print_section("EXTERNAL IP CONTACTS")
        ext_rows = sorted(result.external_ips)
        ui.print_table(
            "External IPs Observed",
            columns=[("IP Address", "bold red", "left")],
            rows=[[ip] for ip in ext_rows],
            max_rows=top if not full else 9999,
        )

    # ── Risk Score Banner ─────────────────────────────────────────────
    ui.print_section("RISK ASSESSMENT")
    risk_data = {
        "Overall Risk Score": f"{risk.score}/100",
        "Risk Tier":          risk.tier,
        "Total Events":       str(risk.event_count),
        "Critical":           str(risk.by_severity.get("CRITICAL", 0)),
        "High":               str(risk.by_severity.get("HIGH", 0)),
        "Medium":             str(risk.by_severity.get("MEDIUM", 0)),
        "Low":                str(risk.by_severity.get("LOW", 0)),
    }
    if risk.top_sources:
        risk_data["Top Attacker IPs"] = ", ".join(risk.top_sources[:3])
    if risk.top_targets:
        risk_data["Top Target IPs"]   = ", ".join(risk.top_targets[:3])

    ui.print_summary_panel(f"RISK SCORE: {risk.score}/100 [{risk.tier}]", risk_data)

    if risk.summary:
        ui.print_alert(risk.tier, risk.summary)

    # ── Detection Events Table ────────────────────────────────────────
    if events:
        ui.print_section("DETECTION EVENTS", f"{len(events)} findings")
        sev_colors = {
            "CRITICAL": "bold red",
            "HIGH":     "bold yellow",
            "MEDIUM":   "bold cyan",
            "LOW":      "bold green",
        }
        event_rows = []
        for e in events:
            sev_tag = f"[{sev_colors.get(e.severity.value, 'white')}]{e.severity.value}[/{sev_colors.get(e.severity.value, 'white')}]"
            dst_info = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
            event_rows.append([
                e.severity.value,
                e.event_type.value.replace("_", " "),
                e.src_ip or "—",
                dst_info,
                e.description[:72] + ("…" if len(e.description) > 72 else ""),
            ])

        ui.print_table(
            "Threat Intelligence Findings",
            columns=[
                ("Severity",    "bold white", "center"),
                ("Type",        "yellow",     "left"),
                ("Source IP",   "red",        "left"),
                ("Destination", "cyan",       "left"),
                ("Description", "dim white",  "left"),
            ],
            rows=event_rows,
            max_rows=top if not full else 9999,
        )
    else:
        ui.print_status("No threats detected in this capture.", status="ok")

    # ── Correlation Engine ────────────────────────────────────────────
    ui.print_section("ATTACK CORRELATION", "linking events into attack chains")

    if chains:
        ui.print_status(f"{len(chains)} attack chain(s) identified.", status="warn")

        for i, chain in enumerate(chains, 1):
            sev_color = {
                "CRITICAL": "red", "HIGH": "yellow",
                "MEDIUM": "cyan",  "LOW": "green",
            }.get(chain.severity.value, "white")

            # Chain header panel
            chain_data = {
                "Chain ID":         chain.chain_id,
                "Severity":         chain.severity.value,
                "Confidence":       f"{chain.confidence * 100:.0f}%",
                "Events Linked":    str(chain.event_count),
                "Attacker IPs":     ", ".join(sorted(chain.attacker_ips)) or "—",
                "Target IPs":       ", ".join(sorted(chain.target_ips)) or "—",
                "Kill Chain Phases": " → ".join(chain.kill_chain_phases) if chain.kill_chain_phases else "—",
                "Primary Phase":    chain.primary_phase or "—",
            }

            # MITRE ATT&CK techniques
            if chain.mitre_techniques:
                techs = "; ".join(
                    f"{t.technique_id} ({t.technique_name})"
                    for t in chain.mitre_techniques[:6]
                )
                chain_data["MITRE Techniques"] = techs

            ui.print_summary_panel(
                f"CHAIN {i}/{len(chains)}: {chain.name}",
                chain_data,
            )

            # Description and analyst note
            ui.print_raw(f"  [dim white]{chain.description}[/dim white]")
            if chain.analyst_note:
                ui.print_raw("\n  [bold yellow]► ANALYST NOTE:[/bold yellow]")
                ui.print_raw(f"  [yellow]{chain.analyst_note}[/yellow]")

            # Linked events mini-table
            if chain.events:
                ev_rows = [
                    [
                        e.severity.value,
                        e.event_type.value.replace("_", " "),
                        e.src_ip or "—",
                        f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—"),
                        e.description[:60] + ("…" if len(e.description) > 60 else ""),
                    ]
                    for e in chain.events
                ]
                ui.print_table(
                    "Linked Events",
                    columns=[
                        ("Sev",         "bold white", "center"),
                        ("Type",        "yellow",     "left"),
                        ("Source",      "red",        "left"),
                        ("Target",      "cyan",       "left"),
                        ("Description", "dim white",  "left"),
                    ],
                    rows=ev_rows,
                    max_rows=8 if not full else 9999,
                )
            ui.print_divider(char="·")

    else:
        ui.print_status("No multi-stage attack chains correlated.", status="ok")

    # ── OS Fingerprints ───────────────────────────────────────────────
    if fingerprints:
        ui.print_section("PASSIVE OS FINGERPRINTS", f"{len(fingerprints)} host(s) identified")
        fp_rows = [
            [f.src_ip, f"{f.os_icon} {f.os_guess}", str(f.observed_ttl),
             str(f.initial_ttl), str(f.hops), "EXTERNAL" if f.is_external else "internal"]
            for f in fingerprints[:top]
        ]
        ui.print_table(
            "Device OS Signatures",
            columns=[
                ("Source IP",    "bold green", "left"),
                ("OS Guess",     "cyan",       "left"),
                ("Observed TTL", "dim white",  "right"),
                ("Initial TTL",  "dim white",  "right"),
                ("Hops",         "dim white",  "right"),
                ("Scope",        "yellow",     "center"),
            ],
            rows=fp_rows,
            max_rows=top if not full else 9999,
        )

    # ── Timeline Engine ───────────────────────────────────────────────
    if timeline:
        ui.print_section("ATTACK TIMELINE", "chronological event reconstruction")
        from packetiq.timeline import TimelineBuilder, TimelineRenderer
        tl = TimelineBuilder().build(result, events, chains)
        TimelineRenderer(ui).render(tl, max_events=60 if not full else 9999)

    # ── Telegram Alerts ───────────────────────────────────────────────
    if alert:
        _send_telegram_alerts(
            pcap_path=pcap_path,
            result=result,
            events=events,
            chains=chains,
            risk=risk,
            threshold=alert_threshold,
        )

    # ── Record to history (best-effort) ────────────────────────────────
    try:
        from packetiq import storage
        storage.record(
            filename=pcap_path.name, packets=result.total_packets,
            risk_score=risk.score, risk_tier=risk.tier,
            event_count=len(events), chain_count=len(chains),
            top_attacker=(risk.top_sources[0] if risk.top_sources else ""),
        )
    except Exception:
        pass

    # ── Done ──────────────────────────────────────────────────────────
    ui.print_divider()
    ui.print_status(
        f"Analysis complete — {len(events)} events | "
        f"{len(chains)} chain(s) | Risk: {risk.score}/100 [{risk.tier}]",
        status="ok",
    )
    ui.print_status("Run 'packetiq report' to generate a full SOC report.", status="info")
    ui.print_divider()


# ──────────────────────────────────────────────────────────────────────────────
# report command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("report")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None,
              help="Output file path for the report (default: report_<name>_<ts>.md).")
@click.option("--alert/--no-alert", default=False,
              help="Send Telegram alerts + attach report file after generation.")
def report(pcap_file: str, out: str, alert: bool):
    """
    Run full analysis and generate an AI SOC report.

    \b
    Example:
        packetiq report capture.pcap
        packetiq report capture.pcap --out /tmp/incident_report.md
        packetiq report capture.pcap --alert
    """
    from packetiq.copilot import build_context
    from packetiq.copilot.multi_provider import MultiProviderClient

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("AI SOC REPORT GENERATION", "Gemini / Groq / Anthropic / local Ollama")

    client = MultiProviderClient()
    if not client.available():
        ui.print_status(
            "No AI provider available. Add a free GEMINI_API_KEY or GROQ_API_KEY to "
            ".env, or run a local model with Ollama (ollama serve). See .env.example.",
            status="error",
        )
        sys.exit(1)

    ui.print_status("Building PCAP context for AI...", status="loading")
    context = build_context(file_meta, result, events, chains, risk.score, risk.tier)
    client.load_context(context)
    ui.print_status(f"Using {client.model_label}.", status="ok")

    ui.print_status("Generating SOC report (this may take 30–60 seconds)...", status="loading")

    from packetiq.copilot.prompts import SLASH_PROMPTS
    try:
        report_text = client.single_message(SLASH_PROMPTS["report"])
    except Exception as e:
        ui.print_status(f"Report generation failed: {e}", status="error")
        sys.exit(1)

    # Save report
    if out:
        out_path = Path(out)
    else:
        from datetime import datetime
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        stem = pcap_path.stem
        out_path = pcap_path.parent / f"report_{stem}_{ts}.md"

    out_path.write_text(report_text, encoding="utf-8")
    ui.print_status(f"Report saved: {out_path.resolve()}", status="ok")

    if alert:
        _send_telegram_alerts(
            pcap_path   = pcap_path,
            result      = result,
            events      = events,
            chains      = chains,
            risk        = risk,
            threshold   = "HIGH",
            report_path = str(out_path),
        )

    ui.print_divider()


# ──────────────────────────────────────────────────────────────────────────────
# chat command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("chat")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
def chat(pcap_file: str):
    """
    Run full analysis then open an AI chat session about the PCAP.

    \b
    Example:
        packetiq chat capture.pcap
    """
    from packetiq.copilot import InteractiveChat, build_context
    from packetiq.copilot.multi_provider import MultiProviderClient

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("AI COPILOT", "loading analysis context")

    client = MultiProviderClient()
    if not client.available():
        ui.print_status(
            "No AI provider available. Add a free GEMINI_API_KEY or GROQ_API_KEY to "
            ".env, or run a local model with Ollama (ollama serve). See .env.example.",
            status="error",
        )
        sys.exit(1)

    ui.print_status("Building PCAP context for AI...", status="loading")
    context = build_context(file_meta, result, events, chains, risk.score, risk.tier)
    client.load_context(context)
    ui.print_status(
        f"Context built: {len(context):,} chars | {len(context.split()) :,} tokens (approx).",
        status="ok",
    )

    ui.print_status(f"Copilot ready ({client.model_label}). Starting interactive session.", status="ok")

    session = InteractiveChat(
        client     = client,
        pcap_name  = pcap_path.name,
        report_dir = str(pcap_path.parent),
    )
    session.run()


@main.command("timeline")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--full", is_flag=True, default=False,
              help="Show all timeline events (no truncation).")
def timeline_cmd(pcap_file: str, full: bool):
    """
    Run full analysis and display the attack timeline.

    \b
    Example:
        packetiq timeline capture.pcap
    """
    from packetiq.timeline import TimelineBuilder, TimelineRenderer

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("ATTACK TIMELINE", "chronological event reconstruction")
    tl = TimelineBuilder().build(result, events, chains)
    TimelineRenderer(ui).render(tl, max_events=9999 if full else 80)

    ui.print_divider()
    ui.print_status(
        f"Timeline: {len(tl.events)} events | {len(tl.phases_seen)} kill chain phase(s) | "
        f"{len(tl.pivot_points)} pivot(s)",
        status="ok",
    )
    ui.print_divider()


@main.command("sigma")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None,
              help="Directory to write .yml rule files (default: print to stdout).")
@click.option("--min-level", default="medium",
              type=click.Choice(["low","medium","high","critical"], case_sensitive=False),
              show_default=True, help="Minimum severity level to generate rules for.")
def sigma_cmd(pcap_file: str, out: str, min_level: str):
    """
    Generate SIGMA detection rules from PCAP analysis.

    \b
    Example:
        packetiq sigma capture.pcap
        packetiq sigma capture.pcap --out ./sigma_rules/
        packetiq sigma capture.pcap --min-level high
    """
    from packetiq.sigma import SigmaGenerator

    level_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_ord     = level_order[min_level.lower()]

    pcap_path = Path(pcap_file).resolve()
    _, _, events, _, chains, _ = _run_pipeline(pcap_path, ui)

    ui.print_section("SIGMA RULE GENERATOR")
    gen   = SigmaGenerator()
    rules = [r for r in gen.generate(events, chains) if level_order.get(r.level, 0) >= min_ord]
    ui.print_status(f"Generated {len(rules)} SIGMA rule(s) (min level: {min_level.upper()})", status="ok")

    if not out:
        for r in rules:
            ui.print_raw(f"\n[bold cyan]─── {r.title} [{r.level.upper()}] ───[/bold cyan]")
            ui.print_raw(f"[dim white]{r.raw_yaml}[/dim white]")
    else:
        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        for i, r in enumerate(rules):
            filename = out_dir / f"packetiq_{i:03d}_{r.level}.yml"
            filename.write_text(r.raw_yaml, encoding="utf-8")
        ui.print_status(f"Wrote {len(rules)} rule files → {out_dir.resolve()}", status="ok")

    ui.print_divider()


@main.command("dashboard")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--port", "-p", default=8080, show_default=True,
              help="Port to serve the dashboard on.")
@click.option("--no-browser", is_flag=True, default=False,
              help="Don't open the browser automatically.")
def dashboard(pcap_file: str, port: int, no_browser: bool):
    """
    Launch the interactive 3D web dashboard for a PCAP file.

    \b
    Runs the full analysis pipeline and serves a real-time hacker-themed
    web dashboard at http://localhost:<port>/

    Example:
        packetiq dashboard capture.pcap
        packetiq dashboard capture.pcap --port 9090
    """
    from packetiq.dashboard.server import launch_dashboard

    pcap_path = Path(pcap_file).resolve()
    ui.print_status(
        f"Launching dashboard for {pcap_path.name} → http://127.0.0.1:{port}/",
        status="info",
    )
    launch_dashboard(str(pcap_path), port=port, open_browser=not no_browser)


@main.command("fuse")
@click.argument("pcap_files", nargs=-1, required=True,
                type=click.Path(exists=True, readable=True))
@click.option("--top", "-t", default=10, show_default=True)
@click.option("--full", is_flag=True, default=False)
def fuse(pcap_files, top: int, full: bool):
    """
    Fuse multiple PCAP files into a unified campaign timeline.

    Deduplicates events by attacker IP + event type across captures,
    merges attack chains, and produces a single consolidated analysis.

    \b
    Example:
        packetiq fuse day1.pcap day2.pcap day3.pcap
        packetiq fuse *.pcap --full
    """
    from packetiq.correlation.engine import CorrelationEngine
    from packetiq.timeline import TimelineBuilder, TimelineRenderer

    if len(pcap_files) < 2:
        ui.print_status("Provide at least 2 PCAP files to fuse.", status="error")
        return

    ui.print_section("MULTI-PCAP CAMPAIGN FUSION", f"{len(pcap_files)} capture(s)")

    all_events: list = []
    all_chains: list = []
    all_results: list = []
    earliest_ts = float("inf")
    latest_ts   = 0.0

    for pcap_file in pcap_files:
        pcap_path = Path(pcap_file).resolve()
        ui.print_status(f"Processing: {pcap_path.name}", status="loading")
        try:
            _, result, events, risk, chains, fps = _run_pipeline(pcap_path, ui, quiet=True)
            all_events.extend(events)
            all_chains.extend(chains)
            all_results.append(result)
            if result.capture_start: earliest_ts = min(earliest_ts, result.capture_start)
            if result.capture_end:   latest_ts   = max(latest_ts, result.capture_end)
            ui.print_status(
                f"  {pcap_path.name}: {len(events)} events, {len(chains)} chains, Risk {risk.score}/100",
                status="ok",
            )
        except Exception as e:
            ui.print_status(f"  Failed: {pcap_path.name} — {e}", status="error")

    # ── Deduplicate events ────────────────────────────────────────────────────
    ui.print_section("CAMPAIGN FUSION", "deduplicating across captures")
    seen_keys: set = set()
    deduped: list  = []
    for ev in sorted(all_events, key=lambda e: e.timestamp):
        key = (ev.event_type, ev.src_ip, ev.dst_ip, ev.dst_port)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(ev)

    # ── Re-correlate merged events ────────────────────────────────────────────
    merged_chains = CorrelationEngine().correlate(deduped)

    from packetiq.detection.risk_scorer import score as risk_score
    campaign_risk = risk_score(deduped)

    duration = max(0.0, latest_ts - earliest_ts)
    ui.print_summary_panel("CAMPAIGN SUMMARY", {
        "PCAP Files Fused":   str(len(pcap_files)),
        "Total Events":       str(len(all_events)),
        "Deduplicated Events":str(len(deduped)),
        "Attack Chains":      str(len(merged_chains)),
        "Campaign Risk":      f"{campaign_risk.score}/100 [{campaign_risk.tier}]",
        "Campaign Duration":  format_duration(duration),
        "Unique Attackers":   str(len({e.src_ip for e in deduped if e.src_ip})),
    })

    # ── Build merged extraction result for timeline ───────────────────────────
    if all_results:
        merged_result = all_results[0]
        merged_result.capture_start = earliest_ts
        merged_result.capture_end   = latest_ts
        for r in all_results[1:]:
            merged_result.dns_queries.extend(r.dns_queries)
            merged_result.http_requests.extend(r.http_requests)

        ui.print_section("CAMPAIGN TIMELINE", "unified event reconstruction")
        tl = TimelineBuilder().build(merged_result, deduped, merged_chains)
        TimelineRenderer(ui).render(tl, max_events=9999 if full else 80)

    # ── Attribution across campaign ───────────────────────────────────────────
    from packetiq.attribution.engine import AttributionEngine
    attrs = AttributionEngine().attribute(deduped, merged_chains)
    if attrs:
        ui.print_section("THREAT-ACTOR TTP OVERLAP", "behavioural similarity — NOT confirmed attribution")
        for a in attrs[:3]:
            bar = "█" * int(a.confidence * 20) + "░" * (20 - int(a.confidence * 20))
            ui.print_raw(
                f"  {a.icon} [{a.color}]{a.actor_name:<22}[/{a.color}]  "
                f"[green]{bar}[/green]  "
                f"[bold white]{int(a.confidence*100):3d}%[/bold white] overlap  "
                f"[dim]{a.origin}[/dim]"
            )
        ui.print_status(
            "TTP overlap is an investigative lead only — confirm with infrastructure/IOC correlation.",
            status="warn",
        )

    ui.print_divider()
    ui.print_status(
        f"Campaign fusion complete — {len(pcap_files)} PCAP(s) | "
        f"{len(deduped)} events | {len(merged_chains)} chain(s) | "
        f"Risk {campaign_risk.score}/100",
        status="ok",
    )
    ui.print_divider()


@main.command("slice")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--ip", "ips", multiple=True, help="Match packets with this src/dst IP (repeatable).")
@click.option("--port", "ports", multiple=True, type=int, help="Match packets with this src/dst port (repeatable).")
@click.option("--out", "-o", required=True, help="Output evidence .pcap path.")
@click.option("--max", "max_packets", default=0, type=int, help="Max packets to write (0 = no limit).")
def slice_cmd(pcap_file: str, ips, ports, out: str, max_packets: int):
    """
    Extract the packets relevant to a finding into a smaller evidence PCAP.

    \b
    Example:
        packetiq slice capture.pcap --ip 45.33.32.156 --port 443 -o evidence.pcap
    """
    from packetiq.export.pcap_slicer import PcapFilter, slice_pcap

    pf = PcapFilter(ips=set(ips), ports=set(ports))
    if pf.is_empty:
        ui.print_status("Provide at least one --ip or --port to filter on.", status="error")
        sys.exit(1)

    ui.print_section("EVIDENCE PCAP SLICE")
    ui.print_status(f"Filtering {pcap_file} → {out}", status="loading")
    n = slice_pcap(pcap_file, out, pf, max_packets=max_packets)
    if n:
        ui.print_status(f"Wrote {n:,} matching packet(s) → {Path(out).resolve()}", status="ok")
    else:
        ui.print_status("No packets matched the filter.", status="warn")


@main.command("stix")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None, help="Output .json path (default: stdout).")
def stix_cmd(pcap_file: str, out: str):
    """
    Export detected indicators as a STIX 2.1 bundle (for MISP / OpenCTI / TAXII).

    \b
    Example:
        packetiq stix capture.pcap -o iocs.stix.json
    """
    import json

    from packetiq.export import to_stix_bundle

    pcap_path = Path(pcap_file).resolve()
    _, _, events, _, chains, _ = _run_pipeline(pcap_path, ui)

    bundle = to_stix_bundle(events, chains)
    payload = json.dumps(bundle, indent=2)

    ui.print_section("STIX 2.1 EXPORT")
    n = len(bundle["objects"])
    if out:
        Path(out).write_text(payload, encoding="utf-8")
        ui.print_status(f"Wrote {n} indicator(s) → {Path(out).resolve()}", status="ok")
    else:
        ui.print_status(f"{n} indicator(s):", status="ok")
        ui.print_raw(payload)


@main.command("navigator")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None, help="Output layer .json path (default: stdout).")
def navigator_cmd(pcap_file: str, out: str):
    """
    Export a MITRE ATT&CK Navigator layer of the detected techniques.

    \b
    Open the result at https://mitre-attack.github.io/attack-navigator/
    Example:
        packetiq navigator capture.pcap -o layer.json
    """
    import json

    from packetiq.export import build_navigator_layer

    pcap_path = Path(pcap_file).resolve()
    _, _, events, _, _, _ = _run_pipeline(pcap_path, ui)
    layer = build_navigator_layer(events, name=f"PacketIQ — {pcap_path.name}")
    payload = json.dumps(layer, indent=2)

    ui.print_section("ATT&CK NAVIGATOR LAYER")
    n = len(layer["techniques"])
    if out:
        Path(out).write_text(payload, encoding="utf-8")
        ui.print_status(f"Wrote {n} technique(s) → {Path(out).resolve()}", status="ok")
        ui.print_status("Open it at https://mitre-attack.github.io/attack-navigator/", status="info")
    else:
        ui.print_status(f"{n} technique(s):", status="ok")
        ui.print_raw(payload)


@main.command("cve")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--json", "as_json", is_flag=True, help="Print the raw JSON result.")
def cve_cmd(pcap_file: str, as_json: bool):
    """
    Look up real CVEs (NIST NVD) for software observed in a capture.

    \b
    Reads HTTP Server / User-Agent banners from the PCAP and queries the
    official NVD API. Set NVD_API_KEY in your .env for a higher rate limit.
    Nothing is invented — if no versioned banners are seen, nothing is reported.

    \b
    Example:
        packetiq cve capture.pcap
    """
    from packetiq.enrichment import nvd

    pcap_path = Path(pcap_file).resolve()
    ui.print_section("CVE LOOKUP", "NIST National Vulnerability Database")

    parser = PCAPParser(str(pcap_path))
    extractor = DataExtractor()
    with ui.make_progress("Reading banners...") as progress:
        progress.add_task("Reading banners...", total=None)
        for record in parser.stream():
            extractor.feed(record)
    banners = extractor.finalize().software_banners

    if not banners:
        ui.print_status("No HTTP Server / User-Agent banners observed. Encrypted (HTTPS) "
                        "traffic exposes none, so there is nothing to look up.", status="warn")
        return

    ui.print_status(f"Observed {len(banners)} software banner(s):", status="ok")
    for b in banners[:20]:
        ui.print_key_value(b["source"], b["value"])
    if not nvd.get_api_key():
        ui.print_status("No NVD_API_KEY set — using the slower anonymous rate limit "
                        "(add one to .env to speed this up).", status="warn")
    ui.print_status("Querying NVD for matching CVEs...", status="loading")

    data = nvd.lookup_banners(banners)

    if as_json:
        import json
        ui.print_raw(json.dumps(data, indent=2))
        return

    if data.get("error"):
        ui.print_status(f"NVD error: {data['error']}", status="error")
    if not data["results"]:
        ui.print_status(data.get("note", "No CVEs matched."), status="warn")
        return

    for r in data["results"]:
        ui.print_section(f"{r['product']} {r['version']}",
                         f"{r['source']} · {len(r['cves'])} CVE(s)")
        if not r["cves"]:
            ui.print_status("No CVEs matched this version in NVD.", status="info")
            continue
        for c in r["cves"]:
            sev = c["severity"] or "—"
            score = c["cvss"] if c["cvss"] is not None else "—"
            ui.print_status(f"{c['id']}  [CVSS {score} {sev}]  {c['published']}", status="warn")
            ui.print_key_value("", c["description"][:160])
            ui.print_key_value("link", c["url"])
    ui.print_status(data["note"], status="ok")


@main.command("vulns")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--json", "as_json", is_flag=True, help="Print the raw JSON result.")
def vulns_cmd(pcap_file: str, as_json: bool):
    """
    Version-aware vulnerability assessment (NVD CPE + CVSS + CISA KEV).

    \b
    Maps each host's observed software (HTTP Server / User-Agent banners) to a
    CPE, queries NVD for the CVEs affecting that exact version, flags those on
    CISA's actively-exploited (KEV) list, and correlates any observed exploit
    attempts against the target's real software. NVD_API_KEY in .env speeds it up.
    """
    from packetiq.detection.models import EventType
    from packetiq.enrichment import nvd

    pcap_path = Path(pcap_file).resolve()
    ui.print_section("VULNERABILITY ASSESSMENT", "NVD CPE · CVSS · CISA KEV")

    parser = PCAPParser(str(pcap_path))
    extractor = DataExtractor()
    with ui.make_progress("Reading software banners...") as progress:
        progress.add_task("Reading software banners...", total=None)
        for record in parser.stream():
            extractor.feed(record)
    result = extractor.finalize()
    banners = result.software_banners
    _, _, events, _, _, _ = _run_pipeline(pcap_path, ui, quiet=True)
    attacks = [{"attack_type": e.evidence.get("attack_type", ""), "dst_ip": e.dst_ip or ""}
               for e in events if e.event_type == EventType.HTTP_ATTACK]

    if not banners:
        ui.print_status("No software banners observed (encrypted traffic exposes none). Nothing to assess.", status="warn")
        return
    if not nvd.get_api_key():
        ui.print_status("No NVD_API_KEY set — using the slower anonymous rate limit.", status="warn")
    ui.print_status("Resolving CPEs and querying NVD + CISA KEV...", status="loading")

    data = nvd.assess_vulnerabilities(banners, attacks)
    if as_json:
        import json
        ui.print_raw(json.dumps(data, indent=2))
        return
    if data.get("error"):
        ui.print_status(f"NVD error: {data['error']}", status="error")

    rk = data["risk"]
    ui.print_status(f"Vulnerability risk: {rk['score']}/100 [{rk['tier']}] · {data['note']}",
                    status="error" if rk["tier"] in ("CRITICAL", "HIGH") else "ok")
    for p in data["products"]:
        ui.print_section(f"{p['product']} {p['version']}", f"{p['source']} · CPE {p['cpe'] or 'n/a'}")
        if not p["cves"]:
            ui.print_status("No current CVEs matched this version.", status="info")
            continue
        for c in p["cves"]:
            tag = " ⚠KEV" if c["kev"] else ""
            tag += " ☣RANSOMWARE" if c.get("ransomware") else ""
            ui.print_status(f"{c['id']}  [CVSS {c['cvss']} {c['severity']}]{tag}", status="error" if c["kev"] else "warn")
            ui.print_key_value("link", c["url"])
    for cor in data["correlations"]:
        ui.print_status(f"⚡ Exploit attempt for {cor['name']} ({', '.join(cor['cves'])}) → {cor['target']}"
                        + (f"  [target runs {', '.join(cor['target_software'])}]" if cor["target_software"] else ""),
                        status="error")
    ui.print_status(f"{data['totals']['cves']} CVE(s), {data['totals']['kev']} actively exploited "
                    f"(of {data['totals']['kev_catalog']} in CISA KEV).", status="ok")


@main.command("live")
@click.option("--interface", "-i", default=None, help="Network interface to sniff (e.g. en0, eth0).")
@click.option("--read", "read_pcap", default=None, type=click.Path(exists=True),
              help="Replay a PCAP through the live engine instead of sniffing (no root needed).")
@click.option("--window", default=300.0, show_default=True, help="Rolling detection window (seconds).")
@click.option("--interval", default=10.0, show_default=True, help="Seconds between detection scans (live mode).")
@click.option("--threshold", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
              default="HIGH", show_default=True, help="Minimum severity to alert on.")
@click.option("--alert/--no-alert", default=False, help="Also send Telegram/other-channel alerts for findings.")
def live_cmd(interface, read_pcap, window, interval, threshold, alert):
    """
    Real-time monitoring: sniff an interface (or replay a PCAP) and alert on
    findings as they appear — a lightweight IDS built on the same detectors.

    \b
    Example:
        sudo packetiq live -i en0
        packetiq live --read capture.pcap        # offline replay, no root
    """
    from packetiq import live as live_mod

    ui.print_section("LIVE MONITOR", f"threshold: {threshold.upper()}")

    def _on_alert(e):
        sev = e.severity.value
        color = {"CRITICAL": "bold red", "HIGH": "bold yellow",
                 "MEDIUM": "bold cyan", "LOW": "bold green"}.get(sev, "white")
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        ui.print_raw(f"  [dim green]{ts}[/dim green] [{color}]{sev:<8}[/{color}] "
                     f"[yellow]{e.event_type.value}[/yellow] [red]{e.src_ip or '—'}[/red] "
                     f"→ [cyan]{dst}[/cyan]  [dim]{e.description[:70]}[/dim]")
        if alert:
            try:
                from packetiq.alerts import channels
                channels.broadcast("PacketIQ live alert", f"[{sev}] {e.description}")
            except Exception:
                pass

    if read_pcap:
        ui.print_status(f"Replaying {read_pcap} through the live engine...", status="loading")
        mon = live_mod.replay(read_pcap, _on_alert, window_secs=window, threshold=threshold)
        ui.print_divider()
        ui.print_status(f"Replay complete — {mon.alert_count} alert(s) raised.", status="ok")
        return

    if not interface:
        ui.print_status("Provide -i/--interface to sniff, or --read PCAP to replay.", status="error")
        sys.exit(1)

    ui.print_status(f"Sniffing {interface} (Ctrl+C to stop)...", status="loading")
    try:
        live_mod.sniff_live(interface, _on_alert, window_secs=window,
                            interval_secs=interval, threshold=threshold)
    except RuntimeError as e:
        ui.print_status(str(e), status="error")
        sys.exit(1)
    ui.print_divider()


@main.command("zeek")
@click.argument("conn_log", type=click.Path(exists=True, readable=True))
@click.option("--top", "-t", default=15, show_default=True)
def zeek_cmd(conn_log: str, top: int):
    """
    Analyze a Zeek conn.log (TSV or JSON) — flow-based detection without a PCAP.

    \b
    Example:
        packetiq zeek /opt/zeek/logs/current/conn.log
    """
    from packetiq.inputs import load_conn_log

    ui.print_section("ZEEK conn.log ANALYSIS", "flow-log ingestion")
    ui.print_status(f"Loading {conn_log}...", status="loading")
    try:
        result = load_conn_log(conn_log)
    except Exception as e:
        ui.print_status(f"Failed to parse conn.log: {e}", status="error")
        sys.exit(1)

    ui.print_status(
        f"Loaded {len(result.flows):,} flow(s), {len(result.unique_src_ips)} source(s), "
        f"{len(result.external_ips)} external IP(s).",
        status="ok",
    )

    engine = DetectionEngine()
    events, risk, _fps = engine.run(result, conn_log)   # payload passes no-op gracefully
    chains = CorrelationEngine().correlate(events)

    ui.print_summary_panel(f"RISK SCORE: {risk.score}/100 [{risk.tier}]", {
        "Total Events":  str(len(events)),
        "Attack Chains": str(len(chains)),
        "Critical":      str(risk.by_severity.get("CRITICAL", 0)),
        "High":          str(risk.by_severity.get("HIGH", 0)),
        "Medium":        str(risk.by_severity.get("MEDIUM", 0)),
        "Low":           str(risk.by_severity.get("LOW", 0)),
    })

    if events:
        rows = []
        for e in events:
            dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
            rows.append([e.severity.value, e.event_type.value.replace("_", " "),
                         e.src_ip or "—", dst, e.description[:70]])
        ui.print_table(
            "Detection Events",
            columns=[("Severity", "bold white", "center"), ("Type", "yellow", "left"),
                     ("Source", "red", "left"), ("Destination", "cyan", "left"),
                     ("Description", "dim white", "left")],
            rows=rows, max_rows=top,
        )
    else:
        ui.print_status("No threats detected in this conn.log.", status="ok")
    ui.print_divider()


@main.command("notify")
@click.argument("message", default="PacketIQ test notification.")
@click.option("--status", "show_status", is_flag=True, help="Show which channels are configured.")
def notify_cmd(message: str, show_status: bool):
    """
    Send a test message to all configured alert channels
    (Slack / email / generic webhook — configure via .env).

    \b
    Example:
        packetiq notify "Critical findings in capture.pcap"
        packetiq notify --status
    """
    from packetiq.alerts import channels

    ui.print_section("ALERT CHANNELS")
    configured = channels.configured_channels()
    if not configured:
        ui.print_status(
            "No channels configured. Add SLACK_WEBHOOK_URL, ALERT_WEBHOOK_URL, "
            "or SMTP_* + ALERT_EMAIL_TO to your .env.",
            status="warn",
        )
        return

    ui.print_status(f"Configured: {', '.join(configured)}", status="info")
    if show_status:
        return

    results = channels.broadcast("PacketIQ", message)
    for chan, (ok, err) in results.items():
        ui.print_status(f"{chan}: {'sent' if ok else 'FAILED — ' + err}", status="ok" if ok else "error")


@main.command("misp")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--url", default=None, help="MISP base URL (or set MISP_URL).")
@click.option("--key", default=None, help="MISP API key (or set MISP_KEY).")
@click.option("--dry-run", is_flag=True, default=False, help="Build the event and print it, don't push.")
def misp_cmd(pcap_file: str, url: str, key: str, dry_run: bool):
    """
    Push detected indicators to a MISP instance as a new Event.

    \b
    Example:
        export MISP_URL=https://misp.local MISP_KEY=...
        packetiq misp capture.pcap
        packetiq misp capture.pcap --dry-run
    """
    import json

    from packetiq.export import push_to_misp, to_misp_event

    pcap_path = Path(pcap_file).resolve()
    _, _, events, _, chains, _ = _run_pipeline(pcap_path, ui)
    event = to_misp_event(events, info=f"PacketIQ — {pcap_path.name}")

    ui.print_section("MISP EXPORT")
    n = len(event["Event"]["Attribute"])
    if dry_run:
        ui.print_status(f"{n} attribute(s) (dry run, not pushed):", status="ok")
        ui.print_raw(json.dumps(event, indent=2))
        return
    if n == 0:
        ui.print_status("No indicators to push.", status="warn")
        return
    ui.print_status(f"Pushing {n} indicator(s) to MISP...", status="loading")
    ok, msg = push_to_misp(event, url=url, key=key)
    ui.print_status(msg, status="ok" if ok else "error")
    if not ok:
        sys.exit(1)


@main.command("html")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None, help="Output .html path (default: report_<name>.html).")
@click.option("--vulns", is_flag=True, default=False,
              help="Include a live NVD/CISA-KEV vulnerability assessment (needs network).")
def html_cmd(pcap_file: str, out: str, vulns: bool):
    """
    Generate a self-contained HTML report (offline, no AI) with a network graph.

    \b
    Example:
        packetiq html capture.pcap -o report.html
        packetiq html capture.pcap --vulns        # add NVD + CISA KEV section
    """
    import hashlib

    from packetiq.attribution.engine import AttributionEngine
    from packetiq.detection.models import EventType
    from packetiq.export import build_html

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, _fps = _run_pipeline(pcap_path, ui)
    attrs = AttributionEngine().attribute(events, chains)

    try:
        sha = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    except Exception:
        sha = None

    vuln_data = None
    if vulns:
        from packetiq.enrichment import nvd
        ui.print_status("Assessing vulnerabilities (NVD CPE + CVSS + CISA KEV)…", status="loading")
        attacks = [{"attack_type": e.evidence.get("attack_type", ""), "dst_ip": e.dst_ip or ""}
                   for e in events if e.event_type == EventType.HTTP_ATTACK]
        vuln_data = nvd.assess_vulnerabilities(result.software_banners, attacks)

    out_path = Path(out) if out else pcap_path.parent / f"report_{pcap_path.stem}.html"
    out_path.write_text(build_html(file_meta, result, events, chains, risk, attrs,
                                   pcap_sha256=sha, vulns=vuln_data), encoding="utf-8")

    ui.print_section("HTML REPORT")
    ui.print_status(f"Report written → {out_path.resolve()}", status="ok")


@main.command("history")
@click.option("--limit", default=20, show_default=True, help="Number of recent analyses to show.")
def history_cmd(limit: int):
    """Show recent analyses recorded in the local history database."""
    from packetiq.storage import recent

    ui.print_section("ANALYSIS HISTORY")
    rows = recent(limit)
    if not rows:
        ui.print_status("No analyses recorded yet.", status="info")
        return
    table = [[r["analyzed_at"][:19], r["filename"][:30], f"{r['risk_score']}/100",
              r["risk_tier"], str(r["event_count"]), str(r["chain_count"])] for r in rows]
    ui.print_table(
        "Recent Analyses",
        columns=[("When", "dim white", "left"), ("Capture", "bold green", "left"),
                 ("Risk", "cyan", "right"), ("Tier", "yellow", "center"),
                 ("Events", "dim white", "right"), ("Chains", "dim white", "right")],
        rows=table, max_rows=limit,
    )


@main.command("setup-capture")
def setup_capture_cmd():
    """
    One-time setup so live packet capture works without per-run sudo.

    \b
    macOS  : installs ChmodBPF (grants the access_bpf group capture access).
    Linux  : grants CAP_NET_RAW to the Python interpreter (setcap).
    Windows: checks Npcap and explains how to enable non-admin capture.
    You'll be asked for your password once.
    """
    from packetiq import capture_setup

    ui.print_section("LIVE CAPTURE SETUP")
    ok, plat, detail = capture_setup.status()
    ui.print_status(f"Platform: {plat} — {detail}", status="info")
    if ok:
        ui.print_status("Live capture is already enabled. Nothing to do.", status="ok")
        return
    ui.print_status("Applying one-time capture-privilege setup...", status="loading")
    done, msg = capture_setup.setup()
    ui.print_status(msg, status="ok" if done else "error")
    if not done:
        sys.exit(1)


@main.command("version")
def version():
    """Show PacketIQ version."""
    from packetiq import __version__
    ui.print_status(f"PacketIQ v{__version__}", status="ok")


# ──────────────────────────────────────────────────────────────────────────────
# feeds group  (packetiq feeds status | packetiq feeds update)
# ──────────────────────────────────────────────────────────────────────────────

@main.group("feeds")
def feeds_group():
    """Manage threat-intel feeds (IOC enrichment + JA3)."""


@feeds_group.command("status")
def feeds_status():
    """Show which threat-intel feeds are loaded and how many entries each has."""
    from packetiq.detection.ja3 import load_blocklist
    from packetiq.enrichment import feed_summary
    from packetiq.enrichment.feeds import cache_dir

    ui.print_section("THREAT-INTEL FEEDS")
    summary = feed_summary()
    ja3 = load_blocklist()
    if ja3:
        summary = {**summary, "JA3 blocklist (TLS)": len(ja3)}

    if not summary:
        ui.print_status("No feeds loaded. Run 'packetiq feeds update' to fetch them.", status="warn")
        return

    rows = [[name, f"{count:,}"] for name, count in summary.items()]
    ui.print_table(
        "Loaded Indicators",
        columns=[("Feed", "bold green", "left"), ("Entries", "cyan", "right")],
        rows=rows, max_rows=50,
    )
    ui.print_status(f"Cache dir: {cache_dir()}", status="info")
    ui.print_status("Run 'packetiq feeds update' to refresh from source.", status="info")


@feeds_group.command("update")
def feeds_update():
    """
    Download fresh threat-intel feeds (Feodo, ThreatFox, Tor, Spamhaus DROP,
    MalwareBazaar) into your local cache, overriding the bundled snapshots.
    """
    from packetiq.enrichment.feeds import cache_dir, load_store
    from packetiq.enrichment.update import update_feeds

    ui.print_section("REFRESH THREAT-INTEL FEEDS", "downloading from source")
    ui.print_status("This requires internet access. Fetching feeds...", status="loading")

    results = update_feeds(progress=lambda name: ui.print_status(f"Fetching {name}...", status="loading"))

    ok = 0
    for filename, outcome in results.items():
        if isinstance(outcome, int):
            ui.print_status(f"{filename}: {outcome:,} entries", status="ok")
            ok += 1
        else:
            ui.print_status(f"{filename}: {outcome}", status="error")

    load_store.cache_clear()   # force reload on next analysis
    ui.print_status(f"Updated {ok}/{len(results)} feeds → {cache_dir()}", status="ok" if ok else "warn")


# ──────────────────────────────────────────────────────────────────────────────
# alert group  (packetiq alert setup | packetiq alert test)
# ──────────────────────────────────────────────────────────────────────────────

@main.group("alert")
def alert_group():
    """Manage Telegram alert configuration."""


@alert_group.command("setup")
def alert_setup():
    """
    Test Telegram credentials and send a verification message.

    \b
    Reads TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID from .env or shell env.
    Example:
        packetiq alert setup
    """
    from packetiq.alerts import TelegramSender, load_credentials

    ui.print_section("TELEGRAM ALERT SETUP")

    token, chat_id = load_credentials()

    if not token:
        ui.print_status("TELEGRAM_BOT_TOKEN not found in .env or environment.", status="error")
        ui.print_status("Get one from @BotFather on Telegram.", status="info")
        sys.exit(1)

    if not chat_id:
        ui.print_status("TELEGRAM_CHAT_ID not found in .env or environment.", status="error")
        ui.print_status(
            "To find your chat ID: send a message to your bot, then visit "
            "https://api.telegram.org/bot<TOKEN>/getUpdates",
            status="info",
        )
        sys.exit(1)

    ui.print_status(f"Token found: {token[:12]}{'*' * (len(token) - 12)}", status="info")
    ui.print_status(f"Chat ID: {chat_id}", status="info")
    ui.print_status("Testing connection...", status="loading")

    sender = TelegramSender(token, chat_id)
    ok, msg = sender.test_connection()

    if ok:
        ui.print_status(f"Connection OK — {msg}", status="ok")
        ui.print_status("A test message has been sent to your Telegram chat.", status="ok")
    else:
        ui.print_status(f"Connection FAILED — {msg}", status="error")
        sys.exit(1)


@alert_group.command("test")
@click.argument("message", default="PacketIQ test alert fired successfully.")
def alert_test(message: str):
    """Send a custom test message to your Telegram chat."""
    from packetiq.alerts import TelegramSender, load_credentials

    token, chat_id = load_credentials()
    if not token or not chat_id:
        ui.print_status("Telegram credentials not configured. Run 'packetiq alert setup'.", status="error")
        sys.exit(1)

    sender = TelegramSender(token, chat_id)
    ok, err = sender.send(f"🔔 <b>PacketIQ Test Alert</b>\n\n{message}")
    if ok:
        ui.print_status("Test message sent successfully.", status="ok")
    else:
        ui.print_status(f"Send failed: {err}", status="error")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    from packetiq.utils.helpers import is_private_ip
    return is_private_ip(ip)


def _send_telegram_alerts(
    pcap_path,
    result,
    events,
    chains,
    risk,
    threshold: str = "HIGH",
    report_path=None,
):
    """Dispatch Telegram alerts after analysis. Called by analyze and report commands."""
    from packetiq.alerts import AlertDispatcher, TelegramSender, load_credentials

    ui.print_section("TELEGRAM ALERTS", f"threshold: {threshold}")

    token, chat_id = load_credentials()
    if not token or not chat_id:
        ui.print_status(
            "Telegram credentials not configured. "
            "Add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to .env or run 'packetiq alert setup'.",
            status="warn",
        )
        return

    try:
        sev_threshold = Severity[threshold.upper()]
    except KeyError:
        sev_threshold = Severity.HIGH

    sender     = TelegramSender(token, chat_id)
    dispatcher = AlertDispatcher(sender, threshold=sev_threshold)

    ui.print_status(f"Sending alerts to Telegram (chat: {chat_id})...", status="loading")

    dr = dispatcher.dispatch(
        file_name   = pcap_path.name,
        risk        = risk,
        events      = events,
        chains      = chains,
        result      = result,
        report_path = report_path,
    )

    if dr.ok:
        ui.print_status(
            f"Alerts sent: {dr.sent} message(s) | {dr.skipped} skipped.",
            status="ok",
        )
    else:
        ui.print_status(
            f"Alert dispatch partial: {dr.sent} sent, {dr.failed} failed.",
            status="warn",
        )
        for err in dr.errors[:3]:
            ui.print_status(f"  Error: {err}", status="error")


@main.command("webapp")
@click.option("--port", "-p", default=8080, show_default=True,
              help="Port to serve the web application on.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Host to bind to. Use 0.0.0.0 to expose on all interfaces.")
@click.option("--no-browser", is_flag=True, default=False,
              help="Don't open the browser automatically.")
def webapp(port: int, host: str, no_browser: bool):
    """
    Launch the PacketIQ web application.

    \b
    Upload any PCAP file in your browser and get a full real-time analysis:
    threat detection, attack chains, SIGMA rules, attribution, and more.

    Example:
        packetiq webapp
        packetiq webapp --port 9090
        packetiq webapp --host 0.0.0.0 --port 8080
    """
    import threading
    import webbrowser

    import uvicorn

    from packetiq.webapp import create_app

    url = f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{port}/"  # nosec B104 - string compare, not a bind
    ui.print_status(f"PacketIQ Web App → {url}", status="info")
    ui.print_status("Upload a PCAP file in your browser to begin analysis.", status="info")
    ui.print_status("Press Ctrl+C to stop.", status="info")
    if host not in ("127.0.0.1", "localhost", "::1"):
        # Widen the DNS-rebinding/CSRF Host allow-list for the operator's chosen
        # bind address (or disable the Host check for a wildcard 0.0.0.0 bind).
        import os as _os
        _os.environ["PACKETIQ_ALLOWED_HOSTS"] = "*" if host == "0.0.0.0" else host  # nosec B104 - operator opt-in
        ui.print_status(
            "SECURITY: the web API has no authentication. Binding to "
            f"'{host}' exposes upload/analysis (and AI usage) to your network. "
            "Only do this on a trusted network or behind an authenticated reverse proxy.",
            status="warn")

    if not no_browser:
        import time

        def _open():
            time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()

    uvicorn.run(
        create_app(), host=host, port=port, log_level="warning",
        limit_max_requests=None,
        timeout_keep_alive=75,    # bounded keep-alive (was 600s — slowloris surface)
        h11_max_incomplete_event_size=16 * 1024 * 1024,  # 16 MB header buffer (was 10 GB → DoS)
    )


if __name__ == "__main__":
    main()
