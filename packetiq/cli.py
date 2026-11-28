"""
PacketIQ CLI — Entry point for all commands.

Usage:
    packetiq analyze <file.pcap>
    packetiq report  <file.pcap>
    packetiq chat    <file.pcap>
    packetiq version
"""

import contextlib
import sys
from pathlib import Path

import click

from packetiq import __version__, config
from packetiq.correlation.engine import CorrelationEngine
from packetiq.detection.engine import DetectionEngine
from packetiq.detection.models import Severity
from packetiq.display.terminal import TerminalUI
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.utils.helpers import UNSPECIFIED_IPV4, format_bytes, format_duration

# Choices for `--provider` on the AI commands. "auto" keeps the existing
# behaviour (first configured provider, switching away from a rate-limited one);
# naming one pins it, which is what you want when a specific model must answer.
_AI_PROVIDERS = ["auto", "gemini", "groq", "anthropic", "ollama"]


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


def _machine_output_requested(argv=None) -> bool:
    """True when this invocation writes a JSON/YAML document to stdout.

    The banner is printed by this group callback, before Click has parsed the
    subcommand, so the decision has to come from raw argv. Being wrong only moves
    decoration between stdout and stderr — the document itself is written
    verbatim either way — so a conservative match is fine.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--json" in argv:
        return True
    if argv[:1] == ["misp"] and "--dry-run" in argv:
        return True
    # These print their document to stdout unless an output file was named.
    if argv and argv[0] in ("stix", "navigator", "sigma"):
        return not any(a in ("-o", "--out") for a in argv)
    return False


def _force_utf8_output(streams=None) -> None:
    """Keep PacketIQ's output printable on a stream that is not UTF-8.

    The rules, arrows and box characters the tables are drawn with sit outside
    every legacy 8-bit code page, so a non-UTF-8 stdout does not print them oddly
    — it raises. `packetiq analyze capture.pcap > report.txt` on Windows redirects
    to the ANSI code page and died part-way through the first table with a
    UnicodeEncodeError; `LC_ALL=C packetiq analyze` fails identically on Linux and
    macOS, so this is not a Windows special case.

    Switching the stream to UTF-8 fixes the redirected case outright.
    `errors="replace"` covers what is left: a console that genuinely cannot
    render a character now shows a placeholder instead of aborting the analysis,
    which is the right trade when the alternative is losing the whole report.
    """
    targets: tuple = tuple(streams) if streams is not None else (sys.stdout, sys.stderr)
    for stream in targets:
        with contextlib.suppress(Exception):
            if (getattr(stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
                stream.reconfigure(encoding="utf-8", errors="replace")


# ──────────────────────────────────────────────────────────────────────────────
# Root group
# ──────────────────────────────────────────────────────────────────────────────

def _print_smb_section(ui, smb_data: dict, full: bool) -> None:
    """Render the SMB forensics section of an analyze run.

    Lifted out of the command body so it can be exercised with crafted data:
    an account authenticated over SMB, and an anonymous null session, both come
    from a session setup that scapy can read from a real capture but cannot
    rebuild into a pcap of its own, so a round-trip test cannot reach them.
    """
    if not smb_data:
        return
    ui.print_section(
        "FILE SHARING — SMB",
        f"{smb_data.get('operations', 0)} operation(s) across "
        f"{smb_data.get('sessions', 0)} session(s)")
    shares = smb_data.get("shares", {}) or {}
    files = smb_data.get("files", {}) or {}
    if shares or files:
        ui.print_table(
            "Shares reached and files opened",
            columns=[("Path", "bold green", "left"), ("Kind", "yellow", "left"),
                     ("Times", "cyan", "right")],
            rows=([[s, "share", f"{n:,}"] for s, n in shares.items()]
                  + [[f, "file", f"{n:,}"] for f, n in files.items()]),
            max_rows=9999 if full else 20,
        )
    accounts = smb_data.get("accounts", []) or []
    if accounts:
        ui.print_table(
            "Accounts authenticated over SMB",
            columns=[("Account", "bold red", "left"), ("Domain", "yellow", "left"),
                     ("Client called itself", "cyan", "left")],
            rows=[[a.get("user", "?"), a.get("domain", "—"),
                   a.get("workstation", "not sent")] for a in accounts],
            max_rows=9999,
        )
    pipes = smb_data.get("named_pipes", {}) or {}
    for pipe, meaning in pipes.items():
        ui.print_status(f"Named pipe {pipe} opened — {meaning}.", "warning")
    if smb_data.get("anonymous_sessions"):
        ui.print_status(
            f"{smb_data['anonymous_sessions']} anonymous (null) session setup(s): "
            "the NTLM message carried no username, domain or NT response at all, "
            "which is a deliberate unauthenticated bind rather than a failed logon.",
            "warning")
    if smb_data.get("smb1_seen"):
        ui.print_status(
            "SMB1 was negotiated. It has been deprecated since 2014 and is the "
            "dialect the EternalBlue family targets.", "warning")


def _print_cleartext_section(ui, ct: dict) -> None:
    """Render recovered cleartext sessions: credentials, uploads, shell transcripts."""
    if not ct:
        return
    ui.print_section(
        "RECOVERED CLEARTEXT SESSIONS",
        "credentials, file transfers and shell commands read off the wire")

    valid = ct.get("valid_credentials", []) or []
    if valid:
        ui.print_table(
            "Credentials recovered in cleartext (the login that worked)",
            columns=[("Protocol", "yellow", "left"), ("Username", "bold red", "left"),
                     ("Password", "bold red", "left"), ("Result", "cyan", "left")],
            rows=[[c.get("protocol", "?"), c.get("username", "?"),
                   c.get("password", "?"), c.get("result", "?")] for c in valid],
            max_rows=9999,
        )
    if ct.get("failed_password_attempts"):
        ui.print_status(
            f"{ct['failed_password_attempts']} failed password attempt(s) preceded the "
            "successful login: a brute-force run against this account.", "info")

    for ftp in ct.get("ftp_sessions", []) or []:
        if not (ftp.get("working_directory") or ftp.get("uploaded")):
            continue
        detail = []
        if ftp.get("working_directory"):
            detail.append(f"working directory {ftp['working_directory']}")
        if ftp.get("uploaded"):
            detail.append(f"uploaded {', '.join(ftp['uploaded'])}")
        ui.print_status(
            f"FTP session as {ftp.get('username') or '?'}: " + "; ".join(detail), "warning")

    for up in ct.get("uploaded_files", []) or []:
        for url in up.get("urls", []) or []:
            ui.print_status(f"Indicator inside uploaded {up.get('kind', 'file')}: {url}", "warning")
        for cb in up.get("callbacks", []) or []:
            ui.print_status(f"Call-back address inside uploaded {up.get('kind', 'file')}: {cb}",
                            "warning")

    for sh in ct.get("shell_sessions", []) or []:
        head = "Interactive shell recovered"
        if sh.get("hostname"):
            head += f" on host {sh['hostname']}"
        if sh.get("became_root"):
            head += " (escalated to root)"
        ui.print_section(head, f"{len(sh.get('commands', []))} command(s) the attacker typed")
        if sh.get("commands"):
            ui.print_table(
                "Commands issued (read from the cleartext shell stream)",
                columns=[("#", "dim white", "right"), ("Command", "bold green", "left")],
                rows=[[str(i), cmd] for i, cmd in enumerate(sh["commands"], 1)],
                max_rows=9999,
            )
        for proj in sh.get("github_projects", []) or []:
            ui.print_status(f"GitHub project fetched during the session: {proj}", "warning")

    for em in ct.get("email_sessions", []) or []:
        detail = []
        if em.get("mail_from"):
            detail.append(f"from {em['mail_from']}")
        if em.get("recipients"):
            detail.append(f"to {', '.join(em['recipients'])}")
        if em.get("subject"):
            detail.append(f"subject {em['subject']!r}")
        ui.print_status("Email (SMTP) recovered: " + "; ".join(detail), "warning")

    for irc in ct.get("irc_sessions", []) or []:
        head = f"IRC chat recovered as {irc.get('nick') or '?'}"
        if irc.get("channels"):
            head += f" in {', '.join(irc['channels'])}"
        ui.print_section(head, f"{len(irc.get('messages', []))} message(s)")
        if irc.get("messages"):
            ui.print_table(
                "IRC messages (read from the cleartext stream)",
                columns=[("#", "dim white", "right"), ("Message", "bold green", "left")],
                rows=[[str(i), m] for i, m in enumerate(irc["messages"], 1)],
                max_rows=9999,
            )

    for tel in ct.get("telnet_logins", []) or []:
        pw = f" / {tel['password']}" if tel.get("password") else ""
        ui.print_status(f"Telnet login recovered on {tel.get('server')}: "
                        f"{tel.get('username') or '?'}{pw}", "warning")


def _print_artifacts_section(ui, art: dict) -> None:
    """Render decoded artifacts: CTF flags, carved secrets, deobfuscated payloads."""
    if not art:
        return
    ui.print_section(
        "DECODED ARTIFACTS & SECRETS",
        "flags, keys and obfuscated payloads carved from the reassembled streams")

    flags = art.get("flags", []) or []
    if flags:
        ui.print_table(
            "CTF flags recovered (the literal flag on the wire)",
            columns=[("Flag", "bold green", "left"), ("Orientation", "cyan", "left")],
            rows=[[f.get("value", "?"), f.get("orientation", "forward")] for f in flags],
            max_rows=9999,
        )
    secrets = art.get("secrets", []) or []
    if secrets:
        ui.print_table(
            "Secrets carved from the streams (read off the wire, treat as compromised)",
            columns=[("Kind", "yellow", "left"), ("Value", "bold red", "left")],
            rows=[[s.get("detail", s.get("kind", "?")), s.get("value", "?")] for s in secrets],
            max_rows=9999,
        )
    payloads = art.get("decoded_payloads", []) or []
    if payloads:
        ui.print_table(
            "Obfuscated payloads decoded (transform chain and the content it held)",
            columns=[("Transform", "magenta", "left"), ("Decoded preview", "white", "left")],
            rows=[[d.get("chain", "?"), d.get("preview", "")] for d in payloads],
            max_rows=9999,
        )


def _print_http_forensics_section(ui, hf: dict) -> None:
    """Render HTTP deep inspection: credentials, cookies, headers, uploads, bodies."""
    if not hf:
        return
    ui.print_section(
        "HTTP DEEP INSPECTION",
        f"{hf.get('transactions', 0)} transaction(s) read in full")

    creds = hf.get("credentials", []) or []
    if creds:
        ui.print_table(
            "Credentials sent over cleartext HTTP",
            columns=[("Via", "yellow", "left"), ("Username", "bold red", "left"),
                     ("Password / token", "bold red", "left"), ("Host", "cyan", "left")],
            rows=[[c.get("via", "?"), c.get("username") or "(token)",
                   c.get("password", "?"), c.get("host", "?")] for c in creds],
            max_rows=9999,
        )
    cookies = hf.get("session_cookies", []) or []
    if cookies:
        ui.print_table(
            "Session cookies (replayable to hijack the session)",
            columns=[("Host", "cyan", "left"), ("Name", "bold red", "left"),
                     ("Value", "white", "left")],
            rows=[[c["host"], c["name"], c["value"]] for c in cookies],
            max_rows=9999,
        )
    for name, value in (hf.get("custom_headers") or {}).items():
        ui.print_status(f"Custom header {name}: {value}", "info")
    for up in hf.get("uploads", []) or []:
        ui.print_status(f"HTTP upload to {up['host']}: {up['filename']} "
                        f"(field {up.get('field') or '?'})", "warning")
    for d in hf.get("decompressed", []) or []:
        ui.print_status(f"Decompressed {d['encoding']} response body "
                        f"({d['bytes']} bytes) from {d['server']}", "info")
    for f in hf.get("flags", []) or []:
        ui.print_status(f"Flag recovered from an HTTP body: {f['value']}", "warning")
    for s in hf.get("secrets", []) or []:
        ui.print_status(f"Secret in an HTTP body: {s['detail']}: {s['value']}", "warning")


def _print_dcerpc_section(ui, rpc: dict) -> None:
    """Render the DCERPC section: which RPC interfaces were bound, and why it matters."""
    if not rpc:
        return
    ui.print_section(
        "RPC INTERFACES — DCERPC",
        f"{rpc.get('binds', 0)} bind(s) across {rpc.get('sessions', 0)} session(s)")
    interfaces = rpc.get("interfaces", {}) or {}
    if interfaces:
        ui.print_table(
            "Remote-procedure interfaces bound (the UUID says what was asked for)",
            columns=[("Interface", "bold red", "left"),
                     ("What it is used for", "yellow", "left")],
            rows=[[name, meaning] for name, meaning in interfaces.items()],
            max_rows=9999,
        )
    for op in (rpc.get("operations", []) or []):
        ui.print_status(f"RPC operation observed: {op}", "warning")
    if rpc.get("endpoint_mapper_requests") or rpc.get("rejected_binds"):
        ui.print_status(
            f"{rpc.get('endpoint_mapper_requests', 0)} endpoint-mapper bind(s) and "
            f"{rpc.get('rejected_binds', 0)} rejected bind(s): the RPC surface being "
            "mapped before a service is chosen. This is reconnaissance, not execution.",
            "info")


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
# `packetiq version` prints the banner and the full build/environment block; this
# is the conventional one-line form that scripts and packagers reach for first,
# and answering "No such option" to `--version` is a wrong answer, not a missing
# feature. Eager, so it prints and exits before the banner is drawn.
@click.version_option(__version__, "-V", "--version", prog_name="PacketIQ",
                      message="%(prog)s %(version)s")
# A whole sensitivity posture in one flag, applied before any subcommand runs, so
# `packetiq --profile ctf analyze|chat|html|webapp <pcap>` all see the lowered
# thresholds. Choices are the bundled profiles under packetiq/profiles/.
@click.option("--profile", type=click.Choice(config.available_profiles(), case_sensitive=False),
              default=None, metavar="NAME",
              help="Apply a bundled sensitivity profile before analysis. 'ctf' lowers "
                   "detector thresholds so small, targeted captures still trigger the "
                   "full correlation. Also settable via $PACKETIQ_PROFILE.")
@click.pass_context
def main(ctx, profile):
    """
    \b
    PacketIQ — AI PCAP Forensics & SOC Copilot
    Defensive network intelligence for SOC analysts.
    """
    _force_utf8_output()
    if _machine_output_requested():
        ui.route_chrome_to_stderr()
    ui.print_banner()
    if profile:
        config.set_active_profile(profile)
        ui.print_status(
            f"Sensitivity profile '{profile}' active: detector thresholds lowered so a "
            f"small or targeted capture still trips detection (trades precision for recall).",
            "info")
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
@click.option("--crack", "do_crack", is_flag=True, default=False,
              help="Also run the offline step (crack the AS-REP roast, decrypt WinRM) and "
                   "show the recovered password, commands and flag.")
@click.option("--wordlist", "-w", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Wordlist for --crack (default: the bundled common-password list).")
def analyze(pcap_file: str, top: int, full: bool, alert: bool, alert_threshold: str,
            timeline: bool, do_crack: bool, wordlist: str | None):
    """
    Parse and analyze a PCAP file.

    \b
    Example:
        packetiq analyze capture.pcap
        packetiq analyze capture.pcap --top 20
        packetiq analyze capture.pcap --alert
        packetiq analyze capture.pcap --crack        # also recover cracked creds/commands/flag
    """
    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)
    _rec = _apply_offline_recovery(result, str(pcap_path), do_crack, wordlist)
    if _rec:
        _print_offline_recovery(_rec)
    _print_credential_exposure(result)

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

    # ── Device inventory (real transmitting NICs) ──────────────────────
    devices = getattr(result, "devices", []) or []
    if devices:
        from packetiq.utils.helpers import oui_vendor
        _KIND = {"endpoint": "Host", "gateway": "Gateway", "infrastructure": "Switch/Infra",
                 "host": "Host (no IP)"}
        ui.print_section("DEVICE INVENTORY",
                         f"{len(devices)} physical device(s) that actually transmitted")
        dev_rows = [
            [", ".join(d.get("ips", [])) or "— (no IP)",
             d.get("mac", ""),
             oui_vendor(d.get("mac", "")) or "unknown",
             _KIND.get(d.get("kind", "endpoint"), "Host"),
             f"{d.get('packets', 0):,}"]
            for d in sorted(devices, key=lambda x: -x.get("packets", 0))
        ]
        ui.print_table(
            "Devices on the wire (by NIC/MAC — probed-but-silent IPs excluded)",
            columns=[
                ("IP address(es)", "bold green", "left"),
                ("MAC",            "dim white",  "left"),
                ("Vendor",         "cyan",       "left"),
                ("Role",           "yellow",     "left"),
                ("Packets",        "cyan",       "right"),
            ],
            rows=dev_rows,
            max_rows=9999 if full else 20,
        )
        # Same-chassis inference (e.g. a switch's STP MAC + its DHCP management
        # MAC on one OUI). Stated as an inference; the NICs are never merged.
        for g in (getattr(result, "chassis_groups", []) or []):
            macs = g.get("macs", [])
            vendor = ""
            for m in macs:
                vendor = oui_vendor(m) or vendor
            note = ((f"{vendor} " if vendor else "")
                    + "NICs " + " and ".join(macs) + " share OUI " + g.get("oui", "")
                    + " — likely the same physical switch (control-plane + management "
                    "interface), shown separately because the packets prove two "
                    "distinct MACs.")
            ui.print_status(note, "info")

    # ── Active Directory / Kerberos ────────────────────────────────────
    # The accounts a KDC confirmed are the answer to the first question asked
    # of a directory capture, and they used to be invisible: the findings table
    # truncates a description, so "six accounts were confirmed" appeared while
    # their names did not. This section exists to print the names.
    krb = getattr(result, "kerberos", {}) or {}
    if krb:
        realms = ", ".join(krb.get("realms", []) or []) or "unknown"
        ui.print_section(
            "DIRECTORY SERVICES — KERBEROS",
            f"{krb.get('messages', 0)} message(s), realm {realms}")

        types = krb.get("message_types", {}) or {}
        errors = krb.get("kdc_errors", {}) or {}
        if types or errors:
            ui.print_table(
                "Kerberos message flow",
                columns=[("Message / KDC reply", "bold green", "left"),
                         ("Count", "cyan", "right")],
                rows=([[k, f"{v:,}"] for k, v in sorted(types.items())]
                      + [[k, f"{v:,}"] for k, v in errors.items()]),
                max_rows=9999,
            )

        valid = krb.get("valid_accounts", {}) or {}
        if valid:
            ui.print_table(
                "Accounts the KDC confirmed exist",
                columns=[("Account", "bold red", "left"),
                         ("Proved by", "yellow", "left")],
                rows=[[name, proof] for name, proof in valid.items()],
                max_rows=9999,
            )
            ui.print_status(
                f"{len(valid)} account(s) confirmed by the domain controller itself. "
                "A KDC only answers KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_PREAUTH_FAILED "
                "or KDC_ERR_CLIENT_REVOKED for a principal it knows, so these are "
                "observations, not guesses.", "warning")

        hashes = krb.get("asrep_hashes", {}) or {}
        if hashes:
            ui.print_table(
                "AS-REP roastable credential material (hashcat -m 18200)",
                columns=[("Account", "bold red", "left"),
                         ("Crackable hash", "yellow", "left")],
                rows=[[name, digest] for name, digest in hashes.items()],
                max_rows=9999,
            )
            ui.print_status(
                "These accounts have pre-authentication disabled, so the KDC's reply "
                "carried the hash above. It is the credential material that left the "
                "network; the password is recovered by cracking it offline against a "
                "wordlist, which this tool does not do. Treat the account as "
                "compromised and rotate it.", "warning")

        tried = krb.get("usernames_seen", []) or []
        if tried:
            shown = tried if full else tried[:20]
            ui.print_status(
                f"Principals probed ({len(tried)} distinct): " + ", ".join(shown)
                + ("" if full or len(tried) <= 20 else f" … +{len(tried) - 20} more "
                   "(run with --full for the list)"), "info")

        spns = krb.get("service_principals", []) or []
        if spns:
            ui.print_status(
                f"Service principals requested ({len(spns)}): " + ", ".join(spns[:20]),
                "info")

        undecodable = krb.get("undecodable_messages", 0) or 0
        if undecodable:
            ui.print_status(
                f"{undecodable} Kerberos message(s) could not be decoded, typically "
                "because they were fragmented across TCP segments. They are counted "
                "rather than dropped silently.", "info")

    # ── Directory reads (LDAP) ─────────────────────────────────────────
    # Filters are printed as written, because that is how they are recognised.
    ldp = getattr(result, "ldap", {}) or {}
    if ldp:
        ui.print_section(
            "DIRECTORY READS — LDAP",
            f"{ldp.get('operations', 0)} operation(s), {ldp.get('searches', 0)} search(es)")
        filters = ldp.get("filters", {}) or {}
        if filters:
            ui.print_table(
                "Search filters sent to the directory",
                columns=[("Filter", "bold green", "left"), ("Times", "cyan", "right")],
                rows=[[f, f"{n:,}"] for f, n in filters.items()],
                max_rows=9999 if full else 12,
            )
        notable = ldp.get("notable_attributes", {}) or {}
        if notable:
            ui.print_table(
                "Attributes asked for that say what was being hunted",
                columns=[("Attribute", "bold red", "left"), ("What it finds", "yellow", "left")],
                rows=[[k, v] for k, v in notable.items()],
                max_rows=9999,
            )
        if ldp.get("rootdse_searches"):
            ui.print_status(
                f"{ldp['rootdse_searches']} RootDSE query/queries — the one search that "
                "works before you know anything about the domain, and the usual first "
                "step of directory enumeration.", "warning")
        if ldp.get("binds"):
            ui.print_status("LDAP binds: " + ", ".join(ldp["binds"]), "info")

    # ── File sharing (SMB) ─────────────────────────────────────────────
    _print_smb_section(ui, getattr(result, "smb", {}) or {}, full)

    # ── RPC interfaces (DCERPC) ────────────────────────────────────────
    _print_dcerpc_section(ui, getattr(result, "dcerpc", {}) or {})

    # ── Recovered cleartext sessions ───────────────────────────────────
    _print_cleartext_section(ui, getattr(result, "cleartext", {}) or {})

    # ── Decoded artifacts & secrets ────────────────────────────────────
    _print_artifacts_section(ui, getattr(result, "artifacts", {}) or {})

    # ── HTTP deep inspection ───────────────────────────────────────────
    _print_http_forensics_section(ui, getattr(result, "http_forensics", {}) or {})

    # ── Remote management (WinRM / WS-Management) ──────────────────────
    # 792 POSTs to one path is not web browsing, and reporting one of them as a
    # "suspicious User-Agent" was the old behaviour. The account and the client
    # software survive SPNEGO encryption; the commands do not, and this says so.
    wrm = getattr(result, "winrm", {}) or {}
    if wrm:
        ui.print_section(
            "REMOTE MANAGEMENT — WINRM",
            f"{wrm.get('requests', 0)} WS-Management request(s) across "
            f"{wrm.get('sessions', 0)} session(s)")

        accounts = wrm.get("accounts", []) or []
        if accounts:
            ui.print_table(
                "Accounts authenticated over WinRM (from the NTLM handshake)",
                columns=[("Account", "bold red", "left"),
                         ("Domain", "yellow", "left"),
                         ("Client called itself", "cyan", "left")],
                rows=[[a.get("user", "?"), a.get("domain", "—"),
                       a.get("workstation", "not sent")] for a in accounts],
                max_rows=9999,
            )

        agents = wrm.get("user_agents", {}) or {}
        if agents:
            ui.print_table(
                "Client software driving the session",
                columns=[("User-Agent", "bold green", "left"), ("Requests", "cyan", "right")],
                rows=[[name, f"{n:,}"] for name, n in agents.items()],
                max_rows=9999,
            )

        ui.print_status(
            f"{wrm.get('encrypted_requests', 0):,} request(s) carried SPNEGO "
            f"session-encrypted payloads totalling {wrm.get('payload_bytes', 0):,} bytes. "
            "The commands themselves are NOT recoverable from this capture — pull "
            "PowerShell operational and WinRM logs on the target for that window, "
            "which do hold the command text.", "info")

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

    # ── Threat Forecast (grounded prediction) ─────────────────────────
    try:
        from packetiq import prediction
        preds = prediction.predict(result, events)
    except Exception:
        preds = []
    if preds:
        ui.print_section("THREAT FORECAST", "possible attacks given the exposed services & behaviour")
        ui.print_status(
            "Prediction of attacks this capture is EXPOSED to — not confirmed events. "
            "Each rests on the evidence shown.", status="info")
        pred_rows = [[
            p.severity,
            p.likelihood,
            p.attack[:44] + ("…" if len(p.attack) > 44 else ""),
            (p.evidence[0][:60] + "…" if p.evidence and len(p.evidence[0]) > 60
             else (p.evidence[0] if p.evidence else "")),
        ] for p in preds]
        ui.print_table(
            "Predicted Attacks",
            columns=[
                ("Impact",     "bold white", "center"),
                ("Likelihood", "magenta",    "center"),
                ("Predicted Attack", "yellow", "left"),
                ("Key evidence", "dim white", "left"),
            ],
            rows=pred_rows,
            max_rows=9999 if full else 12,
        )

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
            [f.src_ip, f.os_guess, str(f.observed_ttl),
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
    with contextlib.suppress(Exception):
        from packetiq import storage
        storage.record(
            filename=pcap_path.name, packets=result.total_packets,
            risk_score=risk.score, risk_tier=risk.tier,
            event_count=len(events), chain_count=len(chains),
            top_attacker=(risk.top_sources[0] if risk.top_sources else ""),
        )

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
# crack command — offline AS-REP crack + WinRM decryption (opt-in)
# ──────────────────────────────────────────────────────────────────────────────

def _print_offline_recovery(rec) -> None:
    """Render the offline result: the cracked password(s), and the decrypted WinRM
    commands, exfiltrated files and flag. Shared by `crack`, `chat` and `analyze`."""
    for account, password in rec.credentials.items():
        ui.print_status(f"CRACKED {account}: {password}", "warning")
    uncracked = rec.roasts - len(rec.credentials)
    if uncracked:
        ui.print_status(f"{uncracked} AS-REP roast(s) not cracked with this wordlist "
                        "(try a larger one, e.g. rockyou.txt).", "info")
    if rec.commands or rec.flags:
        ui.print_section("WINRM SESSION DECRYPTED",
                         f"{rec.sessions} session(s) unsealed with the cracked password")
        if rec.commands:
            ui.print_table(
                "Commands run on the target (decrypted from the WinRM session)",
                columns=[("#", "dim white", "right"), ("Command", "bold green", "left")],
                rows=[[str(i), c] for i, c in enumerate(rec.commands, 1)],
                max_rows=9999,
            )
        for path in rec.exfiltrated_files:
            ui.print_status(f"File written/exfiltrated on the target: {path}", "warning")
        for flag in rec.flags:
            ui.print_status(f"Flag recovered from the decrypted session: {flag}", "warning")


def _print_credential_exposure(result) -> None:
    """Visible panel: every credential the capture leaks or the attacker steals,
    aligned to the account that owns it and shown as plaintext where PacketIQ cracked
    it. Reads the same synthesis the copilot does (`copilot.credentials`), so the
    terminal and the AI never disagree. Prints nothing when there is nothing to show."""
    from packetiq.copilot.credentials import build_credential_exposure

    records, techniques = build_credential_exposure(
        getattr(result, "cleartext", None),
        getattr(result, "http_forensics", None),
        getattr(result, "kerberos", None),
        getattr(result, "offline", None),
        getattr(result, "winrm", None),
    )
    if not records and not techniques:
        return

    ui.print_section("CREDENTIAL EXPOSURE",
                     "leaked & stolen credentials, aligned to Active Directory")

    if records:
        rows = []
        for rec in records:
            who = rec["principal"] + (f"@{rec['domain']}" if rec["domain"] else "")
            if rec["plaintext"]:
                secret = rec["plaintext"]
            else:
                secret = f"(hash only — not cracked, {rec['hash_mode'] or 'offline'})"
            source = rec["sources"][0] if rec["sources"] else "—"
            rows.append([who, secret, source])
        ui.print_table(
            "Exposed credentials",
            columns=[("Account", "bold cyan", "left"),
                     ("Password / secret", "bold green", "left"),
                     ("Recovered from", "dim white", "left")],
            rows=rows, max_rows=9999,
        )
        for rec in records:
            for use in rec["used_for"]:
                ui.print_status(f"{rec['principal']}: {use}", "info")

    for tech in techniques:
        mitre = " / ".join(tech["mitre"])
        ui.print_status(f"CREDENTIAL ACCESS [{mitre}] {tech['technique']}: "
                        + "; ".join(tech["commands"]), "warning")
        if tech.get("has_credential_pair"):
            ui.print_status("The SAM + SYSTEM pair recovers every local account's NTLM hash "
                            "offline (secretsdump.py -sam SAM -system SYSTEM LOCAL).", "info")


def _apply_offline_recovery(result, pcap_path: str, do_crack: bool, wordlist: str | None):
    """For chat/analyze: run the opt-in offline step and fold it into the result so
    the copilot and the report can use the recovered facts. Returns the recovery
    when --crack ran, else hints that it is available and returns None."""
    from packetiq.offline.recover import recover

    if not do_crack:
        if (getattr(result, "kerberos", None) or {}).get("asrep_hashes"):
            ui.print_status("An AS-REP roast is present. Re-run with --crack to recover the "
                            "password, the WinRM commands and the flag for the copilot.", "info")
        return None
    rec = recover(pcap_path, wordlist)
    result.offline = rec.to_dict()
    if not rec.roasts:
        ui.print_status("No AS-REP roast in this capture to crack.", "info")
    return rec


@main.command("crack")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--wordlist", "-w", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Wordlist to crack the AS-REP roast with (default: a small bundled "
                   "common-password list; point this at rockyou.txt for real work).")
def crack(pcap_file: str, wordlist: str | None):
    """
    Offline: crack an AS-REP roast, then decrypt the WinRM session it unlocks.

    \b
    This is the deliberate exception to PacketIQ's read-only stance: it takes the
    credential material the capture exposes and does the offline work by hand —
    recovering the password from the roast, then using it to decrypt the sealed
    WinRM traffic and read the commands that ran. It needs a wordlist, and it
    only recovers what weak credentials and a cracked password allow.
    """
    from packetiq.offline.recover import recover

    pcap_path = str(Path(pcap_file).resolve())
    ui.print_section("OFFLINE CRACK + DECRYPT",
                     "AS-REP roasting and WinRM session recovery")

    source = Path(wordlist).name if wordlist else "bundled common-password list"
    rec = recover(pcap_path, wordlist)
    if not rec.roasts:
        ui.print_status("No AS-REP roastable credential found in this capture. "
                        "Nothing to crack.", "warning")
        return
    ui.print_status(f"Found {rec.roasts} AS-REP roast(s); cracked against {source}.", "info")
    _print_offline_recovery(rec)


# ──────────────────────────────────────────────────────────────────────────────
# report command
# ──────────────────────────────────────────────────────────────────────────────

@main.command("report")
@click.argument("pcap_file", type=click.Path(exists=True, readable=True))
@click.option("--out", "-o", default=None,
              help="Output file path for the report (default: report_<name>_<ts>.md).")
@click.option("--alert/--no-alert", default=False,
              help="Send Telegram alerts + attach report file after generation.")
@click.option("--provider", type=click.Choice(_AI_PROVIDERS), default="auto",
              show_default=True, help="AI provider to use.")
@click.option("--model", default="", metavar="NAME",
              help="Pin the model (e.g. qwen2.5:3b). Local models: `ollama list`. "
                   "Pick one that fits your RAM — a larger model is slower.")
def report(pcap_file: str, out: str, alert: bool, provider: str, model: str):
    """
    Run full analysis and generate an AI SOC report.

    \b
    Example:
        packetiq report capture.pcap
        packetiq report capture.pcap --out /tmp/incident_report.md
        packetiq report capture.pcap --provider ollama --model qwen2.5:3b
        packetiq report capture.pcap --alert
    """
    from packetiq.copilot import build_context
    from packetiq.copilot.multi_provider import MultiProviderClient

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)

    ui.print_section("AI SOC REPORT GENERATION", "Gemini / Groq / Anthropic / local Ollama")

    client = MultiProviderClient(provider=provider, model=model)
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
@click.option("--provider", type=click.Choice(_AI_PROVIDERS), default="auto",
              show_default=True, help="AI provider to use.")
@click.option("--model", default="", metavar="NAME",
              help="Pin the model (e.g. qwen2.5:3b). Local models: `ollama list`. "
                   "Pick one that fits your RAM — a larger model is slower.")
@click.option("--crack", "do_crack", is_flag=True, default=False,
              help="Also run the offline step (crack the AS-REP roast, decrypt WinRM) and "
                   "give the copilot the recovered password, commands and flag.")
@click.option("--wordlist", "-w", type=click.Path(exists=True, dir_okay=False), default=None,
              help="Wordlist for --crack (default: the bundled common-password list).")
def chat(pcap_file: str, provider: str, model: str, do_crack: bool, wordlist: str | None):
    """
    Run full analysis then open an AI chat session about the PCAP.

    \b
    Example:
        packetiq chat capture.pcap
        packetiq chat capture.pcap --provider ollama --model qwen2.5:3b
        packetiq chat capture.pcap --crack        # also recover cracked creds/commands/flag
    """
    from packetiq.copilot import InteractiveChat, build_context
    from packetiq.copilot.multi_provider import MultiProviderClient

    pcap_path = Path(pcap_file).resolve()
    file_meta, result, events, risk, chains, fingerprints = _run_pipeline(pcap_path, ui)
    rec = _apply_offline_recovery(result, str(pcap_path), do_crack, wordlist)
    if rec:
        _print_offline_recovery(rec)
    _print_credential_exposure(result)

    ui.print_section("AI COPILOT", "loading analysis context")

    client = MultiProviderClient(provider=provider, model=model)
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
            ui.print_data(r.raw_yaml)
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


def _warn_if_window_overflowed(mon) -> None:
    """Say so when the rolling window became rate-limited rather than time-limited.

    The window is capped at `live._MAX_WINDOW_RECORDS` so a busy link cannot
    exhaust memory, but a monitor that silently analysed a subset of the traffic
    while reporting as though it saw all of it would be the kind of overstated
    result this project exists to avoid.
    """
    dropped = getattr(mon, "dropped", 0) or 0
    if dropped:
        ui.print_status(
            f"{dropped:,} packet(s) fell out of the rolling window — traffic "
            f"arrived faster than the {len(mon.buf):,}-record cap allows, so "
            f"detection ran on the most recent packets only.",
            status="warn",
        )


def _attribution_line(a) -> str:
    """Render one TTP-overlap row for the fuse report.

    Kept out of the command body so a test can render a real AttributionMatch:
    a field removed from the dataclass has silently broken this row before.
    """
    filled = int(a.confidence * 20)
    bar = "█" * filled + "░" * (20 - filled)
    return (
        f"  [{a.color}]{a.actor_name:<22}[/{a.color}]  "
        f"[green]{bar}[/green]  "
        f"[bold white]{int(a.confidence * 100):3d}%[/bold white] overlap  "
        f"[dim]{a.origin}[/dim]"
    )


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
            ui.print_raw(_attribution_line(a))
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
        ui.print_data(payload)


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
        ui.print_data(payload)


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
        note = ("No HTTP Server / User-Agent banners observed. Encrypted (HTTPS) "
                "traffic exposes none, so there is nothing to look up.")
        ui.print_status(note, status="warn")
        # --json promises a JSON document on every run; returning prose here left
        # `packetiq cve … --json | jq` failing on any all-encrypted capture.
        if as_json:
            import json
            ui.print_data(json.dumps({"results": [], "note": note}, indent=2))
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
        ui.print_data(json.dumps(data, indent=2))
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
        note = "No software banners observed (encrypted traffic exposes none). Nothing to assess."
        ui.print_status(note, status="warn")
        if as_json:
            import json
            ui.print_data(json.dumps(
                {"products": [], "correlations": [], "note": note,
                 "risk": {"score": 0, "tier": "NONE"},
                 "totals": {"cves": 0, "kev": 0}}, indent=2))
        return
    if not nvd.get_api_key():
        ui.print_status("No NVD_API_KEY set — using the slower anonymous rate limit.", status="warn")
    ui.print_status("Resolving CPEs and querying NVD + CISA KEV...", status="loading")

    data = nvd.assess_vulnerabilities(banners, attacks)
    if as_json:
        import json
        ui.print_data(json.dumps(data, indent=2))
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
            tag += " RANSOMWARE" if c.get("ransomware") else ""
            ui.print_status(f"{c['id']}  [CVSS {c['cvss']} {c['severity']}]{tag}", status="error" if c["kev"] else "warn")
            ui.print_key_value("link", c["url"])
    for cor in data["correlations"]:
        ui.print_status(f"Exploit attempt for {cor['name']} ({', '.join(cor['cves'])}) → {cor['target']}"
                        + (f"  [target runs {', '.join(cor['target_software'])}]" if cor["target_software"] else ""),
                        status="error")
    ui.print_status(f"{data['totals']['cves']} CVE(s), {data['totals']['kev']} actively exploited "
                    f"(of {data['totals']['kev_catalog']} in CISA KEV).", status="ok")


def _print_interfaces():
    """Print a Wireshark-style capture-interface list (name, friendly, IP, link)."""
    try:
        from packetiq.net_interfaces import list_interfaces
        recs = list_interfaces()
    except Exception as exc:  # pragma: no cover - defensive
        ui.print_status(f"Could not enumerate interfaces: {exc}", status="error")
        return
    if not recs:
        ui.print_status("No capture interfaces found.", status="error")
        return
    ui.print_section("CAPTURE INTERFACES", "★ = recommended · ● link up · ○ no link")
    for r in recs:
        # Pad the plain text to fixed widths first, THEN colour, so rich markup
        # characters don't throw off column alignment.
        if r["up"] is True:
            link = "[green]" + f"{'● up':<7}" + "[/green]"
        elif r["up"] is False:
            link = "[dim]" + f"{'○ down':<7}" + "[/dim]"
        else:
            link = "[dim]" + f"{'· ?':<7}" + "[/dim]"
        star = "[bold yellow]★[/bold yellow]" if r["recommended"] else " "
        label = r["label"] if r["label"] and r["label"] != r["name"] else ""
        ip = f"[cyan]{r['ip']:<15}[/cyan]" if r["ip"] else "[dim]" + f"{'—':<15}" + "[/dim]"
        ui.print_raw(f"  {star} [bold]{r['name']:<9}[/bold] {link} {ip} [dim]{label}[/dim]")
    ui.print_raw("\n  Start monitoring:  [bold]sudo packetiq live -i <name>[/bold]")


@main.command("live")
@click.option("--interface", "-i", default=None, help="Network interface to sniff (e.g. en0, eth0).")
@click.option("--read", "read_pcap", default=None, type=click.Path(exists=True),
              help="Replay a PCAP through the live engine instead of sniffing (no root needed).")
@click.option("--window", default=300.0, show_default=True, help="Rolling detection window (seconds).")
@click.option("--interval", default=10.0, show_default=True, help="Seconds between detection scans (live mode).")
@click.option("--threshold", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"], case_sensitive=False),
              default="HIGH", show_default=True, help="Minimum severity to alert on.")
@click.option("--alert/--no-alert", default=False, help="Also send Telegram/other-channel alerts for findings.")
@click.option("--list", "list_ifaces", is_flag=True, help="List capture interfaces (friendly name, IP, link status) and exit.")
def live_cmd(interface, read_pcap, window, interval, threshold, alert, list_ifaces):
    """
    Real-time monitoring: sniff an interface (or replay a PCAP) and alert on
    findings as they appear — a lightweight IDS built on the same detectors.

    \b
    Example:
        packetiq live --list                     # see interfaces (like Wireshark)
        sudo packetiq live -i en0
        packetiq live --read capture.pcap        # offline replay, no root
    """
    from packetiq import live as live_mod

    if list_ifaces:
        _print_interfaces()
        return

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
            with contextlib.suppress(Exception):
                from packetiq.alerts import channels
                channels.broadcast("PacketIQ live alert", f"[{sev}] {e.description}")

    if read_pcap:
        ui.print_status(f"Replaying {read_pcap} through the live engine...", status="loading")
        mon = live_mod.replay(read_pcap, _on_alert, window_secs=window, threshold=threshold)
        ui.print_divider()
        ui.print_status(f"Replay complete — {mon.alert_count} alert(s) raised.", status="ok")
        _warn_if_window_overflowed(mon)
        return

    if not interface:
        ui.print_status("Provide -i/--interface to sniff, or --read PCAP to replay. "
                        "Available interfaces:", status="error")
        _print_interfaces()
        sys.exit(1)

    ui.print_status(f"Sniffing {interface} (Ctrl+C to stop)...", status="loading")
    try:
        mon = live_mod.sniff_live(interface, _on_alert, window_secs=window,
                                  interval_secs=interval, threshold=threshold)
    except RuntimeError as e:
        ui.print_status(str(e), status="error")
        sys.exit(1)
    _warn_if_window_overflowed(mon)
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
        for ev in events:
            dst = f"{ev.dst_ip}:{ev.dst_port}" if ev.dst_ip and ev.dst_port else (ev.dst_ip or "—")
            rows.append([ev.severity.value, ev.event_type.value.replace("_", " "),
                         ev.src_ip or "—", dst, ev.description[:70]])
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


@main.command("netflow")
@click.argument("flow_file", type=click.Path(exists=True, readable=True))
@click.option("--top", "-t", default=15, show_default=True)
def netflow_cmd(flow_file: str, top: int):
    """
    Analyze a NetFlow v5 / v9 / IPFIX export — flow-based detection without a PCAP.

    \b
    Example:
        packetiq netflow /var/lib/nfcapd/flows.bin
    """
    from packetiq.inputs import load_netflow

    ui.print_section("NETFLOW / IPFIX ANALYSIS", "flow-export ingestion")
    ui.print_status(f"Loading {flow_file}...", status="loading")
    try:
        result = load_netflow(flow_file)
    except Exception as e:
        ui.print_status(f"Failed to parse flow export: {e}", status="error")
        sys.exit(1)

    ui.print_status(
        f"Loaded {len(result.flows):,} flow(s), {len(result.unique_src_ips)} source(s), "
        f"{len(result.external_ips)} external IP(s).",
        status="ok",
    )

    engine = DetectionEngine()
    events, risk, _fps = engine.run(result, flow_file)   # payload passes no-op gracefully
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
        for ev in events:
            dst = f"{ev.dst_ip}:{ev.dst_port}" if ev.dst_ip and ev.dst_port else (ev.dst_ip or "—")
            rows.append([ev.severity.value, ev.event_type.value.replace("_", " "),
                         ev.src_ip or "—", dst, ev.description[:70]])
        ui.print_table(
            "Detection Events",
            columns=[("Severity", "bold white", "center"), ("Type", "yellow", "left"),
                     ("Source", "red", "left"), ("Destination", "cyan", "left"),
                     ("Description", "dim white", "left")],
            rows=rows, max_rows=top,
        )
    else:
        ui.print_status("No threats detected in this flow export.", status="ok")
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
        ui.print_data(json.dumps(event, indent=2))
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
    ok, err = sender.send(f"<b>PacketIQ Test Alert</b>\n\n{message}")
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

    url = f"http://{host if host != UNSPECIFIED_IPV4 else '127.0.0.1'}:{port}/"
    ui.print_status(f"PacketIQ Web App → {url}", status="info")
    ui.print_status("Upload a PCAP file in your browser to begin analysis.", status="info")
    ui.print_status("Press Ctrl+C to stop.", status="info")
    if host not in ("127.0.0.1", "localhost", "::1"):
        # Widen the DNS-rebinding/CSRF Host allow-list for the operator's chosen
        # bind address (or disable the Host check for a wildcard 0.0.0.0 bind).
        import os as _os
        _os.environ["PACKETIQ_ALLOWED_HOSTS"] = "*" if host == UNSPECIFIED_IPV4 else host
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
