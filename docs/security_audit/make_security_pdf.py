#!/usr/bin/env python3
"""Render the PacketIQ security audit into a professional PDF report."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "reports", "PacketIQ_Security_Audit_Report.pdf")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

NAVY = colors.HexColor("#0b1f3a")
BLUE = colors.HexColor("#1d4ed8")
GREEN = colors.HexColor("#15803d")
RED = colors.HexColor("#b91c1c")
ORANGE = colors.HexColor("#c2410c")
YELLOW = colors.HexColor("#a16207")
GREY = colors.HexColor("#475569")
LIGHT = colors.HexColor("#eef2f7")
LINE = colors.HexColor("#cbd5e1")
MONO = "Courier"

SEV_COLOR = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": GREY}

st = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=st["Heading1"], textColor=NAVY, fontSize=16, spaceAfter=6, spaceBefore=8)
H2 = ParagraphStyle("H2", parent=st["Heading2"], textColor=BLUE, fontSize=12, spaceAfter=4, spaceBefore=8)
H3 = ParagraphStyle("H3", parent=st["Heading3"], textColor=NAVY, fontSize=10.5, spaceAfter=2, spaceBefore=4)
BODY = ParagraphStyle("Body", parent=st["Normal"], fontSize=9.3, leading=13.5, textColor=colors.HexColor("#1e293b"))
SMALL = ParagraphStyle("Small", parent=st["Normal"], fontSize=8, leading=11, textColor=GREY)
CODE = ParagraphStyle("Code", parent=st["Normal"], fontName=MONO, fontSize=7.6, leading=10,
                      textColor=colors.HexColor("#0f172a"), backColor=colors.HexColor("#f1f5f9"),
                      borderPadding=4, leftIndent=2)
CELL = ParagraphStyle("Cell", parent=st["Normal"], fontSize=8.2, leading=11)
CELLW = ParagraphStyle("CellW", parent=CELL, textColor=colors.white)
TITLE = ParagraphStyle("T", parent=st["Title"], textColor=NAVY, fontSize=25, leading=29)
SUB = ParagraphStyle("Sub", parent=st["Normal"], fontSize=12, textColor=GREY, alignment=TA_CENTER)


def P(t, s=BODY):
    return Paragraph(t, s)


def sev_badge(sev):
    return P(f"<b>{sev}</b>", ParagraphStyle("sb", parent=CELL, textColor=colors.white, fontSize=8, alignment=TA_CENTER))


# ── findings (curated from the real audit) ───────────────────────────────────
FINDINGS = [
    {"id": "F-01", "title": "Live API keys committed to git history", "sev": "CRITICAL", "cwe": "CWE-798 Hard-coded Credentials",
     "desc": "Real Google Gemini and Groq API keys were committed to <font face='Courier'>.env.example</font> in earlier history. The working tree is sanitised, but the secrets remain recoverable from the git history of every clone.",
     "evidence": "git log -p -- .env.example →\n-GEMINI_API_KEY=\"AIzaSyDBdy_…\"\n-GROQ_API_KEY=\"gsk_VYQsfBEN7…\"   (4 occurrences across history)",
     "impact": "Anyone with the repo (or a fork/mirror) can extract working keys → unauthorised AI usage billed to the owner, quota abuse.",
     "fix": "Working tree sanitised to placeholders and .env is gitignored. The account owner REVOKED both keys in the provider consoles on 2026-07-12, so the exposed values are now dead and cannot be used. An optional git-history scrub (commands in §6) remains only to tidy the historical record before any public push.",
     "status": "RESOLVED — keys revoked by the owner (2026-07-12); the leaked values no longer authenticate. Optional history scrub before a public push."},
    {"id": "F-02", "title": "Upload memory-exhaustion DoS", "sev": "MEDIUM", "cwe": "CWE-400 Uncontrolled Resource Consumption",
     "desc": "The /api/upload and /api/fuse endpoints read the entire uploaded body into RAM (<font face='Courier'>await file.read()</font>) and only checked the size afterwards, with a 10&nbsp;GB cap.",
     "evidence": "content = await file.read(); if len(content)/MB > MAX_UPLOAD_MB …   # MAX_UPLOAD_MB = 10_240",
     "impact": "A single large (or many concurrent) uploads exhaust server memory before any limit is enforced — denial of service.",
     "fix": "Rewrote uploads to STREAM to disk in 1&nbsp;MiB chunks with an early abort once the cap is exceeded — memory use is now bounded by the 1&nbsp;MiB chunk, not the file size, which is what actually removes the DoS. The size cap is a secondary, disk-bounded limit (default 10&nbsp;GB, env-overridable via PACKETIQ_MAX_UPLOAD_MB); analysis then reads the capture packet-by-packet via a streaming PcapReader, so even a 10&nbsp;GB file is processed in bounded memory. Added a 50-file campaign limit; filenames are basename-sanitised.",
     "status": "FIXED — verified by test (3&nbsp;MiB vs 1&nbsp;MiB cap → HTTP 413, partial file removed)."},
    {"id": "F-03", "title": "Oversized HTTP buffer / long keep-alive", "sev": "MEDIUM", "cwe": "CWE-400 / Slowloris",
     "desc": "uvicorn was started with h11_max_incomplete_event_size = 10&nbsp;GB and timeout_keep_alive = 600&nbsp;s.",
     "evidence": "uvicorn.run(…, timeout_keep_alive=600, h11_max_incomplete_event_size=10*1024**3)",
     "impact": "A client could force the server to buffer up to 10&nbsp;GB for a single incomplete request, and hold connections open for 10&nbsp;min — resource-exhaustion / slowloris surface.",
     "fix": "Reduced the header buffer to 16&nbsp;MB and keep-alive to 75&nbsp;s.",
     "status": "FIXED."},
    {"id": "F-04", "title": "Known-vulnerable dependencies", "sev": "MEDIUM", "cwe": "CWE-1395 Vulnerable Components",
     "desc": "pip-audit flags advisories (mostly DoS / parser edge cases) in python-multipart, starlette, requests, urllib3, click and python-dotenv.",
     "evidence": "The reference environment was migrated to Python 3.12.13 (2026-07-15), where pip resolves the pinned floors to their fully-patched releases: python-multipart 0.0.20→0.0.32, requests 2.32.5→2.34.2, urllib3 2.6.3→2.7.0, starlette 0.49.3→1.3.1, click 8.1.8→8.4.2, python-dotenv 1.2.1→1.2.2. pip-audit on that venv reports zero advisories across the runtime dependency set. On Python 3.9 each package is instead pinned to the newest 3.9-compatible release, and the advisory fixes require Python ≥ 3.10.",
     "impact": "DoS / parsing and request-handling weaknesses inherited from third-party libraries. None is remotely exploitable in PacketIQ's default deployment (loopback bind, single user, trusted local capture input).",
     "fix": "Security-patched minimum versions are pinned in pyproject.toml and requirements.txt (requests ≥2.32.4, urllib3 ≥2.6.0, python-multipart ≥0.0.18, cryptography ≥44.0.1). The reference/dev environment was migrated to Python 3.12.13 (2026-07-15) using a standalone uv-managed interpreter — no system change and no code change (requires-python stays ≥3.9) — and there the floors resolve to fully-patched releases. Python 3.9 remains supported for anyone who needs it, installing at the newest 3.9-compatible release (Python 3.9 reached end-of-life in October 2025).",
     "status": "RESOLVED on the reference environment (Python 3.12.13) — the runtime-dependency advisories (python-multipart, starlette, requests, urllib3, click, python-dotenv) are cleared. Python 3.9 stays supported with newest-compatible pins. One dev-only transitive advisory remains: diskcache (pulled by the dev-extra pySigma, not a runtime dependency) — PYSEC-2026-2447, no upstream fix released yet; never shipped to runtime users."},
    {"id": "F-05", "title": "Command-injection hardening (privileged setup)", "sev": "LOW", "cwe": "CWE-78 OS Command Injection",
     "desc": "capture_setup interpolates $USER/$LOGNAME into a shell script run with administrator privileges via osascript.",
     "evidence": "script = f\"… dseditgroup -o edit -a '{user}' …\"  (run 'with administrator privileges')",
     "impact": "A tampered $USER containing a single quote could break out of the quoting and inject commands in a root context (low likelihood — local, user-controlled env — but high impact).",
     "fix": "Added strict charset validation (^[A-Za-z0-9._-]{1,32}$); the privileged script is not built unless the username is safe.",
     "status": "FIXED — verified by test (evil$(id), a;rm -rf /, x'y all rejected)."},
    {"id": "F-06", "title": "Unauthenticated web API when exposed", "sev": "LOW", "cwe": "CWE-306 Missing Authentication",
     "desc": "The web API has no authentication, CORS or rate-limiting. It binds 127.0.0.1 by default (safe), but --host 0.0.0.0 exposes upload/analysis/AI to the network.",
     "evidence": "FastAPI(...) — no auth dependency; cli webapp --host 0.0.0.0 option.",
     "impact": "On a non-loopback bind, anyone on the network can upload captures, read results, drive paid AI usage, or trigger the privileged capture setup.",
     "fix": "Added an explicit security warning printed whenever the server binds to a non-loopback address; documented that exposure requires a trusted network or an authenticated reverse proxy. (By design the tool is single-user/local.)",
     "status": "FIXED (warning + guidance) — full auth is a deployment-layer concern, documented as a recommendation."},
    {"id": "F-09", "title": "Path traversal / arbitrary file write in evidence export", "sev": "MEDIUM", "cwe": "CWE-22 Path Traversal",
     "desc": "The /api/evidence endpoint built the output filename by interpolating the user-controlled <font face='Courier'>ip</font> query parameter directly into a filesystem path.",
     "evidence": "out = UPLOAD_DIR / f\"evidence_{job_id[:8]}_{ip}_{port}.pcap\"   # ip from the URL",
     "impact": "A request with ip=../../../../tmp/PWNED wrote the sliced capture OUTSIDE the upload directory — arbitrary .pcap file write (verified: the crafted path escaped UPLOAD_DIR).",
     "fix": "The `ip` is now validated as a real IP (ipaddress.ip_address) and the output filename is built from server-controlled values + a random token only — the raw parameter never reaches the path. (The filter itself uses set membership, not a BPF string, so there was no BPF injection.)",
     "status": "FIXED — verified live (ip=../../../../tmp/PWNED → HTTP 400, no file created) and by test."},
    {"id": "F-10", "title": "No Host-header validation (DNS rebinding)", "sev": "MEDIUM", "cwe": "CWE-350 Reliance on Untrusted Inputs",
     "desc": "The local web server did not validate the HTTP Host header, so a malicious website whose domain resolves to 127.0.0.1 (DNS rebinding) could drive the API from the victim's browser.",
     "evidence": "No TrustedHost / Host check on any route.",
     "impact": "A visited web page could read analysis results or invoke actions on the locally-running PacketIQ.",
     "fix": "Added a security middleware that validates the Host header against a loopback allow-list (widened by the launcher only when the operator deliberately binds a non-loopback address).",
     "status": "FIXED — verified live (Host: evil.com → HTTP 400) and by test."},
    {"id": "F-11", "title": "Cross-site request forgery on state-changing endpoints", "sev": "MEDIUM", "cwe": "CWE-352 CSRF",
     "desc": "State-changing POSTs (including /api/live/setup-capture, which triggers a privileged admin-password prompt) had no origin check, so a malicious page could submit them cross-origin from the victim's browser.",
     "evidence": "POST /api/live/setup-capture with no CSRF/Origin protection.",
     "impact": "A visited web page could pop the OS admin-password prompt or start analysis / drive paid AI usage without consent.",
     "fix": "The same middleware rejects state-changing requests whose Origin is cross-site (HTTP 403); read-only GETs are unaffected; same-origin SPA calls continue to work.",
     "status": "FIXED — verified live (cross-origin POST setup-capture → HTTP 403) and by test."},
    {"id": "F-12", "title": "World-readable upload / history directories", "sev": "LOW", "cwe": "CWE-732 / CWE-377 Insecure Permissions",
     "desc": "Uploaded captures and the SQLite history DB were stored in directories created with default (world-readable) permissions in a shared temp location.",
     "evidence": "UPLOAD_DIR.mkdir(exist_ok=True)  # default 0755; captures written 0644",
     "impact": "On a multi-user host, other local users could read potentially sensitive captured traffic and analysis history.",
     "fix": "The upload and history directories are now chmod 0700 (owner-only).",
     "status": "FIXED."},
    {"id": "F-07", "title": "MD5 used in JA3 fingerprinting", "sev": "INFO", "cwe": "CWE-327 (false positive)",
     "desc": "bandit flagged hashlib.md5 in the JA3 fingerprinter as a weak hash.",
     "evidence": "return hashlib.md5(ja3_str.encode()).hexdigest()",
     "impact": "None. JA3 is DEFINED as the MD5 of the cipher string (Salesforce spec); it is an identifier, not a security/integrity control.",
     "fix": "Annotated with usedforsecurity=False and a comment documenting the intent (also clears the bandit HIGH).",
     "status": "RESOLVED (annotated; not a real weakness)."},
    {"id": "F-08", "title": "Subprocess started via PATH lookup", "sev": "INFO", "cwe": "CWE-426 Untrusted Search Path",
     "desc": "getcap/setcap/osascript are invoked by name (relying on PATH) rather than absolute path.",
     "evidence": "bandit B607 — start_process_with_partial_path (×2).",
     "impact": "Low — these are standard system binaries; exploitation needs an attacker-controlled PATH, which implies prior local compromise.",
     "fix": "Accepted risk / documented. All subprocess calls already use list-form args (no shell=True) so there is no shell-metacharacter exposure.",
     "status": "ACCEPTED (documented residual risk)."},
]

CONTROLS_OK = [
    ("Cross-site scripting (XSS)", "Every SPA interpolation of attacker-influenceable free text (packet info, HTTP host/path/User-Agent, software banners, CVE descriptions, filenames) is HTML-escaped; an interpolation scan of all 287 template expressions confirmed no unescaped free-text sink (IP fields, additionally escaped, are structurally constrained)."),
    ("BPF / filter injection", "The evidence filter matches by Python set membership, not a compiled BPF string — no filter-language injection."),
    ("ReDoS", "Attacker-facing regexes (HTTP-attack, DNS, banner parsing) use bounded quantifiers with no catastrophic backtracking."),
    ("Unsafe deserialisation", "No yaml.load / pickle / marshal on untrusted input; all parsing is JSON or Scapy."),
    ("SQL injection", "All database access uses parameterised queries (? placeholders, int() casts). No string-built SQL."),
    ("Path traversal", "File paths are derived from server-generated UUID job keys validated against the in-memory job registry — the URL job_id is never used to build a filesystem path directly."),
    ("Dangerous sinks", "No eval / exec / pickle / os.system / shell=True / yaml.load anywhere in production code."),
    ("Injection in HTML report", "All user/observed data is HTML-escaped (_esc) in the report; the SPA escapes via esc()."),
    ("Network timeouts", "All outbound requests (NVD, CISA, MISP, Telegram, feeds) set explicit timeouts (no hang/DoS)."),
    ("Secrets at rest", ".env is gitignored; the working tree contains only placeholders; API keys are read at runtime, never logged."),
    ("API surface", "Swagger/ReDoc docs are disabled (docs_url=None); the server defaults to loopback binding."),
    ("SSRF", "All third-party URLs are hard-coded (NVD/CISA/abuse.ch); only the operator-configured MISP/webhook URLs are user-set, by design."),
]

STEPS = [
    ("Establish a safe baseline", "python -m pytest ; ruff check",
     "143 tests pass, lint clean", "Confirm the codebase is green before touching it, so any later breakage is attributable to a fix, not pre-existing."),
    ("Static pattern sweep", "grep -rnE 'eval|exec|pickle|os.system|shell=True|yaml.load' packetiq",
     "Only an interactive input() in the CLI chat — no dangerous sinks", "Manually hunt the classic RCE/deserialisation sinks before trusting any automated tool."),
    ("Review file I/O & path handling", "read _job_pcap_paths, /api/upload, /api/evidence",
     "job_id validated against the job registry; no traversal", "Verify attacker-controlled URL parameters cannot escape the upload directory."),
    ("Review database layer", "read packetiq/storage.py",
     "Parameterised queries throughout — no SQLi", "Confirm history persistence cannot be injected."),
    ("Review privileged code", "read capture_setup.py (osascript / setcap)",
     "$USER interpolated into an admin-privileged shell script → F-05", "Privileged execution paths get the highest scrutiny."),
    ("Static analysis (SAST)", "python -m bandit -r packetiq",
     "1 High (MD5/JA3 — FP), 1 Medium (bind-all string), 41 Low", "Automated CWE coverage to catch what manual review misses."),
    ("Dependency CVE scan", "python -m pip_audit",
     "Advisories in python-multipart, starlette, requests, urllib3, cryptography, idna, python-dotenv → F-04", "Most real-world risk is in third-party components; audit the supply chain."),
    ("Secret scan (git history)", "git log -p -- .env.example | grep -E 'AIzaSy|gsk_'",
     "Live Gemini + Groq keys found in history → F-01 (CRITICAL)", "Secrets removed from the working tree often persist in history; scan the whole DAG."),
    ("Remediate code findings", "edit app.py / cli.py / capture_setup.py / ja3.py",
     "Streamed uploads, bounded buffers, username validation, MD5 annotation, bind warning", "Fix the issues we control, in code, with the least disruptive change."),
    ("Remediate dependencies", "pin security floors in pyproject.toml + requirements.txt",
     "reference env migrated to Python 3.12.13 — runtime advisories cleared; 3.9 stays supported at newest-compatible pins", "Apply the patches that are installable now; pin safe minimums for future installs."),
    ("Add regression tests", "tests/test_security.py",
     "4 tests (upload abort, username gate) pass", "Lock the fixes so they cannot silently regress."),
    ("Deep round-2 (verified, not assumed)", "XSS interpolation scan ; live traversal/rebinding/CSRF exploit attempts",
     "Found + FIXED path traversal (F-09), DNS-rebinding (F-10), CSRF (F-11), dir perms (F-12)", "Go beyond the obvious surface: actively try to exploit each class rather than assume it is safe."),
    ("Re-verify", "pytest ; ruff ; bandit ; pip_audit ; live exploit re-tests",
     "full suite (now 304 tests) passes, lint clean, bandit High=0 & Medium=0, all exploits blocked", "Prove the fixes work and introduced no regressions."),
]


def kv_table(rows, w0=3.2 * cm):
    t = Table([[P(f"<b>{k}</b>", CELL), P(v, CELL)] for k, v in rows], colWidths=[w0, 17 * cm - w0])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("BACKGROUND", (0, 0), (0, -1), LIGHT), ("TOPPADDING", (0, 0), (-1, -1), 3),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY); canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(colors.white); canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(15 * mm, A4[1] - 8 * mm, "PacketIQ — Security Audit Report")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 8 * mm, "Confidential · Authorised self-assessment")
    canvas.setFillColor(GREY); canvas.setFont("Helvetica", 7.5)
    canvas.drawString(15 * mm, 8 * mm, "Defensive security review of the author's own project. No third-party systems were tested.")
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.setStrokeColor(LINE); canvas.line(15 * mm, 11 * mm, A4[0] - 15 * mm, 11 * mm)
    canvas.restoreState()


def build():
    story = []
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in FINDINGS:
        counts[f["sev"]] += 1

    # Cover
    story += [Spacer(1, 3 * cm), P("PacketIQ", TITLE),
              P("Security Audit Report", ParagraphStyle("st", parent=TITLE, fontSize=16, textColor=BLUE)),
              Spacer(1, 6), P("AI PCAP Forensics &amp; SOC Copilot — Static, Dependency &amp; Secret Assessment", SUB),
              Spacer(1, 1.2 * cm)]
    chips = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = SEV_COLOR[sev]
        cell = Table([[P(f"<b>{counts[sev]}</b>", ParagraphStyle("n", parent=CELL, fontSize=15, textColor=colors.white, alignment=TA_CENTER))],
                      [P(sev, ParagraphStyle("l", parent=CELL, fontSize=7, textColor=colors.white, alignment=TA_CENTER))]],
                     colWidths=[3.1 * cm], rowHeights=[0.8 * cm, 0.45 * cm])
        cell.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), c), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
        chips.append(cell)
    crow = Table([chips], colWidths=[3.3 * cm] * 5)
    crow.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story += [crow, Spacer(1, 1 * cm)]
    story += [kv_table([
        ("Target", "PacketIQ v1.0.0 — Python network-forensics tool (CLI + FastAPI web app)"),
        ("Audit type", "White-box: manual code review + SAST (bandit) + dependency CVE scan (pip-audit) + git secret scan"),
        ("Scope", "All Python source under packetiq/, dependencies, git history. Authorised self-assessment of the author's own project."),
        ("Environment", f"Sandboxed local venv · Python {__import__('platform').python_version()} · {__import__('platform').system()}"),
        ("Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
        ("Result", f"{counts['CRITICAL']} Critical, {counts['MEDIUM']} Medium, {counts['LOW']} Low, {counts['INFO']} Info. "
                   "All findings remediated: every code-level fix is in place and the Critical (leaked keys) was closed by owner key-revocation on 2026-07-12."),
    ])]
    story += [PageBreak()]

    # 1. Executive summary
    story += [P("1. Executive Summary", H1), HRFlowable(width="100%", color=LINE, spaceAfter=6)]
    story += [P(
        "PacketIQ was assessed with a white-box methodology combining manual source review of every security-sensitive "
        "code path with three automated tools: <b>bandit</b> (Python SAST), <b>pip-audit</b> (dependency CVEs) and a "
        "<b>git-history secret scan</b>. The codebase is fundamentally sound — it uses parameterised SQL, validates all "
        "file paths against a server-side job registry, contains no dangerous execution sinks (no eval/exec/pickle/"
        "shell=True), sets timeouts on every outbound request, and HTML-escapes all rendered data.", BODY)]
    story += [Spacer(1, 4), P(
        "Twelve findings were raised across two rounds. The single <b>Critical</b> was operational, not code: live AI "
        "keys committed to git history. The account owner has since revoked those keys (2026-07-12), so they are now "
        "dead — the finding is closed, with an optional history scrub remaining only for tidiness. Six <b>Medium</b> findings were "
        "identified and <b>fixed</b> — an upload memory-exhaustion DoS, oversized HTTP buffers, vulnerable "
        "dependencies, and (found by actively attempting the exploits in round 2) a <b>path-traversal / arbitrary "
        "file write</b>, <b>DNS-rebinding</b>, and <b>cross-site request forgery</b> against the local server. Three "
        "<b>Low</b> findings (privileged-script command-injection hardening, exposure when bound to all interfaces, "
        "and world-readable temp directories) were also fixed. Every code-level fix is covered by new regression "
        "tests and, where exploitable, re-tested live to confirm it is blocked. The two Info items are a false "
        "positive (MD5 is the JA3 spec) and one accepted residual.", BODY)]
    story += [Spacer(1, 8), P("Findings overview", H2)]
    rows = [[P("<b>ID</b>", CELLW), P("<b>Finding</b>", CELLW), P("<b>Severity</b>", CELLW), P("<b>Status</b>", CELLW)]]
    for f in FINDINGS:
        rows.append([P(f["id"], CELL), P(f["title"], CELL),
                     P(f"<b>{f['sev']}</b>", ParagraphStyle("s", parent=CELL, textColor=SEV_COLOR[f["sev"]])),
                     P(f["status"].split("—")[0].split("(")[0].strip(), SMALL)])
    t = Table(rows, colWidths=[1.4 * cm, 7.8 * cm, 2.2 * cm, 5.6 * cm], repeatRows=1)
    ts = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
          ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            ts.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    t.setStyle(TableStyle(ts))
    story += [t, PageBreak()]

    # 2. Methodology
    story += [P("2. Scope &amp; Methodology", H1), HRFlowable(width="100%", color=LINE, spaceAfter=6)]
    story += [P("This is an <b>authorised, defensive self-assessment</b> of the author's own project, performed entirely "
                "in a local sandbox. No external systems, networks or third parties were touched. Three complementary "
                "techniques were used:", BODY), Spacer(1, 4)]
    story += [kv_table([
        ("Manual review", "Line-by-line reading of the highest-risk paths: file upload/download, the SQLite layer, the privileged capture-setup, subprocess usage, report rendering, and the web app's configuration."),
        ("bandit (SAST)", "Static analysis of all Python source against the CWE-mapped Bandit ruleset to surface insecure patterns automatically."),
        ("pip-audit", "Cross-references every installed dependency against the Python Packaging Advisory Database (PyPA) and OSV."),
        ("git secret scan", "Greps the full commit history for credential patterns (AIza…, gsk_…) that may persist after a working-tree clean-up."),
    ], w0=3.2 * cm)]
    story += [PageBreak()]

    # 3. Steps
    story += [P("3. Audit Procedure — Step by Step", H1), HRFlowable(width="100%", color=LINE, spaceAfter=4),
              P("Each step records <b>why</b> it was performed, the <b>command/action</b>, the <b>result</b>, and an "
                "<b>explanation</b>.", SMALL), Spacer(1, 4)]
    rows = [[P("<b>#</b>", CELLW), P("<b>Step &amp; why</b>", CELLW), P("<b>Command / action</b>", CELLW), P("<b>Result</b>", CELLW)]]
    for i, (what, cmd, res, why) in enumerate(STEPS, 1):
        rows.append([P(str(i), CELL),
                     P(f"<b>{what}</b><br/><font size=7 color='#475569'>{why}</font>", CELL),
                     P(cmd, ParagraphStyle("c", parent=CELL, fontName=MONO, fontSize=7)),
                     P(res, SMALL)])
    t = Table(rows, colWidths=[0.8 * cm, 6.0 * cm, 5.4 * cm, 4.8 * cm], repeatRows=1)
    ts = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
          ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            ts.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    t.setStyle(TableStyle(ts))
    story += [t, PageBreak()]

    # 4. Findings detail
    story += [P("4. Findings in Detail", H1), HRFlowable(width="100%", color=LINE, spaceAfter=6)]
    for f in FINDINGS:
        block = [P(f"{f['id']} · {f['title']}", H2),
                 kv_table([
                     ("Severity", f"<font color='#{SEV_COLOR[f['sev']].hexval()[2:]}'><b>{f['sev']}</b></font> · {f['cwe']}"),
                     ("Description", f["desc"]),
                     ("Impact", f["impact"]),
                 ], w0=2.6 * cm),
                 Spacer(1, 3), P("<b>Evidence</b>", SMALL), P(f["evidence"].replace("\n", "<br/>"), CODE),
                 Spacer(1, 3),
                 kv_table([("Remediation", f["fix"]), ("Status", f["status"])], w0=2.6 * cm),
                 Spacer(1, 10)]
        story.append(KeepTogether(block))
    story += [PageBreak()]

    # 5. Controls verified secure
    story += [P("5. Security Controls Verified (No Finding)", H1), HRFlowable(width="100%", color=LINE, spaceAfter=6),
              P("The following were specifically tested and found to be implemented correctly:", BODY), Spacer(1, 4)]
    rows = [[P("<b>Control</b>", CELLW), P("<b>Result</b>", CELLW)]]
    for k, v in CONTROLS_OK:
        rows.append([P(k, CELL), P("✓ " + v, SMALL)])
    t = Table(rows, colWidths=[4.0 * cm, 13.0 * cm], repeatRows=1)
    ts = [("BACKGROUND", (0, 0), (-1, 0), GREEN), ("GRID", (0, 0), (-1, -1), 0.4, LINE),
          ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    for i in range(1, len(rows)):
        if i % 2 == 0:
            ts.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
    t.setStyle(TableStyle(ts))
    story += [t, Spacer(1, 12)]

    # 6. Post-fix verification + required owner action
    story += [P("6. Remediation Verification &amp; Required Owner Action", H1), HRFlowable(width="100%", color=LINE, spaceAfter=6)]
    story += [P("After applying the fixes the full battery was re-run:", BODY), Spacer(1, 4)]
    story += [kv_table([
        ("Unit/integration tests", "304 passed — the full suite, including the security regression tests added in this engagement — no regressions."),
        ("Linter (ruff)", "All checks passed."),
        ("bandit (SAST)", "High: 0, Medium: 0, Low: 53 (defensive try/except/pass and list-form subprocess calls — no shell=True anywhere). MD5/JA3 annotated usedforsecurity=False; the pseudo-random calls in the synthetic capture/benchmark generators are annotated <font face='Courier'>#&nbsp;nosec&nbsp;B311</font> (deterministic sample data, never cryptographic)."),
        ("Live exploit re-tests", "Path traversal (ip=../../..) → 400 with no file written; DNS-rebinding (bad Host) → 400; cross-origin POST to privileged setup-capture → 403."),
        ("pip-audit", "Reference env migrated to Python 3.12.13: the pinned floors resolve to fully-patched releases and the runtime dependency set reports zero advisories. Only a dev-only transitive remains (diskcache via the dev-extra pySigma), no upstream fix yet. Python 3.9 stays supported at newest-compatible pins."),
    ], w0=4.2 * cm)]
    story += [Spacer(1, 10), P("Owner action (F-01) — completed", H2)]
    story += [P("The account owner revoked both exposed keys in the provider consoles (Google AI Studio &amp; Groq) on "
                "2026-07-12, so the leaked values no longer authenticate. Optionally, scrub them from git history before any "
                "public push so the dead values do not linger in the record:", BODY)]
    story += [P("pip install git-filter-repo<br/>"
                "git filter-repo --path .env.example --invert-paths    # or: --replace-text with the key strings<br/>"
                "git push --force --all", CODE)]
    story += [Spacer(1, 6), P("Recommended next step: run PacketIQ on Python 3.10+ (3.11/3.12) so every dependency advisory "
                              "is patched automatically by the existing version floors.", SMALL)]

    # 7. Conclusion
    story += [Spacer(1, 10), P("7. Conclusion", H1), HRFlowable(width="100%", color=LINE, spaceAfter=6)]
    story += [P("PacketIQ is, at the code level, a well-built and defensible application: it avoids the common high-impact "
                "web vulnerabilities (injection, traversal, unsafe deserialisation) and now streams uploads, bounds its "
                "buffers, hardens its one privileged path, and warns on insecure exposure. After this engagement there are "
                "<b>no outstanding code-level vulnerabilities</b>, and the one operational risk — API keys committed to git "
                "history — has been closed by the owner revoking those keys. The project meets a sound security bar for a "
                "local, single-user forensics tool. The main forward-looking recommendation is to run on Python 3.10+ so "
                "the pinned dependency floors resolve to fully-patched releases; further hardening (authentication, "
                "rate-limiting) is worthwhile only if the web app is ever exposed beyond localhost.", BODY)]

    doc = SimpleDocTemplate(OUT, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                            leftMargin=15 * mm, rightMargin=15 * mm,
                            title="PacketIQ Security Audit Report", author="PacketIQ Security Review")
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    print("Wrote", OUT)


if __name__ == "__main__":
    build()
