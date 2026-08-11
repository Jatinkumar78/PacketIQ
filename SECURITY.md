# Security Policy

## Supported version

PacketIQ is at **v1.0.0**. Security fixes land on the latest release.

| Version | Supported |
|---|---|
| 1.0.0 | ✅ |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

- Open a private security advisory on the project's GitHub repository
  (**Security → Report a vulnerability**), or
- Contact the maintainer through the repository's listed contact.

Include the affected file or endpoint, a short reproduction, and the impact you
observed. A first response can be expected within a few days. Please give a
reasonable window to ship a fix before any public disclosure.

## Security posture

PacketIQ is a **local, single-user forensics tool**. Its design keeps the attack
surface small:

- **Loopback by default.** The web app binds `127.0.0.1`. Exposing it on a network
  (`--host 0.0.0.0`) is an explicit operator choice and prints a warning.
- **DNS-rebinding / CSRF guard.** A middleware validates the HTTP `Host` header
  against a loopback allow-list and rejects cross-origin state-changing requests.
- **Bounded, streamed uploads.** Captures are streamed to disk in 1 MiB chunks with
  an early size-cap abort (`PACKETIQ_MAX_UPLOAD_MB`, default 10 GB), so a large upload
  cannot exhaust memory. The cap is deliberately generous because memory is bounded by
  the 1 MiB chunk and by packet-at-a-time analysis (`PcapReader`), not by file size —
  the binding constraint is free disk. Filenames are basename-sanitised;
  server-generated UUIDs, not user input, build file paths.
- **Owner-only data directories.** The upload directory and history store are created
  `0700`.
- **No dangerous sinks.** No `eval`/`exec`/`pickle`/`os.system`/`shell=True`. The one
  privileged path (macOS/Linux capture setup) validates `$USER` against a strict
  charset before building a script and only ever uses list-form `subprocess` calls.
- **Parameterised SQL** throughout the history layer; **HTML-escaped** rendering in
  the web app and reports; **timeouts** on every outbound request.
- **Secrets stay local.** `.env` is git-ignored; API keys are read at runtime and
  never logged. The interactive docs (`/docs`, `/redoc`) are disabled.
- **Offline-capable, no telemetry.** Front-end libraries are vendored and the shipped
  threat-intel data is a bundled dated snapshot, so analysis needs no network at all.
  Nothing is sent anywhere unless you invoke it. The complete set of destinations any
  PacketIQ code can reach:

  | When | Destination |
  |---|---|
  | `packetiq feeds update` | abuse.ch (Feodo, ThreatFox, MalwareBazaar), Spamhaus DROP, the Tor exit list |
  | `packetiq cve` / `vulns` | `services.nvd.nist.gov`, CISA KEV (`www.cisa.gov`) |
  | Alerts, once configured | `api.telegram.org`, your Slack incoming-webhook URL, your generic webhook URL, your SMTP server |
  | `packetiq misp`, once configured | the MISP instance you name |
  | AI copilot | your configured cloud provider — or **loopback only**, if the provider is the local Ollama daemon |

  There is no analytics, crash-reporting or update-check traffic of any kind.

## Dependency security

Runtime dependencies are pinned to **security-patched floors** in `pyproject.toml`
and `requirements.txt`, re-checked by **`pip-audit`** in CI on every push. The
**reference/dev environment runs on Python 3.12.13**, where those floors resolve to
fully-patched releases and `pip-audit` reports **zero advisories in the runtime
dependency set** — that audit is **blocking**, so a finding fails the build. One
dev-only transitive (`diskcache`, via the `dev`-extra `pySigma`) has no upstream
fix and is never installed by `pip install packetiq`; its audit is advisory. Both
closures were last re-audited from a freshly built virtualenv on **2026-08-11**,
with the resolved versions and findings recorded in
[docs/security_audit/pip_audit.txt](docs/security_audit/pip_audit.txt).

**Python 3.9 is a different answer, and CI now states it rather than implying it.**
3.9 has been end-of-life since October 2025, and several dependencies have moved
past it: the current `pillow`, `python-dotenv` and `python-multipart` releases all
require Python ≥ 3.10. A 3.9 install therefore resolves to the newest
3.9-compatible version of each, and some of those carry published advisories with
**no release to upgrade to**. CI runs a second, **advisory-only** `pip-audit` on
3.9 so that residual is visible in every run's log instead of being a sentence
here that nobody re-checks. **Python 3.10 or newer is recommended** for the
fullest patch set; 3.9 remains supported and tested, with that caveat stated.

Static analysis uses **bandit**, run over `packetiq/` at its strictest setting
(`--severity-level low --confidence-level low`, so nothing is filtered out). As of
**2026-08-11** it reports **no issues at any severity** across 16,864 lines, which
is why that step is **blocking** too. Fourteen findings are suppressed by targeted
`# nosec BXXX` comments, each with a written justification; there are no blanket
suppressions, and every one is itemised in
[docs/security_audit/bandit.txt](docs/security_audit/bandit.txt).

## Audit

A full white-box security review (manual code review + bandit + pip-audit + git
secret scan + live exploitation) is documented in
[docs/reports/PacketIQ_Security_Audit_Report.pdf](docs/reports/PacketIQ_Security_Audit_Report.pdf).
The reproducible scripts and raw tool output live in
[docs/security_audit/](docs/security_audit/).

That report is a **point-in-time record dated 2026-07-15** and is deliberately left
as it was written on that date. One figure in it has since been superseded: it
records bandit as `High 0 / Medium 0 / Low 53`, and those 53 Low findings have
since been worked through — the current scan is clean at every severity, as above.
For the current state of either tool, read
[docs/security_audit/bandit.txt](docs/security_audit/bandit.txt) and
[docs/security_audit/pip_audit.txt](docs/security_audit/pip_audit.txt), which are
kept up to date; the PDF's other findings (1 Critical, 6 Medium, 3 Low, 2 Info —
all remediated, the Critical closed by the owner revoking the leaked keys on
2026-07-12) are unchanged.
