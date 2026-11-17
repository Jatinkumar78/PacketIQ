# Security Policy

## Supported version

PacketIQ is at **v1.1.0**. Security fixes land on the latest release.

| Version | Supported | Note |
|---|---|---|
| 1.1.0 | ✅ | requires Python 3.11+ |
| 1.0.0 | ❌ | runs on Python 3.9/3.10, where several dependencies have no patched release — see *Why the floor is Python 3.11* below |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

- **[Open a private security advisory](https://github.com/Jatinkumar78/PacketIQ/security/advisories/new)**
  (in the repository: **Security → Advisories → Report a vulnerability**), or
- contact the maintainer through the profile at
  [github.com/Jatinkumar78](https://github.com/Jatinkumar78).

Include the affected file or endpoint, a short reproduction, and the impact you
observed. A first response can be expected within a few days. Please give a
reasonable window to ship a fix before any public disclosure.

Do not attach a capture taken from a production network. It carries real
addresses, hostnames and credentials from cleartext protocols. A synthetic
reproduction is enough: `python samples/generate_sample.py` builds one locally.

Reports about conduct rather than code go through the same private form, which is
the only private channel this project has; see
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). For questions that are not
vulnerabilities, [SUPPORT.md](SUPPORT.md) is the front door.

## Security posture

PacketIQ is a **local, single-user forensics tool**. Its design keeps the attack
surface small:

- **Loopback by default.** The web app binds `127.0.0.1`. Exposing it on a network
  (`--host 0.0.0.0`) is an explicit operator choice and prints a warning.
- **DNS-rebinding / CSRF guard.** A middleware validates the HTTP `Host` header
  against a loopback allow-list and rejects cross-origin state-changing requests.
  Reaching the app under any other name, such as a reverse proxy's hostname, means
  naming it in `PACKETIQ_ALLOWED_HOSTS` (comma separated); loopback stays allowed
  either way, so the variable only ever widens the list, never replaces it.
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
and `requirements.txt`, re-checked by **`pip-audit`** in CI on every push. Each floor
was verified against the advisory database *at the floor version itself*, not at
whatever a fresh resolve happens to pick, so a constrained or locked install gets the
same guarantee as a default one. Audited from a freshly built virtualenv on
**2026-11-15**: the runtime closure (73 packages) and the development closure (103
packages with every extra) each report **no known vulnerabilities**. The runtime
audit is **blocking**, so a finding fails the build. Resolved versions and findings
are recorded in
[docs/security_audit/pip_audit.txt](docs/security_audit/pip_audit.txt).

### Why the floor is Python 3.11

Not taste, and not "newer is better" — it is the oldest interpreter on which this
project's dependencies have a patched release to install. Measured the same day, by
resolving `requirements.txt` for each interpreter and auditing the result:

  | Floor | Advisories in the resolved closure | What blocks it |
  |---|---|---|
  | 3.9 | **111** across 7 packages | every fix requires ≥ 3.10; 3.9 is EOL since Oct 2025 |
  | 3.10 | **42**, all `pillow` via `reportlab` | `pillow` 13.0.0 requires ≥ 3.11; 3.10 is EOL since Oct 2026 |
  | **3.11** | **0** | — |

Carrying 3.9 meant declaring four dependencies twice — the patched floor for 3.10+,
and the newest release 3.9 could install, which was vulnerable with nowhere to
upgrade to — and printing the residual in an advisory CI step so it was at least
visible. 3.10 would have removed most of it and left 42, because the one package
that still lagged, `pillow`, is reached through `reportlab` and ships its fix only
for 3.11. At 3.11 there is no residual, no version-conditional dependency, and no
advisory-only exception: **every supported interpreter resolves a clean closure.**

`tests/test_project_metadata_sync.py` holds `requires-python`, the version
classifiers and the CI matrix to each other, and `tests/test_python311_compat.py`
parses every source file under the 3.11 grammar, so neither the promise nor the code
can drift past the floor unnoticed. The advisory `pip-audit` step on the oldest
supported interpreter is kept even though it is clean today: the day a dependency's
fix outruns the floor again, it shows up in a CI log rather than in a user's install.

The one long-standing dev-only residual is also gone: `pySigma` 2.1.0 replaced the
unmaintained `diskcache` 5.6.3 (PYSEC-2026-2447 / CVE-2025-69872, no upstream fix)
with the maintained `diskcache-community` fork. pySigma 2.x requires Python ≥ 3.11,
which the floor now guarantees, so that closure is clean on every supported
interpreter rather than only on the newest. Its CI step stays advisory — contributor
tooling is a wider, faster-moving closure than the one users install, and a new
advisory in it should not wedge the pipeline for everyone.

Static analysis uses **bandit**, run over `packetiq/` at its strictest setting
(`--severity-level low --confidence-level low`, so nothing is filtered out). As of
**2026-11-15** it reports **no issues at any severity** across 17,450 lines, which
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
