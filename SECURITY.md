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
  an early size-cap abort (`PACKETIQ_MAX_UPLOAD_MB`, default 2 GB), so a large upload
  cannot exhaust memory. Filenames are basename-sanitised; server-generated UUIDs,
  not user input, build file paths.
- **Owner-only data directories.** The upload directory and history store are created
  `0700`.
- **No dangerous sinks.** No `eval`/`exec`/`pickle`/`os.system`/`shell=True`. The one
  privileged path (macOS/Linux capture setup) validates `$USER` against a strict
  charset before building a script and only ever uses list-form `subprocess` calls.
- **Parameterised SQL** throughout the history layer; **HTML-escaped** rendering in
  the web app and reports; **timeouts** on every outbound request.
- **Secrets stay local.** `.env` is git-ignored; API keys are read at runtime and
  never logged. The interactive docs (`/docs`, `/redoc`) are disabled.
- **Offline-capable, no telemetry.** Front-end libraries are vendored. Outbound
  traffic only goes to the threat-intel feeds (NVD, CISA KEV, abuse.ch) and to the
  AI/alert providers you configure — nothing else.

## Dependency security

Runtime dependencies are pinned to **security-patched floors** in `pyproject.toml`
and `requirements.txt`, re-checked by **`pip-audit`** in CI on every push. The
**reference/dev environment runs on Python 3.12.13**, where those floors resolve to
fully-patched releases and `pip-audit` reports **zero advisories in the runtime
dependency set** — that audit is **blocking**, so a finding fails the build. One
dev-only transitive (`diskcache`, via the `dev`-extra `pySigma`) has no upstream
fix and is never installed by `pip install packetiq`; its audit is advisory.

**Python 3.9 is a different answer, and CI now states it rather than implying it.**
3.9 has been end-of-life since October 2025, and several dependencies have moved
past it: the current `pillow`, `python-dotenv` and `python-multipart` releases all
require Python ≥ 3.10. A 3.9 install therefore resolves to the newest
3.9-compatible version of each, and some of those carry published advisories with
**no release to upgrade to**. CI runs a second, **advisory-only** `pip-audit` on
3.9 so that residual is visible in every run's log instead of being a sentence
here that nobody re-checks. **Python 3.10 or newer is recommended** for the
fullest patch set; 3.9 remains supported and tested, with that caveat stated.

Static analysis uses **bandit**.

## Audit

A full white-box security review (manual code review + bandit + pip-audit + git
secret scan + live exploitation) is documented in
[docs/reports/PacketIQ_Security_Audit_Report.pdf](docs/reports/PacketIQ_Security_Audit_Report.pdf).
The reproducible scripts and raw tool output live in
[docs/security_audit/](docs/security_audit/).
