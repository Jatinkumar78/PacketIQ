# Releasing PacketIQ

PacketIQ is versioned **1.0.0** and packaged with modern **PEP 621** metadata in
`pyproject.toml` (there is no `setup.py`). Building produces a standard wheel and
sdist that install with `pip` anywhere.

## Build the artifacts

```bash
python -m pip install build
python -m build                       # writes dist/packetiq-1.0.0-py3-none-any.whl + .tar.gz
```

The wheel bundles all runtime data (threat-intel feeds, YARA rules, JA3 blocklist,
web templates) via `[tool.setuptools.package-data]`, and installs the `packetiq`
console command (`[project.scripts]`). Verified by installing the wheel into a clean
virtualenv and running `packetiq analyze` end-to-end.

## Verify before releasing

```bash
pip install dist/packetiq-1.0.0-py3-none-any.whl   # into a fresh venv
packetiq --version                                 # → PacketIQ 1.0.0
packetiq analyze samples/demo_attack.pcap          # smoke test
pytest -q                                          # full suite
python tools/validate.py --suite --min-recall 1.0 --min-precision 1.0
```

### Result of that checklist for 1.0.0 (2026-08-11)

Recorded so the next person can tell a regression from the expected baseline, on
macOS 26.6.1 arm64 / CPython 3.12.13:

| Check | Result |
|---|---|
| `ruff check packetiq tools tests` | clean |
| `mypy packetiq` | clean, 83 source files |
| `pytest` with `--cov-fail-under=100` | **1,802 passed**, 100.00% of 9,971 statements |
| `bandit -r packetiq --severity-level low --confidence-level low` | no issues at any severity, 17,056 lines |
| `pip-audit` (runtime closure, fresh venv) | no known vulnerabilities |
| `pip-audit` (dev closure, fresh venv) | 1 advisory — `diskcache`, unfixable upstream, advisory-only |
| Guardrail invariant tests | 26 passed (0 ungrounded entities) |
| `validate.py --suite` regression gate | GATE PASSED (100% recall, 100% precision) |
| `benchmark.py --demo --packets 20000` | 4,020 pkts/s, exit 0 |
| `analyze samples/demo_attack.pcap` | 39 events, 5 chains, risk 100/100 |

Audit dependencies in a **freshly built** virtualenv, never in a long-lived
developer venv — the latter measures the developer's machine, not what users
install, and will over-report. See
[docs/security_audit/pip_audit.txt](security_audit/pip_audit.txt).

## What CI actually gates

`.github/workflows/ci.yml` has two jobs. The **test** job runs on a matrix of
Python 3.9, 3.10, 3.11 and 3.12 on Linux, plus 3.12 on macOS and 3.12 on Windows —
six legs, because the parts that differ between platforms (capture privileges,
interface enumeration, path handling, console encoding) are exactly the parts that
break. Each leg runs, in order:

| Step | Blocking? |
|---|---|
| `packetiq --help` + `import packetiq` from an unrelated directory | yes |
| `ruff check packetiq tools tests` | yes |
| `mypy packetiq` | yes |
| `pytest` — **with `--cov-fail-under=100` on the Linux legs only** | yes |
| Guardrail invariant (`test_grounding_guard.py`, `test_grounding.py`) | yes |
| Detection regression gate (`tools/validate.py --suite`, 100% recall + precision) | yes |
| Throughput benchmark smoke (`tools/benchmark.py --demo`) | yes |

The coverage gate is deliberately Linux-only: coverage of the platform branches is
necessarily different on each OS, so one "100%" measured three ways would be three
different claims. The macOS and Windows legs prove the suite *passes* there.

The **security** job runs four scans, and their blocking status is not uniform —
see *Dependency security* below for why:

| Scan | Interpreter | Blocking? |
|---|---|---|
| `pip-audit` on `pip install -e .` (what users get) | 3.12 | **yes** |
| `pip-audit` on `pip install ".[dev]"` (contributor tooling) | 3.12 | advisory |
| `bandit -r packetiq` at low severity + low confidence | 3.12 | **yes** |
| `pip-audit` on `pip install .` (oldest supported interpreter) | 3.9 | advisory |

## Cut the release (repository owner)

These steps touch the outside world and are intentionally left to you:

```bash
git tag -a v1.0.0 -m "PacketIQ 1.0.0"
git push origin main --tags
gh release create v1.0.0 dist/* \
  --title "PacketIQ 1.0.0" \
  --notes-file CHANGELOG.md
```

Optional PyPI publish (requires a PyPI account + API token):

```bash
python -m pip install twine
twine upload dist/*
# → pip install packetiq
```

## Dependency security

Runtime pins in `pyproject.toml` / `requirements.txt` sit at **verified,
security-patched floors that exist on PyPI**:

| Package | Floor | Reason |
|---|---|---|
| `python-multipart` | `>=0.0.18` | CVE-2024-53981 (parser DoS) |
| `requests` | `>=2.32.4` | CVE-2024-47081 (.netrc credential leak) |
| `urllib3` | `>=2.6.0` | decompression-bomb DoS fix |
| `cryptography` | `>=44.0.1` | GHSA-537c-gmf6-5ccf and prior |

Do not lower these. Re-check with `pip-audit` (run automatically in CI).

On **Python 3.10+** these floors resolve to the fully-patched upstream releases with
no code change — the 3.12 audit in CI is clean, which is why it is allowed to block.

On **Python 3.9** (still supported, but end-of-life since October 2025) each package
installs at the newest 3.9-compatible version, and three of them carry published
advisories whose *only* fixes ship in releases that require 3.10+:

| Package | Resolves to on 3.9 | Resolves to on 3.12 |
|---|---|---|
| `pillow` | 11.3.0 (PYSEC-2026-3493) | 12.3.0 — clean |
| `python-dotenv` | 1.2.1 (PYSEC-2026-2270) | 1.2.2 — clean |
| `python-multipart` | 0.0.20 (six advisories) | 0.0.32 — clean |

There is nothing to bump: on 3.9 those *are* the newest installable versions. Raising
the floors would break installability on 3.9, and raising `requires-python` would drop
3.9 support, so the residual is reported rather than papered over — the 3.9 `pip-audit`
step is advisory and prints it in every CI log. **Run on 3.10+ for the fullest patch
set.** The full analysis is in
[docs/reports/PacketIQ_Security_Audit_Report.pdf](reports/PacketIQ_Security_Audit_Report.pdf)
and the policy is stated in [SECURITY.md](../SECURITY.md).

### Upgrading a local dev machine to Python 3.10+ (done on the reference env)

> The project's reference/dev environment has already been migrated to
> **Python 3.12.13** (standalone, uv-managed — no system change). On it the pinned
> floors resolve to fully-patched releases and `pip-audit` reports zero advisories
> in the runtime dependency set. The steps below are the exact, verified procedure
> to do the same on any machine.

No code change is needed — `requires-python` stays `>=3.9`, so 3.9 keeps working.
This just rebuilds your local `.venv` on a newer interpreter so `pip` resolves the
security floors to their fully-patched releases. CI already validates 3.9–3.12 on
Linux, plus 3.12 on macOS and Windows.

```bash
# 1. Install a newer Python (macOS — pick one):
#      • Official installer:  https://www.python.org/downloads/  (python.org .pkg)
#      • Homebrew:            brew install python@3.12
# 2. Rebuild the venv on it (the launchers auto-prefer python3.12→3.10 when present):
cd /path/to/PacketIQ
rm -rf .venv
python3.12 -m venv .venv          # or: ./quickstart.sh  (auto-selects the newest)
./.venv/bin/python -m pip install -U pip
# Regular (non-editable) install so the `packetiq` command works from any directory.
./.venv/bin/pip install ".[dev,yara,geoip]"
# 3. Verify — everything should stay green:
./.venv/bin/python -m pytest -q --cov=packetiq --cov-fail-under=100
./.venv/bin/python -m pip_audit          # advisories now resolve to patched releases
```

### Live-editing the source (editable install)

For an editable install so `packetiq/` edits take effect immediately **and** the
`packetiq` command still works from any directory, use compat mode:

```bash
./.venv/bin/pip install -e ".[dev,yara,geoip]" --config-settings editable_mode=compat
```

**macOS gotcha (important) — and the permanent fix:** if your `.venv` directory
carries the macOS `UF_HIDDEN` flag (some background services — Time Machine, a
cloud-sync client, Spotlight — periodically apply it to dot-directories and their
contents), pip's editable `.pth` file gets hidden too, and **CPython's `site.py`
deliberately skips hidden `.pth` files** — so the editable install silently stops
working and `import packetiq` fails outside the repo. `chflags -R nohidden .venv`
clears it, but the flag comes back, so that alone is only a temporary patch.

The **permanent fix** is a `sitecustomize.py` in the venv's `site-packages`.
Python's import machinery does **not** skip hidden modules (only `site.py`'s
`.pth` handling does), so a `sitecustomize.py` runs on every interpreter start
even when it (and the `.pth`) are hidden. It re-adds the repo root to `sys.path`,
which keeps the editable install — and live source edits — working from any
directory regardless of the flag:

```python
# .venv/lib/pythonX.Y/site-packages/sitecustomize.py
import os, sys
_here = os.path.dirname(os.path.abspath(__file__))
_repo = os.path.abspath(os.path.join(_here, "..", "..", "..", ".."))
if os.path.isdir(os.path.join(_repo, "packetiq")) and _repo not in sys.path:
    sys.path.append(_repo)
```

`quickstart.sh` writes this file automatically on macOS, so a fresh setup is
robust with no babysitting. Verify with:

```bash
cd /tmp && /path/to/PacketIQ/.venv/bin/packetiq version   # resolves from anywhere
```

(Two forms, both valid: `packetiq version` prints the banner and the full build
block, while `packetiq --version` / `-V` prints the bare `PacketIQ 1.0.0` line that
scripts and packagers expect. Both read `packetiq.__version__`, so neither can
drift from the packaged metadata.)

> **Zero-config alternative:** running from the repo root always picks up live
> source edits (the source tree shadows the install), with no `.pth` involved —
> e.g. `./.venv/bin/python -m packetiq.cli analyze …`. The `quickstart.sh` and
> `PacketIQ.command` launchers already run PacketIQ this way (`python -m
> packetiq.cli`), so the app itself is unaffected by the flag either way. A plain
> non-editable `pip install .` is also fully immune (the package is copied into
> site-packages, so there is no `.pth`), at the cost of re-running it after edits.

The `PacketIQ.command` / `quickstart.sh` launchers already prefer the newest
installed CI-tested interpreter, so once 3.10+ is on `PATH` a fresh setup uses it
automatically.
