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
packetiq version                                   # → PacketIQ v1.0.0
packetiq analyze samples/demo_attack.pcap          # smoke test
pytest -q                                          # full suite
python tools/validate.py --suite --min-recall 1.0 --min-precision 1.0
```

CI (`.github/workflows/ci.yml`) runs the test suite, the deterministic guardrail
invariant, the detection regression gate, a throughput smoke test, and a `pip-audit`
dependency-CVE scan on Python 3.9–3.12.

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
no code change. On **Python 3.9** (still supported, but end-of-life since October
2025) each package installs at the newest 3.9-compatible version; a handful of
upstream advisories are only fixed in releases that require Python 3.10+, so **3.10+
is recommended** for the fullest patch set. The full analysis is in
[docs/reports/PacketIQ_Security_Audit_Report.pdf](reports/PacketIQ_Security_Audit_Report.pdf).

### Upgrading a local dev machine to Python 3.10+ (done on the reference env)

> The project's reference/dev environment has already been migrated to
> **Python 3.12.13** (standalone, uv-managed — no system change). On it the pinned
> floors resolve to fully-patched releases and `pip-audit` reports zero advisories
> in the runtime dependency set. The steps below are the exact, verified procedure
> to do the same on any machine.

No code change is needed — `requires-python` stays `>=3.9`, so 3.9 keeps working.
This just rebuilds your local `.venv` on a newer interpreter so `pip` resolves the
security floors to their fully-patched releases. CI already validates 3.9–3.12.

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
./.venv/bin/python -m pytest -q --cov=packetiq --cov-fail-under=65
./.venv/bin/python -m pip_audit          # advisories now resolve to patched releases
```

### Live-editing the source (editable install)

For an editable install so `packetiq/` edits take effect immediately **and** the
`packetiq` command still works from any directory, use compat mode:

```bash
./.venv/bin/pip install -e ".[dev,yara,geoip]" --config-settings editable_mode=compat
```

**macOS gotcha (important):** if your `.venv` directory carries the macOS
`UF_HIDDEN` flag (some tools set it on dot-directories), pip writes the editable
`.pth` file hidden too, and **CPython's `site.py` deliberately skips hidden `.pth`
files** — so the editable install silently does nothing and `import packetiq`
fails outside the repo. Clear the flag once and the editable install works
normally (it stays cleared across reinstalls):

```bash
chflags -R nohidden .venv          # macOS only; harmless to re-run
python -c "import packetiq; print(packetiq.__file__)"   # → …/PacketIQ/packetiq/__init__.py
```

`quickstart.sh` clears this flag automatically on macOS.

> **Zero-config alternative:** running from the repo root always picks up live
> source edits (the source tree shadows the install), with no `.pth` involved —
> e.g. `./.venv/bin/python -m packetiq.cli analyze …`. Use this if you ever hit
> the hidden-`.pth` issue and don't want to touch flags.

The `PacketIQ.command` / `quickstart.sh` launchers already prefer the newest
installed CI-tested interpreter, so once 3.10+ is on `PATH` a fresh setup uses it
automatically.
