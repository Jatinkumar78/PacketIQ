# Releasing PacketIQ

PacketIQ is versioned **1.1.0** and packaged with modern **PEP 621** metadata in
`pyproject.toml` (there is no `setup.py`). Building produces a standard wheel and
sdist that install with `pip` anywhere.

## Build the artifacts

```bash
python -m pip install build
python -m build                       # writes dist/packetiq-1.1.0-py3-none-any.whl + .tar.gz
```

The wheel bundles all runtime data (threat-intel feeds, YARA rules, JA3 blocklist,
web templates) via `[tool.setuptools.package-data]`, and installs the `packetiq`
console command (`[project.scripts]`). Verified by installing the wheel into a clean
virtualenv and running `packetiq analyze` end-to-end.

## Verify before releasing

```bash
pip install dist/packetiq-1.1.0-py3-none-any.whl   # into a fresh venv
packetiq --version                                 # → PacketIQ 1.1.0
packetiq analyze samples/demo_attack.pcap          # smoke test
pytest -q                                          # full suite
python tools/validate.py --suite --min-recall 1.0 --min-precision 1.0
```

### Re-sync the two drifting figures in the README

The README states a test count and a statement count. Both move with every
commit, so neither can be gated by a test the way the detection-type count, the
detector-module count, the harness-guard count and the indicator floor are
(`tests/test_project_metadata_sync.py`). They drifted silently once already —
the README claimed 8,398 indicators while the feeds held 7,855, and that one
*was* gated, which is how it was caught. The ungated pair needs a human here:

```bash
pytest -q | tail -1                                           # → N passed
pytest -q --cov=packetiq --cov-report=term | grep '^TOTAL'    # → statements
```

Update the badge and every figure in the README that quotes either number
(`grep -n 'tests\|statements' README.md`). Leave the dated tables in this file
and the per-release entries in `CHANGELOG.md` alone: they record what was
measured on the day, and rewriting them would turn a baseline into a guess.


### Result of that checklist for 1.1.0 (2026-11-15)

The current baseline, on macOS 26.6.1 arm64 / CPython 3.12.13. The test and
coverage row was re-measured on 2026-11-17, after the documentation gates were
added; every other row is the 2026-11-15 measurement and was re-confirmed then
except the two `pip-audit` closures, which were not re-run:

| Check | Result |
|---|---|
| `ruff check packetiq tools tests` | clean (now at `target-version = "py311"`) |
| `mypy packetiq` | clean, 90 source files, `python_version = "3.11"` |
| `pytest` with `--cov-fail-under=100` | **2,450 passed**, 100.00% of 13,477 statements |
| `bandit -r packetiq --severity-level low --confidence-level low` | no issues at any severity, 17,450 lines |
| `pip-audit` (runtime closure, fresh venv, 73 packages) | no known vulnerabilities |
| `pip-audit` (dev closure, fresh venv, 103 packages) | no known vulnerabilities — the diskcache residual is gone |
| `pip-audit` (oldest supported interpreter, 3.11) | no known vulnerabilities |
| Guardrail invariant tests | 26 passed (0 ungrounded entities) |
| `validate.py --suite` regression gate | GATE PASSED (100% recall, 100% precision) |
| `benchmark.py --demo --packets 20000` | 4,855 pkts/s, exit 0 |
| `analyze samples/demo_attack.pcap` | 39 events, 5 chains, risk 100/100 — identical to 1.0.0 |

The detection figures and the 12-capture throughput aggregate were **not** re-run
for 1.1.0: no detector changed, and quoting a number that was not measured on the
day would make this table the guess it exists to prevent.

### Result of that checklist for 1.0.0 (2026-08-11)

Recorded so the next person can tell a regression from the expected baseline, on
macOS 26.6.1 arm64 / CPython 3.12.13:

| Check | Result |
|---|---|
| `ruff check packetiq tools tests` | clean |
| `mypy packetiq` | clean, 98 source files |
| `pytest` with `--cov-fail-under=100` | **1,846 passed**, 100.00% of 10,050 statements |
| `bandit -r packetiq --severity-level low --confidence-level low` | no issues at any severity, 17,196 lines |
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
Python 3.11 and 3.12 on Linux, plus 3.12 on macOS and 3.12 on Windows — four
legs, because the parts that differ between platforms (capture privileges,
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
| `pip-audit` on `pip install .` (oldest supported interpreter) | 3.11 | advisory |

## Bump the version in both places

The version lives in `packetiq/__init__.py`, and `pyproject.toml` is held to it
by `tests/test_project_metadata_sync.py`. Since 1.1.0 there is a third file:

| File | Field | Gated by |
|---|---|---|
| `packetiq/__init__.py` | `__version__` | the source of truth |
| `pyproject.toml` | `version` | `test_the_packaged_version_matches_the_one_the_code_reports` |
| `CITATION.cff` | `version` and `date-released` | `test_the_citation_version_is_the_version_the_package_reports` and `test_the_citation_release_date_matches_the_newest_changelog_entry` |

`CITATION.cff` is what GitHub renders behind the **Cite this repository** button,
so a stale version there becomes a wrong citation in somebody else's
bibliography. Its `date-released` must equal the date on the newest `## [x.y.z]`
heading in `CHANGELOG.md`; the suite fails if the two disagree, which is the only
reason this is a checklist item rather than a thing to remember.

## Cut the release (repository owner)

These steps touch the outside world and are intentionally left to you:

```bash
git tag -a v1.1.0 -m "PacketIQ 1.1.0"
git push origin main --tags
gh release create v1.1.0 dist/* \
  --title "PacketIQ 1.1.0" \
  --notes-file CHANGELOG.md
```

Optional PyPI publish (requires a PyPI account + API token):

```bash
python -m pip install twine
twine upload dist/*
# → pip install packetiq
```

### After the first release exists

Two README badges are deliberately static today because the live versions would
render an error on a repository that has never published a release. Once
`gh release create` has run at least once, either can be switched:

```
https://img.shields.io/github/v/release/Jatinkumar78/PacketIQ?style=for-the-badge
https://img.shields.io/pypi/v/packetiq?style=for-the-badge
```

`tests/test_docs_and_community_health.py::test_no_badge_claims_a_github_release_that_does_not_exist`
blocks the first of those on purpose, so swapping it in means deleting that test
and recording why. Check what the badge actually renders before trusting it: on a
repository with no releases it reads "no releases or repo not found", and shields
returns HTTP 200 either way.

## Dependency security

Runtime pins in `pyproject.toml` / `requirements.txt` sit at **verified,
security-patched floors that exist on PyPI**:

| Package | Floor | Reason |
|---|---|---|
| `scapy` | `>=2.7.0` | GHSA-cq46-m9x9-j8w2 — 2.5.0 and 2.6.x affected |
| `cryptography` | `>=50.0.0` | 44.0.1 itself carries 10 advisories; 50.0.0 is clean |
| `urllib3` | `>=2.8.0` | PYSEC-2026-4175 / 4176 / 4177 and prior |
| `requests` | `>=2.33.0` | GHSA-gc5v-m9x4-r6x2 / PYSEC-2026-2275 |
| `python-dotenv` | `>=1.2.2` | GHSA-mf9w-mj56-hr94 / PYSEC-2026-2270 |
| `python-multipart` | `>=0.0.31` | 12 advisories through 0.0.30 |

Do not lower these. Re-check with `pip-audit` (run automatically in CI).

Every floor above is a patched release, and each was checked against the advisory
database *at the floor version itself* rather than at whatever a fresh resolve
happens to pick — otherwise a constrained or locked install gets a guarantee the
default install only appears to have.

Four of these used to be declared twice, split on `python_version`, because their
patched release needs a Python newer than 3.9. That split is gone, and so is 3.9.

**The Python floor is 3.11, and that is a dependency decision.** Resolving
`requirements.txt` for each interpreter on 2026-11-15 and auditing the result:

| Floor | Advisories in the resolved closure | What blocks it |
|---|---|---|
| 3.9 | **111** across 7 packages | every fix requires ≥ 3.10; EOL since Oct 2025 |
| 3.10 | **42**, all `pillow` via `reportlab` | `pillow` 13.0.0 requires ≥ 3.11; EOL since Oct 2026 |
| **3.11** | **0** | — |

3.10 is the interesting row: it clears six of the seven packages that were stuck on
3.9 and still leaves 42 advisories, because `reportlab` pulls `pillow` and the
`pillow` release that fixes them ships only for 3.11+. Stopping at 3.10 would have
meant carrying that quietly. At 3.11 the closure is clean, nothing is
version-conditional, and the advisory-only CI step has nothing left to report —
it is kept anyway, so the next time a fix outruns the floor it lands in a CI log
rather than in a user's install. The full analysis is in
[docs/reports/PacketIQ_Security_Audit_Report.pdf](reports/PacketIQ_Security_Audit_Report.pdf)
and the policy is stated in [SECURITY.md](../SECURITY.md).

### Upgrading a local dev machine to Python 3.11+ (done on the reference env)

> The project's reference/dev environment has already been migrated to
> **Python 3.12.13** (standalone, uv-managed — no system change). On it the pinned
> floors resolve to fully-patched releases and `pip-audit` reports zero advisories
> in the runtime dependency set. The steps below are the exact, verified procedure
> to do the same on any machine.

`requires-python` is `>=3.11`, so a `.venv` built on anything older will refuse to
install. This rebuilds yours on a supported interpreter. CI validates 3.11 and 3.12
on Linux, plus 3.12 on macOS and Windows.

```bash
# 1. Install a newer Python (macOS — pick one):
#      • Official installer:  https://www.python.org/downloads/  (python.org .pkg)
#      • Homebrew:            brew install python@3.12
# 2. Rebuild the venv on it (the launchers pick the first interpreter that meets the floor):
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
block, while `packetiq --version` / `-V` prints the bare `PacketIQ 1.1.0` line that
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
installed CI-tested interpreter, so once 3.11+ is on `PATH` a fresh setup uses it
automatically.
