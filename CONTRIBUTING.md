# Contributing to PacketIQ

Thanks for considering it. PacketIQ is a forensics tool, so a patch here can
change what an analyst believes about a real capture. That shapes most of the
rules below: they exist to keep every claim the tool makes traceable to
evidence.

Read the [Code of Conduct](CODE_OF_CONDUCT.md) first. It is short, and the two
clauses specific to this project (authorised defensive use, and no fabricated
results) are enforced in review.

## Scope

PacketIQ is **defensive**. Welcome: detectors, parsers, threat-intelligence
sources, SIEM and export backends, accuracy work, documentation, tests. Out of
scope and closed on sight: offensive tooling, detection evasion, anything
intended to analyse or act against a network you are not authorised to test.

## Getting set up

Python **3.11 or newer** is required. The floor is not cosmetic: on 3.9 and 3.10
this project's dependency closure resolves to releases with published advisories
and nothing newer to install. [SECURITY.md](SECURITY.md) records the measurement.

```bash
git clone https://github.com/Jatinkumar78/PacketIQ.git
cd PacketIQ
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,yara,geoip]"
```

Build a capture to work against, which needs no download:

```bash
python samples/generate_sample.py
packetiq analyze samples/demo_attack.pcap --full
```

## The gates

CI runs exactly these, on Linux, macOS and Windows, across Python 3.11 and 3.12.
Run them locally before opening a pull request and there will be no surprises.

| What | Command |
|---|---|
| Lint | `ruff check packetiq tools tests` |
| Types | `mypy packetiq` |
| Tests and the coverage floor | `pytest -q --cov=packetiq --cov-report=term-missing --cov-fail-under=100` |
| Grounding invariant | `pytest -q tests/test_grounding_guard.py tests/test_grounding.py` |
| Detection regression | `python tools/validate.py --suite --min-recall 1.0 --min-precision 1.0` |
| Throughput smoke test | `python tools/benchmark.py --demo --packets 20000` |
| Static security scan | `bandit -r packetiq --severity-level low --confidence-level low` |
| Dependency audit | `pip-audit` |

The coverage floor is enforced on the Linux legs only, deliberately: coverage of
the platform-specific branches differs per operating system, and one number
measured three ways would be three different claims.

## House rules that review will hold you to

**Coverage is 100% and the floor is real.** Every statement in `packetiq/` is
executed by the suite. If you add a line, add the test that reaches it.

**Unreachable code is deleted, not excluded.** When a branch turns out to be
impossible, remove it. The only permitted exclusions are `if TYPE_CHECKING`,
`...` protocol stubs, `raise NotImplementedError` and `__main__` guards. A
`# pragma: no cover` on real logic will be asked about.

**Tests never touch the network or the host.** Seven autouse fixtures in
`tests/conftest.py` enforce this, and `tests/test_harness_guards.py` asserts each
one still holds: a test gets its own history database, cannot open a socket,
cannot open a real capture device, never sees the machine's own interface list,
never resolves a link-layer address on the wire, is told the machine has one
fixed amount of RAM, and renders every table at one fixed width. Without those
guards a developer's workstation quietly flatters the coverage number. Drive
host-specific and platform-specific paths from a fixture.

**No fabricated data, anywhere.** Threat-intelligence indicators are verbatim
snapshots of public feeds. Benchmark and accuracy figures are measurements you
can reproduce, with the command that produced them. If a number in a document
cannot be regenerated, it does not belong in the document. Where a measurement
is unflattering, state it: the real-world precision is reported as 90%, and the
single false positive is documented rather than suppressed.

**Threat-actor output is TTP overlap, never attribution.** Any user-visible
string in that area must say so. This is not a style preference; it is the
difference between an investigative lead and a false accusation.

**Claims in the documentation are gated by tests.** `tests/test_project_metadata_sync.py`
holds the README's detection-type count, detector-module count, harness-guard
count and indicator count to what the code actually does, and
`tests/test_docs_and_community_health.py` holds every relative link in the
Markdown files to a file that exists. If you change a number in the README,
expect a test to check it.

**`pyproject.toml` and `requirements.txt` stay in lockstep,** and dependency
floors only go up. Each floor is a patched release verified against the advisory
database at the floor version itself. Do not lower one.

**Name tests as sentences, and say what regression they prevent.** The suite
reads `test_the_readme_detection_type_count_is_the_number_the_code_emits`, not
`test_readme_1`. When a test exists because something broke, the docstring tells
that story, so the next person does not undo the fix.

## Adding a detector

1. Add a member to `EventType` in `packetiq/detection/models.py`. There are 18
   today.
2. Write the module in `packetiq/detection/`, emitting `DetectionEvent` objects
   with `event_type=EventType.YOUR_TYPE`. Every event carries severity,
   confidence, the evidence behind it, and a MITRE technique.
3. Wire it into the import block and the run sequence in
   `packetiq/detection/engine.py`.
4. Make the thresholds configurable in `packetiq/config.py` and document them in
   `packetiq.toml.example`. Analysts tune detectors; hard-coded constants stop
   them.
5. Add a row to the detector table in the README, and add your event type to the
   name mapping in `tests/test_project_metadata_sync.py`. Two tests fail until
   you do, on purpose: a detector nobody documents is a feature nobody knows
   they have.
6. Add a labelled fixture to the synthetic validation suite so the regression
   gate covers it, and keep `--min-recall 1.0 --min-precision 1.0` passing.
7. Explain the finding. `packetiq/triage.py` supplies the what, why, evidence and
   recommended action that the web app shows under "Why was this flagged?". A
   detection a user cannot interrogate is a black box.

## Adding or changing a YARA rule

One extra constraint applies here. **No file in this repository may contain a
contiguous malware signature.** Desktop anti-virus scans source archives, and an
earlier release was deleted wholesale from a user's machine because Microsoft
Defender matched a webshell string inside a Python test fixture that is never
executed.

So: write the EICAR pattern as bytes, keep webshell patterns as fragments with no
PHP tag, and assemble test fixtures at runtime. `tests/test_repo_hygiene.py`
scans the tracked file set on every CI run and fails the build if a literal
reappears. Detection is unaffected, since the same rules match the same bytes,
and `tests/test_yara.py` proves it against the published EICAR digest.

## Pull requests

Branch from `main`, keep one logical change per pull request, and make the
description say what changed and how you verified it. A measurement beats an
assertion: paste the command and its output.

```bash
git checkout -b feature/my-detector
# write code and tests
ruff check packetiq tools tests && mypy packetiq && pytest -q
```

Update [CHANGELOG.md](CHANGELOG.md) under an `Unreleased` heading for anything a
user would notice. The format follows [Keep a Changelog](https://keepachangelog.com/).

Do not bump the version in a pull request. The version is written in one place,
`packetiq/__init__.py`, and `pyproject.toml` is held to it by a test; releases
are cut by the maintainer following [docs/RELEASE.md](docs/RELEASE.md).

## Reporting a vulnerability

Not here. Follow [SECURITY.md](SECURITY.md), which asks for a private advisory
rather than a public issue.

## Good places to start

* New detectors in `packetiq/detection/`.
* YARA rules in `packetiq/detection/data/yara_rules/`, subject to the constraint
  above.
* Threat-actor TTP profiles in `packetiq/attribution/actors.py`.
* Additional SIEM backends for the SIGMA export.
* The open items in the README roadmap, where the GeoIP map in the single-page
  app is the most self-contained.
