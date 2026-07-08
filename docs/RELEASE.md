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
