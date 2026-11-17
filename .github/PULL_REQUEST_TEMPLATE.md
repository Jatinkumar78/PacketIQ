<!--
Thanks for the patch. CONTRIBUTING.md has the full rules; this is the short list
a reviewer will check. Delete any section that does not apply.
-->

## What this changes

<!-- One or two sentences. What is different after this lands? -->

## Why

<!-- The problem, the bug, or the gap. Link an issue if there is one. -->

Closes #

## How it was verified

<!--
A measurement beats an assertion. Paste the command and its output rather than
saying it works.
-->

```
```

## Checklist

- [ ] `ruff check packetiq tools tests` is clean
- [ ] `mypy packetiq` is clean
- [ ] `pytest -q --cov=packetiq --cov-report=term-missing --cov-fail-under=100` passes, so coverage is still 100%
- [ ] New or changed lines are reached by a test; nothing is excluded from coverage, and code that turned out to be unreachable was deleted rather than marked
- [ ] No test opens a socket, reads a real capture device, or depends on this machine
- [ ] Every number added to a document is reproducible, and the command that produced it is stated
- [ ] `pyproject.toml` and `requirements.txt` still agree, if dependencies changed
- [ ] [CHANGELOG.md](../CHANGELOG.md) updated under `Unreleased`, if a user would notice
- [ ] Version not bumped (releases are cut by the maintainer)

## Detection changes only

- [ ] `python tools/validate.py --suite --min-recall 1.0 --min-precision 1.0` still passes
- [ ] A labelled fixture covers the new or changed detector
- [ ] The README detector table and the event-type mapping in `tests/test_project_metadata_sync.py` are updated
- [ ] Any threat-actor output still says TTP overlap rather than attribution

## YARA or fixture changes only

- [ ] No file contains a contiguous malware signature; `pytest -q tests/test_repo_hygiene.py` passes
