"""
Guards the `requires-python = ">=3.11"` promise in pyproject.toml.

The suite runs on 3.11 and 3.12 in CI, but a grammar or stdlib feature newer than
the floor is easy to add on a 3.12 developer machine and only discovered when the
3.11 leg runs — or, for a release cut between CI runs, by a user. Two different
gates cover the two halves of that risk:

  * mypy owns the *library* half. `python_version = "3.11"` in pyproject makes
    typeshed reject a 3.12-only stdlib symbol (`itertools.batched`,
    `typing.override`) used without a guard.
  * This file owns the *grammar* half, which mypy's config does not police as
    directly: PEP 695 type parameters (`class Box[T]`, `type Alias = ...`) parse
    fine on 3.12 and are a SyntaxError on 3.11.

The PEP 604 scanner this file used to carry is gone. It existed because Python 3.9
evaluates `int | None` in a runtime-reachable annotation and raises TypeError; from
3.10 that is valid, so the scan could only ever pass.
"""

import ast
from pathlib import Path

import pytest

MIN_VERSION = (3, 11)
ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIRS = ("packetiq", "tools", "tests")


def _source_files():
    for name in PACKAGE_DIRS:
        yield from sorted((ROOT / name).rglob("*.py"))


def _rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


ALL_FILES = list(_source_files())


def test_source_tree_is_not_empty():
    """A path typo here would make every other test vacuously pass."""
    assert len(ALL_FILES) > 50, f"only found {len(ALL_FILES)} python files under {PACKAGE_DIRS}"


def test_parses_under_the_oldest_supported_grammar():
    offenders = []
    for path in ALL_FILES:
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path),
                      feature_version=MIN_VERSION)
        except SyntaxError as exc:
            offenders.append(f"{_rel(path)}:{exc.lineno}: {exc.msg}")
    if offenders:  # pragma: no cover - only on a real regression
        pytest.fail(
            f"not valid Python {MIN_VERSION[0]}.{MIN_VERSION[1]}, which is the "
            "`requires-python` floor:\n  " + "\n  ".join(offenders))


def test_the_guard_is_pinned_to_the_declared_floor():
    """The check above is only worth anything if MIN_VERSION tracks pyproject.

    Raising `requires-python` and forgetting this constant leaves the gate
    testing an interpreter nobody supports any more — it would keep passing and
    stop meaning anything.
    """
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - impossible at the 3.11 floor
        pytest.skip("no tomllib")
    with open(ROOT / "pyproject.toml", "rb") as fh:
        requires = tomllib.load(fh)["project"]["requires-python"]
    declared = tuple(int(part) for part in requires.lstrip(">=").split("."))
    assert declared == MIN_VERSION, (
        f"pyproject declares {requires} but this guard checks "
        f"{MIN_VERSION[0]}.{MIN_VERSION[1]}")
