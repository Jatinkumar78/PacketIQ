"""
Guards the `requires-python = ">=3.9"` promise in pyproject.toml.

The CI matrix runs the suite on 3.9, but nothing checked that the *source* stays
3.9-compatible on the developer's machine — and mypy can no longer help: mypy 2.x
refuses to target anything below 3.10, so `python_version = "3.9"` was silently
ignored while it checked 3.10 semantics.

Two things break a 3.9 install in practice, and both are caught here:

  1. Grammar the 3.9 parser cannot read (`match` statements, PEP 695 generics).
  2. PEP 604 unions (`int | None`) in an annotation that Python *evaluates* at
     runtime. Under `from __future__ import annotations` every annotation is a
     lazy string and is therefore safe; without it, 3.9 raises TypeError on
     import — which no amount of test coverage on 3.12 would reveal.

PEP 585 builtin generics (`list[str]`, `dict[str, int]`) are deliberately NOT
flagged: those are valid at runtime on 3.9.
"""

import ast
from pathlib import Path

import pytest

MIN_VERSION = (3, 9)
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


def test_parses_under_python_39_grammar():
    offenders = []
    for path in ALL_FILES:
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path),
                      feature_version=MIN_VERSION)
        except SyntaxError as exc:
            offenders.append(f"{_rel(path)}:{exc.lineno}: {exc.msg}")
    if offenders:  # pragma: no cover - only on a real regression
        pytest.fail("not valid Python 3.9:\n  " + "\n  ".join(offenders))


def _runtime_pep604_unions(path: Path):
    """Yield (lineno, context) for PEP 604 unions Python 3.9 would evaluate."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    # With this future import every annotation stays an unevaluated string.
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            if any(alias.name == "annotations" for alias in node.names):
                return

    def unions_in(annotation):
        if annotation is None:
            return
        for sub in ast.walk(annotation):
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.BitOr):
                yield sub.lineno

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign):
            for lineno in unions_in(node.annotation):
                yield lineno, "variable annotation"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            every = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if args.vararg:
                every.append(args.vararg)
            if args.kwarg:
                every.append(args.kwarg)
            for arg in every:
                for lineno in unions_in(arg.annotation):
                    yield lineno, f"parameter of {node.name}()"
            for lineno in unions_in(node.returns):
                yield lineno, f"return type of {node.name}()"


def test_no_runtime_evaluated_pep604_unions():
    offenders = []
    for path in ALL_FILES:
        for lineno, where in _runtime_pep604_unions(path):
            offenders.append(f"{_rel(path)}:{lineno}: {where}")
    if offenders:  # pragma: no cover - only on a real regression
        pytest.fail(
            "`X | Y` in an annotation Python 3.9 evaluates at import time — add "
            "`from __future__ import annotations` or use typing.Optional/Union:\n  "
            + "\n  ".join(offenders)
        )
