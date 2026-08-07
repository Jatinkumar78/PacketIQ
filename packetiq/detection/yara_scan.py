"""
YARA scanning over reassembled traffic / carved files.

Compiles YARA rules from:
  1. $PACKETIQ_YARA_RULES  (a .yar/.yara file or a directory of them)
  2. packetiq/detection/data/yara_rules/*.yar  (bundled examples)

Requires the `yara-python` package; if it is not installed (or no rules
compile), scanning is a no-op — never a fabricated match.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

_BUNDLED_DIR = Path(__file__).parent / "data" / "yara_rules"


def available() -> bool:
    return _rules() is not None


def _rule_files() -> list[str]:
    files: list[str] = []
    env = os.environ.get("PACKETIQ_YARA_RULES")
    if env:
        p = Path(env)
        if p.is_file():
            files.append(str(p))
        elif p.is_dir():
            files += [str(x) for x in sorted(p.glob("*.yar")) + sorted(p.glob("*.yara"))]
    if _BUNDLED_DIR.is_dir():
        files += [str(x) for x in sorted(_BUNDLED_DIR.glob("*.yar")) + sorted(_BUNDLED_DIR.glob("*.yara"))]
    return files


def _compile_valid_only(yara_mod, files: list):
    """Compile just the rule files that are individually valid.

    One malformed rule makes a whole-set compile fail, which would silently cost
    us every other rule. Retesting file by file keeps the good ones loaded.
    """
    good = {}
    for i, path in enumerate(files):
        try:
            yara_mod.compile(filepath=path)
        except Exception:  # nosec B112 # a broken rule file is skipped; the rest still load
            continue
        good[f"ns{i}"] = path
    if not good:
        return None
    try:
        return yara_mod.compile(filepaths=good)
    except Exception:
        return None


@lru_cache(maxsize=1)
def _rules():
    try:
        import yara
    except Exception:
        return None
    files = _rule_files()
    if not files:
        return None
    namespaces = {f"ns{i}": path for i, path in enumerate(files)}
    try:
        return yara.compile(filepaths=namespaces)
    except Exception:
        return _compile_valid_only(yara, files)


def scan_bytes(data: bytes) -> list[dict]:
    """Return a list of {rule, severity, tags, description} for matches in `data`."""
    rules = _rules()
    if not rules or not data:
        return []
    try:
        matches = rules.match(data=bytes(data), timeout=10)
    except Exception:
        return []
    out = []
    for m in matches:
        meta = getattr(m, "meta", {}) or {}
        out.append({
            "rule": m.rule,
            "severity": str(meta.get("severity", "high")).upper(),
            "description": meta.get("description", m.rule),
            "tags": list(getattr(m, "tags", []) or []),
        })
    return out
