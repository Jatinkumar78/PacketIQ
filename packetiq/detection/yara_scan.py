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
        # try compiling individually, skipping broken files
        good = {}
        try:
            import yara as _y
            for i, path in enumerate(files):
                try:
                    _y.compile(filepath=path)
                    good[f"ns{i}"] = path
                except Exception:  # nosec B112 - skip a rule file that fails to compile, keep the rest
                    continue
            return _y.compile(filepaths=good) if good else None
        except Exception:
            return None


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
