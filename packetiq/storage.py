"""
Lightweight analysis history — persists a summary row per analysis in a local
SQLite database so past runs can be listed and compared.

DB location: $PACKETIQ_DB, else ~/.packetiq/history.db
Recording is best-effort and never raises into the analysis path.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _db_path() -> Path:
    env = os.environ.get("PACKETIQ_DB")
    if env:
        return Path(env)
    return Path.home() / ".packetiq" / "history.db"


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(Exception):
        os.chmod(path.parent, 0o700)   # history may reference sensitive captures
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at  TEXT NOT NULL,
            filename     TEXT NOT NULL,
            packets      INTEGER,
            risk_score   INTEGER,
            risk_tier    TEXT,
            event_count  INTEGER,
            chain_count  INTEGER,
            top_attacker TEXT
        )
        """
    )
    conn.commit()
    return conn


def record(filename: str, packets: int, risk_score: int, risk_tier: str,
           event_count: int, chain_count: int, top_attacker: str = "") -> bool:
    """Insert one analysis summary. Returns True on success (best-effort)."""
    try:
        conn = _connect()
        conn.execute(
            "INSERT INTO analyses (analyzed_at, filename, packets, risk_score, "
            "risk_tier, event_count, chain_count, top_attacker) VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), filename, packets, risk_score,
             risk_tier, event_count, chain_count, top_attacker),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def recent(limit: int = 20) -> list[dict]:
    """Return the most recent analyses as dicts (newest first)."""
    try:
        conn = _connect()
        conn.row_factory = sqlite3.Row
        cur = conn.execute(
            "SELECT * FROM analyses ORDER BY id DESC LIMIT ?", (int(limit),)
        )
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def clear() -> int:
    """Delete all recorded analyses. Returns the number of rows removed."""
    try:
        conn = _connect()
        cur = conn.execute("SELECT COUNT(*) FROM analyses")
        n = cur.fetchone()[0]
        conn.execute("DELETE FROM analyses")
        conn.commit()
        conn.close()
        return int(n)
    except Exception:
        return 0


def delete(analysis_id: int) -> bool:
    """Delete a single analysis row by id."""
    try:
        conn = _connect()
        conn.execute("DELETE FROM analyses WHERE id = ?", (int(analysis_id),))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False
