"""
Central configuration — lets analysts tune detector thresholds per environment
without editing code.

Resolution order (first found wins):
  1. $PACKETIQ_CONFIG                (explicit path)
  2. ./packetiq.toml                 (current working directory)
  3. built-in defaults below

Reading TOML uses the stdlib `tomllib` (Python 3.11+, which is the floor). A
missing, unreadable or malformed file falls back to the built-in defaults —
configuration is always optional and must never stop the tool starting.

Usage:
    from packetiq import config
    threshold = config.get("brute_force", "ssh_threshold", 20)
"""

from __future__ import annotations

import os
import tomllib
from functools import lru_cache
from pathlib import Path

# ── Built-in defaults (mirror the detectors' historical constants) ────────────
DEFAULTS: dict = {
    "brute_force": {
        "window_secs": 60,
        "ssh_threshold": 20,
        "ftp_threshold": 15,
        "telnet_threshold": 10,
        "rdp_threshold": 10,
        "vnc_threshold": 10,
        "legitimate_session_bytes": 15000,
    },
    "port_scan": {
        "vertical_port_threshold": 15,
        "horizontal_host_threshold": 20,
        "stealth_halfopen_threshold": 10,
    },
    "beacon": {
        "min_connections": 12,
        "min_interval": 5.0,
        "max_interval": 600.0,
        "cv_threshold_high": 0.10,
        "cv_threshold_med": 0.25,
        "cv_threshold_jittered": 0.50,   # upper CV bound for the jitter-tolerant check
        "periodicity_ratio": 0.70,       # fraction of intervals near the median to flag a jittered beacon
    },
    "kerberos": {
        # A sweep is distinguished from ordinary authentication by two things at
        # once: many distinct principals, and the KDC disowning some of them. A
        # workstation asks for tickets constantly, but always for its own user.
        "user_enum_min_names": 10,
        "user_enum_min_unknown": 3,
        "spray_min_users": 5,
    },
    "winrm": {
        # One or two WS-Management calls is a management action; a sustained
        # exchange is a session somebody is working in.
        "session_min_requests": 5,
    },
    "ldap": {
        # Two searches is a client that looked around; a single bind-and-read is
        # an application doing its job.
        "enum_min_searches": 2,
    },
    "smb": {
        "session_min_operations": 3,
    },
    "dns": {
        "dga_entropy_threshold": 3.8,
        "dga_min_length": 12,
        "tunnel_label_length": 50,
        "excessive_query_count": 20,
    },
    "icmp": {
        "tunnel_threshold_bytes": 102400,
    },
}


def _load_toml(path: Path) -> dict:
    """Parse a config file, treating anything unreadable as "no config".

    This used to branch on `tomllib` with a `tomli` backport fallback, because no
    interpreter in the matrix had both: `tomllib` arrived in 3.11 and `tomli` was
    a dependency only below it. Raising the floor to 3.11 made the backport arm
    unreachable, so it is deleted rather than excluded from coverage.
    """
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except Exception:
        return {}


def _config_path() -> Path | None:
    env = os.environ.get("PACKETIQ_CONFIG")
    if env and Path(env).is_file():
        return Path(env)
    local = Path.cwd() / "packetiq.toml"
    if local.is_file():
        return local
    return None


@lru_cache(maxsize=1)
def load() -> dict:
    """Return the merged config (defaults overlaid with the user's file)."""
    merged = {section: dict(values) for section, values in DEFAULTS.items()}
    path = _config_path()
    if path:
        user = _load_toml(path)
        for section, values in user.items():
            if isinstance(values, dict):
                merged.setdefault(section, {}).update(values)
    return merged


def get(section: str, key: str, default=None):
    """Fetch a single setting, falling back to DEFAULTS then `default`."""
    cfg = load()
    if section in cfg and key in cfg[section]:
        return cfg[section][key]
    return DEFAULTS.get(section, {}).get(key, default)


def reload() -> dict:
    """Clear the cache and reload (used after writing a config file / in tests)."""
    load.cache_clear()
    return load()
