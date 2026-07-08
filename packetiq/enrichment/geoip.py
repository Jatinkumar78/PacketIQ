"""
Optional GeoIP enrichment.

Resolves IP -> country/city/ASN using a local MaxMind GeoLite2 database, IF the
`geoip2` package is installed and a database is available. There is no bundled
database (MaxMind licensing forbids redistribution), so this is a no-op until
the user provides one — it never invents location data.

Setup:
  pip install geoip2
  # download GeoLite2-City.mmdb (free, requires a MaxMind account) and point at it:
  export PACKETIQ_GEOIP_DB=/path/to/GeoLite2-City.mmdb

Usage:
  from packetiq.enrichment import geoip
  if geoip.available():
      info = geoip.lookup("8.8.8.8")   # -> {"country": "...", "city": "...", ...}
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path


def _db_path() -> Path | None:
    env = os.environ.get("PACKETIQ_GEOIP_DB")
    if env and Path(env).is_file():
        return Path(env)
    # common default locations
    for c in ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb",
              str(Path.home() / ".packetiq" / "GeoLite2-City.mmdb")):
        if Path(c).is_file():
            return Path(c)
    return None


@lru_cache(maxsize=1)
def _reader():
    path = _db_path()
    if not path:
        return None
    try:
        import geoip2.database
        return geoip2.database.Reader(str(path))
    except Exception:
        return None


def available() -> bool:
    return _reader() is not None


def lookup(ip: str) -> dict | None:
    """Return geo info for an IP, or None if unavailable / not found."""
    reader = _reader()
    if reader is None:
        return None
    try:
        resp = reader.city(ip)
        return {
            "ip": ip,
            "country": resp.country.name or "",
            "country_code": resp.country.iso_code or "",
            "city": (resp.city.name or "") if hasattr(resp, "city") else "",
            "latitude": getattr(resp.location, "latitude", None),
            "longitude": getattr(resp.location, "longitude", None),
        }
    except Exception:
        return None
