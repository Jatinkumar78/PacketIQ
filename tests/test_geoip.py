"""
Optional GeoIP loader.

No MaxMind database ships with PacketIQ (their licence forbids redistribution), so
this module is a deliberate no-op until the user supplies one — README tracks the
SPA map that will consume it as an open item. That is exactly why it needs tests:
nothing in the product calls it today, so a defect here would sit undetected until
the first person actually configures a database.

The contract under test is "never invent location data": every failure path must
return None rather than a plausible-looking guess.
"""

import sys
import types

import pytest

from packetiq.enrichment import geoip


@pytest.fixture(autouse=True)
def _clean_cache(monkeypatch):
    """The reader is cached for the process; every test starts from a cold one."""
    monkeypatch.delenv("PACKETIQ_GEOIP_DB", raising=False)
    geoip.reset()
    yield
    geoip.reset()


def _fake_response(country="Germany", code="DE", city="Berlin", lat=52.52, lon=13.40):
    return types.SimpleNamespace(
        country=types.SimpleNamespace(name=country, iso_code=code),
        city=types.SimpleNamespace(name=city),
        location=types.SimpleNamespace(latitude=lat, longitude=lon),
    )


def _install_fake_geoip2(monkeypatch, reader_factory):
    """Stand in for the geoip2 package without needing a real .mmdb file."""
    db_mod = types.ModuleType("geoip2.database")
    db_mod.Reader = reader_factory
    pkg = types.ModuleType("geoip2")
    pkg.database = db_mod
    monkeypatch.setitem(sys.modules, "geoip2", pkg)
    monkeypatch.setitem(sys.modules, "geoip2.database", db_mod)


# --------------------------------------------------------------------------- #
#  Database discovery                                                           #
# --------------------------------------------------------------------------- #

def test_no_database_configured_means_unavailable():
    assert geoip._db_path() is None
    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None


def test_env_var_pointing_at_a_real_file_is_used(tmp_path, monkeypatch):
    db = tmp_path / "GeoLite2-City.mmdb"
    db.write_bytes(b"not-a-real-mmdb")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))
    assert geoip._db_path() == db


def test_env_var_pointing_at_a_missing_file_is_ignored(tmp_path, monkeypatch):
    """A stale setting must not be treated as a database."""
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(tmp_path / "gone.mmdb"))
    assert geoip._db_path() is None


def test_env_var_pointing_at_a_directory_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(tmp_path))
    assert geoip._db_path() is None


def test_a_database_in_the_working_directory_is_found(tmp_path, monkeypatch):
    (tmp_path / "GeoLite2-City.mmdb").write_bytes(b"x")
    monkeypatch.chdir(tmp_path)
    assert geoip._db_path() == geoip.Path("GeoLite2-City.mmdb")


def test_the_country_only_database_is_accepted_too(tmp_path, monkeypatch):
    (tmp_path / "GeoLite2-Country.mmdb").write_bytes(b"x")
    monkeypatch.chdir(tmp_path)
    assert geoip._db_path() == geoip.Path("GeoLite2-Country.mmdb")


# --------------------------------------------------------------------------- #
#  Lookups                                                                      #
# --------------------------------------------------------------------------- #

def test_a_successful_lookup_returns_only_data_the_database_gave(tmp_path, monkeypatch):
    db = tmp_path / "db.mmdb"
    db.write_bytes(b"x")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))

    class Reader:
        def __init__(self, path):
            self.path = path

        def city(self, ip):
            return _fake_response()

    _install_fake_geoip2(monkeypatch, Reader)
    geoip.reset()

    assert geoip.available() is True
    assert geoip.lookup("8.8.8.8") == {
        "ip": "8.8.8.8",
        "country": "Germany",
        "country_code": "DE",
        "city": "Berlin",
        "latitude": 52.52,
        "longitude": 13.40,
    }


def test_missing_fields_become_empty_strings_never_invented(tmp_path, monkeypatch):
    db = tmp_path / "db.mmdb"
    db.write_bytes(b"x")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))

    class Reader:
        def __init__(self, path):
            pass

        def city(self, ip):
            return _fake_response(country=None, code=None, city=None, lat=None, lon=None)

    _install_fake_geoip2(monkeypatch, Reader)
    geoip.reset()

    info = geoip.lookup("1.1.1.1")
    assert info == {"ip": "1.1.1.1", "country": "", "country_code": "",
                    "city": "", "latitude": None, "longitude": None}


def test_an_address_absent_from_the_database_returns_none(tmp_path, monkeypatch):
    db = tmp_path / "db.mmdb"
    db.write_bytes(b"x")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))

    class Reader:
        def __init__(self, path):
            pass

        def city(self, ip):
            raise KeyError("address not in database")

    _install_fake_geoip2(monkeypatch, Reader)
    geoip.reset()

    assert geoip.available() is True
    assert geoip.lookup("10.0.0.1") is None      # no guess, no partial record


def test_a_corrupt_database_degrades_to_unavailable(tmp_path, monkeypatch):
    db = tmp_path / "db.mmdb"
    db.write_bytes(b"corrupt")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))

    def Reader(path):
        raise OSError("invalid database file")

    _install_fake_geoip2(monkeypatch, Reader)
    geoip.reset()

    assert geoip.available() is False
    assert geoip.lookup("8.8.8.8") is None


def test_the_package_being_absent_degrades_to_unavailable(tmp_path, monkeypatch):
    db = tmp_path / "db.mmdb"
    db.write_bytes(b"x")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))
    monkeypatch.setitem(sys.modules, "geoip2", None)      # import raises
    geoip.reset()

    assert geoip.available() is False


# --------------------------------------------------------------------------- #
#  Cache behaviour                                                              #
# --------------------------------------------------------------------------- #

def test_the_reader_is_cached_rather_than_reopened_per_lookup(tmp_path, monkeypatch):
    db = tmp_path / "db.mmdb"
    db.write_bytes(b"x")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))
    opens = []

    class Reader:
        def __init__(self, path):
            opens.append(path)

        def city(self, ip):
            return _fake_response()

    _install_fake_geoip2(monkeypatch, Reader)
    geoip.reset()

    geoip.lookup("8.8.8.8")
    geoip.lookup("1.1.1.1")
    geoip.available()
    assert len(opens) == 1


def test_reset_lets_a_newly_configured_database_take_effect(tmp_path, monkeypatch):
    """Without reset(), configuring a database after first use never applies."""
    assert geoip.available() is False          # caches the "no database" answer

    db = tmp_path / "db.mmdb"
    db.write_bytes(b"x")
    monkeypatch.setenv("PACKETIQ_GEOIP_DB", str(db))

    class Reader:
        def __init__(self, path):
            pass

        def city(self, ip):
            return _fake_response()

    _install_fake_geoip2(monkeypatch, Reader)

    assert geoip.available() is False          # still the stale cached answer
    geoip.reset()
    assert geoip.available() is True
