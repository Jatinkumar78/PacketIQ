"""
YARA payload scanning and outbound alert channels.

Both modules sit at an external boundary — a compiled rule engine and three
network/SMTP transports — and both were largely uncovered. The behaviour that
matters is failure handling: a broken rule file must not cost the other rules,
and one dead channel must not stop the rest of the alert going out.

Nothing here reaches the network or SMTP; the transports are stubbed and the
working directory is moved to a temp dir so the repository's own `.env` cannot
leak real credentials into a test.
"""

import types

import pytest

from packetiq.alerts import channels as ch
from packetiq.detection import yara_scan


@pytest.fixture(autouse=True)
def _isolate_env(tmp_path, monkeypatch):
    """`_env` falls back to scanning ./.env and ../.env — keep the real one out."""
    monkeypatch.chdir(tmp_path)
    for var in ("SLACK_WEBHOOK_URL", "ALERT_WEBHOOK_URL", "SMTP_HOST", "SMTP_PORT",
                "SMTP_USER", "SMTP_PASSWORD", "ALERT_EMAIL_TO", "ALERT_EMAIL_FROM"):
        monkeypatch.delenv(var, raising=False)


# =========================================================================== #
#  YARA                                                                        #
# =========================================================================== #

GOOD_RULE = """
rule PacketIQ_Test_Eicar {
    meta:
        description = "Synthetic test rule"
        severity = "critical"
    strings:
        $a = "PACKETIQ-YARA-TESTMARKER"
    condition:
        $a
}
"""

BROKEN_RULE = "rule Broken { condition: this is not valid yara }"


@pytest.fixture(autouse=True)
def _clear_rule_cache():
    """Drop the memoised rule set around every test in this module.

    Looks the attribute up on each side instead of assuming it: a test may replace
    `yara_scan._rules` with a plain stub, and a plain function has no `cache_clear`.
    Whether teardown runs before or after monkeypatch restores the original depends on
    fixture ordering elsewhere in the session, so relying on it made an otherwise
    passing test fail during teardown.
    """
    def clear():
        clear_cache = getattr(yara_scan._rules, "cache_clear", None)
        if clear_cache is not None:
            clear_cache()

    clear()
    yield
    clear()


def test_rule_files_are_discovered_from_a_directory(tmp_path, monkeypatch):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "b.yar").write_text(GOOD_RULE, encoding="utf-8")
    (d / "a.yara").write_text(GOOD_RULE, encoding="utf-8")
    (d / "ignored.txt").write_text("not a rule", encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(d))

    files = yara_scan._rule_files()
    assert any(f.endswith("b.yar") for f in files)
    assert any(f.endswith("a.yara") for f in files)
    assert not any(f.endswith("ignored.txt") for f in files)


def test_a_single_rule_file_can_be_pointed_at(tmp_path, monkeypatch):
    f = tmp_path / "one.yar"
    f.write_text(GOOD_RULE, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(f))
    assert str(f) in yara_scan._rule_files()


def test_the_bundled_rules_are_found_without_configuration(monkeypatch):
    monkeypatch.delenv("PACKETIQ_YARA_RULES", raising=False)
    files = yara_scan._rule_files()
    assert all(f.endswith((".yar", ".yara")) for f in files)


def test_a_matching_payload_is_reported_with_its_metadata(tmp_path, monkeypatch):
    pytest.importorskip("yara")
    f = tmp_path / "t.yar"
    f.write_text(GOOD_RULE, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(f))
    yara_scan._rules.cache_clear()

    hits = yara_scan.scan_bytes(b"junk PACKETIQ-YARA-TESTMARKER junk")
    names = {h["rule"] for h in hits}
    assert "PacketIQ_Test_Eicar" in names
    hit = next(h for h in hits if h["rule"] == "PacketIQ_Test_Eicar")
    assert hit["severity"] == "CRITICAL"
    assert hit["description"] == "Synthetic test rule"
    assert isinstance(hit["tags"], list)


def test_a_clean_payload_matches_nothing(tmp_path, monkeypatch):
    pytest.importorskip("yara")
    f = tmp_path / "t.yar"
    f.write_text(GOOD_RULE, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(f))
    yara_scan._rules.cache_clear()
    assert yara_scan.scan_bytes(b"an entirely ordinary HTTP response body") == []


def test_one_broken_rule_file_does_not_disable_the_others(tmp_path, monkeypatch):
    """A single malformed rule used to fail the whole-set compile silently."""
    pytest.importorskip("yara")
    d = tmp_path / "rules"
    d.mkdir()
    (d / "good.yar").write_text(GOOD_RULE, encoding="utf-8")
    (d / "broken.yar").write_text(BROKEN_RULE, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(d))
    yara_scan._rules.cache_clear()

    hits = yara_scan.scan_bytes(b"PACKETIQ-YARA-TESTMARKER")
    assert "PacketIQ_Test_Eicar" in {h["rule"] for h in hits}


def test_every_rule_file_being_broken_yields_no_engine(tmp_path, monkeypatch):
    """With the bundled set out of the picture, nothing compilable means no engine."""
    pytest.importorskip("yara")
    d = tmp_path / "rules"
    d.mkdir()
    (d / "broken.yar").write_text(BROKEN_RULE, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(d))
    monkeypatch.setattr(yara_scan, "_BUNDLED_DIR", tmp_path / "no-bundled-rules-here")
    yara_scan._rules.cache_clear()

    assert yara_scan._rules() is None
    assert yara_scan.available() is False
    assert yara_scan.scan_bytes(b"anything") == []


def test_the_bundled_rules_stay_available_when_a_user_rule_is_broken(tmp_path, monkeypatch):
    """A user's typo must not disarm the rules that ship with the product."""
    pytest.importorskip("yara")
    d = tmp_path / "rules"
    d.mkdir()
    (d / "broken.yar").write_text(BROKEN_RULE, encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_YARA_RULES", str(d))
    yara_scan._rules.cache_clear()
    assert yara_scan.available() is True


def test_no_rule_files_at_all_yields_no_engine(tmp_path, monkeypatch):
    pytest.importorskip("yara")
    monkeypatch.delenv("PACKETIQ_YARA_RULES", raising=False)
    monkeypatch.setattr(yara_scan, "_BUNDLED_DIR", tmp_path / "absent")
    yara_scan._rules.cache_clear()
    assert yara_scan._rule_files() == []
    assert yara_scan._rules() is None


def test_an_empty_payload_is_never_scanned():
    assert yara_scan.scan_bytes(b"") == []


def test_the_package_being_absent_degrades_to_no_scanning(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "yara", None)
    yara_scan._rules.cache_clear()
    assert yara_scan.available() is False
    assert yara_scan.scan_bytes(b"PACKETIQ-YARA-TESTMARKER") == []


def test_a_scan_error_is_swallowed_rather_than_raised(monkeypatch):
    class Boom:
        def match(self, **kw):
            raise RuntimeError("scan blew up")

    monkeypatch.setattr(yara_scan, "_rules", lambda: Boom())
    assert yara_scan.scan_bytes(b"data") == []


# =========================================================================== #
#  Alert channels                                                              #
# =========================================================================== #

def test_no_configuration_means_no_channels_and_no_sends():
    assert ch.configured_channels() == []
    assert ch.broadcast("Subject", "body") == {}


def test_configuration_is_read_from_a_dotenv_file(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        '# comment\nSLACK_WEBHOOK_URL="https://hooks.example.com/T/B/X"\nnot-a-pair\n',
        encoding="utf-8",
    )
    assert ch._env("SLACK_WEBHOOK_URL") == "https://hooks.example.com/T/B/X"
    assert ch._env("NOTHING_SET") is None


def test_the_environment_takes_precedence_over_dotenv(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("SLACK_WEBHOOK_URL=from-file\n", encoding="utf-8")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "from-environment")
    assert ch._env("SLACK_WEBHOOK_URL") == "from-environment"


def _stub_post(monkeypatch, status=200):
    sent = []

    def post(url, json=None, timeout=None):
        sent.append({"url": url, "json": json, "timeout": timeout})
        return types.SimpleNamespace(status_code=status, ok=200 <= status < 300)

    monkeypatch.setattr(ch, "requests", types.SimpleNamespace(post=post))
    return sent


def test_slack_posts_the_subject_and_body(monkeypatch):
    sent = _stub_post(monkeypatch)
    ok, err = ch.SlackWebhook("https://hooks.example.com/x").send("hello")
    assert (ok, err) == (True, "")
    assert sent[0]["json"] == {"text": "hello"}
    assert sent[0]["timeout"] == ch._TIMEOUT


def test_slack_reports_a_failing_status(monkeypatch):
    _stub_post(monkeypatch, status=500)
    ok, err = ch.SlackWebhook("https://hooks.example.com/x").send("hello")
    assert ok is False
    assert "500" in err


def test_slack_reports_a_transport_failure(monkeypatch):
    def post(*a, **k):
        raise ConnectionError("no route to host")

    monkeypatch.setattr(ch, "requests", types.SimpleNamespace(post=post))
    ok, err = ch.SlackWebhook("https://x").send("hello")
    assert ok is False
    assert "no route to host" in err


@pytest.mark.parametrize("status,expected", [(200, True), (201, True), (204, True),
                                             (400, False), (500, False)])
def test_generic_webhook_accepts_any_2xx(monkeypatch, status, expected):
    _stub_post(monkeypatch, status=status)
    ok, _ = ch.GenericWebhook("https://x").send({"a": 1})
    assert ok is expected


def test_email_is_sent_over_starttls_with_login(monkeypatch):
    actions = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            actions.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            actions.append(("starttls", context is not None))

        def login(self, user, password):
            actions.append(("login", user))

        def send_message(self, msg):
            actions.append(("send", msg["To"], msg["Subject"]))

    monkeypatch.setattr(ch.smtplib, "SMTP", FakeSMTP)
    ok, err = ch.EmailSender("smtp.example.com", 587, "u", "p",
                             "from@example.com", "to@example.com").send("Subj", "Body")

    assert (ok, err) == (True, "")
    assert ("connect", "smtp.example.com", 587) in actions
    assert ("starttls", True) in actions, "credentials must not cross in the clear"
    assert ("login", "u") in actions
    assert ("send", "to@example.com", "Subj") in actions


def test_email_without_credentials_skips_login(monkeypatch):
    actions = []

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            pass

        def login(self, *a):
            actions.append("login")

        def send_message(self, msg):
            actions.append("send")

    monkeypatch.setattr(ch.smtplib, "SMTP", FakeSMTP)
    ok, _ = ch.EmailSender("h", None, "", "", "f@x", "t@x").send("S", "B")
    assert ok is True
    assert actions == ["send"]


def test_email_defaults_to_the_submission_port():
    assert ch.EmailSender("h", None, "u", "p", "f@x", "t@x").port == 587


def test_email_reports_a_failure_instead_of_raising(monkeypatch):
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(ch.smtplib, "SMTP", boom)
    ok, err = ch.EmailSender("h", 25, "u", "p", "f@x", "t@x").send("S", "B")
    assert ok is False
    assert "connection refused" in err


def test_configured_channels_lists_only_what_is_usable(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://s")
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")   # no recipient → unusable
    assert ch.configured_channels() == ["slack"]

    monkeypatch.setenv("ALERT_EMAIL_TO", "to@example.com")
    assert set(ch.configured_channels()) == {"slack", "email"}


def test_broadcast_reaches_every_configured_channel(monkeypatch):
    sent = _stub_post(monkeypatch)
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.example.com/x")
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hook.example.com/y")

    results = ch.broadcast("Critical finding", "3 events", payload={"events": 3})

    assert set(results) == {"slack", "webhook"}
    assert all(ok for ok, _ in results.values())
    assert sent[0]["json"]["text"] == "*Critical finding*\n3 events"
    assert sent[1]["json"] == {"events": 3}


def test_one_dead_channel_does_not_stop_the_others(monkeypatch):
    """A failing Slack hook must not swallow the webhook alert."""
    def post(url, json=None, timeout=None):
        if "slack" in url:
            raise ConnectionError("slack is down")
        return types.SimpleNamespace(status_code=200, ok=True)

    monkeypatch.setattr(ch, "requests", types.SimpleNamespace(post=post))
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.example.com/x")
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hook.example.com/y")

    results = ch.broadcast("Subject", "text")
    assert results["slack"][0] is False
    assert results["webhook"][0] is True


def test_broadcast_falls_back_to_a_default_webhook_payload(monkeypatch):
    sent = _stub_post(monkeypatch)
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hook.example.com/y")
    ch.broadcast("Subj", "Body")
    assert sent[0]["json"] == {"subject": "Subj", "text": "Body"}


def test_configured_channels_includes_a_generic_webhook(monkeypatch):
    """The webhook arm of the listing — the UI shows this list before sending."""
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hook.example.com/y")
    assert ch.configured_channels() == ["webhook"]


def test_a_generic_webhook_reports_a_transport_failure(monkeypatch):
    """An unreachable webhook is a failed delivery, not an exception up the stack.

    broadcast() collects per-channel results, so a raise here would take down
    the alerts that were still deliverable.
    """
    def post(url, json=None, timeout=None):
        raise ConnectionError("connection reset")

    monkeypatch.setattr(ch, "requests", types.SimpleNamespace(post=post))

    ok, err = ch.GenericWebhook("https://hook.example.com/y").send({"a": 1})
    assert ok is False
    assert "connection reset" in err


def test_broadcast_sends_email_when_smtp_is_configured(monkeypatch):
    """The email arm of broadcast, wired from environment to EmailSender.

    Checks the address defaulting too: with no ALERT_EMAIL_FROM set, the SMTP
    user becomes the sender rather than the message going out with no From.
    """
    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            captured["host"], captured["port"] = host, port

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            captured["tls"] = True

        def login(self, user, password):
            captured["login"] = (user, password)

        def send_message(self, msg):
            captured["msg"] = msg

    monkeypatch.setattr(ch.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_USER", "alerts@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "secret")
    monkeypatch.setenv("ALERT_EMAIL_TO", "soc@example.com")
    monkeypatch.delenv("ALERT_EMAIL_FROM", raising=False)

    results = ch.broadcast("Critical finding", "3 events")

    assert results == {"email": (True, "")}
    assert captured["host"] == "smtp.example.com"
    assert captured["port"] == 2525
    assert captured["tls"] is True
    assert captured["login"] == ("alerts@example.com", "secret")
    assert captured["msg"]["To"] == "soc@example.com"
    assert captured["msg"]["From"] == "alerts@example.com"
    assert captured["msg"]["Subject"] == "Critical finding"
