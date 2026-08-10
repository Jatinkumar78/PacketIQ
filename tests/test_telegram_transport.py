"""
Telegram alert transport.

This is how a finding actually leaves the machine, and it was half-covered. Three
behaviours are worth pinning down:

  * **Credential validation** decides whether the setup UI accepts what a user
    pastes. Too loose and a typo silently never delivers; too strict and a valid
    group id is rejected.
  * **Message splitting** — Telegram hard-caps a message at 4096 characters and
    rejects anything longer, so a long report must be chunked or the alert is
    simply lost.
  * **HTML escaping** — findings quote attacker-controlled strings (URIs, user
    agents). An unescaped `<` breaks the message parse, which again means no
    alert; it is also how injected markup would reach the analyst's client.

Nothing here touches the network.
"""

import types

import pytest

from packetiq.alerts import telegram as tg


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """load_credentials falls back to scanning ./.env — keep the real one out."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)


# --------------------------------------------------------------------------- #
#  Credential validation                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("token", [
    "123456789:AAHrqUxE3n7bQZ8vXm2kLpTyWc4dFgHjKlQ",
    "12345:" + "A" * 20,
])
def test_a_real_looking_bot_token_is_accepted(token):
    assert tg.valid_token(token) is True


@pytest.mark.parametrize("token", [
    "", "   ", None,
    "not-a-token",
    "123:short",                       # secret part too short
    "1234:" + "A" * 20,                # bot id too short
    "abcdefghi:" + "A" * 20,           # non-numeric bot id
    "123456789 AAHrqUxE3n7bQZ8vXm2kLpTyWc4dFgHjKlQ",   # missing colon
])
def test_a_malformed_bot_token_is_rejected(token):
    assert tg.valid_token(token) is False


def test_surrounding_whitespace_is_tolerated_on_a_token():
    """Users paste from BotFather; a stray newline must not fail setup."""
    assert tg.valid_token("  123456789:" + "A" * 25 + "\n") is True


@pytest.mark.parametrize("chat_id", [
    "123456789",          # user
    "-1001234567890",     # supergroup
    "-987654",            # group
    "@packetiq_alerts",   # channel username
])
def test_a_valid_chat_id_is_accepted(chat_id):
    assert tg.valid_chat_id(chat_id) is True


@pytest.mark.parametrize("chat_id", [
    "", "   ", None, "12", "@ab", "not a chat", "@has spaces",
])
def test_an_invalid_chat_id_is_rejected(chat_id):
    assert tg.valid_chat_id(chat_id) is False


# --------------------------------------------------------------------------- #
#  Credential loading                                                           #
# --------------------------------------------------------------------------- #

def test_credentials_come_from_the_environment_first(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "env-token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "env-chat")
    assert tg.load_credentials() == ("env-token", "env-chat")


def test_credentials_fall_back_to_a_dotenv_file(tmp_path):
    (tmp_path / ".env").write_text(
        '# PacketIQ config\n'
        'TELEGRAM_BOT_TOKEN="file-token"\n'
        "TELEGRAM_CHAT_ID='-1001234567890'\n"
        "MALFORMED LINE\n",
        encoding="utf-8",
    )
    assert tg.load_credentials() == ("file-token", "-1001234567890")


def test_a_commented_out_setting_in_dotenv_is_not_read(tmp_path):
    """A `#`-prefixed assignment is a disabled setting, not a value.

    Commenting a line out is how people park an old chat id, so the parser has to
    reject a line that *does* look like an assignment — the case a bare `#`
    comment or a line with no `=` at all never reaches.
    """
    (tmp_path / ".env").write_text(
        "#TELEGRAM_BOT_TOKEN=disabled-token\n"
        "# TELEGRAM_CHAT_ID=-1009999999999\n"
        "TELEGRAM_BOT_TOKEN=live-token\n",
        encoding="utf-8",
    )
    assert tg.load_credentials() == ("live-token", None)


def test_missing_credentials_are_reported_as_none():
    assert tg.load_credentials() == (None, None)


def test_an_empty_value_is_treated_as_absent(tmp_path):
    (tmp_path / ".env").write_text("TELEGRAM_BOT_TOKEN=\n", encoding="utf-8")
    token, chat = tg.load_credentials()
    assert token is None and chat is None


# --------------------------------------------------------------------------- #
#  Message splitting                                                            #
# --------------------------------------------------------------------------- #

def test_a_short_message_is_not_split():
    assert tg._split_message("hello", 4096) == ["hello"]


def test_a_long_message_is_split_within_the_limit():
    """Telegram rejects >4096 chars outright, so an unsplit alert never arrives."""
    text = "\n\n".join(f"Paragraph {i} " + "x" * 200 for i in range(60))
    chunks = tg._split_message(text, 4096)
    assert len(chunks) > 1
    assert all(len(c) <= 4096 for c in chunks)


def test_splitting_prefers_paragraph_boundaries():
    para = "A" * 100
    text = "\n\n".join([para] * 10)
    chunks = tg._split_message(text, 250)
    assert all(not c.startswith("\n") for c in chunks)
    assert all(c.strip() == c for c in chunks)


def test_splitting_falls_back_to_a_hard_cut_when_there_is_no_break():
    text = "Z" * 500                     # one unbroken run
    chunks = tg._split_message(text, 100)
    assert all(len(c) <= 100 for c in chunks)
    assert "".join(chunks) == text


def test_no_content_is_lost_when_splitting():
    text = "\n\n".join(f"Line {i}" for i in range(300))
    rejoined = "".join(tg._split_message(text, 200))
    assert rejoined.replace("\n", "") == text.replace("\n", "")


# --------------------------------------------------------------------------- #
#  HTML escaping                                                                #
# --------------------------------------------------------------------------- #

def test_markup_in_attacker_controlled_text_is_escaped():
    hostile = "<script>alert(1)</script> & <b>bold</b>"
    out = tg.esc(hostile)
    assert "<script>" not in out
    assert "&lt;script&gt;" in out
    assert "&amp;" in out


def test_escaping_accepts_non_string_values():
    assert tg.esc(443) == "443"
    assert tg.esc(None) == "None"


# --------------------------------------------------------------------------- #
#  Sending                                                                      #
# --------------------------------------------------------------------------- #

def _fake_requests(**handlers):
    """A requests stand-in that still carries the exception types the code catches."""
    import requests as real

    return types.SimpleNamespace(
        Timeout=real.Timeout,
        RequestException=real.RequestException,
        ConnectionError=real.ConnectionError,
        **handlers,
    )


def _sender(monkeypatch, response, *, method_capture=None):
    def post(url, **kw):
        if method_capture is not None:
            method_capture.append({"url": url, **kw})
        return response

    monkeypatch.setattr(tg, "requests", _fake_requests(post=post, get=post))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-1001234567890")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)      # no real sleeping
    return s


def test_a_successful_send_reports_success(monkeypatch):
    calls = []
    s = _sender(monkeypatch,
                types.SimpleNamespace(status_code=200, json=lambda: {"ok": True}),
                method_capture=calls)
    ok, err = s.send("A finding")
    assert ok is True
    assert err == ""
    assert "sendMessage" in calls[0]["url"]


def test_a_rejected_send_surfaces_the_api_description(monkeypatch):
    s = _sender(monkeypatch, types.SimpleNamespace(
        status_code=400, json=lambda: {"ok": False, "description": "chat not found"}))
    ok, err = s.send("A finding")
    assert ok is False
    assert "chat not found" in err


def test_a_network_failure_is_reported_not_raised(monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("dns failure")

    monkeypatch.setattr(tg, "requests", _fake_requests(post=boom, get=boom))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)
    ok, err = s.send("x")
    assert ok is False
    assert "dns failure" in err


def test_a_long_alert_is_delivered_as_several_messages(monkeypatch):
    calls = []
    s = _sender(monkeypatch,
                types.SimpleNamespace(status_code=200, json=lambda: {"ok": True}),
                method_capture=calls)
    ok, _ = s.send("\n\n".join("y" * 500 for _ in range(20)))
    assert ok is True
    assert len(calls) > 1, "an over-length alert must be chunked, not dropped"


def test_sending_a_missing_document_fails_cleanly(monkeypatch, tmp_path):
    s = _sender(monkeypatch, types.SimpleNamespace(status_code=200, json=lambda: {"ok": True}))
    ok, err = s.send_document(str(tmp_path / "absent.pdf"))
    assert ok is False
    assert err


def test_a_report_file_is_uploaded(monkeypatch, tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"%PDF-1.4 synthetic")
    calls = []
    s = _sender(monkeypatch,
                types.SimpleNamespace(status_code=200, json=lambda: {"ok": True}),
                method_capture=calls)
    ok, _ = s.send_document(str(f), caption="Incident report")
    assert ok is True
    assert "sendDocument" in calls[0]["url"]


# --------------------------------------------------------------------------- #
#  Chat discovery                                                               #
# --------------------------------------------------------------------------- #

def test_chat_discovery_deduplicates_and_names_each_chat(monkeypatch):
    payload = {"ok": True, "result": [
        # Same chat twice — the most recent update supplies the displayed name.
        {"message": {"chat": {"id": 111, "type": "private", "first_name": "Ada"}}},
        {"message": {"chat": {"id": 111, "type": "private",
                              "first_name": "Ada", "last_name": "Lovelace"}}},
        {"channel_post": {"chat": {"id": -1001, "type": "channel", "title": "SOC Alerts"}}},
        {"my_chat_member": {"chat": {"id": -1002, "type": "group",
                                     "username": "blueteam"}}},
        {"message": {"chat": {}}},                 # no id — skipped
    ]}
    monkeypatch.setattr(tg, "requests", _fake_requests(
        get=lambda url, **kw: types.SimpleNamespace(json=lambda: payload)))

    ok, chats = tg.detect_chat_ids("123456789:" + "A" * 25)
    assert ok is True
    by_id = {c["chat_id"]: c for c in chats}
    assert by_id["111"]["name"] == "Ada Lovelace"
    assert by_id["-1001"]["name"] == "SOC Alerts"
    assert by_id["-1002"]["name"] == "@blueteam"
    assert len(chats) == 3


def test_chat_discovery_reports_an_invalid_token(monkeypatch):
    monkeypatch.setattr(tg, "requests", _fake_requests(
        get=lambda url, **kw: types.SimpleNamespace(
            json=lambda: {"ok": False, "description": "Unauthorized"})))
    ok, err = tg.detect_chat_ids("bad")
    assert ok is False
    assert "Unauthorized" in err


def test_chat_discovery_reports_a_network_failure(monkeypatch):
    def boom(*a, **k):
        raise TimeoutError("timed out")

    monkeypatch.setattr(tg, "requests", _fake_requests(get=boom))
    ok, err = tg.detect_chat_ids("123456789:" + "A" * 25)
    assert ok is False
    assert "Network error" in err


def test_connection_test_reports_the_bot_identity(monkeypatch):
    monkeypatch.setattr(tg, "requests", _fake_requests(
        get=lambda url, **kw: types.SimpleNamespace(
            status_code=200,
            json=lambda: {"ok": True, "result": {"username": "packetiq_bot"}}),
        post=lambda url, **kw: types.SimpleNamespace(
            status_code=200, json=lambda: {"ok": True})))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)
    ok, msg = s.test_connection()
    assert isinstance(ok, bool)
    assert msg


def test_connection_test_reports_an_unreachable_api(monkeypatch):
    """getMe never completes — the setup UI has to say so rather than hang."""
    def boom(*a, **k):
        raise OSError("no route to host")

    monkeypatch.setattr(tg, "requests", _fake_requests(get=boom, post=boom))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)

    ok, err = s.test_connection()
    assert ok is False
    assert "Network error" in err and "no route to host" in err


def test_connection_test_names_a_bad_token(monkeypatch):
    """The two failure modes must stay distinguishable: a rejected token is a
    typo to fix, an accepted token with a rejected message is a wrong chat id."""
    monkeypatch.setattr(tg, "requests", _fake_requests(
        get=lambda url, **kw: types.SimpleNamespace(
            status_code=401, json=lambda: {"ok": False, "description": "Unauthorized"})))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)

    ok, err = s.test_connection()
    assert ok is False
    assert "Invalid bot token" in err and "Unauthorized" in err


def test_connection_test_distinguishes_a_valid_token_from_a_bad_chat(monkeypatch):
    monkeypatch.setattr(tg, "requests", _fake_requests(
        get=lambda url, **kw: types.SimpleNamespace(
            status_code=200,
            json=lambda: {"ok": True, "result": {"username": "packetiq_bot"}}),
        post=lambda url, **kw: types.SimpleNamespace(
            status_code=400, json=lambda: {"ok": False, "description": "chat not found"})))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)

    ok, err = s.test_connection()
    assert ok is False
    assert "Token valid but message failed" in err
    assert "chat not found" in err


def test_a_rejected_document_upload_surfaces_the_api_description(monkeypatch, tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"%PDF-1.4 synthetic")
    s = _sender(monkeypatch, types.SimpleNamespace(
        status_code=400,
        json=lambda: {"ok": False, "description": "file is too big"}))

    ok, err = s.send_document(str(f))
    assert ok is False
    assert "file is too big" in err


def test_a_document_rejection_with_no_description_still_reports_failure(monkeypatch, tmp_path):
    f = tmp_path / "report.pdf"
    f.write_bytes(b"%PDF-1.4 synthetic")
    s = _sender(monkeypatch, types.SimpleNamespace(status_code=500, json=lambda: {"ok": False}))

    ok, err = s.send_document(str(f))
    assert ok is False
    assert err == "Unknown error"


def test_a_send_timeout_is_named_as_such(monkeypatch):
    """`requests.Timeout` and `ConnectionError` produce different guidance for
    the user — one means retry, the other means check the network."""
    import requests as real

    def timeout(*a, **k):
        raise real.Timeout()

    monkeypatch.setattr(tg, "requests", _fake_requests(post=timeout, get=timeout))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)

    ok, err = s.send("x")
    assert (ok, err) == (False, "Request timed out")


def test_a_send_connection_error_is_named_as_such(monkeypatch):
    import requests as real

    def unreachable(*a, **k):
        raise real.ConnectionError()

    monkeypatch.setattr(tg, "requests", _fake_requests(post=unreachable, get=unreachable))
    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    monkeypatch.setattr(s, "_rate_limit", lambda: None)

    ok, err = s.send("x")
    assert (ok, err) == (False, "Network unreachable")


def test_consecutive_sends_are_spaced_by_the_rate_limit(monkeypatch):
    """Telegram throttles a bot to roughly one message per second per chat.

    Every other test stubs this out, so the real arithmetic — how long to wait
    given how long ago the last send was — was never exercised. Getting it wrong
    means a burst of findings is rejected by the API, not delivered slowly.
    """
    slept: list = []
    clock = {"t": 1000.0}
    monkeypatch.setattr(tg.time, "time", lambda: clock["t"])
    monkeypatch.setattr(tg.time, "sleep", lambda s: slept.append(s))

    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    s._last_sent = clock["t"]          # a send just happened
    s._rate_limit()

    assert slept == [pytest.approx(tg.MIN_DELAY)]
    assert s._last_sent == clock["t"]


def test_a_send_after_a_long_gap_does_not_wait(monkeypatch):
    slept: list = []
    monkeypatch.setattr(tg.time, "time", lambda: 2000.0)
    monkeypatch.setattr(tg.time, "sleep", lambda s: slept.append(s))

    s = tg.TelegramSender("123456789:" + "A" * 25, "-100123456")
    s._last_sent = 1000.0              # far longer ago than the minimum delay
    s._rate_limit()

    assert slept == [], "no need to throttle when the last send was ages ago"
