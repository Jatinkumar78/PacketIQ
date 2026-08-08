"""The interactive copilot REPL: slash commands, streaming, and report saving.

`packetiq chat` is a blocking loop around `input()`, which is why it had no
coverage at all. Every test here drives it with a scripted list of inputs and a
recording client, so the command routing and the failure handling run for real
without a terminal.

The behaviours that matter are the recovery paths: a failed API call must not
leave a dangling user turn in the history (the next request would then be
rejected as malformed), and an unwritable report path must still show the
analyst the report rather than losing it.
"""

import io
import os

import pytest
from rich.console import Console

from packetiq.copilot import chat as chat_mod
from packetiq.copilot.chat import InteractiveChat


class RecordingClient:
    """Stands in for CopilotClient / MultiProviderClient."""

    model_label = "test-model"

    def __init__(self, reply="The host was scanned.", report="# SOC Report\n\nBody.",
                 stream_error=None, report_error=None):
        self.reply = reply
        self.report = report
        self.stream_error = stream_error
        self.report_error = report_error
        self.streamed: list = []
        self.reports: list = []

    def stream_message(self, messages, on_chunk):
        self.streamed.append([dict(m) for m in messages])
        if self.stream_error:
            raise self.stream_error
        on_chunk(self.reply)
        return self.reply

    def single_message(self, prompt):
        self.reports.append(prompt)
        if self.report_error:
            raise self.report_error
        return self.report


@pytest.fixture
def captured_console(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(chat_mod, "console",
                        Console(file=buf, width=100, force_terminal=False, no_color=True))
    return buf


def _run(monkeypatch, inputs, client=None, **kw):
    """Drive the REPL with a scripted sequence of user lines."""
    script = iter(inputs)
    monkeypatch.setattr("builtins.input", lambda: next(script))
    client = client or RecordingClient()
    session = InteractiveChat(client, pcap_name="attack.pcap", **kw)
    session.run()
    return session


# ── Session lifecycle ────────────────────────────────────────────────────────

@pytest.mark.parametrize("word", ["exit", "quit", "q", "/exit", "/quit", "EXIT"])
def test_every_exit_spelling_ends_the_session(monkeypatch, captured_console, word):
    session = _run(monkeypatch, [word])

    assert session.turn == 0
    assert "Exiting PacketIQ Copilot" in captured_console.getvalue()


def test_ctrl_c_ends_the_session_cleanly(monkeypatch, captured_console):
    """Ctrl-C at the prompt is how most sessions actually end."""
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt)
    InteractiveChat(RecordingClient(), pcap_name="attack.pcap").run()

    assert "Session ended" in captured_console.getvalue()


def test_end_of_input_ends_the_session_cleanly(monkeypatch, captured_console):
    """Piped input runs out — that is not an error."""
    def eof():
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    InteractiveChat(RecordingClient(), pcap_name="attack.pcap").run()

    assert "Session ended" in captured_console.getvalue()


def test_the_header_names_the_capture_and_the_model(monkeypatch, captured_console):
    _run(monkeypatch, ["exit"])
    out = captured_console.getvalue()

    assert "attack.pcap" in out
    assert "test-model" in out


def test_a_client_without_a_model_label_still_renders_a_header(monkeypatch, captured_console):
    class Bare(RecordingClient):
        pass

    Bare.model_label = property(lambda self: (_ for _ in ()).throw(AttributeError))
    client = RecordingClient()
    del type(client).model_label
    try:
        _run(monkeypatch, ["exit"], client=client)
        assert "attack.pcap" in captured_console.getvalue()
    finally:
        RecordingClient.model_label = "test-model"


def test_a_blank_line_is_ignored(monkeypatch, captured_console):
    client = RecordingClient()
    session = _run(monkeypatch, ["", "   ", "exit"], client=client)

    assert client.streamed == []
    assert session.turn == 0


# ── Slash commands ───────────────────────────────────────────────────────────

def test_help_prints_the_command_list_without_calling_the_model(monkeypatch, captured_console):
    client = RecordingClient()
    _run(monkeypatch, ["/help", "exit"], client=client)

    assert client.streamed == []
    assert "report" in captured_console.getvalue().lower()


def test_clear_resets_the_conversation(monkeypatch, captured_console):
    client = RecordingClient()
    session = _run(monkeypatch, ["what happened?", "/clear", "exit"], client=client)

    assert session.history == []
    assert session.turn == 0
    assert "history cleared" in captured_console.getvalue()


def test_a_known_slash_command_sends_its_prewritten_prompt(monkeypatch, captured_console):
    """The point of the shortcuts: the analyst types /timeline, the model gets a
    carefully worded prompt rather than one word."""
    from packetiq.copilot.chat import SLASH_PROMPTS

    name = next(k for k in SLASH_PROMPTS if k != "report")
    client = RecordingClient()
    _run(monkeypatch, [f"/{name}", "exit"], client=client)

    assert client.streamed[0][-1]["content"] == SLASH_PROMPTS[name]


def test_an_unknown_slash_command_is_sent_as_typed(monkeypatch, captured_console):
    client = RecordingClient()
    _run(monkeypatch, ["/notacommand", "exit"], client=client)

    assert client.streamed[0][-1]["content"] == "/notacommand"


def test_a_plain_question_is_sent_verbatim(monkeypatch, captured_console):
    client = RecordingClient()
    session = _run(monkeypatch, ["which host was scanned?", "exit"], client=client)

    assert client.streamed[0][-1]["content"] == "which host was scanned?"
    assert session.turn == 1


def test_the_conversation_accumulates_both_sides(monkeypatch, captured_console):
    client = RecordingClient()
    session = _run(monkeypatch, ["first?", "second?", "exit"], client=client)

    assert [m["role"] for m in session.history] == [
        "user", "assistant", "user", "assistant"]
    assert session.history[1]["content"] == "The host was scanned."
    assert session.turn == 2


# ── Streaming failures ───────────────────────────────────────────────────────

def test_a_failed_turn_is_rolled_back_out_of_the_history(monkeypatch, captured_console):
    """A dangling user turn would make the *next* request malformed, so one
    transient API error would break every following question in the session.
    """
    import anthropic

    client = RecordingClient(stream_error=anthropic.APIError(
        message="upstream error", request=None, body=None))
    session = _run(monkeypatch, ["what happened?", "exit"], client=client)

    assert session.history == []
    assert session.turn == 0
    assert "API Error" in captured_console.getvalue()


def test_the_session_continues_after_a_failed_turn(monkeypatch, captured_console):
    import anthropic

    class Flaky(RecordingClient):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def stream_message(self, messages, on_chunk):
            self.calls += 1
            if self.calls == 1:
                raise anthropic.APIError(message="rate limited", request=None, body=None)
            on_chunk(self.reply)
            return self.reply

    client = Flaky()
    session = _run(monkeypatch, ["first?", "second?", "exit"], client=client)

    assert client.calls == 2
    assert [m["content"] for m in session.history] == ["second?", "The host was scanned."]


def test_the_error_class_resolves_even_without_the_anthropic_package(monkeypatch):
    """The REPL runs on providers that have nothing to do with Anthropic."""
    import builtins

    real_import = builtins.__import__

    def no_anthropic(name, *a, **kw):
        if name == "anthropic":
            raise ImportError("not installed")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_anthropic)
    assert chat_mod.anthropic_error() is Exception


# ── /report ──────────────────────────────────────────────────────────────────

def test_report_writes_a_timestamped_file_next_to_the_capture(monkeypatch, tmp_path,
                                                              captured_console):
    client = RecordingClient()
    session = _run(monkeypatch, ["/report", "exit"], client=client,
                   report_dir=str(tmp_path))

    written = list(tmp_path.glob("report_attack_*.md"))
    assert len(written) == 1
    assert written[0].read_text(encoding="utf-8") == "# SOC Report\n\nBody."
    assert "Report saved" in captured_console.getvalue()
    assert [m["role"] for m in session.history] == ["user", "assistant"]


def test_report_honours_an_explicit_filename(monkeypatch, tmp_path, captured_console):
    target = tmp_path / "nested" / "incident.md"
    _run(monkeypatch, [f"/report {target}", "exit"], report_dir=str(tmp_path))

    assert target.read_text(encoding="utf-8") == "# SOC Report\n\nBody."


def test_a_failed_report_generation_is_reported_and_not_saved(monkeypatch, tmp_path,
                                                              captured_console):
    client = RecordingClient(report_error=RuntimeError("quota exhausted"))
    session = _run(monkeypatch, ["/report", "exit"], client=client,
                   report_dir=str(tmp_path))

    assert list(tmp_path.glob("*.md")) == []
    assert session.history == []
    assert "Report generation failed" in captured_console.getvalue()
    assert "quota exhausted" in captured_console.getvalue()


def test_a_report_that_cannot_be_written_is_printed_instead_of_lost(monkeypatch,
                                                                    tmp_path,
                                                                    captured_console):
    """The model already spent the tokens. Losing the text because the path is
    read-only would be the worst possible outcome."""
    from pathlib import Path

    real_write = Path.write_text

    def refuse(self, *a, **kw):
        if self.suffix == ".md":
            raise PermissionError("read-only filesystem")
        return real_write(self, *a, **kw)

    monkeypatch.setattr(Path, "write_text", refuse)

    session = _run(monkeypatch, ["/report", "exit"], report_dir=str(tmp_path))
    out = captured_console.getvalue()

    assert "Could not save report" in out
    assert "Report content" in out
    assert "SOC Report" in out
    assert session.history == [], "an unsaved report is not added to the conversation"


def test_a_saved_report_is_previewed_and_kept_for_follow_up_questions(monkeypatch,
                                                                      tmp_path,
                                                                      captured_console):
    long_report = "\n".join(f"line {i}" for i in range(60))
    client = RecordingClient(report=long_report)
    session = _run(monkeypatch, ["/report", "exit"], client=client,
                   report_dir=str(tmp_path))
    out = captured_console.getvalue()

    assert "Report Preview (first 30 lines)" in out
    assert "line 0" in out
    assert "line 59" not in out, "only the first 30 lines are previewed"
    assert session.history[1]["content"] == long_report


def test_the_report_directory_defaults_to_the_working_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    session = InteractiveChat(RecordingClient(), pcap_name="attack.pcap")

    assert session.report_dir == os.getcwd()
