"""
Interactive Chat Session — hacker-terminal chat UI for PacketIQ Copilot.

Supports:
  - Free-form questions about the loaded PCAP
  - Slash commands: /summary /iocs /timeline /mitre /actions /report /clear /help
  - Streaming responses rendered live in the terminal
  - Full conversation history maintained in memory
  - Report saving to Markdown file
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text

from packetiq.copilot.client import CopilotClient
from packetiq.copilot.prompts import HELP_TEXT, SLASH_PROMPTS
from packetiq.display.terminal import TerminalUI

console = Console(highlight=False)
ui      = TerminalUI()

# Slash commands that trigger pre-written prompts
SLASH_COMMANDS = set(SLASH_PROMPTS.keys()) | {"clear", "help", "exit", "quit", "q"}


class InteractiveChat:
    """
    Manages a multi-turn conversation with PacketIQ Copilot.
    Each call to run() starts the interactive REPL.
    """

    def __init__(
        self,
        client:     CopilotClient,
        pcap_name:  str = "capture.pcap",
        report_dir: Optional[str] = None,
    ):
        self.client     = client
        self.pcap_name  = pcap_name
        self.report_dir = report_dir or os.getcwd()
        self.history:   list[dict] = []   # Anthropic messages format
        self.turn:      int = 0

    def run(self):
        """Main REPL loop — blocks until user exits."""
        self._print_chat_header()
        console.print(Markdown(HELP_TEXT))

        while True:
            try:
                user_input = self._prompt()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim green]Session ended.[/dim green]")
                break

            if not user_input.strip():
                continue

            # ── Slash command routing ───────────────────────────────
            cmd = user_input.strip().lower().lstrip("/")

            if cmd in ("exit", "quit", "q"):
                console.print("[dim green]Exiting PacketIQ Copilot.[/dim green]")
                break

            if cmd == "help":
                console.print(Markdown(HELP_TEXT))
                continue

            if cmd == "clear":
                self.history.clear()
                self.turn = 0
                console.print("[dim green]Conversation history cleared.[/dim green]\n")
                continue

            # Check for /report with optional filename
            if cmd.startswith("report"):
                parts = user_input.strip().split(None, 1)
                filename = parts[1] if len(parts) > 1 else None
                self._handle_report(filename)
                continue

            # Other slash commands → inject pre-written prompt
            if user_input.strip().startswith("/") and cmd in SLASH_PROMPTS:
                actual_prompt = SLASH_PROMPTS[cmd]
            else:
                actual_prompt = user_input.strip()

            # ── Send to Claude ──────────────────────────────────────
            self.turn += 1
            self.history.append({"role": "user", "content": actual_prompt})

            self._print_thinking_prefix()
            full_response = self._stream_response()
            console.print()  # newline after streaming

            self.history.append({"role": "assistant", "content": full_response})

    # ── Private: UI rendering ─────────────────────────────────────────────────

    def _print_chat_header(self):
        console.print()
        title = Text("PacketIQ AI Copilot", style="bold green")
        model_label = getattr(self.client, "model_label", "claude-sonnet-4-6")
        subtitle = Text(f"  Loaded: {self.pcap_name}  |  {model_label}",
                        style="dim green")
        console.print(Panel(
            f"{title}\n{subtitle}",
            border_style="green",
            box=box.DOUBLE_EDGE,
            padding=(0, 2),
        ))
        console.print()

    def _prompt(self) -> str:
        """Display the hacker-style input prompt and read user input."""
        console.print(
            "[dim green]┌─[/dim green][bold green][ANALYST][/bold green]"
            "[dim green]──────────────────────────────────────[/dim green]"
        )
        console.print("[dim green]└──[/dim green] ", end="")
        return input()

    def _print_thinking_prefix(self):
        console.print()
        console.print(
            "[dim green]┌─[/dim green][bold cyan][COPILOT][/bold cyan]"
            "[dim green]──────────────────────────────────────[/dim green]"
        )
        console.print("[dim green]└──[/dim green] ", end="", flush=True)

    def _stream_response(self) -> str:
        """Stream Claude's response, printing each chunk as it arrives."""
        full_text = ""

        def on_chunk(chunk: str):
            nonlocal full_text
            # Print chunk without newline prefix — continuation of the └── line
            print(chunk, end="", flush=True)
            full_text += chunk

        try:
            full_text = self.client.stream_message(
                messages=self.history,
                on_chunk=on_chunk,
            )
        except anthropic_error() as e:
            console.print(f"\n[bold red]API Error:[/bold red] {e}")
            # Remove the failed user message from history
            if self.history and self.history[-1]["role"] == "user":
                self.history.pop()
            self.turn = max(0, self.turn - 1)

        return full_text

    def _handle_report(self, filename: Optional[str]):
        """Generate a full SOC report and save to file."""
        console.print("[bold cyan]Generating SOC report (non-streaming)...[/bold cyan]")

        try:
            report_text = self.client.single_message(SLASH_PROMPTS["report"])
        except Exception as e:
            console.print(f"[bold red]Report generation failed:[/bold red] {e}")
            return

        # Determine output path
        if filename:
            out_path = Path(filename)
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            stem = Path(self.pcap_name).stem
            out_path = Path(self.report_dir) / f"report_{stem}_{ts}.md"

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(report_text, encoding="utf-8")
            console.print(f"[bold green]Report saved:[/bold green] {out_path.resolve()}")
        except Exception as e:
            console.print(f"[bold red]Could not save report:[/bold red] {e}")
            console.print("[dim]Report content:[/dim]")
            console.print(Markdown(report_text))
            return

        # Also add to conversation history so analyst can ask follow-ups
        self.history.append({"role": "user",      "content": SLASH_PROMPTS["report"]})
        self.history.append({"role": "assistant",  "content": report_text})

        # Show a preview (first 30 lines)
        preview_lines = report_text.split("\n")[:30]
        console.print("\n[dim green]─── Report Preview (first 30 lines) ───[/dim green]")
        console.print(Markdown("\n".join(preview_lines)))
        console.print("[dim green]─── (full report saved to file) ───[/dim green]\n")


def anthropic_error():
    """Return the base exception class from the anthropic package."""
    try:
        import anthropic as _a
        return _a.APIError
    except Exception:
        return Exception
