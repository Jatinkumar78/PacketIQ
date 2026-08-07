"""
Terminal UI - Hacker-themed display layer for PacketIQ.
Uses rich for styled, matrix-style terminal output.
"""

import sys
from datetime import datetime

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

# Global console with forced terminal color support
console = Console(highlight=False)

BANNER = r"""
██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗██╗ ██████╗
██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██║██╔═══██╗
██████╔╝███████║██║     █████╔╝ █████╗     ██║   ██║██║   ██║
██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ██║██║▄▄ ██║
██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ██║╚██████╔╝
╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚══▀▀═╝
"""

TAGLINE = "[ AI PCAP Forensics & SOC Copilot ] | Defensive Intelligence Platform"


class TerminalUI:
    """All terminal rendering logic — banner, tables, panels, progress."""

    def __init__(self):
        self.console = console

    def route_chrome_to_stderr(self) -> None:
        """Send styled human output to stderr, leaving stdout for data alone.

        Commands that emit a JSON/YAML document write it to stdout so it can be
        redirected or piped. The banner, section headers and progress bars would
        otherwise land in the same stream and make the document unusable.
        """
        self.console = Console(highlight=False, stderr=True)

    def print_data(self, text: str) -> None:
        """Write machine-readable output to stdout exactly as given.

        Deliberately bypasses rich. Its console soft-wraps at the terminal width —
        which inserts newlines *inside* JSON string literals and makes the
        document unparseable — and it interprets square-bracketed text as style
        markup, so a CVE description containing "[bold]" silently lost characters.
        """
        sys.stdout.write(text + "\n")
        sys.stdout.flush()

    def print_banner(self):
        from packetiq import __version__

        banner_text = Text(BANNER, style="bold green")
        tagline_text = Text(TAGLINE, style="dim green", justify="center")
        # Read the version rather than repeating it, so the banner cannot drift
        # from the package the user actually has installed.
        version_text = Text(f"v{__version__}  |  github.com/PacketIQ  |  SOC Ready",
                            style="dim cyan", justify="center")

        self.console.print()
        self.console.print(Align.center(banner_text))
        self.console.print(Align.center(tagline_text))
        self.console.print(Align.center(version_text))
        self.console.print()

    def print_section(self, title: str, subtitle: str = ""):
        ts = datetime.now().strftime("%H:%M:%S")
        header = f"[bold green]>[/bold green] [bold white]{title}[/bold white]"
        if subtitle:
            header += f" [dim]— {subtitle}[/dim]"
        self.console.print(f"\n[dim green][{ts}][/dim green] {header}")
        self.console.print("[dim green]" + "─" * 72 + "[/dim green]")

    def print_status(self, msg: str, status: str = "info"):
        icons = {
            "info":    ("[cyan]>[/cyan]", "cyan"),
            "ok":      ("[bold green]✓[/bold green]", "green"),
            "warn":    ("[bold yellow]![/bold yellow]", "yellow"),
            "error":   ("[bold red]✗[/bold red]", "red"),
            "loading": ("[bold cyan]~[/bold cyan]", "cyan"),
        }
        icon, color = icons.get(status, icons["info"])
        self.console.print(f"  {icon}  [{color}]{msg}[/{color}]")

    def print_key_value(self, key: str, value: str, color: str = "green"):
        self.console.print(f"  [dim]├─[/dim] [dim white]{key}:[/dim white] [bold {color}]{value}[/bold {color}]")

    def print_summary_panel(self, title: str, data: dict):
        """Render a summary box with key-value pairs."""
        lines = []
        for k, v in data.items():
            lines.append(f"[dim white]{k:<22}[/dim white] [bold green]{v}[/bold green]")
        content = "\n".join(lines)
        panel = Panel(
            content,
            title=f"[bold green][ {title} ][/bold green]",
            border_style="green",
            padding=(1, 2),
            box=box.DOUBLE_EDGE,
        )
        self.console.print(panel)

    def print_table(self, title: str, columns: list[tuple], rows: list[list], max_rows: int = 50):
        """
        Render a hacker-themed rich table.
        columns: list of (header_name, style, justify)
        rows: list of row data (strings)
        """
        table = Table(
            title=f"[bold green]{title}[/bold green]",
            box=box.SIMPLE_HEAD,
            border_style="green",
            header_style="bold green",
            title_style="bold green",
            show_lines=False,
            padding=(0, 1),
        )
        for col_name, col_style, col_justify in columns:
            table.add_column(col_name, style=col_style, justify=col_justify)

        display_rows = rows[:max_rows]
        for row in display_rows:
            table.add_row(*[str(cell) for cell in row])

        self.console.print(table)
        if len(rows) > max_rows:
            self.console.print(
                f"  [dim yellow]  ... {len(rows) - max_rows} more rows truncated (use --full to see all)[/dim yellow]"
            )

    def print_alert(self, level: str, message: str, detail: str = ""):
        """Print a colored alert box. level: CRITICAL / HIGH / MEDIUM / LOW."""
        colors = {
            "CRITICAL": ("red", "bold red"),
            "HIGH":     ("yellow", "bold yellow"),
            "MEDIUM":   ("cyan", "bold cyan"),
            "LOW":      ("green", "bold green"),
        }
        border, text_style = colors.get(level.upper(), ("white", "white"))
        content = f"[{text_style}]{message}[/{text_style}]"
        if detail:
            content += f"\n[dim]{detail}[/dim]"
        self.console.print(
            Panel(content, title=f"[{border}][ {level.upper()} ][/{border}]", border_style=border, padding=(0, 2))
        )

    def make_progress(self, description: str = "Processing..."):
        """Return a Rich Progress context manager with hacker styling."""
        return Progress(
            SpinnerColumn(spinner_name="dots", style="green"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=40, style="green", complete_style="bold green"),
            TextColumn("[bold cyan]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )

    def print_divider(self, char: str = "─", color: str = "dim green"):
        self.console.print(f"[{color}]" + char * 72 + f"[/{color}]")

    def print_raw(self, msg: str):
        self.console.print(msg)
