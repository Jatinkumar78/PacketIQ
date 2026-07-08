"""
Timeline Renderer — hacker-terminal display of the reconstructed timeline.

Output sections:
  1. Activity density sparkline (ASCII bar)
  2. Kill chain phase coverage summary
  3. Chronological event table with phase banners and gap markers
  4. Pivot point summary
"""

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from packetiq.timeline.models import CATEGORY_EMOJI, PHASE_BADGE, Category, Timeline, TimelineEvent
from packetiq.utils.helpers import format_duration, ts_to_str

console = Console(highlight=False)

# ── Phase colours ─────────────────────────────────────────────────────────────
PHASE_COLOR = {
    "Reconnaissance":       "bright_cyan",
    "Weaponization":        "bright_yellow",
    "Delivery":             "yellow",
    "Exploitation":         "bright_red",
    "Installation":         "red",
    "Command & Control":    "magenta",
    "Actions on Objectives":"bright_magenta",
}

SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "LOW":      "bold green",
}

# ── Bar characters ────────────────────────────────────────────────────────────
BAR_CHARS = " ▁▂▃▄▅▆▇█"


class TimelineRenderer:

    def __init__(self, ui=None):
        # Accept optional TerminalUI for section headers; fall back to inline
        self._ui = ui

    def render(self, timeline: Timeline, max_events: int = 80):
        """Full timeline render — all sections."""
        self._render_activity_bar(timeline)
        self._render_phase_coverage(timeline)
        self._render_event_table(timeline, max_events)
        self._render_pivot_summary(timeline)

    # ── Activity bar ──────────────────────────────────────────────────────────

    def _render_activity_bar(self, tl: Timeline):
        console.print()
        console.print(
            "[bold green]► ACTIVITY TIMELINE[/bold green]  "
            f"[dim]({ts_to_str(tl.capture_start)} → {ts_to_str(tl.capture_end)} | "
            f"{format_duration(tl.duration)})[/dim]"
        )

        if not tl.activity_bar:
            console.print("  [dim]Insufficient data for activity bar.[/dim]")
            return

        ab  = tl.activity_bar
        max_v = max(ab.buckets) or 1

        # Build the sparkline
        bar_chars: list[str] = []
        for v in ab.buckets:
            idx = int(v / max_v * (len(BAR_CHARS) - 1))
            bar_chars.append(BAR_CHARS[idx])

        bar_str = "".join(bar_chars)

        # Colour: high-activity buckets are brighter
        bar_text = Text()
        for i, ch in enumerate(bar_chars):
            density = ab.buckets[i] / max_v
            if density >= 0.75:
                style = "bold red"
            elif density >= 0.4:
                style = "bold yellow"
            elif density > 0:
                style = "green"
            else:
                style = "dim green"
            bar_text.append(ch, style=style)

        console.print(
            Panel(
                bar_text,
                title="[bold green][ Event Density ][/bold green]",
                border_style="dim green",
                padding=(0, 1),
                box=box.SIMPLE,
            )
        )
        console.print(
            f"  [dim]Each column = {format_duration(ab.bucket_secs)} | "
            f"Peak: {max(ab.buckets)} events | Total plotted: {ab.total_events}[/dim]"
        )

    # ── Phase coverage summary ─────────────────────────────────────────────────

    def _render_phase_coverage(self, tl: Timeline):
        phases = tl.phases_seen
        if not phases:
            return

        console.print()
        console.print("[bold green]► KILL CHAIN COVERAGE[/bold green]")

        phase_parts: list[Text] = []
        for i, phase in enumerate(phases):
            color   = PHASE_COLOR.get(phase, "white")
            badge   = PHASE_BADGE.get(phase, phase)
            t       = Text()
            if i > 0:
                t.append(" → ", style="dim green")
            t.append(badge, style=f"bold {color}")
            phase_parts.append(t)

        line = Text()
        for p in phase_parts:
            line.append_text(p)

        console.print("  ", end="")
        console.print(line)

        # Per-phase event counts
        phase_counts: dict[str, int] = {}
        for ev in tl.events:
            if ev.phase and ev.category not in (Category.GAP, Category.PIVOT):
                phase_counts[ev.phase] = phase_counts.get(ev.phase, 0) + 1

        console.print()
        for phase in phases:
            color = PHASE_COLOR.get(phase, "white")
            count = phase_counts.get(phase, 0)
            console.print(f"  [{color}]{phase:<28}[/{color}] [dim]{count} event(s)[/dim]")

    # ── Event table ────────────────────────────────────────────────────────────

    def _render_event_table(self, tl: Timeline, max_events: int):
        console.print()
        console.print(
            "[bold green]► CHRONOLOGICAL EVENT TABLE[/bold green]  "
            f"[dim]({len(tl.events)} entries)[/dim]"
        )
        console.print("[dim green]" + "─" * 72 + "[/dim green]")

        visible = [e for e in tl.events][:max_events]
        prev_phase = ""

        for ev in visible:
            # Phase banner on phase change
            if ev.phase and ev.phase != prev_phase and ev.category not in (Category.GAP,):
                color = PHASE_COLOR.get(ev.phase, "white")
                badge = PHASE_BADGE.get(ev.phase, ev.phase)
                console.print(
                    f"\n  [bold {color}]{'─'*5} {badge} {ev.phase.upper()} {'─'*5}[/bold {color}]"
                )
                prev_phase = ev.phase

            self._render_event_line(ev)

        if len(tl.events) > max_events:
            console.print(
                f"\n  [dim yellow]  … {len(tl.events) - max_events} more events — "
                "use --full to see all[/dim yellow]"
            )

    def _render_event_line(self, ev: TimelineEvent):
        ts_str = ev.ts_str[11:23] if len(ev.ts_str) > 11 else ev.ts_str   # just time part

        if ev.category == Category.GAP:
            console.print(
                f"  [dim green]  {ts_str}  [/dim green]"
                f"[dim]{'·' * 10}  {ev.description}  {'·' * 10}[/dim]"
            )
            return

        if ev.category == Category.PIVOT:
            color = PHASE_COLOR.get(ev.phase, "white")
            console.print(
                f"\n  [dim green]{ts_str}[/dim green]  "
                f"[bold {color}]🔀 {ev.description}[/bold {color}]"
            )
            return

        # Severity prefix
        sev_tag = ""
        if ev.severity:
            sev_color = SEV_COLOR.get(ev.severity.value, "white")
            sev_tag   = f"[{sev_color}]{ev.severity.value[:4]}[/{sev_color}] "

        # Source → dest
        src_dst = ""
        if ev.src_ip:
            src_dst = f"[dim cyan]{ev.src_ip}[/dim cyan]"
            if ev.dst_ip:
                dst = ev.dst_ip
                if ev.dst_port:
                    dst += f":{ev.dst_port}"
                src_dst += f"[dim] → [/dim][dim cyan]{dst}[/dim cyan]"

        emoji = CATEGORY_EMOJI.get(ev.category, "•")

        # MITRE badge
        mitre_tag = f" [dim magenta][{ev.mitre_id}][/dim magenta]" if ev.mitre_id else ""

        # Chain membership
        chain_tag = ""
        if ev.chain_name:
            short = ev.chain_name[:30] + ("…" if len(ev.chain_name) > 30 else "")
            chain_tag = f" [dim yellow](⛓ {short})[/dim yellow]"

        # Truncate description
        desc = ev.description
        if len(desc) > 65:
            desc = desc[:62] + "…"

        console.print(
            f"  [dim green]{ts_str}[/dim green]  "
            f"{emoji} {sev_tag}[white]{desc}[/white]{mitre_tag}"
        )
        if src_dst:
            console.print(f"  {'':>13}  [dim]└── {src_dst}[/dim]{chain_tag}")

    # ── Pivot summary ─────────────────────────────────────────────────────────

    def _render_pivot_summary(self, tl: Timeline):
        if not tl.pivot_points:
            return

        console.print()
        console.print(
            "[bold green]► ATTACK PROGRESSION PIVOTS[/bold green]  "
            f"[dim]({len(tl.pivot_points)} phase transition(s))[/dim]"
        )
        console.print("[dim green]" + "─" * 72 + "[/dim green]")

        for pv in tl.pivot_points:
            ts_str = pv.ts_str[11:23] if len(pv.ts_str) > 11 else pv.ts_str
            color  = PHASE_COLOR.get(pv.phase, "white")
            console.print(
                f"  [dim green]{ts_str}[/dim green]  "
                f"[bold {color}]🔀  {pv.description}[/bold {color}]"
            )
