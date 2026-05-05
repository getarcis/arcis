"""
Shared rich-based console for Arcis CLI.

Every CLI module (audit / scan / sca / update) imports from here so the
output palette, severity colors, spinner glyph, and live status behavior
stay consistent across all three scanners.

Design rules (enforced):
- One Console singleton routed to stderr for live status, stdout for results.
  Rich auto-strips ANSI on non-TTY, so `arcis audit . | cat` produces clean
  text and `arcis audit --json` is unaffected.
- Severity palette is the single source of truth. Hand-rolled ANSI in CLI
  modules is a violation.
- No emoji, no em-dashes, no AI-style flourish in any helper output.
- Machine output (--json / --sarif) bypasses this module entirely and writes
  raw text to stdout via `print()` so byte-for-byte determinism is preserved.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text


# ── Console singletons ──────────────────────────────────────────────────────
# stdout console — used for findings, summaries, "real" output a user might
# pipe to a file. Rich detects non-TTY and strips ANSI automatically.
console: Console = Console()

# stderr console — used for live status / progress / spinners. We keep these
# off stdout so `arcis audit . > findings.txt` produces a clean file without
# the spinner overlay leaking into it.
err_console: Console = Console(stderr=True)


# ── Severity palette (the single source of truth) ──────────────────────────
# Style names are rich's markup strings. Keep these in sync with the spec
# in dashboard-cli-ux-fixes.md Phase 4.
SEVERITY_STYLES = {
    "critical": "bold red",
    "high":     "bold orange3",
    "medium":   "bold yellow",
    "low":      "bold blue",
    "info":     "dim",
    "ok":       "bold green",
}

# Single-char ASCII glyphs that render safely on every terminal. Used for
# the leading marker on each finding line. We keep them ASCII so Windows
# cp1252 terminals don't render boxes.
SEVERITY_GLYPH = {
    "critical": "!!",
    "high":     "!",
    "medium":   "*",
    "low":      ".",
}


def severity_label(severity: str, *, glyph: bool = True) -> Text:
    """Return a rich Text object for a severity label, ready to print.

    `glyph=True` (default) prepends the ASCII glyph. Set glyph=False when
    the caller already has its own marker layout.
    """
    sev = severity.lower()
    style = SEVERITY_STYLES.get(sev, "default")
    label = sev.upper().ljust(8)
    if glyph:
        marker = SEVERITY_GLYPH.get(sev, "-")
        text = Text(f"{marker} {label}", style=style)
    else:
        text = Text(label, style=style)
    return text


# ── Live status context manager ────────────────────────────────────────────
@contextmanager
def live_status(initial: str = "Working...") -> Iterator["LiveStatus"]:
    """Context manager that pins a single dim status line to the terminal
    while a scan loop is running. Status updates in place; findings printed
    above it via `console.print()` stay in scrollback.

    Usage:
        with live_status("Scanning...") as status:
            for path in paths:
                status.update(f"Scanning [dim cyan]{path}[/]")
                ...
                console.print(finding_text)  # prints above the live line

    Falls through to a no-op tracker on non-TTY (so CI logs aren't filled
    with spinner control codes). The caller's `console.print()` calls still
    work normally.
    """
    # No-op path: when stderr isn't a TTY, return a tracker that swallows
    # update() calls. Rich's Live would also no-op, but going through a
    # tracker is cheaper and avoids the Live setup cost on every CI run.
    if not err_console.is_terminal:
        yield _NullStatus()
        return

    spinner = Spinner("dots", text=Text(initial, style="dim"))
    with Live(
        spinner,
        console=err_console,
        refresh_per_second=8,
        transient=True,  # clears the line on exit so summary prints clean
    ) as live:
        yield _LiveStatusAdapter(live, spinner)


class _NullStatus:
    """Tracker used when stderr is not a TTY. update() is a no-op."""
    def update(self, _text: str) -> None:
        pass


class _LiveStatusAdapter:
    """Wraps a rich.live.Live + Spinner pair so callers only need .update()."""
    def __init__(self, live: Live, spinner: Spinner) -> None:
        self._live = live
        self._spinner = spinner

    def update(self, text: str) -> None:
        self._spinner.update(text=Text.from_markup(text, style="dim"))
        self._live.update(self._spinner)


# ── Convenience: clear the live line on demand ─────────────────────────────
def clear_status() -> None:
    """Force-clear any pending status line. Most callers don't need this;
    `live_status` already clears on exit. Useful when an error path needs
    to print to stderr cleanly."""
    if err_console.is_terminal:
        err_console.print("", end="")


# ── Helpers exposed for CLI modules ────────────────────────────────────────
def is_machine_output(args) -> bool:
    """True when --json or --sarif is set on the parsed args namespace.

    Centralized so every CLI module checks the same way — and so the rule
    'machine mode bypasses rich entirely' has one chokepoint.
    """
    return bool(getattr(args, "json_output", False) or getattr(args, "sarif_output", False))


__all__ = [
    "console",
    "err_console",
    "SEVERITY_STYLES",
    "SEVERITY_GLYPH",
    "severity_label",
    "live_status",
    "clear_status",
    "is_machine_output",
]
