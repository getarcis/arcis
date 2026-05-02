"""
Arcis CLI — command dispatcher.

Usage:
    arcis              # show command catalog
    arcis --list       # show command catalog (verbose)
    arcis scan <url> [options]
    arcis audit <path> [options]
    arcis sca [path] [options]
"""

import os
import sys


# ── ANSI helpers (minimal, mirror the per-command CLIs) ─────────────────────
_USE_COLOR = os.environ.get("NO_COLOR") is None and sys.stdout.isatty()


def _c(text: str, *codes: str) -> str:
    if not _USE_COLOR:
        return text
    return "".join(codes) + text + "\033[0m"


_BOLD = "\033[1m"
_DIM = "\033[2m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_WHITE = "\033[37m"


def _print_catalog(verbose: bool = False) -> None:
    """Render the command catalog. ``verbose`` adds the example lines."""
    try:
        from arcis import __version__
    except Exception:
        __version__ = "?"

    print()
    print(_c(f"  Arcis", _BOLD, _CYAN) + _c(f"  v{__version__}", _DIM))
    print(_c("  Zero-dep security middleware + scanners for Node, Python, Go.", _DIM))
    print()
    print(_c("  Commands", _BOLD))

    rows = [
        ("scan",
         "Send live attack payloads to a running app and report which got through.",
         "arcis scan http://localhost:8000 --route POST:/echo --field q"),
        ("audit",
         "Static-analyse Python / JS / TS source for unsafe patterns.",
         "arcis audit ."),
        ("sca",
         "Match installed dependencies against the supply-chain threat database.",
         "arcis sca ."),
        ("update",
         "Check PyPI for a newer Arcis release.",
         "arcis update --apply"),
    ]

    for name, desc, example in rows:
        print(f"    {_c(name.ljust(8), _BOLD, _GREEN)} {desc}")
        if verbose:
            print(f"             {_c(example, _DIM)}")

    print()
    print(_c("  Discovery", _BOLD))
    print(f"    {_c('--list'.ljust(8), _BOLD, _CYAN)}   Show this catalog (verbose, with examples).")
    print(f"    {_c('<cmd> --list'.ljust(14), _BOLD, _CYAN)}  List what that command covers (categories / rules / threats).")
    print(f"    {_c('<cmd> --help'.ljust(14), _BOLD, _CYAN)}  Show full flags for that command.")
    print()
    print(_c("  Quick test (run all three from your project root)", _BOLD))
    print(_c("    arcis sca .  &&  arcis audit .  &&  arcis scan http://localhost:8000 \\", _DIM))
    print(_c("        --route POST:/echo --field q --categories xss", _DIM))
    print()


def _try_interactive_picker() -> bool:
    """Show an arrow-key picker if `questionary` is installed and stdin is a
    TTY. Returns True if the picker handled the run (already dispatched into
    a subcommand or the user quit), False if the caller should fall through
    to the static catalog.

    The picker is opt-in: install with `pip install "arcis[interactive]"`.
    Plain `pip install arcis` keeps the zero-deps default and falls back to
    the static catalog automatically.
    """
    if not sys.stdin.isatty():
        return False
    try:
        import questionary  # type: ignore[import-untyped]
    except ImportError:
        return False

    print()
    choice = questionary.select(
        "Arcis — what do you want to do?",
        choices=[
            questionary.Choice("scan    Send live attacks to a running app", value="scan"),
            questionary.Choice("audit   Scan source code for unsafe patterns", value="audit"),
            questionary.Choice("sca     Check dependencies for known compromises", value="sca"),
            questionary.Choice("update  Check PyPI for a newer Arcis release", value="update"),
            questionary.Choice("Quit", value=None),
        ],
    ).ask()

    if choice is None:
        return True  # user picked Quit (or hit Ctrl-C)

    # Reset argv so the dispatched subcommand sees a clean parse.
    if choice == "audit":
        path = questionary.path(
            "Path to scan?", default=".", only_directories=False
        ).ask() or "."
        sys.argv = ["arcis audit", path]
        from arcis.cli.audit import main as audit_main
        audit_main()
        return True

    if choice == "sca":
        path = questionary.path(
            "Project root?", default=".", only_directories=True
        ).ask() or "."
        sys.argv = ["arcis sca", path]
        from arcis.cli.sca import main as sca_main
        sca_main()
        return True

    if choice == "scan":
        url = questionary.text(
            "Server URL?", default="http://localhost:8000"
        ).ask()
        if not url:
            return True
        route = questionary.text(
            "Route to test? (METHOD:/path)", default="POST:/echo"
        ).ask() or "POST:/echo"
        field = questionary.text(
            "JSON field name to inject into?", default="q"
        ).ask() or "q"
        sys.argv = ["arcis scan", url, "--route", route, "--field", field]
        from arcis.cli.scan import main as scan_main
        scan_main()
        return True

    if choice == "update":
        sys.argv = ["arcis update"]
        from arcis.cli.update import main as update_main
        update_main()
        return True

    return False


def main() -> None:
    # No args → try interactive picker first, fall back to static catalog.
    # --list / -h / --help / -V always print directly (scriptable, predictable).
    if len(sys.argv) < 2:
        if _try_interactive_picker():
            return
        _print_catalog(verbose=False)
        sys.exit(0)

    arg = sys.argv[1]
    if arg in ("--list", "-l"):
        _print_catalog(verbose=True)
        sys.exit(0)
    if arg in ("-h", "--help"):
        _print_catalog(verbose=False)
        print(_c("  Run 'arcis <command> --help' for full flags.", _DIM))
        print()
        sys.exit(0)
    if arg in ("-V", "--version"):
        try:
            from arcis import __version__
            print(__version__)
        except Exception:
            print("?")
        sys.exit(0)

    command = arg
    # Remove the subcommand so the sub-parser sees clean argv
    sys.argv = [f"arcis {command}"] + sys.argv[2:]

    if command == "scan":
        from arcis.cli.scan import main as scan_main
        scan_main()
    elif command == "audit":
        from arcis.cli.audit import main as audit_main
        audit_main()
    elif command == "sca":
        from arcis.cli.sca import main as sca_main
        sca_main()
    elif command == "update":
        from arcis.cli.update import main as update_main
        update_main()
    else:
        print(f"arcis: unknown command '{command}'")
        print("Run 'arcis --list' for available commands.")
        sys.exit(1)
