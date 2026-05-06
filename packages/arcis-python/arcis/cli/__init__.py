"""
Arcis CLI command dispatcher.

Usage:
    arcis              # interactive picker (TTY) or command catalog (non-TTY)
    arcis --list       # show command catalog (verbose, with examples)
    arcis scan <url> [options]
    arcis audit <path> [options]
    arcis sca [path] [options]
    arcis update [--apply]

The no-arg path drops into a guided session when stdout is a TTY: pick a
verb, fill in path/URL, run. On non-TTY (CI, pipes) it prints the static
catalog and exits cleanly so scripted runs never hang on a prompt.
"""

import sys

from rich.prompt import Prompt

from arcis.cli._console import console


def _print_catalog(verbose: bool = False) -> None:
    """Render the command catalog. ``verbose`` adds the example lines."""
    try:
        from arcis import __version__
    except Exception:
        __version__ = "?"

    console.print()
    console.print(f"  [bold cyan]Arcis[/]  [dim]v{__version__}[/]")
    console.print("  [dim]Zero-dep security middleware + scanners for Node, Python, Go.[/]")
    console.print()
    console.print("  [bold]Commands[/]")

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
        console.print(f"    [bold green]{name.ljust(8)}[/] {desc}")
        if verbose:
            console.print(f"             [dim]{example}[/]")

    console.print()
    console.print("  [bold]Discovery[/]")
    console.print(f"    [bold cyan]{'--list'.ljust(8)}[/]   Show this catalog (verbose, with examples).")
    console.print(f"    [bold cyan]{'<cmd> --list'.ljust(14)}[/]  List what that command covers (categories / rules / threats).")
    console.print(f"    [bold cyan]{'<cmd> --help'.ljust(14)}[/]  Show full flags for that command.")
    console.print()
    console.print("  [bold]Quick test (run all three from your project root)[/]")
    console.print(
        "    [dim]arcis sca .  &&  arcis audit .  &&  arcis scan http://localhost:8000 \\[/]"
    )
    console.print(
        "    [dim]    --route POST:/echo --field q --categories xss[/]"
    )
    console.print()


def _try_interactive_picker() -> bool:
    """Show a guided picker if stdin and stdout are both TTYs.

    Returns True when the picker has handled the run (already dispatched a
    subcommand or the user quit). Returns False when the caller should fall
    through to the static catalog.

    Implemented with rich.prompt so the dependency surface stays the same
    as the rest of the CLI output. Plain `pip install arcis` ships this by
    default. There is no separate `[interactive]` extra.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False

    console.print()
    console.print("  [bold cyan]Arcis[/]  [dim]Pick a verb to run.[/]")
    console.print()
    choice = Prompt.ask(
        "  [bold]What do you want to do?[/]",
        choices=["scan", "audit", "sca", "update", "quit"],
        default="audit",
    )

    if choice == "quit":
        return True

    if choice == "audit":
        path = Prompt.ask("  Path to scan", default=".")
        sys.argv = ["arcis audit", path]
        from arcis.cli.audit import main as audit_main
        audit_main()
        return True

    if choice == "sca":
        path = Prompt.ask("  Project root", default=".")
        sys.argv = ["arcis sca", path]
        from arcis.cli.sca import main as sca_main
        sca_main()
        return True

    if choice == "scan":
        # Phase A auto-discovery handles target + routes inside scan.main().
        # The picker just hands off so the user gets the full discovery
        # flow (env / control-plane / port sniff + source-aware routes)
        # instead of three separate prompts here.
        sys.argv = ["arcis scan"]
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
    # No args. Try guided picker first, fall back to static catalog on
    # non-TTY. --list / -h / --help / -V always print directly so scripted
    # callers get predictable output.
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
        console.print("  [dim]Run 'arcis <command> --help' for full flags.[/]")
        console.print()
        sys.exit(0)
    if arg in ("-V", "--version"):
        try:
            from arcis import __version__
            print(__version__)
        except Exception:
            print("?")
        sys.exit(0)

    command = arg
    # Strip the subcommand so the sub-parser sees clean argv.
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
        console.print(f"arcis: unknown command '{command}'")
        console.print("Run 'arcis --list' for available commands.")
        sys.exit(1)
