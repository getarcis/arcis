"""
arcis update — check PyPI for a newer Arcis release.

Why this is a "check + suggest" rather than auto-upgrade by default:
- Running ``pip install --upgrade`` from inside the package itself can
  break the running interpreter mid-run, leak into the wrong venv, or
  require root in system installs.
- The honest UX is: tell the user what's available and the exact command
  to run. ``--apply`` opts in to actually invoking pip when the user has
  decided that's safe in their environment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Optional, Tuple


PYPI_JSON_URL = "https://pypi.org/pypi/arcis/json"
PYPI_TIMEOUT_SECONDS = 5


# ── ANSI helpers (same minimal palette as the rest of the CLIs) ──────────


def _c(text: str, *codes: str, no_color: bool = False) -> str:
    if no_color:
        return text
    return "".join(codes) + text + "\033[0m"


_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"


# ── Version handling ─────────────────────────────────────────────────────


def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    """Convert "1.4.4" -> (1, 4, 4). Returns None on anything non-trivial
    (pre-releases, dev builds, local versions) so we err on the side of
    "don't claim the user is outdated when we're not sure"."""
    parts = v.strip().split(".")
    out: Tuple[int, ...] = ()
    for p in parts:
        if not p.isdigit():
            return None
        out = out + (int(p),)
    return out


def _fetch_latest_version() -> Optional[str]:
    """Hit PyPI's JSON endpoint and return ``info.version``. Returns None
    on any network/parse error — caller decides how to surface that.
    Uses stdlib urllib so we don't add a runtime dependency."""
    try:
        req = urllib.request.Request(PYPI_JSON_URL, headers={"User-Agent": "arcis-update-check"})
        with urllib.request.urlopen(req, timeout=PYPI_TIMEOUT_SECONDS) as resp:
            data = json.load(resp)
        info = data.get("info") or {}
        return info.get("version")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def _current_version() -> str:
    try:
        from arcis import __version__
        return __version__
    except Exception:
        return "?"


# ── Output ───────────────────────────────────────────────────────────────


def _print_status(current: str, latest: Optional[str], no_color: bool) -> int:
    """Render the version comparison and return the desired exit code:
    0 = up-to-date, 1 = outdated, 2 = unknown (network failure)."""
    bold = "" if no_color else _BOLD
    dim = "" if no_color else _DIM
    green = "" if no_color else _GREEN
    yellow = "" if no_color else _YELLOW
    red = "" if no_color else _RED
    cyan = "" if no_color else _CYAN
    reset = "" if no_color else "\033[0m"

    print()
    print(f"  {bold}{cyan}Arcis update check{reset}")
    print(f"  {dim}Source: {PYPI_JSON_URL}{reset}")
    print()

    if latest is None:
        print(f"    Installed   arcis {current}")
        print(f"    Latest      {yellow}? unreachable{reset}  {dim}(network error or PyPI down){reset}")
        print()
        print(f"  {dim}Try again later, or run 'pip index versions arcis' directly.{reset}")
        print()
        return 2

    cur_t = _parse_version(current)
    lat_t = _parse_version(latest)

    if cur_t is None or lat_t is None:
        # Pre-release / dev build — be honest, don't compare.
        print(f"    Installed   arcis {current}  {dim}(pre-release or dev build){reset}")
        print(f"    Latest      arcis {latest}")
        print()
        print(f"  {dim}Skipping comparison — manually decide if you want the stable release.{reset}")
        print()
        return 0

    if cur_t >= lat_t:
        print(f"    Installed   arcis {current}")
        print(f"    Latest      arcis {latest}")
        print()
        print(f"  {green}{bold}You are on the latest version.{reset}")
        print()
        return 0

    print(f"    Installed   arcis {current}")
    print(f"    Latest      {bold}arcis {latest}{reset}  {yellow}(update available){reset}")
    print()
    print(f"  {bold}Run to upgrade{reset}")
    print(f"    {green}pip install --upgrade arcis{reset}")
    print()
    print(f"  {dim}Or rerun: 'arcis update --apply' to upgrade in place.{reset}")
    print()
    return 1


# ── CLI ──────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="arcis update",
        description="Check PyPI for a newer Arcis release.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  arcis update                   check only — print what's available
  arcis update --apply           check, then run pip install --upgrade arcis
  arcis update --check           CI mode: exit 0 if up-to-date, 1 if outdated, 2 if unreachable
        """,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Run 'pip install --upgrade arcis' after the check (prompts for confirmation).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Don't print upgrade hints — exit non-zero if outdated. Designed for CI.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable coloured terminal output.",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="With --apply, skip the confirmation prompt.",
    )

    args = parser.parse_args()

    current = _current_version()
    latest = _fetch_latest_version()

    if args.check:
        # Quiet single-line CI mode.
        if latest is None:
            print("arcis: could not reach PyPI to check for updates", file=sys.stderr)
            sys.exit(2)
        cur_t = _parse_version(current)
        lat_t = _parse_version(latest)
        if cur_t is None or lat_t is None or cur_t >= lat_t:
            print(f"arcis {current} is up-to-date")
            sys.exit(0)
        print(f"arcis {current} is outdated; latest is {latest}", file=sys.stderr)
        sys.exit(1)

    exit_code = _print_status(current, latest, no_color=args.no_color)

    if args.apply and exit_code == 1:
        if not args.yes:
            try:
                response = input("Upgrade now? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(exit_code)
            if not response.startswith("y"):
                sys.exit(exit_code)
        # Use the running interpreter's pip so we hit the right venv.
        cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "arcis"]
        print(f"  $ {' '.join(cmd)}")
        result = subprocess.run(cmd)
        sys.exit(result.returncode)

    sys.exit(exit_code)
