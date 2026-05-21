"""
arcis CLI shim.

`pip install arcis` registers this module as the `arcis` console script.
It is intentionally minimal: the heavyweight scan/audit/sca commands
live in the Rust binary distributed via `npm install -g @arcis/cli`.

This shim does two things:

1. Detect whether the real Rust CLI is installed somewhere on the
   system. If yes, exec passthrough so users can type `arcis ...`
   anywhere and the real binary handles it.

2. Otherwise, print a friendly welcome screen with the version of the
   Python SDK that's installed, instructions for getting the full CLI,
   and a couple of SDK-level operations that work without the binary
   (`arcis --version`, `arcis check '<payload>'`).

Why this shim exists: v1.4.x shipped a full Python CLI as part of the
SDK. v1.5.0 stripped `[project.scripts]` on the assumption that
`@arcis/cli` was already on npm. It wasn't, until 2026-05-21. Users who
ran `pip install arcis` between 2026-05-11 and that publish got the
SDK with no `arcis` command on PATH, which produced a confusing
"command not found" error. This shim closes that gap.

Self-recursion guard: when the shim is on PATH first (typical for
Python's `Scripts/` directory on Windows ahead of npm's global bin),
`shutil.which("arcis")` would return the shim itself, infinitely
recursing. We resolve the absolute path of `sys.argv[0]` and reject
any candidate that matches.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import List, Optional


# Version of the SDK shipping this shim. Kept in sync with
# arcis/__init__.py:__version__ — both should bump together.
SDK_VERSION = "1.5.2"


# Locations where npm install -g writes binaries. We check these in
# order; the first hit that's not us wins.
def _candidate_paths() -> List[str]:
    """Probe likely install locations for the real `arcis` binary."""
    candidates: List[str] = []

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            # npm-global default on Windows
            for name in ("arcis.cmd", "arcis.exe", "arcis.ps1", "arcis"):
                candidates.append(os.path.join(appdata, "npm", name))
        # Some Windows users have npm under USERPROFILE\AppData\Roaming\npm
        userprofile = os.environ.get("USERPROFILE", "")
        if userprofile:
            for name in ("arcis.cmd", "arcis.exe"):
                candidates.append(
                    os.path.join(userprofile, "AppData", "Roaming", "npm", name)
                )
    else:
        for prefix in (
            "/usr/local/bin",
            "/opt/homebrew/bin",
            os.path.expanduser("~/.npm-global/bin"),
            os.path.expanduser("~/.volta/bin"),
            "/usr/bin",
        ):
            candidates.append(os.path.join(prefix, "arcis"))

    # As a last attempt, ask npm itself where its global prefix is.
    try:
        result = subprocess.run(
            ["npm", "config", "get", "prefix"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            prefix = result.stdout.strip()
            if prefix:
                if sys.platform == "win32":
                    candidates.append(os.path.join(prefix, "arcis.cmd"))
                    candidates.append(os.path.join(prefix, "arcis.exe"))
                else:
                    candidates.append(os.path.join(prefix, "bin", "arcis"))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # npm not installed, or hung. Don't block on it.
        pass

    return candidates


def _is_python_entry_point(path: str) -> bool:
    """Heuristic: does this path look like a Python `console_scripts` entry
    point rather than the real Rust CLI? Used as the recursion guard.

    Strong signals:
      - Path contains `\\Scripts\\` (Windows pip install)
      - Path contains `/bin/` AND we're inside a virtualenv (sys.prefix)
      - Path is under sys.exec_prefix (the Python install root)

    The Rust CLI from `@arcis/cli` lives under `npm`'s prefix, which is
    almost never under Python's install root. False positives are
    acceptable here: worst case we miss a real CLI install and fall
    back to the welcome screen. False negatives (treating the Python
    shim as the real CLI) cause infinite recursion, which we MUST
    avoid.
    """
    normalized = path.replace("\\", "/").lower()

    # Windows pip console_scripts go into <PythonRoot>/Scripts/
    if "/scripts/" in normalized:
        return True

    # Inside a Python install / virtualenv layout
    try:
        py_root = os.path.realpath(sys.exec_prefix).replace("\\", "/").lower()
        if py_root and normalized.startswith(py_root):
            return True
    except (TypeError, ValueError, OSError):
        pass

    # Editable install: pip + setuptools/uv put a shim entry point in a
    # Python bin/ dir that ALSO contains `python` or `python.exe`. Check
    # for a sibling python interpreter.
    parent = os.path.dirname(path)
    if parent:
        for python_name in ("python", "python.exe", "python3", "python3.exe"):
            if os.path.isfile(os.path.join(parent, python_name)):
                return True

    return False


def _find_real_cli() -> Optional[str]:
    """Return the path to the real @arcis/cli binary, or None.

    Recursion guard: filters out Python entry points (the shim itself).
    Without this guard, the shim would call itself in a subprocess
    loop on systems where Python's Scripts/ dir comes before npm's
    global bin on PATH (common on Windows).
    """
    # Check PATH first; fast path when the npm bin is ahead of Python's
    # Scripts/.
    found = shutil.which("arcis")
    if found and not _is_python_entry_point(found):
        return found

    # Probe well-known npm install locations.
    for candidate in _candidate_paths():
        if not os.path.isfile(candidate):
            continue
        if _is_python_entry_point(candidate):
            continue
        return candidate

    return None


def _print_welcome() -> None:
    """Friendly help when the real CLI isn't installed.

    Two sections: how to get the full CLI, and what works without it.
    The SDK-only operations exercise the real Python detection code so
    users can verify the install before reaching for npm.
    """
    bar = "=" * 64
    print(bar)
    print(f"  Arcis Python SDK v{SDK_VERSION}")
    print(bar)
    print()
    print("  You have the Python SDK installed. The scan/audit/sca CLI")
    print("  ships separately as a native binary via npm.")
    print()
    print("  Install the full CLI:")
    print("      npm install -g @arcis/cli")
    print()
    print("  After installing, you'll get:")
    print("      arcis scan <url>      Probe a running endpoint for vulnerabilities")
    print("      arcis audit <path>    Static analysis on a source tree")
    print("      arcis sca <path>      Supply-chain scan of dependencies")
    print()
    print("  Without the CLI, you can still use the Python SDK in code:")
    print("      from arcis import sanitize_string")
    print("      from arcis.sanitizers.sanitize import scan_threats")
    print()
    print("  Quick SDK self-test from this shim:")
    print("      arcis check '<script>alert(1)</script>'")
    print("      arcis --version")
    print()
    print("  Docs:  https://github.com/Gagancm/arcis")
    print()


def _sdk_self_test(payload: str) -> int:
    """Run a payload through the Python SDK's scan_threats and print
    the result. Exists so users can verify the SDK works without the
    full CLI binary."""
    try:
        from .sanitizers.sanitize import scan_threats
    except Exception as exc:
        print(f"arcis: failed to load SDK: {exc}", file=sys.stderr)
        return 2

    result = scan_threats(payload)
    if result is None:
        print(f"clean: no threat detected in input ({len(payload)} chars)")
        return 0

    vector, rule, matched = result
    print("THREAT detected")
    print(f"  vector:  {vector}")
    print(f"  rule:    {rule}")
    print(f"  matched: {matched[:80]}")
    return 1


def main() -> int:
    """Entry point registered as `arcis` in pyproject.toml.

    Behavior:
      - With no args or `--help` or `-h`: print welcome screen.
      - With `--version` or `-V`: print SDK version + tell user about
        the separate CLI binary.
      - With `check <payload>`: run scan_threats on the payload (SDK
        self-test).
      - With any other args: try to passthrough to the real CLI; if
        not installed, print welcome screen.
    """
    args = sys.argv[1:]

    # Fast path for self-help / version. Don't probe for the CLI
    # binary on these because the Python SDK can answer them honestly.
    if not args or args[0] in ("-h", "--help"):
        # If the real CLI is on the system, defer to its help rather
        # than printing the shim's welcome.
        real_cli = _find_real_cli()
        if real_cli and args:
            try:
                os.execv(real_cli, [real_cli] + args)
            except OSError:
                pass
        _print_welcome()
        return 0

    if args[0] in ("-V", "--version"):
        print(f"arcis SDK {SDK_VERSION} (Python)")
        real_cli = _find_real_cli()
        if real_cli:
            print(f"  CLI binary available at: {real_cli}")
            # Also print the CLI's own version
            try:
                result = subprocess.run(
                    [real_cli, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                cli_ver = (result.stdout or "").strip()
                if cli_ver:
                    print(f"  CLI version: {cli_ver}")
            except (OSError, subprocess.TimeoutExpired):
                pass
        else:
            print("  CLI binary: not installed. Get it: npm install -g @arcis/cli")
        return 0

    if args[0] == "check":
        if len(args) < 2:
            print("usage: arcis check '<payload>'", file=sys.stderr)
            return 2
        return _sdk_self_test(args[1])

    # Any other subcommand: passthrough to the real CLI if installed.
    real_cli = _find_real_cli()
    if real_cli:
        try:
            os.execv(real_cli, [real_cli] + args)
        except OSError as exc:
            print(f"arcis: failed to launch real CLI ({real_cli}): {exc}", file=sys.stderr)
            return 2

    # Real CLI not installed. Be helpful instead of cryptic.
    print(
        f"arcis: '{args[0]}' requires the full CLI binary, which isn't "
        "installed on this system.",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    print("  Install:  npm install -g @arcis/cli", file=sys.stderr)
    print("  Then:     arcis " + " ".join(args), file=sys.stderr)
    print("", file=sys.stderr)
    print("  Or run 'arcis --help' for SDK-only options.", file=sys.stderr)
    return 127


if __name__ == "__main__":
    sys.exit(main())
