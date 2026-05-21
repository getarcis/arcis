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
SDK_VERSION = "1.5.4"


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
    # On Windows we must resolve `npm` to its full `.cmd` path because
    # subprocess.run with shell=False does NOT honor PATHEXT; calling
    # "npm" directly would CreateProcess("npm.exe") and fail since npm
    # ships as npm.cmd on Windows.
    npm_exe = shutil.which("npm")
    if npm_exe:
        try:
            result = subprocess.run(
                [npm_exe, "config", "get", "prefix"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                prefix = result.stdout.strip()
                if prefix:
                    if sys.platform == "win32":
                        # npm on Windows places the shim directly in
                        # the prefix root: <prefix>\arcis.cmd|exe|ps1
                        for name in ("arcis.cmd", "arcis.exe", "arcis.ps1", "arcis"):
                            candidates.append(os.path.join(prefix, name))
                    else:
                        candidates.append(os.path.join(prefix, "bin", "arcis"))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # npm hung or returned garbage. Don't block on it.
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

    # Shebang probe (Unix): `pip install --user arcis` drops a Python
    # script at ~/.local/bin/arcis with no sibling python interpreter,
    # and that location is never under sys.exec_prefix or /Scripts/.
    # The script itself starts with `#!/.../python...`, which is the
    # cleanest signal we have for that layout.
    #
    # We skip the probe when the file is larger than 64 KiB: pip-generated
    # entry-point scripts are well under 4 KiB, while native Arcis binaries
    # are several MB. The size gate caps disk I/O so that PATH dirs on slow
    # filesystems (network drives, fuse mounts) don't make every `arcis`
    # invocation block on a multi-MB read. Fail open on any OSError so
    # unreadable files still fall through to the non-shim branch.
    try:
        if os.path.getsize(path) > 64 * 1024:
            return False
        with open(path, "rb") as f:
            head = f.read(256)
        if head.startswith(b"#!"):
            first_line = head.split(b"\n", 1)[0].lower()
            if b"python" in first_line:
                return True
    except (OSError, ValueError):
        pass

    return False


def _path_matches(name: str) -> List[str]:
    """Return every `name` hit on PATH, in PATH order.

    `shutil.which` stops at the first match. On Windows when Python's
    `Scripts/` sits ahead of npm's prefix on PATH, that first match is
    our own shim and we'd never get to consider the npm binary further
    down. Walking the full PATH and returning all matches lets the
    caller skip past the shim. PATHEXT (the Windows list of executable
    extensions) is honored so `arcis.cmd`, `arcis.exe`, etc. all count.
    """
    matches: List[str] = []
    seen: set = set()

    if sys.platform == "win32":
        # PATHEXT entries FIRST, bare name LAST. npm on Windows ships
        # BOTH `<prefix>\arcis.cmd` (the real Windows launcher) AND
        # `<prefix>\arcis` (a bash script for git-bash / WSL users).
        # Picking the bare name on a Windows host blows up with WinError
        # 193 ("not a valid Win32 application") because the kernel can't
        # exec a shell script. The bare extension is only useful as a
        # last-resort fallback for the edge case where someone has just
        # an extensionless executable on PATH.
        pathext = os.environ.get("PATHEXT", ".EXE;.CMD;.BAT;.COM").split(";")
        extensions = [e for e in pathext if e] + [""]
    else:
        extensions = [""]

    for d in os.environ.get("PATH", "").split(os.pathsep):
        d = d.strip().strip('"')
        if not d:
            continue
        for ext in extensions:
            candidate = os.path.join(d, name + ext)
            if not os.path.isfile(candidate):
                continue
            key = os.path.normcase(os.path.abspath(candidate))
            if key in seen:
                continue
            seen.add(key)
            matches.append(candidate)
            break  # only the first valid extension per directory

    return matches


def _find_real_cli() -> Optional[str]:
    """Return the path to the real @arcis/cli binary, or None.

    Recursion guard: filters out Python entry points (the shim itself).
    Without this guard, the shim would call itself in a subprocess
    loop on systems where Python's Scripts/ dir comes before npm's
    global bin on PATH (common on Windows).
    """
    # Walk PATH for ALL `arcis` matches and pick the first that isn't
    # this shim. shutil.which would stop at the first match (our own
    # shim) and we'd never see the npm binary one directory later.
    for found in _path_matches("arcis"):
        if not _is_python_entry_point(found):
            return found

    # Belt-and-suspenders: probe well-known npm install locations in
    # case the binary lives somewhere not on PATH (broken setups,
    # custom prefixes, etc.).
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


def _exec_real(real_cli: str, args: List[str]) -> int:
    """Hand off to the real CLI with the given args.

    Unix: `os.execv` replaces this process, so signals (Ctrl+C, SIGTERM)
    propagate naturally to the binary and we never return.

    Windows: `os.execv` can ONLY launch a Windows executable. npm-global
    binaries on Windows are `.cmd` files (the JS shim that spawns the
    real binary), and `execv` on a `.cmd` raises OSError. We fall back
    to `subprocess.run`, which routes through CreateProcess properly
    for `.cmd` / `.bat` / `.ps1` shims. We return its exit code so the
    caller can `sys.exit(...)` with it.
    """
    if sys.platform == "win32":
        try:
            result = subprocess.run([real_cli, *args])
            return result.returncode if result.returncode is not None else 1
        except OSError as exc:
            print(
                f"arcis: failed to launch CLI ({real_cli}): {exc}",
                file=sys.stderr,
            )
            return 2
    else:
        try:
            os.execv(real_cli, [real_cli, *args])
        except OSError as exc:
            print(
                f"arcis: failed to launch CLI ({real_cli}): {exc}",
                file=sys.stderr,
            )
            return 2
        return 0  # unreachable; execv replaces the process on success


def _print_diag() -> int:
    """Diagnostic dump. Shows what the shim sees when looking for the
    real CLI: PATH matches, _is_python_entry_point verdict per match,
    candidate paths from `_candidate_paths`, npm's reported prefix, and
    the platform pair Python detected. Helps debug "shim won't pass
    through" reports without having to remote into the user's box.
    """
    print(f"arcis-shim diag (SDK {SDK_VERSION} on {sys.platform})")
    print(f"  sys.argv[0]:     {os.path.realpath(sys.argv[0])}")
    print(f"  sys.exec_prefix: {sys.exec_prefix}")
    print()
    print("PATH walk for 'arcis':")
    matches = _path_matches("arcis")
    if not matches:
        print("  (no PATH hits)")
    for m in matches:
        flag = "shim" if _is_python_entry_point(m) else "real"
        print(f"  [{flag}] {m}")
    print()
    print("Candidate paths from _candidate_paths():")
    candidates = _candidate_paths()
    if not candidates:
        print("  (none)")
    for c in candidates:
        exists = "exists" if os.path.isfile(c) else "missing"
        print(f"  [{exists}] {c}")
    print()
    npm_exe = shutil.which("npm")
    print(f"npm on PATH:       {npm_exe or '(not found)'}")
    if npm_exe:
        try:
            result = subprocess.run(
                [npm_exe, "config", "get", "prefix"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            print(f"npm config prefix: {(result.stdout or '').strip() or '(empty)'}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"npm config prefix: (failed: {exc})")
    print()
    resolved = _find_real_cli()
    print(f"_find_real_cli():  {resolved or '(None)'}")
    return 0


def main() -> int:
    """Entry point registered as `arcis` in pyproject.toml.

    Behavior:
      - With no args or `--help` or `-h`: pass through to the real CLI
        when installed, else print the shim's welcome screen.
      - With `--version` or `-V`: print SDK version + tell user about
        the separate CLI binary.
      - With `--diag`: print a diagnostic dump (PATH matches, candidate
        paths, npm prefix, what _find_real_cli resolved to). Always
        runs locally so users with a broken setup can still get answers.
      - With `check <payload>`: run scan_threats on the payload (SDK
        self-test).
      - With any other args: try to passthrough to the real CLI; if
        not installed, print install hint.
    """
    args = sys.argv[1:]

    if args and args[0] == "--diag":
        return _print_diag()

    # No-args and `--help` / `-h`: prefer the real CLI's own surface
    # whenever it's installed. The Rust binary prints a richer welcome
    # screen (with the burst mascot + commands list) on no-args, and a
    # full per-command flag reference on --help. The shim's plain-text
    # welcome is only a fallback for when the binary isn't installed.
    if not args or args[0] in ("-h", "--help"):
        real_cli = _find_real_cli()
        if real_cli:
            return _exec_real(real_cli, args)
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
        return _exec_real(real_cli, args)

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
