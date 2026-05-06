#!/usr/bin/env python3
"""
Parity test harness for the Rust CLI.

Runs the Python `arcis` CLI and the built Rust `arcis` binary against the
same fixture inputs, then asserts:

  * both exit with the expected exit code
  * stdout / stderr match the per-fixture pattern (regex)
  * neither side diverges from the other on exit code

Phase A: structure-based parity (regex matchers) — enough to validate
the harness end-to-end without forcing byte-equal output before the
real commands have ported. Phase B onward: we can flip a fixture flag
to demand byte-equal stdout / stderr for ported commands.

Usage:
    python tests/parity/run.py --rust-bin path/to/arcis [--fixture name]

The Python CLI is invoked as `python -m arcis.cli` by default — make sure
the `arcis` package is importable (e.g. `pip install -e packages/arcis-python`).

Exits 0 if every fixture passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import shlex
from pathlib import Path
from typing import List, Tuple

FIXTURES_DIR = Path(__file__).parent / "fixtures"
DEFAULT_TIMEOUT_S = 15


def run_binary(cmd: List[str], timeout: int = DEFAULT_TIMEOUT_S) -> Tuple[int, str, str]:
    """Run `cmd`, capture stdout / stderr, return (exit_code, out, err).

    On timeout or OSError, return exit_code=-1 and the error in stderr so
    the caller's diff logic can treat the failure uniformly instead of
    crashing the harness.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except OSError as exc:
        return -1, "", f"OSError: {exc}"


def check_fixture(
    fixture: dict,
    py_cmd: List[str],
    rust_cmd: List[str],
) -> Tuple[bool, List[str]]:
    """Run a single fixture against both binaries; return (passed, errors)."""
    args = fixture.get("args", [])
    expected_code = fixture.get("exit_code", 0)
    stdout_pat = fixture.get("stdout_pattern")
    stderr_pat = fixture.get("stderr_pattern")
    byte_equal = fixture.get("byte_equal", False)
    # Same as byte_equal but strips the volatile `Time` summary row before
    # comparing. Use this for SCA fixtures whose only non-deterministic
    # output is the elapsed-time line.
    byte_equal_strip_time = fixture.get("byte_equal_strip_time", False)

    py_full = py_cmd + args
    rust_full = rust_cmd + args

    errors: List[str] = []

    py_code, py_out, py_err = run_binary(py_full)
    rust_code, rust_out, rust_err = run_binary(rust_full)

    # --- exit code parity -------------------------------------------------
    if py_code != expected_code:
        errors.append(
            f"python exit code {py_code} != expected {expected_code} "
            f"(stderr: {py_err.strip()[:200]!r})"
        )
    if rust_code != expected_code:
        errors.append(
            f"rust exit code {rust_code} != expected {expected_code} "
            f"(stderr: {rust_err.strip()[:200]!r})"
        )
    if py_code != rust_code:
        errors.append(
            f"exit code divergence: python={py_code} rust={rust_code}"
        )

    # --- stdout match -----------------------------------------------------
    if byte_equal and py_out != rust_out:
        errors.append(
            "byte-equal stdout failed:\n"
            f"  python (first 200): {py_out[:200]!r}\n"
            f"  rust   (first 200): {rust_out[:200]!r}"
        )

    if byte_equal_strip_time:
        time_re = re.compile(r"^\s+Time\s+\S+\s*$\n?", re.MULTILINE)
        py_norm = time_re.sub("", py_out)
        rust_norm = time_re.sub("", rust_out)
        if py_norm != rust_norm:
            # Find the first diverging char so the message points at the
            # exact column where things drifted.
            common = 0
            for a, b in zip(py_norm, rust_norm):
                if a != b:
                    break
                common += 1
            window = 80
            lo = max(0, common - 20)
            errors.append(
                "byte-equal-strip-time stdout failed:\n"
                f"  first diff at column {common}\n"
                f"  python near diff: {py_norm[lo:lo+window]!r}\n"
                f"  rust   near diff: {rust_norm[lo:lo+window]!r}"
            )

    if stdout_pat:
        if not re.search(stdout_pat, py_out, re.MULTILINE):
            errors.append(
                f"python stdout does not match {stdout_pat!r}: {py_out[:200]!r}"
            )
        if not re.search(stdout_pat, rust_out, re.MULTILINE):
            errors.append(
                f"rust stdout does not match {stdout_pat!r}: {rust_out[:200]!r}"
            )

    # --- stderr match -----------------------------------------------------
    if stderr_pat:
        if not re.search(stderr_pat, py_err, re.MULTILINE):
            errors.append(
                f"python stderr does not match {stderr_pat!r}: {py_err[:200]!r}"
            )
        if not re.search(stderr_pat, rust_err, re.MULTILINE):
            errors.append(
                f"rust stderr does not match {stderr_pat!r}: {rust_err[:200]!r}"
            )

    return (len(errors) == 0), errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Python <-> Rust CLI parity tests"
    )
    parser.add_argument(
        "--rust-bin",
        help="Path to the built `arcis` Rust binary (required unless --list)",
    )
    parser.add_argument(
        "--py-cmd",
        default="python -m arcis.cli",
        help="Python CLI invocation (default: 'python -m arcis.cli'). "
             "Use shlex-style quoting if needed.",
    )
    parser.add_argument(
        "--fixture",
        help="Run only this fixture name (basename without .json)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available fixtures and exit",
    )
    args = parser.parse_args()

    fixtures = sorted(FIXTURES_DIR.glob("*.json"))

    # `--list` is informational and works without a Rust binary, so handle
    # it before the rust-bin existence check.
    if args.list:
        if not fixtures:
            print("(no fixtures)")
        for f in fixtures:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            print(f"  {f.stem:30s}  {data.get('name', '')}")
        return 0

    if not args.rust_bin:
        print("  --rust-bin is required (try --list to see fixtures)", file=sys.stderr)
        return 1

    rust_bin = Path(args.rust_bin)
    if not rust_bin.exists():
        print(f"  rust binary not found: {rust_bin}", file=sys.stderr)
        return 1
    if not rust_bin.is_file():
        print(f"  rust binary path is not a file: {rust_bin}", file=sys.stderr)
        return 1

    py_cmd = shlex.split(args.py_cmd)
    rust_cmd = [str(rust_bin)]

    if args.fixture:
        fixtures = [f for f in fixtures if f.stem == args.fixture]
        if not fixtures:
            print(f"  no fixture named {args.fixture!r}", file=sys.stderr)
            return 1

    if not fixtures:
        print("  no parity fixtures found", file=sys.stderr)
        return 1

    print(f"Running {len(fixtures)} parity fixture(s)...")
    print(f"  python: {' '.join(py_cmd)}")
    print(f"  rust:   {rust_bin}")
    print()

    passed = 0
    failed = 0
    for fpath in fixtures:
        with open(fpath, encoding="utf-8") as f:
            fixture = json.load(f)
        name = fixture.get("name", fpath.stem)
        ok, errors = check_fixture(fixture, py_cmd, rust_cmd)
        if ok:
            print(f"  [ok]   {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name}")
            for err in errors:
                # Indent the error so it's visually grouped under the case
                for line in err.splitlines():
                    print(f"           {line}")
            failed += 1

    print()
    total = passed + failed
    if failed == 0:
        print(f"  {passed}/{total} parity fixtures passed")
        return 0
    else:
        print(f"  {failed}/{total} parity fixtures FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
