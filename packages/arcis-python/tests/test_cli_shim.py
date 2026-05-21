"""Regression tests for `arcis.cli_shim`.

The shim is the entry point registered by `pip install arcis`. It must
defer to the real `@arcis/cli` binary whenever that binary is on the
system, so users see the Rust CLI's rich welcome screen rather than the
shim's plain-text install hint.

Bugs these guard (both shipped in v1.5.3):
1. The no-args branch incorrectly required `args` to be non-empty
   before calling `os.execv`, which meant typing bare `arcis` always
   rendered the shim welcome even after `npm install -g @arcis/cli`.
2. `_find_real_cli` relied on `shutil.which`, which returns only the
   first PATH hit. On Windows where Python's `Scripts/` sits ahead of
   npm's prefix, that first hit is the shim itself, and the npm
   binary further down PATH was never considered.
"""

import os
import sys
from unittest.mock import patch

import pytest

from arcis import cli_shim


@pytest.fixture
def no_real_cli(monkeypatch):
    """Force `_find_real_cli` to report the binary is not installed."""
    monkeypatch.setattr(cli_shim, "_find_real_cli", lambda: None)


@pytest.fixture
def real_cli_at(monkeypatch):
    """Inject a fake `@arcis/cli` path that `_find_real_cli` will return."""
    fake_path = "/usr/local/bin/arcis-real"
    monkeypatch.setattr(cli_shim, "_find_real_cli", lambda: fake_path)
    return fake_path


def test_no_args_with_real_cli_execs_passthrough(real_cli_at, monkeypatch):
    """Bare `arcis` defers to the real CLI when installed (regression: v1.5.2)."""
    monkeypatch.setattr(sys, "argv", ["arcis"])
    with patch.object(cli_shim, "_exec_real", return_value=0) as mock_exec:
        cli_shim.main()
    mock_exec.assert_called_once_with(real_cli_at, [])


def test_no_args_without_real_cli_prints_welcome(no_real_cli, monkeypatch, capsys):
    """Bare `arcis` falls back to shim welcome when the real CLI is missing."""
    monkeypatch.setattr(sys, "argv", ["arcis"])
    with patch.object(cli_shim, "_exec_real") as mock_exec:
        rc = cli_shim.main()
    mock_exec.assert_not_called()
    out = capsys.readouterr().out
    assert rc == 0
    assert "Arcis Python SDK" in out
    assert "npm install -g @arcis/cli" in out


def test_help_with_real_cli_execs_passthrough(real_cli_at, monkeypatch):
    """`arcis --help` defers to the real CLI when installed."""
    monkeypatch.setattr(sys, "argv", ["arcis", "--help"])
    with patch.object(cli_shim, "_exec_real", return_value=0) as mock_exec:
        cli_shim.main()
    mock_exec.assert_called_once_with(real_cli_at, ["--help"])


def test_subcommand_with_real_cli_execs_passthrough(real_cli_at, monkeypatch):
    """`arcis scan ...` defers to the real CLI when installed."""
    monkeypatch.setattr(sys, "argv", ["arcis", "scan", "http://localhost"])
    with patch.object(cli_shim, "_exec_real", return_value=0) as mock_exec:
        cli_shim.main()
    mock_exec.assert_called_once_with(real_cli_at, ["scan", "http://localhost"])


def test_check_command_runs_locally_even_with_real_cli(real_cli_at, monkeypatch, capsys):
    """`arcis check '<payload>'` is SDK-local; never delegates to the binary."""
    monkeypatch.setattr(sys, "argv", ["arcis", "check", "hello world"])
    with patch.object(cli_shim, "_exec_real") as mock_exec:
        rc = cli_shim.main()
    mock_exec.assert_not_called()
    # rc 0 if clean, 1 if threat detected. Either is fine; we only care
    # that the shim didn't pass through.
    assert rc in (0, 1)


def test_version_flag_prints_sdk_version_without_passthrough(real_cli_at, monkeypatch, capsys):
    """`arcis --version` prints the Python SDK version locally."""
    monkeypatch.setattr(sys, "argv", ["arcis", "--version"])
    with patch.object(cli_shim, "_exec_real") as mock_exec:
        rc = cli_shim.main()
    mock_exec.assert_not_called()
    out = capsys.readouterr().out
    assert rc == 0
    assert cli_shim.SDK_VERSION in out


def test_unknown_subcommand_without_real_cli_prints_install_hint(no_real_cli, monkeypatch, capsys):
    """Unknown subcommand + no binary prints an install hint, exits 127."""
    monkeypatch.setattr(sys, "argv", ["arcis", "audit", "."])
    rc = cli_shim.main()
    err = capsys.readouterr().err
    assert rc == 127
    assert "npm install -g @arcis/cli" in err


# ---------------------------------------------------------------------------
# _exec_real: Unix uses os.execv; Windows uses subprocess.run because execv
# can't launch .cmd shim files.
# ---------------------------------------------------------------------------


def test_exec_real_on_windows_uses_subprocess_not_execv(monkeypatch):
    """Bug #4 (v1.5.3): npm-global on Windows is `arcis.cmd`. os.execv on
    a .cmd raises OSError; subprocess.run handles it correctly."""
    monkeypatch.setattr(cli_shim.sys, "platform", "win32")
    completed = type("CP", (), {"returncode": 0})()
    with patch.object(cli_shim.subprocess, "run", return_value=completed) as mock_run:
        with patch.object(cli_shim.os, "execv") as mock_execv:
            rc = cli_shim._exec_real(r"C:\Users\u\AppData\Roaming\npm\arcis.cmd", ["audit", "."])
    mock_run.assert_called_once_with([r"C:\Users\u\AppData\Roaming\npm\arcis.cmd", "audit", "."])
    mock_execv.assert_not_called()
    assert rc == 0


def test_exec_real_on_unix_uses_execv(monkeypatch):
    """On Unix the shim should `execv` so signals propagate naturally."""
    monkeypatch.setattr(cli_shim.sys, "platform", "linux")
    with patch.object(cli_shim.os, "execv") as mock_execv:
        with patch.object(cli_shim.subprocess, "run") as mock_run:
            cli_shim._exec_real("/usr/local/bin/arcis", ["scan", "http://x"])
    mock_execv.assert_called_once_with(
        "/usr/local/bin/arcis", ["/usr/local/bin/arcis", "scan", "http://x"]
    )
    mock_run.assert_not_called()


def test_exec_real_returns_subprocess_returncode_on_windows(monkeypatch):
    """The subprocess result.returncode must propagate so the user sees
    the same exit status the binary returned."""
    monkeypatch.setattr(cli_shim.sys, "platform", "win32")
    completed = type("CP", (), {"returncode": 7})()
    with patch.object(cli_shim.subprocess, "run", return_value=completed):
        rc = cli_shim._exec_real("arcis.cmd", ["audit", "."])
    assert rc == 7


# ---------------------------------------------------------------------------
# _candidate_paths: npm prefix lookup on Windows must resolve npm.cmd via
# shutil.which, not call "npm" directly (which CreateProcess fails to find).
# ---------------------------------------------------------------------------


def test_candidate_paths_resolves_npm_via_shutil_which_on_windows(monkeypatch):
    """Bug #3 (v1.5.3): subprocess.run(['npm', ...]) on Windows fails
    because Python's subprocess doesn't honor PATHEXT. The shim must
    resolve npm to its full `.cmd` path first."""
    monkeypatch.setattr(cli_shim.sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", r"C:\Users\u\AppData\Roaming")
    monkeypatch.delenv("USERPROFILE", raising=False)
    monkeypatch.setattr(
        cli_shim.shutil, "which", lambda n: r"C:\nodejs\npm.cmd" if n == "npm" else None
    )
    completed = type("CP", (), {"returncode": 0, "stdout": r"C:\nodejs\npm-prefix" + "\n"})()
    with patch.object(cli_shim.subprocess, "run", return_value=completed) as mock_run:
        candidates = cli_shim._candidate_paths()
    # Must have invoked the .cmd-resolved path, not bare "npm".
    invoked = mock_run.call_args[0][0]
    assert invoked[0] == r"C:\nodejs\npm.cmd"
    # Must have added the npm-prefix-based candidate variants. Normalize
    # separators because os.path.join uses the HOST's separator (Linux's
    # forward slash on CI) even when sys.platform is mocked to win32.
    norm = [c.replace("\\", "/").lower() for c in candidates]
    assert any(c.endswith("c:/nodejs/npm-prefix/arcis.cmd") for c in norm)


def test_candidate_paths_skips_npm_lookup_when_npm_not_on_path(monkeypatch):
    """If shutil.which('npm') returns None, the shim must NOT crash trying
    to subprocess.run a bare 'npm' string."""
    monkeypatch.setattr(cli_shim.sys, "platform", "linux")
    monkeypatch.setattr(cli_shim.shutil, "which", lambda n: None)
    with patch.object(cli_shim.subprocess, "run") as mock_run:
        candidates = cli_shim._candidate_paths()
    mock_run.assert_not_called()
    # The fixed-path Unix candidates should still be present. Normalize
    # separators because os.path.join on the host (which may be Windows
    # running this test) uses backslashes.
    norm = [c.replace("\\", "/") for c in candidates]
    assert any(c.endswith("/usr/local/bin/arcis") for c in norm)


# ---------------------------------------------------------------------------
# --diag flag: prints a debug dump so users can self-serve when the shim
# refuses to find their binary.
# ---------------------------------------------------------------------------


def test_diag_flag_prints_path_matches_and_resolution(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["arcis", "--diag"])
    monkeypatch.setattr(cli_shim, "_path_matches", lambda n: ["/path/a/arcis", "/path/b/arcis"])
    monkeypatch.setattr(
        cli_shim,
        "_is_python_entry_point",
        lambda p: p == "/path/a/arcis",
    )
    monkeypatch.setattr(cli_shim, "_candidate_paths", lambda: ["/opt/arcis"])
    monkeypatch.setattr(cli_shim, "_find_real_cli", lambda: "/path/b/arcis")
    monkeypatch.setattr(cli_shim.shutil, "which", lambda n: None)

    rc = cli_shim.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "arcis-shim diag" in out
    assert "/path/a/arcis" in out
    assert "/path/b/arcis" in out
    assert "[shim]" in out
    assert "[real]" in out
    assert "_find_real_cli():" in out


# ---------------------------------------------------------------------------
# _path_matches + _find_real_cli PATH-walk regression coverage.
# Guards bug #2 from v1.5.3: on Windows shutil.which("arcis") returns the
# Python shim first, and we need to keep walking PATH to find the npm
# binary one directory later.
# ---------------------------------------------------------------------------


def test_path_matches_returns_all_hits_in_path_order(tmp_path, monkeypatch):
    """Two PATH entries both holding `arcis` should both appear in result."""
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "arcis").write_text("#!/bin/sh\necho a\n")
    (dir_b / "arcis").write_text("#!/bin/sh\necho b\n")
    if sys.platform != "win32":
        (dir_a / "arcis").chmod(0o755)
        (dir_b / "arcis").chmod(0o755)

    monkeypatch.setenv("PATH", os.pathsep.join([str(dir_a), str(dir_b)]))
    results = cli_shim._path_matches("arcis")
    assert len(results) == 2
    assert results[0].endswith(os.path.join("a", "arcis")) or results[0].endswith(
        os.path.join("a", "arcis.exe")
    )
    assert results[1].endswith(os.path.join("b", "arcis")) or results[1].endswith(
        os.path.join("b", "arcis.exe")
    )


def test_path_matches_prefers_cmd_over_bare_name_on_windows(tmp_path, monkeypatch):
    """Bug #14 (v1.5.4): npm on Windows ships both `<prefix>\\arcis` (a
    bash script for git-bash) and `<prefix>\\arcis.cmd` (the real
    launcher). The shim must pick the .cmd, not the bash script, or the
    Windows kernel refuses with WinError 193.

    Linux CI note: file lookups are case-sensitive on Linux but case-
    insensitive on real Windows. We use a lowercase PATHEXT in the test
    so the lookup matches the lowercase files we create. Real Windows
    PATHEXT is uppercase, but os.path.isfile there is case-insensitive
    so the production code works either way.
    """
    monkeypatch.setattr(cli_shim.sys, "platform", "win32")
    monkeypatch.setenv("PATHEXT", ".exe;.cmd;.bat;.com")
    d = tmp_path / "npm"
    d.mkdir()
    (d / "arcis").write_text("#!/bin/sh\n# git-bash launcher\n")
    (d / "arcis.cmd").write_text("@echo off\nnode arcis-impl.js %*\n")

    monkeypatch.setenv("PATH", str(d))
    results = cli_shim._path_matches("arcis")
    # First result must be the .cmd, not the bare name. Both files exist
    # so the function returns just one per directory (first match wins).
    assert len(results) == 1
    assert results[0].lower().endswith("arcis.cmd")


def test_path_matches_dedupes_repeated_directories(tmp_path, monkeypatch):
    """A PATH with the same directory listed twice still returns one match."""
    d = tmp_path / "only"
    d.mkdir()
    (d / "arcis").write_text("#!/bin/sh\n")
    if sys.platform != "win32":
        (d / "arcis").chmod(0o755)

    monkeypatch.setenv("PATH", os.pathsep.join([str(d), str(d)]))
    results = cli_shim._path_matches("arcis")
    assert len(results) == 1


def test_find_real_cli_skips_python_shim_and_returns_npm_binary(tmp_path, monkeypatch):
    """The fix: when Python's Scripts/ comes first, the npm prefix wins."""
    python_scripts = tmp_path / "Scripts"
    npm_prefix = tmp_path / "npm"
    python_scripts.mkdir()
    npm_prefix.mkdir()
    (python_scripts / "arcis").write_text("#!/bin/sh\n# pip shim\n")
    (npm_prefix / "arcis").write_text("#!/bin/sh\n# real cli\n")
    if sys.platform != "win32":
        (python_scripts / "arcis").chmod(0o755)
        (npm_prefix / "arcis").chmod(0o755)

    monkeypatch.setenv(
        "PATH", os.pathsep.join([str(python_scripts), str(npm_prefix)])
    )
    # Force _is_python_entry_point to match ONLY the Scripts/ path.
    real_python_shim = str(python_scripts / "arcis")
    monkeypatch.setattr(
        cli_shim,
        "_is_python_entry_point",
        lambda p: os.path.normcase(p) == os.path.normcase(real_python_shim),
    )

    result = cli_shim._find_real_cli()
    assert result is not None
    assert os.path.normcase(result).endswith(
        os.path.normcase(os.path.join("npm", "arcis"))
    )


def test_is_python_entry_point_detects_python_shebang(tmp_path):
    """Bug #7 (Linux/macOS): `pip install --user arcis` writes
    ~/.local/bin/arcis with a python shebang and no sibling python
    interpreter. The shebang probe must catch it so we don't infinite-
    loop into the shim."""
    shim = tmp_path / "arcis"
    shim.write_text("#!/usr/bin/python3\nimport sys\nsys.exit(0)\n")
    if sys.platform != "win32":
        shim.chmod(0o755)
    assert cli_shim._is_python_entry_point(str(shim)) is True


def test_is_python_entry_point_does_not_flag_native_binary(tmp_path):
    """The Rust binary from `@arcis/cli` has no python shebang. It must
    not be flagged as a shim or we'd infinite-loop."""
    real = tmp_path / "arcis-bin"
    # Magic bytes of a minimal ELF header (just the first 4) so it
    # clearly looks like a native binary, not a script.
    real.write_bytes(b"\x7fELF" + b"\x00" * 60)
    if sys.platform != "win32":
        real.chmod(0o755)
    assert cli_shim._is_python_entry_point(str(real)) is False


def test_is_python_entry_point_does_not_flag_node_shim(tmp_path):
    """The npm-installed JS wrapper at bin/arcis starts with
    `#!/usr/bin/env node`. It must NOT be flagged as a Python shim."""
    node_shim = tmp_path / "arcis"
    node_shim.write_text("#!/usr/bin/env node\nrequire('./real-impl')\n")
    if sys.platform != "win32":
        node_shim.chmod(0o755)
    assert cli_shim._is_python_entry_point(str(node_shim)) is False


def test_is_python_entry_point_size_gate_skips_large_files(tmp_path):
    """A multi-MB file should never trigger a full read. The size gate
    bails before opening so PATH walks on slow filesystems (network
    drives, fuse mounts) don't add latency to every `arcis` invocation."""
    big = tmp_path / "arcis-bin"
    # Write a 128 KiB file that starts with a python shebang. Without
    # the size gate the probe would match and incorrectly flag it as
    # a shim. With the gate, the function returns False before reading.
    payload = b"#!/usr/bin/python3\n" + b"\x00" * (128 * 1024)
    big.write_bytes(payload)
    if sys.platform != "win32":
        big.chmod(0o755)
    assert cli_shim._is_python_entry_point(str(big)) is False


def test_find_real_cli_returns_none_when_only_shim_exists(tmp_path, monkeypatch):
    """No npm binary anywhere on PATH => `_find_real_cli` returns None."""
    python_scripts = tmp_path / "Scripts"
    python_scripts.mkdir()
    (python_scripts / "arcis").write_text("#!/bin/sh\n")
    if sys.platform != "win32":
        (python_scripts / "arcis").chmod(0o755)

    monkeypatch.setenv("PATH", str(python_scripts))
    monkeypatch.setattr(cli_shim, "_is_python_entry_point", lambda p: True)
    # Disable _candidate_paths fallback so the test is hermetic.
    monkeypatch.setattr(cli_shim, "_candidate_paths", lambda: [])

    assert cli_shim._find_real_cli() is None
