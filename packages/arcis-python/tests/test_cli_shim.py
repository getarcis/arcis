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
    with patch.object(cli_shim.os, "execv") as mock_execv:
        cli_shim.main()
    mock_execv.assert_called_once_with(real_cli_at, [real_cli_at])


def test_no_args_without_real_cli_prints_welcome(no_real_cli, monkeypatch, capsys):
    """Bare `arcis` falls back to shim welcome when the real CLI is missing."""
    monkeypatch.setattr(sys, "argv", ["arcis"])
    with patch.object(cli_shim.os, "execv") as mock_execv:
        rc = cli_shim.main()
    mock_execv.assert_not_called()
    out = capsys.readouterr().out
    assert rc == 0
    assert "Arcis Python SDK" in out
    assert "npm install -g @arcis/cli" in out


def test_help_with_real_cli_execs_passthrough(real_cli_at, monkeypatch):
    """`arcis --help` defers to the real CLI when installed."""
    monkeypatch.setattr(sys, "argv", ["arcis", "--help"])
    with patch.object(cli_shim.os, "execv") as mock_execv:
        cli_shim.main()
    mock_execv.assert_called_once_with(real_cli_at, [real_cli_at, "--help"])


def test_subcommand_with_real_cli_execs_passthrough(real_cli_at, monkeypatch):
    """`arcis scan ...` defers to the real CLI when installed."""
    monkeypatch.setattr(sys, "argv", ["arcis", "scan", "http://localhost"])
    with patch.object(cli_shim.os, "execv") as mock_execv:
        cli_shim.main()
    mock_execv.assert_called_once_with(
        real_cli_at, [real_cli_at, "scan", "http://localhost"]
    )


def test_check_command_runs_locally_even_with_real_cli(real_cli_at, monkeypatch, capsys):
    """`arcis check '<payload>'` is SDK-local; never delegates to the binary."""
    monkeypatch.setattr(sys, "argv", ["arcis", "check", "hello world"])
    with patch.object(cli_shim.os, "execv") as mock_execv:
        rc = cli_shim.main()
    mock_execv.assert_not_called()
    # rc 0 if clean, 1 if threat detected. Either is fine; we only care
    # that the shim didn't execv.
    assert rc in (0, 1)


def test_version_flag_prints_sdk_version_without_execv(real_cli_at, monkeypatch, capsys):
    """`arcis --version` prints the Python SDK version locally."""
    monkeypatch.setattr(sys, "argv", ["arcis", "--version"])
    # subprocess.run on the fake path will fail; we accept either exit
    # path so long as the shim doesn't execv away from us.
    with patch.object(cli_shim.os, "execv") as mock_execv:
        rc = cli_shim.main()
    mock_execv.assert_not_called()
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
