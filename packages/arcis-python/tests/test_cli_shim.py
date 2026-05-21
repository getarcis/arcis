"""Regression tests for `arcis.cli_shim`.

The shim is the entry point registered by `pip install arcis`. It must
defer to the real `@arcis/cli` binary whenever that binary is on the
system, so users see the Rust CLI's rich welcome screen rather than the
shim's plain-text install hint.

The bug this guards: before v1.5.3 the no-args branch incorrectly
required `args` to be non-empty before calling `os.execv`, which meant
typing bare `arcis` always rendered the shim welcome even after
`npm install -g @arcis/cli`.
"""

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
