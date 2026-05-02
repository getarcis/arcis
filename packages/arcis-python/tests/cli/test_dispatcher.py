"""
Tests for the top-level `arcis` dispatcher (arcis.cli.__init__).

Covers:
- catalog rendering with no args
- --list / --help / --version flags
- non-TTY fallback skips the interactive picker
- unknown command returns the right exit code
"""

import io
import sys

import pytest

from arcis.cli import _print_catalog, _try_interactive_picker, main


def test_print_catalog_lists_all_commands(capsys):
    _print_catalog(verbose=False)
    out = capsys.readouterr().out
    assert "scan" in out
    assert "audit" in out
    assert "sca" in out
    assert "Discovery" in out


def test_print_catalog_verbose_includes_examples(capsys):
    _print_catalog(verbose=True)
    out = capsys.readouterr().out
    # Verbose mode shows the sample command lines
    assert "arcis scan http" in out
    assert "arcis audit" in out
    assert "arcis sca" in out


def test_picker_returns_false_when_stdin_not_tty(monkeypatch):
    """Non-TTY (CI, piped input) must skip the picker so scripted runs
    fall through to the static catalog instead of hanging on a prompt."""
    fake_stdin = io.StringIO("")
    monkeypatch.setattr(sys, "stdin", fake_stdin)
    assert _try_interactive_picker() is False


def test_main_no_args_prints_catalog_when_non_tty(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.setattr(sys, "argv", ["arcis"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "scan" in out and "audit" in out and "sca" in out


def test_main_list_flag(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["arcis", "--list"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    assert "arcis sca" in capsys.readouterr().out


def test_main_version_flag(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["arcis", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out = capsys.readouterr().out.strip()
    # Version is whatever __version__ resolves to — just confirm it printed.
    assert out  # non-empty


def test_main_unknown_command(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["arcis", "nope"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
    assert "unknown command" in capsys.readouterr().out
