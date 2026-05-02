"""
Tests for `arcis update`.

Covers version comparison, network-failure handling, and --check CI mode.
Uses monkeypatch to avoid real PyPI calls in the test suite.
"""

import sys
import pytest

from arcis.cli.update import (
    _parse_version,
    _print_status,
    main as update_main,
)


class TestParseVersion:
    def test_simple(self):
        assert _parse_version("1.4.4") == (1, 4, 4)

    def test_two_part(self):
        assert _parse_version("2.0") == (2, 0)

    def test_pre_release_returns_none(self):
        assert _parse_version("1.4.4rc1") is None

    def test_dev_returns_none(self):
        assert _parse_version("1.4.4.dev0") is None

    def test_garbage_returns_none(self):
        assert _parse_version("not-a-version") is None


class TestPrintStatus:
    def test_up_to_date_returns_zero(self, capsys):
        rc = _print_status("1.4.4", "1.4.4", no_color=True)
        out = capsys.readouterr().out
        assert rc == 0
        assert "latest version" in out.lower()

    def test_outdated_returns_one(self, capsys):
        rc = _print_status("1.4.3", "1.4.4", no_color=True)
        out = capsys.readouterr().out
        assert rc == 1
        assert "1.4.4" in out
        assert "pip install --upgrade arcis" in out

    def test_unreachable_returns_two(self, capsys):
        rc = _print_status("1.4.4", None, no_color=True)
        out = capsys.readouterr().out
        assert rc == 2
        assert "unreachable" in out

    def test_pre_release_skips_compare(self, capsys):
        rc = _print_status("1.4.4.dev0", "1.4.4", no_color=True)
        out = capsys.readouterr().out
        # Pre-release skips comparison and exits 0 (we don't claim outdated).
        assert rc == 0
        assert "Skipping" in out or "skipping" in out.lower()


class TestCheckMode:
    def test_check_up_to_date_exits_zero(self, monkeypatch, capsys):
        monkeypatch.setattr("arcis.cli.update._fetch_latest_version", lambda: "1.4.4")
        monkeypatch.setattr("arcis.cli.update._current_version", lambda: "1.4.4")
        monkeypatch.setattr(sys, "argv", ["arcis update", "--check"])
        with pytest.raises(SystemExit) as exc:
            update_main()
        assert exc.value.code == 0

    def test_check_outdated_exits_one(self, monkeypatch):
        monkeypatch.setattr("arcis.cli.update._fetch_latest_version", lambda: "1.4.5")
        monkeypatch.setattr("arcis.cli.update._current_version", lambda: "1.4.4")
        monkeypatch.setattr(sys, "argv", ["arcis update", "--check"])
        with pytest.raises(SystemExit) as exc:
            update_main()
        assert exc.value.code == 1

    def test_check_unreachable_exits_two(self, monkeypatch):
        monkeypatch.setattr("arcis.cli.update._fetch_latest_version", lambda: None)
        monkeypatch.setattr(sys, "argv", ["arcis update", "--check"])
        with pytest.raises(SystemExit) as exc:
            update_main()
        assert exc.value.code == 2
