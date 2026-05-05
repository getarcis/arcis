"""
Tests for the schema v2 range matcher in arcis.cli.sca and the seeded
threat DB. Covers:

- _version_key ordering (numeric, pre-release, weird suffixes)
- _matches_constraint for each operator
- _matches_range AND-of-constraints + _matches_any_range OR-of-ranges
- _is_compromised dual-track (exact list OR range)
- Name normalization (PyPI dash/underscore, case)
- Spot-check seeded entries: rollup CVE range, jsonpath-plus, urllib3,
  ctx exact versions, ua-parser-js exact list, etc.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from arcis.cli import sca
from arcis.cli.sca import (
    CompromisedPackage,
    THREAT_DB,
    _is_compromised,
    _matches_any_range,
    _matches_constraint,
    _matches_range,
    _normalize_name,
    _version_key,
    scan_project,
)


# ── _version_key ───────────────────────────────────────────────────────────

def test_version_key_orders_numeric_parts() -> None:
    assert _version_key("1.0.0") < _version_key("1.0.1")
    assert _version_key("1.0.0") < _version_key("1.1.0")
    assert _version_key("1.0.0") < _version_key("2.0.0")
    assert _version_key("1.10.0") > _version_key("1.9.0")  # numeric, not lexical


def test_version_key_pre_release_below_release() -> None:
    assert _version_key("1.0.0-rc1") < _version_key("1.0.0")
    assert _version_key("4.22.4-beta") < _version_key("4.22.4")


def test_version_key_handles_v_prefix() -> None:
    assert _version_key("v1.2.3") == _version_key("1.2.3")


# ── _matches_constraint ────────────────────────────────────────────────────

@pytest.mark.parametrize("v,c,expected", [
    ("4.22.3", "<4.22.4",  True),
    ("4.22.4", "<4.22.4",  False),
    ("4.22.5", "<4.22.4",  False),
    ("4.22.4", "<=4.22.4", True),
    ("4.22.5", "<=4.22.4", False),
    ("4.22.4", ">=4.22.4", True),
    ("4.22.3", ">=4.22.4", False),
    ("4.22.4", ">4.22.3",  True),
    ("4.22.3", ">4.22.3",  False),
    ("1.0.0",  "==1.0.0",  True),
    ("1.0.1",  "==1.0.0",  False),
    ("1.0.0",  "!=1.0.0",  False),
    ("1.0.1",  "!=1.0.0",  True),
    ("1.0.0",  "1.0.0",    True),   # bare version -> exact match
    ("1.0.1",  "1.0.0",    False),
])
def test_matches_constraint(v: str, c: str, expected: bool) -> None:
    assert _matches_constraint(v, c) is expected


# ── _matches_range ─────────────────────────────────────────────────────────

def test_matches_range_anded_constraints() -> None:
    rng = ">=4.0.0,<4.22.4"
    assert _matches_range("4.22.3", rng) is True
    assert _matches_range("4.0.0", rng) is True
    assert _matches_range("3.99.99", rng) is False  # below lower bound
    assert _matches_range("4.22.4", rng) is False   # at upper bound (exclusive)


def test_matches_range_handles_whitespace_and_empty() -> None:
    assert _matches_range("1.0.0", " >=1.0.0 ,  <2.0.0 ") is True
    assert _matches_range("1.0.0", "") is False
    assert _matches_range("1.0.0", "  ") is False


def test_matches_any_range_ors_multiple() -> None:
    ranges = [">=2.0.0,<2.2.2", ">=1.0.0,<1.26.19"]
    assert _matches_any_range("1.26.18", ranges) is True
    assert _matches_any_range("2.2.1", ranges) is True
    assert _matches_any_range("2.2.2", ranges) is False
    assert _matches_any_range("1.26.19", ranges) is False


# ── _is_compromised ────────────────────────────────────────────────────────

def test_is_compromised_exact_list() -> None:
    threat = CompromisedPackage(
        ecosystem="npm", name="x", malicious_versions=["1.2.3"],
        attack_vector="", severity="critical", cve="", disclosure_date="",
        source="", references=[],
    )
    assert _is_compromised("1.2.3", threat) is True
    assert _is_compromised("1.2.4", threat) is False


def test_is_compromised_range() -> None:
    threat = CompromisedPackage(
        ecosystem="npm", name="x", malicious_versions=[],
        vulnerable_ranges=[">=4.0.0,<4.22.4"],
        attack_vector="", severity="high", cve="", disclosure_date="",
        source="", references=[],
    )
    assert _is_compromised("4.22.3", threat) is True
    assert _is_compromised("4.22.4", threat) is False
    assert _is_compromised("3.99.0", threat) is False


def test_is_compromised_either_track_hits() -> None:
    threat = CompromisedPackage(
        ecosystem="npm", name="x", malicious_versions=["7.0.0-rc1"],
        vulnerable_ranges=[">=8.0.0,<8.5.0"],
        attack_vector="", severity="high", cve="", disclosure_date="",
        source="", references=[],
    )
    assert _is_compromised("7.0.0-rc1", threat) is True   # exact list
    assert _is_compromised("8.4.99", threat) is True       # range
    assert _is_compromised("7.0.0", threat) is False
    assert _is_compromised("8.5.0", threat) is False


def test_is_compromised_empty_version_returns_false() -> None:
    threat = CompromisedPackage(
        ecosystem="npm", name="x", malicious_versions=["1.0.0"],
        attack_vector="", severity="critical", cve="", disclosure_date="",
        source="", references=[],
    )
    assert _is_compromised("", threat) is False


# ── name normalization ────────────────────────────────────────────────────

def test_normalize_name_pypi_folds_separators() -> None:
    assert _normalize_name("Python_DateUtil", "pypi") == "python-dateutil"
    assert _normalize_name("python-dateutil", "pypi") == "python-dateutil"


def test_normalize_name_npm_only_folds_case() -> None:
    assert _normalize_name("@AzuRe/Storage", "npm") == "@azure/storage"


# ── seeded DB sanity checks ────────────────────────────────────────────────

def _threat_by_name(ecosystem: str, name: str) -> CompromisedPackage:
    for t in THREAT_DB:
        if t.ecosystem == ecosystem and t.name == name:
            return t
    raise AssertionError(f"{ecosystem}/{name} not seeded")


def test_seed_has_minimum_entries() -> None:
    """Snyk-parity demo blocker: DB must be substantive, not 2 entries."""
    assert len(THREAT_DB) >= 30


def test_seed_covers_event_stream_chain() -> None:
    es = _threat_by_name("npm", "event-stream")
    assert "3.3.6" in es.malicious_versions
    assert "flatmap-stream" in es.trojanized_deps


def test_seed_covers_ua_parser_js() -> None:
    t = _threat_by_name("npm", "ua-parser-js")
    assert {"0.7.29", "0.8.0", "1.0.0"}.issubset(set(t.malicious_versions))


def test_seed_covers_rollup_range() -> None:
    t = _threat_by_name("npm", "rollup")
    assert _is_compromised("4.22.3", t) is True
    assert _is_compromised("4.22.4", t) is False
    assert _is_compromised("3.0.0", t) is False  # below the range


def test_seed_covers_jsonpath_plus_eval_rce() -> None:
    t = _threat_by_name("npm", "jsonpath-plus")
    assert t.severity == "critical"
    assert _is_compromised("9.9.9", t) is True
    assert _is_compromised("10.0.0", t) is False


def test_seed_covers_urllib3_dual_range() -> None:
    t = _threat_by_name("pypi", "urllib3")
    assert _is_compromised("1.26.18", t) is True
    assert _is_compromised("2.2.1", t) is True
    assert _is_compromised("2.2.2", t) is False
    assert _is_compromised("1.26.19", t) is False


def test_seed_covers_ctx_exact_versions() -> None:
    t = _threat_by_name("pypi", "ctx")
    assert "0.2.2" in t.malicious_versions and "0.2.6" in t.malicious_versions
    assert _is_compromised("0.2.2", t) is True
    assert _is_compromised("0.1.2", t) is False  # last-known-good


# ── end-to-end: scan_project hits range entries via package-lock ──────────

def test_scan_project_detects_rollup_range_in_lockfile(tmp_path: Path) -> None:
    """A real-shaped package-lock.json with a vulnerable rollup version
    should produce a finding via the new vulnerable_ranges path."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/rollup": {"version": "4.21.0"},
            "node_modules/safe-pkg": {"version": "1.0.0"},
        },
    }), encoding="utf-8")
    findings = scan_project(str(tmp_path))
    rollup_findings = [f for f in findings if f.package == "rollup"]
    assert len(rollup_findings) == 1
    assert rollup_findings[0].version == "4.21.0"
    assert rollup_findings[0].severity == "high"


def test_scan_project_does_not_flag_patched_rollup(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/rollup": {"version": "4.22.4"},
        },
    }), encoding="utf-8")
    findings = scan_project(str(tmp_path))
    assert [f for f in findings if f.package == "rollup"] == []


def test_scan_project_detects_urllib3_range_in_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "urllib3==1.26.18\n"
        "requests==2.31.0\n",
        encoding="utf-8",
    )
    findings = scan_project(str(tmp_path))
    by_pkg = {f.package for f in findings}
    assert "urllib3" in by_pkg
    assert "requests" in by_pkg


def test_scan_project_normalized_pypi_name_match(tmp_path: Path) -> None:
    """`Python_Dateutil` in a manifest should normalize to python-dateutil
    and hit the seeded typosquat entry. Use python3-dateutil here since
    that's the seeded malicious package."""
    (tmp_path / "requirements.txt").write_text(
        "python3_dateutil==2.9.1\n",   # underscore form -- typosquat
        encoding="utf-8",
    )
    findings = scan_project(str(tmp_path))
    assert any(f.package == "python3-dateutil" for f in findings)
