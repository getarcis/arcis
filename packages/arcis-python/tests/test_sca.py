"""Tests for arcis sca — Supply Chain Attack Scanner."""

import json
import os
import tempfile

import pytest

from arcis.cli.sca import (
    Finding,
    THREAT_DB,
    scan_project,
    _scan_package_lock,
    _scan_yarn_lock,
    _scan_node_modules,
    _scan_requirements,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def tmpdir():
    """Create a temp directory and clean up after."""
    d = tempfile.mkdtemp()
    yield d
    # Cleanup
    import shutil
    shutil.rmtree(d, ignore_errors=True)


def _write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ── Threat DB ────────────────────────────────────────────────────────────────


def test_threat_db_has_entries():
    assert len(THREAT_DB) >= 2


def test_threat_db_covers_axios():
    axios = [t for t in THREAT_DB if t.name == "axios"]
    assert len(axios) == 1
    assert "1.14.1" in axios[0].malicious_versions
    assert "0.30.4" in axios[0].malicious_versions
    assert axios[0].ecosystem == "npm"
    assert axios[0].severity == "critical"


def test_threat_db_covers_litellm():
    litellm = [t for t in THREAT_DB if t.name == "litellm"]
    assert len(litellm) == 1
    assert "1.82.7" in litellm[0].malicious_versions
    assert "1.82.8" in litellm[0].malicious_versions
    assert litellm[0].ecosystem == "pypi"
    assert litellm[0].severity == "critical"


# ── package-lock.json (v3) ───────────────────────────────────────────────────


def test_detects_axios_in_lockfile_v3(tmpdir):
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/axios": {"version": "1.14.1"},
        },
    })
    findings = _scan_package_lock(tmpdir)
    assert len(findings) >= 1
    assert findings[0].package == "axios"
    assert findings[0].version == "1.14.1"
    assert findings[0].severity == "critical"


def test_detects_axios_030_in_lockfile(tmpdir):
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/axios": {"version": "0.30.4"},
        },
    })
    findings = _scan_package_lock(tmpdir)
    assert len(findings) >= 1
    assert findings[0].version == "0.30.4"


def test_safe_axios_version_not_flagged(tmpdir):
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/axios": {"version": "1.14.0"},
        },
    })
    findings = _scan_package_lock(tmpdir)
    assert len(findings) == 0


def test_detects_trojanized_dep_in_lockfile(tmpdir):
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/plain-crypto-js": {"version": "4.2.1"},
        },
    })
    findings = _scan_package_lock(tmpdir)
    assert len(findings) >= 1
    assert findings[0].package == "plain-crypto-js"
    assert findings[0].finding_type == "trojanized_dep"


def test_detects_axios_in_lockfile_v1(tmpdir):
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 1,
        "dependencies": {
            "axios": {"version": "1.14.1"},
        },
    })
    findings = _scan_package_lock(tmpdir)
    assert len(findings) >= 1
    assert findings[0].package == "axios"


# ── node_modules ─────────────────────────────────────────────────────────────


def test_detects_axios_in_node_modules(tmpdir):
    axios_dir = os.path.join(tmpdir, "node_modules", "axios")
    os.makedirs(axios_dir)
    _write_json(os.path.join(axios_dir, "package.json"), {
        "name": "axios",
        "version": "1.14.1",
    })
    findings = _scan_node_modules(tmpdir)
    assert len(findings) >= 1
    assert findings[0].package == "axios"


def test_safe_axios_in_node_modules(tmpdir):
    axios_dir = os.path.join(tmpdir, "node_modules", "axios")
    os.makedirs(axios_dir)
    _write_json(os.path.join(axios_dir, "package.json"), {
        "name": "axios",
        "version": "1.7.7",
    })
    findings = _scan_node_modules(tmpdir)
    assert len(findings) == 0


def test_detects_trojanized_dep_in_node_modules(tmpdir):
    dep_dir = os.path.join(tmpdir, "node_modules", "plain-crypto-js")
    os.makedirs(dep_dir)
    _write_json(os.path.join(dep_dir, "package.json"), {
        "name": "plain-crypto-js",
        "version": "4.2.1",
    })
    findings = _scan_node_modules(tmpdir)
    assert len(findings) >= 1
    assert findings[0].finding_type == "trojanized_dep"


# ── requirements.txt ─────────────────────────────────────────────────────────


def test_detects_litellm_in_requirements(tmpdir):
    _write_text(os.path.join(tmpdir, "requirements.txt"), "litellm==1.82.7\nflask==3.0.0\n")
    findings = _scan_requirements(tmpdir)
    assert len(findings) == 1
    assert findings[0].package == "litellm"
    assert findings[0].version == "1.82.7"


def test_detects_litellm_182_8(tmpdir):
    _write_text(os.path.join(tmpdir, "requirements.txt"), "litellm==1.82.8\n")
    findings = _scan_requirements(tmpdir)
    assert len(findings) == 1
    assert findings[0].version == "1.82.8"


def test_safe_litellm_not_flagged(tmpdir):
    _write_text(os.path.join(tmpdir, "requirements.txt"), "litellm==1.82.6\n")
    findings = _scan_requirements(tmpdir)
    assert len(findings) == 0


def test_detects_litellm_in_pipfile_lock(tmpdir):
    _write_json(os.path.join(tmpdir, "Pipfile.lock"), {
        "_meta": {},
        "default": {
            "litellm": {"version": "==1.82.7"},
        },
        "develop": {},
    })
    findings = _scan_requirements(tmpdir)
    assert len(findings) == 1
    assert findings[0].package == "litellm"


def test_detects_litellm_in_poetry_lock(tmpdir):
    _write_text(os.path.join(tmpdir, "poetry.lock"), """
[[package]]
name = "litellm"
version = "1.82.7"
description = "Library"
""")
    findings = _scan_requirements(tmpdir)
    assert len(findings) == 1


# ── Unified scanner ──────────────────────────────────────────────────────────


def test_scan_project_clean_dir(tmpdir):
    findings = scan_project(tmpdir)
    assert len(findings) == 0


def test_scan_project_finds_all(tmpdir):
    # npm threat
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/axios": {"version": "1.14.1"},
            "node_modules/plain-crypto-js": {"version": "4.2.1"},
        },
    })
    # Python threat
    _write_text(os.path.join(tmpdir, "requirements.txt"), "litellm==1.82.7\n")

    findings = scan_project(tmpdir)
    assert len(findings) == 3

    packages = {f.package for f in findings}
    assert "axios" in packages
    assert "plain-crypto-js" in packages
    assert "litellm" in packages


def test_scan_project_deduplicates(tmpdir):
    # Same threat in lockfile v1 deps AND v3 packages — should deduplicate
    _write_json(os.path.join(tmpdir, "package-lock.json"), {
        "name": "test",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/axios": {"version": "1.14.1"},
        },
        "dependencies": {
            "axios": {"version": "1.14.1"},
        },
    })
    findings = scan_project(tmpdir)
    # Both v1 and v3 point to same lockfile — deduplicated to 1
    axios_findings = [f for f in findings if f.package == "axios"]
    assert len(axios_findings) == 1


def test_no_lockfile_no_crash(tmpdir):
    # Empty dir — should return empty, not crash
    findings = scan_project(tmpdir)
    assert findings == []


def test_malformed_lockfile_no_crash(tmpdir):
    _write_text(os.path.join(tmpdir, "package-lock.json"), "not json at all {{{")
    findings = scan_project(tmpdir)
    assert findings == []
