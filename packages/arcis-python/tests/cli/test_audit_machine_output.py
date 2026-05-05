"""
Tests for `arcis audit --json` and `arcis audit --sarif`.

Covers the two machine-readable output modes added for CI consumption
(plan: cli-audit.md Phase A items 4 + 5).
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

from arcis.cli.audit import Finding, render_json, render_sarif


# ── Helper ───────────────────────────────────────────────────────────────────

def _write_temp(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _run_cli(args):
    """Invoke main() in a child process so sys.exit doesn't terminate pytest.
    Returns (exit_code, stdout, stderr)."""
    code = (
        "import sys; "
        f"sys.argv = {['arcis-audit'] + list(args)!r}; "
        "from arcis.cli.audit import main; main()"
    )
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


# ── render_json — pure renderer ──────────────────────────────────────────────

class TestRenderJson:
    def test_returns_valid_json(self):
        out = render_json(
            target="/tmp/x",
            findings=[],
            files_scanned=0,
            languages={},
            rules_applied=14,
            sev_counts={},
            duration_seconds=0.0,
        )
        json.loads(out)  # must not raise

    def test_top_level_shape(self):
        doc = json.loads(render_json(
            target="/tmp/x",
            findings=[],
            files_scanned=3,
            languages={"python": 3},
            rules_applied=14,
            sev_counts={},
            duration_seconds=0.5,
        ))
        assert doc["tool"] == "arcis-audit"
        assert doc["target"] == "/tmp/x"
        assert doc["durationMs"] == 500
        assert doc["summary"]["filesScanned"] == 3
        assert doc["summary"]["rulesApplied"] == 14
        assert doc["summary"]["byLanguage"] == {"python": 3}
        assert doc["summary"]["totalFindings"] == 0
        assert doc["findings"] == []

    def test_findings_serialised(self):
        f = Finding(
            rule_id="YAML-UNSAFE",
            severity="high",
            message="yaml.load() without SafeLoader",
            file="/tmp/a.py",
            line=42,
            snippet="yaml.load(f)",
        )
        doc = json.loads(render_json(
            target="/tmp",
            findings=[f],
            files_scanned=1,
            languages={"python": 1},
            rules_applied=14,
            sev_counts={"high": 1},
            duration_seconds=0.1,
        ))
        assert doc["summary"]["bySeverity"] == {"high": 1}
        assert doc["summary"]["totalFindings"] == 1
        assert len(doc["findings"]) == 1
        finding = doc["findings"][0]
        assert finding["ruleId"] == "YAML-UNSAFE"
        assert finding["severity"] == "high"
        assert finding["file"] == "/tmp/a.py"
        assert finding["line"] == 42
        assert finding["snippet"] == "yaml.load(f)"

    def test_severity_filter_recorded(self):
        doc = json.loads(render_json(
            target="/tmp",
            findings=[],
            files_scanned=0,
            languages={},
            rules_applied=14,
            sev_counts={},
            duration_seconds=0.0,
            severity_filter="high",
        ))
        assert doc["severityFilter"] == "high"


# ── render_sarif — pure renderer ─────────────────────────────────────────────

class TestRenderSarif:
    def test_returns_valid_json(self):
        out = render_sarif(target="/tmp", findings=[])
        json.loads(out)

    def test_sarif_version(self):
        doc = json.loads(render_sarif(target="/tmp", findings=[]))
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        assert doc["runs"][0]["tool"]["driver"]["name"] == "arcis-audit"

    def test_severity_to_sarif_level(self):
        critical = Finding("EVAL-EXEC", "critical", "eval", "/x.py", 1, "eval(x)")
        high = Finding("YAML-UNSAFE", "high", "yaml", "/x.py", 2, "yaml.load(f)")
        medium = Finding("JSONP-CALLBACK", "medium", "jsonp", "/x.py", 3, "callback")
        low = Finding("X", "low", "low", "/x.py", 4, "x")
        doc = json.loads(render_sarif(target="/tmp", findings=[critical, high, medium, low]))
        levels = [r["level"] for r in doc["runs"][0]["results"]]
        assert levels == ["error", "error", "warning", "note"]

    def test_only_referenced_rules_included(self):
        f = Finding("YAML-UNSAFE", "high", "yaml", "/x.py", 1, "yaml.load(f)")
        doc = json.loads(render_sarif(target="/tmp", findings=[f]))
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["YAML-UNSAFE"]

    def test_dedupes_rules(self):
        f1 = Finding("YAML-UNSAFE", "high", "y", "/a.py", 1, "yaml.load(f)")
        f2 = Finding("YAML-UNSAFE", "high", "y", "/b.py", 5, "yaml.load(g)")
        doc = json.loads(render_sarif(target="/tmp", findings=[f1, f2]))
        rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["YAML-UNSAFE"]
        assert len(doc["runs"][0]["results"]) == 2

    def test_uri_uses_forward_slashes(self):
        f = Finding("YAML-UNSAFE", "high", "y", os.path.join("a", "b", "c.py"), 1, "yaml.load(f)")
        doc = json.loads(render_sarif(target="/tmp", findings=[f]))
        uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri
        assert "/" in uri or uri == "c.py" or uri.endswith("c.py")

    def test_omits_null_snippet(self):
        f = Finding("X", "high", "y", "/a.py", 1, "")
        doc = json.loads(render_sarif(target="/tmp", findings=[f]))
        region = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert "snippet" not in region


# ── End-to-end CLI behavior ──────────────────────────────────────────────────

class TestCliJsonMode:
    def test_json_mode_emits_valid_json_with_findings(self):
        path = _write_temp("import yaml\ndata = yaml.load(f)\n", ".py")
        try:
            code, out, err = _run_cli([path, "--json"])
            assert code == 1, f"expected exit 1 (findings present), got {code}; stderr={err}"
            doc = json.loads(out)
            assert doc["summary"]["totalFindings"] >= 1
            assert any(f["ruleId"] == "YAML-UNSAFE" for f in doc["findings"])
        finally:
            os.unlink(path)

    def test_json_mode_clean_repo_exits_zero(self):
        path = _write_temp("x = 1\n", ".py")
        try:
            code, out, err = _run_cli([path, "--json"])
            assert code == 0
            doc = json.loads(out)
            assert doc["summary"]["totalFindings"] == 0
            assert doc["findings"] == []
        finally:
            os.unlink(path)

    def test_json_mode_suppresses_human_output(self):
        """JSON mode must produce ONLY a JSON document on stdout — no header,
        progress, or summary text mixed in (CI parsers will choke)."""
        path = _write_temp("import yaml\ndata = yaml.load(f)\n", ".py")
        try:
            code, out, err = _run_cli([path, "--json"])
            stripped = out.strip()
            assert stripped.startswith("{") and stripped.endswith("}")
            json.loads(stripped)  # whole stdout is one JSON doc
            # Sanity: no ANSI codes, no "Arcis Audit" banner.
            assert "\033[" not in out
            assert "Arcis Audit" not in out
            assert "Summary" not in out
        finally:
            os.unlink(path)

    def test_json_mode_no_scannable_files_emits_empty_doc(self):
        with tempfile.TemporaryDirectory() as d:
            # Empty dir → no scannable files. Should still emit valid JSON.
            code, out, err = _run_cli([d, "--json"])
            assert code == 2
            doc = json.loads(out)
            assert doc["summary"]["totalFindings"] == 0
            assert doc["findings"] == []


class TestCliSarifMode:
    def test_sarif_mode_emits_valid_sarif(self):
        path = _write_temp("import yaml\ndata = yaml.load(f)\n", ".py")
        try:
            code, out, err = _run_cli([path, "--sarif"])
            assert code == 1
            doc = json.loads(out)
            assert doc["version"] == "2.1.0"
            assert doc["runs"][0]["tool"]["driver"]["name"] == "arcis-audit"
            assert len(doc["runs"][0]["results"]) >= 1
        finally:
            os.unlink(path)

    def test_sarif_mode_clean_repo(self):
        path = _write_temp("x = 1\n", ".py")
        try:
            code, out, err = _run_cli([path, "--sarif"])
            assert code == 0
            doc = json.loads(out)
            assert doc["runs"][0]["results"] == []
            assert doc["runs"][0]["tool"]["driver"]["rules"] == []
        finally:
            os.unlink(path)


class TestCliMutex:
    def test_json_and_sarif_are_mutually_exclusive(self):
        code, out, err = _run_cli([".", "--json", "--sarif"])
        assert code == 2
        assert "mutually exclusive" in err
