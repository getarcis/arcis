//! End-to-end CLI tests for cli-audit.md item 9 (baseline mode) and
//! item 8 standalone (`--severity`).
//!
//! These spawn the actual `arcis` binary via `CARGO_BIN_EXE_arcis` so
//! the assertions cover argv parsing, mutex enforcement, file IO,
//! exit codes, and JSON shape end-to-end. Unit tests in `audit.rs`
//! cover individual fns; this file pins the user-visible contract.
//!
//! ## Fixture conventions
//!
//! * Each test uses its own [`tempfile::TempDir`] for hermetic source
//!   trees and baseline files.
//! * Source fixtures use real audit rule patterns so the scanner
//!   actually fires (`eval(...)` → `EVAL-EXEC` critical, `yaml.load(f)`
//!   → `YAML-UNSAFE` high). Avoids stubbing the engine.
//! * Baseline files are JSON the test writes directly when it needs
//!   to pin specific contents (e.g. stale-rule case, version mismatch);
//!   otherwise we round-trip via `--baseline-write`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const ARCIS_BIN: &str = env!("CARGO_BIN_EXE_arcis");

// ── Helpers ────────────────────────────────────────────────────────────────

struct RunOutput {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run_audit(cwd: &Path, args: &[&str]) -> RunOutput {
    let out = Command::new(ARCIS_BIN)
        .arg("audit")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn arcis audit");
    RunOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

fn write_fixture(td: &Path, rel: &str, body: &str) -> PathBuf {
    let p = td.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, body).unwrap();
    p
}

/// A Python source body that fires multiple rules at known severities.
/// Used as the "before" snapshot in drift tests.
const PY_MIXED: &str = "\
import yaml
def parse(s):
    return yaml.load(s)

def run(expr):
    return eval(expr)
";

/// Two findings — same shape as `PY_MIXED` but no `eval`. Used as the
/// "after fixing critical" snapshot in resolved-finding tests.
const PY_YAML_ONLY: &str = "\
import yaml
def parse(s):
    return yaml.load(s)

def run(expr):
    return parse(expr)
";

// ── Round-trip ─────────────────────────────────────────────────────────────

#[test]
fn baseline_write_then_read_roundtrip_no_new_findings() {
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src, "a.py", PY_MIXED);

    let baseline_path = td.path().join("base.json");

    // Pass 1: write baseline.
    let r1 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline-write",
            baseline_path.to_str().unwrap(),
            "--quiet",
        ],
    );
    assert_eq!(r1.code, 0, "write run must exit 0 (recording is success)");
    assert!(
        baseline_path.exists(),
        "baseline file should have been written"
    );
    let raw = std::fs::read_to_string(&baseline_path).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(v["version"], Value::from(1));
    assert!(v["createdAt"].as_str().unwrap().ends_with('Z'));
    assert!(
        v["findings"].as_array().unwrap().len() >= 2,
        "expected at least 2 baseline entries, got {raw}"
    );

    // Pass 2: read baseline. No source change → zero added → exit 0.
    let r2 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        r2.code, 0,
        "round-trip read must exit 0 with no new findings (got {}: stderr={})",
        r2.code, r2.stderr
    );
    let doc: Value = serde_json::from_str(&r2.stdout).unwrap();
    assert_eq!(doc["summary"]["baseline"]["added"], Value::from(0));
    assert!(
        doc["summary"]["baseline"]["unchangedCount"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert_eq!(doc["findings"].as_array().unwrap().len(), 0);
    assert_eq!(doc["resolvedFindings"].as_array().unwrap().len(), 0);
}

// ── Drift +1 ───────────────────────────────────────────────────────────────

#[test]
fn baseline_diff_detects_added_finding() {
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src, "a.py", PY_YAML_ONLY);

    let baseline_path = td.path().join("base.json");

    // Pass 1: write baseline at the "before adding eval" state.
    let r1 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline-write",
            baseline_path.to_str().unwrap(),
            "--quiet",
        ],
    );
    assert_eq!(r1.code, 0);

    // Mutate source: add an eval call (= a new EVAL-EXEC finding).
    std::fs::write(src.join("a.py"), PY_MIXED).unwrap();

    // Pass 2: diff. Expect exit 1 + exactly one added finding.
    let r2 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        r2.code, 1,
        "expected exit 1 on new finding, got {}: stderr={}",
        r2.code, r2.stderr
    );
    let doc: Value = serde_json::from_str(&r2.stdout).unwrap();
    assert_eq!(doc["summary"]["baseline"]["added"], Value::from(1));
    let arr = doc["findings"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["ruleId"], Value::from("EVAL-EXEC"));
}

// ── Drift -1 (resolved) ────────────────────────────────────────────────────

#[test]
fn baseline_diff_detects_resolved_finding() {
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src, "a.py", PY_MIXED);

    let baseline_path = td.path().join("base.json");
    let r1 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline-write",
            baseline_path.to_str().unwrap(),
            "--quiet",
        ],
    );
    assert_eq!(r1.code, 0);

    // Remove the eval — EVAL-EXEC finding goes away.
    std::fs::write(src.join("a.py"), PY_YAML_ONLY).unwrap();

    let r2 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(
        r2.code, 0,
        "resolved-only run must NOT fail (positive signal): code={} stderr={}",
        r2.code, r2.stderr
    );
    let doc: Value = serde_json::from_str(&r2.stdout).unwrap();
    assert_eq!(doc["summary"]["baseline"]["added"], Value::from(0));
    assert_eq!(doc["summary"]["baseline"]["resolvedCount"], Value::from(1));
    let resolved = doc["resolvedFindings"].as_array().unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0]["ruleId"], Value::from("EVAL-EXEC"));
}

// ── Severity × baseline (item 8 fold-in) ───────────────────────────────────

#[test]
fn severity_filter_applies_before_baseline_classification() {
    // Severity-filter runs BEFORE diff classification. A baseline
    // captured at default severity contains a YAML-UNSAFE (high) AND
    // a JSONP-CALLBACK (medium). Re-running with `--severity high`
    // filters the medium out of the current run, so it surfaces as
    // resolved relative to the baseline — even though the source
    // didn't change. Documented behavior; pin it here.
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Mixed-severity source: high (yaml.load) + medium (JSONP via
    // request.args.get('callback')).
    write_fixture(
        &src,
        "a.py",
        "\
import yaml
def parse(s):
    return yaml.load(s)

def jsonp(request):
    cb = request.args.get('callback')
    return cb
",
    );

    let baseline_path = td.path().join("base.json");
    let r1 = run_audit(
        td.path(),
        &[
            "src",
            "--baseline-write",
            baseline_path.to_str().unwrap(),
            "--quiet",
        ],
    );
    assert_eq!(r1.code, 0);

    // Filter to high+ AND diff. Medium baseline entry must surface
    // as resolved even though the code path still exists.
    let r2 = run_audit(
        td.path(),
        &[
            "src",
            "--severity",
            "high",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--json",
        ],
    );
    let doc: Value = serde_json::from_str(&r2.stdout).unwrap();
    assert_eq!(doc["severityFilter"], Value::from("high"));
    let resolved = doc["resolvedFindings"].as_array().unwrap();
    let resolved_rule_ids: Vec<&str> = resolved
        .iter()
        .map(|e| e.get("ruleId").and_then(Value::as_str).unwrap_or(""))
        .collect();
    assert!(
        resolved_rule_ids.contains(&"JSONP-CALLBACK"),
        "medium-severity baseline entry should surface as resolved when filtered out by --severity high; got {resolved_rule_ids:?}",
    );
    assert_eq!(
        r2.code, 0,
        "no NEW findings → exit 0 even though the medium entry is now classified as resolved"
    );
}

// ── Standalone --severity (item 8 independent pin per refinement #1) ───────

#[test]
fn severity_filter_applies_to_findings_without_baseline() {
    // Pins the standalone --severity behavior independently of the
    // baseline machinery, so a future refactor to baseline-mode can't
    // silently break the `--severity` contract.
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // Mixed: critical (eval) + high (yaml.load) + medium (jsonp).
    write_fixture(
        &src,
        "a.py",
        "\
import yaml

def run(expr):
    return eval(expr)

def parse(s):
    return yaml.load(s)

def jsonp(request):
    cb = request.args.get('callback')
    return cb
",
    );

    let r = run_audit(td.path(), &["src", "--severity", "high", "--json"]);
    assert_eq!(r.code, 1, "findings present → exit 1: stderr={}", r.stderr);
    let doc: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(doc["severityFilter"], Value::from("high"));
    let arr = doc["findings"].as_array().unwrap();
    let rule_ids: Vec<&str> = arr.iter().map(|e| e["ruleId"].as_str().unwrap()).collect();
    // critical + high pass; medium dropped.
    assert!(
        rule_ids.contains(&"EVAL-EXEC"),
        "critical EVAL-EXEC must pass `--severity high`: {rule_ids:?}"
    );
    assert!(
        rule_ids.contains(&"YAML-UNSAFE"),
        "high YAML-UNSAFE must pass `--severity high`: {rule_ids:?}"
    );
    assert!(
        !rule_ids.contains(&"JSONP-CALLBACK"),
        "medium JSONP-CALLBACK must be dropped by `--severity high`: {rule_ids:?}"
    );
    // Sanity: no baseline block, no resolvedFindings key.
    assert!(doc["summary"].get("baseline").is_none());
    assert!(doc.get("resolvedFindings").is_none());
}

// ── Stale rule ─────────────────────────────────────────────────────────────

#[test]
fn baseline_with_stale_rule_id_warns_but_does_not_fail() {
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    // Clean source — no current findings. Isolates the stale-baseline
    // signal so we test it without an added finding muddying the exit
    // code. The fixture HAS to be clean: a current finding becomes a
    // NEW (in current, not in baseline) entry and pushes exit to 1,
    // which is a different code path than the one this test pins.
    write_fixture(&src, "a.py", "def hello():\n    return 1\n");

    // Hand-craft a baseline whose rule_id no longer exists in the
    // registry. classify() must surface staleCount > 0 + the rule
    // name, but exit code stays 0 (no NEW findings) — staleness is
    // informational, not a failure.
    let baseline_path = td.path().join("base.json");
    let stale = r#"{
        "version": 1,
        "createdAt": "2026-05-07T00:00:00Z",
        "toolVersion": "0.1.0",
        "findings": [
            {"id": "BOGUS-RULE-NEVER-EXISTED-1111111111111111",
             "ruleId": "BOGUS-RULE-NEVER-EXISTED",
             "file": "src/a.py",
             "line": 1}
        ]
    }"#;
    std::fs::write(&baseline_path, stale).unwrap();

    let r = run_audit(
        td.path(),
        &[
            "src",
            "--baseline",
            baseline_path.to_str().unwrap(),
            "--json",
        ],
    );
    let doc: Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(doc["summary"]["baseline"]["staleCount"], Value::from(1));
    // The stale entry has no current-run match, so it ALSO appears as
    // resolved. Both count.
    assert_eq!(doc["summary"]["baseline"]["resolvedCount"], Value::from(1));
    assert_eq!(
        r.code, 0,
        "stale-only baseline must not fail the run: stderr={}",
        r.stderr
    );
}

// ── Schema errors ──────────────────────────────────────────────────────────

#[test]
fn baseline_unsupported_version_errors_with_exit_2() {
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src, "a.py", PY_YAML_ONLY);

    let baseline_path = td.path().join("base.json");
    std::fs::write(
        &baseline_path,
        r#"{
            "version": 999,
            "createdAt": "2026-05-07T00:00:00Z",
            "toolVersion": "0.1.0",
            "findings": []
        }"#,
    )
    .unwrap();

    let r = run_audit(
        td.path(),
        &["src", "--baseline", baseline_path.to_str().unwrap()],
    );
    assert_eq!(r.code, 2, "unsupported version → exit 2");
    assert!(
        r.stderr.contains("schema version") || r.stderr.contains("not supported"),
        "stderr should explain the version mismatch: {}",
        r.stderr
    );
}

#[test]
fn baseline_file_not_found_errors_with_exit_2() {
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src, "a.py", PY_YAML_ONLY);

    let r = run_audit(td.path(), &["src", "--baseline", "does/not/exist.json"]);
    assert_eq!(r.code, 2, "missing baseline → exit 2");
    assert!(
        r.stderr.contains("baseline file not found") || r.stderr.contains("not found"),
        "stderr should mention the missing baseline: {}",
        r.stderr
    );
}

// ── Mutex (parse-side) ─────────────────────────────────────────────────────

#[test]
fn baseline_and_baseline_write_mutex_errors_with_second_flag_named() {
    // Refinement: error message points to the second/offending flag
    // by name so users editing a config can find it quickly.
    let td = tempfile::TempDir::new().unwrap();
    let r = run_audit(
        td.path(),
        &[".", "--baseline", "b.json", "--baseline-write", "w.json"],
    );
    assert_eq!(r.code, 2, "mutex violation → exit 2");
    assert!(
        r.stderr.contains("--baseline-write"),
        "second flag must be named in the error: {}",
        r.stderr
    );
    assert!(
        r.stderr.contains("conflicts with --baseline"),
        "error must show prior flag for context: {}",
        r.stderr
    );
}

// ── --baseline-write coexistence with machine modes ────────────────────────

#[test]
fn baseline_write_with_json_emits_both_file_and_machine_output() {
    // --baseline-write + --json: write the file AND emit JSON to
    // stdout (no diff filtering, since this is write mode). Exit 0.
    let td = tempfile::TempDir::new().unwrap();
    let src = td.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    write_fixture(&src, "a.py", PY_MIXED);

    let baseline_path = td.path().join("base.json");
    let r = run_audit(
        td.path(),
        &[
            "src",
            "--baseline-write",
            baseline_path.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(r.code, 0, "write-mode always exits 0: stderr={}", r.stderr);
    assert!(baseline_path.exists(), "baseline file must be written");

    // stdout is valid JSON with the full findings (NO baseline block,
    // since we wrote, didn't read).
    let doc: Value = serde_json::from_str(&r.stdout).unwrap();
    assert!(doc["summary"].get("baseline").is_none());
    assert!(doc.get("resolvedFindings").is_none());
    assert!(
        doc["findings"].as_array().unwrap().len() >= 2,
        "machine output must reflect ALL findings in write mode, got: {}",
        r.stdout
    );
}
