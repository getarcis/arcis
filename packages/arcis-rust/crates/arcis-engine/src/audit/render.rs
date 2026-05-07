//! Machine-readable output renderers for `arcis audit`.
//!
//! Direct ports of `render_json` + `render_sarif` from
//! `packages/arcis-python/arcis/cli/audit.py`. The contract is byte-equal
//! output to the Python implementation, pinned by the 18 tests in
//! `packages/arcis-python/tests/cli/test_audit_machine_output.py`.
//!
//! ## Byte-equal alignment notes
//!
//! Three Python defaults that must be honoured:
//!
//! * `json.dumps(..., indent=2)` — 2-space indent, `": "` between key and
//!   value, `,\n` between items. `serde_json::to_string_pretty` matches
//!   these defaults exactly.
//! * `ensure_ascii=True` (the Python default) — codepoints `>= U+0080`
//!   are escaped as `\uXXXX` (BMP) or surrogate pairs (supplementary
//!   plane). serde_json does NOT do this; we post-process its output via
//!   [`escape_non_ascii`].
//! * Dict iteration order: Python 3.7+ preserves insertion order. We
//!   need explicit field ordering via the workspace-level `preserve_order`
//!   feature on `serde_json`. The two summary maps that Python builds in
//!   walk order (`byLanguage`, `bySeverity`) are sorted both here and in
//!   `audit.py` so the key sequence is deterministic regardless of FS
//!   walk order.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::engine::Finding;
use super::rules::{rules as compiled_rules, Rule, Severity};

// ── render_json ─────────────────────────────────────────────────────────────

/// Inputs for [`render_json`]. Mirrors the kwargs of Python's
/// `render_json` one-for-one, plus an explicit `tool_version` so the
/// caller controls what shows up in the `version` field.
pub struct JsonReport<'a> {
    /// Goes in the `version` field. Python reads `arcis.__version__`;
    /// the Rust CLI passes `env!("CARGO_PKG_VERSION")` (note: the two
    /// strings will diverge until Python becomes SDK-only — flag for
    /// strip-fields handling in the parity harness).
    pub tool_version: &'a str,
    pub target: &'a str,
    pub findings: &'a [Finding],
    pub files_scanned: usize,
    /// Sorted keys; iteration order ends up in JSON output verbatim.
    /// Use a `BTreeMap` for guaranteed alphabetical ordering.
    pub by_language: &'a BTreeMap<String, usize>,
    pub rules_applied: usize,
    /// Ordered by [`Severity`] enum (Critical, High, Medium, Low).
    pub by_severity: &'a BTreeMap<Severity, usize>,
    pub duration_ms: u64,
    pub severity_filter: Option<Severity>,
    /// Findings that fired but were silenced by a suppress-comment
    /// directive (cli-audit.md item 6). Surfaces as
    /// `summary.suppressed` in the JSON output. Suppressed findings
    /// are NOT included in the `findings` array — only the count
    /// surfaces, by design.
    pub suppressed: usize,
    /// Files excluded by an `.arcisignore` / `.gitignore` /
    /// `.git/info/exclude` rule (cli-audit.md item 7). Surfaces as
    /// `summary.ignored` in the JSON output. Always emitted (zero is
    /// informative — confirms the field exists even on a clean run).
    /// Ignored files do NOT appear in `filesScanned` or `byLanguage`.
    pub ignored: usize,
}

/// Render the audit result as a JSON document. Schema:
/// ```text
/// {
///   "tool": "arcis-audit",
///   "version": "<tool_version>",
///   "target": "<target>",
///   "durationMs": N,
///   "severityFilter": "high" | null,
///   "summary": {
///     "filesScanned": N,
///     "rulesApplied": N,
///     "byLanguage": { ... sorted ... },
///     "bySeverity": { "critical": N, "high": N, "medium": N, "low": N },
///     "totalFindings": N
///   },
///   "findings": [
///     { "ruleId": "...", "severity": "...", "message": "...",
///       "file": "...", "line": N, "snippet": "..." }
///   ]
/// }
/// ```
pub fn render_json(report: &JsonReport<'_>) -> String {
    let mut doc = Map::new();
    doc.insert("tool".into(), Value::from("arcis-audit"));
    doc.insert("version".into(), Value::from(report.tool_version));
    doc.insert("target".into(), Value::from(report.target));
    doc.insert("durationMs".into(), Value::from(report.duration_ms));
    doc.insert(
        "severityFilter".into(),
        match report.severity_filter {
            Some(s) => Value::from(s.as_str()),
            None => Value::Null,
        },
    );

    let mut summary = Map::new();
    summary.insert("filesScanned".into(), Value::from(report.files_scanned));
    summary.insert("rulesApplied".into(), Value::from(report.rules_applied));

    let mut by_lang = Map::new();
    for (k, v) in report.by_language {
        by_lang.insert(k.clone(), Value::from(*v));
    }
    summary.insert("byLanguage".into(), Value::Object(by_lang));

    let mut by_sev = Map::new();
    for (k, v) in report.by_severity {
        by_sev.insert(k.as_str().into(), Value::from(*v));
    }
    summary.insert("bySeverity".into(), Value::Object(by_sev));

    summary.insert("totalFindings".into(), Value::from(report.findings.len()));
    // cli-audit.md item 6: count of suppress-comment-silenced findings.
    // Always emitted (zero is informative — confirms the field exists
    // even on a clean run). Suppressed findings themselves are NOT
    // listed; only the count.
    summary.insert("suppressed".into(), Value::from(report.suppressed));
    // cli-audit.md item 7: count of files excluded by `.arcisignore` /
    // `.gitignore` / `.git/info/exclude`. Always emitted (same noise
    // tradeoff as `suppressed`); the human report hides the line at 0.
    summary.insert("ignored".into(), Value::from(report.ignored));
    doc.insert("summary".into(), Value::Object(summary));

    let mut findings_arr = Vec::with_capacity(report.findings.len());
    for f in report.findings {
        let mut item = Map::new();
        item.insert("ruleId".into(), Value::from(f.rule_id));
        // `id` is the deterministic `<RULE_ID>-<16hex>` fingerprint.
        // Sits second so consumers can scan a finding's identity in the
        // first two keys without paging through the message/file/line
        // body. cli-audit.md item 10.
        item.insert("id".into(), Value::from(f.id.as_str()));
        item.insert("severity".into(), Value::from(f.severity.as_str()));
        item.insert("message".into(), Value::from(f.message));
        item.insert("file".into(), Value::from(f.file.as_str()));
        item.insert("line".into(), Value::from(f.line));
        item.insert("snippet".into(), Value::from(f.snippet.as_str()));
        findings_arr.push(Value::Object(item));
    }
    doc.insert("findings".into(), Value::Array(findings_arr));

    let raw = serde_json::to_string_pretty(&Value::Object(doc))
        .expect("serde_json never fails on values built from owned data");
    escape_non_ascii(&raw)
}

// ── render_sarif ────────────────────────────────────────────────────────────

/// Inputs for [`render_sarif`].
pub struct SarifReport<'a> {
    pub tool_version: &'a str,
    /// Absolute path to the scanned target. Goes into
    /// `runs[0].originalUriBaseIds.TARGET.uri` after `\\`-to-`/`
    /// normalization and a trailing `/`.
    pub target_abspath: &'a str,
    pub findings: &'a [Finding],
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Render the audit result as SARIF 2.1.0 for GitHub Code Scanning.
/// Mirrors `audit.py:render_sarif` field-for-field. The rules table is
/// built only from rules referenced by findings, in first-occurrence
/// order — Python does the same.
pub fn render_sarif(report: &SarifReport<'_>) -> String {
    // First-occurrence order of rule ids in findings.
    let mut rule_ids: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in report.findings {
        if seen.insert(f.rule_id) {
            rule_ids.push(f.rule_id);
        }
    }

    // O(1) rule lookup by id.
    let rule_by_id: std::collections::HashMap<&str, &Rule> =
        compiled_rules().iter().map(|r| (r.id, r)).collect();

    // Build the SARIF rules entries for the run.tool.driver.rules slot.
    let mut sarif_rules = Vec::with_capacity(rule_ids.len());
    for rid in &rule_ids {
        let rule = rule_by_id.get(rid).copied();
        let msg = rule.map(|r| r.message).unwrap_or(rid);
        // Python: `msg.split(" — ")[0][:120]`. Em-dash separator.
        let short = msg
            .split_once(" \u{2014} ")
            .map(|(before, _)| before)
            .unwrap_or(msg);
        let short_120: String = short.chars().take(120).collect();
        let level = rule.map(|r| sarif_level(r.severity)).unwrap_or("warning");

        let mut entry = Map::new();
        entry.insert("id".into(), Value::from(*rid));
        entry.insert("name".into(), Value::from(*rid));
        let mut short_obj = Map::new();
        short_obj.insert("text".into(), Value::from(short_120));
        entry.insert("shortDescription".into(), Value::Object(short_obj));
        let mut full_obj = Map::new();
        full_obj.insert("text".into(), Value::from(msg));
        entry.insert("fullDescription".into(), Value::Object(full_obj));
        let mut default_cfg = Map::new();
        default_cfg.insert("level".into(), Value::from(level));
        entry.insert("defaultConfiguration".into(), Value::Object(default_cfg));
        sarif_rules.push(Value::Object(entry));
    }

    // Build the run.results slot.
    let mut results = Vec::with_capacity(report.findings.len());
    for f in report.findings {
        // Python: `os.path.relpath(f.file).replace(os.sep, "/")`. We
        // compute relpath-from-cwd; if the path can't be relativized
        // (different drive on Windows, for example) we fall back to the
        // raw string with `\\` flipped to `/`.
        let rel = relpath_from_cwd(&f.file).replace('\\', "/");

        let mut region = Map::new();
        region.insert("startLine".into(), Value::from(f.line));
        if !f.snippet.is_empty() {
            // SARIF validators reject null fields; emit the snippet
            // sub-object only when there's content. Matches Python's
            // post-construction `region.pop("snippet", None)` cleanup.
            let mut snip = Map::new();
            snip.insert("text".into(), Value::from(f.snippet.as_str()));
            region.insert("snippet".into(), Value::Object(snip));
        }

        let mut artifact = Map::new();
        artifact.insert("uri".into(), Value::from(rel));

        let mut physical = Map::new();
        physical.insert("artifactLocation".into(), Value::Object(artifact));
        physical.insert("region".into(), Value::Object(region));

        let mut location = Map::new();
        location.insert("physicalLocation".into(), Value::Object(physical));

        let mut result = Map::new();
        result.insert("ruleId".into(), Value::from(f.rule_id));
        result.insert("level".into(), Value::from(sarif_level(f.severity)));
        let mut message = Map::new();
        message.insert("text".into(), Value::from(f.message));
        result.insert("message".into(), Value::Object(message));
        result.insert(
            "locations".into(),
            Value::Array(vec![Value::Object(location)]),
        );
        // SARIF 2.1.0 §3.27.16: `partialFingerprints` is a tool-defined
        // map that GitHub Code Scanning hashes for cross-run de-dupe.
        // Versioned key (`arcis/v1`) gives us a clean rotation lane if
        // we ever change the hash function — bumping to `arcis/v2`
        // signals to GitHub that the fingerprint domain shifted.
        // Empty `id` (scan_file path that bypassed assign_ids) is
        // skipped so we don't emit empty-string fingerprints.
        if !f.id.is_empty() {
            let mut pf = Map::new();
            pf.insert("arcis/v1".into(), Value::from(f.id.as_str()));
            result.insert("partialFingerprints".into(), Value::Object(pf));
        }
        results.push(Value::Object(result));
    }

    // Tool / driver block.
    let mut driver = Map::new();
    driver.insert("name".into(), Value::from("arcis-audit"));
    driver.insert("version".into(), Value::from(report.tool_version));
    driver.insert("informationUri".into(), Value::from("https://arcis.dev"));
    driver.insert("rules".into(), Value::Array(sarif_rules));

    let mut tool = Map::new();
    tool.insert("driver".into(), Value::Object(driver));

    // Run block.
    let target_uri = {
        let normalized = report.target_abspath.replace('\\', "/");
        let trimmed = normalized.trim_end_matches('/');
        format!("{trimmed}/")
    };
    let mut target_obj = Map::new();
    target_obj.insert("uri".into(), Value::from(target_uri));
    let mut original_uri_base_ids = Map::new();
    original_uri_base_ids.insert("TARGET".into(), Value::Object(target_obj));

    let mut run = Map::new();
    run.insert("tool".into(), Value::Object(tool));
    run.insert("results".into(), Value::Array(results));
    run.insert(
        "originalUriBaseIds".into(),
        Value::Object(original_uri_base_ids),
    );

    // Top-level doc.
    let mut doc = Map::new();
    doc.insert("version".into(), Value::from("2.1.0"));
    doc.insert(
        "$schema".into(),
        Value::from(
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        ),
    );
    doc.insert("runs".into(), Value::Array(vec![Value::Object(run)]));

    let raw = serde_json::to_string_pretty(&Value::Object(doc))
        .expect("serde_json never fails on values built from owned data");
    escape_non_ascii(&raw)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Mirror Python's `json.dumps(..., ensure_ascii=True)`: any codepoint
/// `>= U+0080` is escaped as `\uXXXX`. Codepoints in the supplementary
/// plane (`>= U+10000`) are emitted as a surrogate pair, also matching
/// Python.
///
/// serde_json's pretty output is well-formed JSON in UTF-8: every byte
/// `>= 0x80` is part of a non-ASCII codepoint INSIDE a string literal
/// (existing escape sequences like `\\n`, `\\\"`, `\\uXXXX` are entirely
/// ASCII), so walking by `chars()` and re-emitting as escapes is safe.
fn escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp < 0x80 {
            out.push(c);
        } else if cp < 0x10000 {
            out.push_str(&format!("\\u{cp:04x}"));
        } else {
            let v = cp - 0x10000;
            let hi = 0xd800 + (v >> 10);
            let lo = 0xdc00 + (v & 0x3ff);
            out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
        }
    }
    out
}

/// Best-effort port of Python's `os.path.relpath(path)` (start defaults
/// to cwd). Returns the path with cwd stripped; if the input is already
/// relative, returns it unchanged. Doesn't compute `..` to walk up,
/// unlike Python — those edge cases (target outside cwd) are rare for
/// audit and the parity harness will catch any drift.
fn relpath_from_cwd(file: &str) -> String {
    let p = std::path::Path::new(file);
    if !p.is_absolute() {
        return file.to_string();
    }
    let Ok(cwd) = std::env::current_dir() else {
        return file.to_string();
    };
    match p.strip_prefix(&cwd) {
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) => file.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value as Json;

    fn finding(rule_id: &'static str, sev: Severity, file: &str, line: usize) -> Finding {
        // Test fixture id mirrors the live `<RULE_ID>-<16hex>` shape
        // without invoking the hasher — render tests should exercise
        // the renderer, not the hasher.
        Finding {
            rule_id,
            severity: sev,
            message: "yaml.load() without SafeLoader \u{2014} use yaml.safe_load()",
            file: file.to_string(),
            line,
            snippet: "yaml.load(f)".to_string(),
            id: format!("{rule_id}-deadbeefcafef00d"),
        }
    }

    fn parse(s: &str) -> Json {
        serde_json::from_str(s).expect("renderer output must be valid JSON")
    }

    // ── render_json ────────────────────────────────────────────────────

    #[test]
    fn json_top_level_shape_no_findings() {
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let report = JsonReport {
            tool_version: "1.0.0",
            target: "/tmp/x",
            findings: &[],
            files_scanned: 3,
            by_language: &by_lang,
            rules_applied: 14,
            by_severity: &by_sev,
            duration_ms: 500,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        };
        let out = render_json(&report);
        let doc = parse(&out);
        assert_eq!(doc["tool"], Json::from("arcis-audit"));
        assert_eq!(doc["target"], Json::from("/tmp/x"));
        assert_eq!(doc["durationMs"], Json::from(500u64));
        assert_eq!(doc["severityFilter"], Json::Null);
        assert_eq!(doc["summary"]["filesScanned"], Json::from(3u64));
        assert_eq!(doc["summary"]["rulesApplied"], Json::from(14u64));
        assert_eq!(doc["summary"]["totalFindings"], Json::from(0u64));
        // cli-audit.md item 6: suppressed key always present, defaults
        // to 0 even on a clean run.
        assert_eq!(doc["summary"]["suppressed"], Json::from(0u64));
        assert!(doc["findings"].is_array());
        assert_eq!(doc["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_severity_filter_recorded() {
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let report = JsonReport {
            tool_version: "1.0.0",
            target: "/tmp",
            findings: &[],
            files_scanned: 0,
            by_language: &by_lang,
            rules_applied: 14,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: Some(Severity::High),
            suppressed: 0,
            ignored: 0,
        };
        let doc = parse(&render_json(&report));
        assert_eq!(doc["severityFilter"], Json::from("high"));
    }

    #[test]
    fn json_finding_serialised_with_python_field_order() {
        let f = finding("YAML-UNSAFE", Severity::High, "/tmp/a.py", 42);
        let by_lang: BTreeMap<String, usize> = [("python".to_string(), 1)].into_iter().collect();
        let by_sev: BTreeMap<Severity, usize> = [(Severity::High, 1)].into_iter().collect();
        let report = JsonReport {
            tool_version: "1.0.0",
            target: "/tmp",
            findings: std::slice::from_ref(&f),
            files_scanned: 1,
            by_language: &by_lang,
            rules_applied: 14,
            by_severity: &by_sev,
            duration_ms: 100,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        };
        let out = render_json(&report);
        let doc = parse(&out);
        assert_eq!(doc["summary"]["bySeverity"]["high"], Json::from(1u64));
        assert_eq!(doc["summary"]["totalFindings"], Json::from(1u64));
        let arr = doc["findings"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        let item = &arr[0];
        assert_eq!(item["ruleId"], Json::from("YAML-UNSAFE"));
        assert_eq!(item["id"], Json::from("YAML-UNSAFE-deadbeefcafef00d"));
        assert_eq!(item["severity"], Json::from("high"));
        assert_eq!(item["file"], Json::from("/tmp/a.py"));
        assert_eq!(item["line"], Json::from(42u64));
        assert_eq!(item["snippet"], Json::from("yaml.load(f)"));
    }

    #[test]
    fn json_finding_id_appears_second_after_rule_id() {
        // cli-audit.md item 10: `id` sits between `ruleId` and the
        // body fields so consumers see the identity pair up front.
        let f = finding("YAML-UNSAFE", Severity::High, "/tmp/a.py", 42);
        let by_lang: BTreeMap<String, usize> = BTreeMap::new();
        let by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: std::slice::from_ref(&f),
            files_scanned: 1,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        });
        // String-position sniff: ruleId opens the finding object, id
        // follows immediately, severity comes after.
        let rule_pos = out.find("\"ruleId\"").expect("ruleId key in output");
        let id_pos = out.find("\"id\"").expect("id key in output");
        let sev_pos = out.find("\"severity\"").expect("severity key in output");
        assert!(
            rule_pos < id_pos && id_pos < sev_pos,
            "expected ruleId < id < severity in output, got positions \
             rule={rule_pos} id={id_pos} sev={sev_pos}"
        );
    }

    #[test]
    fn json_top_level_field_order_matches_python() {
        // Order is fixed by insertion + preserve_order. Python's
        // render_json builds: tool, version, target, durationMs,
        // severityFilter, summary, findings.
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: &[],
            files_scanned: 0,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        });
        let positions: Vec<usize> = [
            "\"tool\"",
            "\"version\"",
            "\"target\"",
            "\"durationMs\"",
            "\"severityFilter\"",
            "\"summary\"",
            "\"findings\"",
        ]
        .into_iter()
        .map(|key| out.find(key).unwrap_or_else(|| panic!("missing key {key}")))
        .collect();
        for w in positions.windows(2) {
            assert!(w[0] < w[1], "field order broken: {positions:?}");
        }
    }

    #[test]
    fn json_em_dash_in_message_escaped_to_u2014() {
        // Python json.dumps with ensure_ascii=True escapes U+2014 as
        // `—`. Our post-process must do the same.
        let f = finding("YAML-UNSAFE", Severity::High, "/tmp/a.py", 1);
        let by_lang: BTreeMap<String, usize> = BTreeMap::new();
        let by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: std::slice::from_ref(&f),
            files_scanned: 0,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        });
        assert!(
            out.contains("\\u2014"),
            "em dash should be escaped as \\u2014 in output (ensure_ascii=True parity)"
        );
        assert!(
            !out.contains('\u{2014}'),
            "em dash should not appear literally — Python's default escapes it"
        );
    }

    #[test]
    fn json_suppressed_count_emitted_in_summary() {
        // cli-audit.md item 6: when the scan suppressed N findings,
        // `summary.suppressed` reports the count. Suppressed findings
        // do NOT appear in the `findings` array.
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: &[],
            files_scanned: 1,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 12,
            ignored: 0,
        });
        let doc = parse(&out);
        assert_eq!(doc["summary"]["suppressed"], Json::from(12u64));
        assert_eq!(doc["summary"]["totalFindings"], Json::from(0u64));
        assert_eq!(doc["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_ignored_count_emitted_in_summary() {
        // cli-audit.md item 7: when the walker excluded N files via
        // `.arcisignore` / `.gitignore`, `summary.ignored` reports the
        // count. Ignored files do NOT appear in `filesScanned` (the
        // walker drops them before scanning).
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: &[],
            files_scanned: 7,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 0,
            ignored: 4,
        });
        let doc = parse(&out);
        assert_eq!(doc["summary"]["ignored"], Json::from(4u64));
        assert_eq!(doc["summary"]["filesScanned"], Json::from(7u64));
    }

    #[test]
    fn json_ignored_key_always_present_even_at_zero() {
        // Same noise tradeoff as `suppressed`: zero is informative —
        // confirms the field exists on a clean run, so consumers don't
        // have to handle "missing" vs "zero".
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: &[],
            files_scanned: 0,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        });
        let doc = parse(&out);
        assert_eq!(doc["summary"]["ignored"], Json::from(0u64));
    }

    #[test]
    fn json_uses_two_space_indent() {
        let by_lang = BTreeMap::new();
        let by_sev = BTreeMap::new();
        let out = render_json(&JsonReport {
            tool_version: "1.0",
            target: "/tmp",
            findings: &[],
            files_scanned: 0,
            by_language: &by_lang,
            rules_applied: 0,
            by_severity: &by_sev,
            duration_ms: 0,
            severity_filter: None,
            suppressed: 0,
            ignored: 0,
        });
        // Python `json.dumps(..., indent=2)` uses 2-space indent. Our
        // serde_json::to_string_pretty default is also 2 spaces. Pin
        // it: the second line must start with exactly two spaces.
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines.len() >= 2);
        assert!(lines[1].starts_with("  "));
        assert!(!lines[1].starts_with("   ")); // not 3+
        assert!(!lines[1].starts_with('\t'));
    }

    // ── render_sarif ───────────────────────────────────────────────────

    #[test]
    fn sarif_top_level_version_and_schema() {
        let out = render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp/proj",
            findings: &[],
        });
        let doc = parse(&out);
        assert_eq!(doc["version"], Json::from("2.1.0"));
        assert!(doc["$schema"].is_string());
        assert_eq!(
            doc["runs"][0]["tool"]["driver"]["name"],
            Json::from("arcis-audit")
        );
    }

    #[test]
    fn sarif_severity_to_level_mapping() {
        let f1 = finding("EVAL-EXEC", Severity::Critical, "/x.py", 1);
        let f2 = finding("YAML-UNSAFE", Severity::High, "/x.py", 2);
        let f3 = finding("JSONP-CALLBACK", Severity::Medium, "/x.py", 3);
        let f4 = finding("X", Severity::Low, "/x.py", 4);
        let findings = vec![f1, f2, f3, f4];
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: &findings,
        }));
        let levels: Vec<String> = doc["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["level"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(levels, vec!["error", "error", "warning", "note"]);
    }

    #[test]
    fn sarif_only_referenced_rules_in_driver_table() {
        let f = finding("YAML-UNSAFE", Severity::High, "/x.py", 1);
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: std::slice::from_ref(&f),
        }));
        let rule_ids: Vec<String> = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(rule_ids, vec!["YAML-UNSAFE"]);
    }

    #[test]
    fn sarif_dedupes_rules_in_driver_table() {
        let f1 = finding("YAML-UNSAFE", Severity::High, "/a.py", 1);
        let f2 = finding("YAML-UNSAFE", Severity::High, "/b.py", 5);
        let findings = vec![f1, f2];
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: &findings,
        }));
        let rule_ids: Vec<String> = doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(rule_ids, vec!["YAML-UNSAFE"]);
        assert_eq!(doc["runs"][0]["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn sarif_uri_uses_forward_slashes() {
        // Cross-platform: Python uses `os.path.relpath(...).replace(os.sep, "/")`.
        // Our impl flips `\\` to `/` on Windows; on POSIX the `\\` flip is a no-op.
        let mut f = finding("YAML-UNSAFE", Severity::High, "", 1);
        f.file = "a/b/c.py".to_string();
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: std::slice::from_ref(&f),
        }));
        let uri = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert!(!uri.contains('\\'));
        assert!(uri.ends_with("c.py"));
    }

    #[test]
    fn sarif_omits_snippet_when_empty() {
        let mut f = finding("X", Severity::High, "/a.py", 1);
        f.snippet = String::new();
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: std::slice::from_ref(&f),
        }));
        let region = &doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert!(region.get("snippet").is_none());
        assert_eq!(region["startLine"], Json::from(1u64));
    }

    #[test]
    fn sarif_target_uri_has_trailing_slash() {
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp/proj",
            findings: &[],
        }));
        let target_uri = doc["runs"][0]["originalUriBaseIds"]["TARGET"]["uri"]
            .as_str()
            .unwrap();
        assert!(target_uri.ends_with('/'));
        // No double trailing slash if input already had one.
        let doc2 = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp/proj/",
            findings: &[],
        }));
        let target_uri2 = doc2["runs"][0]["originalUriBaseIds"]["TARGET"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(target_uri, target_uri2);
    }

    #[test]
    fn sarif_partial_fingerprints_emitted_under_arcis_v1_key() {
        // GitHub Code Scanning de-dupes results across runs by hashing
        // the partialFingerprints map. cli-audit.md item 10 — versioned
        // key gives us a clean rotation lane.
        let f = finding("YAML-UNSAFE", Severity::High, "/x.py", 1);
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: std::slice::from_ref(&f),
        }));
        let pf = &doc["runs"][0]["results"][0]["partialFingerprints"];
        assert!(pf.is_object(), "partialFingerprints must be an object");
        assert_eq!(
            pf["arcis/v1"],
            Json::from("YAML-UNSAFE-deadbeefcafef00d"),
            "fingerprint sits under tool-versioned key"
        );
    }

    #[test]
    fn sarif_partial_fingerprints_omitted_when_id_empty() {
        // Finding produced by `scan_file` (no relpath context) carries
        // an empty id. The SARIF renderer must skip emitting an empty
        // partialFingerprints entry rather than ship a useless `""` —
        // a downstream tool with strict schema validation would reject
        // it as a degenerate fingerprint.
        let mut f = finding("YAML-UNSAFE", Severity::High, "/x.py", 1);
        f.id = String::new();
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: std::slice::from_ref(&f),
        }));
        assert!(
            doc["runs"][0]["results"][0]
                .get("partialFingerprints")
                .is_none(),
            "partialFingerprints must be absent for empty id"
        );
    }

    #[test]
    fn sarif_short_description_split_on_em_dash() {
        // Rule message "msg-prefix — fix-suggestion" → shortDescription
        // text is "msg-prefix" only.
        let f = finding("YAML-UNSAFE", Severity::High, "/x.py", 1);
        let doc = parse(&render_sarif(&SarifReport {
            tool_version: "1.0",
            target_abspath: "/tmp",
            findings: std::slice::from_ref(&f),
        }));
        let short = doc["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
            .as_str()
            .unwrap();
        let full = doc["runs"][0]["tool"]["driver"]["rules"][0]["fullDescription"]["text"]
            .as_str()
            .unwrap();
        assert!(full.len() > short.len());
        assert!(!short.contains('\u{2014}'));
    }

    // ── escape_non_ascii ───────────────────────────────────────────────

    #[test]
    fn escape_non_ascii_passes_ascii_through() {
        assert_eq!(
            escape_non_ascii("\"plain\": [1, 2]\n"),
            "\"plain\": [1, 2]\n"
        );
    }

    #[test]
    fn escape_non_ascii_bmp_codepoint() {
        assert_eq!(escape_non_ascii("a — b"), "a \\u2014 b");
        assert_eq!(escape_non_ascii("café"), "caf\\u00e9");
    }

    #[test]
    fn escape_non_ascii_surrogate_pair_for_supplementary() {
        // U+1F600 → surrogate pair 😀
        assert_eq!(escape_non_ascii("smile \u{1F600}"), "smile \\ud83d\\ude00");
    }
}
