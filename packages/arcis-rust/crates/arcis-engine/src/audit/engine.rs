//! Audit engine — applies compiled rules over walked files.
//!
//! Direct port of `scan_file` + `scan_directory` from
//! `packages/arcis-python/arcis/cli/audit.py`. Produces structured
//! [`Finding`]s; output formatting (human / `--json` / `--sarif`)
//! lives in `arcis-cli` next to the clap glue.

use std::fs;
use std::path::Path;

use super::finding_id;
use super::rules::{rules as compiled_rules, Language, Rule, Severity};
use super::walker::{collect_files, detect_language};

/// One audit finding.
///
/// `id` is the deterministic fingerprint computed by
/// [`finding_id::assign_ids`]; `scan_file` leaves it empty (no relpath
/// context), `scan_directory` fills it in. The CLI calls
/// [`finding_id::assign_ids`] explicitly when it scans via
/// `collect_files` + `scan_file` rather than `scan_directory` so it can
/// pin the relpath to the user's input arg. Empty `id` indicates "not
/// yet assigned" — never an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: &'static str,
    pub severity: Severity,
    pub message: &'static str,
    pub file: String,
    pub line: usize,
    pub snippet: String,
    /// `<RULE_ID>-<16hex>` deterministic fingerprint. See
    /// [`finding_id`] for the derivation.
    pub id: String,
}

/// Scan a single file. Returns empty if extension is unknown or read
/// fails. Mirrors `audit.py:scan_file`.
///
/// Per-line, comment-only lines (lines whose first non-whitespace char
/// is `#` or `//`) are skipped — matches Python's `stripped.startswith`
/// check. Lines that match a rule's `pattern` AND its `safe_pattern`
/// (when set) are exempted, e.g. `yaml.load(f, Loader=SafeLoader)`.
pub fn scan_file(path: &Path) -> Vec<Finding> {
    let lang = match detect_language(path) {
        Some(l) => l,
        None => return Vec::new(),
    };

    let applicable: Vec<&Rule> = compiled_rules()
        .iter()
        .filter(|r| r.languages.contains(&lang))
        .collect();
    if applicable.is_empty() {
        return Vec::new();
    }

    // Match Python's `errors='replace'` semantics. `read_to_string`
    // fails on invalid UTF-8; falling back to `read` + lossy decode
    // keeps the scan moving on weird inputs (rare in source files).
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => match fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => return Vec::new(),
        },
    };

    let file_str = path.to_string_lossy().into_owned();
    let mut findings = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let stripped = line.trim();
        if stripped.starts_with('#') || stripped.starts_with("//") {
            continue;
        }
        for rule in &applicable {
            if !rule.pattern.is_match(line) {
                continue;
            }
            if let Some(safe) = &rule.safe_pattern {
                if safe.is_match(line) {
                    continue;
                }
            }
            // Snippet: codepoint-bounded prefix of the trimmed line.
            // Python's `stripped[:120]` is a unicode-codepoint slice;
            // matching that requires `chars().take(120)` rather than a
            // byte slice (which would panic on non-ASCII boundaries).
            let snippet: String = stripped.chars().take(120).collect();
            findings.push(Finding {
                rule_id: rule.id,
                severity: rule.severity,
                message: rule.message,
                file: file_str.clone(),
                line: line_num,
                snippet,
                id: String::new(),
            });
        }
    }

    findings
}

/// Scan a directory tree. Mirrors `audit.py:scan_directory`.
///
/// `severity` is the *minimum* severity to keep — passing
/// `Some(Severity::High)` removes medium/low findings. Final list is
/// sorted by `(severity, file, line)` so JSON / SARIF output is
/// byte-stable across runs.
pub fn scan_directory(
    path: &Path,
    language: Option<Language>,
    severity: Option<Severity>,
) -> Vec<Finding> {
    let files = collect_files(path, language);
    let mut findings: Vec<Finding> = files.into_iter().flat_map(|f| scan_file(&f)).collect();

    if let Some(threshold) = severity {
        // Severity Ord declares Critical < High < Medium < Low. The
        // CLI flag `--severity high` semantically means "show high and
        // worse". "Worse" here is smaller Ord. So keep findings whose
        // severity <= threshold.
        findings.retain(|f| f.severity <= threshold);
    }

    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    // Fill in deterministic ids so two runs of `scan_directory` over
    // the same target return findings that compare PartialEq. The CLI
    // can override later with a different `target_root` if the user
    // passed one (e.g. ran `arcis audit .` and we want relpaths
    // relative to cwd, not absolutized).
    finding_id::assign_ids(&mut findings, path);

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn write(td: &TempDir, rel: &str, content: &str) -> PathBuf {
        let p = td.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        p
    }

    // ── scan_file ──────────────────────────────────────────────────────

    #[test]
    fn scan_file_yaml_unsafe_fires() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "import yaml\ndata = yaml.load(f)\n");
        let findings = scan_file(&f);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "YAML-UNSAFE");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].snippet, "data = yaml.load(f)");
    }

    #[test]
    fn scan_file_safe_pattern_exempts_yaml_safeloader() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "yaml.load(f, Loader=SafeLoader)\n");
        assert!(scan_file(&f).is_empty());
    }

    #[test]
    fn scan_file_safe_pattern_exempts_yaml_yaml_safeloader() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "yaml.load(f, Loader=yaml.SafeLoader)\n");
        assert!(scan_file(&f).is_empty());
    }

    #[test]
    fn scan_file_python_hash_comment_skipped() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "# yaml.load(f)\n  # eval(x)\n");
        assert!(scan_file(&f).is_empty());
    }

    #[test]
    fn scan_file_js_double_slash_comment_skipped() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.js", "// document.write('hi')\n");
        assert!(scan_file(&f).is_empty());
    }

    #[test]
    fn scan_file_unknown_extension_returns_empty() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.txt", "yaml.load(f)\n");
        assert!(scan_file(&f).is_empty());
    }

    #[test]
    fn scan_file_clean_returns_empty() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "import os\nprint('hello')\n");
        assert!(scan_file(&f).is_empty());
    }

    #[test]
    fn scan_file_snippet_truncated_to_120_chars() {
        let td = TempDir::new().unwrap();
        // 95 occurrences of "x " is 190 chars; appending "yaml.load(f)"
        // makes a 202-char line.
        let mut line = "x ".repeat(95);
        line.push_str("yaml.load(f)");
        let f = write(&td, "main.py", &format!("{line}\n"));
        let findings = scan_file(&f);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].snippet.chars().count(), 120);
    }

    #[test]
    fn scan_file_multiple_rules_can_fire_on_same_line() {
        let td = TempDir::new().unwrap();
        // EVAL-EXEC + HARDCODED-SECRET (AKIA + 16 alnum) on one line.
        let aws = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        let line = format!("key = {aws}; eval(x)\n");
        let f = write(&td, "main.py", &line);
        let findings = scan_file(&f);
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"EVAL-EXEC"));
        assert!(ids.contains(&"HARDCODED-SECRET"));
    }

    #[test]
    fn scan_file_only_applicable_language_rules_fire() {
        // YAML-UNSAFE is python-only; it must NOT fire on a JS file.
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.js", "yaml.load(f)\n");
        let findings = scan_file(&f);
        assert!(findings.iter().all(|x| x.rule_id != "YAML-UNSAFE"));
    }

    #[test]
    fn scan_file_inline_comment_does_not_skip() {
        // Python's comment-skip checks `stripped.startswith("#")`.
        // `x = 1  # yaml.load(f)` is NOT skipped — the `#` is mid-line —
        // so YAML-UNSAFE fires. Test pins this contract.
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "x = 1  # yaml.load(f)\n");
        let findings = scan_file(&f);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "YAML-UNSAFE");
    }

    // ── scan_directory ─────────────────────────────────────────────────

    #[test]
    fn scan_directory_walks_and_sorts_by_severity_file_line() {
        let td = TempDir::new().unwrap();
        write(&td, "a.py", "yaml.load(f)\n"); // HIGH
        write(&td, "b.py", "pickle.loads(b'x')\n"); // CRITICAL
        write(&td, "c.js", "el.innerHTML = x\n"); // HIGH
        let findings = scan_directory(td.path(), None, None);
        assert!(findings.len() >= 3);
        // First item must be CRITICAL.
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].file.ends_with("b.py"));
        // Within HIGH tier, file order is alphabetical.
        let highs: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .collect();
        for w in highs.windows(2) {
            assert!(
                (w[0].file.as_str(), w[0].line) <= (w[1].file.as_str(), w[1].line),
                "file/line ordering broken: {:?} then {:?}",
                w[0],
                w[1]
            );
        }
    }

    #[test]
    fn scan_directory_severity_filter_drops_lower_tiers() {
        let td = TempDir::new().unwrap();
        write(&td, "a.py", "yaml.load(f)\n"); // HIGH
        write(&td, "b.py", "pickle.loads(b'x')\n"); // CRITICAL
        write(&td, "c.py", "request.args.get('callback')\n"); // MEDIUM
        let findings = scan_directory(td.path(), None, Some(Severity::High));
        assert!(findings.iter().all(|f| f.severity <= Severity::High));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id).collect();
        assert!(ids.contains(&"PICKLE-LOAD"));
        assert!(ids.contains(&"YAML-UNSAFE"));
        assert!(!ids.contains(&"JSONP-CALLBACK"));
    }

    #[test]
    fn scan_directory_severity_filter_critical_keeps_only_critical() {
        let td = TempDir::new().unwrap();
        write(&td, "a.py", "yaml.load(f)\n"); // HIGH
        write(&td, "b.py", "pickle.loads(b'x')\n"); // CRITICAL
        let findings = scan_directory(td.path(), None, Some(Severity::Critical));
        assert!(findings.iter().all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn scan_directory_language_filter() {
        let td = TempDir::new().unwrap();
        write(&td, "a.py", "yaml.load(f)\n");
        write(&td, "b.js", "el.innerHTML = x\n");
        let findings = scan_directory(td.path(), Some(Language::Python), None);
        assert!(findings.iter().all(|f| f.file.ends_with(".py")));
    }

    #[test]
    fn scan_directory_skip_dirs_pruned() {
        let td = TempDir::new().unwrap();
        write(&td, "src/a.py", "yaml.load(f)\n");
        write(&td, "node_modules/b.py", "yaml.load(f)\n");
        write(&td, ".git/c.py", "yaml.load(f)\n");
        let findings = scan_directory(td.path(), None, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].file.contains("a.py"));
    }

    #[test]
    fn scan_directory_two_runs_byte_equal() {
        // Determinism gate: two runs over the same tree must yield
        // identical findings (same order, same fields). Validates the
        // (severity, file, line) sort is stable across runs.
        let td = TempDir::new().unwrap();
        write(&td, "a/x.py", "yaml.load(f)\n");
        write(&td, "b/y.py", "pickle.loads(b'x')\n");
        write(&td, "c/z.py", "eval(user_input)\n");
        let r1 = scan_directory(td.path(), None, None);
        let r2 = scan_directory(td.path(), None, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn scan_directory_clean_repo_returns_empty() {
        let td = TempDir::new().unwrap();
        write(&td, "a.py", "x = 1\n");
        write(&td, "b.js", "const x = 1;\n");
        let findings = scan_directory(td.path(), None, None);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_directory_empty_dir_returns_empty() {
        let td = TempDir::new().unwrap();
        let findings = scan_directory(td.path(), None, None);
        assert!(findings.is_empty());
    }
}
