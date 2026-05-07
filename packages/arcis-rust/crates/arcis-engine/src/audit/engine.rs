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
use super::suppress::{self, Directive};
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

/// Result of scanning one or more files: kept findings plus a
/// per-scan count of findings that fired but were silenced by a
/// suppress directive (cli-audit.md item 6). The suppressed payload
/// itself is intentionally NOT retained — a `--show-suppressed` flag
/// can resurrect it later if there's demand. Only the count surfaces,
/// shown in the human summary as `Suppressed N`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileResult {
    pub findings: Vec<Finding>,
    pub suppressed: usize,
}

/// Scan a single file. Returns empty if extension is unknown or read
/// fails. Backward-compatible thin wrapper over
/// [`scan_file_with_suppression`] that drops the suppression count.
///
/// Per-line, comment-only lines (lines whose first non-whitespace char
/// is `#` or `//`) are skipped — matches Python's `stripped.startswith`
/// check. Lines that match a rule's `pattern` AND its `safe_pattern`
/// (when set) are exempted, e.g. `yaml.load(f, Loader=SafeLoader)`.
pub fn scan_file(path: &Path) -> Vec<Finding> {
    scan_file_with_suppression(path).findings
}

/// Scan a single file. Same scan logic as [`scan_file`] but also
/// honours the suppress-comment directives documented in
/// [`super::suppress`] (cli-audit.md item 6).
///
/// Suppressed findings are excluded from the `findings` vec; the count
/// is surfaced via `FileResult.suppressed` so the CLI can show a
/// `Suppressed N` line in the human summary.
pub fn scan_file_with_suppression(path: &Path) -> FileResult {
    let lang = match detect_language(path) {
        Some(l) => l,
        None => return FileResult::default(),
    };

    let applicable: Vec<&Rule> = compiled_rules()
        .iter()
        .filter(|r| r.languages.contains(&lang))
        .collect();
    if applicable.is_empty() {
        return FileResult::default();
    }

    // Match Python's `errors='replace'` semantics. `read_to_string`
    // fails on invalid UTF-8; falling back to `read` + lossy decode
    // keeps the scan moving on weird inputs (rare in source files).
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => match fs::read(path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => return FileResult::default(),
        },
    };

    let lines: Vec<&str> = content.lines().collect();

    // Per-line directive table. Indexed 0-based; aligned with the
    // (line_num - 1) used in the rule loop below. Built up-front so
    // line N can cheaply look at line N-1's directive.
    let directives: Vec<Option<Directive>> =
        lines.iter().map(|l| suppress::parse_line(l)).collect();

    // File-level directive: any line carrying a File directive
    // suppresses every finding in this file. The suppressed count
    // still records what *would* have fired, so users get a number to
    // act on if they later remove the directive.
    let file_level = directives
        .iter()
        .any(|d| matches!(d, Some(Directive::File)));

    let file_str = path.to_string_lossy().into_owned();
    let mut findings = Vec::new();
    let mut suppressed = 0usize;

    for (idx, line) in lines.iter().enumerate() {
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

            // Suppress check, in priority order:
            //   1. File-level directive anywhere in the file.
            //   2. Same-line directive matching this rule_id.
            //   3. Preceding-line directive matching this rule_id —
            //      ONLY when line N-1 is a comment-only line. A
            //      trailing inline directive on line N-1's code does
            //      NOT spill onto line N (Semgrep semantics; explicit
            //      footgun-prevention).
            let same = directives.get(idx).and_then(|d| d.as_ref());
            let prev_comment_only = idx > 0 && suppress::is_comment_only_line(lines[idx - 1]);
            let prev = if prev_comment_only {
                directives.get(idx - 1).and_then(|d| d.as_ref())
            } else {
                None
            };
            let is_suppressed = file_level
                || same.is_some_and(|d| suppress::matches(d, rule.id))
                || prev.is_some_and(|d| suppress::matches(d, rule.id));
            if is_suppressed {
                suppressed += 1;
                continue;
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

    FileResult {
        findings,
        suppressed,
    }
}

/// Scan a directory tree. Mirrors `audit.py:scan_directory`.
///
/// `severity` is the *minimum* severity to keep — passing
/// `Some(Severity::High)` removes medium/low findings. Final list is
/// sorted by `(severity, file, line)` so JSON / SARIF output is
/// byte-stable across runs.
///
/// Backward-compatible wrapper over [`scan_directory_with_suppression`]
/// that drops the suppression count.
pub fn scan_directory(
    path: &Path,
    language: Option<Language>,
    severity: Option<Severity>,
) -> Vec<Finding> {
    scan_directory_with_suppression(path, language, severity).findings
}

/// Same scan as [`scan_directory`] but additionally returns the count
/// of suppressed findings (via the `FileResult.suppressed` field).
/// Suppressed findings themselves are excluded from `findings`.
pub fn scan_directory_with_suppression(
    path: &Path,
    language: Option<Language>,
    severity: Option<Severity>,
) -> FileResult {
    let files = collect_files(path, language);

    let mut findings = Vec::new();
    let mut suppressed = 0usize;
    for f in files {
        let r = scan_file_with_suppression(&f);
        findings.extend(r.findings);
        suppressed += r.suppressed;
    }

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

    FileResult {
        findings,
        suppressed,
    }
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

    // ── suppress comments (cli-audit.md item 6) ────────────────────────

    #[test]
    fn suppress_same_line_double_slash_hides_finding() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.js", "el.innerHTML = x  // arcis-audit: ignore\n");
        let r = scan_file_with_suppression(&f);
        assert!(r.findings.is_empty());
        assert_eq!(r.suppressed, 1);
    }

    #[test]
    fn suppress_same_line_hash_hides_finding_python() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "yaml.load(f)  # arcis-audit: ignore\n");
        let r = scan_file_with_suppression(&f);
        assert!(r.findings.is_empty());
        assert_eq!(r.suppressed, 1);
    }

    #[test]
    fn suppress_preceding_comment_only_line_hides_finding() {
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "# arcis-audit: ignore\nyaml.load(f)\n");
        let r = scan_file_with_suppression(&f);
        assert!(r.findings.is_empty());
        assert_eq!(r.suppressed, 1);
    }

    #[test]
    fn suppress_preceding_inline_directive_does_not_hide_next_line() {
        // Footgun-prevention: a trailing inline directive on a code
        // line N-1 (e.g. `eval(x)  // arcis-audit: ignore EVAL-EXEC`)
        // applies ONLY to its own line. A real, unsuppressed finding
        // on line N must survive — silent suppression is a
        // classic SAST footgun and we deliberately avoid it.
        let td = TempDir::new().unwrap();
        let f = write(
            &td,
            "main.py",
            "eval(x)  # arcis-audit: ignore EVAL-EXEC\nyaml.load(f)\n",
        );
        let r = scan_file_with_suppression(&f);
        // Line 1 (eval): suppressed by its own same-line directive.
        // Line 2 (yaml.load): NOT suppressed, even though directive
        // sits on line 1, because line 1 is not comment-only.
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule_id, "YAML-UNSAFE");
        assert_eq!(r.findings[0].line, 2);
        assert_eq!(r.suppressed, 1);
    }

    #[test]
    fn suppress_two_lines_before_does_not_hide_finding() {
        // Spec: "Two-lines-before does NOT suppress." Only the
        // immediately preceding (comment-only) line counts.
        let td = TempDir::new().unwrap();
        let f = write(&td, "main.py", "# arcis-audit: ignore\n\nyaml.load(f)\n");
        let r = scan_file_with_suppression(&f);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule_id, "YAML-UNSAFE");
        assert_eq!(r.suppressed, 0);
    }

    #[test]
    fn suppress_rule_id_specificity_does_not_cross_rules() {
        // Spec: `ignore SQL-CONCAT` does NOT hide a YAML-UNSAFE
        // finding. Rule IDs in a directive name only those rules.
        let td = TempDir::new().unwrap();
        let f = write(
            &td,
            "main.py",
            "yaml.load(f)  # arcis-audit: ignore SQL-CONCAT\n",
        );
        let r = scan_file_with_suppression(&f);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule_id, "YAML-UNSAFE");
        assert_eq!(r.suppressed, 0);
    }

    #[test]
    fn suppress_comma_list_hides_each_listed_rule() {
        // EVAL-EXEC and HARDCODED-SECRET both fire on this line; a
        // comma-list directive that names both must hide both.
        let td = TempDir::new().unwrap();
        let aws = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        let line =
            format!("key = {aws}; eval(x)  # arcis-audit: ignore EVAL-EXEC,HARDCODED-SECRET\n");
        let f = write(&td, "main.py", &line);
        let r = scan_file_with_suppression(&f);
        // Both rules suppressed → no surviving findings on this line.
        assert!(
            r.findings.is_empty(),
            "expected both rules suppressed, got {:?}",
            r.findings
        );
        assert_eq!(r.suppressed, 2);
    }

    #[test]
    fn suppress_file_level_directive_hides_everything_in_file() {
        let td = TempDir::new().unwrap();
        let f = write(
            &td,
            "main.py",
            "# arcis-audit: ignore-file\nyaml.load(f)\npickle.loads(b'x')\neval(y)\n",
        );
        let r = scan_file_with_suppression(&f);
        assert!(r.findings.is_empty());
        assert!(
            r.suppressed >= 3,
            "expected at least 3 suppressed (one per line), got {}",
            r.suppressed
        );
    }

    #[test]
    fn suppress_file_level_directive_works_when_placed_anywhere() {
        // The file-level directive is global to the file — placement
        // (top, middle, bottom) shouldn't matter.
        let td = TempDir::new().unwrap();
        let f = write(
            &td,
            "main.py",
            "yaml.load(f)\n# arcis-audit: ignore-file\npickle.loads(b'x')\n",
        );
        let r = scan_file_with_suppression(&f);
        assert!(r.findings.is_empty());
        assert!(r.suppressed >= 2);
    }

    #[test]
    fn suppress_count_propagates_through_scan_directory() {
        let td = TempDir::new().unwrap();
        write(&td, "a.py", "yaml.load(f)  # arcis-audit: ignore\n"); // 1 suppressed
        write(&td, "b.py", "pickle.loads(b'x')\n"); // 1 finding, no suppress
        let r = scan_directory_with_suppression(td.path(), None, None);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule_id, "PICKLE-LOAD");
        assert_eq!(r.suppressed, 1);
    }

    #[test]
    fn suppress_two_runs_byte_equal_with_directive() {
        // Determinism: directives must not change run-to-run output.
        let td = TempDir::new().unwrap();
        write(
            &td,
            "a.py",
            "# arcis-audit: ignore\nyaml.load(f)\npickle.loads(b'x')\n",
        );
        let r1 = scan_directory_with_suppression(td.path(), None, None);
        let r2 = scan_directory_with_suppression(td.path(), None, None);
        assert_eq!(r1, r2);
    }
}
