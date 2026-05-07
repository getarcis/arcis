//! `arcis audit` — static analysis security scanner CLI subcommand.
//!
//! Direct port of the entry-point glue in `packages/arcis-python/arcis/cli/audit.py`.
//! The byte-equal parity contract for the machine modes (`--json`,
//! `--sarif`) lives in `packages/arcis-python/tests/cli/test_audit_machine_output.py`.
//! Human-readable output is intentionally minimal here; the rich-output
//! port lands separately once the rest of the audit phase is verified.

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use arcis_engine::audit::{
    assign_ids, collect_files, detect_language, render_json, render_sarif, rules as compiled_rules,
    scan_file_with_suppression, Finding, JsonReport, Language, SarifReport, Severity,
};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
struct Args {
    path: Option<PathBuf>,
    language: Option<Language>,
    severity: Option<Severity>,
    no_color: bool,
    list: bool,
    quiet: bool,
    json_output: bool,
    sarif_output: bool,
}

#[derive(Debug)]
enum ParseOutcome {
    Args(Args),
    /// `-h` / `--help`: caller should print help and exit 0.
    Help,
    /// Parse error: caller should print msg to stderr and exit 2.
    Err(String),
}

fn parse_args(argv: &[String]) -> ParseOutcome {
    let mut path: Option<PathBuf> = None;
    let mut language: Option<Language> = None;
    let mut severity: Option<Severity> = None;
    let mut no_color = false;
    let mut list = false;
    let mut quiet = false;
    let mut json_output = false;
    let mut sarif_output = false;

    let mut iter = argv.iter().enumerate();
    while let Some((_, arg)) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return ParseOutcome::Help,
            "--no-color" => no_color = true,
            "--list" => list = true,
            "--quiet" | "-q" => quiet = true,
            "--json" => json_output = true,
            "--sarif" => sarif_output = true,
            "--language" | "-l" => match iter.next() {
                Some((_, v)) => match Language::parse(v) {
                    Some(l) => language = Some(l),
                    None => {
                        return ParseOutcome::Err(format!(
                            "arcis audit: invalid language: {v} (expected python, javascript, typescript)"
                        ));
                    }
                },
                None => {
                    return ParseOutcome::Err(
                        "arcis audit: --language requires an argument".into(),
                    );
                }
            },
            "--severity" | "-s" => match iter.next() {
                Some((_, v)) => match Severity::parse(v) {
                    Some(s) => severity = Some(s),
                    None => {
                        return ParseOutcome::Err(format!(
                            "arcis audit: invalid severity: {v} (expected critical, high, medium, low)"
                        ));
                    }
                },
                None => {
                    return ParseOutcome::Err(
                        "arcis audit: --severity requires an argument".into(),
                    );
                }
            },
            other if other.starts_with("--") || (other.starts_with('-') && other.len() > 1) => {
                return ParseOutcome::Err(format!("arcis audit: unknown flag: {other}"));
            }
            other => {
                if path.is_some() {
                    return ParseOutcome::Err(format!(
                        "arcis audit: unexpected positional argument: {other}"
                    ));
                }
                path = Some(PathBuf::from(other));
            }
        }
    }

    ParseOutcome::Args(Args {
        path,
        language,
        severity,
        no_color,
        list,
        quiet,
        json_output,
        sarif_output,
    })
}

/// Abspath helper. Mirrors Python's `os.path.abspath` semantics — does
/// NOT follow symlinks, unlike `Path::canonicalize`.
fn abspath(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        env::current_dir().unwrap_or_default().join(p)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn print_help<W: Write>(out: &mut W) -> io::Result<()> {
    writeln!(out, "Usage: arcis audit [PATH] [OPTIONS]")?;
    writeln!(out)?;
    writeln!(
        out,
        "Static analysis security scanner for Python and JavaScript/TypeScript source code."
    )?;
    writeln!(out)?;
    writeln!(out, "Positional:")?;
    writeln!(out, "  PATH                File or directory to scan.")?;
    writeln!(out)?;
    writeln!(out, "Options:")?;
    writeln!(
        out,
        "  -l, --language LANG  Only scan files of this language (python|javascript|typescript)."
    )?;
    writeln!(
        out,
        "  -s, --severity LVL   Minimum severity to report (critical|high|medium|low)."
    )?;
    writeln!(
        out,
        "      --no-color       Disable coloured terminal output."
    )?;
    writeln!(
        out,
        "      --list           List all detection rules and exit."
    )?;
    writeln!(out, "  -q, --quiet          Suppress progress output.")?;
    writeln!(
        out,
        "      --json           Emit results as a single JSON document. Suppresses human output."
    )?;
    writeln!(
        out,
        "      --sarif          Emit results as SARIF 2.1.0 for GitHub Code Scanning."
    )?;
    writeln!(out, "  -h, --help           Show this message and exit.")?;
    Ok(())
}

fn print_rule_catalog<W: Write>(out: &mut W) -> io::Result<()> {
    let rules = compiled_rules();
    writeln!(out, "arcis audit detection rules ({} total)", rules.len())?;
    writeln!(out)?;

    // Group by language for display order: python, javascript, typescript.
    for lang in [Language::Python, Language::JavaScript, Language::TypeScript] {
        let mut applicable: Vec<&arcis_engine::audit::Rule> = rules
            .iter()
            .filter(|r| r.languages.contains(&lang))
            .collect();
        applicable.sort_by(|a, b| a.severity.cmp(&b.severity).then_with(|| a.id.cmp(b.id)));
        if applicable.is_empty() {
            continue;
        }
        writeln!(out, "{} ({} rules)", lang.as_str(), applicable.len())?;
        for r in applicable {
            writeln!(
                out,
                "  {:<8} {:<24} {}",
                r.severity.as_str().to_ascii_uppercase(),
                r.id,
                r.message
            )?;
        }
        writeln!(out)?;
    }
    Ok(())
}

/// Entry point. Called from `main.rs` when the user runs `arcis audit ...`.
/// Returns the process exit code.
pub fn run(argv: &[String]) -> ExitCode {
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();
    let stderr = io::stderr();
    let mut stderr_lock = stderr.lock();

    let mut args = match parse_args(argv) {
        ParseOutcome::Args(a) => a,
        ParseOutcome::Help => {
            let _ = print_help(&mut stdout_lock);
            return ExitCode::from(0);
        }
        ParseOutcome::Err(msg) => {
            let _ = writeln!(stderr_lock, "{msg}");
            return ExitCode::from(2);
        }
    };

    // Mutex: --json and --sarif are mutually exclusive. Same exit code
    // and stderr message as Python so test_audit_machine_output.py's
    // mutex test passes the same way.
    if args.json_output && args.sarif_output {
        let _ = writeln!(
            stderr_lock,
            "arcis audit: --json and --sarif are mutually exclusive"
        );
        return ExitCode::from(2);
    }

    // Machine modes imply quiet + no-color so progress / banners don't
    // contaminate stdout. Stderr stays available for hard errors.
    let machine_mode = args.json_output || args.sarif_output;
    if machine_mode {
        args.quiet = true;
        args.no_color = true;
    }

    if args.list {
        let _ = print_rule_catalog(&mut stdout_lock);
        return ExitCode::from(0);
    }

    let Some(path) = args.path.clone() else {
        let _ = print_help(&mut stdout_lock);
        return ExitCode::from(1);
    };

    if !path.exists() {
        let _ = writeln!(
            stdout_lock,
            "arcis audit: path not found: {}",
            path.display()
        );
        return ExitCode::from(1);
    }

    let target_abs = abspath(&path);
    let target_str = target_abs.to_string_lossy().into_owned();

    let files = collect_files(&path, args.language);

    // No scannable files: machine modes still emit a valid empty
    // document so CI parsers don't choke; non-machine prints a hint.
    // Either way, exit 2.
    if files.is_empty() {
        if machine_mode {
            let by_lang: BTreeMap<String, usize> = BTreeMap::new();
            let by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
            let out = if args.json_output {
                render_json(&JsonReport {
                    tool_version: TOOL_VERSION,
                    target: &target_str,
                    findings: &[],
                    files_scanned: 0,
                    by_language: &by_lang,
                    rules_applied: 0,
                    by_severity: &by_sev,
                    duration_ms: 0,
                    severity_filter: args.severity,
                    suppressed: 0,
                })
            } else {
                render_sarif(&SarifReport {
                    tool_version: TOOL_VERSION,
                    target_abspath: &target_str,
                    findings: &[],
                })
            };
            let _ = writeln!(stdout_lock, "{out}");
            return ExitCode::from(2);
        }

        let lang_clause = match args.language {
            Some(l) => format!(" (language={})", l.as_str()),
            None => String::new(),
        };
        let _ = writeln!(
            stdout_lock,
            "arcis audit: no scannable files found in {}{}",
            path.display(),
            lang_clause
        );
        let _ = writeln!(stdout_lock, "  Supported: .py .js .ts .jsx .tsx .mjs .cjs");
        return ExitCode::from(2);
    }

    // Build language breakdown — used by header + summary in human
    // mode and emitted in the JSON `byLanguage` field. Sorted via
    // BTreeMap so the JSON output is deterministic regardless of FS
    // walk order. Python audit.py sorts before serialising for the
    // same reason.
    let mut by_language: BTreeMap<String, usize> = BTreeMap::new();
    for fp in &files {
        let lang_label = detect_language(fp)
            .map(|l| l.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        *by_language.entry(lang_label).or_insert(0) += 1;
    }

    // Apply language filter to rule count we report (header honesty).
    let applicable_rule_count = match args.language {
        Some(l) => compiled_rules()
            .iter()
            .filter(|r| r.languages.contains(&l))
            .count(),
        None => compiled_rules().len(),
    };

    // Run scan. Time only the scan phase, like Python.
    let start = Instant::now();
    let mut findings: Vec<Finding> = Vec::new();
    let mut suppressed_total: usize = 0;
    for f in &files {
        let r = scan_file_with_suppression(f);
        findings.extend(r.findings);
        suppressed_total += r.suppressed;
    }
    let duration_ms = start.elapsed().as_millis() as u64;

    // Severity filter — keep findings whose severity rank <= threshold.
    if let Some(threshold) = args.severity {
        findings.retain(|f| f.severity <= threshold);
    }

    // Sort by (severity, file, line) so JSON / SARIF output is byte-stable.
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    // Deterministic finding ids — `<RULE_ID>-<16hex>` over
    // `(rule_id, relpath, line, snippet)`. Pinned to the user's input
    // path so `arcis audit .` and `arcis audit /abs/repo` produce the
    // same id for the same source line. cli-audit.md item 10.
    assign_ids(&mut findings, &path);

    // Per-severity counts. Sorted by Severity Ord so the JSON
    // `bySeverity` map keys come out in [critical, high, medium, low]
    // order — matches Python's audit.py once the sort tweak lands.
    let mut by_severity: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in &findings {
        *by_severity.entry(f.severity).or_insert(0) += 1;
    }

    if machine_mode {
        let out = if args.json_output {
            render_json(&JsonReport {
                tool_version: TOOL_VERSION,
                target: &target_str,
                findings: &findings,
                files_scanned: files.len(),
                by_language: &by_language,
                rules_applied: applicable_rule_count,
                by_severity: &by_severity,
                duration_ms,
                severity_filter: args.severity,
                suppressed: suppressed_total,
            })
        } else {
            render_sarif(&SarifReport {
                tool_version: TOOL_VERSION,
                target_abspath: &target_str,
                findings: &findings,
            })
        };
        let _ = writeln!(stdout_lock, "{out}");
        return if findings.is_empty() {
            ExitCode::from(0)
        } else {
            ExitCode::from(1)
        };
    }

    // Human mode (intentionally minimal until rich-output port lands).
    // Phase B2's parity contract is the machine modes; this path just
    // exists so `arcis audit foo/` produces something usable.
    let _ = print_human_report(
        &mut stdout_lock,
        &path,
        &files,
        &by_language,
        applicable_rule_count,
        args.severity,
        &findings,
        &by_severity,
        duration_ms,
        suppressed_total,
    );

    if findings.is_empty() {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

#[allow(clippy::too_many_arguments)]
fn print_human_report<W: Write>(
    out: &mut W,
    target: &Path,
    files: &[PathBuf],
    by_language: &BTreeMap<String, usize>,
    rules_applied: usize,
    severity_filter: Option<Severity>,
    findings: &[Finding],
    by_severity: &BTreeMap<Severity, usize>,
    duration_ms: u64,
    suppressed: usize,
) -> io::Result<()> {
    writeln!(out)?;
    writeln!(out, "  Arcis Audit")?;
    writeln!(out, "  Target:   {}", target.display())?;
    writeln!(
        out,
        "  Rules:    {} ({})",
        rules_applied,
        if by_language.is_empty() {
            "all".to_string()
        } else {
            by_language.keys().cloned().collect::<Vec<_>>().join(", ")
        }
    )?;
    let breakdown = by_language
        .iter()
        .map(|(k, v)| format!("{v} {k}"))
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(out, "  Files:    {} scanned ({})", files.len(), breakdown)?;
    if let Some(s) = severity_filter {
        writeln!(out, "  Filter:   severity >= {}", s.as_str())?;
    }
    writeln!(
        out,
        "  ------------------------------------------------------------"
    )?;
    writeln!(out)?;

    if findings.is_empty() {
        writeln!(out, "  No issues found.")?;
        writeln!(out)?;
    } else {
        // Group by file.
        let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            by_file.entry(f.file.as_str()).or_default().push(f);
        }
        for (file, items) in &by_file {
            writeln!(out, "  {} ({} issue(s))", file, items.len())?;
            for f in items {
                writeln!(
                    out,
                    "    {:<8} {}:{}  {}",
                    f.severity.as_str().to_ascii_uppercase(),
                    f.file,
                    f.line,
                    f.rule_id
                )?;
                writeln!(out, "      {}", f.message)?;
                if !f.snippet.is_empty() {
                    writeln!(out, "      {}", f.snippet)?;
                }
            }
            writeln!(out)?;
        }
        writeln!(
            out,
            "  {} issue(s) found across {} file(s).",
            findings.len(),
            by_file.len()
        )?;
        writeln!(out)?;
    }

    writeln!(
        out,
        "  ------------------------------------------------------------"
    )?;
    writeln!(out, "  Summary")?;
    writeln!(out, "    Files scanned   {}  [{}]", files.len(), breakdown)?;
    writeln!(out, "    Rules applied   {rules_applied}")?;
    let total: usize = by_severity.values().sum();
    if total == 0 {
        writeln!(out, "    Findings        0  clean")?;
    } else {
        let parts: Vec<String> = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ]
        .into_iter()
        .filter_map(|s| {
            by_severity
                .get(&s)
                .filter(|&&n| n > 0)
                .map(|n| format!("{} {}", n, s.as_str()))
        })
        .collect();
        writeln!(out, "    Findings        {} ({})", total, parts.join(", "))?;
    }
    // cli-audit.md item 6: surface suppress-comment count only when
    // non-zero. Zero is the common case and would just be visual noise
    // in the summary; the count exists in JSON output for tooling that
    // wants the unconditional view.
    if suppressed > 0 {
        writeln!(out, "    Suppressed      {suppressed}")?;
    }
    writeln!(out, "    Time            {duration_ms}ms")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_no_args() {
        match parse_args(&[]) {
            ParseOutcome::Args(a) => {
                assert!(a.path.is_none());
                assert!(!a.json_output);
                assert!(!a.sarif_output);
                assert!(!a.list);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_path_only() {
        match parse_args(&["src/".to_string()]) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.path.unwrap(), PathBuf::from("src/"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_help_short_and_long() {
        assert!(matches!(
            parse_args(&["-h".to_string()]),
            ParseOutcome::Help
        ));
        assert!(matches!(
            parse_args(&["--help".to_string()]),
            ParseOutcome::Help
        ));
    }

    #[test]
    fn parse_args_language_flag() {
        match parse_args(&[
            "src/".to_string(),
            "--language".to_string(),
            "python".to_string(),
        ]) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.language, Some(Language::Python));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_severity_flag() {
        match parse_args(&[
            "src/".to_string(),
            "--severity".to_string(),
            "high".to_string(),
        ]) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.severity, Some(Severity::High));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_invalid_severity_errors() {
        let r = parse_args(&[
            ".".to_string(),
            "--severity".to_string(),
            "bogus".to_string(),
        ]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("invalid severity")));
    }

    #[test]
    fn parse_args_invalid_language_errors() {
        let r = parse_args(&[
            ".".to_string(),
            "--language".to_string(),
            "rust".to_string(),
        ]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("invalid language")));
    }

    #[test]
    fn parse_args_unknown_flag_errors() {
        let r = parse_args(&[".".to_string(), "--bogus".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("unknown flag")));
    }

    #[test]
    fn parse_args_json_and_sarif_both_set() {
        // parse_args itself doesn't error here — the mutex check lives
        // in run() so the error message lands on stderr after parse.
        match parse_args(&[".".to_string(), "--json".to_string(), "--sarif".to_string()]) {
            ParseOutcome::Args(a) => {
                assert!(a.json_output);
                assert!(a.sarif_output);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_two_positionals_errors() {
        let r = parse_args(&["a".to_string(), "b".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("unexpected positional")));
    }

    #[test]
    fn abspath_handles_dotdot() {
        let p = abspath(Path::new("a/b/../c"));
        assert!(!p.to_string_lossy().contains("..")); // collapsed
    }

    #[test]
    fn human_summary_emits_suppressed_line_when_count_positive() {
        // cli-audit.md item 6: Summary block must include
        // "Suppressed N" when at least one finding was silenced by a
        // suppress-comment directive.
        let mut buf: Vec<u8> = Vec::new();
        let by_lang: BTreeMap<String, usize> = [("python".to_string(), 1)].into_iter().collect();
        let by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        print_human_report(
            &mut buf,
            Path::new("/tmp"),
            &[PathBuf::from("/tmp/a.py")],
            &by_lang,
            14,
            None,
            &[],
            &by_sev,
            42,
            7,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Suppressed      7"),
            "expected Suppressed line in summary, got:\n{out}"
        );
    }

    #[test]
    fn human_summary_omits_suppressed_line_when_count_zero() {
        // Zero is the common case; printing "Suppressed 0" every time
        // is just noise. Tooling can read the JSON output for the
        // unconditional value.
        let mut buf: Vec<u8> = Vec::new();
        let by_lang: BTreeMap<String, usize> = [("python".to_string(), 1)].into_iter().collect();
        let by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        print_human_report(
            &mut buf,
            Path::new("/tmp"),
            &[PathBuf::from("/tmp/a.py")],
            &by_lang,
            14,
            None,
            &[],
            &by_sev,
            42,
            0,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("Suppressed"),
            "Suppressed line should not appear when count is 0, got:\n{out}"
        );
    }
}
