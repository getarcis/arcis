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
    assign_ids, classify_baseline, collect_files_with_options, detect_language, render_json,
    render_sarif, rules as compiled_rules, scan_files_parallel, Baseline, BaselineEntry,
    BaselineError, BaselineSummary, Finding, IgnoreOptions, JsonReport, Language, SarifReport,
    Severity,
};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default worker count when `--jobs` is not given. cli-audit.md item 11
/// pins this at 8: enough to hit the 4–8× speedup target on 1k-file
/// monorepos without oversubscribing typical dev machines. Users on
/// tiny CI runners or beefy 16-core boxes override via `--jobs N`.
const DEFAULT_JOBS: usize = 8;

/// Severity threshold that gates non-zero exit codes. Mirrors
/// `arcis sca`'s `FailOn` so CI configs can use the same vocabulary on
/// both surfaces. Closes cli-test round-1 bug 2.
///
/// Semantics:
/// * `--severity` filters which findings are **displayed** (or emitted
///   in JSON/SARIF).
/// * `--fail-on` gates the **exit code**: exit 1 when any displayed
///   finding is at or above the threshold.
///
/// Default (`Any`) preserves legacy behaviour: any finding → exit 1.
/// `None` is the "report only" mode for CI summaries that want the
/// findings list logged but not gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    #[default]
    Any,
    None,
}

impl FailOn {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            "any" => Some(Self::Any),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

const FAIL_ON_VALUES: &str = "critical|high|medium|low|any|none";

/// Decide whether `findings` should produce a non-zero exit under the
/// given threshold. `Severity` is `Ord` with Critical < Low, so "at or
/// above the threshold" is `f.severity <= threshold` (Critical satisfies
/// `<= High`).
fn should_fail(findings: &[Finding], fail_on: FailOn) -> bool {
    match fail_on {
        FailOn::None => false,
        FailOn::Any => !findings.is_empty(),
        FailOn::Critical => findings.iter().any(|f| f.severity == Severity::Critical),
        FailOn::High => findings.iter().any(|f| f.severity <= Severity::High),
        FailOn::Medium => findings.iter().any(|f| f.severity <= Severity::Medium),
        FailOn::Low => findings.iter().any(|f| f.severity <= Severity::Low),
    }
}

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
    /// `--no-ignore`: disable BOTH `.arcisignore` AND `.gitignore`
    /// (and `.git/info/exclude`, and global git ignore). Mirrors
    /// ripgrep's flag of the same name.
    no_ignore: bool,
    /// `--no-gitignore`: disable `.gitignore` only — `.arcisignore`
    /// stays active. Useful in monorepos with broad gitignore lines
    /// over vendored dirs you do want to scan. Mirrors ripgrep.
    no_gitignore: bool,
    /// `--baseline <path>`: read mode. Read a baseline JSON file,
    /// classify current findings against it, suppress unchanged from
    /// output. Exit code reflects added findings only. Mutually
    /// exclusive with [`Self::baseline_write`] — see cli-audit.md
    /// item 9.
    baseline: Option<PathBuf>,
    /// `--baseline-write <path>`: write mode. Run a normal scan, then
    /// write a baseline JSON snapshot to `path` (atomic via deterministic
    /// `<path>.tmp` rename). Always exits 0 — recording IS success by
    /// definition. Mutually exclusive with [`Self::baseline`].
    baseline_write: Option<PathBuf>,
    /// `--jobs N` / `-j N`: worker thread count for parallel file
    /// scanning. cli-audit.md item 11. `None` falls back to
    /// [`DEFAULT_JOBS`] (8). Zero is rejected at parse time.
    jobs: Option<usize>,
    /// `--fail-on <level>`: severity threshold that triggers a non-zero
    /// exit. Default `Any` preserves legacy "exit 1 on any finding".
    /// `None` always exits 0 even with findings (report-only mode).
    /// cli-test round-1 bug 2.
    fail_on: FailOn,
    /// `--verbose` / `-v`: show finding IDs under each finding in the
    /// human report. IDs are always present in JSON/SARIF; verbose
    /// surfaces them inline so a user can paste the ID into a baseline
    /// or suppress comment without re-running with `--json`. cli-test
    /// round-1 bug 3.
    verbose: bool,
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
    let mut no_ignore = false;
    let mut no_gitignore = false;
    let mut baseline: Option<PathBuf> = None;
    let mut baseline_write: Option<PathBuf> = None;
    let mut jobs: Option<usize> = None;
    let mut fail_on = FailOn::default();
    let mut verbose = false;

    let mut iter = argv.iter().enumerate();
    while let Some((_, arg)) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return ParseOutcome::Help,
            "--no-color" => no_color = true,
            "--list" => list = true,
            "--quiet" | "-q" => quiet = true,
            "--verbose" | "-v" => verbose = true,
            "--json" => json_output = true,
            "--sarif" => sarif_output = true,
            "--no-ignore" => no_ignore = true,
            "--no-gitignore" => no_gitignore = true,
            "--fail-on" => match iter.next() {
                Some((_, v)) => match FailOn::parse(v) {
                    Some(f) => fail_on = f,
                    None => {
                        return ParseOutcome::Err(format!(
                            "arcis audit: invalid --fail-on value: {v} (expected {FAIL_ON_VALUES})"
                        ));
                    }
                },
                None => {
                    return ParseOutcome::Err(format!(
                        "arcis audit: --fail-on requires a value ({FAIL_ON_VALUES})"
                    ));
                }
            },
            other if other.starts_with("--fail-on=") => {
                let val = &other["--fail-on=".len()..];
                match FailOn::parse(val) {
                    Some(f) => fail_on = f,
                    None => {
                        return ParseOutcome::Err(format!(
                            "arcis audit: invalid --fail-on value: {val} (expected {FAIL_ON_VALUES})"
                        ));
                    }
                }
            }
            // cli-audit.md item 9: baseline mode (read). Mutex with
            // `--baseline-write` is enforced HERE at parse time, not
            // post-parse, so the error message can name the second
            // (offending) flag — easier to find when editing a config
            // or a long argv. The first-given flag always "wins" the
            // semantic slot; the second one is the one we point at.
            "--baseline" => match iter.next() {
                Some((_, v)) => {
                    if baseline_write.is_some() {
                        return ParseOutcome::Err(
                            "arcis audit: --baseline conflicts with --baseline-write \
                             (already given) — pick one: read OR write a baseline, not both"
                                .into(),
                        );
                    }
                    baseline = Some(PathBuf::from(v));
                }
                None => {
                    return ParseOutcome::Err(
                        "arcis audit: --baseline requires a path argument".into(),
                    );
                }
            },
            "--baseline-write" => match iter.next() {
                Some((_, v)) => {
                    if baseline.is_some() {
                        return ParseOutcome::Err(
                            "arcis audit: --baseline-write conflicts with --baseline \
                             (already given) — pick one: read OR write a baseline, not both"
                                .into(),
                        );
                    }
                    baseline_write = Some(PathBuf::from(v));
                }
                None => {
                    return ParseOutcome::Err(
                        "arcis audit: --baseline-write requires a path argument".into(),
                    );
                }
            },
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
            "--jobs" | "-j" => match iter.next() {
                Some((_, v)) => match v.parse::<usize>() {
                    Ok(0) => {
                        return ParseOutcome::Err("arcis audit: --jobs must be at least 1".into());
                    }
                    Ok(n) => jobs = Some(n),
                    Err(_) => {
                        return ParseOutcome::Err(format!(
                            "arcis audit: invalid --jobs value: {v} (expected a positive integer)"
                        ));
                    }
                },
                None => {
                    return ParseOutcome::Err("arcis audit: --jobs requires an argument".into());
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
        no_ignore,
        no_gitignore,
        baseline,
        baseline_write,
        jobs,
        fail_on,
        verbose,
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
        "  -v, --verbose        Show finding IDs under each finding in the human report."
    )?;
    writeln!(
        out,
        "      --fail-on LVL    Severity that triggers exit 1 ({FAIL_ON_VALUES})."
    )?;
    writeln!(
        out,
        "                       Default: any (exit 1 on any finding). 'none' exits 0 even"
    )?;
    writeln!(
        out,
        "                       with findings (report-only mode for CI summaries)."
    )?;
    writeln!(
        out,
        "      --json           Emit results as a single JSON document. Suppresses human output."
    )?;
    writeln!(
        out,
        "      --sarif          Emit results as SARIF 2.1.0 for GitHub Code Scanning."
    )?;
    writeln!(
        out,
        "      --no-ignore      Disable both .arcisignore and .gitignore (gitignore-style glob syntax)."
    )?;
    writeln!(
        out,
        "      --no-gitignore   Disable .gitignore only; keep .arcisignore active."
    )?;
    writeln!(
        out,
        "      --baseline PATH  Read mode: classify findings against PATH; suppress unchanged,"
    )?;
    writeln!(
        out,
        "                       fail only on new ones. Resolved findings reported as a positive"
    )?;
    writeln!(
        out,
        "                       signal. Mutually exclusive with --baseline-write."
    )?;
    writeln!(out, "      --baseline-write PATH")?;
    writeln!(
        out,
        "                       Write mode: record current findings to PATH as a baseline JSON"
    )?;
    writeln!(
        out,
        "                       file (atomic write). Always exits 0. Mutually exclusive with"
    )?;
    writeln!(
        out,
        "                       --baseline. Note: --severity applies BEFORE diff classification —"
    )?;
    writeln!(
        out,
        "                       writing a baseline at one severity then reading at a stricter one"
    )?;
    writeln!(
        out,
        "                       will surface the lower-severity entries as resolved."
    )?;
    writeln!(
        out,
        "  -j, --jobs N         Worker threads for parallel file scanning (default 8)."
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

    // cli-audit.md item 7: build ignore options from CLI flags.
    // `--no-ignore` is a superset of `--no-gitignore` — when set it
    // disables both files. Asymmetry is intentional: there's no
    // `--no-arcisignore` because arcisignore-only-off has no use case
    // (just delete the file).
    let ignore_opts = IgnoreOptions {
        use_arcisignore: !args.no_ignore,
        use_gitignore: !(args.no_ignore || args.no_gitignore),
    };

    let walk = collect_files_with_options(&path, args.language, &ignore_opts);
    let files = walk.files;
    let ignored_count = walk.ignored;

    // No scannable files: machine modes still emit a valid empty
    // document so CI parsers don't choke; non-machine prints a hint.
    // Either way, exit 2.
    if files.is_empty() {
        if machine_mode {
            let by_lang: BTreeMap<String, usize> = BTreeMap::new();
            let by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
            let out = if args.json_output {
                // No-files-found path: baseline mode is moot — there's
                // nothing to diff. Emit the empty document with no
                // baseline block regardless of `--baseline*` flags.
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
                    ignored: ignored_count,
                    baseline: None,
                    resolved_findings: &[],
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

    // Run scan. Time only the scan phase, like Python. Worker pool
    // (cli-audit.md item 11) processes files concurrently; the engine
    // clamps `jobs` to `[1, files.len()]` and falls through to the
    // serial path on a single-core CI runner without thread overhead.
    let jobs = args.jobs.unwrap_or(DEFAULT_JOBS);
    let start = Instant::now();
    let scan_result = scan_files_parallel(&files, jobs);
    let mut findings: Vec<Finding> = scan_result.findings;
    let suppressed_total: usize = scan_result.suppressed;
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
    // same id for the same source line. cli-audit.md item 10. MUST
    // run before baseline classification — the diff is keyed on `id`.
    assign_ids(&mut findings, &path);

    // ── cli-audit.md item 9: --baseline-write (terminal branch in
    // human mode; falls through with forced exit 0 in machine mode so
    // the user gets BOTH the recorded baseline AND the JSON/SARIF
    // output a CI pipeline expects). Mutex with --baseline is
    // enforced parse-side; can't both be set here.
    let baseline_write_succeeded = if let Some(write_path) = args.baseline_write.as_ref() {
        let new_baseline = Baseline::from_findings(&findings, TOOL_VERSION);
        if let Err(e) = new_baseline.write(write_path) {
            let _ = writeln!(stderr_lock, "arcis audit: {e}");
            return ExitCode::from(2);
        }
        if !args.quiet && !machine_mode {
            let _ = writeln!(
                stderr_lock,
                "wrote baseline to {} ({} finding(s))",
                write_path.display(),
                new_baseline.findings.len(),
            );
        }
        if !machine_mode {
            // Pure write run with human stdout: nothing more to print.
            // Recording is success — exit 0 even if findings exist.
            return ExitCode::from(0);
        }
        true
    } else {
        false
    };

    // ── cli-audit.md item 9: --baseline (read mode). Reads the
    // baseline file, classifies current findings against it, replaces
    // `findings` with diff.added so the rest of the render path
    // naturally surfaces NEW findings only. Resolved + unchanged are
    // surfaced via the BaselineSummary block, not the findings array.
    //
    // Backing String storage lives at this scope so the `&str` refs
    // in the borrowed BaselineSummary outlive the JsonReport build.
    let mut baseline_path_owned: Option<String> = None;
    let mut baseline_created_owned: Option<String> = None;
    let mut baseline_added_count: usize = 0;
    let mut baseline_resolved_count: usize = 0;
    let mut baseline_unchanged_count: usize = 0;
    let mut baseline_stale_count: usize = 0;
    let mut resolved_entries: Vec<BaselineEntry> = Vec::new();

    if let Some(read_path) = args.baseline.as_ref() {
        let baseline_doc = match Baseline::read(read_path) {
            Ok(b) => b,
            Err(BaselineError::NotFound(p)) => {
                let _ = writeln!(stderr_lock, "arcis audit: baseline file not found: {p}");
                return ExitCode::from(2);
            }
            Err(e) => {
                let _ = writeln!(stderr_lock, "arcis audit: {e}");
                return ExitCode::from(2);
            }
        };
        let diff = classify_baseline(&findings, &baseline_doc);

        // Stale-rule warning is informational — doesn't fail the run,
        // just surfaces orphaned baseline rows (rule deleted/renamed
        // since the baseline was written). Quiet/machine modes get a
        // count via summary.baseline.staleCount, not a stderr line.
        if !args.quiet && !machine_mode && diff.stale_count > 0 {
            let _ = writeln!(
                stderr_lock,
                "warning: baseline has {} stale {} (rule no longer in registry: {})",
                diff.stale_count,
                if diff.stale_count == 1 {
                    "entry"
                } else {
                    "entries"
                },
                diff.stale_rule_ids.join(", "),
            );
        }

        baseline_path_owned = Some(read_path.display().to_string());
        baseline_created_owned = Some(baseline_doc.created_at);
        baseline_added_count = diff.added.len();
        baseline_resolved_count = diff.resolved.len();
        baseline_unchanged_count = diff.unchanged_count;
        baseline_stale_count = diff.stale_count;
        findings = diff.added;
        resolved_entries = diff.resolved;
    }

    // Per-severity counts over the (possibly diffed) findings vec.
    // Sorted by Severity Ord so the JSON `bySeverity` map keys come
    // out in [critical, high, medium, low] order — matches Python's
    // audit.py once the sort tweak lands.
    let mut by_severity: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in &findings {
        *by_severity.entry(f.severity).or_insert(0) += 1;
    }

    // Borrow-bridge: BaselineSummary's `&str`s point into the owned
    // strings declared above. Same scope, same lifetime — safe.
    let baseline_summary = match (
        baseline_path_owned.as_ref(),
        baseline_created_owned.as_ref(),
    ) {
        (Some(p), Some(c)) => Some(BaselineSummary {
            path: p.as_str(),
            created_at: c.as_str(),
            added: baseline_added_count,
            resolved_count: baseline_resolved_count,
            unchanged_count: baseline_unchanged_count,
            stale_count: baseline_stale_count,
        }),
        _ => None,
    };

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
                ignored: ignored_count,
                baseline: baseline_summary.as_ref(),
                resolved_findings: &resolved_entries,
            })
        } else {
            // SARIF schema has no baseline block; the diffed findings
            // slice naturally surfaces "new" results only when in
            // baseline mode, which is what GitHub Code Scanning wants
            // anyway (it computes the rest from partialFingerprints).
            render_sarif(&SarifReport {
                tool_version: TOOL_VERSION,
                target_abspath: &target_str,
                findings: &findings,
            })
        };
        let _ = writeln!(stdout_lock, "{out}");
        // --baseline-write owns the exit code: always 0 (recording IS
        // success). Otherwise, classic "exit 1 on findings, 0 on
        // clean" — and in baseline read mode `findings` IS diff.added
        // so the same expression already gates on new only.
        return if baseline_write_succeeded || !should_fail(&findings, args.fail_on) {
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
        ignored_count,
        baseline_summary.as_ref(),
        &resolved_entries,
        args.verbose,
    );

    if should_fail(&findings, args.fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
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
    ignored: usize,
    baseline_summary: Option<&BaselineSummary<'_>>,
    resolved_entries: &[BaselineEntry],
    verbose: bool,
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
    // cli-audit.md item 9: header gains a baseline line in baseline
    // mode so users see at-a-glance which file was diffed against and
    // a punch-card of the result.
    if let Some(bs) = baseline_summary {
        writeln!(
            out,
            "  Baseline: {} ({} new, {} resolved, {} unchanged)",
            bs.path, bs.added, bs.resolved_count, bs.unchanged_count
        )?;
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
                // cli-test round-1 bug 3: `--verbose` surfaces the
                // deterministic finding ID under each entry. IDs are
                // always emitted in JSON/SARIF; this just makes them
                // visible in human mode so users can paste one into a
                // baseline or a suppress comment without re-running.
                if verbose && !f.id.is_empty() {
                    writeln!(out, "      id: {}", f.id)?;
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
    // cli-audit.md item 7: surface .arcisignore / .gitignore exclusion
    // count only when non-zero. Same noise rationale as Suppressed
    // above — JSON always carries the field for machine consumers.
    if ignored > 0 {
        writeln!(out, "    Files ignored   {ignored}")?;
    }
    writeln!(out, "    Time            {duration_ms}ms")?;

    // cli-audit.md item 9: Summary block gains baseline lines in
    // baseline mode — resolved is shown even at 0 (positive signal is
    // the point), stale gated on > 0 (warning, not the common case).
    if let Some(bs) = baseline_summary {
        writeln!(out)?;
        writeln!(out, "    Baseline        {}", bs.path)?;
        writeln!(out, "    New             {}", bs.added)?;
        writeln!(out, "    Unchanged       {}", bs.unchanged_count)?;
        writeln!(out, "    Resolved        {}", bs.resolved_count)?;
        if bs.stale_count > 0 {
            writeln!(out, "    Stale entries   {}", bs.stale_count)?;
        }
        // Per-line resolved list (each up to 80-ish chars). Helpful for
        // a human auditor; machine consumers get the structured data
        // via the top-level `resolvedFindings` array.
        if !resolved_entries.is_empty() {
            writeln!(out)?;
            writeln!(out, "  Resolved findings")?;
            for e in resolved_entries {
                writeln!(out, "    {} {}:{}", e.rule_id, e.file, e.line)?;
            }
        }
    }
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
            0,
            None,
            &[],
            false,
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
            0,
            None,
            &[],
            false,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("Suppressed"),
            "Suppressed line should not appear when count is 0, got:\n{out}"
        );
    }

    // ── ignore-file machinery (cli-audit.md item 7) ────────────────────

    #[test]
    fn parse_args_no_ignore_flag() {
        match parse_args(&[".".to_string(), "--no-ignore".to_string()]) {
            ParseOutcome::Args(a) => {
                assert!(a.no_ignore);
                assert!(!a.no_gitignore);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_no_gitignore_flag() {
        match parse_args(&[".".to_string(), "--no-gitignore".to_string()]) {
            ParseOutcome::Args(a) => {
                assert!(!a.no_ignore);
                assert!(a.no_gitignore);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_no_ignore_and_no_gitignore_both_set() {
        // Redundant but legal — `--no-ignore` already implies
        // `--no-gitignore`. Both flags being set is fine, no error.
        match parse_args(&[
            ".".to_string(),
            "--no-ignore".to_string(),
            "--no-gitignore".to_string(),
        ]) {
            ParseOutcome::Args(a) => {
                assert!(a.no_ignore);
                assert!(a.no_gitignore);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn help_documents_no_ignore_flags() {
        // cli-audit.md item 7 spec: help text must surface both flags
        // and explain `.arcisignore` uses gitignore-style syntax so
        // users don't have to dig through crate docs.
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("--no-ignore"), "help must mention --no-ignore");
        assert!(
            out.contains("--no-gitignore"),
            "help must mention --no-gitignore"
        );
        assert!(
            out.contains(".arcisignore"),
            "help must mention .arcisignore"
        );
        assert!(
            out.to_lowercase().contains("gitignore-style")
                || out.to_lowercase().contains("gitignore syntax")
                || out.to_lowercase().contains("gitignore-style glob"),
            "help must mention that patterns follow gitignore-style syntax, got:\n{out}"
        );
    }

    #[test]
    fn human_summary_emits_files_ignored_line_when_count_positive() {
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
            5,
            None,
            &[],
            false,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("Files ignored   5"),
            "expected Files ignored line in summary, got:\n{out}"
        );
    }

    #[test]
    fn human_summary_omits_files_ignored_line_when_count_zero() {
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
            0,
            None,
            &[],
            false,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("Files ignored"),
            "Files ignored line should not appear when count is 0, got:\n{out}"
        );
    }

    // ── baseline mode (cli-audit.md item 9) ───────────────────────────

    #[test]
    fn parse_args_baseline_flag() {
        match parse_args(&[
            ".".to_string(),
            "--baseline".to_string(),
            "b.json".to_string(),
        ]) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.baseline, Some(PathBuf::from("b.json")));
                assert!(a.baseline_write.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_baseline_write_flag() {
        match parse_args(&[
            ".".to_string(),
            "--baseline-write".to_string(),
            "out.json".to_string(),
        ]) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.baseline_write, Some(PathBuf::from("out.json")));
                assert!(a.baseline.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_baseline_then_write_errors_pointing_to_second_flag() {
        // User asked for --baseline first, then --baseline-write — the
        // second flag is the offender. The error message MUST name it
        // by its long form so a user editing a config file or a long
        // argv can spot the offending line at a glance.
        let r = parse_args(&[
            ".".to_string(),
            "--baseline".to_string(),
            "b.json".to_string(),
            "--baseline-write".to_string(),
            "w.json".to_string(),
        ]);
        match r {
            ParseOutcome::Err(msg) => {
                assert!(
                    msg.contains("--baseline-write"),
                    "second flag --baseline-write must appear in error: {msg}"
                );
                assert!(
                    msg.contains("conflicts with --baseline"),
                    "error must point at the prior flag for context: {msg}"
                );
                assert!(
                    msg.contains("read OR write"),
                    "error should explain WHY the mutex exists: {msg}"
                );
            }
            other => panic!("expected mutex error, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_write_then_baseline_errors_pointing_to_second_flag() {
        // Inverse order — `--baseline-write` first, then `--baseline`.
        // Now `--baseline` is the second/offending flag.
        let r = parse_args(&[
            ".".to_string(),
            "--baseline-write".to_string(),
            "w.json".to_string(),
            "--baseline".to_string(),
            "b.json".to_string(),
        ]);
        match r {
            ParseOutcome::Err(msg) => {
                assert!(
                    msg.contains("--baseline"),
                    "second flag --baseline must appear in error: {msg}"
                );
                assert!(
                    msg.contains("conflicts with --baseline-write"),
                    "error must point at the prior flag for context: {msg}"
                );
            }
            other => panic!("expected mutex error, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_baseline_without_path_errors() {
        let r = parse_args(&[".".to_string(), "--baseline".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("requires a path")));
    }

    #[test]
    fn parse_args_baseline_write_without_path_errors() {
        let r = parse_args(&[".".to_string(), "--baseline-write".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("requires a path")));
    }

    // ── --fail-on + --verbose (cli-test round-1 bugs 2 + 3) ───────────

    #[test]
    fn parse_args_fail_on_critical() {
        match parse_args(&[".".to_string(), "--fail-on".to_string(), "critical".to_string()]) {
            ParseOutcome::Args(a) => assert_eq!(a.fail_on, FailOn::Critical),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_fail_on_none() {
        match parse_args(&[".".to_string(), "--fail-on".to_string(), "none".to_string()]) {
            ParseOutcome::Args(a) => assert_eq!(a.fail_on, FailOn::None),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_fail_on_equals_form() {
        match parse_args(&[".".to_string(), "--fail-on=high".to_string()]) {
            ParseOutcome::Args(a) => assert_eq!(a.fail_on, FailOn::High),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_fail_on_default_is_any() {
        match parse_args(&[".".to_string()]) {
            ParseOutcome::Args(a) => assert_eq!(a.fail_on, FailOn::Any),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_fail_on_invalid_value_errors() {
        let r = parse_args(&[".".to_string(), "--fail-on".to_string(), "bogus".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("invalid --fail-on")));
    }

    #[test]
    fn parse_args_fail_on_without_value_errors() {
        let r = parse_args(&[".".to_string(), "--fail-on".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("requires a value")));
    }

    #[test]
    fn parse_args_verbose_short_and_long() {
        match parse_args(&[".".to_string(), "--verbose".to_string()]) {
            ParseOutcome::Args(a) => assert!(a.verbose),
            other => panic!("unexpected {other:?}"),
        }
        match parse_args(&[".".to_string(), "-v".to_string()]) {
            ParseOutcome::Args(a) => assert!(a.verbose),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_verbose_default_false() {
        match parse_args(&[".".to_string()]) {
            ParseOutcome::Args(a) => assert!(!a.verbose),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn should_fail_threshold_logic() {
        use arcis_engine::audit::Finding;
        let mk = |sev: Severity| Finding {
            rule_id: "TEST",
            severity: sev,
            message: "test",
            file: "f".into(),
            line: 1,
            snippet: String::new(),
            id: String::new(),
        };
        let empty: Vec<Finding> = Vec::new();
        let just_low = vec![mk(Severity::Low)];
        let high_and_low = vec![mk(Severity::High), mk(Severity::Low)];

        // None: never fail
        assert!(!should_fail(&empty, FailOn::None));
        assert!(!should_fail(&high_and_low, FailOn::None));

        // Any: fail on anything, even Low
        assert!(!should_fail(&empty, FailOn::Any));
        assert!(should_fail(&just_low, FailOn::Any));

        // Critical: only fail on Critical
        assert!(!should_fail(&high_and_low, FailOn::Critical));
        assert!(should_fail(&vec![mk(Severity::Critical)], FailOn::Critical));

        // High: fail on Critical or High, not Medium or Low
        assert!(should_fail(&high_and_low, FailOn::High));
        assert!(!should_fail(&just_low, FailOn::High));
    }

    #[test]
    fn help_documents_fail_on_and_verbose() {
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("--fail-on"), "help must mention --fail-on");
        assert!(out.contains("--verbose"), "help must mention --verbose");
        assert!(
            out.contains("critical|high|medium|low|any|none"),
            "help must list all --fail-on values: {out}"
        );
    }

    #[test]
    fn verbose_human_report_includes_finding_id() {
        use arcis_engine::audit::Finding;
        let mut buf: Vec<u8> = Vec::new();
        let by_lang: BTreeMap<String, usize> = [("python".to_string(), 1)].into_iter().collect();
        let mut by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        by_sev.insert(Severity::High, 1);
        let findings = vec![Finding {
            rule_id: "INNERHTML",
            severity: Severity::High,
            message: "test message",
            file: "a.py".into(),
            line: 42,
            snippet: "snippet".into(),
            id: "INNERHTML-0123456789abcdef".into(),
        }];
        print_human_report(
            &mut buf,
            Path::new("/tmp"),
            &[PathBuf::from("/tmp/a.py")],
            &by_lang,
            14,
            None,
            &findings,
            &by_sev,
            42,
            0,
            0,
            None,
            &[],
            true, // verbose
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("id: INNERHTML-0123456789abcdef"),
            "verbose mode must surface finding IDs in human report: {out}"
        );
    }

    #[test]
    fn non_verbose_human_report_omits_finding_id() {
        use arcis_engine::audit::Finding;
        let mut buf: Vec<u8> = Vec::new();
        let by_lang: BTreeMap<String, usize> = [("python".to_string(), 1)].into_iter().collect();
        let mut by_sev: BTreeMap<Severity, usize> = BTreeMap::new();
        by_sev.insert(Severity::High, 1);
        let findings = vec![Finding {
            rule_id: "INNERHTML",
            severity: Severity::High,
            message: "test message",
            file: "a.py".into(),
            line: 42,
            snippet: "snippet".into(),
            id: "INNERHTML-0123456789abcdef".into(),
        }];
        print_human_report(
            &mut buf,
            Path::new("/tmp"),
            &[PathBuf::from("/tmp/a.py")],
            &by_lang,
            14,
            None,
            &findings,
            &by_sev,
            42,
            0,
            0,
            None,
            &[],
            false, // not verbose
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("id:"),
            "default mode must not surface finding IDs: {out}"
        );
    }

    // ── --jobs flag (cli-audit.md item 11) ─────────────────────────────

    #[test]
    fn parse_args_jobs_long_flag() {
        match parse_args(&[".".to_string(), "--jobs".to_string(), "4".to_string()]) {
            ParseOutcome::Args(a) => assert_eq!(a.jobs, Some(4)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_jobs_short_flag() {
        match parse_args(&[".".to_string(), "-j".to_string(), "16".to_string()]) {
            ParseOutcome::Args(a) => assert_eq!(a.jobs, Some(16)),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_jobs_default_is_none() {
        // Caller fills in DEFAULT_JOBS (8) — parser stays neutral so the
        // explicit-flag-vs-default distinction stays visible if we ever
        // need to log it.
        match parse_args(&[".".to_string()]) {
            ParseOutcome::Args(a) => assert!(a.jobs.is_none()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_args_jobs_zero_errors() {
        // Zero workers would never make progress. Reject at parse time
        // so the user gets a clear message instead of a silent hang.
        let r = parse_args(&[".".to_string(), "--jobs".to_string(), "0".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("at least 1")));
    }

    #[test]
    fn parse_args_jobs_non_numeric_errors() {
        let r = parse_args(&[".".to_string(), "--jobs".to_string(), "many".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("invalid --jobs")));
    }

    #[test]
    fn parse_args_jobs_negative_errors() {
        // `-4`.parse::<usize>() rejects the leading minus — covered by
        // the same path as the non-numeric case but pin it explicitly so
        // a future move to a signed type doesn't silently accept it.
        let r = parse_args(&[".".to_string(), "--jobs".to_string(), "-4".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("invalid --jobs")));
    }

    #[test]
    fn parse_args_jobs_without_value_errors() {
        let r = parse_args(&[".".to_string(), "--jobs".to_string()]);
        assert!(matches!(r, ParseOutcome::Err(msg) if msg.contains("requires an argument")));
    }

    #[test]
    fn help_text_documents_jobs_flag() {
        // Refinement #3 mirror: pin --jobs in the help text. Both forms
        // appear, the default (8) is named, and the purpose ("parallel"
        // / "worker") is surfaced so users know what they're tuning.
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("--jobs"), "help must mention --jobs");
        assert!(out.contains("-j"), "help must mention -j short form");
        assert!(
            out.contains("8"),
            "help must surface the default worker count: {out}"
        );
        assert!(
            out.to_lowercase().contains("worker") || out.to_lowercase().contains("parallel"),
            "help must explain --jobs is about parallelism: {out}"
        );
    }

    #[test]
    fn help_text_documents_baseline_flags() {
        // Refinement #3: help-text pin. Future help-text refactors that
        // drop these fail loudly. Asserts BOTH flags appear, the mutex
        // note is surfaced, AND a one-liner explaining diff
        // classification (the "fail only on new" semantic) is present.
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(
            out.contains("--baseline "),
            "help must mention --baseline (with trailing space, not as a prefix match for --baseline-write)"
        );
        assert!(
            out.contains("--baseline-write"),
            "help must mention --baseline-write"
        );
        assert!(
            out.to_lowercase().contains("mutually exclusive"),
            "help must surface the --baseline / --baseline-write mutex: {out}"
        );
        // "Fail only on new" semantic — the user-visible reason to use
        // baseline mode at all. Keep the assertion permissive so a
        // wording polish doesn't trip it.
        assert!(
            out.to_lowercase().contains("new")
                && (out.to_lowercase().contains("fail") || out.to_lowercase().contains("exit")),
            "help must explain the diff classification (fail/exit on NEW only): {out}"
        );
        assert!(
            out.to_lowercase().contains("resolved"),
            "help must surface the resolved-as-positive-signal contract: {out}"
        );
    }
}
