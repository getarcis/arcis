//! `arcis sca` — supply chain attack scanner CLI subcommand.
//!
//! Output formatter mirrors `print_sca_report` and `print_threat_list` in
//! `packages/arcis-python/arcis/cli/sca.py` byte-for-byte under
//! `--no-color`. The only non-deterministic line is the `Time` row, which
//! the parity harness strips before byte-comparing.

use std::env;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use arcis_engine::sca::{discover_manifests, scan_project, Finding, FindingType};
use arcis_engine::threat_db::Threat;

const WIDTH: usize = 64;
const LINE_CHAR: &str = "\u{2500}"; // ─
const TICK: &str = "\u{2713}"; // ✓
const CROSS: &str = "\u{2717}"; // ✗

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[92m";
const RED: &str = "\x1b[91m";
const YELLOW: &str = "\x1b[93m";
const CYAN: &str = "\x1b[96m";
const WHITE: &str = "\x1b[97m";

#[derive(Debug)]
struct Args {
    path: PathBuf,
    system: bool,
    list_threats: bool,
    no_color: bool,
    /// Reserved: matches the Python flag but only suppresses the live
    /// progress, which the Rust port doesn't render yet. Kept so users
    /// can pass `-q` without a parse error.
    _quiet: bool,
}

#[derive(Debug)]
enum ParseOutcome {
    Args(Args),
    /// `-h` / `--help`: caller should print help text and exit 0.
    Help,
    /// Parse error: caller should print msg to stderr and exit 2.
    Err(String),
}

fn parse_args(argv: &[String]) -> ParseOutcome {
    let mut path: Option<PathBuf> = None;
    let mut system = false;
    let mut list_threats = false;
    let mut no_color = false;
    let mut quiet = false;

    for arg in argv {
        match arg.as_str() {
            "--system" => system = true,
            "--list-threats" | "--list" | "-l" => list_threats = true,
            "--no-color" => no_color = true,
            "--quiet" | "-q" => quiet = true,
            "-h" | "--help" => return ParseOutcome::Help,
            other if other.starts_with("--") || (other.starts_with('-') && other.len() > 1) => {
                return ParseOutcome::Err(format!("arcis sca: unknown flag: {other}"));
            }
            other => {
                if path.is_some() {
                    return ParseOutcome::Err(format!(
                        "arcis sca: unexpected positional argument: {other}"
                    ));
                }
                path = Some(PathBuf::from(other));
            }
        }
    }

    ParseOutcome::Args(Args {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        system,
        list_threats,
        no_color,
        _quiet: quiet,
    })
}

/// Compose ANSI codes around `text` unless `no_color` is set. Mirrors
/// Python's `_c(*codes, text=..., no_color=...)`.
fn c(text: &str, codes: &[&str], no_color: bool) -> String {
    if no_color {
        text.to_string()
    } else {
        let mut out = String::with_capacity(text.len() + 16);
        for code in codes {
            out.push_str(code);
        }
        out.push_str(text);
        out.push_str(RESET);
        out
    }
}

/// Manual `os.path.abspath`-equivalent: prepend `cwd` if relative, then
/// resolve `.` and `..` segments. Does NOT follow symlinks (matches
/// Python's `abspath` semantics, unlike `Path::canonicalize`).
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
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Word-wrap matching the Python `_wrap`: split on whitespace, build lines
/// up to `width` characters each. Uses char counts (not bytes) so wide
/// glyphs land at the same boundary as Python's `len()`.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;
    for word in text.split_whitespace() {
        let wlen = word.chars().count();
        if !current.is_empty() && current_len + 1 + wlen > width {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
            current_len = wlen;
        } else if current.is_empty() {
            current.push_str(word);
            current_len = wlen;
        } else {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + wlen;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Render duration as `89ms` / `1.4s` / `2m 18s`, matching `_format_sca_duration`.
fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{}ms", (seconds * 1000.0) as u64)
    } else if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        let mins = (seconds / 60.0) as u64;
        let secs = (seconds % 60.0) as u64;
        format!("{mins}m {secs}s")
    }
}

/// Path::file_name as a String — manifest discovery only ever returns
/// children of `path`, so `relpath` is always just the filename.
fn manifest_relname(m: &Path) -> String {
    m.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn print_sca_report<W: Write>(
    w: &mut W,
    path: &Path,
    findings: &[Finding],
    duration: f64,
    no_color: bool,
    manifests: &[PathBuf],
    threat_count: usize,
) -> io::Result<()> {
    let line: String = LINE_CHAR.repeat(WIDTH);
    let manifest_summary = if manifests.is_empty() {
        String::new()
    } else {
        manifests
            .iter()
            .map(|m| manifest_relname(m))
            .collect::<Vec<_>>()
            .join(", ")
    };

    writeln!(w)?;
    writeln!(
        w,
        "{}",
        c("  Arcis Supply Chain Scanner", &[BOLD, CYAN], no_color)
    )?;
    writeln!(
        w,
        "{}",
        c(
            &format!("  Target:    {}", path.display()),
            &[DIM],
            no_color
        )
    )?;
    if !manifest_summary.is_empty() {
        writeln!(
            w,
            "{}",
            c(
                &format!("  Manifests: {manifest_summary}"),
                &[DIM],
                no_color
            )
        )?;
    }
    let pkg_word = if threat_count == 1 {
        "package"
    } else {
        "packages"
    };
    writeln!(
        w,
        "{}",
        c(
            &format!("  Threat DB: {threat_count} known compromised {pkg_word}"),
            &[DIM],
            no_color
        )
    )?;
    writeln!(
        w,
        "{}",
        c(
            "  Mode:      Offline - no network calls, no telemetry",
            &[DIM],
            no_color
        )
    )?;
    writeln!(w, "{}", c(&line, &[DIM], no_color))?;

    if findings.is_empty() {
        let manifests_count = manifests.len();
        let tail = if manifests_count > 0 {
            let s = if manifests_count == 1 { "" } else { "s" };
            format!("in {manifests_count} manifest{s}")
        } else {
            "in installed packages".into()
        };
        writeln!(w)?;
        writeln!(
            w,
            "{}",
            c(
                &format!("  {TICK}  Clean. No known compromised packages found {tail}."),
                &[GREEN, BOLD],
                no_color
            )
        )?;
        let cs = if threat_count == 1 { "" } else { "s" };
        writeln!(
            w,
            "{}",
            c(
                &format!("     {threat_count} known compromise{cs} checked, 0 matches."),
                &[DIM],
                no_color
            )
        )?;
        writeln!(w)?;
        writeln!(w, "{}", c(&line, &[DIM], no_color))?;
        writeln!(w, "  {}", c("Summary", &[BOLD], no_color))?;
        if manifests_count > 0 {
            writeln!(w, "    Manifests       {manifests_count}")?;
        }
        writeln!(
            w,
            "    Compromised     {}",
            c("0", &[GREEN, BOLD], no_color)
        )?;
        writeln!(w, "    Time            {}", format_duration(duration))?;
        writeln!(w, "{}", c(&line, &[DIM], no_color))?;
        writeln!(w)?;
        return Ok(());
    }

    let npm: Vec<&Finding> = findings.iter().filter(|f| f.ecosystem == "npm").collect();
    let pypi: Vec<&Finding> = findings.iter().filter(|f| f.ecosystem == "pypi").collect();

    for (group_name, group) in [("npm", &npm), ("PyPI", &pypi)] {
        if group.is_empty() {
            continue;
        }
        writeln!(w)?;
        writeln!(
            w,
            "{}",
            c(&format!("  {group_name}"), &[BOLD, WHITE], no_color)
        )?;

        for f in group.iter() {
            let sev_col = if f.severity == "critical" {
                RED
            } else {
                YELLOW
            };
            let sev_label = f.severity.to_ascii_uppercase();
            let type_label = match f.finding_type {
                FindingType::TrojanizedDep => "TROJANIZED DEPENDENCY",
                FindingType::PersistenceArtifact => "BACKDOOR ARTIFACT",
                FindingType::CompromisedVersion => "COMPROMISED VERSION",
            };

            writeln!(w)?;
            writeln!(
                w,
                "{}",
                c(
                    &format!("    {CROSS}  [{sev_label}] {type_label}"),
                    &[sev_col, BOLD],
                    no_color
                )
            )?;
            writeln!(w, "       Package:   {}@{}", f.package, f.version)?;
            writeln!(
                w,
                "{}",
                c(
                    &format!("       Location:  {}", f.location),
                    &[DIM],
                    no_color
                )
            )?;
            writeln!(w)?;
            writeln!(w, "{}", c("       Attack:", &[BOLD, WHITE], no_color))?;
            for av_line in wrap_text(&f.attack_vector, 55) {
                writeln!(w, "         {av_line}")?;
            }
            writeln!(w)?;
            writeln!(w, "{}", c("       Source:", &[BOLD, WHITE], no_color))?;
            writeln!(w, "         {}", f.source)?;
            for r in &f.references {
                writeln!(w, "{}", c(&format!("         {r}"), &[DIM], no_color))?;
            }
            writeln!(w)?;
            writeln!(w, "{}", c("       Fix:", &[BOLD, GREEN], no_color))?;
            for rem_line in f.remediation.split('\n') {
                writeln!(w, "         {}", rem_line.trim())?;
            }
        }
    }

    writeln!(w)?;
    writeln!(w, "{}", c(&line, &[DIM], no_color))?;
    writeln!(w)?;

    let critical = findings.iter().filter(|f| f.severity == "critical").count();
    let high = findings.iter().filter(|f| f.severity == "high").count();

    writeln!(w, "  {}", c("Summary", &[BOLD], no_color))?;
    if !manifests.is_empty() {
        writeln!(w, "    Manifests       {}", manifests.len())?;
    }
    writeln!(
        w,
        "    Compromised     {}",
        c(&findings.len().to_string(), &[RED, BOLD], no_color)
    )?;
    if critical > 0 {
        writeln!(
            w,
            "    Critical        {}",
            c(&critical.to_string(), &[RED, BOLD], no_color)
        )?;
    }
    if high > 0 {
        writeln!(
            w,
            "    High            {}",
            c(&high.to_string(), &[YELLOW, BOLD], no_color)
        )?;
    }
    writeln!(w, "    Time            {}", format_duration(duration))?;
    writeln!(w)?;
    writeln!(
        w,
        "{}",
        c(
            &format!(
                "  {CROSS}  Supply chain compromise detected \u{2014} follow remediation steps above"
            ),
            &[RED, BOLD],
            no_color
        )
    )?;
    writeln!(w)?;
    writeln!(w, "{}", c(&line, &[DIM], no_color))?;
    writeln!(w)?;
    Ok(())
}

fn print_threat_list<W: Write>(w: &mut W, threats: &[Threat], no_color: bool) -> io::Result<()> {
    let line: String = LINE_CHAR.repeat(WIDTH);
    let pluralz = if threats.len() == 1 { "" } else { "s" };

    writeln!(w)?;
    writeln!(
        w,
        "{}",
        c(
            "  Arcis SCA \u{2014} Threat Database",
            &[BOLD, CYAN],
            no_color
        )
    )?;
    writeln!(
        w,
        "{}",
        c(
            &format!("  {} known supply chain attack{}", threats.len(), pluralz),
            &[DIM],
            no_color
        )
    )?;
    writeln!(
        w,
        "{}",
        c("  Source: <embedded threat-db.json>", &[DIM], no_color)
    )?;
    writeln!(w, "{}", c(&line, &[DIM], no_color))?;

    for t in threats {
        let sev_col = if t.severity == "critical" {
            RED
        } else {
            YELLOW
        };
        writeln!(w)?;
        writeln!(
            w,
            "{}",
            c(
                &format!("  {} ({})", t.name, t.ecosystem),
                &[BOLD, WHITE],
                no_color
            )
        )?;
        writeln!(
            w,
            "    Severity:    {}",
            c(&t.severity.to_ascii_uppercase(), &[sev_col, BOLD], no_color)
        )?;
        writeln!(w, "    CVE:         {}", t.cve)?;
        writeln!(w, "    Disclosed:   {}", t.disclosure_date)?;
        writeln!(w, "    Versions:    {}", t.malicious_versions.join(", "))?;
        writeln!(w)?;
        writeln!(w, "{}", c("    Attack:", &[BOLD], no_color))?;
        for av in wrap_text(&t.attack_vector, 56) {
            writeln!(w, "      {av}")?;
        }
        if !t.references.is_empty() {
            writeln!(w)?;
            writeln!(w, "{}", c("    References:", &[BOLD], no_color))?;
            for r in &t.references {
                writeln!(w, "{}", c(&format!("      {r}"), &[DIM], no_color))?;
            }
        }
    }

    writeln!(w)?;
    writeln!(w, "{}", c(&line, &[DIM], no_color))?;
    writeln!(w)?;
    Ok(())
}

fn print_help<W: Write>(w: &mut W) -> io::Result<()> {
    writeln!(
        w,
        "usage: arcis sca [path] [--system] [--list] [--no-color] [-q]"
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "Supply Chain Attack Scanner \u{2014} detect compromised packages from"
    )?;
    writeln!(w, "known supply chain attacks. Runs entirely offline.")?;
    writeln!(w)?;
    writeln!(w, "positional arguments:")?;
    writeln!(
        w,
        "  path                Project directory to scan (default: .)"
    )?;
    writeln!(w)?;
    writeln!(w, "options:")?;
    writeln!(
        w,
        "  --system            Also scan globally installed packages and site-packages"
    )?;
    writeln!(
        w,
        "  --list, -l          List all threats in the bundled database and exit"
    )?;
    writeln!(w, "  --no-color          Disable colored output")?;
    writeln!(w, "  --quiet, -q         Suppress progress output")?;
    Ok(())
}

/// Entry point dispatched from `main.rs` when the user runs `arcis sca`.
/// `argv` is everything AFTER `sca` itself.
pub fn run(argv: &[String]) -> ExitCode {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let args = match parse_args(argv) {
        ParseOutcome::Args(a) => a,
        ParseOutcome::Help => {
            let _ = print_help(&mut out);
            return ExitCode::from(0);
        }
        ParseOutcome::Err(msg) => {
            eprintln!("{msg}");
            return ExitCode::from(2);
        }
    };

    let threats = Threat::load_all();

    if args.list_threats {
        let _ = print_threat_list(&mut out, &threats, args.no_color);
        return ExitCode::from(0);
    }

    let abs = abspath(&args.path);
    if !abs.is_dir() {
        let _ = writeln!(out, "arcis sca: path not found: {}", abs.display());
        return ExitCode::from(1);
    }

    let manifests = discover_manifests(&abs);
    if manifests.is_empty() && !args.system {
        let msg = format!(
            "arcis sca: no supported manifests found in {}\n  Looked for: package-lock.json, yarn.lock, pnpm-lock.yaml, node_modules,\n             requirements.txt, Pipfile.lock, poetry.lock\n  Run from your project root, or pass --system to scan installed packages.",
            abs.display()
        );
        if args.no_color {
            let _ = writeln!(out, "{msg}");
        } else {
            // Python wraps the whole message in yellow when --no-color isn't
            // set (`\033[33m{msg}\033[0m`). Mirror byte-for-byte.
            let _ = writeln!(out, "\x1b[33m{msg}\x1b[0m");
        }
        return ExitCode::from(2);
    }

    let start = Instant::now();
    let findings = scan_project(&abs, args.system, &threats);
    let duration = start.elapsed().as_secs_f64();

    let _ = print_sca_report(
        &mut out,
        &abs,
        &findings,
        duration,
        args.no_color,
        &manifests,
        threats.len(),
    );

    if findings.is_empty() {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_defaults() {
        let argv = vec![];
        match parse_args(&argv) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.path, PathBuf::from("."));
                assert!(!a.system);
                assert!(!a.list_threats);
                assert!(!a.no_color);
            }
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_collects_flags_and_path() {
        let argv: Vec<String> = ["--no-color", "/tmp/proj", "--system"]
            .into_iter()
            .map(String::from)
            .collect();
        match parse_args(&argv) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.path, PathBuf::from("/tmp/proj"));
                assert!(a.system);
                assert!(a.no_color);
            }
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_help_short_circuits() {
        let argv = vec!["--help".to_string()];
        assert!(matches!(parse_args(&argv), ParseOutcome::Help));
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        let argv = vec!["--banana".to_string()];
        assert!(matches!(parse_args(&argv), ParseOutcome::Err(_)));
    }

    #[test]
    fn format_duration_subsecond() {
        assert_eq!(format_duration(0.012), "12ms");
        assert_eq!(format_duration(0.0), "0ms");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(1.42), "1.4s");
        assert_eq!(format_duration(59.99), "60.0s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(138.0), "2m 18s");
    }

    #[test]
    fn wrap_text_breaks_on_width() {
        let lines = wrap_text("the quick brown fox jumps over the lazy dog", 10);
        for l in &lines {
            assert!(l.chars().count() <= 10, "line too long: {l:?}");
        }
        assert_eq!(
            lines.join(" "),
            "the quick brown fox jumps over the lazy dog"
        );
    }

    #[test]
    fn wrap_text_handles_long_word() {
        // Single word longer than width: emits as its own line, unbroken.
        let lines = wrap_text("supercalifragilistic", 5);
        assert_eq!(lines, vec!["supercalifragilistic".to_string()]);
    }

    #[test]
    fn abspath_normalizes_dot_dot() {
        let cwd = env::current_dir().unwrap();
        let result = abspath(Path::new("./foo/../bar"));
        assert_eq!(result, cwd.join("bar"));
    }

    #[test]
    fn report_clean_path_emits_summary() {
        let mut buf: Vec<u8> = Vec::new();
        let path = PathBuf::from("/tmp/demo");
        let manifests = vec![path.join("requirements.txt")];
        print_sca_report(&mut buf, &path, &[], 0.012, true, &manifests, 47).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Arcis Supply Chain Scanner"));
        assert!(out.contains("Manifests: requirements.txt"));
        assert!(out.contains("Threat DB: 47 known compromised packages"));
        assert!(out.contains("Clean. No known compromised packages found in 1 manifest."));
        assert!(out.contains("Compromised     0"));
        assert!(out.contains("Time            12ms"));
    }

    #[test]
    fn report_finding_path_groups_by_ecosystem() {
        let mut buf: Vec<u8> = Vec::new();
        let path = PathBuf::from("/tmp/demo");
        let manifests = vec![path.join("package-lock.json")];
        let findings = vec![Finding {
            package: "axios".into(),
            ecosystem: "npm".into(),
            version: "1.14.1".into(),
            severity: "critical".into(),
            location: "/tmp/demo/package-lock.json".into(),
            attack_vector: "Trojanized dependency.".into(),
            remediation: "1. uninstall\n2. reinstall".into(),
            source: "npm Security Advisory".into(),
            references: vec!["https://example.com/a".into()],
            finding_type: FindingType::CompromisedVersion,
        }];
        print_sca_report(&mut buf, &path, &findings, 0.020, true, &manifests, 47).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("npm\n"));
        assert!(out.contains("[CRITICAL] COMPROMISED VERSION"));
        assert!(out.contains("Package:   axios@1.14.1"));
        assert!(out.contains("Compromised     1"));
        assert!(out.contains("Critical        1"));
    }
}
