//! `arcis sca` — supply chain attack scanner CLI subcommand.
//!
//! Output formatter mirrors `print_sca_report` and `print_threat_list` in
//! `packages/arcis-python/arcis/cli/sca.py` byte-for-byte under
//! `--no-color`. The only non-deterministic line is the `Time` row, which
//! the parity harness strips before byte-comparing.

use std::env;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use arcis_engine::sca::{
    discover_manifests, enumerate_packages, scan_project, scan_project_with_osv, Finding,
    FindingType, OsvOptions,
};
use arcis_engine::sca_sbom::{emit_cyclonedx, emit_spdx};
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
    /// Augment embedded DB with live OSV.dev lookups.
    osv: bool,
    /// Skip the on-disk cache for OSV results (refetch every package).
    /// No-op without `--osv`.
    no_cache: bool,
    /// Reserved: matches the Python flag but only suppresses the live
    /// progress, which the Rust port doesn't render yet. Kept so users
    /// can pass `-q` without a parse error.
    _quiet: bool,
    /// Severity ladder that gates the non-zero exit. `Any` (default)
    /// preserves legacy behaviour: any finding → exit 1.
    fail_on: FailOn,
    /// SBOM emit format. `None` keeps the human report; `Some` swaps in
    /// the matching emitter and (when `output` is also `None`) suppresses
    /// the human report on stdout.
    sbom: Option<Sbom>,
    /// Destination file for the SBOM. `None` writes to stdout.
    /// Validation requires `sbom.is_some()` whenever this is set —
    /// `-o` redirecting the human report is a separate feature, not on
    /// this commit.
    output: Option<PathBuf>,
}

/// Severity threshold for `arcis sca --fail-on <level>`. The CLI compares
/// each finding's severity string against this enum: `Critical` only
/// trips on critical, `High` on critical+high, `Medium` on
/// critical+high+medium, `Any` on any finding (current default), `None`
/// always exits 0 even with findings (report-only mode for CI logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum FailOn {
    Critical,
    High,
    Medium,
    #[default]
    Any,
    None,
}

impl FailOn {
    /// Case-insensitive parse. Returns `None` for unknown values; the
    /// caller turns that into a `ParseOutcome::Err` with the value list.
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "any" => Some(Self::Any),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

const FAIL_ON_VALUES: &str = "critical|high|medium|any|none";

/// SBOM format selector. CycloneDX 1.5 and SPDX 2.3 both emit JSON; the
/// engine picks the right shape per spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sbom {
    Cyclonedx,
    Spdx,
}

impl Sbom {
    fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cyclonedx" => Some(Self::Cyclonedx),
            "spdx" => Some(Self::Spdx),
            _ => None,
        }
    }
}

const SBOM_VALUES: &str = "cyclonedx|spdx";

/// Decide whether `findings` should produce a non-zero exit under the
/// given threshold. The severity ladder is `critical > high > medium`
/// matching what the embedded threat DB emits today; `Any` and `None`
/// short-circuit the ladder.
fn should_fail(findings: &[Finding], fail_on: FailOn) -> bool {
    match fail_on {
        FailOn::None => false,
        FailOn::Any => !findings.is_empty(),
        FailOn::Critical => findings.iter().any(|f| f.severity == "critical"),
        FailOn::High => findings
            .iter()
            .any(|f| matches!(f.severity.as_str(), "critical" | "high")),
        FailOn::Medium => findings
            .iter()
            .any(|f| matches!(f.severity.as_str(), "critical" | "high" | "medium")),
    }
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
    let mut osv = false;
    let mut no_cache = false;
    let mut quiet = false;
    let mut fail_on = FailOn::default();
    let mut sbom: Option<Sbom> = None;
    let mut output: Option<PathBuf> = None;

    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        match arg {
            "--system" => system = true,
            "--list-threats" | "--list" | "-l" => list_threats = true,
            "--no-color" => no_color = true,
            "--osv" => osv = true,
            "--no-cache" => no_cache = true,
            "--quiet" | "-q" => quiet = true,
            "-h" | "--help" => return ParseOutcome::Help,
            "--fail-on" => {
                i += 1;
                let Some(val) = argv.get(i) else {
                    return ParseOutcome::Err(format!(
                        "arcis sca: --fail-on requires a value ({FAIL_ON_VALUES})"
                    ));
                };
                let Some(parsed) = FailOn::parse(val) else {
                    return ParseOutcome::Err(format!(
                        "arcis sca: invalid --fail-on value: {val} (expected {FAIL_ON_VALUES})"
                    ));
                };
                fail_on = parsed;
            }
            other if other.starts_with("--fail-on=") => {
                let val = &other["--fail-on=".len()..];
                let Some(parsed) = FailOn::parse(val) else {
                    return ParseOutcome::Err(format!(
                        "arcis sca: invalid --fail-on value: {val} (expected {FAIL_ON_VALUES})"
                    ));
                };
                fail_on = parsed;
            }
            "--sbom" => {
                i += 1;
                let Some(val) = argv.get(i) else {
                    return ParseOutcome::Err(format!(
                        "arcis sca: --sbom requires a value ({SBOM_VALUES})"
                    ));
                };
                let Some(parsed) = Sbom::parse(val) else {
                    return ParseOutcome::Err(format!(
                        "arcis sca: invalid --sbom value: {val} (expected {SBOM_VALUES})"
                    ));
                };
                sbom = Some(parsed);
            }
            other if other.starts_with("--sbom=") => {
                let val = &other["--sbom=".len()..];
                let Some(parsed) = Sbom::parse(val) else {
                    return ParseOutcome::Err(format!(
                        "arcis sca: invalid --sbom value: {val} (expected {SBOM_VALUES})"
                    ));
                };
                sbom = Some(parsed);
            }
            "-o" | "--output" => {
                i += 1;
                let Some(val) = argv.get(i) else {
                    return ParseOutcome::Err(
                        "arcis sca: -o/--output requires a file path".to_string(),
                    );
                };
                output = Some(PathBuf::from(val));
            }
            other if other.starts_with("--output=") => {
                let val = &other["--output=".len()..];
                if val.is_empty() {
                    return ParseOutcome::Err(
                        "arcis sca: --output= requires a file path".to_string(),
                    );
                }
                output = Some(PathBuf::from(val));
            }
            other if other.starts_with("-o=") => {
                let val = &other["-o=".len()..];
                if val.is_empty() {
                    return ParseOutcome::Err("arcis sca: -o= requires a file path".to_string());
                }
                output = Some(PathBuf::from(val));
            }
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
        i += 1;
    }

    if output.is_some() && sbom.is_none() {
        return ParseOutcome::Err(
            "arcis sca: -o/--output requires --sbom (the human report cannot be redirected)"
                .to_string(),
        );
    }

    // note: when `arcis sca --json` lands, error here if both `--sbom`
    // and `--json` are supplied (different machine output modes).

    ParseOutcome::Args(Args {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        system,
        list_threats,
        no_color,
        osv,
        no_cache,
        _quiet: quiet,
        fail_on,
        sbom,
        output,
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

// Eight scalar args (one per report-row datum); a wrapper struct doesn't
// add clarity for a single-use renderer with three callsites. Revisit if
// this grows past ~10 args or gains another caller.
#[allow(clippy::too_many_arguments)]
fn print_sca_report<W: Write>(
    w: &mut W,
    path: &Path,
    findings: &[Finding],
    duration: f64,
    no_color: bool,
    manifests: &[PathBuf],
    threat_count: usize,
    osv_enabled: bool,
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
    let mode_line = if osv_enabled {
        "  Mode:      OSV-augmented - embedded DB plus live api.osv.dev"
    } else {
        "  Mode:      Offline - no network calls, no telemetry"
    };
    writeln!(w, "{}", c(mode_line, &[DIM], no_color))?;
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
        "usage: arcis sca [path] [--system] [--list] [--osv] [--no-cache] [--fail-on <level>] [--sbom <format> [-o <file>]] [--no-color] [-q]"
    )?;
    writeln!(w)?;
    writeln!(
        w,
        "Supply Chain Attack Scanner \u{2014} detect compromised packages from"
    )?;
    writeln!(
        w,
        "known supply chain attacks. Runs offline by default; pass"
    )?;
    writeln!(w, "--osv to augment with live data from api.osv.dev.")?;
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
    writeln!(
        w,
        "  --osv               Augment embedded DB with live api.osv.dev lookups"
    )?;
    writeln!(
        w,
        "  --no-cache          Skip the on-disk OSV cache (~/.arcis/osv-cache.json)"
    )?;
    writeln!(
        w,
        "  --fail-on <level>   Minimum severity that triggers a non-zero exit."
    )?;
    writeln!(
        w,
        "                      Values: critical, high, medium, any, none."
    )?;
    writeln!(
        w,
        "                      Default: any (exit 1 on any finding)."
    )?;
    writeln!(
        w,
        "  --sbom <format>     Emit a Software Bill of Materials."
    )?;
    writeln!(
        w,
        "                      Values: cyclonedx (CycloneDX 1.5), spdx (SPDX 2.3)."
    )?;
    writeln!(
        w,
        "                      License fields are NOASSERTION (Arcis does not"
    )?;
    writeln!(w, "                      track package license metadata).")?;
    writeln!(
        w,
        "  -o, --output <file> Write the SBOM to <file> (requires --sbom)."
    )?;
    writeln!(
        w,
        "                      Without -o the SBOM goes to stdout and the"
    )?;
    writeln!(
        w,
        "                      human report is suppressed; with -o the human"
    )?;
    writeln!(w, "                      report still prints to stdout.")?;
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
    let findings = if args.osv {
        let opts = OsvOptions {
            cache_path: arcis_engine::osv_cache::OsvCache::default_path(),
            use_cache: !args.no_cache,
            offline: false,
            timeout: Duration::from_secs(5),
        };
        scan_project_with_osv(&abs, args.system, &threats, &opts)
    } else {
        scan_project(&abs, args.system, &threats)
    };
    let duration = start.elapsed().as_secs_f64();

    if let Some(format) = args.sbom {
        let packages = enumerate_packages(&abs);
        let emit_to_stdout = args.output.is_none();
        let emit_result: io::Result<()> = match args.output.as_ref() {
            None => match format {
                Sbom::Cyclonedx => emit_cyclonedx(&mut out, &packages, &findings),
                Sbom::Spdx => emit_spdx(&mut out, &packages, &findings),
            },
            Some(path) => {
                let file = match File::create(path) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("arcis sca: cannot write SBOM to {}: {e}", path.display());
                        return ExitCode::from(2);
                    }
                };
                let mut bw = BufWriter::new(file);
                let r = match format {
                    Sbom::Cyclonedx => emit_cyclonedx(&mut bw, &packages, &findings),
                    Sbom::Spdx => emit_spdx(&mut bw, &packages, &findings),
                };
                r.and_then(|_| bw.flush())
            }
        };
        if let Err(e) = emit_result {
            eprintln!("arcis sca: SBOM emit failed: {e}");
            return ExitCode::from(2);
        }
        // -o present → human report still goes to stdout. -o absent →
        // SBOM owns stdout, no human report.
        if !emit_to_stdout {
            let _ = print_sca_report(
                &mut out,
                &abs,
                &findings,
                duration,
                args.no_color,
                &manifests,
                threats.len(),
                args.osv,
            );
        }
        return if should_fail(&findings, args.fail_on) {
            ExitCode::from(1)
        } else {
            ExitCode::from(0)
        };
    }

    let _ = print_sca_report(
        &mut out,
        &abs,
        &findings,
        duration,
        args.no_color,
        &manifests,
        threats.len(),
        args.osv,
    );

    if should_fail(&findings, args.fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
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
                assert_eq!(a.fail_on, FailOn::Any, "default fail_on must be Any");
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
    fn parse_args_osv_and_no_cache() {
        let argv: Vec<String> = ["--osv", "--no-cache", "/tmp/proj"]
            .into_iter()
            .map(String::from)
            .collect();
        match parse_args(&argv) {
            ParseOutcome::Args(a) => {
                assert!(a.osv, "--osv must enable OSV");
                assert!(a.no_cache, "--no-cache must disable cache");
                assert_eq!(a.path, PathBuf::from("/tmp/proj"));
            }
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_default_osv_off() {
        match parse_args(&[]) {
            ParseOutcome::Args(a) => {
                assert!(!a.osv);
                assert!(!a.no_cache);
            }
            other => panic!("expected Args, got {other:?}"),
        }
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
        print_sca_report(&mut buf, &path, &[], 0.012, true, &manifests, 47, false).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("Arcis Supply Chain Scanner"));
        assert!(out.contains("Manifests: requirements.txt"));
        assert!(out.contains("Threat DB: 47 known compromised packages"));
        assert!(out.contains("Clean. No known compromised packages found in 1 manifest."));
        assert!(out.contains("Compromised     0"));
        assert!(out.contains("Time            12ms"));
    }

    // ── --fail-on parsing + should_fail truth table ───────────────────────

    fn finding_with_severity(sev: &str) -> Finding {
        Finding {
            package: "p".into(),
            ecosystem: "npm".into(),
            version: "1.0.0".into(),
            severity: sev.into(),
            location: "/tmp/lock".into(),
            attack_vector: String::new(),
            remediation: String::new(),
            source: String::new(),
            references: Vec::new(),
            finding_type: FindingType::CompromisedVersion,
            paths: Vec::new(),
            path_count: 0,
        }
    }

    #[test]
    fn parse_args_fail_on_separate_value() {
        for (input, want) in [
            ("critical", FailOn::Critical),
            ("high", FailOn::High),
            ("medium", FailOn::Medium),
            ("any", FailOn::Any),
            ("none", FailOn::None),
        ] {
            let argv: Vec<String> = ["--fail-on", input].into_iter().map(String::from).collect();
            match parse_args(&argv) {
                ParseOutcome::Args(a) => assert_eq!(a.fail_on, want, "for {input:?}"),
                other => panic!("expected Args for {input:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_args_fail_on_equals_form() {
        let argv = vec!["--fail-on=high".to_string()];
        match parse_args(&argv) {
            ParseOutcome::Args(a) => assert_eq!(a.fail_on, FailOn::High),
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_fail_on_case_insensitive() {
        for input in ["HIGH", "High", "hIgH", " high "] {
            let argv: Vec<String> = ["--fail-on", input].into_iter().map(String::from).collect();
            match parse_args(&argv) {
                ParseOutcome::Args(a) => assert_eq!(a.fail_on, FailOn::High, "for {input:?}"),
                other => panic!("expected Args for {input:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_args_fail_on_missing_value_errors() {
        let argv = vec!["--fail-on".to_string()];
        match parse_args(&argv) {
            ParseOutcome::Err(msg) => assert!(msg.contains("requires a value"), "msg: {msg}"),
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_fail_on_invalid_value_errors() {
        let argv: Vec<String> = ["--fail-on", "banana"]
            .into_iter()
            .map(String::from)
            .collect();
        match parse_args(&argv) {
            ParseOutcome::Err(msg) => {
                assert!(msg.contains("banana"), "msg: {msg}");
                assert!(msg.contains("expected"), "msg: {msg}");
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_rejects_low_value() {
        // `low` is intentionally not in the value set today: the embedded
        // threat DB only emits critical/high/medium, so `--fail-on low`
        // would be a footgun (selects nothing additional vs `any`). If a
        // low-severity finding ever lands, add `low` here AND in the enum.
        let argv: Vec<String> = ["--fail-on", "low"].into_iter().map(String::from).collect();
        assert!(matches!(parse_args(&argv), ParseOutcome::Err(_)));
    }

    #[test]
    fn should_fail_truth_table() {
        let crit = vec![finding_with_severity("critical")];
        let high = vec![finding_with_severity("high")];
        let med = vec![finding_with_severity("medium")];
        let none: Vec<Finding> = vec![];

        // Critical: only critical trips
        assert!(should_fail(&crit, FailOn::Critical));
        assert!(!should_fail(&high, FailOn::Critical));
        assert!(!should_fail(&med, FailOn::Critical));
        assert!(!should_fail(&none, FailOn::Critical));

        // High: critical + high
        assert!(should_fail(&crit, FailOn::High));
        assert!(should_fail(&high, FailOn::High));
        assert!(!should_fail(&med, FailOn::High));
        assert!(!should_fail(&none, FailOn::High));

        // Medium: critical + high + medium
        assert!(should_fail(&crit, FailOn::Medium));
        assert!(should_fail(&high, FailOn::Medium));
        assert!(should_fail(&med, FailOn::Medium));
        assert!(!should_fail(&none, FailOn::Medium));

        // Any: any non-empty list
        assert!(should_fail(&crit, FailOn::Any));
        assert!(should_fail(&high, FailOn::Any));
        assert!(should_fail(&med, FailOn::Any));
        assert!(!should_fail(&none, FailOn::Any));

        // None: never trips, even with critical findings
        assert!(!should_fail(&crit, FailOn::None));
        assert!(!should_fail(&high, FailOn::None));
        assert!(!should_fail(&med, FailOn::None));
        assert!(!should_fail(&none, FailOn::None));
    }

    #[test]
    fn should_fail_any_matches_legacy_default_behaviour() {
        // Future-proof against drift: --fail-on any must produce the
        // same exit decision as the pre-flag predicate (`!findings.is_empty()`)
        // for every fixture below. If the default ever changes silently,
        // this test catches it.
        let fixtures: Vec<Vec<Finding>> = vec![
            vec![],
            vec![finding_with_severity("critical")],
            vec![finding_with_severity("high")],
            vec![finding_with_severity("medium")],
            vec![
                finding_with_severity("critical"),
                finding_with_severity("medium"),
            ],
            vec![
                finding_with_severity("medium"),
                finding_with_severity("high"),
            ],
        ];
        for f in &fixtures {
            let legacy = !f.is_empty();
            let any_mode = should_fail(f, FailOn::Any);
            let default_mode = should_fail(f, FailOn::default());
            assert_eq!(any_mode, legacy, "Any drifted from legacy for {f:?}");
            assert_eq!(
                default_mode, legacy,
                "Default drifted from legacy for {f:?}"
            );
            assert_eq!(any_mode, default_mode, "Default != Any for {f:?}");
        }
    }

    #[test]
    fn should_fail_critical_with_high_only_findings_returns_false() {
        // End-to-end-flavored: simulates the documented "--fail-on critical
        // with only high findings → exit 0" amendment from the design call.
        let findings = vec![
            finding_with_severity("high"),
            finding_with_severity("high"),
            finding_with_severity("medium"),
        ];
        assert!(!should_fail(&findings, FailOn::Critical));
    }

    #[test]
    fn print_help_documents_fail_on() {
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("--fail-on"), "help missing --fail-on");
        assert!(
            out.contains("critical, high, medium, any, none"),
            "help missing the value list"
        );
        assert!(
            out.contains("Default: any"),
            "help should document the default"
        );
        // Usage line should advertise the flag too.
        assert!(out.contains("--fail-on <level>"), "usage missing --fail-on");
    }

    // ── --sbom + -o parsing ───────────────────────────────────────────────

    #[test]
    fn parse_args_sbom_separate_value() {
        for (input, want) in [("cyclonedx", Sbom::Cyclonedx), ("spdx", Sbom::Spdx)] {
            let argv: Vec<String> = ["--sbom", input].into_iter().map(String::from).collect();
            match parse_args(&argv) {
                ParseOutcome::Args(a) => assert_eq!(a.sbom, Some(want), "for {input:?}"),
                other => panic!("expected Args for {input:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_args_sbom_equals_form_and_case_insensitive() {
        let argv = vec!["--sbom=CycloneDX".to_string()];
        match parse_args(&argv) {
            ParseOutcome::Args(a) => assert_eq!(a.sbom, Some(Sbom::Cyclonedx)),
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_sbom_invalid_value_errors() {
        let argv: Vec<String> = ["--sbom", "swid"].into_iter().map(String::from).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(msg) => {
                assert!(msg.contains("swid"), "msg: {msg}");
                assert!(msg.contains("cyclonedx"), "msg: {msg}");
                assert!(msg.contains("spdx"), "msg: {msg}");
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_sbom_missing_value_errors() {
        let argv = vec!["--sbom".to_string()];
        match parse_args(&argv) {
            ParseOutcome::Err(msg) => assert!(msg.contains("requires a value"), "msg: {msg}"),
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_o_requires_sbom_errors() {
        // -o without --sbom is rejected: today there's no sca --json mode
        // and -o redirecting the human report is a separate feature.
        let argv: Vec<String> = ["-o", "out.json"].into_iter().map(String::from).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(msg) => assert!(
                msg.contains("requires --sbom"),
                "msg should explain the dependency: {msg}"
            ),
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_sbom_with_output_file() {
        let argv: Vec<String> = ["--sbom", "spdx", "-o", "/tmp/sbom.json"]
            .into_iter()
            .map(String::from)
            .collect();
        match parse_args(&argv) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.sbom, Some(Sbom::Spdx));
                assert_eq!(a.output, Some(PathBuf::from("/tmp/sbom.json")));
            }
            other => panic!("expected Args, got {other:?}"),
        }
        let argv: Vec<String> = ["--sbom=cyclonedx", "--output=/tmp/sbom.json"]
            .into_iter()
            .map(String::from)
            .collect();
        match parse_args(&argv) {
            ParseOutcome::Args(a) => {
                assert_eq!(a.sbom, Some(Sbom::Cyclonedx));
                assert_eq!(a.output, Some(PathBuf::from("/tmp/sbom.json")));
            }
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_sbom_default_off() {
        // Regression guard: bare `arcis sca` does not emit an SBOM.
        match parse_args(&[]) {
            ParseOutcome::Args(a) => {
                assert!(a.sbom.is_none(), "SBOM must default to off");
                assert!(a.output.is_none(), "output must default to None");
            }
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn print_help_documents_sbom() {
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("--sbom <format>"), "help missing --sbom");
        assert!(
            out.contains("cyclonedx (CycloneDX 1.5)"),
            "help should list cyclonedx"
        );
        assert!(out.contains("spdx (SPDX 2.3)"), "help should list spdx");
        assert!(
            out.contains("-o, --output <file>"),
            "help missing -o/--output"
        );
        assert!(
            out.contains("requires --sbom"),
            "help should document the dependency"
        );
        assert!(
            out.contains("NOASSERTION"),
            "help should disclose the license posture"
        );
        // Usage line should advertise --sbom too.
        assert!(out.contains("--sbom <format>"), "usage missing --sbom");
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
            paths: Vec::new(),
            path_count: 0,
        }];
        print_sca_report(
            &mut buf, &path, &findings, 0.020, true, &manifests, 47, false,
        )
        .unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("npm\n"));
        assert!(out.contains("[CRITICAL] COMPROMISED VERSION"));
        assert!(out.contains("Package:   axios@1.14.1"));
        assert!(out.contains("Compromised     1"));
        assert!(out.contains("Critical        1"));
    }
}
