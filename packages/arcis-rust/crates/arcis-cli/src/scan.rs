//! `arcis scan` - HTTP security scanner CLI subcommand.
//!
//! The catalog (`--list` / `-l` output) mirrors `_print_payload_catalog`
//! in `packages/arcis-python/arcis/cli/scan.py` byte-for-byte under
//! `--no-color`. Other modes (real network scans) are not pinned by the
//! current parity harness; a follow-up wires per-route mock-server
//! fixtures.

use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use arcis_engine::scan::{
    attack_categories, discover_routes, format_curl, payloads::slug, scan_route, AuthConfig,
    DiscoveredRoute, RouteResult, ScanOptions, DEFAULT_FIELDS,
};

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";

#[derive(Debug, Clone)]
struct Args {
    url: Option<String>,
    routes: Vec<String>,
    fields: Vec<String>,
    categories: Option<Vec<String>>,
    timeout: u64,
    thorough: bool,
    no_color: bool,
    list: bool,
    quiet: bool,
    yes: bool,
    no_discovery: bool,
    no_control_plane: bool,
    json_output: bool,
    bearer: Option<String>,
    cookie: Option<String>,
}

#[derive(Debug)]
enum ParseOutcome {
    Args(Box<Args>),
    Help,
    Err(String),
}

fn parse_args(argv: &[String]) -> ParseOutcome {
    let mut args = Args {
        url: None,
        routes: Vec::new(),
        fields: Vec::new(),
        categories: None,
        timeout: 5,
        thorough: false,
        no_color: false,
        list: false,
        quiet: false,
        yes: false,
        no_discovery: false,
        no_control_plane: false,
        json_output: false,
        bearer: None,
        cookie: None,
    };

    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "-h" | "--help" => return ParseOutcome::Help,
            "--list" => {
                args.list = true;
            }
            "--thorough" => args.thorough = true,
            "--no-color" => args.no_color = true,
            "--quiet" | "-q" => args.quiet = true,
            "--yes" | "-y" => args.yes = true,
            "--no-discovery" => args.no_discovery = true,
            "--no-control-plane" => args.no_control_plane = true,
            "--json" => args.json_output = true,
            "--route" | "-r" => {
                i += 1;
                let Some(v) = argv.get(i) else {
                    return ParseOutcome::Err("arcis scan: --route needs a value".into());
                };
                args.routes.push(v.clone());
            }
            "--field" | "-f" => {
                i += 1;
                let Some(v) = argv.get(i) else {
                    return ParseOutcome::Err("arcis scan: --field needs a value".into());
                };
                args.fields.push(v.clone());
            }
            "--timeout" | "-t" => {
                i += 1;
                let Some(v) = argv.get(i) else {
                    return ParseOutcome::Err("arcis scan: --timeout needs a value".into());
                };
                let Ok(n) = v.parse::<u64>() else {
                    return ParseOutcome::Err(format!(
                        "arcis scan: --timeout expected an integer, got: {v}"
                    ));
                };
                args.timeout = n;
            }
            "--categories" | "-c" => {
                // Accept either nargs+ (space-separated, `--categories xss
                // sql path`) or comma-separated (`--categories xss,sql,path`)
                // or a mix of both. Each consumed token is split on `,`,
                // trimmed, and empty pieces (from a stray comma) are dropped.
                let mut cats: Vec<String> = Vec::new();
                while i + 1 < argv.len() && !argv[i + 1].starts_with('-') {
                    i += 1;
                    for piece in argv[i].split(',') {
                        let p = piece.trim();
                        if !p.is_empty() {
                            cats.push(p.to_string());
                        }
                    }
                }
                if cats.is_empty() {
                    return ParseOutcome::Err(
                        "arcis scan: --categories needs at least one value".into(),
                    );
                }
                args.categories = Some(cats);
            }
            "-l" => {
                args.list = true;
            }
            "--bearer" => {
                i += 1;
                let Some(v) = argv.get(i) else {
                    return ParseOutcome::Err("arcis scan: --bearer needs a value".into());
                };
                match validate_bearer_value(v) {
                    Ok(t) => args.bearer = Some(t),
                    Err(e) => return ParseOutcome::Err(e),
                }
            }
            arg if arg.starts_with("--bearer=") => {
                let v = &arg["--bearer=".len()..];
                match validate_bearer_value(v) {
                    Ok(t) => args.bearer = Some(t),
                    Err(e) => return ParseOutcome::Err(e),
                }
            }
            "--cookie" => {
                i += 1;
                let Some(v) = argv.get(i) else {
                    return ParseOutcome::Err("arcis scan: --cookie needs a value".into());
                };
                match validate_cookie_value(v) {
                    Ok(t) => args.cookie = Some(t),
                    Err(e) => return ParseOutcome::Err(e),
                }
            }
            arg if arg.starts_with("--cookie=") => {
                let v = &arg["--cookie=".len()..];
                match validate_cookie_value(v) {
                    Ok(t) => args.cookie = Some(t),
                    Err(e) => return ParseOutcome::Err(e),
                }
            }
            // note(commit #4 --login): when --login lands, add a mutex
            // check here:
            //   if args.login.is_some() && args.bearer.is_some() { exit 2 }
            //   if args.login.is_some() && args.cookie.is_some() { exit 2 }
            // --login generates its own auth artifact, so combining it
            // with manual flags is ambiguous. Reject early.
            other if other.starts_with("--") || (other.starts_with('-') && other.len() > 1) => {
                return ParseOutcome::Err(format!("arcis scan: unknown flag: {other}"));
            }
            other => {
                if args.url.is_some() {
                    return ParseOutcome::Err(format!(
                        "arcis scan: unexpected positional argument: {other}"
                    ));
                }
                args.url = Some(other.to_string());
            }
        }
        i += 1;
    }

    ParseOutcome::Args(Box::new(args))
}

fn validate_bearer_value(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("arcis scan: --bearer cannot be empty or whitespace-only".into())
    } else {
        Ok(value.to_string())
    }
}

fn validate_cookie_value(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err("arcis scan: --cookie cannot be empty or whitespace-only".into())
    } else {
        Ok(value.to_string())
    }
}

fn ansi(no_color: bool, code: &str) -> &str {
    if no_color {
        ""
    } else {
        code
    }
}

/// Render the attack catalog. Matches Python `_print_payload_catalog`
/// byte-for-byte under `--no-color`. Em-dash kept verbatim for byte
/// parity with Python's source string; cleanup is a separate Python-side
/// task once we control both versions.
fn print_catalog(out: &mut dyn Write, no_color: bool) -> io::Result<()> {
    let bold = ansi(no_color, BOLD);
    let dim = ansi(no_color, DIM);
    let cyan = ansi(no_color, CYAN);
    let reset = ansi(no_color, RESET);

    let categories = attack_categories();
    let total: usize = categories.iter().map(|c| c.vectors.len()).sum();

    writeln!(out)?;
    writeln!(
        out,
        "  {bold}arcis scan \u{2014} attack catalog ({} categories, {total} payloads){reset}",
        categories.len(),
    )?;
    writeln!(
        out,
        "  {dim}Pass --categories to narrow scope, e.g. --categories xss sql{reset}",
    )?;
    writeln!(out)?;
    for cat in categories {
        let s = slug(cat.name);
        writeln!(out, "  {bold}{}{reset}  {dim}({s}){reset}", cat.name)?;
        for v in cat.vectors {
            let preview = if v.payload.chars().count() <= 60 {
                v.payload.to_string()
            } else {
                let head: String = v.payload.chars().take(57).collect();
                format!("{head}...")
            };
            // Python `label.ljust(18)`: pad to width 18 with spaces, no
            // truncation if longer. Use char-count for codepoint correctness.
            let pad = 18usize.saturating_sub(v.label.chars().count());
            writeln!(
                out,
                "    {cyan}{}{}{reset} {preview}",
                v.label,
                " ".repeat(pad)
            )?;
        }
        writeln!(out)?;
    }
    writeln!(
        out,
        "  {bold}Default fields tried (--field overrides){reset}"
    )?;
    writeln!(out, "    {}", DEFAULT_FIELDS.join(", "))?;
    writeln!(out)?;
    Ok(())
}

fn print_help(out: &mut dyn Write) -> io::Result<()> {
    let categories = attack_categories();
    let names: Vec<&str> = categories.iter().map(|c| c.name).collect();
    writeln!(out, "usage: arcis scan [URL] [options]")?;
    writeln!(out)?;
    writeln!(
        out,
        "Scan HTTP endpoints for common injection vulnerabilities."
    )?;
    writeln!(out)?;
    writeln!(out, "Options:")?;
    writeln!(
        out,
        "  -r, --route [METHOD:]PATH    Route to test. Repeat for multiple routes."
    )?;
    writeln!(
        out,
        "  -f, --field NAME             JSON field to inject payloads into. Repeat."
    )?;
    writeln!(
        out,
        "  -c, --categories CAT[,CAT..] Attack categories. Comma- or space-separated."
    )?;
    writeln!(
        out,
        "                               (default: all). Choices: {}",
        names.join(", ")
    )?;
    writeln!(
        out,
        "  -t, --timeout SEC            Per-request timeout in seconds (default: 5)."
    )?;
    writeln!(
        out,
        "      --thorough               Test all payloads per category, not just primary."
    )?;
    writeln!(
        out,
        "      --no-color               Disable coloured terminal output."
    )?;
    writeln!(
        out,
        "  -l, --list                   List all attack categories and payloads."
    )?;
    writeln!(
        out,
        "  -q, --quiet                  Suppress per-route progress output."
    )?;
    writeln!(
        out,
        "  -y, --yes                    Skip the confirm prompt (CI-friendly)."
    )?;
    writeln!(
        out,
        "      --no-discovery           Skip source-aware route discovery."
    )?;
    writeln!(
        out,
        "      --no-control-plane       Skip the local control-plane probe."
    )?;
    writeln!(
        out,
        "      --json                   Print machine-readable JSON summary."
    )?;
    writeln!(
        out,
        "      --bearer <token>         Send Authorization: Bearer <token> on every request."
    )?;
    writeln!(
        out,
        "                               Token value never appears in --json output."
    )?;
    writeln!(
        out,
        "      --cookie <value>         Send Cookie: <value> on every request. Pasted verbatim;"
    )?;
    writeln!(
        out,
        "                               join multi-cookie with `; `. Composes with --bearer."
    )?;
    writeln!(
        out,
        "                               Cookie value never appears in --json output."
    )?;
    writeln!(
        out,
        "  -h, --help                   Show this help and exit."
    )?;
    writeln!(out)?;
    Ok(())
}

/// Parse `--route` arguments. Format: `METHOD:/path` or bare `/path`
/// (defaults to POST). Mirrors Python `_parse_route_args`.
fn parse_route_args(raw: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        if let Some((m, p)) = r.split_once(':') {
            // Don't split on a `:` that's part of an http(s):// URL.
            if !r.starts_with("http") {
                out.push((m.to_uppercase(), p.to_string()));
                continue;
            }
        }
        out.push(("POST".into(), r.clone()));
    }
    out
}

#[derive(Debug, Default)]
struct ScanSummary {
    routes_total: usize,
    routes_reachable: usize,
    total_vectors: usize,
    total_blocked: usize,
    total_vulnerable: usize,
    duration_secs: f64,
}

fn summarize(results: &[RouteResult], duration: Duration) -> ScanSummary {
    let mut s = ScanSummary {
        routes_total: results.len(),
        ..Default::default()
    };
    for rr in results {
        if rr.reachable {
            s.routes_reachable += 1;
        }
        s.total_vectors += rr.vectors.len();
        for v in &rr.vectors {
            if v.blocked {
                s.total_blocked += 1;
            } else {
                s.total_vulnerable += 1;
            }
        }
    }
    s.duration_secs = duration.as_secs_f64();
    s
}

fn print_human_report(
    out: &mut dyn Write,
    target_url: &str,
    results: &[RouteResult],
    summary: &ScanSummary,
    no_color: bool,
) -> io::Result<()> {
    let bold = ansi(no_color, BOLD);
    let dim = ansi(no_color, DIM);
    let yellow = ansi(no_color, YELLOW);
    let reset = ansi(no_color, RESET);

    writeln!(out)?;
    writeln!(out, "  {bold}arcis scan \u{2014} report{reset}")?;
    writeln!(out, "  {dim}Target:{reset} {target_url}")?;
    writeln!(out)?;
    for rr in results {
        if !rr.reachable {
            let err = rr.error.as_deref().unwrap_or("unreachable");
            writeln!(
                out,
                "  {yellow}?{reset} {} {} {dim}{err}{reset}",
                rr.method, rr.path
            )?;
            continue;
        }
        let blocked = rr.vectors.iter().filter(|v| v.blocked).count();
        let total = rr.vectors.len();
        writeln!(
            out,
            "  {bold}{} {}{reset}  {blocked}/{total} blocked",
            rr.method, rr.path
        )?;
        for v in &rr.vectors {
            let mark = if v.blocked { "ok" } else { "!!" };
            writeln!(
                out,
                "    {dim}{mark}{reset} [{}] {} {dim}{}{reset}",
                v.category, v.label, v.note
            )?;
            // Emit a copyable curl reproducer for each vulnerable finding
            // so the user can reproduce the probe + verify their fix
            // without re-running the full scan. Blocked findings are
            // intentionally skipped to keep the report scannable.
            if !v.blocked {
                let curl = format_curl(target_url, &rr.method, &rr.path, &rr.field, &v.payload);
                writeln!(out, "       {dim}{curl}{reset}")?;
            }
        }
    }
    writeln!(out)?;
    writeln!(
        out,
        "  {bold}Summary:{reset} {} route(s) scanned, {} vector(s) probed; {} blocked, {} vulnerable {dim}({:.2}s){reset}",
        summary.routes_reachable,
        summary.total_vectors,
        summary.total_blocked,
        summary.total_vulnerable,
        summary.duration_secs,
    )?;
    writeln!(out)?;
    Ok(())
}

fn print_json_report(
    out: &mut dyn Write,
    target_url: &str,
    auth: Option<&AuthConfig>,
    results: &[RouteResult],
    summary: &ScanSummary,
) -> io::Result<()> {
    use serde_json::{json, Map, Value};

    let routes: Vec<Value> = results
        .iter()
        .map(|rr| {
            let vectors: Vec<Value> = rr
                .vectors
                .iter()
                .map(|v| {
                    let mut m = Map::new();
                    m.insert("category".into(), Value::String(v.category.clone()));
                    m.insert("label".into(), Value::String(v.label.clone()));
                    m.insert("payload".into(), Value::String(v.payload.clone()));
                    m.insert("status".into(), json!(v.status));
                    m.insert("blocked".into(), Value::Bool(v.blocked));
                    m.insert("note".into(), Value::String(v.note.clone()));
                    // Include the curl reproducer for every vector (blocked
                    // and vulnerable) so machine consumers can render or
                    // filter as they please.
                    m.insert(
                        "curl".into(),
                        Value::String(format_curl(
                            target_url, &rr.method, &rr.path, &rr.field, &v.payload,
                        )),
                    );
                    Value::Object(m)
                })
                .collect();
            let mut m = Map::new();
            m.insert("method".into(), Value::String(rr.method.clone()));
            m.insert("path".into(), Value::String(rr.path.clone()));
            m.insert("reachable".into(), Value::Bool(rr.reachable));
            m.insert(
                "error".into(),
                rr.error.clone().map(Value::String).unwrap_or(Value::Null),
            );
            m.insert("field".into(), Value::String(rr.field.clone()));
            m.insert("vectors".into(), Value::Array(vectors));
            Value::Object(m)
        })
        .collect();

    let mut doc = Map::new();
    doc.insert("tool".into(), Value::String("arcis-scan".into()));
    doc.insert("target".into(), Value::String(target_url.into()));
    // Auth metadata, redacted. Slot is between `target` and
    // `durationMs` (run setup, before run results). Omitted entirely
    // for unauthenticated runs so prior JSON output stays byte-equal.
    // The redaction rule lives on `AuthConfig::redact_for_json`; see
    // that doc-comment for the contract future flags must follow.
    if let Some(auth) = auth {
        if let Some(meta) = auth.redact_for_json() {
            doc.insert("auth".into(), meta);
        }
    }
    doc.insert(
        "durationMs".into(),
        json!((summary.duration_secs * 1000.0).round() as u64),
    );
    let mut sm = Map::new();
    sm.insert("routesTotal".into(), json!(summary.routes_total));
    sm.insert("routesReachable".into(), json!(summary.routes_reachable));
    sm.insert("totalVectors".into(), json!(summary.total_vectors));
    sm.insert("totalBlocked".into(), json!(summary.total_blocked));
    sm.insert("totalVulnerable".into(), json!(summary.total_vulnerable));
    doc.insert("summary".into(), Value::Object(sm));
    doc.insert("routes".into(), Value::Array(routes));

    let s = serde_json::to_string_pretty(&Value::Object(doc)).unwrap_or_default();
    writeln!(out, "{s}")?;
    Ok(())
}

fn resolve_target(args: &Args, cwd: &Path) -> Result<(String, String), String> {
    if let Some(url) = &args.url {
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(format!(
                "arcis scan: invalid URL scheme: {url}\n  Only http:// and https:// are supported."
            ));
        }
        return Ok((url.trim_end_matches('/').to_string(), "argv".into()));
    }
    let candidates = arcis_engine::scan::detect_target(
        cwd,
        !args.no_control_plane,
        arcis_engine::scan::DEV_PORTS,
    );
    if let Some(first) = candidates.into_iter().next() {
        return Ok((first.url, first.source));
    }
    Err("arcis scan: could not auto-detect a running server. Pass a URL explicitly.".into())
}

pub fn run(argv: &[String]) -> ExitCode {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let stderr = io::stderr();
    let mut err = stderr.lock();

    let parsed = parse_args(argv);
    let args = match parsed {
        ParseOutcome::Help => {
            let _ = print_help(&mut out);
            return ExitCode::from(0);
        }
        ParseOutcome::Err(msg) => {
            let _ = writeln!(err, "{msg}");
            return ExitCode::from(2);
        }
        ParseOutcome::Args(a) => *a,
    };

    if args.list {
        let _ = print_catalog(&mut out, args.no_color);
        return ExitCode::from(0);
    }

    let cwd = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    let (target_url, _target_source) = match resolve_target(&args, &cwd) {
        Ok(t) => t,
        Err(msg) => {
            let _ = writeln!(err, "{msg}");
            return ExitCode::from(2);
        }
    };

    // Resolve routes. Same three paths as Python.
    let routes_user_supplied = !args.routes.is_empty();
    let mut discovered_routes: Vec<DiscoveredRoute> = Vec::new();
    let routes: Vec<(String, String)> = if routes_user_supplied {
        parse_route_args(&args.routes)
    } else if args.no_discovery {
        vec![("POST".into(), "/".into())]
    } else {
        discovered_routes = discover_routes(&cwd, 1500);
        if discovered_routes.is_empty() {
            vec![("POST".into(), "/".into())]
        } else {
            discovered_routes
                .iter()
                .map(|r| (r.method.clone(), r.path.clone()))
                .collect()
        }
    };

    // Categories: pass-through; downstream uses `slug` for matching.
    let categories = args.categories.clone();

    // Default fields if user didn't pass --field.
    let fields_owned: Vec<String> = if args.fields.is_empty() {
        DEFAULT_FIELDS.iter().map(|s| (*s).to_string()).collect()
    } else {
        args.fields.clone()
    };

    let timeout = Duration::from_secs(args.timeout);

    // Build the auth config once. Parser already rejected empty/
    // whitespace-only inputs; the engine validator below is belt-and-
    // braces for any future direct API caller that bypasses the parser.
    // `--bearer` and `--cookie` compose: distinct header names, no
    // collision logic needed.
    let auth_config: Option<AuthConfig> = if args.bearer.is_some() || args.cookie.is_some() {
        let mut cfg = AuthConfig::default();
        if let Some(token) = args.bearer.as_deref() {
            match AuthConfig::with_bearer(token) {
                Ok(c) => cfg.bearer = c.bearer,
                Err(e) => {
                    let _ = writeln!(err, "arcis scan: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        if let Some(value) = args.cookie.as_deref() {
            match AuthConfig::with_cookie(value) {
                Ok(c) => cfg.cookie = c.cookie,
                Err(e) => {
                    let _ = writeln!(err, "arcis scan: {e}");
                    return ExitCode::from(2);
                }
            }
        }
        Some(cfg)
    } else {
        None
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "arcis scan: tokio runtime init failed: {e}");
            return ExitCode::from(2);
        }
    };

    let start = Instant::now();
    let results: Vec<RouteResult> = runtime.block_on(async {
        let mut out: Vec<RouteResult> = Vec::with_capacity(routes.len());
        let fields_borrow: Vec<&str> = fields_owned.iter().map(String::as_str).collect();
        for (method, path) in &routes {
            let opts = ScanOptions {
                fields: &fields_borrow,
                timeout,
                categories: categories.as_deref(),
                thorough: args.thorough,
                auth: auth_config.as_ref(),
            };
            out.push(scan_route(&target_url, method, path, &opts).await);
        }
        out
    });
    let elapsed = start.elapsed();

    let summary = summarize(&results, elapsed);

    if args.json_output {
        let _ = print_json_report(
            &mut out,
            &target_url,
            auth_config.as_ref(),
            &results,
            &summary,
        );
    } else if !args.quiet {
        let _ = print_human_report(&mut out, &target_url, &results, &summary, args.no_color);
    }

    // Discovery footnote (matches Python's tip when fallback was used).
    if !routes_user_supplied
        && discovered_routes.is_empty()
        && !args.no_discovery
        && !args.json_output
        && !args.quiet
    {
        let _ = writeln!(
            err,
            "  Tip: pass --route POST:/api/login or run from a project root with package.json / pyproject.toml / go.mod."
        );
    }

    if summary.total_vulnerable > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(input: &[&str]) -> Args {
        let argv: Vec<String> = input.iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Args(a) => *a,
            other => panic!("expected Args, got {other:?}"),
        }
    }

    #[test]
    fn defaults() {
        let a = args(&[]);
        assert!(a.url.is_none());
        assert_eq!(a.timeout, 5);
        assert!(!a.thorough);
        assert!(!a.list);
        assert!(!a.json_output);
        assert!(a.routes.is_empty());
        assert!(a.fields.is_empty());
        assert!(a.categories.is_none());
    }

    #[test]
    fn parses_url_positional() {
        let a = args(&["http://localhost:5000"]);
        assert_eq!(a.url.as_deref(), Some("http://localhost:5000"));
    }

    #[test]
    fn parses_route_flag_repeatable() {
        let a = args(&["-r", "POST:/api/login", "--route", "GET:/health"]);
        assert_eq!(a.routes, vec!["POST:/api/login", "GET:/health"]);
    }

    #[test]
    fn parses_categories_nargs_plus() {
        let a = args(&["-c", "xss", "sql", "nosql"]);
        assert_eq!(a.categories.as_deref().unwrap(), &["xss", "sql", "nosql"]);
    }

    #[test]
    fn categories_stop_at_next_flag() {
        let a = args(&["-c", "xss", "sql", "--yes"]);
        assert_eq!(a.categories.as_deref().unwrap(), &["xss", "sql"]);
        assert!(a.yes);
    }

    #[test]
    fn parses_categories_comma_separated() {
        let a = args(&["-c", "xss,sql,path"]);
        assert_eq!(a.categories.as_deref().unwrap(), &["xss", "sql", "path"]);
    }

    #[test]
    fn parses_categories_mixed_comma_and_space() {
        let a = args(&["--categories", "xss,sql", "path", "nosql, cmd"]);
        assert_eq!(
            a.categories.as_deref().unwrap(),
            &["xss", "sql", "path", "nosql", "cmd"]
        );
    }

    #[test]
    fn categories_drops_empty_comma_pieces() {
        let a = args(&["-c", "xss,,sql,"]);
        assert_eq!(a.categories.as_deref().unwrap(), &["xss", "sql"]);
    }

    #[test]
    fn parses_timeout() {
        let a = args(&["-t", "10"]);
        assert_eq!(a.timeout, 10);
    }

    #[test]
    fn rejects_non_integer_timeout() {
        let argv: Vec<String> = ["-t", "abc"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(parse_args(&argv), ParseOutcome::Err(_)));
    }

    #[test]
    fn list_flag_short_and_long() {
        assert!(args(&["-l"]).list);
        assert!(args(&["--list"]).list);
    }

    #[test]
    fn flag_only_args_compose() {
        let a = args(&[
            "--thorough",
            "--no-color",
            "--quiet",
            "--yes",
            "--no-discovery",
            "--no-control-plane",
        ]);
        assert!(a.thorough);
        assert!(a.no_color);
        assert!(a.quiet);
        assert!(a.yes);
        assert!(a.no_discovery);
        assert!(a.no_control_plane);
    }

    #[test]
    fn rejects_unknown_flag() {
        let argv: Vec<String> = ["--bogus"].iter().map(|s| s.to_string()).collect();
        assert!(matches!(parse_args(&argv), ParseOutcome::Err(_)));
    }

    #[test]
    fn rejects_double_positional() {
        let argv: Vec<String> = ["http://a", "http://b"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(matches!(parse_args(&argv), ParseOutcome::Err(_)));
    }

    #[test]
    fn parse_route_args_bare_path_defaults_to_post() {
        let r = parse_route_args(&["/api/login".into()]);
        assert_eq!(r, vec![("POST".into(), "/api/login".into())]);
    }

    #[test]
    fn parse_route_args_method_path() {
        let r = parse_route_args(&["GET:/health".into(), "post:/api/users".into()]);
        assert_eq!(
            r,
            vec![
                ("GET".into(), "/health".into()),
                ("POST".into(), "/api/users".into())
            ]
        );
    }

    #[test]
    fn parse_route_args_full_url_kept_as_post() {
        let r = parse_route_args(&["http://example.com/x".into()]);
        assert_eq!(r, vec![("POST".into(), "http://example.com/x".into())]);
    }

    /// Deliberately unique sentinels for the JSON-redaction tests below.
    /// Pinned so a substring match against the emitted JSON cannot
    /// false-positive on a hash digest, route URL, or vector label.
    const TEST_BEARER_TOKEN: &str = "arcis-test-bearer-DEADBEEF-9f3a2c";
    const TEST_COOKIE_VALUE: &str = "session=arcis-test-cookie-CAFEBABE-7e1f4d; csrf=feedface";

    #[test]
    fn parses_bearer_space_separated() {
        let a = args(&["--bearer", "foo"]);
        assert_eq!(a.bearer.as_deref(), Some("foo"));
    }

    #[test]
    fn parses_bearer_equals_inline() {
        let a = args(&["--bearer=foo"]);
        assert_eq!(a.bearer.as_deref(), Some("foo"));
    }

    #[test]
    fn bearer_empty_value_rejected() {
        let argv: Vec<String> = ["--bearer", ""].iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(e) => {
                assert!(e.contains("--bearer cannot be empty"), "got: {e}")
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn bearer_whitespace_only_rejected() {
        let argv: Vec<String> = ["--bearer", "   "].iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(e) => {
                assert!(e.contains("--bearer cannot be empty"), "got: {e}")
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn bearer_inline_equals_empty_rejected() {
        let argv: Vec<String> = ["--bearer="].iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(e) => {
                assert!(e.contains("--bearer cannot be empty"), "got: {e}")
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn json_report_includes_auth_methods_array_for_bearer_and_redacts_token() {
        let auth = AuthConfig::with_bearer(TEST_BEARER_TOKEN).unwrap();
        let summary = ScanSummary::default();
        let mut buf: Vec<u8> = Vec::new();
        print_json_report(
            &mut buf,
            "http://localhost:5000",
            Some(&auth),
            &[],
            &summary,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // Schema: `methods` is always an array (even for one entry).
        assert_eq!(v["auth"]["methods"][0], "bearer");
        assert_eq!(v["auth"]["methods"].as_array().unwrap().len(), 1);
        // Sentinel: the literal token string must NEVER appear anywhere
        // in the emitted JSON. This pins the redaction contract — users
        // pipe `--json` output to logs and CI artifacts; secrets must
        // not leak there.
        assert!(
            !s.contains(TEST_BEARER_TOKEN),
            "token leaked to JSON output: {s}"
        );
    }

    #[test]
    fn json_report_includes_auth_methods_array_for_cookie_and_redacts_value() {
        let auth = AuthConfig::with_cookie(TEST_COOKIE_VALUE).unwrap();
        let summary = ScanSummary::default();
        let mut buf: Vec<u8> = Vec::new();
        print_json_report(
            &mut buf,
            "http://localhost:5000",
            Some(&auth),
            &[],
            &summary,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["auth"]["methods"][0], "cookie");
        assert_eq!(v["auth"]["methods"].as_array().unwrap().len(), 1);
        // Cookie value sentinel must NOT appear anywhere in JSON. The
        // verbatim no-parse policy means we never extract names either.
        assert!(!s.contains(TEST_COOKIE_VALUE), "cookie value leaked: {s}");
        assert!(
            !s.contains("session="),
            "cookie name should not leak under no-parse policy: {s}"
        );
    }

    #[test]
    fn json_report_with_bearer_and_cookie_lists_both_methods_and_redacts_both() {
        // Composite path: alphabetical order pinned, both sentinels
        // checked absent.
        let auth = AuthConfig {
            bearer: Some(TEST_BEARER_TOKEN.into()),
            cookie: Some(TEST_COOKIE_VALUE.into()),
            ..Default::default()
        };
        let summary = ScanSummary::default();
        let mut buf: Vec<u8> = Vec::new();
        print_json_report(
            &mut buf,
            "http://localhost:5000",
            Some(&auth),
            &[],
            &summary,
        )
        .unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let methods = v["auth"]["methods"].as_array().unwrap();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0], "bearer");
        assert_eq!(methods[1], "cookie");
        assert!(
            !s.contains(TEST_BEARER_TOKEN),
            "bearer leaked in composite: {s}"
        );
        assert!(
            !s.contains(TEST_COOKIE_VALUE),
            "cookie leaked in composite: {s}"
        );
    }

    #[test]
    fn json_report_omits_auth_when_unauthenticated() {
        let summary = ScanSummary::default();
        let mut buf: Vec<u8> = Vec::new();
        print_json_report(&mut buf, "http://localhost:5000", None, &[], &summary).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // No-auth runs must not emit the key at all so prior
        // unauthenticated JSON output stays byte-equal.
        assert!(v.get("auth").is_none(), "got: {s}");
        assert!(!s.contains("\"auth\""), "got: {s}");
    }

    #[test]
    fn help_text_documents_bearer_redaction() {
        // The "never appears in --json" line is load-bearing for users
        // running scans in CI — it tells them piping --json to logs is
        // safe. Pin it so future help-text refactors don't drop it.
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("--bearer <token>"), "missing flag entry: {s}");
        assert!(
            s.contains("Authorization: Bearer"),
            "missing header description: {s}"
        );
        assert!(
            s.contains("Token value never appears in --json"),
            "missing bearer redaction note: {s}"
        );
    }

    #[test]
    fn help_text_documents_cookie_redaction() {
        // Parallel to the bearer pin: the redaction promise is also
        // load-bearing for --cookie. Future help-text refactors must
        // not drop either line.
        let mut buf: Vec<u8> = Vec::new();
        print_help(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("--cookie <value>"), "missing flag entry: {s}");
        assert!(
            s.contains("Send Cookie:"),
            "missing header description: {s}"
        );
        assert!(
            s.contains("Cookie value never appears in --json"),
            "missing cookie redaction note: {s}"
        );
    }

    #[test]
    fn parses_cookie_space_separated() {
        let a = args(&["--cookie", "session=abc; csrf=xyz"]);
        assert_eq!(a.cookie.as_deref(), Some("session=abc; csrf=xyz"));
    }

    #[test]
    fn parses_cookie_equals_inline() {
        let a = args(&["--cookie=session=abc"]);
        // Verbatim including the inner `=` — no further parsing.
        assert_eq!(a.cookie.as_deref(), Some("session=abc"));
    }

    #[test]
    fn cookie_empty_value_rejected() {
        let argv: Vec<String> = ["--cookie", ""].iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(e) => {
                assert!(e.contains("--cookie cannot be empty"), "got: {e}")
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn cookie_whitespace_only_rejected() {
        let argv: Vec<String> = ["--cookie", "   "].iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(e) => {
                assert!(e.contains("--cookie cannot be empty"), "got: {e}")
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn cookie_inline_equals_empty_rejected() {
        let argv: Vec<String> = ["--cookie="].iter().map(|s| s.to_string()).collect();
        match parse_args(&argv) {
            ParseOutcome::Err(e) => {
                assert!(e.contains("--cookie cannot be empty"), "got: {e}")
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn parses_bearer_and_cookie_compose() {
        let a = args(&["--bearer", "tok", "--cookie", "session=abc"]);
        assert_eq!(a.bearer.as_deref(), Some("tok"));
        assert_eq!(a.cookie.as_deref(), Some("session=abc"));
    }

    #[test]
    fn catalog_output_no_color_byte_shape() {
        let mut buf: Vec<u8> = Vec::new();
        print_catalog(&mut buf, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Sanity assertions on the byte-shape — full byte-equal parity
        // with Python is exercised in the parity harness fixture.
        assert!(s.starts_with("\n  arcis scan \u{2014} attack catalog ("));
        assert!(s.contains("(8 categories, 27 payloads)"));
        assert!(s.contains("\n  XSS  (xss)\n"));
        assert!(s.contains("\n  SQL Injection  (sqlinjection)\n"));
        assert!(s.contains("\n  NoSQL Injection  (nosqlinjection)\n"));
        assert!(s.contains("\n    script tag         <script>alert(1)</script>\n"));
        assert!(s.contains("\n  Default fields tried (--field overrides)\n"));
        assert!(s.contains(
            "    q, query, search, input, name, username, email, data, value, text, id\n"
        ));
    }

    #[test]
    fn catalog_label_padding_pads_short_labels_to_18() {
        let mut buf: Vec<u8> = Vec::new();
        print_catalog(&mut buf, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // "OR bypass" = 9 chars, padded to 18 = 9 trailing spaces.
        assert!(s.contains("    OR bypass          ' OR '1'='1' --\n"));
        // "wildcard" = 8 chars, padded to 18.
        assert!(s.contains("    wildcard           *)(uid=*))(|(uid=*\n"));
    }

    #[test]
    fn catalog_with_color_emits_ansi() {
        let mut buf: Vec<u8> = Vec::new();
        print_catalog(&mut buf, false).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains(BOLD));
        assert!(s.contains(RESET));
        assert!(s.contains(DIM));
        assert!(s.contains(CYAN));
    }

    fn fixture_route() -> RouteResult {
        use arcis_engine::scan::VectorResult;
        RouteResult {
            method: "POST".into(),
            path: "/api/login".into(),
            reachable: true,
            error: None,
            field: "username".into(),
            vectors: vec![
                VectorResult {
                    category: "XSS".into(),
                    label: "script tag".into(),
                    payload: "<script>alert(1)</script>".into(),
                    status: 200,
                    blocked: false,
                    note: "reflected in response (200)".into(),
                },
                VectorResult {
                    category: "SQL Injection".into(),
                    label: "OR bypass".into(),
                    payload: "' OR '1'='1' --".into(),
                    status: 400,
                    blocked: true,
                    note: "rejected (400)".into(),
                },
            ],
        }
    }

    #[test]
    fn human_report_includes_curl_for_vulnerable_only() {
        let rr = fixture_route();
        let summary = summarize(std::slice::from_ref(&rr), Duration::from_millis(50));
        let mut buf: Vec<u8> = Vec::new();
        print_human_report(&mut buf, "http://localhost:5000", &[rr], &summary, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        // Vulnerable XSS finding should be followed by a curl line.
        assert!(
            s.contains("curl -fsSL -X POST 'http://localhost:5000/api/login'"),
            "expected curl reproducer for vulnerable finding, got:\n{s}"
        );
        // Blocked SQL finding should NOT have a curl line for it.
        // We check that the OR-bypass payload does not appear inside any
        // curl command — it would only show up if format_curl ran.
        assert!(
            !s.contains("' OR '1"),
            "blocked findings should not emit a curl line, got:\n{s}"
        );
    }

    #[test]
    fn json_report_includes_curl_per_vector_and_field_per_route() {
        let rr = fixture_route();
        let summary = summarize(std::slice::from_ref(&rr), Duration::from_millis(50));
        let mut buf: Vec<u8> = Vec::new();
        print_json_report(&mut buf, "http://localhost:5000", None, &[rr], &summary).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let route0 = &v["routes"][0];
        assert_eq!(route0["field"], "username");
        let vectors = route0["vectors"].as_array().unwrap();
        // Both blocked and vulnerable vectors carry a curl reproducer in JSON.
        assert_eq!(vectors.len(), 2);
        for vec in vectors {
            let curl = vec["curl"].as_str().unwrap();
            assert!(curl.starts_with("curl -fsSL"), "curl prefix: {curl}");
        }
        // Vulnerable XSS payload appears URL-encoded INSIDE the JSON body
        // of its own POST curl command (since method=POST). Confirm the
        // method + path land correctly.
        let xss_curl = vectors[0]["curl"].as_str().unwrap();
        assert!(xss_curl.contains("-X POST"), "got: {xss_curl}");
        assert!(xss_curl.contains("/api/login"), "got: {xss_curl}");
    }
}
