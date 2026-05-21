//! `arcis` — native Rust CLI dispatcher.
//!
//! `scan / audit / sca` are full ports of the legacy Python CLI surface
//! plus the Phase B/C ergonomics added during the v1.5 cycle
//! (`--baseline`, `--jobs`, `--osv`, `--sbom`, `--fail-on`, `--bearer`,
//! `--cookie`, `--login`, `--csrf-from`, `--cancel-on`, suppress
//! comments, `.arcisignore`, per-finding curl reproducer, etc.).
//!
//! `update` is still a stub — see `stub.rs`. Self-update can wait until
//! there's a real signal from users. Until then the upgrade path is
//! `npm install -g @arcis/cli@latest`.
//!
//! Output strategy: rich-style text on TTY, plain text on pipes / CI.
//! Plain text is what the parity harness compares against, byte-for-byte
//! with the legacy Python CLI's non-TTY output.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

mod audit;
mod catalog;
mod sca;
mod scan;
mod stub;
mod welcome;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Best-effort terminal column count without adding a dep.
///
/// Reads `$COLUMNS` if exported (most shells set this on interactive
/// sessions); otherwise returns 120 as a reasonable default that's
/// wider than the welcome panel's minimum. If the welcome screen
/// renders wider than the real terminal, lines wrap and the user sees
/// a slightly mangled box. That's acceptable; the catalog fallback
/// only triggers below 80 cols and we trust users to have a normal
/// terminal width.
fn terminal_cols() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(120)
}

fn main() -> ExitCode {
    // Eager schema check so a build with a stale embedded threat DB fails
    // loud on the very first command instead of silently producing wrong
    // findings later. Behavior matches `_load_threat_db()` in the Python
    // CLI which warns on parse failure and falls back to empty.
    if let Err(err) = arcis_engine::check_embedded_schemas() {
        eprintln!("arcis: embedded data version mismatch: {err}");
        return ExitCode::from(2);
    }

    let argv: Vec<String> = std::env::args().collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // No args: pick welcome screen (TTY) or plain catalog (pipe/CI).
    // Welcome screen requires a wide-enough terminal; we use the
    // catalog as a graceful fallback when the user has a narrow window
    // or has piped stdout. This keeps byte-equal parity with the
    // Python CLI on non-TTY paths, where parity tests run.
    if argv.len() < 2 {
        let stdout_is_tty = std::io::stdout().is_terminal();
        let cols = terminal_cols();
        if stdout_is_tty && !welcome::too_narrow(cols) {
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| String::from("."));
            let _ = welcome::print(&mut out, VERSION, &cwd);
        } else {
            let _ = catalog::print(&mut out, VERSION, /* verbose = */ false);
            let _ = writeln!(out);
        }
        return ExitCode::from(0);
    }

    let arg = argv[1].as_str();

    match arg {
        // Discovery flags. Python prints the same catalog with verbose
        // examples, plus a one-line trailer for --help.
        "--list" | "-l" => {
            let _ = catalog::print(&mut out, VERSION, /* verbose = */ true);
            let _ = writeln!(out);
            ExitCode::from(0)
        }
        "-h" | "--help" => {
            let _ = catalog::print(&mut out, VERSION, /* verbose = */ false);
            let _ = writeln!(out, "  Run 'arcis <command> --help' for full flags.");
            let _ = writeln!(out);
            ExitCode::from(0)
        }
        "-V" | "--version" => {
            let _ = writeln!(out, "{VERSION}");
            ExitCode::from(0)
        }

        // Phase B1 / B2 / B3: sca, audit, scan are ported. Only `update`
        // still falls through to the Python CLI stub.
        "sca" => sca::run(&argv[2..]),
        "audit" => audit::run(&argv[2..]),
        "scan" => scan::run(&argv[2..]),
        "update" => stub::dispatch(&argv[1..]),

        // Unknown command. Match Python's error style + exit 1. Python
        // uses `console.print` (stdout) for this message, so stay on
        // stdout for parity. Both implementations should arguably move to
        // stderr later — when that happens, flip both at once.
        unknown => {
            let _ = writeln!(out, "arcis: unknown command '{unknown}'");
            let _ = writeln!(out, "Run 'arcis --list' for available commands.");
            ExitCode::from(1)
        }
    }
}
