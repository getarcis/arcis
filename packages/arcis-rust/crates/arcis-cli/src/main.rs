//! `arcis` — native Rust CLI dispatcher.
//!
//! Phase A scope: bootstraps the binary surface and validates the parity
//! harness end-to-end. The four subcommands (scan / audit / sca / update)
//! are stubs that print a "Phase B" message; the real ports land branch
//! by branch as the per-command parity tests turn green.
//!
//! Output strategy: plain text only in Phase A. Color / spinner work
//! lands when the rich-output side of `audit.py` ports across (Phase B).
//! Plain text is what the parity harness compares against, and what the
//! Python CLI emits on non-TTY anyway, so this is byte-for-byte alignable.

use std::io::Write;
use std::process::ExitCode;

mod audit;
mod catalog;
mod sca;
mod scan;
mod stub;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

    // No args: print catalog (matches Python's len(sys.argv) < 2 path on
    // non-TTY, plus the dispatcher in arcis/cli/__init__.py).
    if argv.len() < 2 {
        let _ = catalog::print(&mut out, VERSION, /* verbose = */ false);
        let _ = writeln!(out);
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
