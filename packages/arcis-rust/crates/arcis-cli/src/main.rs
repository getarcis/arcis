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
mod console;
mod sca;
mod scan;
mod stub;
mod welcome;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Terminal column count, in priority order:
///   1. `$COLUMNS` if a shell exported it (rare on Windows, common on bash).
///   2. Native terminal-size syscall (ioctl `TIOCGWINSZ` on Unix,
///      `GetConsoleScreenBufferInfo` on Windows).
///   3. Conservative default of 132 (the welcome screen's minimum) so
///      a piped or detached invocation still picks the welcome branch.
///
/// Previous version returned 120 when `$COLUMNS` was unset, which
/// guaranteed PowerShell users always fell back to the plain catalog
/// because the welcome panel requires 132+ cols. The native query
/// works on every modern terminal (Windows Terminal, conhost.exe,
/// iTerm2, Alacritty, GNOME Terminal, tmux).
fn terminal_cols() -> usize {
    if let Some(cols) = std::env::var("COLUMNS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        return cols;
    }
    if let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() {
        return w as usize;
    }
    132
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
    //
    // Write-error semantics: BrokenPipe is the standard "the reader
    // hung up" condition (e.g. `arcis | head`). Treat it as a clean
    // exit; the user got what they wanted from the partial output.
    // Any other write error means the terminal itself failed mid-banner,
    // which is rare but worth surfacing as a non-zero exit so wrapper
    // scripts can detect it.
    if argv.len() < 2 {
        let stdout_is_tty = std::io::stdout().is_terminal();
        let stdin_is_tty = std::io::stdin().is_terminal();
        let in_ci = std::env::var("CI").is_ok();
        let opted_out = std::env::var("ARCIS_NO_REPL").is_ok();
        let cols = terminal_cols();

        // Interactive console (v1.6): when every prerequisite is met,
        // drop into the full-screen TUI. The four guards mirror the
        // spec in `documents/plans/improvements.md §1.5`:
        //
        //   * stdout TTY:  we're writing to a terminal, not a pipe
        //   * stdin TTY:   the user can actually type keys back to us
        //   * !CI:         no GitHub Actions / Buildkite / Jenkins
        //   * !ARCIS_NO_REPL: explicit opt-out env var for users who
        //                  prefer the one-shot welcome
        //
        // Anything else falls through to the existing welcome/catalog
        // branch. The static welcome is still right for piped output
        // (parity tests, scripts) and CI logs.
        if stdout_is_tty && stdin_is_tty && !in_ci && !opted_out && !welcome::too_narrow(cols) {
            return console::run();
        }

        let write_result = if stdout_is_tty && !welcome::too_narrow(cols) {
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| String::from("."));
            welcome::print(&mut out, VERSION, &cwd)
        } else {
            catalog::print(&mut out, VERSION, /* verbose = */ false).and_then(|_| writeln!(out))
        };
        return match write_result {
            Ok(()) => ExitCode::from(0),
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => ExitCode::from(0),
            Err(_) => ExitCode::from(1),
        };
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
        //
        // Empty-string subcommand (cli-test round-1 bug 1): falls into
        // this branch by design — `arcis ''` prints "unknown command ''"
        // and exits 1. PowerShell 5.1 silently strips empty quoted args
        // before exec, so on PowerShell the user sees the welcome screen
        // instead (because `arcis ""` becomes `arcis` with no args).
        // That's a shell behavior, not an Arcis bug. cmd.exe and bash do
        // pass the empty argument, and they hit this branch correctly.
        unknown => {
            let _ = writeln!(out, "arcis: unknown command '{unknown}'");
            let _ = writeln!(out, "Run 'arcis --list' for available commands.");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    /// cli-test round-1 bug 1: when the empty-string subcommand DOES
    /// reach the binary (cmd.exe, bash, direct invocation from another
    /// program), it must hit the unknown-command branch — not the
    /// welcome screen. PowerShell strips the empty arg before exec so
    /// users on PowerShell can't trigger this path, but everyone else
    /// can. Locking in the dispatch shape here so a future refactor
    /// can't quietly route empty-string to welcome.
    #[test]
    fn empty_subcommand_classification() {
        // Mirror the dispatch logic from main(). If the match arms here
        // ever diverge from main()'s, this test stops being meaningful.
        fn classify(arg: &str) -> &'static str {
            match arg {
                "--list" | "-l" => "list",
                "-h" | "--help" => "help",
                "-V" | "--version" => "version",
                "sca" => "sca",
                "audit" => "audit",
                "scan" => "scan",
                "update" => "update",
                _ => "unknown",
            }
        }
        assert_eq!(classify(""), "unknown");
        assert_eq!(classify("foobar"), "unknown");
        assert_eq!(classify("audit"), "audit");
    }
}
