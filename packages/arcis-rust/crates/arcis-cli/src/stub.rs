//! Subcommand stubs.
//!
//! Reserved for commands that haven't been ported to the native Rust
//! binary yet (currently just `arcis update`). The stub exits with code
//! 2 (matching Python's "nothing scannable" convention) so CI scripts
//! can pre-detect "not implemented" without parsing stdout.

use std::process::ExitCode;

pub fn dispatch(args: &[String]) -> ExitCode {
    let cmd = args.first().map_or("?", String::as_str);
    eprintln!("arcis: '{cmd}' is not yet implemented in this CLI build.");
    eprintln!("       Upgrade to the latest CLI to pick up newly-ported");
    eprintln!("       commands:");
    eprintln!("           npm install -g @arcis/cli@latest");
    ExitCode::from(2)
}
