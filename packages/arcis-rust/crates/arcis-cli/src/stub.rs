//! Subcommand stubs.
//!
//! Phase A ships these so `arcis scan / audit / sca / update` exit cleanly
//! and tell the user where to look while the Rust port is in flight.
//! Each stub points at `documents/plans/rust-cli.md` and returns exit 2,
//! matching the Python "nothing scannable" exit convention so CI scripts
//! can pre-detect "this isn't ported yet" without parsing stdout.

use std::process::ExitCode;

pub fn dispatch(args: &[String]) -> ExitCode {
    let cmd = args.first().map_or("?", String::as_str);
    eprintln!("arcis: '{cmd}' is not yet ported to the Rust CLI.");
    eprintln!("       The Python CLI still ships every command. Run:");
    eprintln!("           pip install arcis");
    eprintln!("       Migration plan: documents/plans/rust-cli.md");
    ExitCode::from(2)
}
