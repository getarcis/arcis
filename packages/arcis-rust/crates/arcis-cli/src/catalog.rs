//! Catalog renderer for `arcis` (no args), `arcis --help`, and
//! `arcis --list`. Plain-text only; matches the layout produced by
//! `_print_catalog` in `packages/arcis-python/arcis/cli/__init__.py` when
//! rich strips ANSI on non-TTY.
//!
//! The exact byte layout is held under test by the parity harness:
//! tests/parity/run.py compares this output against the Python CLI's
//! output on the same arguments.

use std::io::{self, Write};

/// One row in the catalog: command name, one-line description, an example
/// line shown only when the user passed `--list` (verbose mode).
struct Row {
    name: &'static str,
    desc: &'static str,
    example: &'static str,
}

const COMMANDS: &[Row] = &[
    Row {
        name: "scan",
        desc: "Send live attack payloads to a running app and report which got through.",
        example: "arcis scan http://localhost:8000 --route POST:/echo --field q",
    },
    Row {
        name: "audit",
        desc: "Static-analyse Python / JS / TS source for unsafe patterns.",
        example: "arcis audit .",
    },
    Row {
        name: "sca",
        desc: "Match installed dependencies against the supply-chain threat database.",
        example: "arcis sca .",
    },
    Row {
        name: "update",
        desc: "Check PyPI for a newer Arcis release.",
        example: "arcis update --apply",
    },
];

/// Pad `s` on the right with spaces up to `width`. Matches Python's
/// `str.ljust(width)`. The format spec falls through to the original
/// string when `s.len() >= width`, preserving Python's "no truncation"
/// behavior.
fn ljust(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

/// Render the catalog. `verbose=true` matches the Python `--list` path —
/// each command row is followed by a dim example line.
pub fn print<W: Write>(w: &mut W, version: &str, verbose: bool) -> io::Result<()> {
    writeln!(w)?;
    writeln!(w, "  Arcis  v{version}")?;
    writeln!(
        w,
        "  Security middleware + scanners for Node, Python, Go."
    )?;
    writeln!(w)?;
    writeln!(w, "  Commands")?;
    for row in COMMANDS {
        writeln!(w, "    {} {}", ljust(row.name, 8), row.desc)?;
        if verbose {
            writeln!(w, "             {}", row.example)?;
        }
    }
    writeln!(w)?;
    writeln!(w, "  Discovery")?;
    writeln!(
        w,
        "    {}   Show this catalog (verbose, with examples).",
        ljust("--list", 8)
    )?;
    writeln!(
        w,
        "    {}  List what that command covers (categories / rules / threats).",
        ljust("<cmd> --list", 14)
    )?;
    writeln!(
        w,
        "    {}  Show full flags for that command.",
        ljust("<cmd> --help", 14)
    )?;
    writeln!(w)?;
    writeln!(w, "  Quick test (run all three from your project root)")?;
    writeln!(
        w,
        "    arcis sca .  &&  arcis audit .  &&  arcis scan http://localhost:8000 \\"
    )?;
    writeln!(w, "        --route POST:/echo --field q --categories xss")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(verbose: bool) -> String {
        let mut buf = Vec::new();
        print(&mut buf, "9.9.9", verbose).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn includes_all_subcommand_names() {
        let out = render(false);
        assert!(out.contains("scan"));
        assert!(out.contains("audit"));
        assert!(out.contains("sca"));
        assert!(out.contains("update"));
    }

    #[test]
    fn version_appears_after_arcis_label() {
        let out = render(false);
        assert!(out.contains("Arcis  v9.9.9"));
    }

    #[test]
    fn verbose_includes_example_lines() {
        let out = render(true);
        assert!(out.contains("arcis scan http"));
        assert!(out.contains("arcis audit ."));
        assert!(out.contains("arcis sca ."));
    }

    #[test]
    fn non_verbose_omits_example_lines() {
        let out = render(false);
        assert!(!out.contains("arcis scan http://localhost:8000 --route"));
    }

    #[test]
    fn ljust_pads_short_strings() {
        assert_eq!(ljust("scan", 8), "scan    ");
        assert_eq!(ljust("update", 8), "update  ");
        assert_eq!(ljust("--list", 8), "--list  ");
    }

    #[test]
    fn ljust_returns_input_when_too_long() {
        assert_eq!(ljust("verylongname", 4), "verylongname");
    }
}
