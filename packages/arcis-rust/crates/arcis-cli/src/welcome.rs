//! Two-panel welcome screen for `arcis` no-args on TTY.
//!
//! Shows on `arcis` (no arguments) when stdout is a TTY. Inspired by
//! Claude Code's first-screen layout: left panel for identity (version,
//! cwd), right panel for tips + commands + "what's new". Non-TTY (pipes,
//! CI) and `--help` / `--list` continue to use the plain catalog in
//! `catalog.rs` so byte-equal parity with the Python harness holds.
//!
//! Width: the panels target ~120 columns total. If the terminal is
//! narrower than 80 columns, fall back to the plain catalog. Wider than
//! 120 means we just leave extra blank on the right; we don't stretch
//! panels because hand-stretched panels look worse than fixed-width ones.

use std::io::{self, Write};

/// Bullet entries shown in the right-side "Tips" panel. Kept short so
/// they fit in ~70 columns minus padding.
struct Tip {
    cmd: &'static str,
    note: &'static str,
}

const TIPS: &[Tip] = &[
    Tip {
        cmd: "arcis audit .",
        note: "Static-scan your code for unsafe patterns",
    },
    Tip {
        cmd: "arcis sca .",
        note: "Match deps against supply-chain threat DB",
    },
    Tip {
        cmd: "arcis scan http://localhost:3000",
        note: "Probe a live endpoint for vulnerabilities",
    },
    Tip {
        cmd: "arcis --help",
        note: "Full command reference + flags",
    },
];

/// Bullet entries shown in the "What's new" panel. Bump when the CLI
/// gets new flags / commands worth surfacing on every cold start.
const WHATS_NEW: &[&str] = &[
    "Two-panel welcome screen on `arcis` no-args (TTY only).",
    "Python SDK shim: `pip install arcis` exposes `arcis` again.",
    "Daily cli-install-smoke workflow catches publish-channel breakage.",
    "Auto-published from publish.yml on every nwl to main release.",
];

const LEFT_WIDTH: usize = 42;
const RIGHT_WIDTH: usize = 72;

/// Print the welcome screen. `version` is the CLI binary version; `cwd`
/// is the directory the user invoked `arcis` from (rendered truncated
/// if it would overflow the left panel).
pub fn print<W: Write>(w: &mut W, version: &str, cwd: &str) -> io::Result<()> {
    let title_left = format!(" Arcis CLI v{version} ");
    let title_tips = " Tips for getting started ";
    let title_news = " What's new ";

    // Top border with the embedded titles.
    writeln!(
        w,
        "{}  {}",
        top_border(LEFT_WIDTH, &title_left),
        top_border(RIGHT_WIDTH, title_tips)
    )?;

    // Render row-by-row. The two panels are independent vertically so
    // we compute the height of each and pad the shorter one.
    let left_rows = build_left_rows(version, cwd);
    let mut right_rows: Vec<String> = Vec::new();
    push_blank(&mut right_rows);
    for tip in TIPS {
        push_tip(&mut right_rows, tip.cmd, tip.note);
    }
    push_blank(&mut right_rows);
    // Right panel transitions to "What's new" with an inline title.
    right_rows.push(format!(
        "{}{}",
        section_title(title_news),
        " ".repeat(RIGHT_WIDTH.saturating_sub(title_news.len()).saturating_sub(2))
    ));
    push_blank(&mut right_rows);
    for note in WHATS_NEW {
        push_news(&mut right_rows, note);
    }
    push_blank(&mut right_rows);

    let height = left_rows.len().max(right_rows.len());
    for i in 0..height {
        let left = left_rows
            .get(i)
            .map(String::as_str)
            .unwrap_or("");
        let right = right_rows
            .get(i)
            .map(String::as_str)
            .unwrap_or("");
        let left_padded = format!("|{}|", pad_inside(left, LEFT_WIDTH - 2));
        let right_padded = format!("|{}|", pad_inside(right, RIGHT_WIDTH - 2));
        writeln!(w, "{}  {}", left_padded, right_padded)?;
    }

    writeln!(
        w,
        "{}  {}",
        bottom_border(LEFT_WIDTH),
        bottom_border(RIGHT_WIDTH)
    )?;
    writeln!(w)?;
    writeln!(w, "  Run 'arcis --help' for the full reference.")?;
    writeln!(w, "  Issues: https://github.com/Gagancm/arcis/issues")?;
    Ok(())
}

/// Returns true when the terminal is too narrow to render the welcome
/// nicely. Caller falls back to the plain catalog when true.
pub fn too_narrow(cols: usize) -> bool {
    cols < (LEFT_WIDTH + RIGHT_WIDTH + 4)
}

fn build_left_rows(version: &str, cwd: &str) -> Vec<String> {
    let mut rows: Vec<String> = Vec::new();
    push_blank(&mut rows);
    rows.push(center("Welcome to Arcis", LEFT_WIDTH - 2));
    push_blank(&mut rows);
    // Compact ASCII shield as the visual anchor. Box-drawing characters
    // skipped on purpose so terminals without Unicode font support
    // still render correctly.
    rows.push(center("___", LEFT_WIDTH - 2));
    rows.push(center("/ A \\", LEFT_WIDTH - 2));
    rows.push(center("\\___/", LEFT_WIDTH - 2));
    push_blank(&mut rows);
    rows.push(center(&format!("v{version} (Rust)"), LEFT_WIDTH - 2));
    push_blank(&mut rows);
    let cwd_short = truncate_cwd(cwd, LEFT_WIDTH - 4);
    rows.push(center(&cwd_short, LEFT_WIDTH - 2));
    push_blank(&mut rows);
    push_blank(&mut rows);
    rows
}

fn truncate_cwd(cwd: &str, width: usize) -> String {
    if cwd.len() <= width {
        return cwd.to_string();
    }
    // Show the tail of the path with ellipsis. More useful than the head
    // because the relevant info (project name) is usually at the end.
    let keep = width.saturating_sub(3);
    let start = cwd.len().saturating_sub(keep);
    format!("...{}", &cwd[start..])
}

fn push_blank(rows: &mut Vec<String>) {
    rows.push(String::new());
}

fn push_tip(rows: &mut Vec<String>, cmd: &str, note: &str) {
    // Two-line tip: command (highlighted) then dim explanation.
    rows.push(format!("  {cmd}"));
    rows.push(format!("    {note}"));
    push_blank(rows);
}

fn push_news(rows: &mut Vec<String>, note: &str) {
    rows.push(format!("  - {note}"));
}

fn section_title(title: &str) -> String {
    // A subtle inline divider so the right panel reads as two stacked
    // sections (Tips then What's new) without needing a second box.
    format!("  {title}")
}

/// Left-pad and right-pad a row to exactly `width` inner columns. Used
/// for the contents between the panel's left/right border characters.
fn pad_inside(s: &str, width: usize) -> String {
    if s.len() >= width {
        // Truncate at character boundary; we control the inputs above
        // so this should never fire in practice.
        return s[..width.min(s.len())].to_string();
    }
    let pad = " ".repeat(width - s.len());
    format!("{s}{pad}")
}

fn center(s: &str, width: usize) -> String {
    if s.len() >= width {
        return s.to_string();
    }
    let total = width - s.len();
    let left = total / 2;
    let right = total - left;
    format!("{}{}{}", " ".repeat(left), s, " ".repeat(right))
}

fn top_border(width: usize, title: &str) -> String {
    // Plain ASCII border so it renders on every terminal/font combination.
    // `+- title --------+` style; mimics the rounded look without using
    // Unicode box-drawing chars (which fail on default Windows cmd.exe
    // when chcp != 65001).
    let mut bar = String::from(",");
    bar.push('-');
    bar.push_str(title);
    let used = bar.len();
    let pad = width.saturating_sub(used).saturating_sub(1);
    for _ in 0..pad {
        bar.push('-');
    }
    bar.push('.');
    bar
}

fn bottom_border(width: usize) -> String {
    let mut bar = String::from("'");
    for _ in 1..(width - 1) {
        bar.push('-');
    }
    bar.push('\'');
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(version: &str, cwd: &str) -> String {
        let mut buf = Vec::new();
        print(&mut buf, version, cwd).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn shows_version_and_label() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("Arcis CLI v1.0.1"));
        assert!(out.contains("v1.0.1 (Rust)"));
    }

    #[test]
    fn shows_three_main_commands() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("arcis audit ."));
        assert!(out.contains("arcis sca ."));
        assert!(out.contains("arcis scan"));
    }

    #[test]
    fn shows_tips_panel_title() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("Tips for getting started"));
    }

    #[test]
    fn shows_whats_new_section() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("What's new"));
    }

    #[test]
    fn shows_short_cwd_unchanged() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("/tmp/proj"));
    }

    #[test]
    fn truncates_long_cwd_to_tail() {
        let long = "/a/very/long/path/that/way/exceeds/the/left/panel/width/projectname";
        let out = render("1.0.1", long);
        // Tail (project name) preserved
        assert!(out.contains("projectname"));
        // Ellipsis present
        assert!(out.contains("..."));
    }

    #[test]
    fn too_narrow_threshold() {
        assert!(too_narrow(80));
        assert!(!too_narrow(120));
        assert!(!too_narrow(160));
    }

    #[test]
    fn truncate_cwd_returns_input_when_short() {
        assert_eq!(truncate_cwd("/short", 40), "/short");
    }

    #[test]
    fn truncate_cwd_keeps_tail() {
        let result = truncate_cwd("/a/very/long/path/projectname", 20);
        assert!(result.ends_with("projectname"));
        assert!(result.starts_with("..."));
    }
}
