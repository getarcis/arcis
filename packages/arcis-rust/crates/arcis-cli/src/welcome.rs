//! Claude-Code-shaped welcome screen for `arcis` no-args on TTY.
//!
//! Layout: a single unified rounded box with the title embedded in the
//! top border, an internal vertical divider, and two side-by-side
//! panels. Left panel carries identity (mascot, version, cwd). Right
//! panel carries Tips + What's new with colored section headers.
//!
//! Non-TTY paths (pipes, CI, redirects, narrow terminals) keep the
//! plain catalog so byte-equal parity with the Python harness holds.

use std::io::{self, Write};

// Arcis Emerald #00996D, the brand color used on the website + docs
// per `documents/arcis-brand.md`. The dashboard uses Signal Orange
// #FF5300 instead; CLI is marketing-surface so it picks emerald.
// Encoded as 24-bit ANSI true color. Modern terminals (Windows
// Terminal, iTerm2, Alacritty, all modern Linux terminals) support
// this. Older Windows cmd.exe before Win10 1607 may render the
// escape as literal text, but we only emit this on TTY, and the
// user explicitly invoked an interactive command. Anyone hitting
// that edge case can pipe to `cat` or set NO_COLOR.
const EMERALD: &str = "\x1b[38;2;0;153;109m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

// Box character set. Rounded corners + thin lines mirrors Claude Code.
const TL: &str = "\u{256D}"; // ╭
const TR: &str = "\u{256E}"; // ╮
const BL: &str = "\u{2570}"; // ╰
const BR: &str = "\u{256F}"; // ╯
const V: &str = "\u{2502}"; // │
const H: &str = "\u{2500}"; // ─
const TEE_R: &str = "\u{251C}"; // ├   (full-width footer separator left tee)
const TEE_L: &str = "\u{2524}"; // ┤   (right tee)

/// Total width in display columns. 130 fits comfortably in a 144-col
/// terminal (modern default for most editors / wide terminals).
const TOTAL_WIDTH: usize = 130;

/// Inner content width of the left panel (excludes border + 1-col pad
/// on each side).
const LEFT_INNER: usize = 34;

/// Inner content width of the right panel. Computed as TOTAL_WIDTH (130)
/// minus the fixed structural columns: 2 borders, 4 padding spaces, 1
/// divider, and LEFT_INNER (34). Leaves 89 columns for right-side text.
const RIGHT_INNER: usize = 89;

/// Terminals narrower than this fall back to the catalog. We need at
/// least TOTAL_WIDTH plus a tiny margin so the right edge doesn't
/// hug the terminal edge.
const MIN_COLS: usize = TOTAL_WIDTH + 2;

pub fn too_narrow(cols: usize) -> bool {
    cols < MIN_COLS
}

/// Render the welcome screen. Caller decides TTY-ness; this just
/// writes the formatted output. Shape:
///
/// ```text
/// ╭─ Arcis CLI vX.Y.Z ─────────────────────────────────╮
/// │ left identity │ right command sections             │
/// │ (welcome,     │  Tips for getting started          │
/// │  mascot,      │  More commands                     │
/// │  version,     │  Available Adapters                │
/// │  cwd)         │    Upgrade hint                    │
/// ├──────────────────────────────────────────────────── ┤
/// │ Type 'arcis --help' for commands, or run ...        │
/// ╰────────────────────────────────────────────────────╯
/// ──────────────────────────────────────────────────────  ← prompt area
///   |                                                       (line / cursor /
/// ──────────────────────────────────────────────────────     line — matches
///                                                            v1 + V2 design)
/// ```
pub fn print<W: Write>(w: &mut W, version: &str, cwd: &str) -> io::Result<()> {
    let title = format!(" Arcis CLI v{version} ");
    writeln!(w, "{}", top_border(&title))?;

    let left = build_left(version, cwd);
    let right = build_right();
    let rows = left.len().max(right.len());

    for i in 0..rows {
        let l = left.get(i).map(String::as_str).unwrap_or("");
        let r = right.get(i).map(String::as_str).unwrap_or("");
        render_row(w, l, r)?;
    }

    // Full-width separator between the two-column body and the centered
    // footer hint. Same line weight as the rest of the frame; the
    // vertical divider does NOT continue through it (the row below is
    // a single-column footer, not two columns).
    writeln!(w, "{}", in_box_separator())?;
    let hint = "Type 'arcis --help' for commands, or run 'arcis audit .' to start scanning.";
    render_full_width_row(w, &format!("{DIM}{hint}{RESET}"))?;

    writeln!(w, "{}", bottom_border())?;

    // Prompt area below the box. Matches the V2 design (rendered HTML
    // mockup at `cladue desing/welcome_screen_v2.html`): single
    // emerald rule, one row of prompt space with a cursor `|`, second
    // emerald rule. After this the user's shell prompt takes over.
    print_prompt_area(w)?;
    Ok(())
}

fn top_border(title: &str) -> String {
    // ╭─ Arcis CLI vX.Y.Z ────────────────────────╮
    // The title sits 2 cols in from the left corner. The rest of the
    // top is filled with horizontal lines until the right corner.
    let mut s = String::new();
    s.push_str(EMERALD);
    s.push_str(TL);
    s.push_str(H);
    s.push_str(title);
    let used_cols = 1 + 1 + visible_cols(title);
    let remaining = TOTAL_WIDTH.saturating_sub(used_cols).saturating_sub(1);
    for _ in 0..remaining {
        s.push_str(H);
    }
    s.push_str(TR);
    s.push_str(RESET);
    s
}

fn bottom_border() -> String {
    let mut s = String::new();
    s.push_str(EMERALD);
    s.push_str(BL);
    for _ in 0..(TOTAL_WIDTH - 2) {
        s.push_str(H);
    }
    s.push_str(BR);
    s.push_str(RESET);
    s
}

/// Full-width separator inside the box. Used between the two-column
/// body and the single-column footer hint. The vertical divider that
/// runs through the body rows DOES NOT continue through this line —
/// it ends at the row above. Visually:
///
/// ```text
/// │ left │ right    │
/// ├──────────────────┤   ← in_box_separator
/// │ centered footer │
/// ```
fn in_box_separator() -> String {
    let mut s = String::new();
    s.push_str(EMERALD);
    s.push_str(TEE_R);
    for _ in 0..(TOTAL_WIDTH - 2) {
        s.push_str(H);
    }
    s.push_str(TEE_L);
    s.push_str(RESET);
    s
}

fn render_row<W: Write>(w: &mut W, left: &str, right: &str) -> io::Result<()> {
    let left_padded = pad(left, LEFT_INNER);
    let right_padded = pad(right, RIGHT_INNER);
    // Format: │ <left 34 cols> │ <right 89 cols> │
    writeln!(
        w,
        "{O}{V}{R} {l} {O}{V}{R} {r} {O}{V}{R}",
        O = EMERALD,
        V = V,
        R = RESET,
        l = left_padded,
        r = right_padded
    )
}

/// Render a single-column full-width row (used for the centered
/// footer hint after `in_box_separator`). Inner width is TOTAL_WIDTH
/// minus the two border columns and the surrounding 1-col padding on
/// each side.
fn render_full_width_row<W: Write>(w: &mut W, content: &str) -> io::Result<()> {
    let inner = TOTAL_WIDTH - 4; // 2 borders + 2 padding spaces
    let padded = center(content, inner);
    writeln!(
        w,
        "{O}{V}{R} {p} {O}{V}{R}",
        O = EMERALD,
        V = V,
        R = RESET,
        p = padded
    )
}

/// Prompt area below the box: emerald horizontal rule, one row of
/// prompt space with a `|` cursor marker, second emerald horizontal
/// rule. After this the user's shell prompt takes over on the next
/// line. Matches the V2 mockup design (HTML preview at
/// `cladue desing/welcome_screen_v2.html`).
fn print_prompt_area<W: Write>(w: &mut W) -> io::Result<()> {
    let line = format!("{EMERALD}{}{RESET}", H.repeat(TOTAL_WIDTH));
    writeln!(w, "{line}")?;
    writeln!(w, "  |")?;
    writeln!(w, "{line}")?;
    Ok(())
}

fn build_left(version: &str, cwd: &str) -> Vec<String> {
    let mut rows = Vec::new();
    rows.push(String::new());
    rows.push(center("Welcome to Arcis", LEFT_INNER));
    rows.push(String::new());
    // Arcis burst mascot. Five rows of radial spokes around a dense
    // center mass, approximating the 7-petal sunburst from
    // `cladue desing/exports/arcis-burst-emerald.svg`. Uses U+2572 ╲
    // and U+2571 ╱ (heavy box-drawing diagonals) for the petals so
    // they read as broad rays rather than thin slashes. U+25CF ● is
    // the center where all 7 ellipses overlap in the SVG.
    rows.push(center(
        &format!("{EMERALD}\u{2572} \u{2572}\u{2502}\u{2571} \u{2571}{RESET}"),
        LEFT_INNER,
    ));
    rows.push(center(
        &format!("{EMERALD} \u{2572}\u{2572}\u{2502}\u{2571}\u{2571} {RESET}"),
        LEFT_INNER,
    ));
    rows.push(center(
        &format!("{EMERALD}{H}{H}{H}\u{25CF}{H}{H}{H}{RESET}"),
        LEFT_INNER,
    ));
    rows.push(center(
        &format!("{EMERALD} \u{2571}\u{2571}\u{2502}\u{2572}\u{2572} {RESET}"),
        LEFT_INNER,
    ));
    rows.push(center(
        &format!("{EMERALD}\u{2571} \u{2571}\u{2502}\u{2572} \u{2572}{RESET}"),
        LEFT_INNER,
    ));
    rows.push(String::new());
    rows.push(center(&format!("v{version} (Rust)"), LEFT_INNER));
    rows.push(String::new());
    let cwd_short = truncate_cwd(cwd, LEFT_INNER - 2);
    rows.push(center(
        &format!("{DIM}{cwd_short}{RESET}", DIM = DIM, RESET = RESET),
        LEFT_INNER,
    ));
    rows.push(String::new());
    rows
}

fn build_right() -> Vec<String> {
    // Tips / More commands / Available Adapters layout mirrors the V2
    // design rendered in `cladue desing/welcome_screen_v2.html`. The
    // "Available Adapters" section LISTS the SDK runtime adapters
    // (express, fastapi, gin, etc.) which is a DIFFERENT surface from
    // `arcis audit --language X`. Go runtime adapters exist (gin,
    // echo, chi, fiber, nethttp), so Go appears here even though
    // `audit --language go` does not yet ship. The two facts coexist.
    let mut rows = Vec::new();
    rows.push(String::new());
    rows.push(format!("{EMERALD}Tips for getting started{RESET}"));
    rows.push("  Run 'arcis audit .' to scan your code for unsafe patterns".to_string());
    rows.push("  Run 'arcis sca .' to match deps against the threat database".to_string());
    rows.push("  Run 'arcis scan <url>' to probe a live endpoint".to_string());
    rows.push(String::new());
    rows.push(format!("{EMERALD}More commands{RESET}"));
    rows.push("  arcis --help      Per-command help and full flag reference".to_string());
    rows.push("  arcis --version   Print installed CLI version".to_string());
    rows.push("  arcis --list      Verbose catalog with examples per command".to_string());
    rows.push("  arcis update      Check for a newer Arcis release".to_string());
    rows.push(String::new());
    rows.push(format!("{EMERALD}Available Adapters{RESET}"));
    rows.push(
        "  node:    express, fastify, koa, nestjs, nextjs, sveltekit, astro, nuxt, bun".to_string(),
    );
    rows.push("  python:  fastapi, litestar, django, flask".to_string());
    rows.push("  go:      gin, echo, chi, fiber, nethttp".to_string());
    rows.push(String::new());
    rows.push(String::new());
    rows.push(format!(
        "{DIM}                Upgrade:  npm install -g @arcis/cli@latest{RESET}"
    ));
    rows.push(String::new());
    rows
}

fn truncate_cwd(cwd: &str, width: usize) -> String {
    if cwd.chars().count() <= width {
        return cwd.to_string();
    }
    // Show the tail of the path with leading ellipsis. The tail
    // (project name) is what's relevant for a developer reading the
    // banner; the head is just home directory + a long parent chain.
    let chars: Vec<char> = cwd.chars().collect();
    let keep = width.saturating_sub(3);
    let start = chars.len().saturating_sub(keep);
    let tail: String = chars[start..].iter().collect();
    format!("...{tail}")
}

/// Pad `s` so its visible column count equals `width`. Counts visible
/// columns (ignoring ANSI escape sequences) so colored content lines
/// up with uncolored ones.
fn pad(s: &str, width: usize) -> String {
    let vis = visible_cols(s);
    if vis >= width {
        return s.to_string();
    }
    format!("{s}{}", " ".repeat(width - vis))
}

/// Center `s` within `width` display columns. Ignores ANSI sequences
/// when counting.
fn center(s: &str, width: usize) -> String {
    let vis = visible_cols(s);
    if vis >= width {
        return s.to_string();
    }
    let total = width - vis;
    let left_pad = total / 2;
    let right_pad = total - left_pad;
    format!("{}{}{}", " ".repeat(left_pad), s, " ".repeat(right_pad))
}

/// Count display columns in a string, stripping ANSI escape sequences.
/// Approximate for non-ASCII: counts each `char` as one column. For the
/// glyphs we use (box-drawing, star, ASCII), each is one column.
fn visible_cols(s: &str) -> usize {
    let mut n = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            // ANSI sequences end on a letter. Be loose: stop on any
            // ASCII letter, which covers SGR ('m'), cursor codes, etc.
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        n += 1;
    }
    n
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
    fn includes_version_in_title() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("Arcis CLI v1.0.1"));
    }

    #[test]
    fn left_panel_carries_welcome() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("Welcome to Arcis"));
    }

    #[test]
    fn right_panel_carries_section_titles() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("Tips for getting started"));
        assert!(out.contains("More commands"));
        assert!(out.contains("Available Adapters"));
    }

    #[test]
    fn available_adapters_section_lists_all_three_languages() {
        // V2 design (welcome_screen_v2.html): node + python + go rows
        // in the Available Adapters section. Go appears because the
        // section describes SDK RUNTIME adapters (gin/echo/etc are
        // real Go SDK adapters), not `audit --language` support.
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("node:"));
        assert!(out.contains("express"));
        assert!(out.contains("python:"));
        assert!(out.contains("fastapi"));
        assert!(out.contains("go:"));
        assert!(out.contains("gin"));
    }

    #[test]
    fn in_box_footer_carries_help_hint() {
        // V2 design adds a full-width footer row inside the box with
        // a centered hint, separated from the two-column body by a
        // ├──...──┤ line.
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("Type 'arcis --help'"));
        assert!(out.contains("'arcis audit .'"));
        // Separator chars used for the body / footer divide.
        assert!(out.contains(TEE_R));
        assert!(out.contains(TEE_L));
    }

    #[test]
    fn prompt_area_renders_after_the_box() {
        // V2 design: single line, cursor row with `|`, second line —
        // after the box, before the shell prompt takes over.
        let out = render("1.0.1", "/tmp/proj");
        // The cursor row uses a literal `|`. Bounded count check —
        // exactly one line in the prompt area carries it.
        let lines: Vec<&str> = out.lines().collect();
        let cursor_lines: Vec<&&str> = lines.iter().filter(|l| l.trim() == "|").collect();
        assert_eq!(
            cursor_lines.len(),
            1,
            "expected exactly one cursor `|` row, got {} in:\n{}",
            cursor_lines.len(),
            out
        );
    }

    #[test]
    fn right_panel_lists_three_main_commands() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("arcis audit ."));
        assert!(out.contains("arcis sca ."));
        assert!(out.contains("arcis scan"));
    }

    #[test]
    fn right_panel_lists_meta_commands() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("--help"));
        assert!(out.contains("--version"));
        assert!(out.contains("--list"));
        assert!(out.contains("arcis update"));
        assert!(out.contains("Upgrade:"));
        assert!(out.contains("npm install -g @arcis/cli"));
    }

    #[test]
    fn renders_short_cwd_unchanged() {
        let out = render("1.0.1", "/tmp/proj");
        assert!(out.contains("/tmp/proj"));
    }

    #[test]
    fn long_cwd_truncated_to_tail_with_ellipsis() {
        let long = "/a/very/long/path/that/way/exceeds/the/left/panel/width/projectname";
        let out = render("1.0.1", long);
        assert!(out.contains("projectname"));
        assert!(out.contains("..."));
    }

    #[test]
    fn too_narrow_triggers_at_correct_threshold() {
        assert!(too_narrow(80));
        assert!(too_narrow(MIN_COLS - 1));
        assert!(!too_narrow(MIN_COLS));
        assert!(!too_narrow(160));
    }

    #[test]
    fn visible_cols_ignores_ansi_sequences() {
        assert_eq!(visible_cols("hello"), 5);
        assert_eq!(visible_cols(&format!("{EMERALD}hello{RESET}")), 5);
        assert_eq!(visible_cols("\x1b[38;2;255;0;0mred\x1b[0m"), 3);
    }

    #[test]
    fn pad_uses_visible_width_not_byte_count() {
        let colored = format!("{EMERALD}abc{RESET}");
        let padded = pad(&colored, 10);
        // 3 visible chars + 7 spaces of padding
        assert_eq!(visible_cols(&padded), 10);
    }

    #[test]
    fn truncate_cwd_returns_input_when_short() {
        assert_eq!(truncate_cwd("/short", 40), "/short");
    }

    #[test]
    fn truncate_cwd_handles_unicode() {
        // Should not panic on multi-byte chars.
        let unicode = "/тест/проект/файл";
        let result = truncate_cwd(unicode, 10);
        assert!(!result.is_empty());
    }

    #[test]
    fn render_contains_box_drawing_corners() {
        let out = render("1.0.1", "/p");
        assert!(out.contains(TL));
        assert!(out.contains(TR));
        assert!(out.contains(BL));
        assert!(out.contains(BR));
    }
}
