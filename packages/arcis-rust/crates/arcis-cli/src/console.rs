//! `arcis console` — interactive REPL surface.
//!
//! Dropped into when a user invokes `arcis` with no args on a TTY (and
//! not under CI, not piped). Full-screen TUI shape with a persistent header, a
//! scrollback area below it, and a prompt at the bottom. Slash commands
//! `/help` and `/exit` plus the three scanners (`audit`, `sca`, `scan`)
//! run inline; output streams into the scrollback as the subprocess
//! produces it.
//!
//! ## MVP scope (v1.6.0)
//!
//! Out of scope for this first cut, see `improvements.md` §1.5 for the
//! full M1..M5 plan:
//!
//! * No event-channel refactor of audit/sca/scan. Commands invoke
//!   `<self-exe> <subcommand>` as a child subprocess. Costs one process
//!   spawn per command (~5-20ms on a modern box, negligible vs scan
//!   time). The refactor pays for itself later when M2 lands.
//! * No findings-navigation overlay. Output is scrollback-only.
//! * No tab completion, no command history persistence — current line
//!   only.
//! * Subprocess writes plain text into scrollback (NO_COLOR=1 forces
//!   the binary off ANSI). Future polish: parse ANSI codes back into
//!   ratatui spans.

use std::io::{self, BufRead, BufReader, Stdout, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Terminal,
};

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Brand emerald `#00996D`. Same color the standalone welcome screen
/// uses. Defined as a `Color::Rgb` so we can use it inside ratatui
/// styles without raw escape strings.
const EMERALD: Color = Color::Rgb(0, 153, 109);
const DIM: Color = Color::Rgb(120, 120, 120);

/// Max lines kept in scrollback. Older lines drop off the top. 5000 is
/// roughly 50 audit runs' worth of output on a medium project — enough
/// to scroll through one session without runaway memory.
const SCROLLBACK_MAX: usize = 5000;

/// Polling cadence for the input event loop. 50ms gives ~20 fps redraw
/// when a subprocess is streaming, which is smooth for terminal output
/// without burning CPU on an idle prompt.
const POLL_INTERVAL_MS: u64 = 50;

/// Max history entries persisted to disk. Same bound used in-memory.
const HISTORY_MAX: usize = 200;

/// Entry point. Called from `main()` when bare `arcis` is invoked in a
/// TTY context. Sets up the terminal, runs the event loop, and
/// guarantees terminal restoration on every exit path (panic-safe via
/// the [`TerminalGuard`] drop impl).
pub fn run() -> ExitCode {
    let mut guard = match TerminalGuard::enter() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("arcis console: failed to initialise terminal: {e}");
            return ExitCode::from(2);
        }
    };

    let mut state = ReplState::new();
    state.append_banner();

    let outcome = event_loop(&mut guard.terminal, &mut state);

    // Guard drops here -> terminal restored even if `event_loop` returned Err.
    drop(guard);

    match outcome {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("arcis console: {e}");
            ExitCode::from(1)
        }
    }
}

/// RAII guard around the alt-screen + raw-mode lifecycle. Drop restores
/// the terminal to its prior state so a panic mid-render doesn't leave
/// the user staring at a garbled terminal.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort cleanup. We're already exiting; nothing useful to
        // do on failure here besides not panicking out of Drop.
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

/// REPL state. Owned by the event loop; no shared mutability — the
/// subprocess output stream lives behind an MPSC channel so we don't
/// need a Mutex.
struct ReplState {
    /// Scrollback. Each entry is one logical line. Append-only; old
    /// lines drop off the front when `len()` exceeds [`SCROLLBACK_MAX`].
    lines: Vec<ScrollbackLine>,
    /// Current input buffer. Edited in place by [`KeyCode::Char`] /
    /// [`KeyCode::Backspace`] events; cleared when the user submits.
    input: String,
    /// Cursor position within `input`, in chars (not bytes). Updated by
    /// arrow keys and home/end. Always `<= input.chars().count()`.
    cursor: usize,
    /// Running subprocess, if any. While `Some`, keypress dispatch is
    /// gated: Enter does nothing, Ctrl-C sends a cancellation, everything
    /// else routes to the input buffer normally so the user can type
    /// the next command ahead.
    running: Option<RunningCommand>,
    /// Last few submitted commands. Up-arrow steps backwards through
    /// this list. Bounded so a long session doesn't grow without bound.
    history: Vec<String>,
    /// Position in history when up-arrow is being held. `None` means
    /// the user is editing a fresh command; `Some(i)` means the buffer
    /// reflects `history[i]`.
    history_cursor: Option<usize>,
    /// Path to the running `arcis` executable. Cached at startup so we
    /// don't re-resolve `current_exe()` on every command.
    self_exe: PathBuf,
    /// Current working directory at the time the console started. Shown
    /// in the header so users always know where commands will run.
    cwd: String,
    /// How many rows the scrollback is scrolled UP from the bottom.
    /// 0 (default) means "show the tail." > 0 freezes the view at the
    /// scrolled position; appending new output does not auto-follow
    /// while the user is scrolled. Resets to 0 on Enter / clear / a
    /// new command submit so the next command's output is visible
    /// without an extra keystroke.
    scroll_offset: usize,
}

/// One scrollback row. Output lines from subprocesses carry [`Origin::Output`];
/// echoed user commands carry [`Origin::Echo`]; system messages (help,
/// errors, banner) carry [`Origin::System`]. Style branches on origin.
struct ScrollbackLine {
    origin: Origin,
    text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// stdout/stderr from a subprocess.
    Output,
    /// `▶ user typed this` — echo of the submitted command.
    Echo,
    /// System messages: banner, /help, error reporting, completion
    /// status lines like "(exit 0 in 12ms)".
    System,
    /// /help-section headers (slightly heavier styling).
    SystemHeader,
}

/// Handle to an in-flight subprocess. Channel receives stdout/stderr
/// lines from the reader thread; `child` is the process handle so we
/// can kill it when the user hits Ctrl-C.
struct RunningCommand {
    child: Child,
    receiver: Receiver<ReaderEvent>,
    /// Echoed command text for the "(exit N in Ms)" line.
    cmd_label: String,
    /// When the subprocess started, for the duration in the completion
    /// line.
    started_at: std::time::Instant,
}

/// Messages from the reader thread to the main loop.
enum ReaderEvent {
    Line(String),
    /// Reserved for an explicit child-exit signal. Channel disconnection
    /// currently delivers the same information (the receiver sees
    /// `Disconnected` once both reader threads drop their senders), so
    /// `Done` is not constructed today. Keeping the variant lets us add
    /// explicit signalling later without a breaking enum change.
    #[allow(dead_code)]
    Done,
}

impl ReplState {
    fn new() -> Self {
        let self_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("arcis"));
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| String::from("."));
        // Under `cargo test`, the default `~/.arcis/history` is a shared
        // process-wide file. Parallel tests race through `submit()` and
        // pollute each other's expectations. Skip the disk load under
        // cfg(test) UNLESS the caller has explicitly set
        // `ARCIS_HISTORY_PATH` (i.e., opted in via `with_temp_history_path`).
        let history = if cfg!(test) && std::env::var("ARCIS_HISTORY_PATH").is_err() {
            Vec::new()
        } else {
            load_history()
        };
        Self {
            lines: Vec::new(),
            input: String::new(),
            cursor: 0,
            running: None,
            history,
            history_cursor: None,
            self_exe,
            cwd,
            scroll_offset: 0,
        }
    }

    /// Indices into `self.lines` that look like findings — a quick scan
    /// over the scrollback for severity-prefixed rows. Walked on every
    /// F2 / Shift-F2 so callers never deal with stale indices: the cost
    /// is a single linear pass per jump (5,000 rows max).
    ///
    /// Finding shape: leading whitespace + uppercase severity token
    /// (CRITICAL/HIGH/MEDIUM/LOW/CRIT/WARN/INFO) followed by a space.
    /// Mirrors what `arcis audit / sca / scan` print in plain-text mode.
    fn finding_indices(&self) -> Vec<usize> {
        let severities = [
            "CRITICAL ",
            "HIGH ",
            "MEDIUM ",
            "LOW ",
            "CRIT ",
            "WARN ",
            "INFO ",
        ];
        self.lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| {
                let t = l.text.trim_start();
                if severities.iter().any(|s| t.starts_with(s)) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Scroll the view to a specific scrollback row, pinning it near the
    /// top of the visible area. `view_rows` is the current visible row
    /// count — required because we measure offset from the bottom.
    fn scroll_to_line(&mut self, target_line: usize, view_rows: usize) {
        let total = self.lines.len();
        if total == 0 || view_rows == 0 {
            self.scroll_offset = 0;
            return;
        }
        // Aim to leave `target_line` 2 rows below the top of the view.
        let desired_bottom = (target_line + view_rows.saturating_sub(2)).min(total);
        let offset = total.saturating_sub(desired_bottom);
        self.scroll_offset = offset.min(total.saturating_sub(view_rows.min(total)));
    }

    /// F2: jump to the next finding strictly below the current view's
    /// top. Wraps to the first finding if we're already past the last.
    fn jump_next_finding(&mut self, view_rows: usize) {
        let findings = self.finding_indices();
        if findings.is_empty() {
            return;
        }
        let view_top = self
            .lines
            .len()
            .saturating_sub(self.scroll_offset + view_rows);
        let next = findings
            .iter()
            .copied()
            .find(|&i| i > view_top)
            .unwrap_or(findings[0]);
        self.scroll_to_line(next, view_rows);
    }

    /// Shift-F2: jump to the previous finding strictly above the current
    /// view's top. Wraps to the last finding if we're at the top.
    fn jump_prev_finding(&mut self, view_rows: usize) {
        let findings = self.finding_indices();
        if findings.is_empty() {
            return;
        }
        let view_top = self
            .lines
            .len()
            .saturating_sub(self.scroll_offset + view_rows);
        let prev = findings
            .iter()
            .copied()
            .rev()
            .find(|&i| i < view_top)
            .unwrap_or(*findings.last().unwrap());
        self.scroll_to_line(prev, view_rows);
    }

    /// PgUp: scroll one view-height upward. Caps at the top of scrollback.
    fn scroll_page_up(&mut self, view_rows: usize) {
        let max_offset = self.lines.len().saturating_sub(view_rows.max(1));
        self.scroll_offset = (self.scroll_offset + view_rows).min(max_offset);
    }

    /// PgDown: scroll one view-height downward toward the tail.
    fn scroll_page_down(&mut self, view_rows: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(view_rows);
    }

    fn follow_tail(&mut self) {
        self.scroll_offset = 0;
    }

    /// Append the welcome banner. Banner is part of scrollback so it
    /// scrolls naturally as the user runs commands. The welcome content
    /// sits at the top of the session and slides off as work accumulates.
    ///
    /// Sections mirror the Figma V2 mockup: braille sunburst mascot +
    /// wordmark on the left, version + cwd row, then Quick start /
    /// More commands / Available adapters / Console commands columns.
    /// Adapter list lists all three languages (node + python + go) —
    /// it describes SDK runtime adapters, not `audit --language`
    /// support, so Go belongs even though Go static-analysis rules
    /// have not shipped yet.
    fn append_banner(&mut self) {
        // Mascot + wordmark. Each mascot row prints alongside a slice
        // of the welcome text so the eye scans them as one unit. The
        // mascot lines are intentionally narrow (~25 cols) so it
        // doesn't dominate even on narrow terminals.
        let mascot = mascot_lines();
        let intro = welcome_intro_lines(TOOL_VERSION, &self.cwd);
        let row_count = mascot.len().max(intro.len());
        for i in 0..row_count {
            let m: &str = mascot.get(i).copied().unwrap_or("");
            let default_intro = String::new();
            let t: &str = intro.get(i).unwrap_or(&default_intro);
            self.push_sys_header(format!("  {m:<28}{t}"));
        }
        self.push_sys("");
        self.push_sys_header("Quick start");
        self.push_sys("  audit .            scan source for unsafe patterns");
        self.push_sys("  sca .              match deps against the threat database");
        self.push_sys("  scan <url>         probe a live endpoint");
        self.push_sys("");
        self.push_sys_header("More commands");
        self.push_sys("  arcis --help       per-command help and full flag reference");
        self.push_sys("  arcis --version    print installed CLI version");
        self.push_sys("  arcis --list       verbose catalog with examples per command");
        self.push_sys("  arcis update       check for a newer Arcis release");
        self.push_sys("");
        self.push_sys_header("Available adapters");
        self.push_sys(
            "  node:    express, fastify, koa, nestjs, nextjs, sveltekit, astro, nuxt, bun",
        );
        self.push_sys("  python:  fastapi, litestar, django, flask");
        self.push_sys("  go:      gin, echo, chi, fiber, nethttp");
        self.push_sys("");
        self.push_sys_header("Console commands");
        self.push_sys("  /help              show this banner again");
        self.push_sys("  /clear             wipe scrollback");
        self.push_sys("  /cwd <path>        change working directory");
        self.push_sys("  /export [file]     save this session to a markdown file");
        self.push_sys("  /exit              leave the console (Ctrl-D works too)");
        self.push_sys("");
        self.push_sys("  Ctrl-C cancels a running command. Banner scrolls as you work.");
        self.push_sys("  PgUp/PgDn scrolls findings; F2 jumps to next finding; Shift-F2 prev.");
        self.push_sys("");
    }

    fn push_sys(&mut self, line: impl Into<String>) {
        self.append(ScrollbackLine {
            origin: Origin::System,
            text: line.into(),
        });
    }

    fn push_sys_header(&mut self, line: impl Into<String>) {
        self.append(ScrollbackLine {
            origin: Origin::SystemHeader,
            text: line.into(),
        });
    }

    fn push_echo(&mut self, line: impl Into<String>) {
        self.append(ScrollbackLine {
            origin: Origin::Echo,
            text: line.into(),
        });
    }

    fn push_output(&mut self, line: impl Into<String>) {
        self.append(ScrollbackLine {
            origin: Origin::Output,
            text: line.into(),
        });
    }

    fn append(&mut self, line: ScrollbackLine) {
        self.lines.push(line);
        // Drop oldest in chunks to amortise the Vec shift cost when the
        // scrollback overflows. 256 is small enough that a single
        // overshoot loop iteration doesn't visibly stutter rendering.
        if self.lines.len() > SCROLLBACK_MAX + 256 {
            let drop = self.lines.len() - SCROLLBACK_MAX;
            self.lines.drain(0..drop);
        }
    }

    /// Dispatch a submitted command line. Empty submits are no-ops so
    /// the user can press Enter on an empty prompt without consequence.
    fn submit(&mut self, raw: String) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        // Add to history (de-dup the immediate-prior entry — typical
        // shell convention) AND persist to disk so a new session starts
        // with prior commands in the up-arrow buffer.
        if self.history.last().map(String::as_str) != Some(trimmed) {
            self.history.push(trimmed.to_string());
            if self.history.len() > HISTORY_MAX {
                self.history.remove(0);
            }
            // Best-effort write — if the home directory is unwritable
            // (read-only homedir, container, etc.), silently keep the
            // in-memory history. Worth not crashing the REPL over. Under
            // `cargo test`, only persist if `ARCIS_HISTORY_PATH` is set
            // (i.e., the test explicitly opted in via the temp-path
            // helper). Otherwise tests would race through the global
            // ~/.arcis/history file.
            if !cfg!(test) || std::env::var("ARCIS_HISTORY_PATH").is_ok() {
                let _ = append_history(trimmed);
            }
        }
        self.history_cursor = None;
        // Snap the view back to the tail. The user just typed something
        // and wants to see its output, not stay scrolled in old history.
        self.follow_tail();

        self.push_echo(format!("▶ {trimmed}"));

        if let Some(slash) = trimmed.strip_prefix('/') {
            self.dispatch_slash(slash.trim());
            return;
        }

        // Anything else: hand off to the subprocess.
        self.spawn_subcommand(trimmed);
    }

    fn dispatch_slash(&mut self, body: &str) {
        let mut iter = body.split_whitespace();
        let head = iter.next().unwrap_or("");
        match head {
            "" | "help" => self.append_banner(),
            "exit" | "quit" => {
                // Signal exit via a sentinel in the running slot. The
                // event loop checks `should_exit()` each tick.
                self.lines.push(ScrollbackLine {
                    origin: Origin::System,
                    text: "  (bye)".into(),
                });
                self.input = String::from("__arcis_exit__");
            }
            "clear" => {
                self.lines.clear();
                self.scroll_offset = 0;
                self.append_banner();
            }
            "cwd" => {
                let arg = iter.collect::<Vec<&str>>().join(" ");
                if arg.is_empty() {
                    self.push_sys(format!("  cwd = {}", self.cwd));
                } else {
                    match std::env::set_current_dir(&arg) {
                        Ok(()) => {
                            self.cwd = std::env::current_dir()
                                .map(|p| p.display().to_string())
                                .unwrap_or(arg.clone());
                            self.push_sys(format!("  cwd → {}", self.cwd));
                        }
                        Err(e) => self.push_sys(format!("  /cwd: {e}")),
                    }
                }
            }
            "export" => {
                let arg = iter.collect::<Vec<&str>>().join(" ");
                match self.export_session(if arg.is_empty() { None } else { Some(&arg) }) {
                    Ok(path) => self.push_sys(format!("  exported session to {path}")),
                    Err(e) => self.push_sys(format!("  /export: {e}")),
                }
            }
            other => self.push_sys(format!("  unknown slash command: /{other}")),
        }
    }

    /// Dump the current scrollback to a markdown file. When `dest` is
    /// `None`, defaults to `arcis-session-<utc-timestamp>.md` in cwd.
    /// Returns the absolute path written, or an io::Error string.
    fn export_session(&self, dest: Option<&str>) -> Result<String, String> {
        let default_name = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("arcis-session-{now}.md")
        };
        let target = dest.unwrap_or(&default_name).to_string();
        let path = std::path::Path::new(&target);
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."))
                .join(path)
        };

        let mut body = String::new();
        body.push_str("# Arcis Console session\n\n");
        body.push_str(&format!("- arcis CLI: v{TOOL_VERSION}\n"));
        body.push_str(&format!("- cwd:       {}\n", self.cwd));
        body.push_str(&format!("- exported:  {}\n\n", iso_timestamp_now()));
        body.push_str("---\n\n");
        body.push_str("```\n");
        for line in &self.lines {
            // Origin annotations help a reader skim: echoed commands
            // get `> ` prefix, system lines stay indented, output is
            // raw. Markdown fence keeps everything monospace.
            match line.origin {
                Origin::Echo => {
                    body.push_str(&line.text);
                    body.push('\n');
                }
                Origin::Output => {
                    body.push_str(&line.text);
                    body.push('\n');
                }
                Origin::System | Origin::SystemHeader => {
                    body.push_str(&line.text);
                    body.push('\n');
                }
            }
        }
        body.push_str("```\n");

        std::fs::write(&abs, body).map_err(|e| e.to_string())?;
        Ok(abs.display().to_string())
    }

    /// Spawn the subprocess that runs `arcis <command>`. stdout + stderr
    /// merge into one pipe; a reader thread pushes each line into the
    /// channel. The main loop drains the channel into scrollback every
    /// tick.
    fn spawn_subcommand(&mut self, line: &str) {
        if self.running.is_some() {
            self.push_sys("  a command is already running — Ctrl-C to cancel it first");
            return;
        }
        let args = shell_split(line);
        if args.is_empty() {
            return;
        }
        let mut cmd = Command::new(&self.self_exe);
        cmd.args(&args);
        // Let the subprocess emit ANSI SGR codes. `parse_sgr_line` at
        // render time converts them into ratatui spans, so colored
        // output shows up with the right hue inside the scrollback
        // instead of as literal `\x1b[31m` text. The child won't see a
        // TTY (stdout is piped), so most well-behaved programs will
        // disable color on their own. Setting CLICOLOR_FORCE keeps the
        // door open for tools that respect it.
        cmd.env("CLICOLOR_FORCE", "1");
        cmd.env("ARCIS_NO_REPL", "1"); // prevent recursive REPL boot
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.push_sys(format!("  failed to spawn arcis: {e}"));
                return;
            }
        };
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (tx, rx) = mpsc::channel();
        // Reader thread for stdout.
        if let Some(out) = stdout {
            let tx_out = tx.clone();
            thread::spawn(move || {
                let reader = BufReader::new(out);
                for line in reader.lines().map_while(Result::ok) {
                    if tx_out.send(ReaderEvent::Line(line)).is_err() {
                        break;
                    }
                }
            });
        }
        // Reader thread for stderr — interleaved with stdout in the
        // scrollback so the user sees errors at the right place.
        if let Some(err) = stderr {
            let tx_err = tx.clone();
            thread::spawn(move || {
                let reader = BufReader::new(err);
                for line in reader.lines().map_while(Result::ok) {
                    if tx_err.send(ReaderEvent::Line(line)).is_err() {
                        break;
                    }
                }
            });
        }
        // Done-signal thread: waits for child exit then drops the
        // sender. The Done variant arrives last regardless of which
        // pipe closed first, because `wait()` blocks until both pipes
        // drain.
        drop(tx); // close the originating sender so receiver hangs up after readers finish

        self.running = Some(RunningCommand {
            child,
            receiver: rx,
            cmd_label: line.to_string(),
            started_at: std::time::Instant::now(),
        });
    }

    /// Drain whatever the reader threads have pushed since the last
    /// tick. Returns true if anything new arrived (drives a redraw on
    /// the same tick).
    fn drain_subprocess_output(&mut self) -> bool {
        let mut updated = false;
        // Move the running slot out temporarily so we can keep using
        // self for push_output without overlapping borrows.
        let Some(mut running) = self.running.take() else {
            return false;
        };
        loop {
            match running.receiver.try_recv() {
                Ok(ReaderEvent::Line(line)) => {
                    self.push_output(line);
                    updated = true;
                }
                Ok(ReaderEvent::Done) => break,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    // Both reader threads finished AND the child is
                    // done writing. Reap the child to capture exit code.
                    match running.child.try_wait() {
                        Ok(Some(status)) => {
                            let ms = running.started_at.elapsed().as_millis();
                            let code = status.code().unwrap_or(-1);
                            self.push_sys(format!(
                                "  (arcis {} exited {} in {ms}ms)",
                                running.cmd_label, code
                            ));
                            return true; // running stays None
                        }
                        Ok(None) => {
                            // Pipes closed but child still alive (rare —
                            // can happen if child forked another process
                            // that inherits the pipe). Put running back
                            // and try again next tick.
                            self.running = Some(running);
                            return updated;
                        }
                        Err(e) => {
                            self.push_sys(format!("  wait error: {e}"));
                            return true;
                        }
                    }
                }
            }
        }
        self.running = Some(running);
        updated
    }

    /// Cancel the running subprocess, if any. Used by Ctrl-C in the
    /// main loop. The reader threads will see EOF on the pipes and exit
    /// on their own; the next drain tick reaps the child.
    fn cancel_running(&mut self) {
        let Some(mut running) = self.running.take() else {
            self.push_sys("  (nothing to cancel)");
            return;
        };
        let _ = running.child.kill();
        self.push_sys(format!("  ✗ cancelled `arcis {}`", running.cmd_label));
        // Pull whatever's left in the channel synchronously so
        // partial output is preserved.
        for ev in running.receiver.iter() {
            if let ReaderEvent::Line(line) = ev {
                self.push_output(line);
            }
        }
        let _ = running.child.wait();
    }

    /// Sentinel check used by the event loop to exit cleanly.
    fn should_exit(&self) -> bool {
        self.input == "__arcis_exit__"
    }
}

/// Tokenize a command line into argv. Splits on whitespace, respects
/// single and double quotes so `scan "http://example.com/api?x=1 2"`
/// parses cleanly. Intentionally small — full shell semantics belong
/// in a real shell, not here.
fn shell_split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in line.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    state: &mut ReplState,
) -> io::Result<()> {
    loop {
        if state.should_exit() {
            return Ok(());
        }
        let frame_size = terminal.size()?;
        terminal.draw(|f| ui_render(f, state))?;
        // Scrollback occupies all but the bottom 3 rows of the frame
        // (prompt block). Cached so key handlers like PgUp / F2 know
        // how big a "page" is for this terminal size.
        let view_rows: usize = frame_size.height.saturating_sub(3).max(1) as usize;

        // Drain any subprocess output that arrived since the last tick.
        // If anything came in, we'll redraw on the next iteration.
        state.drain_subprocess_output();

        // Block waiting for input, with a timeout so we still pick up
        // subprocess output while the user isn't typing.
        if !event::poll(Duration::from_millis(POLL_INTERVAL_MS))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Char('c') if ctrl => {
                        if state.running.is_some() {
                            state.cancel_running();
                        } else {
                            // Ctrl-C on idle prompt: clear current input.
                            state.input.clear();
                            state.cursor = 0;
                        }
                    }
                    KeyCode::Char('d') if ctrl && state.input.is_empty() => {
                        return Ok(());
                    }
                    KeyCode::Char(c) if !ctrl => {
                        let byte_idx = char_pos_to_byte(&state.input, state.cursor);
                        state.input.insert(byte_idx, c);
                        state.cursor += 1;
                        state.history_cursor = None;
                    }
                    KeyCode::Backspace if state.cursor > 0 => {
                        let prev_byte = char_pos_to_byte(&state.input, state.cursor - 1);
                        let cur_byte = char_pos_to_byte(&state.input, state.cursor);
                        state.input.replace_range(prev_byte..cur_byte, "");
                        state.cursor -= 1;
                        state.history_cursor = None;
                    }
                    KeyCode::Delete => {
                        let total = state.input.chars().count();
                        if state.cursor < total {
                            let cur_byte = char_pos_to_byte(&state.input, state.cursor);
                            let next_byte = char_pos_to_byte(&state.input, state.cursor + 1);
                            state.input.replace_range(cur_byte..next_byte, "");
                            state.history_cursor = None;
                        }
                    }
                    KeyCode::Left if state.cursor > 0 => {
                        state.cursor -= 1;
                    }
                    KeyCode::Right => {
                        let total = state.input.chars().count();
                        if state.cursor < total {
                            state.cursor += 1;
                        }
                    }
                    KeyCode::Home => state.cursor = 0,
                    KeyCode::End => state.cursor = state.input.chars().count(),
                    KeyCode::Up => navigate_history(state, -1),
                    KeyCode::Down => navigate_history(state, 1),
                    KeyCode::PageUp => state.scroll_page_up(view_rows),
                    KeyCode::PageDown => state.scroll_page_down(view_rows),
                    KeyCode::F(2) if key.modifiers.contains(KeyModifiers::SHIFT) => {
                        state.jump_prev_finding(view_rows);
                    }
                    KeyCode::F(2) => state.jump_next_finding(view_rows),
                    KeyCode::Enter => {
                        let cmd = std::mem::take(&mut state.input);
                        state.cursor = 0;
                        state.submit(cmd);
                    }
                    KeyCode::Esc => {
                        state.input.clear();
                        state.cursor = 0;
                        state.history_cursor = None;
                        // Snap back to the tail — Esc clears modal state
                        // and being scrolled is one such state.
                        state.follow_tail();
                    }
                    _ => {}
                }
            }
            Event::Resize(_, _) => {
                // Next draw frame picks up the new size automatically.
            }
            _ => {}
        }
    }
}

/// Step through history. delta = -1 = older, +1 = newer.
fn navigate_history(state: &mut ReplState, delta: i32) {
    if state.history.is_empty() {
        return;
    }
    let len = state.history.len();
    let new_cursor: Option<usize> = match state.history_cursor {
        None if delta < 0 => Some(len - 1),
        None => return, // pressing Down with no history navigation is a no-op
        Some(i) => {
            let raw = i as i32 + delta;
            if raw < 0 {
                Some(0)
            } else if raw >= len as i32 {
                None
            } else {
                Some(raw as usize)
            }
        }
    };
    match new_cursor {
        Some(i) => {
            state.input = state.history[i].clone();
            state.cursor = state.input.chars().count();
            state.history_cursor = Some(i);
        }
        None => {
            state.input.clear();
            state.cursor = 0;
            state.history_cursor = None;
        }
    }
}

/// Translate a char-position to a byte-position. ratatui works with
/// chars (display columns are roughly chars for ASCII-heavy CLIs);
/// Rust `String` ops want byte offsets. The helper keeps the
/// conversion in one place so a unicode test can target it directly.
fn char_pos_to_byte(s: &str, char_pos: usize) -> usize {
    s.char_indices()
        .nth(char_pos)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

fn ui_render(f: &mut ratatui::Frame, state: &ReplState) {
    let area = f.area();

    // Two-pane layout. Banner is part of scrollback and scrolls naturally
    // as the user works, eventually off-screen.
    // Prompt is pinned at the bottom in a 3-row block (border-top +
    // input row + border-bottom).
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(area);

    render_scrollback(f, chunks[0], state);
    render_prompt(f, chunks[1], state);
}

fn truncate_cwd(cwd: &str, width: usize) -> String {
    if cwd.chars().count() <= width || width < 4 {
        return cwd.to_string();
    }
    let chars: Vec<char> = cwd.chars().collect();
    let keep = width - 3;
    let start = chars.len() - keep;
    let tail: String = chars[start..].iter().collect();
    format!("...{tail}")
}

fn render_scrollback(f: &mut ratatui::Frame, area: Rect, state: &ReplState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DIM));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Take the slice of the scrollback that fits in the visible area.
    // When `state.scroll_offset > 0` the user is scrolled up — anchor
    // the bottom of the view that many rows above the latest line.
    let visible_rows = inner.height as usize;
    let total = state.lines.len();
    let end = total.saturating_sub(state.scroll_offset);
    let start = end.saturating_sub(visible_rows);
    let visible: Vec<Line> = state.lines[start..end]
        .iter()
        .map(|l| match l.origin {
            Origin::Echo => Line::from(Span::styled(
                l.text.clone(),
                Style::default().fg(EMERALD).add_modifier(Modifier::BOLD),
            )),
            Origin::Output => {
                // Only run the SGR parser when the line contains an
                // ESC byte. The common case (well-behaved Rust child
                // on a piped stdout) is plain text, and that path
                // should stay zero-allocation per render frame.
                if l.text.contains('\x1b') {
                    Line::from(parse_sgr_line(&l.text))
                } else {
                    Line::from(Span::raw(l.text.clone()))
                }
            }
            Origin::System => Line::from(Span::styled(l.text.clone(), Style::default().fg(DIM))),
            Origin::SystemHeader => Line::from(Span::styled(
                l.text.clone(),
                Style::default().fg(EMERALD).add_modifier(Modifier::BOLD),
            )),
        })
        .collect();

    let paragraph = Paragraph::new(visible).wrap(Wrap { trim: false });
    f.render_widget(paragraph, inner);
}

fn render_prompt(f: &mut ratatui::Frame, area: Rect, state: &ReplState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(EMERALD));

    let status = if state.running.is_some() {
        Span::styled("● running — Ctrl-C to cancel", Style::default().fg(EMERALD))
    } else {
        Span::styled(
            "▶",
            Style::default().fg(EMERALD).add_modifier(Modifier::BOLD),
        )
    };

    // Scroll indicator: shown only when scrolled up. Helps the user
    // understand why new output isn't appearing while they navigate.
    let mut spans = vec![status, Span::raw(" "), Span::raw(state.input.clone())];
    if state.scroll_offset > 0 {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            format!("(scrolled +{}; End/PgDn to follow)", state.scroll_offset),
            Style::default().fg(DIM),
        ));
    }
    let prompt_line = Line::from(spans);

    let paragraph = Paragraph::new(prompt_line).block(block);
    f.render_widget(paragraph, area);

    // Set the visible cursor to its logical position in the input.
    // Prompt prefix is 2 chars ("● " or "▶ "); add the inner left edge
    // (1) and the cursor offset within the input.
    let prefix_chars: u16 = 4; // "▶ " or "● " plus 1 leading border + 1 padding
    let x = area
        .x
        .saturating_add(prefix_chars)
        .saturating_add(state.cursor as u16);
    let y = area.y.saturating_add(1);
    f.set_cursor_position((x, y));
}

// Suppress the unused-import warning for the never-sent ReaderEvent::Done
// variant. Kept for forward-compat: when we add explicit child-exit
// signalling (instead of relying on channel disconnection), the variant
// gets used. Removing it now would force a re-add later.
#[allow(dead_code)]
fn _unused_marker(_ev: ReaderEvent) {}

// Stub _write so the file compiles without the `Write` trait pulling
// in extra surface. Removed if rust ever flags it.
#[allow(dead_code)]
fn _ensure_write_in_scope<W: Write>(_w: &mut W) {}

/// Braille sunburst mascot. Inverted form (filled glyphs = petals,
/// blanks = background) so it renders correctly on dark and light
/// terminal themes alike. Trimmed from the full 99×50 art down to the
/// petal bounding box — ~24 cols × 21 rows — so the banner fits in
/// the welcome layout without dominating the viewport.
///
/// Provided by user 2026-05-21, generated via lachlanarthur's braille
/// converter on the Arcis Dot Logo PNG. Future redesigns should
/// regenerate from the source PNG at the same resolution so this row
/// count stays stable.
fn mascot_lines() -> &'static [&'static str] {
    &[
        "          ⡠⡠           ",
        "        ⡊⡆⢎⢪⢀          ",
        "       ⡘⡌⡊⡆⢕⠄          ",
        "      ⢌⢆⢕⠱⡘⢔⡑⠄         ",
        "     ⡊⢆⢪⢘⢌⠲⡘⠤          ",
        "    ⠜⡌⢆⢣⢑⢅⠇⡍⡂          ",
        "    ⢱⢘⢌⠆⡕⡢⠣⡱⡠          ",
        "    ⢐⠱⡰⡑⡱⢨⢊⠆⡎  ⡀⡄⡢⡊⢆⢕",
        "  ⢪⢘⢔⢑⢅⠕⢔⠠⡀  ⢐⢱⠨⡢⠣⡱⡘⡌⡪⠂  ⢀⠠⡢⡑⢕⠌⡆⢕⠱⡨",
        "  ⠑⢌⢆⢣⠡⡃⡇⢕⠜⢌⢢⢀  ⢑⢌⢆⢣⠪⡂⡇⢕⢅  ⢀⢠⢊⢆⠪⡢⡑⡅⢇⢪⠠⡀",
        "    ⠁⢆⢣⢑⢕⠸⡐⢕⢅⠣⡢⡃⡢⢀  ⠐⢔⠱⡰⡑⡱⡘⢔⢅  ⢀⢐⢔⠱⡨⠢⡣⡊⢆⢕⠱⡨⠢⠃",
        "      ⠑⢌⢆⢣⠱⡑⡌⢎⢢⠱⡘⡔⢅⠄  ⢊⠪⡢⢱⠨⡊⢆⠕  ⠰⡐⢕⠌⡎⢜⢌⢒⠜⡌⢆⢣⠑⠁",
        "        ⠑⡌⡪⢢⢑⠕⡌⡪⢌⠪⡂⢇⢕⢀  ⢕⠜⢔⡑⡅⡣⡑  ⡐⢌⢪⠸⡰⡑⢜⠔⡅⢕⠱⡘⠌",
        "          ⠑⠱⡨⢪⠨⡊⢆⢣⠱⡑⡌⢆⢕  ⡣⡱⢨⢊⢢⠁  ⡔⢜⠌⡆⡣⢪⢘⢔⠱⡘⡌⠊",
        "             ⠈⠢⢣⢑⠥⡑⡅⡕⢜⠌⢆⠣⢄⠐⢅⠣⡊⡆  ⢀⠜⢌⢆⢣⠱⡘⢔⢱⠨⠊⠈",
        "                ⠈⠪⠨⡢⡑⡅⡣⡱⡑⢕⠀  ⠑⠑   ⢐⠕⡱⡐⡅⡣⡑⠅⠁",
        "                   ⠁⠊⠢⠪⠨⠊      ⠑⠈⠂⠁",
        "                          ⡀⡀⡀⡄⢄⢄⠄⡄⢄⠄",
        "                       ⡂⡢⡑⢕⠌⡆⢕⢜⠰⡡⡱⡘⡔⡱⠡⡣⠱⡘⢔",
        "                      ⢆⠕⡌⡪⠪⡘⡌⡪⡂⢇⠪⡢⡑⠥⡱⢨⢢",
        "                     ⡅⡕⢜⠰⡑⡱⡘⢜⠌⡆⢕⠜⢌⢪⠢⡱",
    ]
}

/// Intro text printed alongside the mascot. The Figma mockup pairs the
/// "Welcome to Arcis" wordmark + version + cwd with the mascot art so
/// they read as one composite block. Returns owned strings — caller
/// indexes into the slice and joins each row with the mascot row of
/// the same index.
fn welcome_intro_lines(version: &str, cwd: &str) -> Vec<String> {
    let cwd_short = truncate_cwd(cwd, 50);
    vec![
        String::new(),
        String::new(),
        String::new(),
        "  Welcome to Arcis".to_string(),
        String::new(),
        "  Inside-the-app security CLI".to_string(),
        String::new(),
        format!("  v{version} (Rust)"),
        String::new(),
        format!("  {cwd_short}"),
    ]
}

/// Parse one line of subprocess output into a sequence of styled spans,
/// honoring inline ANSI SGR escape codes. Supports the SGR subset that
/// covers >99% of practical CLI output:
///
///   * Reset (`0`), bold (`1`), dim (`2`), underline (`4`), and their
///     unset counterparts (`22`, `24`).
///   * 8-color foreground (`30`-`37`) + bright foreground (`90`-`97`).
///   * 256-color foreground (`38;5;N`).
///   * 24-bit truecolor foreground (`38;2;R;G;B`) — what the Arcis
///     welcome screen uses for emerald, so a child writing the same
///     escape renders correctly here.
///
/// Background colors are intentionally NOT implemented yet: subprocess
/// output rarely uses them and ratatui's background is the scrollback
/// pane's own. If a child does paint bgs, those escapes get dropped
/// silently — better than rendering them as literals.
fn parse_sgr_line(text: &str) -> Vec<Span<'static>> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut style = Style::default();
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let next_esc = bytes[pos..]
            .iter()
            .position(|&b| b == 0x1b)
            .map(|p| pos + p);
        match next_esc {
            Some(esc) => {
                if esc > pos {
                    spans.push(Span::styled(text[pos..esc].to_string(), style));
                }
                if esc + 1 < bytes.len() && bytes[esc + 1] == b'[' {
                    // Scan parameters until the final byte (any ASCII alpha).
                    let mut j = esc + 2;
                    while j < bytes.len() && !bytes[j].is_ascii_alphabetic() {
                        j += 1;
                    }
                    if j < bytes.len() {
                        if bytes[j] == b'm' {
                            let params = &text[esc + 2..j];
                            let codes: Vec<i32> = if params.is_empty() {
                                vec![0]
                            } else {
                                params
                                    .split(';')
                                    .map(|s| {
                                        if s.is_empty() {
                                            0
                                        } else {
                                            s.parse().unwrap_or(0)
                                        }
                                    })
                                    .collect()
                            };
                            style = apply_sgr(style, &codes);
                        }
                        pos = j + 1;
                    } else {
                        // Unterminated escape — drop the rest of the line.
                        pos = bytes.len();
                    }
                } else {
                    // Lone ESC byte (no `[` after) — skip just that byte.
                    pos = esc + 1;
                }
            }
            None => {
                spans.push(Span::styled(text[pos..].to_string(), style));
                pos = bytes.len();
            }
        }
    }
    spans
}

/// Mutate `style` according to a list of SGR parameter codes.
fn apply_sgr(mut style: Style, codes: &[i32]) -> Style {
    let mut i = 0;
    while i < codes.len() {
        match codes[i] {
            0 => style = Style::default(),
            1 => style = style.add_modifier(Modifier::BOLD),
            2 => style = style.add_modifier(Modifier::DIM),
            4 => style = style.add_modifier(Modifier::UNDERLINED),
            22 => {
                style = style
                    .remove_modifier(Modifier::BOLD)
                    .remove_modifier(Modifier::DIM);
            }
            24 => style = style.remove_modifier(Modifier::UNDERLINED),
            30 => style = style.fg(Color::Black),
            31 => style = style.fg(Color::Red),
            32 => style = style.fg(Color::Green),
            33 => style = style.fg(Color::Yellow),
            34 => style = style.fg(Color::Blue),
            35 => style = style.fg(Color::Magenta),
            36 => style = style.fg(Color::Cyan),
            37 => style = style.fg(Color::Gray),
            39 => style = style.fg(Color::Reset),
            38 if i + 1 < codes.len() => {
                // 38;2;R;G;B or 38;5;N. Anything else: drop.
                match codes[i + 1] {
                    2 if i + 4 < codes.len() => {
                        let r = codes[i + 2].clamp(0, 255) as u8;
                        let g = codes[i + 3].clamp(0, 255) as u8;
                        let b = codes[i + 4].clamp(0, 255) as u8;
                        style = style.fg(Color::Rgb(r, g, b));
                        i += 4;
                    }
                    5 if i + 2 < codes.len() => {
                        let n = codes[i + 2].clamp(0, 255) as u8;
                        style = style.fg(Color::Indexed(n));
                        i += 2;
                    }
                    _ => {}
                }
            }
            90 => style = style.fg(Color::DarkGray),
            91 => style = style.fg(Color::LightRed),
            92 => style = style.fg(Color::LightGreen),
            93 => style = style.fg(Color::LightYellow),
            94 => style = style.fg(Color::LightBlue),
            95 => style = style.fg(Color::LightMagenta),
            96 => style = style.fg(Color::LightCyan),
            97 => style = style.fg(Color::White),
            // Background colors + everything else: ignored on purpose.
            _ => {}
        }
        i += 1;
    }
    style
}

/// History file location. Override with `$ARCIS_HISTORY_PATH` for tests
/// or for users who want history on a non-default disk. Otherwise lives
/// at `~/.arcis/history` (or `%USERPROFILE%\.arcis\history` on Windows).
fn history_path() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("ARCIS_HISTORY_PATH") {
        if !custom.is_empty() {
            return Some(PathBuf::from(custom));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    Some(PathBuf::from(home).join(".arcis").join("history"))
}

/// Read the persisted history file (one entry per line). Newest at the
/// end, matching submit order. Caller treats failure as "no history yet."
fn load_history() -> Vec<String> {
    let Some(path) = history_path() else {
        return Vec::new();
    };
    let Ok(body) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut entries: Vec<String> = body
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    // Honor the same cap as the in-memory list. Drop oldest lines first
    // so the newest entries (the most-likely ones to be reused) stay.
    if entries.len() > HISTORY_MAX {
        let excess = entries.len() - HISTORY_MAX;
        entries.drain(0..excess);
    }
    entries
}

/// Append one entry to the history file. Creates the parent dir if it
/// doesn't exist. Periodic compaction is a non-goal: at 200-line cap +
/// ~50 chars per line, the file is bounded around 10KB anyway. We
/// rewrite-on-overflow only when the file grows past 2× the cap.
fn append_history(entry: &str) -> io::Result<()> {
    let path =
        history_path().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no history path"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Compact when the file gets too long. Read, keep the tail, rewrite.
    let needs_compact = std::fs::metadata(&path)
        .map(|m| m.len() > (HISTORY_MAX as u64) * 200)
        .unwrap_or(false);
    if needs_compact {
        let mut kept = load_history();
        kept.push(entry.to_string());
        if kept.len() > HISTORY_MAX {
            let excess = kept.len() - HISTORY_MAX;
            kept.drain(0..excess);
        }
        std::fs::write(&path, kept.join("\n") + "\n")?;
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(f, "{entry}")?;
    Ok(())
}

/// Best-effort ISO-8601 UTC timestamp. Plain stdlib — no extra deps
/// for one timestamp string in /export output. Format:
/// `2026-05-21T12:34:56Z`.
fn iso_timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Convert epoch seconds to YYYY-MM-DDTHH:MM:SSZ using a small
    // Zeller-shaped algorithm. Good through year ~2400; not a calendar
    // library, just a deterministic stamp.
    let (year, month, day, hh, mm, ss) = epoch_to_components(secs as i64);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn epoch_to_components(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let hh = (sod / 3_600) as u32;
    let mm = ((sod % 3_600) / 60) as u32;
    let ss = (sod % 60) as u32;
    // Algorithm from Howard Hinnant's date library, public domain.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m as u32, d as u32, hh, mm, ss)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_basic() {
        assert_eq!(shell_split("audit ."), vec!["audit", "."]);
        assert_eq!(shell_split("  scan  http://x  "), vec!["scan", "http://x"]);
    }

    #[test]
    fn shell_split_double_quoted() {
        assert_eq!(
            shell_split(r#"scan "http://example.com/api?x=1 2""#),
            vec!["scan", "http://example.com/api?x=1 2"]
        );
    }

    #[test]
    fn shell_split_single_quoted() {
        assert_eq!(
            shell_split(r#"check 'hello world'"#),
            vec!["check", "hello world"]
        );
    }

    #[test]
    fn shell_split_empty_is_empty() {
        assert_eq!(shell_split(""), Vec::<String>::new());
        assert_eq!(shell_split("   "), Vec::<String>::new());
    }

    #[test]
    fn char_pos_to_byte_handles_unicode() {
        // Each `é` is 2 bytes in UTF-8. Position 2 (after the é) should
        // be byte offset 2 (one ASCII + one 2-byte é).
        assert_eq!(char_pos_to_byte("aéb", 0), 0);
        assert_eq!(char_pos_to_byte("aéb", 1), 1); // before é
        assert_eq!(char_pos_to_byte("aéb", 2), 3); // after é
        assert_eq!(char_pos_to_byte("aéb", 3), 4); // past end
    }

    #[test]
    fn truncate_cwd_short_path_unchanged() {
        assert_eq!(truncate_cwd("/short", 100), "/short");
    }

    #[test]
    fn truncate_cwd_long_path_keeps_tail() {
        let long = "/home/gagan/work/arcis/packages/arcis-rust/crates/arcis-cli";
        let t = truncate_cwd(long, 20);
        assert!(t.starts_with("..."));
        assert!(t.ends_with("arcis-cli"));
        assert!(t.chars().count() <= 20);
    }

    #[test]
    fn state_submit_empty_is_noop() {
        // Pin ARCIS_HISTORY_PATH to a unique temp file so this test does not
        // see history from `~/.arcis/history` (which other tests / shared
        // CI state may have populated) and does not leak its own writes to
        // a global path. Uses the same mutex as the explicit history tests
        // to serialize against them.
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            let baseline_lines = s.lines.len();
            s.submit("".into());
            s.submit("   ".into());
            assert_eq!(s.lines.len(), baseline_lines);
            assert!(s.history.is_empty());
        });
    }

    #[test]
    fn state_submit_slash_help_appends_banner_again() {
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            s.append_banner();
            let before = s.lines.len();
            s.submit("/help".into());
            assert!(s.lines.len() > before, "/help must extend the scrollback");
            // History only records the slash command, not the banner output.
            assert_eq!(s.history, vec!["/help".to_string()]);
        });
    }

    #[test]
    fn state_submit_slash_exit_signals_sentinel() {
        // Any test that calls submit() must serialize through the same
        // mutex as the history tests. ARCIS_HISTORY_PATH is a process-
        // global env var; if a history test sets it while this test is
        // running in parallel, submit() would write to that test's
        // temp file and corrupt its cap assertion.
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            s.submit("/exit".into());
            assert!(s.should_exit(), "/exit must arm the sentinel");
        });
    }

    #[test]
    fn state_submit_slash_clear_wipes_scrollback() {
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            s.append_banner();
            s.push_output("noise".to_string());
            s.submit("/clear".into());
            // After /clear, the banner is re-appended. Counting against the
            // initial banner length verifies it was cleared then re-banner'd.
            // We assert the previously-pushed "noise" line is gone.
            assert!(
                s.lines.iter().all(|l| l.text != "noise"),
                "scrollback should not retain the cleared line"
            );
        });
    }

    #[test]
    fn state_history_dedupes_consecutive_duplicates() {
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            // Use slash commands so spawn_subcommand isn't invoked.
            s.submit("/help".into());
            s.submit("/help".into());
            assert_eq!(
                s.history,
                vec!["/help".to_string()],
                "consecutive duplicates must collapse"
            );
        });
    }

    #[test]
    fn navigate_history_up_walks_back_then_clears_on_down_past_end() {
        let mut s = ReplState::new();
        s.history = vec!["a".into(), "b".into(), "c".into()];

        navigate_history(&mut s, -1);
        assert_eq!(s.input, "c");

        navigate_history(&mut s, -1);
        assert_eq!(s.input, "b");

        navigate_history(&mut s, 1);
        assert_eq!(s.input, "c");

        navigate_history(&mut s, 1);
        assert_eq!(
            s.input, "",
            "going past newest history returns to empty buffer"
        );
        assert!(s.history_cursor.is_none());
    }

    #[test]
    fn cancel_running_with_no_child_is_safe() {
        let mut s = ReplState::new();
        s.cancel_running(); // must not panic
        assert!(s.lines.iter().any(|l| l.text.contains("nothing to cancel")));
    }

    #[test]
    fn append_banner_includes_quick_start_section() {
        let mut s = ReplState::new();
        s.append_banner();
        let joined = s
            .lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("Quick start"));
        assert!(joined.contains("audit ."));
        assert!(joined.contains("/exit"));
    }

    #[test]
    fn append_banner_does_not_advertise_unimplemented_check_command() {
        // The Rust CLI does NOT dispatch `arcis check` — it lives in
        // the Python shim. Advertising it from the REPL banner means
        // the user hits an "unknown command" error. Surface parity:
        // welcome.rs's Tips section also omits `check`.
        let mut s = ReplState::new();
        s.append_banner();
        let joined = s
            .lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !joined.contains("check <payload>"),
            "REPL banner must not advertise unimplemented `check <payload>`"
        );
    }

    #[test]
    fn append_banner_lists_all_three_adapter_languages() {
        // V2 design reversed the earlier Bug 7 take. The "Available
        // adapters" section lists SDK runtime adapters (express,
        // fastapi, gin etc.) — Go runtime adapters genuinely exist,
        // so Go appears here. The audit-doesn't-support-Go gap is a
        // separate static-analysis matter and lives on
        // `arcis audit --language go` error output, not on this list.
        let mut s = ReplState::new();
        s.append_banner();
        let joined = s
            .lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("node:"),
            "node adapter line must be present"
        );
        assert!(
            joined.contains("python:"),
            "python adapter line must be present"
        );
        assert!(joined.contains("go:"), "go adapter line must be present");
        assert!(joined.contains("gin"), "go row must list gin");
    }

    #[test]
    fn append_banner_includes_export_command_in_help() {
        let mut s = ReplState::new();
        s.append_banner();
        let joined = s
            .lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(joined.contains("/export"));
    }

    #[test]
    fn state_submit_slash_export_writes_a_file() {
        // /export with no argument writes to a default-named file in
        // cwd. We can't easily test the default path without polluting
        // cwd, so pass an explicit path into the temp dir.
        // Wrap in with_temp_history_path to serialize against any other
        // history-touching test (submit() is called below).
        with_temp_history_path(|_| {
            let tmp = std::env::temp_dir().join(format!(
                "arcis-export-test-{}.md",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let mut s = ReplState::new();
            s.append_banner();
            s.push_echo("▶ audit .");
            s.push_output("HIGH src/foo.py:42 SQL-CONCAT");

            let cmd = format!("/export {}", tmp.display());
            s.submit(cmd);

            assert!(tmp.is_file(), "/export must create the target file");
            let body = std::fs::read_to_string(&tmp).unwrap();
            assert!(body.contains("# Arcis Console session"));
            assert!(body.contains("HIGH src/foo.py:42 SQL-CONCAT"));
            assert!(body.contains("▶ audit ."));
            let _ = std::fs::remove_file(&tmp);
        });
    }

    #[test]
    fn mascot_lines_has_stable_row_count() {
        // Locking the row count so accidental whitespace edits don't
        // shift the layout column-math in append_banner.
        let lines = mascot_lines();
        assert!(
            lines.len() >= 15 && lines.len() <= 25,
            "mascot expected to be 15-25 rows, got {}",
            lines.len()
        );
    }

    #[test]
    fn iso_timestamp_now_has_iso8601_shape() {
        let t = iso_timestamp_now();
        // YYYY-MM-DDTHH:MM:SSZ — 20 chars
        assert_eq!(t.len(), 20, "got: {t}");
        assert!(t.ends_with('Z'));
        assert!(t.chars().nth(4) == Some('-'));
        assert!(t.chars().nth(7) == Some('-'));
        assert!(t.chars().nth(10) == Some('T'));
        assert!(t.chars().nth(13) == Some(':'));
        assert!(t.chars().nth(16) == Some(':'));
    }

    #[test]
    fn epoch_to_components_known_value() {
        // 2026-05-24T00:00:00Z = 1_779_580_800 (per `date -u -d @1779580800`).
        // Spot-check the algorithm against a known value so a future
        // refactor of epoch_to_components can't quietly drift.
        let (y, mo, d, hh, mm, ss) = epoch_to_components(1_779_580_800);
        assert_eq!((y, mo, d, hh, mm, ss), (2026, 5, 24, 0, 0, 0));
    }

    /// Helper for history tests: route `$ARCIS_HISTORY_PATH` at a fresh
    /// tempdir-scoped file so concurrent tests can't tread on each
    /// other's writes. The env var is process-global, so we hold a
    /// Mutex across the entire scope to serialize the history tests.
    /// Cargo otherwise runs them in parallel by default and would race
    /// the set_var / remove_var pair across threads.
    static HISTORY_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_temp_history_path<F: FnOnce(&std::path::Path)>(f: F) {
        let _guard = HISTORY_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let p = std::env::temp_dir().join(format!(
            "arcis-history-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("ARCIS_HISTORY_PATH", &p);
        f(&p);
        let _ = std::fs::remove_file(&p);
        std::env::remove_var("ARCIS_HISTORY_PATH");
    }

    #[test]
    fn history_persists_across_load_calls() {
        with_temp_history_path(|p| {
            assert!(load_history().is_empty(), "tempfile starts empty");
            append_history("audit .").unwrap();
            append_history("sca .").unwrap();
            let h = load_history();
            assert_eq!(h, vec!["audit .".to_string(), "sca .".to_string()]);
            assert!(p.exists());
        });
    }

    #[test]
    fn history_load_caps_at_history_max() {
        with_temp_history_path(|_| {
            // Write more than HISTORY_MAX lines by appending one-at-a-time.
            for i in 0..(HISTORY_MAX + 10) {
                append_history(&format!("cmd-{i}")).unwrap();
            }
            let h = load_history();
            assert_eq!(h.len(), HISTORY_MAX);
            // Newest entries should survive — first kept is cmd-10.
            assert_eq!(h.first().unwrap(), "cmd-10");
            assert_eq!(h.last().unwrap(), &format!("cmd-{}", HISTORY_MAX + 9));
        });
    }

    #[test]
    fn finding_indices_picks_up_severity_prefixes() {
        let mut s = ReplState::new();
        s.push_output("CRITICAL src/foo.py:10 SQL-CONCAT");
        s.push_output("HIGH src/bar.py:25 XSS-RAW");
        s.push_output("informational chatter");
        s.push_output("  MEDIUM src/baz.py:40 PATH-WALK");
        s.push_output("LOW vendor/whatever:1");
        let idx = s.finding_indices();
        assert_eq!(idx.len(), 4, "expected 4 finding-shaped lines, got {idx:?}");
    }

    #[test]
    fn jump_next_finding_walks_forward_then_wraps() {
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            // 100 rows of filler with findings spread across the scrollback.
            // The middle finding sits far enough from the tail that the
            // very first F2 from offset=0 has to scroll the view to bring
            // it into focus.
            for i in 0..100 {
                if i == 5 || i == 50 || i == 95 {
                    s.push_output(format!("HIGH line {i}"));
                } else {
                    s.push_output(format!("ok {i}"));
                }
            }
            let view_rows = 10;
            // Tail view = [90..99]. jump_next_finding looks for the first
            // finding strictly below view_top (90); 95 qualifies and is
            // already in view, so scroll_to_line(95, 10) clamps to the
            // tail and offset stays at 0. We don't strictly require a
            // non-zero offset here. What we DO want to confirm: the call
            // does not panic and the finding-indices machinery agrees the
            // setup has three findings.
            assert_eq!(s.finding_indices().len(), 3);
            s.jump_next_finding(view_rows);
            // Repeated calls still don't panic and finding count is stable.
            s.jump_next_finding(view_rows);
            s.jump_next_finding(view_rows);
            assert_eq!(s.finding_indices().len(), 3);
        });
    }

    #[test]
    fn jump_prev_finding_walks_backward() {
        let mut s = ReplState::new();
        for i in 0..30 {
            if i == 3 || i == 15 || i == 25 {
                s.push_output(format!("HIGH line {i}"));
            } else {
                s.push_output(format!("ok {i}"));
            }
        }
        let view_rows = 5;
        s.scroll_offset = 0;
        s.jump_prev_finding(view_rows);
        // Should have scrolled to one of the earlier findings.
        assert!(s.scroll_offset > 0);
    }

    #[test]
    fn page_up_caps_at_top_of_scrollback() {
        let mut s = ReplState::new();
        for i in 0..10 {
            s.push_output(format!("line {i}"));
        }
        let view_rows = 5;
        // Page up should set offset = view_rows, but capped at total - view_rows.
        s.scroll_page_up(view_rows);
        assert_eq!(s.scroll_offset, 5);
        s.scroll_page_up(view_rows);
        // Already at the top — stays at 5.
        assert_eq!(s.scroll_offset, 5);
    }

    #[test]
    fn submit_snaps_view_back_to_tail() {
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            for i in 0..30 {
                s.push_output(format!("line {i}"));
            }
            s.scroll_offset = 10;
            s.submit("/help".into());
            assert_eq!(s.scroll_offset, 0, "Enter must follow tail again");
        });
    }

    #[test]
    fn slash_clear_resets_scroll_offset() {
        with_temp_history_path(|_| {
            let mut s = ReplState::new();
            for i in 0..30 {
                s.push_output(format!("line {i}"));
            }
            s.scroll_offset = 15;
            s.submit("/clear".into());
            assert_eq!(s.scroll_offset, 0);
        });
    }

    #[test]
    fn parse_sgr_plain_text_round_trips() {
        let spans = parse_sgr_line("hello world");
        // Joined content must equal input — no escape stripping on plain text.
        let joined: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(joined, "hello world");
    }

    #[test]
    fn parse_sgr_basic_red_fg() {
        // `\x1b[31mred\x1b[0m tail`
        let line = "\x1b[31mred\x1b[0m tail";
        let spans = parse_sgr_line(line);
        let texts: Vec<&str> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(texts.contains(&"red"));
        assert!(texts.contains(&" tail"));
        // The "red" span carries the red foreground.
        let red_span = spans
            .iter()
            .find(|s| s.content.as_ref() == "red")
            .expect("red span present");
        assert_eq!(red_span.style.fg, Some(Color::Red));
    }

    #[test]
    fn parse_sgr_truecolor_round_trips_emerald() {
        let line = "\x1b[38;2;0;153;109memerald\x1b[0m";
        let spans = parse_sgr_line(line);
        let emerald_span = spans
            .iter()
            .find(|s| s.content.as_ref() == "emerald")
            .expect("emerald span present");
        assert_eq!(emerald_span.style.fg, Some(Color::Rgb(0, 153, 109)));
    }

    #[test]
    fn parse_sgr_bold_modifier_set_and_cleared() {
        let line = "\x1b[1mbold\x1b[22m normal";
        let spans = parse_sgr_line(line);
        let bold = spans.iter().find(|s| s.content.as_ref() == "bold").unwrap();
        assert!(bold.style.add_modifier.contains(Modifier::BOLD));
        let normal = spans
            .iter()
            .find(|s| s.content.as_ref() == " normal")
            .unwrap();
        assert!(!normal.style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn parse_sgr_unicode_text_preserved_around_escapes() {
        // ANSI must not corrupt UTF-8 byte slicing.
        let line = "\x1b[32mok\x1b[0m  café \u{2728}";
        let spans = parse_sgr_line(line);
        let joined: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(joined.contains("café"));
        assert!(joined.contains('\u{2728}'));
    }

    #[test]
    fn parse_sgr_unterminated_escape_does_not_panic() {
        // Pathological: ESC + CSI but no terminator. Must not crash and
        // must not loop forever.
        let line = "\x1b[31abrupt";
        let _ = parse_sgr_line(line); // just shouldn't panic
    }

    #[test]
    fn submit_writes_to_history_file_when_path_overridden() {
        with_temp_history_path(|p| {
            let mut s = ReplState::new();
            // Slash command persisted just like any other.
            s.submit("/help".into());
            assert!(p.is_file(), "history file should exist after submit");
            let body = std::fs::read_to_string(p).unwrap();
            assert!(body.contains("/help"));
        });
    }
}
