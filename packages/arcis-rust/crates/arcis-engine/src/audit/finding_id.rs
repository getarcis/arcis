//! Deterministic finding IDs.
//!
//! Implements cli-audit.md Phase B item 10. Each finding gets a stable
//! id `<RULE_ID>-<16hex>` derived from `(rule_id, relpath, line,
//! snippet)`. Two runs over the same source produce byte-equal output;
//! a run on Windows and a run on Linux over the same repo produce the
//! same ids. This is the foundation for baseline diffing (item 9) and
//! SARIF de-dupe in GitHub Code Scanning.
//!
//! ## Hash inputs
//!
//! * `rule_id` — verbatim.
//! * `relpath` — file path with backslashes flipped to `/`, leading
//!   `./` trimmed. Computed against the audit's target root so a
//!   `cd repo && arcis audit .` and `arcis audit /abs/repo` produce
//!   the same id.
//! * `line` — 1-indexed line number, decimal.
//! * `snippet` — with trailing whitespace stripped. Editors auto-strip
//!   trailing spaces on save; preserving them would invalidate every
//!   baseline id on a `git config core.whitespace` flip. Leading
//!   whitespace is preserved — indentation carries information.
//!
//! Inputs are joined with NUL (`\0`) so a `:` inside a Windows drive
//! letter, a `-` inside a rule id, or a structural char in a snippet
//! can't shift hash boundaries via concatenation collisions.
//!
//! ## Output shape
//!
//! `<RULE_ID>-<16hex>` — 16 lowercase hex chars (64-bit fingerprint).
//! 64 bits is wide enough that a single repo with ~100k findings hits
//! a collision with probability < 1e-10 (birthday). Snyk and Semgrep
//! emit the same width.

use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::engine::Finding;

/// Compute the deterministic id for a finding.
///
/// Inputs are NUL-joined and SHA-256 hashed; the first 8 bytes (16
/// hex chars, lowercase) form the fingerprint. The snippet has
/// trailing whitespace trimmed before hashing per the cli-audit.md
/// item 10 amendment.
pub fn compute(rule_id: &str, relpath: &str, line: usize, snippet: &str) -> String {
    let snippet_trimmed = snippet.trim_end();
    let line_str = line.to_string();
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(relpath.as_bytes());
    hasher.update(b"\0");
    hasher.update(line_str.as_bytes());
    hasher.update(b"\0");
    hasher.update(snippet_trimmed.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for byte in &digest[..8] {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("{rule_id}-{hex}")
}

/// Normalize a finding's file path to a stable relpath against
/// `target_root`. Strips the absolute target_root prefix, flips
/// backslashes to forward slashes, removes a leading `./`. Falls back
/// to the input path with separators flipped if the prefix can't be
/// stripped (e.g. cross-drive on Windows, or a finding outside the
/// target tree).
pub fn normalize_relpath(file: &Path, target_root: &Path) -> String {
    let file_abs = make_absolute(file);
    let root_abs = make_absolute(target_root);

    // Single-file scan: target_root is the file itself, so the relpath
    // base is its parent (relpath becomes the bare filename).
    let base = if root_abs.is_file() {
        root_abs.parent().map(Path::to_path_buf).unwrap_or(root_abs)
    } else {
        root_abs
    };

    let stripped: PathBuf = file_abs
        .strip_prefix(&base)
        .map(Path::to_path_buf)
        .unwrap_or(file_abs);
    flip_to_unix_separators(&stripped.to_string_lossy())
}

/// Fill in `id` on every finding, computing relpaths against
/// `target_root`. Idempotent — overwrites whatever was there.
pub fn assign_ids(findings: &mut [Finding], target_root: &Path) {
    for f in findings.iter_mut() {
        let relpath = normalize_relpath(Path::new(&f.file), target_root);
        f.id = compute(f.rule_id, &relpath, f.line, &f.snippet);
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Mirror Python's `os.path.abspath` — does NOT follow symlinks
/// (unlike `Path::canonicalize`, which would also fail on missing
/// paths during testing). Resolves `..` and `.` lexically.
fn make_absolute(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    normalize_components(&abs)
}

fn normalize_components(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn flip_to_unix_separators(s: &str) -> String {
    let flipped = s.replace('\\', "/");
    flipped
        .strip_prefix("./")
        .map(str::to_string)
        .unwrap_or(flipped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::engine::Finding;
    use crate::audit::rules::Severity;
    use tempfile::TempDir;

    fn sample(file: &str, line: usize, snippet: &str) -> Finding {
        Finding {
            rule_id: "YAML-UNSAFE",
            severity: Severity::High,
            message: "yaml.load() without SafeLoader",
            file: file.to_string(),
            line,
            snippet: snippet.to_string(),
            id: String::new(),
        }
    }

    // ── compute ────────────────────────────────────────────────────────

    #[test]
    fn compute_is_deterministic() {
        let a = compute("YAML-UNSAFE", "src/a.py", 10, "yaml.load(f)");
        let b = compute("YAML-UNSAFE", "src/a.py", 10, "yaml.load(f)");
        assert_eq!(a, b);
    }

    #[test]
    fn compute_changes_with_rule_id() {
        let a = compute("YAML-UNSAFE", "src/a.py", 10, "x");
        let b = compute("PICKLE-LOAD", "src/a.py", 10, "x");
        assert_ne!(a, b);
        assert!(a.starts_with("YAML-UNSAFE-"));
        assert!(b.starts_with("PICKLE-LOAD-"));
    }

    #[test]
    fn compute_changes_with_relpath() {
        let a = compute("X", "src/a.py", 1, "s");
        let b = compute("X", "src/b.py", 1, "s");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_changes_with_line() {
        let a = compute("X", "src/a.py", 1, "s");
        let b = compute("X", "src/a.py", 2, "s");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_changes_with_snippet() {
        let a = compute("X", "src/a.py", 1, "yaml.load(f)");
        let b = compute("X", "src/a.py", 1, "yaml.load(g)");
        assert_ne!(a, b);
    }

    #[test]
    fn compute_strips_trailing_whitespace_from_snippet() {
        // Editors auto-strip trailing whitespace; baseline ids must
        // survive that. Per cli-audit.md item 10 amendment.
        let a = compute("X", "src/a.py", 1, "yaml.load(f)");
        let b = compute("X", "src/a.py", 1, "yaml.load(f)   ");
        let c = compute("X", "src/a.py", 1, "yaml.load(f)\t");
        let d = compute("X", "src/a.py", 1, "yaml.load(f)\r\n");
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a, d);
    }

    #[test]
    fn compute_does_not_strip_leading_whitespace() {
        // Indent carries information. A finding inside a function body
        // shouldn't share an id with a top-level one if their snippets
        // happen to share a tail.
        let a = compute("X", "src/a.py", 1, "yaml.load(f)");
        let b = compute("X", "src/a.py", 1, "  yaml.load(f)");
        assert_ne!(a, b);
    }

    #[test]
    fn id_format_matches_pattern() {
        let id = compute("YAML-UNSAFE", "src/a.py", 10, "yaml.load(f)");
        let rest = id.strip_prefix("YAML-UNSAFE-").expect("rule id prefix");
        assert_eq!(rest.len(), 16, "fingerprint width is 16 hex chars");
        assert!(
            rest.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "fingerprint must be lowercase hex: {rest}"
        );
    }

    #[test]
    fn nul_separator_prevents_concatenation_collision() {
        // Without a separator, ("AB", "C") and ("A", "BC") would hash
        // identically. NUL byte rules that out.
        let a = compute("AB", "C", 1, "x");
        let b = compute("A", "BC", 1, "x");
        assert_ne!(a, b);
    }

    // ── flip_to_unix_separators ────────────────────────────────────────

    #[test]
    fn flip_separators_replaces_backslashes() {
        assert_eq!(flip_to_unix_separators("a\\b\\c"), "a/b/c");
    }

    #[test]
    fn flip_separators_strips_leading_dot_slash() {
        assert_eq!(flip_to_unix_separators("./a/b"), "a/b");
        assert_eq!(flip_to_unix_separators(".\\a\\b"), "a/b");
    }

    #[test]
    fn flip_separators_passes_clean_path_unchanged() {
        assert_eq!(flip_to_unix_separators("a/b/c.py"), "a/b/c.py");
    }

    // ── normalize_relpath ──────────────────────────────────────────────

    #[test]
    fn normalize_relpath_strips_target_root_dir() {
        let td = TempDir::new().unwrap();
        let f = td.path().join("src").join("a.py");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "").unwrap();
        let rel = normalize_relpath(&f, td.path());
        assert_eq!(rel, "src/a.py");
    }

    #[test]
    fn normalize_relpath_strips_target_root_file_to_filename() {
        // Single-file scan: relpath = bare filename.
        let td = TempDir::new().unwrap();
        let f = td.path().join("a.py");
        std::fs::write(&f, "").unwrap();
        let rel = normalize_relpath(&f, &f);
        assert_eq!(rel, "a.py");
    }

    #[test]
    fn normalize_relpath_no_leading_dot_slash() {
        let td = TempDir::new().unwrap();
        let f = td.path().join("a.py");
        std::fs::write(&f, "").unwrap();
        let rel = normalize_relpath(&f, td.path());
        assert!(
            !rel.starts_with("./"),
            "relpath must not start with ./: {rel}"
        );
        assert!(!rel.starts_with(".\\"));
    }

    #[test]
    fn normalize_relpath_outside_target_falls_back_to_input() {
        // A finding path that doesn't sit under target_root should
        // still produce a string (no panic, no canonicalize). Used
        // when a follow-symlink scenario or a cross-drive Windows
        // case escapes the prefix.
        let td = TempDir::new().unwrap();
        let other = TempDir::new().unwrap();
        let f = other.path().join("a.py");
        std::fs::write(&f, "").unwrap();
        let rel = normalize_relpath(&f, td.path());
        // We don't assert exact contents (cwd-dependent). Only that
        // the function returned something non-empty without panicking.
        assert!(!rel.is_empty());
    }

    // ── assign_ids ─────────────────────────────────────────────────────

    #[test]
    fn assign_ids_fills_id_field() {
        let td = TempDir::new().unwrap();
        let f = td.path().join("src").join("a.py");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "").unwrap();
        let mut findings = vec![sample(f.to_string_lossy().as_ref(), 1, "yaml.load(f)")];
        assert!(findings[0].id.is_empty());
        assign_ids(&mut findings, td.path());
        assert!(!findings[0].id.is_empty());
        assert!(findings[0].id.starts_with("YAML-UNSAFE-"));
    }

    #[test]
    fn assign_ids_is_idempotent() {
        let td = TempDir::new().unwrap();
        let f = td.path().join("a.py");
        std::fs::write(&f, "").unwrap();
        let mut findings = vec![sample(f.to_string_lossy().as_ref(), 1, "x")];
        assign_ids(&mut findings, td.path());
        let first = findings[0].id.clone();
        assign_ids(&mut findings, td.path());
        assert_eq!(findings[0].id, first);
    }

    #[test]
    fn assign_ids_two_targets_same_relpath_same_id() {
        // Two different repos, same file layout, same line/snippet
        // should produce the same id. This is what makes baselines
        // portable across machines and CI runners.
        let td_a = TempDir::new().unwrap();
        let td_b = TempDir::new().unwrap();
        let fa = td_a.path().join("src").join("a.py");
        let fb = td_b.path().join("src").join("a.py");
        std::fs::create_dir_all(fa.parent().unwrap()).unwrap();
        std::fs::create_dir_all(fb.parent().unwrap()).unwrap();
        std::fs::write(&fa, "").unwrap();
        std::fs::write(&fb, "").unwrap();

        let mut a = vec![sample(fa.to_string_lossy().as_ref(), 7, "yaml.load(f)")];
        let mut b = vec![sample(fb.to_string_lossy().as_ref(), 7, "yaml.load(f)")];
        assign_ids(&mut a, td_a.path());
        assign_ids(&mut b, td_b.path());
        assert_eq!(a[0].id, b[0].id);
    }

    #[test]
    fn assign_ids_different_relpath_different_id() {
        let td = TempDir::new().unwrap();
        let f1 = td.path().join("src").join("a.py");
        let f2 = td.path().join("src").join("b.py");
        std::fs::create_dir_all(f1.parent().unwrap()).unwrap();
        std::fs::write(&f1, "").unwrap();
        std::fs::write(&f2, "").unwrap();
        let mut findings = vec![
            sample(f1.to_string_lossy().as_ref(), 1, "x"),
            sample(f2.to_string_lossy().as_ref(), 1, "x"),
        ];
        assign_ids(&mut findings, td.path());
        assert_ne!(findings[0].id, findings[1].id);
    }
}
