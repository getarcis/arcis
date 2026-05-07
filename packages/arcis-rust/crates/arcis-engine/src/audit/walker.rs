//! File walker for the audit module.
//!
//! Walks the target tree, prunes [`SKIP_DIRS`], honours `.arcisignore`,
//! `.gitignore`, and `.git/info/exclude`, and returns paths whose
//! extensions map to a known [`Language`] via
//! [`Language::from_extension`].
//!
//! Uses BurntSushi's `ignore` crate (same engine as ripgrep) for native
//! gitignore stacking: per-directory files apply to their subtree,
//! `**`, negation (`!important.js`), and trailing-comment syntax all
//! work without a hand-rolled matcher. The walk was previously
//! `walkdir`-based for byte-equal parity with Python's `os.walk` (which
//! does NOT honor gitignore); that constraint went away when the Python
//! audit was cut in commit `a9353af`.
//!
//! Symlinks are not followed — matches the post-fix Python behaviour
//! from commit `e778439`.
//!
//! ## Hardcoded fallback ([`SKIP_DIRS`])
//!
//! 13 directory names are pruned regardless of ignore-file presence
//! (e.g. `node_modules`, `.git`, `__pycache__`, `dist`). This is the
//! belt-and-braces safety net for: (a) projects with no `.gitignore`,
//! (b) users who pass `--no-ignore` to bypass ignore files, (c)
//! always-junk dirs that nobody ever wants to scan deliberately. It
//! applies to BOTH the main walk and the `--no-ignore` count walk.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use super::rules::Language;

/// Directory names pruned during the walk. Bit-identical to Python
/// `SKIP_DIRS` in `audit.py`.
pub const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "env",
    ".env",
    "site-packages",
];

fn is_skipped_dir_name(name: &str) -> bool {
    SKIP_DIRS.contains(&name)
}

/// Detect the language of a single file path. Wraps
/// [`Language::from_extension`] with [`Path::extension`]. Returns
/// `None` for files with no extension or extensions outside
/// `LANGUAGE_MAP`.
pub fn detect_language(path: &Path) -> Option<Language> {
    path.extension()
        .and_then(|s| s.to_str())
        .and_then(Language::from_extension)
}

/// Options controlling which ignore-file machinery is honoured during
/// the walk. Patterns in `.arcisignore` and `.gitignore` follow standard
/// gitignore syntax via the `ignore` crate — `**` glob, `!important.js`
/// negation, per-directory scoping, `#` comments, and trailing-slash
/// directory-only matchers all work without further configuration.
///
/// Default is **both on**, matching ripgrep / Semgrep convention. Users
/// expect gitignored generated files / build artifacts / vendored deps
/// to skip without extra flags.
///
/// CLI flag mapping:
/// * `--no-ignore` disables both → `IgnoreOptions { use_arcisignore: false, use_gitignore: false }`
/// * `--no-gitignore` disables gitignore only → `IgnoreOptions { use_arcisignore: true, use_gitignore: false }`
///
/// There is intentionally no `--no-arcisignore` flag: gitignore-only-off
/// is a real monorepo case (vendored dirs with broad `.gitignore` lines
/// you do want scanned), arcisignore-only-off has no use case (just
/// delete the file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoreOptions {
    /// Honor `.arcisignore` files at any directory level.
    pub use_arcisignore: bool,
    /// Honor `.gitignore`, `.git/info/exclude`, and the user's global
    /// gitignore.
    pub use_gitignore: bool,
}

impl Default for IgnoreOptions {
    fn default() -> Self {
        Self {
            use_arcisignore: true,
            use_gitignore: true,
        }
    }
}

/// Output of [`collect_files_with_options`]: the kept files plus a
/// count of files that *would* have been collected but were excluded
/// by an ignore rule. Mirrors the [`super::engine::FileResult`]
/// suppressed-count pattern used by item 6.
///
/// `ignored` counts only files whose extension maps to a known
/// [`Language`] (and matches any active language filter) — directories
/// pruned by an ignore rule contribute one entry per ignored
/// language-matching file inside them, NOT one per directory. The
/// number is stable across runs.
///
/// `ignored == 0` whenever both `use_arcisignore` and `use_gitignore`
/// are false, since the count is computed as
/// `total_after_skip_dirs - kept_after_ignore_rules`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WalkResult {
    pub files: Vec<PathBuf>,
    pub ignored: usize,
}

/// Collect scannable source files under `path` (back-compat wrapper).
///
/// Equivalent to [`collect_files_with_options`] with default
/// [`IgnoreOptions`] (both `.arcisignore` and `.gitignore` honoured),
/// returning only the kept files. Existing engine + test callers that
/// don't care about the ignored count keep working unchanged.
pub fn collect_files(path: &Path, language: Option<Language>) -> Vec<PathBuf> {
    collect_files_with_options(path, language, &IgnoreOptions::default()).files
}

/// Collect scannable source files under `path` with explicit ignore
/// configuration.
///
/// * If `path` is a single file, returns `[path]` if its extension
///   maps to a known [`Language`] and matches the optional `language`
///   filter; otherwise empty. Ignore files are NOT consulted in this
///   fast path — the user explicitly named the file.
/// * If `path` is a directory, walks recursively via
///   [`ignore::WalkBuilder`]:
///   - prunes any directory whose name appears in [`SKIP_DIRS`]
///     (always, regardless of `opts`),
///   - honours `.arcisignore` per `opts.use_arcisignore`,
///   - honours `.gitignore` + `.git/info/exclude` + global gitignore
///     per `opts.use_gitignore`,
///   - yields files with a known extension matching the optional
///     `language` filter.
/// * Walk order is unspecified. Final finding output is sorted by
///   `(severity, file, line)` downstream so the unsorted walk order
///   doesn't affect byte-equality of the JSON / SARIF doc.
/// * If `path` doesn't exist, returns empty (the CLI checks existence
///   up-front and emits a friendlier error; a defensive empty here
///   keeps the engine API total).
///
/// The `ignored` count in the returned [`WalkResult`] is computed via
/// a second walk with all ignore-file machinery disabled; the diff is
/// the contribution of the ignore-file rules. Both walks share
/// [`SKIP_DIRS`] + extension filter so "files always pruned" don't
/// inflate the ignored count. See [`WalkResult`] for semantics.
pub fn collect_files_with_options(
    path: &Path,
    language: Option<Language>,
    opts: &IgnoreOptions,
) -> WalkResult {
    if path.is_file() {
        let files = match detect_language(path) {
            Some(lang) if language.is_none() || language == Some(lang) => {
                vec![path.to_path_buf()]
            }
            _ => Vec::new(),
        };
        return WalkResult { files, ignored: 0 };
    }
    if !path.is_dir() {
        return WalkResult::default();
    }

    let files = walk_with_ignore(path, language, opts);

    // Compute `ignored` via a second walk with all ignore machinery
    // disabled. The diff is the contribution of `.arcisignore` +
    // `.gitignore` + `.git/info/exclude`. Acceptable two-walk overhead:
    // the second pass is OS-cached and audit's hot path is per-line
    // pattern matching, not directory traversal. Revisit if/when item
    // 11 (parallel scanning) lands — at that point a single-walk
    // visitor that records both kept + skipped becomes worth the
    // complexity.
    let ignored = if opts.use_arcisignore || opts.use_gitignore {
        let raw = IgnoreOptions {
            use_arcisignore: false,
            use_gitignore: false,
        };
        let total = walk_with_ignore(path, language, &raw).len();
        total.saturating_sub(files.len())
    } else {
        0
    };

    WalkResult { files, ignored }
}

/// Internal walker: one pass with the given [`IgnoreOptions`]. Returns
/// kept files only; counting is layered on top in
/// [`collect_files_with_options`].
fn walk_with_ignore(path: &Path, language: Option<Language>, opts: &IgnoreOptions) -> Vec<PathBuf> {
    let mut builder = WalkBuilder::new(path);
    builder
        .follow_links(false)
        // Don't auto-skip dotfiles. SKIP_DIRS already prunes the
        // always-junk hidden dirs (`.git`, `.venv`, `.tox`,
        // `.pytest_cache`, `.mypy_cache`, `.env`); leaving the
        // ignore-crate `hidden` filter on would silently start skipping
        // every `.foo.py` in a project, a behavior change from the
        // previous walkdir-based traversal.
        .hidden(false)
        // `.gitignore` machinery — three knobs go together. Disabling
        // honors `--no-gitignore` AND `--no-ignore`.
        .git_ignore(opts.use_gitignore)
        .git_global(opts.use_gitignore)
        .git_exclude(opts.use_gitignore)
        // Walk up from `path` to find ancestor `.gitignore` / global
        // git config. Off when gitignore is off so the second
        // count-walk in `collect_files_with_options` doesn't pick up
        // an ancestor `.gitignore` outside the user's target tree.
        .parents(opts.use_gitignore)
        // `require_git(false)` so `.gitignore` is honoured even when
        // the target dir isn't a real git working tree (no `.git/`
        // marker). This is the documented escape hatch for the
        // tempdir-based test pattern AND for users running audit on
        // exported tarballs / vendored snapshots.
        .require_git(false)
        // `.ignore` (rg-style) AND any custom-ignore filename are
        // gated together by this flag. Disabling honors `--no-ignore`.
        .ignore(opts.use_arcisignore);
    if opts.use_arcisignore {
        builder.add_custom_ignore_filename(".arcisignore");
    }
    builder.filter_entry(|e| {
        // Always keep the root: SKIP_DIRS prunes CHILDREN only. If a
        // user runs `arcis audit node_modules/`, walk it.
        if e.depth() == 0 {
            return true;
        }
        if e.file_type().is_some_and(|t| t.is_dir()) {
            return !is_skipped_dir_name(&e.file_name().to_string_lossy());
        }
        true
    });

    let mut files = Vec::new();
    for result in builder.build() {
        let Ok(entry) = result else { continue };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let p = entry.path();
        if let Some(lang) = detect_language(p) {
            if language.is_none() || language == Some(lang) {
                files.push(p.to_path_buf());
            }
        }
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, rel: &str, content: &str) -> PathBuf {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, content).unwrap();
        path
    }

    fn names(paths: &[PathBuf]) -> Vec<String> {
        let mut names: Vec<String> = paths
            .iter()
            .filter_map(|p| p.file_name().and_then(|s| s.to_str()).map(String::from))
            .collect();
        names.sort();
        names
    }

    #[test]
    fn detect_language_from_paths() {
        assert_eq!(detect_language(Path::new("foo.py")), Some(Language::Python));
        assert_eq!(detect_language(Path::new("foo.PY")), Some(Language::Python));
        assert_eq!(
            detect_language(Path::new("foo.tsx")),
            Some(Language::TypeScript)
        );
        assert_eq!(
            detect_language(Path::new("foo.mjs")),
            Some(Language::JavaScript)
        );
        assert_eq!(detect_language(Path::new("foo.rs")), None);
        assert_eq!(detect_language(Path::new(".bashrc")), None);
        assert_eq!(detect_language(Path::new("Makefile")), None);
    }

    #[test]
    fn skip_dirs_constant_matches_python_audit_py() {
        // 13 entries, bit-identical to audit.py SKIP_DIRS. If a future
        // refactor on the Python side adds or drops one, this set
        // diverges and parity breaks — pin both shapes here.
        let mut expected = vec![
            "node_modules",
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "dist",
            "build",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            "env",
            ".env",
            "site-packages",
        ];
        expected.sort_unstable();
        let mut actual: Vec<&str> = SKIP_DIRS.to_vec();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn single_file_known_extension_no_filter() {
        let td = TempDir::new().unwrap();
        let f = write(td.path(), "main.py", "x = 1\n");
        let r = collect_files(&f, None);
        assert_eq!(r, vec![f]);
    }

    #[test]
    fn single_file_unknown_extension_returns_empty() {
        let td = TempDir::new().unwrap();
        let f = write(td.path(), "README.md", "# hi\n");
        assert!(collect_files(&f, None).is_empty());
    }

    #[test]
    fn single_file_with_language_mismatch_returns_empty() {
        let td = TempDir::new().unwrap();
        let f = write(td.path(), "main.py", "");
        // Asked for JavaScript on a Python file → empty.
        assert!(collect_files(&f, Some(Language::JavaScript)).is_empty());
    }

    #[test]
    fn nonexistent_path_returns_empty() {
        let td = TempDir::new().unwrap();
        assert!(collect_files(&td.path().join("does-not-exist"), None).is_empty());
    }

    #[test]
    fn directory_collects_known_extensions() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.py", "");
        write(td.path(), "b.js", "");
        write(td.path(), "c.ts", "");
        write(td.path(), "d.txt", ""); // unknown ext
        write(td.path(), "sub/e.tsx", "");
        write(td.path(), "sub/nested/f.cjs", "");
        let r = collect_files(td.path(), None);
        assert_eq!(names(&r), vec!["a.py", "b.js", "c.ts", "e.tsx", "f.cjs"]);
    }

    #[test]
    fn skip_dirs_pruned() {
        let td = TempDir::new().unwrap();
        write(td.path(), "src/a.py", "");
        write(td.path(), "node_modules/b.js", "");
        write(td.path(), ".git/c.py", "");
        write(td.path(), "__pycache__/d.py", "");
        write(td.path(), ".venv/lib/e.py", "");
        write(td.path(), "dist/f.js", "");
        write(td.path(), "build/g.js", "");
        write(td.path(), "site-packages/h.py", "");
        let r = collect_files(td.path(), None);
        assert_eq!(names(&r), vec!["a.py"]);
    }

    #[test]
    fn skip_dirs_only_prunes_children_not_root() {
        // If user explicitly points at a SKIP_DIRS-named root, walk it
        // anyway — Python's `dirs[:] = ...` only filters children of
        // the current dir, never the root itself.
        let td = TempDir::new().unwrap();
        let root = td.path().join("node_modules");
        write(&root, "x.js", "");
        write(&root, "deep/y.js", "");
        let r = collect_files(&root, None);
        assert_eq!(names(&r), vec!["x.js", "y.js"]);
    }

    #[test]
    fn language_filter_python_only() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.py", "");
        write(td.path(), "b.js", "");
        write(td.path(), "c.ts", "");
        write(td.path(), "d.tsx", "");
        write(td.path(), "e.mjs", "");
        let r = collect_files(td.path(), Some(Language::Python));
        assert_eq!(names(&r), vec!["a.py"]);
    }

    #[test]
    fn language_filter_typescript_includes_tsx_only() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.ts", "");
        write(td.path(), "b.tsx", "");
        write(td.path(), "c.js", "");
        write(td.path(), "d.jsx", "");
        let r = collect_files(td.path(), Some(Language::TypeScript));
        assert_eq!(names(&r), vec!["a.ts", "b.tsx"]);
    }

    #[test]
    fn language_filter_javascript_includes_jsx_mjs_cjs() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.js", "");
        write(td.path(), "b.jsx", "");
        write(td.path(), "c.mjs", "");
        write(td.path(), "d.cjs", "");
        write(td.path(), "e.ts", ""); // excluded
        let r = collect_files(td.path(), Some(Language::JavaScript));
        assert_eq!(names(&r), vec!["a.js", "b.jsx", "c.mjs", "d.cjs"]);
    }

    #[test]
    fn empty_directory_returns_empty() {
        let td = TempDir::new().unwrap();
        let r = collect_files(td.path(), None);
        assert!(r.is_empty());
    }

    #[test]
    fn deeply_nested_tree_collects_correctly() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a/b/c/d/e/deep.py", "");
        write(td.path(), "a/b/c/d/e/skip.txt", "");
        let r = collect_files(td.path(), None);
        assert_eq!(names(&r), vec!["deep.py"]);
    }

    // ── ignore-file machinery (cli-audit.md item 7) ───────────────────

    /// Canary: WITHOUT a `.git/` marker, `.gitignore` must still be
    /// honored. We rely on `WalkBuilder::require_git(false)` to make
    /// this work in tempdir tests AND in tarball-style targets that
    /// are not git working trees.
    #[test]
    fn gitignore_respected_by_default() {
        let td = TempDir::new().unwrap();
        write(td.path(), "src/keep.py", "");
        write(td.path(), "src/skip.py", "");
        write(td.path(), ".gitignore", "skip.py\n");
        let r = collect_files_with_options(td.path(), None, &IgnoreOptions::default());
        assert_eq!(names(&r.files), vec!["keep.py"]);
        assert_eq!(r.ignored, 1, "skip.py should be counted as ignored");
    }

    #[test]
    fn arcisignore_at_root_excludes_glob_pattern() {
        let td = TempDir::new().unwrap();
        write(td.path(), "src/main.ts", "");
        write(td.path(), "src/foo.generated.ts", "");
        write(td.path(), "src/bar.generated.ts", "");
        write(td.path(), ".arcisignore", "*.generated.ts\n");
        let r = collect_files_with_options(td.path(), None, &IgnoreOptions::default());
        assert_eq!(names(&r.files), vec!["main.ts"]);
        assert_eq!(r.ignored, 2);
    }

    #[test]
    fn arcisignore_in_subdir_scopes_to_subdir() {
        // `.arcisignore` semantics mirror `.gitignore`: a file at
        // `pkg/.arcisignore` only applies under `pkg/`. A pattern like
        // `*.gen.ts` in that file must NOT exclude top-level
        // `other.gen.ts`.
        let td = TempDir::new().unwrap();
        write(td.path(), "pkg/keep.ts", "");
        write(td.path(), "pkg/foo.gen.ts", ""); // excluded by pkg/.arcisignore
        write(td.path(), "pkg/.arcisignore", "*.gen.ts\n");
        write(td.path(), "other.gen.ts", ""); // NOT excluded — directive scope is pkg/
        let r = collect_files_with_options(td.path(), None, &IgnoreOptions::default());
        let mut names = names(&r.files);
        names.sort();
        assert_eq!(names, vec!["keep.ts", "other.gen.ts"]);
        assert_eq!(r.ignored, 1);
    }

    #[test]
    fn arcisignore_negation_unexcludes() {
        let td = TempDir::new().unwrap();
        write(td.path(), "src/a.js", "");
        write(td.path(), "src/b.js", "");
        write(td.path(), "src/important.js", "");
        write(td.path(), ".arcisignore", "*.js\n!important.js\n");
        let r = collect_files_with_options(td.path(), None, &IgnoreOptions::default());
        // Only `important.js` survives — the negation un-ignores it
        // even after `*.js` would have excluded it.
        assert_eq!(names(&r.files), vec!["important.js"]);
        assert_eq!(r.ignored, 2);
    }

    #[test]
    fn arcisignore_double_star_glob_excludes_nested() {
        // Use `generated/` not `build/`: `build` is in SKIP_DIRS, so a
        // hardcoded prune would steal credit from the `.arcisignore`
        // rule and the test wouldn't actually exercise the `**` glob
        // path. `generated/` is not in SKIP_DIRS, so without the
        // arcisignore rule both nested `auto.py` files would be
        // collected.
        let td = TempDir::new().unwrap();
        write(td.path(), "src/main.py", "");
        write(td.path(), "src/generated/a.py", "");
        write(td.path(), "lib/generated/nested/b.py", "");
        write(td.path(), ".arcisignore", "**/generated/**\n");
        let r = collect_files_with_options(td.path(), None, &IgnoreOptions::default());
        assert_eq!(names(&r.files), vec!["main.py"]);
        assert_eq!(r.ignored, 2);
    }

    #[test]
    fn no_ignore_disables_both_files() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.py", "");
        write(td.path(), "b.py", "");
        write(td.path(), "c.py", "");
        write(td.path(), ".gitignore", "a.py\n");
        write(td.path(), ".arcisignore", "b.py\n");
        let opts = IgnoreOptions {
            use_arcisignore: false,
            use_gitignore: false,
        };
        let r = collect_files_with_options(td.path(), None, &opts);
        let mut names = names(&r.files);
        names.sort();
        assert_eq!(names, vec!["a.py", "b.py", "c.py"]);
        assert_eq!(
            r.ignored, 0,
            "ignored count must be 0 when both ignore knobs are off"
        );
    }

    #[test]
    fn no_gitignore_keeps_arcisignore() {
        let td = TempDir::new().unwrap();
        write(td.path(), "a.py", "");
        write(td.path(), "b.py", "");
        write(td.path(), "c.py", "");
        write(td.path(), ".gitignore", "a.py\n"); // disabled
        write(td.path(), ".arcisignore", "b.py\n"); // still active
        let opts = IgnoreOptions {
            use_arcisignore: true,
            use_gitignore: false,
        };
        let r = collect_files_with_options(td.path(), None, &opts);
        let mut names = names(&r.files);
        names.sort();
        assert_eq!(names, vec!["a.py", "c.py"]);
        assert_eq!(r.ignored, 1, "only b.py from .arcisignore counts");
    }

    #[test]
    fn skip_dirs_still_skip_with_no_ignore_files() {
        // Belt-and-braces: `target/`, `node_modules/`, etc. must still
        // prune even when the user runs `--no-ignore` on a fresh
        // checkout with no `.gitignore`. Otherwise `arcis audit
        // --no-ignore .` on a Node repo would walk a 100k-file
        // node_modules tree.
        let td = TempDir::new().unwrap();
        write(td.path(), "src/a.py", "");
        write(td.path(), "node_modules/b.py", "");
        write(td.path(), ".git/c.py", "");
        let opts = IgnoreOptions {
            use_arcisignore: false,
            use_gitignore: false,
        };
        let r = collect_files_with_options(td.path(), None, &opts);
        assert_eq!(names(&r.files), vec!["a.py"]);
        assert_eq!(r.ignored, 0);
    }

    #[test]
    fn walkresult_ignored_count_matches_diff() {
        // Pin the `ignored = total - kept` invariant explicitly so a
        // future refactor can't silently break the count semantics.
        let td = TempDir::new().unwrap();
        for i in 0..5 {
            write(td.path(), &format!("keep_{i}.py"), "");
        }
        for i in 0..3 {
            write(td.path(), &format!("skip_{i}.py"), "");
        }
        write(td.path(), ".gitignore", "skip_*.py\n");
        let r = collect_files_with_options(td.path(), None, &IgnoreOptions::default());
        let raw = collect_files_with_options(
            td.path(),
            None,
            &IgnoreOptions {
                use_arcisignore: false,
                use_gitignore: false,
            },
        );
        assert_eq!(r.files.len(), 5);
        assert_eq!(raw.files.len(), 8);
        assert_eq!(r.ignored, raw.files.len() - r.files.len());
    }

    #[test]
    fn single_file_path_unaffected_by_ignore_options() {
        // The single-file fast path doesn't consult ignore files —
        // the user explicitly named the file. Assert that a file
        // matching its parent's `.gitignore` still scans when passed
        // directly. Regression guard: if someone naively threads
        // ignore-file logic into the fast path, this test catches it.
        let td = TempDir::new().unwrap();
        let target = write(td.path(), "skip.py", "");
        write(td.path(), ".gitignore", "skip.py\n");
        let r = collect_files_with_options(&target, None, &IgnoreOptions::default());
        assert_eq!(r.files, vec![target]);
        assert_eq!(r.ignored, 0);
    }

    #[test]
    fn back_compat_collect_files_default_honours_gitignore() {
        // The existing `collect_files` wrapper uses default
        // IgnoreOptions, so any caller that doesn't migrate gets
        // gitignore semantics for free. Pin that contract.
        let td = TempDir::new().unwrap();
        write(td.path(), "keep.py", "");
        write(td.path(), "skip.py", "");
        write(td.path(), ".gitignore", "skip.py\n");
        let files = collect_files(td.path(), None);
        assert_eq!(names(&files), vec!["keep.py"]);
    }
}
