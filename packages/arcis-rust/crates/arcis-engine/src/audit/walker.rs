//! File walker for the audit module.
//!
//! Direct port of `_collect_files` from
//! `packages/arcis-python/arcis/cli/audit.py`. Walks the target tree,
//! prunes `SKIP_DIRS`, returns paths whose extensions map to a known
//! [`Language`] via [`Language::from_extension`].
//!
//! Uses `walkdir`, not the `ignore` crate. Python `os.walk` does NOT
//! honor `.gitignore`, and we need byte-equal parity in the final
//! finding list — using `ignore` would diverge whenever a target tree
//! has gitignored source files. Gitignore support belongs behind a
//! flag (post-parity).
//!
//! Symlinks are not followed — matches the post-fix Python behavior
//! from commit `e778439`.

use std::path::{Path, PathBuf};

use walkdir::WalkDir;

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

/// Collect scannable source files under `path`.
///
/// * If `path` is a single file, returns `[path]` if its extension
///   maps to a known [`Language`] and matches the optional `language`
///   filter; otherwise empty.
/// * If `path` is a directory, walks recursively, prunes any directory
///   whose name appears in [`SKIP_DIRS`], yields files with a known
///   extension (and matching the optional language filter).
/// * Walk order is unspecified — matches Python's `os.walk`. Final
///   finding output is sorted by `(severity, file, line)` downstream
///   so the unsorted walk order doesn't affect byte-equality of the
///   JSON / SARIF doc.
/// * If `path` doesn't exist, returns empty (the CLI checks existence
///   up-front and emits a friendlier error; a defensive empty here
///   keeps the engine API total).
pub fn collect_files(path: &Path, language: Option<Language>) -> Vec<PathBuf> {
    if path.is_file() {
        return match detect_language(path) {
            Some(lang) if language.is_none() || language == Some(lang) => {
                vec![path.to_path_buf()]
            }
            _ => Vec::new(),
        };
    }
    if !path.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();

    let walker = WalkDir::new(path).follow_links(false).into_iter();
    let walker = walker.filter_entry(|e| {
        // Always keep the root: SKIP_DIRS prunes CHILDREN only. If a
        // user runs `arcis audit node_modules/`, walk it. Mirrors the
        // Python `dirs[:] = [d for d in dirs if d not in SKIP_DIRS]`
        // line (which only filters children of the current root).
        if e.depth() == 0 {
            return true;
        }
        if e.file_type().is_dir() {
            return !is_skipped_dir_name(&e.file_name().to_string_lossy());
        }
        true
    });

    for entry in walker.filter_map(|res| res.ok()) {
        if !entry.file_type().is_file() {
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
}
