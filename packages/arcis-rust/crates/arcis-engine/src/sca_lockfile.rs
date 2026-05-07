//! Per-lockfile dependency graph builders for `arcis sca` transitive
//! depth tracking (cli-sca.md Phase C item 5).
//!
//! Each format has its own builder returning [`Option<DepGraph>`]:
//! `Some` when a graph could be reconstructed; `None` when the format
//! either isn't supported yet (yarn Berry, future yarn v2 lockfiles) or
//! is structurally flat (Pipfile.lock has no edge data — the resolver
//! flattens it before writing).
//!
//! The engine separately exposes [`detect_format`] so the CLI can render
//! an honest "Paths: X (graph), Y (flat)" banner row when at least one
//! lockfile in the scan can't yield a graph — the user knows transitive
//! data is incomplete rather than silently flat.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::{Map, Value};

use crate::sca_graph::DepGraph;

/// One of the lockfile formats `arcis sca` knows how to read. The variant
/// determines which builder is invoked and whether a graph is even
/// possible (vs structurally flat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileFormat {
    /// `package-lock.json` with `lockfileVersion: 2` or `3` — has a
    /// `packages` map keyed by `node_modules/...` paths.
    NpmLockV3,
    /// `package-lock.json` with `lockfileVersion: 1` — recursive
    /// `dependencies` object, no top-level `packages` map.
    NpmLockV1,
    /// Yarn classic v1 lockfile (`yarn.lock` without a `__metadata` block).
    YarnClassic,
    /// Yarn Berry / v2+ lockfile (`yarn.lock` with `__metadata: version: 6`).
    /// Graph reconstruction deferred to v2 of this work.
    YarnBerry,
    /// `pnpm-lock.yaml` v6+ — flat `packages` map keyed by `/<name>@<v>`
    /// with `dependencies` sub-maps. Graph builder lands in commit 2.
    Pnpm,
    /// `poetry.lock` — TOML `[[package]]` blocks each with an optional
    /// `[package.dependencies]` sub-table.
    Poetry,
    /// `Pipfile.lock` — structurally flat (resolved package list, no
    /// edge data). Always returns `None` from `build_graph`; the CLI
    /// marks it "flat" in the banner.
    PipfileLock,
}

impl LockfileFormat {
    /// Human-readable label for the report banner. Stable across versions.
    pub fn label(self) -> &'static str {
        match self {
            Self::NpmLockV3 => "package-lock.json (v2/v3)",
            Self::NpmLockV1 => "package-lock.json (v1)",
            Self::YarnClassic => "yarn.lock (classic)",
            Self::YarnBerry => "yarn.lock (berry)",
            Self::Pnpm => "pnpm-lock.yaml",
            Self::Poetry => "poetry.lock",
            Self::PipfileLock => "Pipfile.lock",
        }
    }

    /// Whether the format can yield a dependency graph in the current
    /// implementation. `false` means findings from this lockfile won't
    /// have transitive paths annotated.
    pub fn graph_supported(self) -> bool {
        match self {
            Self::NpmLockV3 | Self::NpmLockV1 | Self::Poetry => true,
            // Yarn classic + pnpm graph builders ship in commit 2.
            // Yarn Berry + Pipfile.lock are intentionally `false` for v1.
            Self::YarnClassic | Self::Pnpm => false,
            Self::YarnBerry | Self::PipfileLock => false,
        }
    }
}

/// Inspect `path` and identify which lockfile format it is, peeking at
/// content where the filename alone is ambiguous (e.g. `package-lock.json`
/// v1 vs v2/v3).
pub fn detect_format(path: &Path) -> Option<LockfileFormat> {
    let name = path.file_name()?.to_str()?;
    match name {
        "package-lock.json" => detect_npm_lock_version(path),
        "yarn.lock" => detect_yarn_flavour(path),
        "pnpm-lock.yaml" => Some(LockfileFormat::Pnpm),
        "poetry.lock" => Some(LockfileFormat::Poetry),
        "Pipfile.lock" => Some(LockfileFormat::PipfileLock),
        _ => None,
    }
}

fn detect_npm_lock_version(path: &Path) -> Option<LockfileFormat> {
    let bytes = fs::read(path).ok()?;
    let data: Value = serde_json::from_slice(&bytes).ok()?;
    let version = data
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    if version >= 2 {
        Some(LockfileFormat::NpmLockV3)
    } else {
        Some(LockfileFormat::NpmLockV1)
    }
}

fn detect_yarn_flavour(path: &Path) -> Option<LockfileFormat> {
    let content = fs::read_to_string(path).ok()?;
    // Berry lockfiles start with a `__metadata` block.
    if content.contains("__metadata:") {
        Some(LockfileFormat::YarnBerry)
    } else {
        Some(LockfileFormat::YarnClassic)
    }
}

/// Dispatch to the right builder for `path`. Returns `None` when no
/// graph is available — caller (the CLI) should render findings without
/// path data and flag the lockfile as "flat" in the banner.
pub fn build_graph(path: &Path) -> Option<DepGraph> {
    let format = detect_format(path)?;
    match format {
        LockfileFormat::NpmLockV3 => build_npm_lock_v3(path),
        LockfileFormat::NpmLockV1 => build_npm_lock_v1(path),
        LockfileFormat::Poetry => build_poetry(path),
        // Stubs for commit 2 / deferred formats:
        LockfileFormat::YarnClassic
        | LockfileFormat::YarnBerry
        | LockfileFormat::Pnpm
        | LockfileFormat::PipfileLock => None,
    }
}

// ── npm package-lock.json v2/v3 ──────────────────────────────────────────

/// Graph builder for `package-lock.json` with `lockfileVersion: 2` or 3.
///
/// The `packages` map is keyed by the install path: `""` (the project
/// root), `node_modules/<name>` (hoisted), and
/// `node_modules/<a>/node_modules/<b>` (nested only when a hoisting
/// conflict exists). Edges come from each entry's `dependencies` field;
/// child resolution mirrors npm's actual algorithm — try nested first,
/// then walk up to hoisted.
pub fn build_npm_lock_v3(path: &Path) -> Option<DepGraph> {
    let bytes = fs::read(path).ok()?;
    let data: Value = serde_json::from_slice(&bytes).ok()?;
    let packages = data.get("packages")?.as_object()?;

    let mut graph = DepGraph::new();
    let root_name = root_name_for_npm(packages, path);
    let root_id = graph.add_node("npm", &root_name, "0.0.0");
    graph.add_root(root_id);

    // First pass: insert every non-root node.
    for (key, info) in packages {
        if key.is_empty() {
            continue;
        }
        let Some(name) = npm_name_from_key(key) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if version.is_empty() {
            continue;
        }
        graph.add_node("npm", name, version);
    }

    // Second pass: add edges via dependencies + devDependencies +
    // optionalDependencies. Each child name is resolved per npm's
    // hoisting rules (nested first, then walk up).
    for (key, info) in packages {
        let parent_id = if key.is_empty() {
            root_id
        } else {
            let Some(name) = npm_name_from_key(key) else {
                continue;
            };
            let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if version.is_empty() {
                continue;
            }
            match graph.find_node("npm", name, version) {
                Some(id) => id,
                None => continue,
            }
        };

        for dep_field in ["dependencies", "devDependencies", "optionalDependencies"] {
            let Some(deps) = info.get(dep_field).and_then(|v| v.as_object()) else {
                continue;
            };
            for child_name in deps.keys() {
                let Some(child_key) = resolve_npm_child(packages, key, child_name) else {
                    continue;
                };
                let child_info = match packages.get(&child_key) {
                    Some(c) => c,
                    None => continue,
                };
                let child_version = child_info
                    .get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if child_version.is_empty() {
                    continue;
                }
                if let Some(child_id) = graph.find_node("npm", child_name, child_version) {
                    graph.add_edge(parent_id, child_id);
                }
            }
        }
    }

    Some(graph)
}

/// Extract the package name from a v3 `packages` map key. Keys look like
/// `node_modules/<name>` or `node_modules/<a>/node_modules/<b>`; we want
/// the segment after the *last* `node_modules/` separator. Returns `None`
/// if the key isn't a node_modules path (e.g. the `""` root entry).
fn npm_name_from_key(key: &str) -> Option<&str> {
    key.rsplit_once("node_modules/").map(|(_, name)| name)
}

/// Resolve `child_name` from `parent_key`'s perspective per npm hoisting:
/// 1. Try the direct nested path: `<parent_key>/node_modules/<child>`.
/// 2. Walk up one ancestor at a time, retrying.
/// 3. Finally try the top-level hoisted form: `node_modules/<child>`.
fn resolve_npm_child(
    packages: &Map<String, Value>,
    parent_key: &str,
    child_name: &str,
) -> Option<String> {
    let mut search: Option<String> = Some(parent_key.to_string());
    while let Some(s) = search {
        let candidate = if s.is_empty() {
            format!("node_modules/{child_name}")
        } else {
            format!("{s}/node_modules/{child_name}")
        };
        if packages.contains_key(&candidate) {
            return Some(candidate);
        }
        search = match s.rfind("/node_modules/") {
            Some(idx) => Some(s[..idx].to_string()),
            None => {
                if s.is_empty() {
                    None
                } else {
                    Some(String::new())
                }
            }
        };
    }
    None
}

fn root_name_for_npm(packages: &Map<String, Value>, lockfile: &Path) -> String {
    if let Some(root) = packages.get("") {
        if let Some(name) = root.get("name").and_then(|v| v.as_str()) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    // Fall back to project directory name; matches what `npm` shows as
    // the unnamed-package root when package.json doesn't set `name`.
    lockfile
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(String::from)
        .unwrap_or_else(|| "(root)".to_string())
}

// ── npm package-lock.json v1 ─────────────────────────────────────────────

/// Graph builder for `package-lock.json` with `lockfileVersion: 1`. The
/// `dependencies` field is a recursive object: each key is a package
/// name, the value has `version`, optional `dependencies` (nested),
/// and optional `requires` (range deps).
pub fn build_npm_lock_v1(path: &Path) -> Option<DepGraph> {
    let bytes = fs::read(path).ok()?;
    let data: Value = serde_json::from_slice(&bytes).ok()?;

    let mut graph = DepGraph::new();
    let root_name = data
        .get("name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| {
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .map(String::from)
                .unwrap_or_else(|| "(root)".to_string())
        });
    let root_id = graph.add_node("npm", &root_name, "0.0.0");
    graph.add_root(root_id);

    if let Some(deps) = data.get("dependencies").and_then(|v| v.as_object()) {
        walk_npm_v1(&mut graph, root_id, deps);
    }

    Some(graph)
}

fn walk_npm_v1(graph: &mut DepGraph, parent_id: usize, deps: &Map<String, Value>) {
    // Two-pass over the same dict: first pass inserts every node so we
    // can resolve `requires` references in pass two regardless of order.
    let mut child_ids: Vec<(String, usize)> = Vec::new();
    for (name, info) in deps {
        let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if version.is_empty() {
            continue;
        }
        let id = graph.add_node("npm", name, version);
        graph.add_edge(parent_id, id);
        child_ids.push((name.clone(), id));
    }
    // Pass two: descend into nested dependencies (the recursive part).
    for (name, info) in deps {
        let Some(nested) = info.get("dependencies").and_then(|v| v.as_object()) else {
            continue;
        };
        let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if version.is_empty() {
            continue;
        }
        let parent = match graph.find_node("npm", name, version) {
            Some(id) => id,
            None => continue,
        };
        walk_npm_v1(graph, parent, nested);
    }
}

// ── poetry.lock ──────────────────────────────────────────────────────────

/// Graph builder for `poetry.lock`. We don't pull in a full TOML
/// dependency — the format is regular enough that a block-split + small
/// regex extracts what we need (name, version, `[package.dependencies]`).
///
/// The root project isn't recorded in `poetry.lock`; we read
/// `pyproject.toml`'s `[tool.poetry] name` if present, falling back to
/// the lockfile's directory name.
pub fn build_poetry(path: &Path) -> Option<DepGraph> {
    let content = fs::read_to_string(path).ok()?;

    let mut graph = DepGraph::new();
    let root_name = poetry_root_name(path);
    let root_id = graph.add_node("pypi", &root_name, "0.0.0");
    graph.add_root(root_id);

    // Split on `[[package]]` boundaries. The first segment (before any
    // `[[package]]`) is metadata + root section — discard.
    let blocks: Vec<&str> = content.split("[[package]]").collect();
    if blocks.len() <= 1 {
        return Some(graph);
    }

    let name_re = Regex::new(r#"(?m)^name\s*=\s*"([^"]+)""#).expect("name re must compile");
    let version_re =
        Regex::new(r#"(?m)^version\s*=\s*"([^"]+)""#).expect("version re must compile");
    let deps_section_re =
        Regex::new(r"(?ms)^\[package\.dependencies\][^\[]*").expect("deps re must compile");
    let dep_key_re = Regex::new(r"(?m)^([A-Za-z0-9_.\-]+)\s*=").expect("dep key re must compile");

    // First pass: insert all nodes + capture per-block dep names for
    // pass two.
    let mut block_nodes: Vec<(String, usize, Vec<String>)> = Vec::new();
    for block in blocks.iter().skip(1) {
        let Some(name) = name_re
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
        else {
            continue;
        };
        let Some(version) = version_re
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
        else {
            continue;
        };
        let id = graph.add_node("pypi", &name, &version);

        let dep_names: Vec<String> = if let Some(section) = deps_section_re.find(block) {
            // Strip the leading `[package.dependencies]` line so the
            // dep-key regex doesn't match it as a dependency named
            // "[package.dependencies]" or similar.
            let body = section.as_str();
            let body_after_header = body.find('\n').map(|idx| &body[idx + 1..]).unwrap_or(body);
            dep_key_re
                .captures_iter(body_after_header)
                .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                .collect()
        } else {
            Vec::new()
        };

        block_nodes.push((name, id, dep_names));
    }

    // Every package in poetry.lock that isn't itself depended on by
    // another package is treated as a direct dep of the root. Track which
    // names appear as dep targets so we can mark roots correctly.
    let mut depended_on: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (_, _, dep_names) in &block_nodes {
        for d in dep_names {
            depended_on.insert(crate::threat_db::normalize_name(d, "pypi"));
        }
    }
    for (name, id, _) in &block_nodes {
        let norm = crate::threat_db::normalize_name(name, "pypi");
        if !depended_on.contains(&norm) {
            graph.add_edge(root_id, *id);
        }
    }

    // Second pass: edges from each package to its dependencies. We
    // resolve by name only — poetry.lock pins one version per package
    // (no diamond version conflicts), so name is enough.
    let by_norm_name: std::collections::HashMap<String, usize> = block_nodes
        .iter()
        .map(|(n, id, _)| (crate::threat_db::normalize_name(n, "pypi"), *id))
        .collect();

    for (_, parent_id, dep_names) in &block_nodes {
        for dep in dep_names {
            let norm = crate::threat_db::normalize_name(dep, "pypi");
            if let Some(&child_id) = by_norm_name.get(&norm) {
                graph.add_edge(*parent_id, child_id);
            }
        }
    }

    Some(graph)
}

fn poetry_root_name(lockfile: &Path) -> String {
    if let Some(parent) = lockfile.parent() {
        let pyproject = parent.join("pyproject.toml");
        if let Ok(content) = fs::read_to_string(&pyproject) {
            // Look for `name = "..."` under `[tool.poetry]`. Cheap regex
            // suffices — if it fails we fall back to dir name.
            let re = Regex::new(r#"(?ms)^\[tool\.poetry\][^\[]*?name\s*=\s*"([^"]+)""#).unwrap();
            if let Some(c) = re.captures(&content) {
                if let Some(m) = c.get(1) {
                    return m.as_str().to_string();
                }
            }
        }
    }
    lockfile
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .map(String::from)
        .unwrap_or_else(|| "(root)".to_string())
}

// ── lockfile discovery ───────────────────────────────────────────────────

/// Names of every lockfile / manifest [`build_graph`] knows how to inspect.
const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
];

/// List the lockfiles present under `path` in canonical order. Returns
/// the absolute path so callers can match `Finding.location` directly.
pub fn discover_lockfiles(path: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for name in LOCKFILE_NAMES {
        let candidate = path.join(name);
        if candidate.is_file() {
            out.push(candidate);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tempdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── format detection ─────────────────────────────────────────────────

    #[test]
    fn detect_format_npm_v3() {
        let dir = tempdir();
        let p = dir.path().join("package-lock.json");
        fs::write(&p, r#"{"lockfileVersion": 3, "packages": {}}"#).unwrap();
        assert_eq!(detect_format(&p), Some(LockfileFormat::NpmLockV3));
    }

    #[test]
    fn detect_format_npm_v1() {
        let dir = tempdir();
        let p = dir.path().join("package-lock.json");
        fs::write(&p, r#"{"lockfileVersion": 1, "dependencies": {}}"#).unwrap();
        assert_eq!(detect_format(&p), Some(LockfileFormat::NpmLockV1));
    }

    #[test]
    fn detect_format_yarn_classic_vs_berry() {
        let dir = tempdir();
        let classic = dir.path().join("yarn.lock");
        fs::write(
            &classic,
            "# yarn lockfile v1\n\"axios@^1.0.0\":\n  version \"1.0.0\"\n",
        )
        .unwrap();
        assert_eq!(detect_format(&classic), Some(LockfileFormat::YarnClassic));

        let berry_dir = tempdir();
        let berry = berry_dir.path().join("yarn.lock");
        fs::write(
            &berry,
            "__metadata:\n  version: 6\n  cacheKey: 8\n\"axios@npm:^1\":\n",
        )
        .unwrap();
        assert_eq!(detect_format(&berry), Some(LockfileFormat::YarnBerry));
    }

    #[test]
    fn detect_format_pnpm_poetry_pipfile() {
        let dir = tempdir();
        let pnpm = dir.path().join("pnpm-lock.yaml");
        fs::write(&pnpm, "lockfileVersion: '6.0'\n").unwrap();
        assert_eq!(detect_format(&pnpm), Some(LockfileFormat::Pnpm));

        let poetry = dir.path().join("poetry.lock");
        fs::write(&poetry, "[[package]]\nname = \"x\"\nversion = \"1\"\n").unwrap();
        assert_eq!(detect_format(&poetry), Some(LockfileFormat::Poetry));

        let pipfile = dir.path().join("Pipfile.lock");
        fs::write(&pipfile, "{\"_meta\": {}, \"default\": {}}").unwrap();
        assert_eq!(detect_format(&pipfile), Some(LockfileFormat::PipfileLock));
    }

    #[test]
    fn graph_supported_marks_pipfile_and_berry_unsupported() {
        assert!(LockfileFormat::NpmLockV3.graph_supported());
        assert!(LockfileFormat::NpmLockV1.graph_supported());
        assert!(LockfileFormat::Poetry.graph_supported());
        assert!(!LockfileFormat::PipfileLock.graph_supported());
        assert!(!LockfileFormat::YarnBerry.graph_supported());
        // Yarn classic + pnpm explicitly unsupported in commit 1; commit 2
        // flips them on.
        assert!(!LockfileFormat::YarnClassic.graph_supported());
        assert!(!LockfileFormat::Pnpm.graph_supported());
    }

    // ── npm v3 ──────────────────────────────────────────────────────────

    #[test]
    fn npm_v3_linear_chain_axios_at_depth_3() {
        let dir = tempdir();
        let body = r#"{
            "name": "your-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "your-app", "version": "1.0.0", "dependencies": {"express": "^4"}},
                "node_modules/express": {"version": "4.0.0", "dependencies": {"middleware": "^1"}},
                "node_modules/middleware": {"version": "1.0.0", "dependencies": {"axios": "^1"}},
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v3(&p).expect("graph builds");
        let axios = g.find_node("npm", "axios", "1.14.1").expect("axios node");
        let path = g.shortest_path(axios).unwrap();
        assert_eq!(path, vec!["your-app", "express", "middleware"]);
        assert_eq!(g.depth(axios), Some(3));
    }

    #[test]
    fn npm_v3_diamond_two_paths() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "your-app", "version": "1.0.0", "dependencies": {"alpha": "^1", "bravo": "^1"}},
                "node_modules/alpha": {"version": "1.0.0", "dependencies": {"axios": "^1"}},
                "node_modules/bravo": {"version": "1.0.0", "dependencies": {"axios": "^1"}},
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v3(&p).expect("graph builds");
        let axios = g.find_node("npm", "axios", "1.14.1").expect("axios node");
        let paths = g.all_paths_to(axios, 8);
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&vec!["your-app".to_string(), "alpha".to_string()]));
        assert!(paths.contains(&vec!["your-app".to_string(), "bravo".to_string()]));
    }

    #[test]
    fn npm_v3_resolves_nested_node_modules_first() {
        // alpha's deps for axios resolve to the NESTED axios@2 (not the
        // hoisted axios@1). Tests the resolve_npm_child walk.
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "your-app", "version": "1.0.0", "dependencies": {"alpha": "^1", "axios": "^1"}},
                "node_modules/alpha": {"version": "1.0.0", "dependencies": {"axios": "^2"}},
                "node_modules/alpha/node_modules/axios": {"version": "2.0.0"},
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v3(&p).expect("graph builds");
        let axios2 = g.find_node("npm", "axios", "2.0.0").expect("axios@2 node");
        let path2 = g.shortest_path(axios2).unwrap();
        assert_eq!(path2, vec!["your-app", "alpha"]);
        let axios1 = g.find_node("npm", "axios", "1.14.1").expect("axios@1 node");
        let path1 = g.shortest_path(axios1).unwrap();
        assert_eq!(path1, vec!["your-app"]);
    }

    #[test]
    fn npm_v3_handles_self_cycle() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "your-app", "version": "1.0.0", "dependencies": {"a": "^1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1"}},
                "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "^1", "axios": "^1"}},
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v3(&p).expect("graph builds");
        let axios = g.find_node("npm", "axios", "1.14.1").expect("axios node");
        assert_eq!(g.depth(axios), Some(3));
    }

    #[test]
    fn npm_v3_root_name_falls_back_to_dir_name() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"version": "1.0.0", "dependencies": {"axios": "^1"}},
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v3(&p).expect("graph builds");
        // Root name is the dir name (TempDir random suffix); we only
        // verify a root node exists at depth 0.
        let axios = g.find_node("npm", "axios", "1.14.1").expect("axios node");
        assert_eq!(g.depth(axios), Some(1));
    }

    // ── npm v1 ──────────────────────────────────────────────────────────

    #[test]
    fn npm_v1_recursive_dependencies() {
        let dir = tempdir();
        let body = r#"{
            "name": "your-app",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "express": {
                    "version": "4.0.0",
                    "requires": {"middleware": "^1"},
                    "dependencies": {
                        "middleware": {
                            "version": "1.0.0",
                            "dependencies": {
                                "axios": {"version": "1.14.1"}
                            }
                        }
                    }
                }
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v1(&p).expect("graph builds");
        let axios = g.find_node("npm", "axios", "1.14.1").expect("axios node");
        let path = g.shortest_path(axios).unwrap();
        assert_eq!(path, vec!["your-app", "express", "middleware"]);
    }

    #[test]
    fn npm_v1_top_level_is_direct_dep() {
        let dir = tempdir();
        let body = r#"{
            "name": "your-app",
            "lockfileVersion": 1,
            "dependencies": {
                "axios": {"version": "1.14.1"}
            }
        }"#;
        let p = dir.path().join("package-lock.json");
        fs::write(&p, body).unwrap();
        let g = build_npm_lock_v1(&p).expect("graph builds");
        let axios = g.find_node("npm", "axios", "1.14.1").expect("axios node");
        assert_eq!(g.depth(axios), Some(1));
    }

    // ── poetry ──────────────────────────────────────────────────────────

    #[test]
    fn poetry_simple_chain() {
        let dir = tempdir();
        // pyproject.toml so we get a stable root name.
        fs::write(
            dir.path().join("pyproject.toml"),
            "[tool.poetry]\nname = \"your-app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let body = r#"
[[package]]
name = "axios"
version = "1.14.1"

[[package]]
name = "express"
version = "4.0.0"

[package.dependencies]
axios = "^1"
"#;
        let p = dir.path().join("poetry.lock");
        fs::write(&p, body).unwrap();
        let g = build_poetry(&p).expect("graph builds");
        let axios = g.find_node("pypi", "axios", "1.14.1").expect("axios node");
        let path = g.shortest_path(axios).unwrap();
        // express depends on axios; express is a root dep (no other pkg
        // depends on it). Path: your-app → express, target axios excluded.
        assert_eq!(path, vec!["your-app", "express"]);
        assert_eq!(g.depth(axios), Some(2));
    }

    #[test]
    fn poetry_normalizes_dep_name_dashes_underscores() {
        let dir = tempdir();
        fs::write(
            dir.path().join("pyproject.toml"),
            "[tool.poetry]\nname = \"your-app\"\n",
        )
        .unwrap();
        // dep table uses "python_dateutil"; package is "python-dateutil".
        let body = r#"
[[package]]
name = "python-dateutil"
version = "2.9.0"

[[package]]
name = "wrapper"
version = "1.0.0"

[package.dependencies]
python_dateutil = "^2"
"#;
        let p = dir.path().join("poetry.lock");
        fs::write(&p, body).unwrap();
        let g = build_poetry(&p).expect("graph builds");
        let dt = g
            .find_node("pypi", "python-dateutil", "2.9.0")
            .expect("dateutil node");
        let path = g.shortest_path(dt).unwrap();
        // python-dateutil is depended on by wrapper, so it isn't a direct
        // root dep — chain: your-app → wrapper.
        assert_eq!(path, vec!["your-app", "wrapper"]);
    }

    #[test]
    fn poetry_no_dependencies_section() {
        let dir = tempdir();
        let body = r#"
[[package]]
name = "axios"
version = "1.14.1"

[[package]]
name = "lodash"
version = "4.0.0"
"#;
        let p = dir.path().join("poetry.lock");
        fs::write(&p, body).unwrap();
        let g = build_poetry(&p).expect("graph builds");
        let axios = g.find_node("pypi", "axios", "1.14.1").unwrap();
        // No dep edges → both packages are direct deps of root.
        assert_eq!(g.depth(axios), Some(1));
    }

    #[test]
    fn poetry_root_name_falls_back_when_no_pyproject() {
        let dir = tempdir();
        let body = "[[package]]\nname = \"axios\"\nversion = \"1\"\n";
        let p = dir.path().join("poetry.lock");
        fs::write(&p, body).unwrap();
        let g = build_poetry(&p).expect("graph builds");
        // Root exists at depth 0. We don't pin the exact name (varies by
        // tempdir) but the graph should have at least one root + axios.
        assert_eq!(g.root_count(), 1);
        let axios = g.find_node("pypi", "axios", "1").unwrap();
        assert_eq!(g.depth(axios), Some(1));
    }

    // ── build_graph dispatcher ──────────────────────────────────────────

    #[test]
    fn build_graph_returns_none_for_pipfile() {
        let dir = tempdir();
        let p = dir.path().join("Pipfile.lock");
        fs::write(
            &p,
            r#"{"_meta": {}, "default": {"axios": {"version": "==1.0.0"}}}"#,
        )
        .unwrap();
        assert!(build_graph(&p).is_none());
    }

    #[test]
    fn build_graph_dispatches_npm_v3() {
        let dir = tempdir();
        let p = dir.path().join("package-lock.json");
        fs::write(
            &p,
            r#"{"lockfileVersion": 3, "packages": {"": {"name":"x"}}}"#,
        )
        .unwrap();
        assert!(build_graph(&p).is_some());
    }

    #[test]
    fn discover_lockfiles_lists_all_present() {
        let dir = tempdir();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        fs::write(dir.path().join("poetry.lock"), "").unwrap();
        let found = discover_lockfiles(dir.path());
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["package-lock.json", "poetry.lock"]);
    }

    #[test]
    fn resolve_npm_child_finds_nested_first() {
        let mut packages: Map<String, Value> = Map::new();
        packages.insert(
            "node_modules/a".into(),
            serde_json::json!({"version": "1.0.0"}),
        );
        packages.insert(
            "node_modules/a/node_modules/x".into(),
            serde_json::json!({"version": "2.0.0"}),
        );
        packages.insert(
            "node_modules/x".into(),
            serde_json::json!({"version": "1.0.0"}),
        );
        let key = resolve_npm_child(&packages, "node_modules/a", "x").unwrap();
        assert_eq!(key, "node_modules/a/node_modules/x");
    }

    #[test]
    fn resolve_npm_child_falls_back_to_hoisted() {
        let mut packages: Map<String, Value> = Map::new();
        packages.insert(
            "node_modules/a".into(),
            serde_json::json!({"version": "1.0.0"}),
        );
        packages.insert(
            "node_modules/x".into(),
            serde_json::json!({"version": "1.0.0"}),
        );
        let key = resolve_npm_child(&packages, "node_modules/a", "x").unwrap();
        assert_eq!(key, "node_modules/x");
    }
}
