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

use regex::Regex;

use crate::threat_db::{is_compromised, normalize_name, Threat};

/// One finding row. Field-for-field with the Python `Finding` dataclass.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
                        finding_type: FindingType::PersistenceArtifact,
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
/// Findings are deduplicated by `(package, version, location)` to mirror
/// Python's `seen` set.
pub fn scan_project(path: &Path, check_system: bool, threats: &[Threat]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(scan_package_lock(path, threats));
    findings.extend(scan_yarn_lock(path, threats));
    findings.extend(scan_node_modules(path, threats));
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
}
