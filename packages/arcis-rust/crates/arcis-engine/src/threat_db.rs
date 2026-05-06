//! Threat-database loader.
//!
//! Strongly-typed deserialization of `arcis/data/threat-db.json` (embedded
//! by the `arcis-data` crate). Mirrors the `CompromisedPackage` dataclass
//! and `_load_threat_db` / `_normalize_name` / `_is_compromised` helpers
//! in `packages/arcis-python/arcis/cli/sca.py`.
//!
//! The schema-version probe in `arcis-data` is the upstream gate: it runs
//! before any of this code touches the bytes, so a mismatched DB never
//! reaches `Threat::load_all` in the first place.

use serde::Deserialize;
use thiserror::Error;

use crate::version::matches_any_range;

#[derive(Debug, Error)]
pub enum ThreatDbError {
    #[error("invalid JSON in threat-db.json: {0}")]
    Parse(#[from] serde_json::Error),
}

/// One known compromised package entry. Field-for-field with the Python
/// `CompromisedPackage` dataclass.
#[derive(Debug, Clone, Deserialize)]
pub struct Threat {
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub malicious_versions: Vec<String>,
    pub attack_vector: String,
    pub severity: String,
    #[serde(default)]
    pub cve: String,
    #[serde(default)]
    pub disclosure_date: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub trojanized_deps: Vec<String>,
    #[serde(default)]
    pub persistence_artifacts: Vec<String>,
    #[serde(default)]
    pub remediation: String,
    /// Range expressions such as `">=4.0.0,<4.22.4"`. Each string is a
    /// comma-separated AND of constraints; the list is OR'd.
    #[serde(default)]
    pub vulnerable_ranges: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ThreatDbFile {
    #[serde(default)]
    threats: Vec<Threat>,
}

impl Threat {
    /// Decode every threat entry from the embedded JSON. Returns the same
    /// shape `_load_threat_db` does in Python: an empty `Vec` when the
    /// payload is malformed, never an error to the caller. Unlike the
    /// Python version we don't print a warning on parse failure — the
    /// `arcis-data::check_threat_db_schema` guard in `arcis-engine::
    /// check_embedded_schemas` runs at startup and surfaces problems
    /// earlier and louder.
    pub fn load_all() -> Vec<Self> {
        match serde_json::from_slice::<ThreatDbFile>(arcis_data::THREAT_DB_JSON) {
            Ok(file) => file.threats,
            Err(_) => Vec::new(),
        }
    }
}

/// Canonicalize a package name for case- and separator-insensitive
/// comparison. PyPI normalizes `_` to `-` and folds case; npm only folds
/// case. Run on both `threat.name` and the matched package name before
/// comparing.
pub fn normalize_name(name: &str, ecosystem: &str) -> String {
    let mut n = name.trim().to_ascii_lowercase();
    if ecosystem == "pypi" {
        n = n.replace('_', "-");
    }
    n
}

/// True iff `version` falls under any of `threat`'s match expressions.
///
/// Two-track matching, in this exact order:
///   1. Exact list (`malicious_versions`) — used by trojanized-package
///      entries where attackers pushed specific malicious versions.
///   2. Range list (`vulnerable_ranges`) — used by high-severity-CVE
///      entries where every version below a fix release is exploitable.
///
/// An empty `version` short-circuits to `false`, matching the Python
/// guard against unknown `pip list` rows.
pub fn is_compromised(version: &str, threat: &Threat) -> bool {
    if version.is_empty() {
        return false;
    }
    if threat.malicious_versions.iter().any(|v| v == version) {
        return true;
    }
    if !threat.vulnerable_ranges.is_empty() && matches_any_range(version, &threat.vulnerable_ranges)
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic(malicious: Vec<&str>, ranges: Vec<&str>) -> Threat {
        Threat {
            ecosystem: "npm".into(),
            name: "x".into(),
            malicious_versions: malicious.into_iter().map(String::from).collect(),
            attack_vector: String::new(),
            severity: "critical".into(),
            cve: String::new(),
            disclosure_date: String::new(),
            source: String::new(),
            references: Vec::new(),
            trojanized_deps: Vec::new(),
            persistence_artifacts: Vec::new(),
            remediation: String::new(),
            vulnerable_ranges: ranges.into_iter().map(String::from).collect(),
        }
    }

    // ── load_all + seed sanity ────────────────────────────────────────────

    #[test]
    fn load_all_returns_at_least_thirty_entries() {
        // Matches `test_seed_has_minimum_entries` in the Python suite.
        let threats = Threat::load_all();
        assert!(
            threats.len() >= 30,
            "expected >=30 seeded threats, got {}",
            threats.len()
        );
    }

    #[test]
    fn load_all_contains_event_stream() {
        let threats = Threat::load_all();
        let es = threats
            .iter()
            .find(|t| t.ecosystem == "npm" && t.name == "event-stream")
            .expect("event-stream should be seeded");
        assert!(es.malicious_versions.iter().any(|v| v == "3.3.6"));
        assert!(es.trojanized_deps.iter().any(|d| d == "flatmap-stream"));
    }

    #[test]
    fn load_all_contains_rollup_range_entry() {
        let threats = Threat::load_all();
        let t = threats
            .iter()
            .find(|t| t.ecosystem == "npm" && t.name == "rollup")
            .expect("rollup should be seeded with a vulnerable_ranges entry");
        assert!(is_compromised("4.22.3", t));
        assert!(!is_compromised("4.22.4", t));
        assert!(!is_compromised("3.0.0", t));
    }

    #[test]
    fn load_all_contains_jsonpath_plus_range() {
        let threats = Threat::load_all();
        let t = threats
            .iter()
            .find(|t| t.ecosystem == "npm" && t.name == "jsonpath-plus")
            .expect("jsonpath-plus should be seeded");
        assert_eq!(t.severity, "critical");
        assert!(is_compromised("9.9.9", t));
        assert!(!is_compromised("10.0.0", t));
    }

    #[test]
    fn load_all_contains_urllib3_dual_range() {
        let threats = Threat::load_all();
        let t = threats
            .iter()
            .find(|t| t.ecosystem == "pypi" && t.name == "urllib3")
            .expect("urllib3 should be seeded with two vulnerable ranges");
        assert!(is_compromised("1.26.18", t));
        assert!(is_compromised("2.2.1", t));
        assert!(!is_compromised("2.2.2", t));
        assert!(!is_compromised("1.26.19", t));
    }

    #[test]
    fn load_all_contains_ctx_exact_versions() {
        let threats = Threat::load_all();
        let t = threats
            .iter()
            .find(|t| t.ecosystem == "pypi" && t.name == "ctx")
            .expect("ctx should be seeded with exact versions");
        assert!(t.malicious_versions.iter().any(|v| v == "0.2.2"));
        assert!(t.malicious_versions.iter().any(|v| v == "0.2.6"));
        assert!(is_compromised("0.2.2", t));
        assert!(!is_compromised("0.1.2", t));
    }

    // ── normalize_name ────────────────────────────────────────────────────

    #[test]
    fn normalize_pypi_folds_dashes_underscores_and_case() {
        assert_eq!(normalize_name("Python_DateUtil", "pypi"), "python-dateutil");
        assert_eq!(normalize_name("python-dateutil", "pypi"), "python-dateutil");
    }

    #[test]
    fn normalize_npm_only_folds_case() {
        assert_eq!(normalize_name("@AzuRe/Storage", "npm"), "@azure/storage");
        // Underscores preserved for npm (unusual but possible).
        assert_eq!(normalize_name("foo_bar", "npm"), "foo_bar");
    }

    // ── is_compromised ────────────────────────────────────────────────────

    #[test]
    fn is_compromised_exact_list() {
        let t = synthetic(vec!["1.2.3"], vec![]);
        assert!(is_compromised("1.2.3", &t));
        assert!(!is_compromised("1.2.4", &t));
    }

    #[test]
    fn is_compromised_range() {
        let t = synthetic(vec![], vec![">=4.0.0,<4.22.4"]);
        assert!(is_compromised("4.22.3", &t));
        assert!(!is_compromised("4.22.4", &t));
        assert!(!is_compromised("3.99.0", &t));
    }

    #[test]
    fn is_compromised_either_track_hits() {
        let t = synthetic(vec!["7.0.0-rc1"], vec![">=8.0.0,<8.5.0"]);
        assert!(is_compromised("7.0.0-rc1", &t));
        assert!(is_compromised("8.4.99", &t));
        assert!(!is_compromised("7.0.0", &t));
        assert!(!is_compromised("8.5.0", &t));
    }

    #[test]
    fn is_compromised_empty_version_is_false() {
        let t = synthetic(vec!["1.0.0"], vec![]);
        assert!(!is_compromised("", &t));
    }
}
