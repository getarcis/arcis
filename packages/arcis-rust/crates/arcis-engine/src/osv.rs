//! OSV.dev API client for the optional `arcis sca --osv` layer.
//!
//! Designed in `documents/plans/cli-sca.md` Phase B (2026-05-07): the
//! embedded `threat-db.json` stays curated and frozen at install time;
//! this module augments per scan with a live lookup against
//! <https://api.osv.dev/v1/query>.
//!
//! Request shape:
//! ```json
//! { "package": { "name": "axios", "ecosystem": "npm" }, "version": "1.14.1" }
//! ```
//!
//! Response shape (only the fields we render):
//! ```json
//! { "vulns": [
//!     { "id": "GHSA-...", "summary": "...",
//!       "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/..."}],
//!       "references": [{"type":"WEB","url":"..."}] }
//! ] }
//! ```
//!
//! Ecosystem labels are case-sensitive on OSV (`npm`, `PyPI`, `Go`). Our
//! internal label is `pypi` (lower-case) so [`osv_ecosystem`] maps before
//! sending.

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};

const OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsvVuln {
    pub id: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OsvReference {
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Serialize)]
struct OsvQuery<'a> {
    package: OsvPackageRef<'a>,
    version: &'a str,
}

#[derive(Debug, Serialize)]
struct OsvPackageRef<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    #[error("OSV network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("OSV returned HTTP {0}")]
    HttpStatus(u16),
    #[error("OSV returned no body")]
    EmptyBody,
}

/// Map an internal ecosystem string (`"npm"`, `"pypi"`, `"go"`) to the
/// label OSV expects. Empty string for unknown ecosystems — the caller
/// should treat that as "skip this package, OSV won't recognize it".
pub fn osv_ecosystem(internal: &str) -> &'static str {
    match internal {
        "npm" => "npm",
        "pypi" => "PyPI",
        "go" => "Go",
        _ => "",
    }
}

/// Heuristic severity rank from an OSV severity array. Returns the same
/// strings the existing `Finding.severity` field uses (`"critical"`,
/// `"high"`, `"medium"`, `"low"`, `"unknown"`) so OSV findings reuse the
/// existing severity tinting in the report.
///
/// OSV severity entries come in two shapes:
///   * a CVSS vector string (`"CVSS:3.1/AV:N/.../C:H/I:H/A:H"`) without
///     an explicit base score
///   * a bare numeric string (rare)
///
/// We only get a numeric rank from the second shape. When OSV sends only
/// vectors, we return `"unknown"` — the report renderer treats it the
/// same as `"high"` for tinting (yellow). A future refinement would
/// compute the CVSS base score from the vector string, but that's a
/// 200-line cvss-rs port and out of scope for v1.
pub fn rank_severity(sev: &[OsvSeverity]) -> &'static str {
    let mut best: f64 = -1.0;
    for entry in sev {
        if let Ok(n) = entry.score.parse::<f64>() {
            if n > best {
                best = n;
            }
        }
    }
    if best < 0.0 {
        return "unknown";
    }
    if best >= 9.0 {
        "critical"
    } else if best >= 7.0 {
        "high"
    } else if best >= 4.0 {
        "medium"
    } else {
        "low"
    }
}

/// Query OSV for vulns affecting `(ecosystem, name, version)`. Errors are
/// network failures, non-2xx HTTP, or malformed JSON. Empty `vulns` is
/// success and returns `Ok(vec![])`.
pub async fn query(
    client: &Client,
    ecosystem: &str,
    name: &str,
    version: &str,
    timeout: Duration,
) -> Result<Vec<OsvVuln>, OsvError> {
    let eco = osv_ecosystem(ecosystem);
    if eco.is_empty() || name.is_empty() || version.is_empty() {
        return Ok(Vec::new());
    }
    let body = OsvQuery {
        package: OsvPackageRef {
            name,
            ecosystem: eco,
        },
        version,
    };
    let resp = client
        .post(OSV_QUERY_URL)
        .timeout(timeout)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        return Err(OsvError::HttpStatus(status.as_u16()));
    }
    let bytes = resp.bytes().await?;
    if bytes.is_empty() {
        return Err(OsvError::EmptyBody);
    }
    let parsed: OsvResponse = serde_json::from_slice(&bytes).map_err(|_| OsvError::EmptyBody)?;
    Ok(parsed.vulns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystem_mapping_known() {
        assert_eq!(osv_ecosystem("npm"), "npm");
        assert_eq!(osv_ecosystem("pypi"), "PyPI");
        assert_eq!(osv_ecosystem("go"), "Go");
    }

    #[test]
    fn ecosystem_mapping_unknown_returns_empty() {
        assert_eq!(osv_ecosystem("rubygems"), "");
        assert_eq!(osv_ecosystem(""), "");
    }

    #[test]
    fn rank_severity_thresholds() {
        let s = |n: &str| OsvSeverity {
            kind: "CVSS_V3".into(),
            score: n.into(),
        };
        assert_eq!(rank_severity(&[s("9.8")]), "critical");
        assert_eq!(rank_severity(&[s("9.0")]), "critical");
        assert_eq!(rank_severity(&[s("8.9")]), "high");
        assert_eq!(rank_severity(&[s("7.0")]), "high");
        assert_eq!(rank_severity(&[s("6.9")]), "medium");
        assert_eq!(rank_severity(&[s("4.0")]), "medium");
        assert_eq!(rank_severity(&[s("3.9")]), "low");
        assert_eq!(rank_severity(&[s("0.1")]), "low");
    }

    #[test]
    fn rank_severity_empty_or_vector_only_is_unknown() {
        assert_eq!(rank_severity(&[]), "unknown");
        let vector_only = OsvSeverity {
            kind: "CVSS_V3".into(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
        };
        assert_eq!(rank_severity(&[vector_only]), "unknown");
    }

    #[test]
    fn rank_severity_picks_highest() {
        let s = |n: &str| OsvSeverity {
            kind: "CVSS_V3".into(),
            score: n.into(),
        };
        assert_eq!(rank_severity(&[s("4.5"), s("9.1"), s("6.0")]), "critical");
    }
}
