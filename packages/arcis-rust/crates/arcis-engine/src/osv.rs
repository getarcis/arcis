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
const OSV_QUERY_BATCH_URL: &str = "https://api.osv.dev/v1/querybatch";

/// OSV.dev's hard cap on a single `/v1/querybatch` payload. Lookups
/// beyond this are split into multiple sequential POSTs.
pub const OSV_MAX_QUERIES_PER_BATCH: usize = 1000;

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

/// `/v1/querybatch` request body. Order is preserved in the response —
/// `results[i]` corresponds to `queries[i]`.
#[derive(Debug, Serialize)]
struct OsvBatchQuery<'a> {
    queries: Vec<OsvQuery<'a>>,
}

/// `/v1/querybatch` response. Each result entry is a `vulns` list shaped
/// like a single-query response. Vulns inside are NOT fully hydrated by
/// OSV — they carry only `id` and `modified`; the caller needs to follow
/// up with `/v1/vulns/{id}` for full data. For Arcis we only need the
/// id at the batch stage, so we keep the shape minimal.
#[derive(Debug, Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvBatchResultEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct OsvBatchResultEntry {
    #[serde(default)]
    vulns: Vec<OsvBatchVulnRef>,
}

/// Minimal shape returned in a batch query — just the vuln id. The
/// caller hydrates this to a full `OsvVuln` via `query()` or `vulns_by_id()`.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct OsvBatchVulnRef {
    pub id: String,
    #[serde(default)]
    pub modified: String,
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

/// One package lookup request, paired so callers can stitch responses
/// back to their original input set.
#[derive(Debug, Clone)]
pub struct BatchInput {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// Query OSV.dev's `/v1/querybatch` endpoint for a list of packages. Up
/// to `OSV_MAX_QUERIES_PER_BATCH` queries fit in one POST; longer input
/// lists are split into multiple sequential POSTs. Returns one
/// `Vec<OsvBatchVulnRef>` per input entry, in input order — empty entry
/// = no vulnerabilities for that package.
///
/// Packages with unknown ecosystem or empty fields are skipped (their
/// result slot is `Vec::new()`), matching the single-query behavior.
///
/// Batch responses carry only `id` + `modified` for each vuln. Callers
/// that need full severity/summary/refs follow up with `query()` per id
/// or, for the existing Arcis sca flow, call `query()` on the packages
/// the batch flagged as non-empty — a typical project produces a few
/// dozen hits at most, so the secondary lookups are cheap.
///
/// Vendor attribution: the batch endpoint contract, chunking strategy,
/// and response ordering invariant are modeled on osv-scanner /
/// osv.dev's Go bindings (Apache-2.0). See `THIRDPARTY-LICENSES.md`.
pub async fn query_batch(
    client: &Client,
    inputs: &[BatchInput],
    timeout: Duration,
) -> Result<Vec<Vec<OsvBatchVulnRef>>, OsvError> {
    if inputs.is_empty() {
        return Ok(Vec::new());
    }

    // Index of every input we actually queried. Skipped entries (unknown
    // ecosystem / empty fields) get an empty result later.
    let mut sendable_indices: Vec<usize> = Vec::with_capacity(inputs.len());
    let mut sendable_ecosystems: Vec<&'static str> = Vec::with_capacity(inputs.len());
    for (idx, inp) in inputs.iter().enumerate() {
        let eco = osv_ecosystem(&inp.ecosystem);
        if !eco.is_empty() && !inp.name.is_empty() && !inp.version.is_empty() {
            sendable_indices.push(idx);
            sendable_ecosystems.push(eco);
        }
    }

    let mut results: Vec<Vec<OsvBatchVulnRef>> = vec![Vec::new(); inputs.len()];
    if sendable_indices.is_empty() {
        return Ok(results);
    }

    // Chunk by OSV's per-batch cap. Sequential POSTs keep the
    // implementation simple; concurrent posting is a v1.8 optimization.
    for chunk_start in (0..sendable_indices.len()).step_by(OSV_MAX_QUERIES_PER_BATCH) {
        let chunk_end = (chunk_start + OSV_MAX_QUERIES_PER_BATCH).min(sendable_indices.len());
        let chunk = &sendable_indices[chunk_start..chunk_end];

        let queries: Vec<OsvQuery> = chunk
            .iter()
            .enumerate()
            .map(|(local_idx, &input_idx)| OsvQuery {
                package: OsvPackageRef {
                    name: &inputs[input_idx].name,
                    ecosystem: sendable_ecosystems[chunk_start + local_idx],
                },
                version: &inputs[input_idx].version,
            })
            .collect();

        let body = OsvBatchQuery { queries };
        let resp = client
            .post(OSV_QUERY_BATCH_URL)
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
        let parsed: OsvBatchResponse =
            serde_json::from_slice(&bytes).map_err(|_| OsvError::EmptyBody)?;

        // OSV preserves order: results[i] ↔ queries[i].
        if parsed.results.len() != chunk.len() {
            // Length mismatch is an OSV protocol error; bail rather than
            // misalign results.
            return Err(OsvError::HttpStatus(0));
        }
        for (local_idx, entry) in parsed.results.into_iter().enumerate() {
            let input_idx = chunk[local_idx];
            results[input_idx] = entry.vulns;
        }
    }

    Ok(results)
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

    #[test]
    fn batch_skips_inputs_with_empty_fields() {
        // Direct test of the skip-logic. We can't easily test the HTTP
        // round-trip without a fixture server, but the input-filtering
        // step is pure and worth pinning.
        let inputs = [
            BatchInput {
                ecosystem: "npm".into(),
                name: "axios".into(),
                version: "1.6.0".into(),
            },
            BatchInput {
                ecosystem: "rubygems".into(), // unknown ecosystem
                name: "rails".into(),
                version: "7.0.0".into(),
            },
            BatchInput {
                ecosystem: "npm".into(),
                name: "".into(), // empty name
                version: "1.0.0".into(),
            },
            BatchInput {
                ecosystem: "pypi".into(),
                name: "requests".into(),
                version: "".into(), // empty version
            },
            BatchInput {
                ecosystem: "go".into(),
                name: "github.com/foo/bar".into(),
                version: "v1.0.0".into(),
            },
        ];
        // Reproduce the filter inline (same logic as query_batch's
        // sendable_indices construction).
        let mut kept = Vec::new();
        for (i, inp) in inputs.iter().enumerate() {
            let eco = osv_ecosystem(&inp.ecosystem);
            if !eco.is_empty() && !inp.name.is_empty() && !inp.version.is_empty() {
                kept.push(i);
            }
        }
        // Indices 0 and 4 are sendable; 1 (unknown eco), 2 (empty name),
        // 3 (empty version) are skipped.
        assert_eq!(kept, vec![0, 4]);
    }

    #[test]
    fn batch_chunking_respects_max_size() {
        // 2,500 inputs at OSV_MAX_QUERIES_PER_BATCH=1000 should split
        // into 3 chunks of [1000, 1000, 500].
        let chunk_count = (0..2500_usize).step_by(OSV_MAX_QUERIES_PER_BATCH).count();
        assert_eq!(chunk_count, 3);
        // First chunk spans 0..1000.
        let first_start = 0;
        let first_end = (first_start + OSV_MAX_QUERIES_PER_BATCH).min(2500);
        assert_eq!(first_end - first_start, 1000);
        // Last chunk spans 2000..2500.
        let last_start = 2000;
        let last_end = (last_start + OSV_MAX_QUERIES_PER_BATCH).min(2500);
        assert_eq!(last_end - last_start, 500);
    }

    #[test]
    fn batch_input_clone_is_independent() {
        let a = BatchInput {
            ecosystem: "npm".into(),
            name: "lodash".into(),
            version: "4.17.21".into(),
        };
        let b = a.clone();
        assert_eq!(a.name, b.name);
        assert_eq!(a.ecosystem, b.ecosystem);
        assert_eq!(a.version, b.version);
    }

    #[test]
    fn batch_vuln_ref_deserializes_from_minimal_json() {
        let json = r#"{"id": "GHSA-test"}"#;
        let parsed: OsvBatchVulnRef = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.id, "GHSA-test");
        assert_eq!(parsed.modified, "");
    }

    #[test]
    fn batch_response_parses_full_shape() {
        let json = r#"{
            "results": [
                { "vulns": [ { "id": "GHSA-1", "modified": "2026-05-01T00:00:00Z" } ] },
                { "vulns": [] },
                { }
            ]
        }"#;
        let parsed: OsvBatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.results.len(), 3);
        assert_eq!(parsed.results[0].vulns.len(), 1);
        assert_eq!(parsed.results[0].vulns[0].id, "GHSA-1");
        assert_eq!(parsed.results[1].vulns.len(), 0);
        assert_eq!(parsed.results[2].vulns.len(), 0);
    }

    #[tokio::test]
    async fn batch_with_empty_input_returns_empty_result() {
        let client = Client::new();
        let result = query_batch(&client, &[], Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn batch_with_only_unsendable_inputs_returns_empty_slots() {
        let client = Client::new();
        let inputs = [
            BatchInput {
                ecosystem: "unknown-eco".into(),
                name: "foo".into(),
                version: "1.0".into(),
            },
            BatchInput {
                ecosystem: "npm".into(),
                name: "".into(),
                version: "1.0".into(),
            },
        ];
        let result = query_batch(&client, &inputs, Duration::from_secs(1)).await;
        assert!(result.is_ok());
        let slots = result.unwrap();
        assert_eq!(slots.len(), 2);
        assert!(slots.iter().all(|s| s.is_empty()));
    }
}
