//! Machine-readable output renderers for `arcis sca`.
//!
//! Closes the CI parity gap with `arcis audit` (see cli-test round-1 bug
//! 6). The audit machine-output module — `audit/render.rs` — sets the
//! shape contract; this module mirrors the same conventions (sorted
//! BTreeMap keys, deterministic field order, ASCII-only string escaping)
//! so a downstream consumer can apply the same JSON schema validation to
//! both surfaces.
//!
//! Schema is documented at the top of each public function.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::sca::{Finding, FindingType};

// ── render_json ─────────────────────────────────────────────────────────────

/// Inputs for [`render_json`]. Caller is responsible for sorting and
/// filtering — the renderer just serialises what it's given.
pub struct ScaJsonReport<'a> {
    pub tool_version: &'a str,
    pub target: &'a str,
    pub manifests: &'a [PathBuf],
    pub threat_db_size: usize,
    pub findings: &'a [Finding],
    pub duration_ms: u64,
    /// `"offline"` (embedded DB only) or `"osv-augmented"` (embedded +
    /// live OSV.dev calls). Mirrors the human-mode `Mode:` banner row.
    pub mode: &'a str,
}

/// Render the sca result as a JSON document.
///
/// Schema:
/// ```text
/// {
///   "tool": "arcis-sca",
///   "version": "<tool_version>",
///   "target": "<abs target dir>",
///   "durationMs": N,
///   "mode": "offline" | "osv-augmented",
///   "summary": {
///     "manifests": ["requirements.txt", ...],
///     "manifestCount": N,
///     "threatDbSize": N,
///     "compromisedCount": N,
///     "bySeverity": { "critical": N, "high": N, "medium": N, "low": N },
///     "byEcosystem": { "pypi": N, "npm": N, ... },
///     "byFindingType": { "compromised_version": N, "trojanized_dep": N, ... }
///   },
///   "findings": [
///     {
///       "package": "...", "ecosystem": "...", "version": "...",
///       "severity": "...", "location": "...", "attackVector": "...",
///       "remediation": "...", "source": "...",
///       "references": [...],
///       "findingType": "compromised_version" | ...,
///       "paths": [["root", "...", "leaf"], ...],
///       "pathCount": N
///     }
///   ]
/// }
/// ```
pub fn render_json(report: &ScaJsonReport<'_>) -> String {
    let mut doc = Map::new();
    doc.insert("tool".into(), Value::from("arcis-sca"));
    doc.insert("version".into(), Value::from(report.tool_version));
    doc.insert("target".into(), Value::from(report.target));
    doc.insert("durationMs".into(), Value::from(report.duration_ms));
    doc.insert("mode".into(), Value::from(report.mode));

    let mut summary = Map::new();

    let manifests_arr: Vec<Value> = report
        .manifests
        .iter()
        .map(|m| {
            let name = m
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| m.display().to_string());
            Value::from(name)
        })
        .collect();
    summary.insert("manifests".into(), Value::Array(manifests_arr));
    summary.insert("manifestCount".into(), Value::from(report.manifests.len()));
    summary.insert("threatDbSize".into(), Value::from(report.threat_db_size));
    summary.insert(
        "compromisedCount".into(),
        Value::from(report.findings.len()),
    );

    // bySeverity — always emits all four canonical levels so consumers
    // don't have to guard on missing keys. Order matches audit's
    // `bySeverity` for cross-surface consistency.
    let mut by_sev_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for level in &["critical", "high", "medium", "low"] {
        by_sev_counts.insert(level, 0);
    }
    for f in report.findings {
        *by_sev_counts.entry(f.severity.as_str()).or_insert(0) += 1;
    }
    let mut by_sev = Map::new();
    for level in &["critical", "high", "medium", "low"] {
        by_sev.insert((*level).into(), Value::from(by_sev_counts[level]));
    }
    summary.insert("bySeverity".into(), Value::Object(by_sev));

    // byEcosystem — derived from findings; alphabetised for stable
    // output. Empty when there are no findings.
    let mut by_eco: BTreeMap<String, usize> = BTreeMap::new();
    for f in report.findings {
        *by_eco.entry(f.ecosystem.clone()).or_insert(0) += 1;
    }
    let mut eco_obj = Map::new();
    for (k, v) in &by_eco {
        eco_obj.insert(k.clone(), Value::from(*v));
    }
    summary.insert("byEcosystem".into(), Value::Object(eco_obj));

    // byFindingType — surfaces the trojanized-dep / persistence-artifact
    // breakdown that the human report uses for the post-DB sweep. All
    // three variants emitted (zero values included) so consumers don't
    // guard on missing keys.
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    by_kind.insert("compromised_version", 0);
    by_kind.insert("trojanized_dep", 0);
    by_kind.insert("persistence_artifact", 0);
    for f in report.findings {
        *by_kind.entry(f.finding_type.label()).or_insert(0) += 1;
    }
    let mut kind_obj = Map::new();
    for k in &[
        "compromised_version",
        "trojanized_dep",
        "persistence_artifact",
    ] {
        kind_obj.insert((*k).into(), Value::from(by_kind[k]));
    }
    summary.insert("byFindingType".into(), Value::Object(kind_obj));

    doc.insert("summary".into(), Value::Object(summary));

    let mut findings_arr = Vec::with_capacity(report.findings.len());
    for f in report.findings {
        let mut item = Map::new();
        item.insert("package".into(), Value::from(f.package.as_str()));
        item.insert("ecosystem".into(), Value::from(f.ecosystem.as_str()));
        item.insert("version".into(), Value::from(f.version.as_str()));
        item.insert("severity".into(), Value::from(f.severity.as_str()));
        item.insert("location".into(), Value::from(f.location.as_str()));
        item.insert("attackVector".into(), Value::from(f.attack_vector.as_str()));
        item.insert("remediation".into(), Value::from(f.remediation.as_str()));
        item.insert("source".into(), Value::from(f.source.as_str()));
        let refs: Vec<Value> = f
            .references
            .iter()
            .map(|r| Value::from(r.as_str()))
            .collect();
        item.insert("references".into(), Value::Array(refs));
        item.insert("findingType".into(), Value::from(f.finding_type.label()));
        let paths: Vec<Value> = f
            .paths
            .iter()
            .map(|chain| Value::Array(chain.iter().map(|n| Value::from(n.as_str())).collect()))
            .collect();
        item.insert("paths".into(), Value::Array(paths));
        item.insert("pathCount".into(), Value::from(f.path_count));
        findings_arr.push(Value::Object(item));
    }
    doc.insert("findings".into(), Value::Array(findings_arr));

    let raw = serde_json::to_string_pretty(&Value::Object(doc))
        .expect("serde_json never fails on values built from owned data");
    escape_non_ascii(&raw)
}

// ── render_sarif ────────────────────────────────────────────────────────────

pub struct ScaSarifReport<'a> {
    pub tool_version: &'a str,
    /// Absolute path to the scanned target dir. Used for
    /// `runs[0].originalUriBaseIds.TARGET.uri` after `\\`-to-`/`
    /// normalisation and trailing-slash addition.
    pub target_abspath: &'a str,
    pub findings: &'a [Finding],
}

fn sarif_level(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Render the sca result as SARIF 2.1.0 for GitHub Code Scanning.
///
/// SARIF model for SCA:
/// * `rules` = one entry per distinct `(ecosystem, package)` pair seen in
///   findings. The `id` is `sca/<ecosystem>/<package>` so it stays unique
///   across ecosystems even when names collide.
/// * `results` = one per finding. `locations` points at the manifest file
///   that surfaced the finding.
/// * `partialFingerprints[arcis/sca/v1]` = stable hash of
///   `(ecosystem, package, version, location)` so GitHub Code Scanning
///   can de-duplicate across runs.
pub fn render_sarif(report: &ScaSarifReport<'_>) -> String {
    // First-occurrence order of (ecosystem, package) keys.
    let mut rule_keys: Vec<(String, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for f in report.findings {
        let key = (f.ecosystem.clone(), f.package.clone());
        if seen.insert(key.clone()) {
            rule_keys.push(key);
        }
    }

    // Per-rule first finding so the rule entry can carry attack-vector
    // text. Most consumers only care that the id+name match the result's
    // ruleId; we attach a description for human readers.
    let mut sarif_rules = Vec::with_capacity(rule_keys.len());
    for (eco, pkg) in &rule_keys {
        let rep = report
            .findings
            .iter()
            .find(|f| &f.ecosystem == eco && &f.package == pkg)
            .expect("rule_keys is derived from findings; at least one match guaranteed");
        let rule_id = format!("sca/{eco}/{pkg}");
        let short = rep
            .attack_vector
            .split_once(". ")
            .map(|(before, _)| before)
            .unwrap_or(rep.attack_vector.as_str());
        let short_120: String = short.chars().take(120).collect();

        let mut entry = Map::new();
        entry.insert("id".into(), Value::from(rule_id.clone()));
        entry.insert("name".into(), Value::from(rule_id));
        let mut short_obj = Map::new();
        short_obj.insert("text".into(), Value::from(short_120));
        entry.insert("shortDescription".into(), Value::Object(short_obj));
        let mut full_obj = Map::new();
        full_obj.insert("text".into(), Value::from(rep.attack_vector.as_str()));
        entry.insert("fullDescription".into(), Value::Object(full_obj));
        let mut default_cfg = Map::new();
        default_cfg.insert("level".into(), Value::from(sarif_level(&rep.severity)));
        entry.insert("defaultConfiguration".into(), Value::Object(default_cfg));
        sarif_rules.push(Value::Object(entry));
    }

    let mut results = Vec::with_capacity(report.findings.len());
    for f in report.findings {
        let rel = relpath_from_cwd(Path::new(&f.location)).replace('\\', "/");
        let rule_id = format!("sca/{}/{}", f.ecosystem, f.package);

        let mut region = Map::new();
        // Manifests don't carry a line number — point at line 1 so SARIF
        // validators accept the result. GitHub Code Scanning collapses
        // multiple line-1 results in the same file under one row.
        region.insert("startLine".into(), Value::from(1));

        let mut artifact = Map::new();
        artifact.insert("uri".into(), Value::from(rel.clone()));

        let mut physical = Map::new();
        physical.insert("artifactLocation".into(), Value::Object(artifact));
        physical.insert("region".into(), Value::Object(region));

        let mut location = Map::new();
        location.insert("physicalLocation".into(), Value::Object(physical));

        let message_text = format!(
            "{} {} ({}) — {}",
            f.package, f.version, f.ecosystem, f.attack_vector
        );

        let mut result = Map::new();
        result.insert("ruleId".into(), Value::from(rule_id));
        result.insert("level".into(), Value::from(sarif_level(&f.severity)));
        let mut message = Map::new();
        message.insert("text".into(), Value::from(message_text));
        result.insert("message".into(), Value::Object(message));
        result.insert(
            "locations".into(),
            Value::Array(vec![Value::Object(location)]),
        );
        // Stable per-instance fingerprint. Versioned key so the hash
        // domain can rotate without colliding with audit's `arcis/v1`.
        let fingerprint = format!("{}|{}|{}|{}", f.ecosystem, f.package, f.version, f.location);
        let mut pf = Map::new();
        pf.insert("arcis/sca/v1".into(), Value::from(fingerprint));
        result.insert("partialFingerprints".into(), Value::Object(pf));
        results.push(Value::Object(result));
    }

    let mut driver = Map::new();
    driver.insert("name".into(), Value::from("arcis-sca"));
    driver.insert("version".into(), Value::from(report.tool_version));
    driver.insert("informationUri".into(), Value::from("https://arcis.dev"));
    driver.insert("rules".into(), Value::Array(sarif_rules));

    let mut tool = Map::new();
    tool.insert("driver".into(), Value::Object(driver));

    let target_uri = {
        let normalized = report.target_abspath.replace('\\', "/");
        let trimmed = normalized.trim_end_matches('/');
        format!("{trimmed}/")
    };
    let mut target_obj = Map::new();
    target_obj.insert("uri".into(), Value::from(target_uri));
    let mut original_uri_base_ids = Map::new();
    original_uri_base_ids.insert("TARGET".into(), Value::Object(target_obj));

    let mut run = Map::new();
    run.insert("tool".into(), Value::Object(tool));
    run.insert("results".into(), Value::Array(results));
    run.insert(
        "originalUriBaseIds".into(),
        Value::Object(original_uri_base_ids),
    );

    let mut doc = Map::new();
    doc.insert("version".into(), Value::from("2.1.0"));
    doc.insert(
        "$schema".into(),
        Value::from(
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        ),
    );
    doc.insert("runs".into(), Value::Array(vec![Value::Object(run)]));

    let raw = serde_json::to_string_pretty(&Value::Object(doc))
        .expect("serde_json never fails on values built from owned data");
    escape_non_ascii(&raw)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Best-effort relpath-from-cwd. Falls back to the raw path if it can't
/// be relativised (different drive on Windows, target outside cwd, etc.).
fn relpath_from_cwd(p: &Path) -> String {
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(_) => return p.display().to_string(),
    };
    match pathdiff_relative(p, &cwd) {
        Some(rel) => rel.display().to_string(),
        None => p.display().to_string(),
    }
}

/// Minimal pathdiff implementation — produces a relative path from `base`
/// to `target` using `..` segments where needed. Inlined so the engine
/// doesn't pick up a new dep just for this one helper. Returns `None`
/// when the paths share no common prefix (e.g. different drives on
/// Windows).
fn pathdiff_relative(target: &Path, base: &Path) -> Option<PathBuf> {
    if target.is_absolute() != base.is_absolute() {
        return None;
    }
    let mut t_comps = target.components();
    let mut b_comps = base.components();
    let mut out = PathBuf::new();
    loop {
        match (t_comps.next(), b_comps.next()) {
            (None, None) => break,
            (Some(t), None) => {
                out.push(t.as_os_str());
                for c in t_comps.by_ref() {
                    out.push(c.as_os_str());
                }
                break;
            }
            (None, _) => out.push(".."),
            (Some(t), Some(b)) if t == b => continue,
            (Some(t), Some(_)) => {
                out.push("..");
                for _ in b_comps.by_ref() {
                    out.push("..");
                }
                out.push(t.as_os_str());
                for c in t_comps.by_ref() {
                    out.push(c.as_os_str());
                }
                break;
            }
        }
    }
    Some(out)
}

/// Python `json.dumps(..., ensure_ascii=True)` equivalent: every codepoint
/// >= U+0080 emitted as `\uXXXX`. Mirrors the audit renderer's same-named
/// helper so consumers can apply the same downstream validation pipeline
/// to both surfaces.
fn escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_string = false;
    let mut escape_next = false;
    for ch in s.chars() {
        if escape_next {
            out.push(ch);
            escape_next = false;
            continue;
        }
        if in_string && ch == '\\' {
            out.push(ch);
            escape_next = true;
            continue;
        }
        if ch == '"' {
            in_string = !in_string;
            out.push(ch);
            continue;
        }
        if in_string && (ch as u32) >= 0x80 {
            let cp = ch as u32;
            if cp <= 0xFFFF {
                out.push_str(&format!("\\u{cp:04x}"));
            } else {
                // Supplementary plane → surrogate pair.
                let adjusted = cp - 0x10000;
                let high = 0xD800 + (adjusted >> 10);
                let low = 0xDC00 + (adjusted & 0x3FF);
                out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
            }
        } else {
            out.push(ch);
        }
    }
    out
}

// ── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sca::FindingType;

    fn mock_colourama() -> Finding {
        Finding {
            package: "colourama".into(),
            ecosystem: "pypi".into(),
            version: "0.1.6".into(),
            severity: "critical".into(),
            location: "/tmp/proj/requirements.txt".into(),
            attack_vector: "Typosquat of colorama. Replaces crypto addresses.".into(),
            remediation: "pip uninstall colourama; pip install colorama".into(),
            source: "PyPI Security Advisory".into(),
            references: vec!["https://snyk.io/research/x".into()],
            finding_type: FindingType::CompromisedVersion,
            paths: vec![],
            path_count: 0,
        }
    }

    #[test]
    fn json_clean_run_is_valid() {
        // A clean run (no findings) must still emit a parseable document
        // with all summary fields present at zero — CI consumers should
        // never have to handle a missing key on a green run.
        let report = ScaJsonReport {
            tool_version: "1.0.0",
            target: "/tmp/proj",
            manifests: &[PathBuf::from("/tmp/proj/requirements.txt")],
            threat_db_size: 100,
            findings: &[],
            duration_ms: 5,
            mode: "offline",
        };
        let s = render_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["tool"], "arcis-sca");
        assert_eq!(v["summary"]["compromisedCount"], 0);
        assert_eq!(v["summary"]["bySeverity"]["critical"], 0);
        assert_eq!(v["summary"]["byFindingType"]["compromised_version"], 0);
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn json_with_colourama_finding() {
        let findings = vec![mock_colourama()];
        let report = ScaJsonReport {
            tool_version: "1.0.0",
            target: "/tmp/proj",
            manifests: &[PathBuf::from("/tmp/proj/requirements.txt")],
            threat_db_size: 100,
            findings: &findings,
            duration_ms: 5,
            mode: "offline",
        };
        let s = render_json(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["summary"]["compromisedCount"], 1);
        assert_eq!(v["summary"]["bySeverity"]["critical"], 1);
        assert_eq!(v["summary"]["byEcosystem"]["pypi"], 1);
        let first = &v["findings"][0];
        assert_eq!(first["package"], "colourama");
        assert_eq!(first["version"], "0.1.6");
        assert_eq!(first["severity"], "critical");
        assert_eq!(first["findingType"], "compromised_version");
        assert_eq!(first["references"][0], "https://snyk.io/research/x");
    }

    #[test]
    fn sarif_clean_run_is_valid() {
        let report = ScaSarifReport {
            tool_version: "1.0.0",
            target_abspath: "/tmp/proj",
            findings: &[],
        };
        let s = render_sarif(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "arcis-sca");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(
            v["runs"][0]["tool"]["driver"]["rules"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn sarif_with_colourama_finding() {
        let findings = vec![mock_colourama()];
        let report = ScaSarifReport {
            tool_version: "1.0.0",
            target_abspath: "/tmp/proj",
            findings: &findings,
        };
        let s = render_sarif(&report);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 1);
        let first = &v["runs"][0]["results"][0];
        assert_eq!(first["ruleId"], "sca/pypi/colourama");
        assert_eq!(first["level"], "error"); // critical maps to error
        assert!(first["partialFingerprints"]["arcis/sca/v1"]
            .as_str()
            .unwrap()
            .contains("colourama"));
        let rule = &v["runs"][0]["tool"]["driver"]["rules"][0];
        assert_eq!(rule["id"], "sca/pypi/colourama");
    }

    #[test]
    fn sarif_severity_to_level_mapping() {
        assert_eq!(sarif_level("critical"), "error");
        assert_eq!(sarif_level("high"), "error");
        assert_eq!(sarif_level("medium"), "warning");
        assert_eq!(sarif_level("low"), "note");
        assert_eq!(sarif_level("unknown"), "note"); // fallback
    }

    #[test]
    fn escape_non_ascii_string_body() {
        // Outside-string characters pass through; inside-string codepoints
        // >= 0x80 escape as \uXXXX. Mirrors json.dumps(ensure_ascii=True).
        let v: Value = serde_json::from_str(r#"{"x":"café"}"#).unwrap();
        let rendered = serde_json::to_string_pretty(&v).unwrap();
        let escaped = escape_non_ascii(&rendered);
        assert!(
            escaped.contains("\\u00e9"),
            "non-ASCII inside string must be escaped: {escaped}"
        );
    }
}
