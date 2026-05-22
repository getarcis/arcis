//! Baseline snapshots for `arcis audit` (cli-audit.md Phase B item 9).
//!
//! A baseline is a JSON record of a previous audit run's finding IDs.
//! The CLI consumes one in two modes:
//!
//! * **Write** (`--baseline-write <path>`) — record current findings to
//!   disk so future runs can compare against them. Always exit 0.
//! * **Read** (`--baseline <path>`) — classify current findings against
//!   the recorded set, emit only NEW ones, ignore unchanged, surface
//!   resolved as a positive signal. Exit code reflects added only.
//!
//! Identity comes from [`super::finding_id`] — `<RULE_ID>-<16hex>` over
//! `(rule_id, relpath, line, snippet.trim_end())`. Because `rule_id`
//! participates in the hash, a rename of a rule produces a NEW id and
//! falls into a paired resolved+added entry, NOT a stale entry. "Stale"
//! is reserved for rule IDs that no longer appear in the registry at
//! all (rule deleted or renamed without baseline regeneration).
//!
//! ## Hand-rolled timestamp duplication
//!
//! [`iso8601_utc`] duplicates the helper in `sca_sbom.rs`. Per the
//! cross-track ADD-ONLY rule we don't reach into a sibling track's
//! file to expose its private formatter; both copies will fold into a
//! shared `arcis_engine::time` module after Phase 1 consolidates.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::engine::Finding;
use super::rules::rules as compiled_rules;

/// Current baseline schema version. Bump if the on-disk shape of a
/// baseline file changes incompatibly. [`Baseline::read`] enforces
/// equality and returns [`BaselineError::UnsupportedVersion`] on
/// mismatch.
pub const BASELINE_SCHEMA_VERSION: u32 = 1;

/// One entry in a baseline file. Carries enough to display a resolved
/// finding in human output without rerunning the original scan, but no
/// message / severity / snippet bodies — those are the current run's
/// responsibility, not the baseline's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub id: String,
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub file: String,
    pub line: usize,
}

/// On-disk baseline snapshot.
///
/// **Locked schema (version 1).** This struct serializes to exactly
/// these top-level keys, in this order:
///
/// 1. `version`     — integer, equal to [`BASELINE_SCHEMA_VERSION`]
/// 2. `createdAt`   — ISO 8601 UTC string `YYYY-MM-DDTHH:MM:SSZ`
/// 3. `toolVersion` — informational; never enforced on read
/// 4. `findings`    — array of [`BaselineEntry`] in scan order
///
/// Each [`BaselineEntry`] serializes as `{id, ruleId, file, line}` —
/// no other keys.
///
/// Future schema extensions MUST bump [`BASELINE_SCHEMA_VERSION`] AND
/// add the field to the enumeration above. Adding a field without
/// bumping the version is a contract break — older Arcis builds would
/// silently ignore the new field and produce wrong diffs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "toolVersion")]
    pub tool_version: String,
    pub findings: Vec<BaselineEntry>,
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("baseline file not found: {0}")]
    NotFound(String),
    #[error("baseline file unreadable ({0}): {1}")]
    Io(String, io::Error),
    #[error("baseline file malformed ({0}): {1}")]
    Malformed(String, serde_json::Error),
    #[error("baseline schema version {0} not supported (this build expects {1})")]
    UnsupportedVersion(u32, u32),
}

impl Baseline {
    /// Build a baseline from current scan findings. Caller MUST have
    /// already populated `Finding.id` via
    /// [`super::finding_id::assign_ids`]; findings with an empty id are
    /// skipped because the baseline could not recognise them on a
    /// later run.
    pub fn from_findings(findings: &[Finding], tool_version: &str) -> Self {
        let entries: Vec<BaselineEntry> = findings
            .iter()
            .filter(|f| !f.id.is_empty())
            .map(|f| BaselineEntry {
                id: f.id.clone(),
                rule_id: f.rule_id.to_string(),
                file: f.file.clone(),
                line: f.line,
            })
            .collect();
        Self {
            version: BASELINE_SCHEMA_VERSION,
            created_at: iso8601_utc_now(),
            tool_version: tool_version.to_string(),
            findings: entries,
        }
    }

    /// Read a baseline from disk. Returns typed errors for
    /// missing-file, IO, malformed-JSON, and version-mismatch — the
    /// CLI maps each to exit 2 with a specific stderr message.
    pub fn read(path: &Path) -> Result<Self, BaselineError> {
        let raw = match crate::fs_util::read_to_string_stripped(path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(BaselineError::NotFound(path.display().to_string()));
            }
            Err(e) => return Err(BaselineError::Io(path.display().to_string(), e)),
        };
        let parsed: Self = serde_json::from_str(&raw)
            .map_err(|e| BaselineError::Malformed(path.display().to_string(), e))?;
        if parsed.version != BASELINE_SCHEMA_VERSION {
            return Err(BaselineError::UnsupportedVersion(
                parsed.version,
                BASELINE_SCHEMA_VERSION,
            ));
        }
        Ok(parsed)
    }

    /// Atomically write the baseline to `path`.
    ///
    /// Strategy: write to `<path>.tmp` (deterministic suffix so a
    /// crashed run leaves at most one easy-to-clean turd, never a
    /// PID/nonce-suffixed pile), `sync_all`, then rename over the
    /// destination. `std::fs::rename` is atomic on POSIX and uses
    /// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows for files
    /// in the same directory — both atomic in the sense relevant here
    /// (a reader either sees the old file or the new one, never a
    /// half-written one).
    pub fn write(&self, path: &Path) -> Result<(), BaselineError> {
        let tmp = tmp_path(path);
        let payload = serde_json::to_string_pretty(self)
            .map_err(|e| BaselineError::Malformed(path.display().to_string(), e))?;
        {
            let mut f =
                File::create(&tmp).map_err(|e| BaselineError::Io(tmp.display().to_string(), e))?;
            f.write_all(payload.as_bytes())
                .map_err(|e| BaselineError::Io(tmp.display().to_string(), e))?;
            f.write_all(b"\n")
                .map_err(|e| BaselineError::Io(tmp.display().to_string(), e))?;
            f.sync_all()
                .map_err(|e| BaselineError::Io(tmp.display().to_string(), e))?;
        }
        fs::rename(&tmp, path).map_err(|e| BaselineError::Io(path.display().to_string(), e))?;
        Ok(())
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    s.into()
}

/// Result of comparing a current scan's findings against a baseline.
///
/// `added` carries the full current [`Finding`] bodies — they will be
/// surfaced in the JSON output and human report. `resolved` carries
/// only the minimal records that were in the baseline; the original
/// finding context is lost (not a regression — the baseline was the
/// last record we kept of those findings).
///
/// `stale_rule_ids` is populated when a baseline entry's `ruleId` is
/// not present in the current rule registry. Surfaced as a warning;
/// never fails the run. Stale entries also flow through the
/// resolved-vs-unchanged classification on `id` like any other entry —
/// staleness is orthogonal to whether the id matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<Finding>,
    pub resolved: Vec<BaselineEntry>,
    pub unchanged_count: usize,
    pub stale_count: usize,
    pub stale_rule_ids: Vec<String>,
}

/// Classify `current` findings against `baseline`.
///
/// Identity is by [`Finding::id`] exclusively. A finding's id encodes
/// `(rule_id, relpath, line, snippet)` so any of: rule rename, file
/// move, line drift past the snippet, code edit on the offending line
/// — surfaces as a paired resolved+added pair, the correct outcome.
///
/// Stale-baseline detection scans every baseline `ruleId` against the
/// compiled rule registry; entries whose rule has been removed from
/// the registry are counted in `stale_count` (and de-duplicated into
/// `stale_rule_ids`) but still flow through the classification on `id`
/// like any other entry. The CLI surfaces stale as a warning, not a
/// failure.
pub fn classify(current: &[Finding], baseline: &Baseline) -> Diff {
    use std::collections::HashSet;

    let baseline_ids: HashSet<&str> = baseline.findings.iter().map(|e| e.id.as_str()).collect();
    let current_ids: HashSet<&str> = current.iter().map(|f| f.id.as_str()).collect();

    let valid_rule_ids: HashSet<&str> = compiled_rules().iter().map(|r| r.id).collect();

    let mut added: Vec<Finding> = Vec::new();
    let mut unchanged_count = 0usize;
    for f in current {
        if baseline_ids.contains(f.id.as_str()) {
            unchanged_count += 1;
        } else {
            added.push(f.clone());
        }
    }

    let mut resolved: Vec<BaselineEntry> = Vec::new();
    let mut stale_count = 0usize;
    let mut stale_rule_ids: Vec<String> = Vec::new();
    for entry in &baseline.findings {
        if !current_ids.contains(entry.id.as_str()) {
            resolved.push(entry.clone());
        }
        if !valid_rule_ids.contains(entry.rule_id.as_str()) {
            stale_count += 1;
            if !stale_rule_ids.contains(&entry.rule_id) {
                stale_rule_ids.push(entry.rule_id.clone());
            }
        }
    }
    stale_rule_ids.sort();

    Diff {
        added,
        resolved,
        unchanged_count,
        stale_count,
        stale_rule_ids,
    }
}

/// Compact summary of a baseline + diff, ready to render into the
/// `--json` output's `summary.baseline` block. Owned by the engine so
/// the render layer stays a pure serializer over scalar inputs.
///
/// **Locked schema (matches [`super::render::JsonReport`]).** This
/// struct's fields map 1:1 to the keys emitted under `summary.baseline`
/// in the JSON output:
///
/// - `path`           → `path`
/// - `created_at`     → `createdAt`
/// - `added`          → `added`
/// - `resolved_count` → `resolvedCount`
/// - `unchanged_count`→ `unchangedCount`
/// - `stale_count`    → `staleCount`
///
/// Future fields MUST be added in BOTH places (here and the render
/// site) AND get a doc-comment bullet here so the contract is auditable
/// from the engine side without reading render.rs.
pub struct BaselineSummary<'a> {
    pub path: &'a str,
    pub created_at: &'a str,
    pub added: usize,
    pub resolved_count: usize,
    pub unchanged_count: usize,
    pub stale_count: usize,
}

// ── ISO 8601 helper ────────────────────────────────────────────────────────

fn iso8601_utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    iso8601_utc(secs)
}

/// Format `secs` since UNIX_EPOCH as `YYYY-MM-DDTHH:MM:SSZ`. Pure
/// arithmetic via Howard Hinnant's civil-from-days algorithm; no
/// chrono dep, no leap-second handling, valid for all proleptic
/// Gregorian dates representable by `i64` days. Mirrors the helper in
/// `sca_sbom.rs` (see module-doc note).
fn iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::engine::Finding;
    use crate::audit::rules::Severity;
    use tempfile::TempDir;

    // ── ISO 8601 ───────────────────────────────────────────────────────

    #[test]
    fn iso8601_at_epoch_zero() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_at_known_date() {
        // 2026-01-01T00:00:00Z = 56*365 days + 14 leap days
        // (1972,76,80,84,88,92,96,2000,04,08,12,16,20,24) since 1970,
        // each day = 86_400s. 56*365 + 14 = 20_454. * 86_400 = 1_767_225_600.
        assert_eq!(iso8601_utc(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn iso8601_with_hms_components() {
        // 2026-01-01T05:07:13Z = 1_767_225_600 + 5*3600 + 7*60 + 13.
        let secs = 1_767_225_600 + 5 * 3600 + 7 * 60 + 13;
        assert_eq!(iso8601_utc(secs), "2026-01-01T05:07:13Z");
    }

    #[test]
    fn iso8601_now_has_z_suffix_and_t_separator() {
        let s = iso8601_utc_now();
        assert!(s.ends_with('Z'), "missing Z suffix: {s}");
        assert_eq!(s.chars().filter(|&c| c == 'T').count(), 1);
        assert_eq!(s.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
    }

    // ── Helpers ────────────────────────────────────────────────────────

    fn finding(id: &str, rule_id: &'static str, file: &str, line: usize) -> Finding {
        Finding {
            rule_id,
            severity: Severity::High,
            message: "msg",
            file: file.to_string(),
            line,
            snippet: "x".to_string(),
            id: id.to_string(),
        }
    }

    fn entry(id: &str, rule_id: &str, file: &str, line: usize) -> BaselineEntry {
        BaselineEntry {
            id: id.to_string(),
            rule_id: rule_id.to_string(),
            file: file.to_string(),
            line,
        }
    }

    // ── from_findings ──────────────────────────────────────────────────

    #[test]
    fn from_findings_skips_empty_id_findings() {
        // Findings with empty id can't be recognised on a re-run, so
        // omitting them from the baseline is the right call — silently.
        let mut f1 = finding("YAML-UNSAFE-aaaaaaaaaaaaaaaa", "YAML-UNSAFE", "a.py", 1);
        let mut f2 = finding("", "YAML-UNSAFE", "b.py", 2);
        f1.snippet = "yaml.load(f)".into();
        f2.snippet = "yaml.load(g)".into();
        let b = Baseline::from_findings(&[f1, f2], "0.1.0");
        assert_eq!(b.findings.len(), 1);
        assert_eq!(b.findings[0].file, "a.py");
    }

    #[test]
    fn from_findings_records_id_ruleid_file_line() {
        let f = finding(
            "YAML-UNSAFE-deadbeefcafef00d",
            "YAML-UNSAFE",
            "src/a.py",
            42,
        );
        let b = Baseline::from_findings(&[f], "0.1.0");
        assert_eq!(b.findings[0].id, "YAML-UNSAFE-deadbeefcafef00d");
        assert_eq!(b.findings[0].rule_id, "YAML-UNSAFE");
        assert_eq!(b.findings[0].file, "src/a.py");
        assert_eq!(b.findings[0].line, 42);
        assert_eq!(b.tool_version, "0.1.0");
        assert_eq!(b.version, BASELINE_SCHEMA_VERSION);
    }

    // ── write + read round-trip ────────────────────────────────────────

    #[test]
    fn round_trip_write_then_read_preserves_data() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("baseline.json");
        let original = Baseline {
            version: 1,
            created_at: "2026-05-07T12:00:00Z".into(),
            tool_version: "0.1.0".into(),
            findings: vec![
                entry("YAML-UNSAFE-1111111111111111", "YAML-UNSAFE", "a.py", 1),
                entry("EVAL-USAGE-2222222222222222", "EVAL-USAGE", "b.py", 7),
            ],
        };
        original.write(&p).unwrap();
        let loaded = Baseline::read(&p).unwrap();
        assert_eq!(loaded, original);
    }

    #[test]
    fn write_atomic_leaves_no_tmp_on_success() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("baseline.json");
        let b = Baseline {
            version: 1,
            created_at: "2026-05-07T12:00:00Z".into(),
            tool_version: "0.1.0".into(),
            findings: vec![],
        };
        b.write(&p).unwrap();
        assert!(p.exists(), "baseline file missing");
        let tmp = tmp_path(&p);
        assert!(!tmp.exists(), "tmp turd left behind: {}", tmp.display());
    }

    #[test]
    fn write_uses_deterministic_tmp_suffix() {
        // Cleanup-after-crash relies on a single, predictable filename.
        // PID/nonce suffixes would produce a pile of orphans on
        // repeated crashes.
        let p = Path::new("/some/dir/baseline.json");
        assert_eq!(tmp_path(p).to_string_lossy(), "/some/dir/baseline.json.tmp");
    }

    #[test]
    fn write_emits_locked_schema_keys_in_order() {
        // The on-disk format is a contract. Pin the key order so a
        // future serde-derive flag flip can't silently scramble it.
        let td = TempDir::new().unwrap();
        let p = td.path().join("baseline.json");
        let b = Baseline {
            version: 1,
            created_at: "2026-05-07T12:00:00Z".into(),
            tool_version: "0.1.0".into(),
            findings: vec![entry(
                "YAML-UNSAFE-1111111111111111",
                "YAML-UNSAFE",
                "a.py",
                1,
            )],
        };
        b.write(&p).unwrap();
        let raw = crate::fs_util::read_to_string_stripped(&p).unwrap();
        let i_version = raw.find("\"version\"").unwrap();
        let i_created = raw.find("\"createdAt\"").unwrap();
        let i_tool = raw.find("\"toolVersion\"").unwrap();
        let i_findings = raw.find("\"findings\"").unwrap();
        assert!(i_version < i_created);
        assert!(i_created < i_tool);
        assert!(i_tool < i_findings);
        // Entry shape: {id, ruleId, file, line}, in that order.
        let i_id = raw.find("\"id\"").unwrap();
        let i_rule = raw.find("\"ruleId\"").unwrap();
        let i_file = raw.find("\"file\"").unwrap();
        let i_line = raw.find("\"line\"").unwrap();
        assert!(i_id < i_rule);
        assert!(i_rule < i_file);
        assert!(i_file < i_line);
    }

    // ── read errors ────────────────────────────────────────────────────

    #[test]
    fn read_missing_file_returns_typed_not_found() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("never-existed.json");
        let r = Baseline::read(&p);
        assert!(matches!(r, Err(BaselineError::NotFound(_))));
    }

    #[test]
    fn read_malformed_json_returns_typed_malformed() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("baseline.json");
        fs::write(&p, b"not json {{{").unwrap();
        let r = Baseline::read(&p);
        assert!(matches!(r, Err(BaselineError::Malformed(..))));
    }

    #[test]
    fn read_unsupported_version_returns_typed_error() {
        let td = TempDir::new().unwrap();
        let p = td.path().join("baseline.json");
        fs::write(
            &p,
            r#"{"version": 999, "createdAt": "2026-05-07T00:00:00Z", "toolVersion": "x", "findings": []}"#,
        )
        .unwrap();
        let r = Baseline::read(&p);
        match r {
            Err(BaselineError::UnsupportedVersion(found, expected)) => {
                assert_eq!(found, 999);
                assert_eq!(expected, BASELINE_SCHEMA_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    // ── classify ───────────────────────────────────────────────────────

    fn baseline_with(entries: Vec<BaselineEntry>) -> Baseline {
        Baseline {
            version: 1,
            created_at: "2026-05-07T00:00:00Z".into(),
            tool_version: "0.1.0".into(),
            findings: entries,
        }
    }

    #[test]
    fn classify_empty_baseline_all_added() {
        let current = vec![
            finding("YAML-UNSAFE-1111111111111111", "YAML-UNSAFE", "a.py", 1),
            finding("EVAL-USAGE-2222222222222222", "EVAL-USAGE", "b.py", 2),
        ];
        let b = baseline_with(vec![]);
        let d = classify(&current, &b);
        assert_eq!(d.added.len(), 2);
        assert_eq!(d.resolved.len(), 0);
        assert_eq!(d.unchanged_count, 0);
    }

    #[test]
    fn classify_empty_current_all_resolved() {
        let current: Vec<Finding> = vec![];
        let b = baseline_with(vec![entry(
            "YAML-UNSAFE-1111111111111111",
            "YAML-UNSAFE",
            "a.py",
            1,
        )]);
        let d = classify(&current, &b);
        assert_eq!(d.added.len(), 0);
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.unchanged_count, 0);
    }

    #[test]
    fn classify_identity_all_unchanged() {
        let current = vec![finding(
            "YAML-UNSAFE-1111111111111111",
            "YAML-UNSAFE",
            "a.py",
            1,
        )];
        let b = baseline_with(vec![entry(
            "YAML-UNSAFE-1111111111111111",
            "YAML-UNSAFE",
            "a.py",
            1,
        )]);
        let d = classify(&current, &b);
        assert!(d.added.is_empty());
        assert!(d.resolved.is_empty());
        assert_eq!(d.unchanged_count, 1);
    }

    #[test]
    fn classify_mixed_one_each() {
        // current: u (unchanged), n (new). baseline: u, r (resolved).
        let current = vec![
            finding("YAML-UNSAFE-aaaaaaaaaaaaaaaa", "YAML-UNSAFE", "a.py", 1), // unchanged
            finding("EVAL-USAGE-bbbbbbbbbbbbbbbb", "EVAL-USAGE", "b.py", 2),   // new
        ];
        let b = baseline_with(vec![
            entry("YAML-UNSAFE-aaaaaaaaaaaaaaaa", "YAML-UNSAFE", "a.py", 1), // unchanged
            entry("PICKLE-LOAD-cccccccccccccccc", "PICKLE-LOAD", "c.py", 3), // resolved
        ]);
        let d = classify(&current, &b);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].id, "EVAL-USAGE-bbbbbbbbbbbbbbbb");
        assert_eq!(d.resolved.len(), 1);
        assert_eq!(d.resolved[0].id, "PICKLE-LOAD-cccccccccccccccc");
        assert_eq!(d.unchanged_count, 1);
        assert_eq!(d.stale_count, 0);
    }

    #[test]
    fn classify_stale_rule_id_bumps_stale_count() {
        // A baseline entry whose ruleId no longer exists in the
        // registry. stale_count counts every such entry, but
        // stale_rule_ids dedups by rule.
        let current: Vec<Finding> = vec![];
        let b = baseline_with(vec![
            entry(
                "BOGUS-RULE-NEVER-EXISTED-1111",
                "BOGUS-RULE-NEVER-EXISTED",
                "a.py",
                1,
            ),
            entry(
                "BOGUS-RULE-NEVER-EXISTED-2222",
                "BOGUS-RULE-NEVER-EXISTED",
                "a.py",
                2,
            ),
            entry("YAML-UNSAFE-3333333333333333", "YAML-UNSAFE", "b.py", 3),
        ]);
        let d = classify(&current, &b);
        assert_eq!(d.stale_count, 2);
        assert_eq!(d.stale_rule_ids, vec!["BOGUS-RULE-NEVER-EXISTED"]);
        // Unrelated to staleness, all three are also resolved (current
        // is empty).
        assert_eq!(d.resolved.len(), 3);
    }

    #[test]
    fn classify_stale_rule_ids_sorted_deterministic() {
        let current: Vec<Finding> = vec![];
        let b = baseline_with(vec![
            entry("ZZZ-OLD-1111111111111111", "ZZZ-OLD", "a.py", 1),
            entry("AAA-OLD-2222222222222222", "AAA-OLD", "a.py", 2),
            entry("MMM-OLD-3333333333333333", "MMM-OLD", "a.py", 3),
        ]);
        let d = classify(&current, &b);
        assert_eq!(d.stale_rule_ids, vec!["AAA-OLD", "MMM-OLD", "ZZZ-OLD"]);
    }

    #[test]
    fn classify_known_rule_id_not_stale() {
        // YAML-UNSAFE is in the real registry. Even when the entry id
        // is fake, the ruleId-validity check should NOT mark it stale.
        let current: Vec<Finding> = vec![];
        let b = baseline_with(vec![entry(
            "YAML-UNSAFE-1111111111111111",
            "YAML-UNSAFE",
            "a.py",
            1,
        )]);
        let d = classify(&current, &b);
        assert_eq!(d.stale_count, 0);
        assert!(d.stale_rule_ids.is_empty());
    }
}
