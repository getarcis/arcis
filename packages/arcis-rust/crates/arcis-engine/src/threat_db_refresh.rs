//! Phase C: refresh the threat-db from a cloud intelligence endpoint.
//!
//! `arcis sca --refresh-db` fetches the curated threat-db snapshot served by
//! the Arcis intelligence dashboard (`GET /v1/intel/threat-db/snapshot`),
//! caches it at `~/.arcis/threat-db-cache.json` (24h TTL, like the OSV cache),
//! and merges it with the embedded DB so the SCA scan uses the freshest
//! curated set without waiting for a new CLI release.
//!
//! Fail-open by contract: any error (no endpoint configured, network failure,
//! bad response) returns the error to the caller, which keeps the embedded DB.
//! The cloud feed only ever *adds* coverage; it never degrades the offline scan.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::threat_db::Threat;

const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Error)]
pub enum RefreshError {
    #[error("no intelligence endpoint configured (set ARCIS_INTEL_ENDPOINT)")]
    NoEndpoint,
    #[error("threat-db refresh returned HTTP {0}")]
    Http(u16),
    #[error("threat-db refresh network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("could not build async runtime: {0}")]
    Runtime(#[from] std::io::Error),
}

/// Options for a refresh. `endpoint` is the dashboard base URL (no trailing
/// path); the snapshot path is appended.
pub struct RefreshOptions {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub cache_path: Option<PathBuf>,
    pub use_cache: bool,
    pub timeout: Duration,
}

impl RefreshOptions {
    /// Build from the standard env vars. Returns `NoEndpoint` when
    /// `ARCIS_INTEL_ENDPOINT` is unset/empty.
    pub fn from_env() -> Result<Self, RefreshError> {
        let endpoint = std::env::var("ARCIS_INTEL_ENDPOINT")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or(RefreshError::NoEndpoint)?;
        Ok(Self {
            endpoint,
            api_key: std::env::var("ARCIS_INTEL_KEY").ok().filter(|s| !s.is_empty()),
            cache_path: default_cache_path(),
            use_cache: true,
            timeout: Duration::from_secs(5),
        })
    }
}

/// `~/.arcis/threat-db-cache.json`, or None when no home dir resolves.
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".arcis").join("threat-db-cache.json"))
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ThreatDbCache {
    #[serde(default)]
    pub fetched_at: u64,
    #[serde(default)]
    pub threats: Vec<Threat>,
}

impl ThreatDbCache {
    pub fn load(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec_pretty(self).unwrap_or_default())
    }

    pub fn is_fresh(&self, ttl_secs: u64) -> bool {
        now_secs().saturating_sub(self.fetched_at) < ttl_secs
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct SnapshotResponse {
    #[serde(default)]
    threats: Vec<Threat>,
}

/// Fetch the threat-db (cache-first when `use_cache`), persisting a fresh fetch
/// to the cache. Returns the fetched threats (NOT yet merged with embedded).
pub fn refresh_threats(opts: &RefreshOptions) -> Result<Vec<Threat>, RefreshError> {
    if opts.use_cache {
        if let Some(path) = &opts.cache_path {
            if let Some(cache) = ThreatDbCache::load(path) {
                if cache.is_fresh(CACHE_TTL_SECS) && !cache.threats.is_empty() {
                    return Ok(cache.threats);
                }
            }
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let threats = runtime.block_on(fetch_snapshot(opts))?;

    if let Some(path) = &opts.cache_path {
        let cache = ThreatDbCache { fetched_at: now_secs(), threats: threats.clone() };
        let _ = cache.save(path); // cache write failures are non-fatal
    }
    Ok(threats)
}

async fn fetch_snapshot(opts: &RefreshOptions) -> Result<Vec<Threat>, RefreshError> {
    let client = reqwest::Client::builder().timeout(opts.timeout).build()?;
    let url = format!(
        "{}/v1/intel/threat-db/snapshot",
        opts.endpoint.trim_end_matches('/')
    );
    let mut req = client.get(&url).header("accept", "application/json");
    if let Some(key) = &opts.api_key {
        req = req.bearer_auth(key);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(RefreshError::Http(resp.status().as_u16()));
    }
    let body: SnapshotResponse = resp.json().await?;
    Ok(body.threats)
}

/// Merge fetched threats over the embedded set, deduped on
/// `ecosystem:name:cve`. The fetched (fresher, curated) entry wins on conflict.
pub fn merge_threats(embedded: Vec<Threat>, fetched: Vec<Threat>) -> Vec<Threat> {
    let key = |t: &Threat| format!("{}:{}:{}", t.ecosystem, t.name, t.cve);
    let mut map: HashMap<String, Threat> = HashMap::with_capacity(embedded.len() + fetched.len());
    for t in embedded {
        map.insert(key(&t), t);
    }
    for t in fetched {
        map.insert(key(&t), t);
    }
    map.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threat(eco: &str, name: &str, cve: &str, sev: &str) -> Threat {
        Threat {
            ecosystem: eco.into(),
            name: name.into(),
            malicious_versions: vec![],
            attack_vector: "x".into(),
            severity: sev.into(),
            cve: cve.into(),
            disclosure_date: String::new(),
            source: String::new(),
            references: vec![],
            trojanized_deps: vec![],
            persistence_artifacts: vec![],
            remediation: String::new(),
            vulnerable_ranges: vec![],
        }
    }

    #[test]
    fn merge_dedupes_and_fetched_wins() {
        let embedded = vec![threat("npm", "lodash", "CVE-1", "medium"), threat("npm", "axios", "CVE-2", "high")];
        let fetched = vec![
            threat("npm", "lodash", "CVE-1", "critical"), // same key -> overrides
            threat("pypi", "flask", "CVE-3", "high"),     // new
        ];
        let merged = merge_threats(embedded, fetched);
        assert_eq!(merged.len(), 3);
        let lodash = merged.iter().find(|t| t.name == "lodash").unwrap();
        assert_eq!(lodash.severity, "critical", "fetched entry should win on conflict");
    }

    #[test]
    fn cache_freshness() {
        let mut c = ThreatDbCache { fetched_at: now_secs(), threats: vec![threat("npm", "x", "CVE-9", "low")] };
        assert!(c.is_fresh(CACHE_TTL_SECS));
        c.fetched_at = now_secs().saturating_sub(CACHE_TTL_SECS + 10);
        assert!(!c.is_fresh(CACHE_TTL_SECS));
    }

    #[test]
    fn cache_roundtrip() {
        let dir = std::env::temp_dir().join(format!("arcis-tdb-{}", now_secs()));
        let path = dir.join("threat-db-cache.json");
        let c = ThreatDbCache { fetched_at: now_secs(), threats: vec![threat("npm", "y", "CVE-7", "high")] };
        c.save(&path).unwrap();
        let loaded = ThreatDbCache::load(&path).unwrap();
        assert_eq!(loaded.threats.len(), 1);
        assert_eq!(loaded.threats[0].name, "y");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_env_requires_endpoint() {
        // Unset -> NoEndpoint (other tests/CI must not set this var).
        std::env::remove_var("ARCIS_INTEL_ENDPOINT");
        assert!(matches!(RefreshOptions::from_env(), Err(RefreshError::NoEndpoint)));
    }
}
