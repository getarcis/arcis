//! Persistent cache for OSV query results.
//!
//! Lives at `~/.arcis/osv-cache.json`. Format:
//!
//! ```json
//! { "version": 1,
//!   "entries": {
//!     "npm:axios:1.14.1": {
//!       "fetched_at": 1715212345,
//!       "vulns": [ { "id": "GHSA-...", "summary": "...", ... } ]
//!     }
//!   }
//! }
//! ```
//!
//! Why a cache and not write-back to the embedded threat-db.json:
//! - `pip install --upgrade` / `npm update -g` would wipe a write-back DB
//!   on every package upgrade.
//! - Per-user augmentation must not dilute the curated 100 entries we
//!   ship as the trust anchor. The cache is per-user; the embedded DB
//!   stays canonical.
//! - Privacy: scan inputs become permanent corpus artifacts.
//!
//! See `documents/plans/cli-sca.md` Phase B (designed 2026-05-07) for the
//! full architectural rationale.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::osv::OsvVuln;

/// 24 hours. The embedded DB doesn't change at runtime, but OSV does —
/// new advisories land daily. A 24h TTL strikes a balance between
/// freshness and not hammering the API on every CI invocation.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

const CACHE_VERSION: u32 = 1;

/// Composite cache key: `<ecosystem>:<name>:<version>`. Same shape as
/// the OSV query parameters; collision-free since OSV's input space is
/// exactly that triple.
pub fn cache_key(ecosystem: &str, name: &str, version: &str) -> String {
    format!("{ecosystem}:{name}:{version}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    /// Unix epoch seconds at the moment OSV returned this answer.
    pub fetched_at: u64,
    pub vulns: Vec<OsvVuln>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsvCache {
    pub version: u32,
    pub entries: HashMap<String, CacheEntry>,
}

impl Default for OsvCache {
    fn default() -> Self {
        Self::empty()
    }
}

impl OsvCache {
    pub fn empty() -> Self {
        Self {
            version: CACHE_VERSION,
            entries: HashMap::new(),
        }
    }

    /// `~/.arcis/osv-cache.json`. None when no home dir is resolvable
    /// (sandboxed environments, CI without HOME). Caller falls back to
    /// in-memory cache in that case.
    pub fn default_path() -> Option<PathBuf> {
        dirs::home_dir().map(|h| h.join(".arcis").join("osv-cache.json"))
    }

    /// Load from disk. Missing file or unparseable contents yield an empty
    /// cache rather than an error — same lenient semantics as the Python
    /// CLI's threat-db loader. A truly broken cache file gets silently
    /// rewritten on the next save.
    pub fn load(path: &Path) -> Self {
        match fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<Self>(&bytes).unwrap_or_default(),
            Err(_) => Self::empty(),
        }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        fs::write(path, bytes)
    }

    /// Return cached vulns iff the entry exists AND is younger than
    /// `ttl_secs`. Stale entries return None so the caller refetches.
    pub fn get(&self, key: &str, ttl_secs: u64) -> Option<&[OsvVuln]> {
        let entry = self.entries.get(key)?;
        let now = unix_now();
        if now.saturating_sub(entry.fetched_at) > ttl_secs {
            return None;
        }
        Some(&entry.vulns)
    }

    pub fn put(&mut self, key: String, vulns: Vec<OsvVuln>) {
        self.entries.insert(
            key,
            CacheEntry {
                fetched_at: unix_now(),
                vulns,
            },
        );
    }

    /// Drop entries older than `ttl_secs`. Useful before saving so the
    /// on-disk file doesn't grow without bound.
    pub fn prune_stale(&mut self, ttl_secs: u64) {
        let now = unix_now();
        self.entries
            .retain(|_, e| now.saturating_sub(e.fetched_at) <= ttl_secs);
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osv::OsvVuln;
    use tempfile::tempdir;

    fn synthetic_vuln() -> OsvVuln {
        OsvVuln {
            id: "GHSA-test-1234".into(),
            summary: "synthetic test vuln".into(),
            severity: Vec::new(),
            references: Vec::new(),
        }
    }

    #[test]
    fn cache_key_format() {
        assert_eq!(cache_key("npm", "axios", "1.14.1"), "npm:axios:1.14.1");
        assert_eq!(
            cache_key("pypi", "urllib3", "1.26.18"),
            "pypi:urllib3:1.26.18"
        );
    }

    #[test]
    fn empty_cache_returns_none() {
        let c = OsvCache::empty();
        assert!(c.get("any-key", DEFAULT_TTL_SECS).is_none());
        assert_eq!(c.version, CACHE_VERSION);
    }

    #[test]
    fn put_then_get_hits() {
        let mut c = OsvCache::empty();
        c.put("npm:axios:1.14.1".into(), vec![synthetic_vuln()]);
        let hit = c.get("npm:axios:1.14.1", DEFAULT_TTL_SECS).unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].id, "GHSA-test-1234");
    }

    #[test]
    fn ttl_expired_returns_none() {
        let mut c = OsvCache::empty();
        c.entries.insert(
            "npm:axios:1.14.1".into(),
            CacheEntry {
                // Far in the past — well beyond any plausible TTL.
                fetched_at: 0,
                vulns: vec![synthetic_vuln()],
            },
        );
        assert!(c.get("npm:axios:1.14.1", DEFAULT_TTL_SECS).is_none());
    }

    #[test]
    fn prune_stale_drops_old_entries() {
        let mut c = OsvCache::empty();
        c.entries.insert(
            "old:pkg:0.0.1".into(),
            CacheEntry {
                fetched_at: 0,
                vulns: Vec::new(),
            },
        );
        c.put("fresh:pkg:1.0.0".into(), Vec::new());
        c.prune_stale(DEFAULT_TTL_SECS);
        assert!(!c.entries.contains_key("old:pkg:0.0.1"));
        assert!(c.entries.contains_key("fresh:pkg:1.0.0"));
    }

    #[test]
    fn save_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let mut c = OsvCache::empty();
        c.put("npm:axios:1.14.1".into(), vec![synthetic_vuln()]);
        c.save(&path).unwrap();

        let loaded = OsvCache::load(&path);
        assert_eq!(loaded.version, CACHE_VERSION);
        let hit = loaded.get("npm:axios:1.14.1", DEFAULT_TTL_SECS).unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].id, "GHSA-test-1234");
    }

    #[test]
    fn load_corrupt_file_yields_empty_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache.json");
        fs::write(&path, b"{ not json").unwrap();
        let loaded = OsvCache::load(&path);
        assert!(loaded.entries.is_empty());
    }

    #[test]
    fn load_missing_file_yields_empty_cache() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let loaded = OsvCache::load(&path);
        assert!(loaded.entries.is_empty());
    }
}
