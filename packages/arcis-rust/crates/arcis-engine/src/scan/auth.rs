//! Authentication for `arcis scan` probe requests.
//!
//! Backs the Phase B item-5 flags: `--bearer`, `--cookie`, `--login`.
//! For the current commit only the `bearer` arm exists; `cookies` and
//! `login` slot into this same struct in follow-up commits.
//!
//! # Redaction contract (load-bearing)
//!
//! Token values, cookie values, and login passwords MUST NEVER appear
//! in machine output (`--json`) or in human log lines / stderr trace
//! messages. Auth metadata is restricted to method identifiers and (for
//! cookies) names. The single rendering entry point is
//! [`AuthConfig::redact_for_json`]; future flags MUST extend that
//! method rather than bypass it. The same rule applies to any future
//! human-output line that wants to surface auth status — add a paired
//! `redact_for_log` helper rather than formatting the field directly.
//!
//! A test in this module asserts that a unique sentinel token literal
//! does not appear anywhere in the serialized JSON.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde_json::{Map, Value};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("--bearer cannot be empty or whitespace-only")]
    EmptyBearer,
}

/// Auth state attached to a scan run. Carried through
/// [`super::probe::ScanOptions::auth`]; `None` means unauthenticated
/// scan (the common path) and skips header-map allocation entirely.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub bearer: Option<String>,
    // commit #3 will add: pub cookies: Vec<(String, String)>
    // commit #4 will add: pub login: Option<LoginArtifact>
}

impl AuthConfig {
    /// Construct an `AuthConfig` carrying `Authorization: Bearer <token>`.
    /// Empty / whitespace-only `token` is rejected at construction time
    /// so every callsite — CLI parser and any direct API user — gets
    /// the same enforcement.
    pub fn with_bearer(token: &str) -> Result<Self, AuthError> {
        if token.trim().is_empty() {
            return Err(AuthError::EmptyBearer);
        }
        Ok(Self {
            bearer: Some(token.to_string()),
        })
    }

    /// Build the `HeaderMap` seeded into
    /// `Client::builder().default_headers`. Probe and every vector
    /// inherits these headers automatically — single injection site.
    pub fn to_header_map(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(token) = &self.bearer {
            // Caller validated non-empty; only way a non-ASCII control
            // byte slips through is direct API misuse, in which case
            // we silently skip rather than panic the scan.
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, v);
            }
        }
        headers
    }

    /// Render auth metadata for `--json` run headers. NEVER emits the
    /// token value, cookie value, or login password — only the method
    /// (and, for cookies, the cookie name). Returns `None` when no auth
    /// is configured so the renderer can omit the key entirely
    /// (preserves byte-parity with prior unauthenticated JSON).
    ///
    /// Future flags MUST extend this method rather than bypass it.
    /// The redaction is enforced by a unit test that fails if a unique
    /// sentinel token literal appears in the serialized output.
    pub fn redact_for_json(&self) -> Option<Value> {
        let mut m = Map::new();
        if self.bearer.is_some() {
            m.insert("method".into(), Value::String("bearer".into()));
        }
        // commit #3 will add: { "method": "cookie", "names": [...] }
        //                  or composite when bearer + cookie are both set.
        // commit #4 will add: { "method": "login", "via": "cookie"|"bearer" }
        if m.is_empty() {
            None
        } else {
            Some(Value::Object(m))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately unique sentinel so a substring match against the
    /// emitted JSON cannot false-positive on a hash digest, route URL,
    /// or vector label.
    const TEST_BEARER_TOKEN: &str = "arcis-test-bearer-DEADBEEF-9f3a2c";

    #[test]
    fn with_bearer_rejects_empty() {
        assert!(matches!(
            AuthConfig::with_bearer(""),
            Err(AuthError::EmptyBearer)
        ));
    }

    #[test]
    fn with_bearer_rejects_whitespace_only() {
        assert!(matches!(
            AuthConfig::with_bearer("   "),
            Err(AuthError::EmptyBearer)
        ));
        assert!(matches!(
            AuthConfig::with_bearer("\t\n"),
            Err(AuthError::EmptyBearer)
        ));
    }

    #[test]
    fn with_bearer_accepts_token() {
        let cfg = AuthConfig::with_bearer("foo").unwrap();
        assert_eq!(cfg.bearer.as_deref(), Some("foo"));
    }

    #[test]
    fn to_header_map_emits_bearer_authorization() {
        let cfg = AuthConfig::with_bearer("foo").unwrap();
        let headers = cfg.to_header_map();
        assert_eq!(
            headers.get("authorization").map(|v| v.to_str().unwrap()),
            Some("Bearer foo")
        );
    }

    #[test]
    fn to_header_map_empty_when_no_auth_set() {
        let cfg = AuthConfig::default();
        assert!(cfg.to_header_map().is_empty());
    }

    #[test]
    fn redact_for_json_bearer_only_emits_method_and_redacts_token() {
        let cfg = AuthConfig::with_bearer(TEST_BEARER_TOKEN).unwrap();
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"method":"bearer"}"#);
        // Sentinel: the token literal must not appear in the serialized
        // output. Pinned by a unique substring so a false-positive
        // against an unrelated string in the run header is impossible.
        assert!(
            !s.contains(TEST_BEARER_TOKEN),
            "redact_for_json leaked the bearer token: {s}"
        );
    }

    #[test]
    fn redact_for_json_returns_none_when_unconfigured() {
        let cfg = AuthConfig::default();
        assert!(cfg.redact_for_json().is_none());
    }
}
