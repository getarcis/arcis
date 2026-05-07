//! Authentication for `arcis scan` probe requests.
//!
//! Backs the Phase B item-5 flags: `--bearer`, `--cookie`, `--login`.
//! `--bearer` and `--cookie` ship today; `--login` slots into the same
//! `AuthConfig` struct in a follow-up commit.
//!
//! # Redaction contract (load-bearing)
//!
//! Token values, cookie values, and login passwords MUST NEVER appear
//! in machine output (`--json`) or in human log lines / stderr trace
//! messages. Auth metadata is restricted to method identifiers only —
//! we deliberately don't parse cookie name/value pairs (verbatim
//! string policy) so cookie names also never surface. The single
//! rendering entry point is [`AuthConfig::redact_for_json`]; future
//! flags MUST extend that method rather than bypass it. The same rule
//! applies to any future human-output line that wants to surface auth
//! status — add a paired `redact_for_log` helper rather than
//! formatting the field directly.
//!
//! Tests in this module assert that unique sentinel token / cookie
//! literals do not appear anywhere in the serialized JSON.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE};
use serde_json::{Map, Value};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("--bearer cannot be empty or whitespace-only")]
    EmptyBearer,
    #[error("--cookie cannot be empty or whitespace-only")]
    EmptyCookie,
}

/// Auth state attached to a scan run. Carried through
/// [`super::probe::ScanOptions::auth`]; `None` means unauthenticated
/// scan (the common path) and skips header-map allocation entirely.
///
/// `cookie` is a verbatim header value: the user pastes from browser
/// dev tools, joins multi-cookie with `; ` themselves. We do not parse
/// `name=value` pairs, dedupe, or validate beyond non-empty — keeps
/// the surface tiny and lets the user control formatting end-to-end.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub bearer: Option<String>,
    pub cookie: Option<String>,
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
            ..Default::default()
        })
    }

    /// Construct an `AuthConfig` carrying `Cookie: <value>` verbatim.
    /// `value` is the entire header body as the user wants it on the
    /// wire — we do not parse, validate `name=value` shape, or dedupe.
    /// Empty / whitespace-only is rejected at construction time.
    pub fn with_cookie(value: &str) -> Result<Self, AuthError> {
        if value.trim().is_empty() {
            return Err(AuthError::EmptyCookie);
        }
        Ok(Self {
            cookie: Some(value.to_string()),
            ..Default::default()
        })
    }

    /// Build the `HeaderMap` seeded into
    /// `Client::builder().default_headers`. Probe and every vector
    /// inherits these headers automatically — single injection site.
    /// `Authorization` and `Cookie` are distinct header names, so
    /// composition is automatic when both are set.
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
        if let Some(value) = &self.cookie {
            if let Ok(v) = HeaderValue::from_str(value) {
                headers.insert(COOKIE, v);
            }
        }
        headers
    }

    /// Render auth metadata for `--json` run headers.
    ///
    /// **Schema:** `{"methods": [<name>, ...]}` where each entry is one
    /// of `"bearer"`, `"cookie"`, `"login"`. Always an array (even for
    /// a single method) so downstream parsers don't switch on type.
    /// Order is stable and alphabetical (`bearer` < `cookie` < `login`).
    ///
    /// **Redaction contract:** NEVER emits the token value, cookie
    /// value, or login password — only method names. Future flags MUST
    /// extend this method rather than bypass it. The redaction is
    /// enforced by tests that fail if a unique sentinel token / cookie
    /// literal appears in the serialized output.
    ///
    /// Returns `None` when no auth is configured so the renderer can
    /// omit the key entirely (preserves byte-parity with prior
    /// unauthenticated JSON).
    pub fn redact_for_json(&self) -> Option<Value> {
        // Insert in alphabetical order — keeps the output deterministic
        // without an explicit sort. When `login` lands in commit #4,
        // append after `cookie` to maintain ordering.
        let mut methods: Vec<Value> = Vec::new();
        if self.bearer.is_some() {
            methods.push(Value::String("bearer".into()));
        }
        if self.cookie.is_some() {
            methods.push(Value::String("cookie".into()));
        }
        if methods.is_empty() {
            return None;
        }
        let mut m = Map::new();
        m.insert("methods".into(), Value::Array(methods));
        Some(Value::Object(m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately unique sentinels so a substring match against the
    /// emitted JSON cannot false-positive on a hash digest, route URL,
    /// or vector label. One per auth surface so each redaction path is
    /// exercised independently.
    const TEST_BEARER_TOKEN: &str = "arcis-test-bearer-DEADBEEF-9f3a2c";
    const TEST_COOKIE_VALUE: &str = "session=arcis-test-cookie-CAFEBABE-7e1f4d; csrf=feedface";

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
        assert!(cfg.cookie.is_none());
    }

    #[test]
    fn with_cookie_rejects_empty() {
        assert!(matches!(
            AuthConfig::with_cookie(""),
            Err(AuthError::EmptyCookie)
        ));
    }

    #[test]
    fn with_cookie_rejects_whitespace_only() {
        assert!(matches!(
            AuthConfig::with_cookie("   "),
            Err(AuthError::EmptyCookie)
        ));
        assert!(matches!(
            AuthConfig::with_cookie("\t\n"),
            Err(AuthError::EmptyCookie)
        ));
    }

    #[test]
    fn with_cookie_accepts_verbatim_value() {
        // Multi-cookie semicolon form goes in unparsed — the user's
        // problem to format, the engine's job to deliver verbatim.
        let raw = "session=abc; csrf=xyz; flavor=chocolate";
        let cfg = AuthConfig::with_cookie(raw).unwrap();
        assert_eq!(cfg.cookie.as_deref(), Some(raw));
        assert!(cfg.bearer.is_none());
    }

    #[test]
    fn to_header_map_emits_bearer_authorization() {
        let cfg = AuthConfig::with_bearer("foo").unwrap();
        let headers = cfg.to_header_map();
        assert_eq!(
            headers.get("authorization").map(|v| v.to_str().unwrap()),
            Some("Bearer foo")
        );
        assert!(headers.get("cookie").is_none());
    }

    #[test]
    fn to_header_map_emits_cookie_header_verbatim() {
        let cfg = AuthConfig::with_cookie("session=abc; csrf=xyz").unwrap();
        let headers = cfg.to_header_map();
        assert_eq!(
            headers.get("cookie").map(|v| v.to_str().unwrap()),
            Some("session=abc; csrf=xyz")
        );
        assert!(headers.get("authorization").is_none());
    }

    #[test]
    fn to_header_map_composes_bearer_and_cookie() {
        // Both fields set => both headers emitted. `Authorization` and
        // `Cookie` are distinct header names; no collision logic needed.
        let cfg = AuthConfig {
            bearer: Some("token-foo".into()),
            cookie: Some("session=abc".into()),
        };
        let headers = cfg.to_header_map();
        assert_eq!(
            headers.get("authorization").map(|v| v.to_str().unwrap()),
            Some("Bearer token-foo")
        );
        assert_eq!(
            headers.get("cookie").map(|v| v.to_str().unwrap()),
            Some("session=abc")
        );
    }

    #[test]
    fn to_header_map_empty_when_no_auth_set() {
        let cfg = AuthConfig::default();
        assert!(cfg.to_header_map().is_empty());
    }

    #[test]
    fn redact_for_json_bearer_only_emits_methods_array_and_redacts_token() {
        let cfg = AuthConfig::with_bearer(TEST_BEARER_TOKEN).unwrap();
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["bearer"]}"#);
        assert!(
            !s.contains(TEST_BEARER_TOKEN),
            "redact_for_json leaked the bearer token: {s}"
        );
    }

    #[test]
    fn redact_for_json_cookie_only_emits_methods_array_and_redacts_value() {
        let cfg = AuthConfig::with_cookie(TEST_COOKIE_VALUE).unwrap();
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["cookie"]}"#);
        // Cookie value sentinel — must NOT appear anywhere in JSON.
        assert!(
            !s.contains(TEST_COOKIE_VALUE),
            "redact_for_json leaked the cookie value: {s}"
        );
        // Even the cookie name (`session=`) must not leak — we don't
        // parse, so we cannot extract a name; nothing about the cookie
        // structure surfaces.
        assert!(
            !s.contains("session"),
            "cookie name leaked despite no-parse policy: {s}"
        );
    }

    #[test]
    fn redact_for_json_composite_lists_both_methods_alphabetical_and_redacts_both() {
        let cfg = AuthConfig {
            bearer: Some(TEST_BEARER_TOKEN.into()),
            cookie: Some(TEST_COOKIE_VALUE.into()),
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        // Alphabetical, deterministic order (bearer < cookie). Pinned
        // exactly so any future drift in order surfaces here.
        assert_eq!(s, r#"{"methods":["bearer","cookie"]}"#);
        // Both sentinels must be absent.
        assert!(
            !s.contains(TEST_BEARER_TOKEN),
            "bearer leaked in composite: {s}"
        );
        assert!(
            !s.contains(TEST_COOKIE_VALUE),
            "cookie leaked in composite: {s}"
        );
    }

    #[test]
    fn redact_for_json_returns_none_when_unconfigured() {
        let cfg = AuthConfig::default();
        assert!(cfg.redact_for_json().is_none());
    }

    #[test]
    fn auth_error_messages_share_a_consistent_template() {
        // Pin the error-message contract: every variant should be
        // "<flag> cannot be empty or whitespace-only". When `--login`
        // lands in commit #4, its `EmptyLogin` (or similar) variant
        // must satisfy the same template — keeps user-facing error
        // strings predictable across the auth surface.
        let bearer_msg = AuthError::EmptyBearer.to_string();
        let cookie_msg = AuthError::EmptyCookie.to_string();
        let suffix = " cannot be empty or whitespace-only";
        assert!(bearer_msg.ends_with(suffix), "bearer message: {bearer_msg}");
        assert!(cookie_msg.ends_with(suffix), "cookie message: {cookie_msg}");
        assert!(bearer_msg.starts_with("--bearer"), "got: {bearer_msg}");
        assert!(cookie_msg.starts_with("--cookie"), "got: {cookie_msg}");
        // Same suffix length: messages differ ONLY in the flag name.
        let bearer_prefix = bearer_msg.strip_suffix(suffix).unwrap();
        let cookie_prefix = cookie_msg.strip_suffix(suffix).unwrap();
        assert_eq!(bearer_prefix, "--bearer");
        assert_eq!(cookie_prefix, "--cookie");
    }
}
