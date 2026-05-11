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

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, COOKIE};
use serde_json::{Map, Value};

use super::csrf::CsrfState;
use super::login::LoginConfig;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("--bearer cannot be empty or whitespace-only")]
    EmptyBearer,
    #[error("--cookie cannot be empty or whitespace-only")]
    EmptyCookie,
    #[error("--login cannot be empty or whitespace-only")]
    EmptyLogin,
}

/// Auth state attached to a scan run. Carried through
/// [`super::probe::ScanOptions::auth`]; `None` means unauthenticated
/// scan (the common path) and skips header-map allocation entirely.
///
/// `cookie` is a verbatim header value: the user pastes from browser
/// dev tools, joins multi-cookie with `; ` themselves. We do not parse
/// `name=value` pairs, dedupe, or validate beyond non-empty — keeps
/// the surface tiny and lets the user control formatting end-to-end.
///
/// `login` is populated when the run was authed via `--login`. After
/// [`super::login::execute_login`] runs, the captured artifact lands in
/// `bearer` OR `cookie`, AND `login` stays populated as a "this run
/// authed via login" marker — so [`AuthConfig::redact_for_json`] can
/// report `methods=["login"]` instead of leaking which artifact type
/// was captured.
///
/// `csrf` is populated when the run was authed via `--csrf-from`.
/// The captured token rides as a request header on every probe via
/// [`AuthConfig::to_header_map`]; the cookie payload (when the
/// strategy was `cookie` or auto-detect resolved to cookie) is
/// expected to be appended to `cookie` by the caller — see
/// [`super::csrf::CsrfFetchOutcome::cookie_to_append`]. CSRF
/// composes with all auth methods (bearer, cookie, login); no
/// mutex.
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub bearer: Option<String>,
    pub cookie: Option<String>,
    pub login: Option<LoginConfig>,
    pub csrf: Option<CsrfState>,
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
    /// `Authorization`, `Cookie`, and the CSRF threading header are
    /// distinct header names, so composition is automatic when more
    /// than one is set.
    ///
    /// CSRF threading uses the runtime header name from
    /// [`CsrfState::thread_header`] (default `X-CSRF-Token`,
    /// overridable via the CLI `--csrf-header` flag).
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
        if let Some(csrf) = &self.csrf {
            // Defensive: validate the header NAME at insertion. The
            // CLI parser should already have rejected invalid names
            // (control chars, empty), but if direct API users
            // construct the state by hand we silently skip rather
            // than panic — same posture as bearer/cookie.
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(csrf.thread_header.as_bytes()),
                HeaderValue::from_str(&csrf.token),
            ) {
                headers.insert(name, value);
            }
        }
        headers
    }

    /// Render auth metadata for `--json` run headers.
    ///
    /// **Locked schema.** This method produces exactly ONE of:
    ///
    /// - `{"methods": ["login"]}`                          — when login is set, no CSRF
    /// - `{"methods": ["login", "csrf-from"]}`             — login + csrf
    /// - `{"methods": ["bearer"]}`                         — bearer only
    /// - `{"methods": ["bearer", "csrf-from"]}`            — bearer + csrf
    /// - `{"methods": ["cookie"]}`                         — cookie only
    /// - `{"methods": ["cookie", "csrf-from"]}`            — cookie + csrf
    /// - `{"methods": ["bearer", "cookie"]}`               — both manual flags
    /// - `{"methods": ["bearer", "cookie", "csrf-from"]}`  — all three
    /// - `{"methods": ["csrf-from"]}`                      — csrf only
    /// - `None`                                            — no auth configured
    ///
    /// No additional keys. No `loginUrl`, no `origin`, no provenance
    /// fields. When `login` is set, `methods` reports `["login"]` and
    /// the captured-artifact channel (bearer or cookie) is NOT
    /// reflected in the output — login overrides for reporting purposes.
    /// `csrf-from` is additive and composes with every other method.
    ///
    /// Method ordering: alphabetical (bearer < cookie < csrf-from)
    /// when login is absent; `login` first then `csrf-from` when
    /// login is set. Deterministic so day-over-day diffs are stable.
    ///
    /// Future auth flags MUST extend the `methods` array AND add a
    /// bullet to the enumeration above — never add sibling keys.
    /// Adding a key requires a deliberate schema bump.
    ///
    /// **Redaction contract:** NEVER emits token values, cookie values,
    /// login form values, or CSRF tokens. Tests assert that unique
    /// sentinel literals for each kind do not appear in the serialized
    /// output.
    pub fn redact_for_json(&self) -> Option<Value> {
        let mut methods: Vec<Value> = Vec::new();
        if self.login.is_some() {
            // Login overrides — defensive even if bearer/cookie are
            // also populated by execute_login's captured artifact, the
            // user-visible method is "login". Don't leak provenance.
            methods.push(Value::String("login".into()));
        } else {
            // Manual flags: alphabetical order, deterministic.
            if self.bearer.is_some() {
                methods.push(Value::String("bearer".into()));
            }
            if self.cookie.is_some() {
                methods.push(Value::String("cookie".into()));
            }
        }
        // CSRF is additive — orthogonal to the auth-method axis.
        // Always last in the array so login/bearer/cookie ordering
        // semantics above remain stable.
        if self.csrf.is_some() {
            methods.push(Value::String("csrf-from".into()));
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
            ..Default::default()
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
            ..Default::default()
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
        // Pin the error-message contract: every variant must be
        // "<flag> cannot be empty or whitespace-only". Future flags
        // must satisfy the same template — keeps user-facing error
        // strings predictable across the auth surface.
        let bearer_msg = AuthError::EmptyBearer.to_string();
        let cookie_msg = AuthError::EmptyCookie.to_string();
        let login_msg = AuthError::EmptyLogin.to_string();
        let suffix = " cannot be empty or whitespace-only";
        for (label, msg) in [
            ("bearer", &bearer_msg),
            ("cookie", &cookie_msg),
            ("login", &login_msg),
        ] {
            assert!(msg.ends_with(suffix), "{label} message: {msg}");
        }
        assert_eq!(bearer_msg.strip_suffix(suffix).unwrap(), "--bearer");
        assert_eq!(cookie_msg.strip_suffix(suffix).unwrap(), "--cookie");
        assert_eq!(login_msg.strip_suffix(suffix).unwrap(), "--login");
    }

    /// Sentinel for form-value redaction. Used by the login-redaction
    /// tests below to prove form values (and keys, by side-effect of
    /// the no-emit policy) never reach `redact_for_json`'s output.
    const TEST_LOGIN_PASSWORD: &str = "arcis-test-pass-FACEFEED-3b8d2e";

    fn login_with_sentinel_password() -> LoginConfig {
        LoginConfig {
            url: "http://localhost:5000/auth/login".into(),
            form: vec![
                ("user".into(), "admin".into()),
                ("password".into(), TEST_LOGIN_PASSWORD.into()),
            ],
            json: false,
        }
    }

    #[test]
    fn redact_for_json_login_only_emits_methods_array_with_login() {
        let cfg = AuthConfig {
            login: Some(login_with_sentinel_password()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["login"]}"#);
    }

    #[test]
    fn redact_for_json_login_overrides_bearer_and_cookie() {
        // Defensive: even if execute_login populated bearer or cookie
        // with the captured artifact, the user-visible auth method is
        // still "login". The captured-artifact provenance does not
        // surface in JSON output.
        let cfg = AuthConfig {
            bearer: Some(TEST_BEARER_TOKEN.into()),
            cookie: Some(TEST_COOKIE_VALUE.into()),
            login: Some(login_with_sentinel_password()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["login"]}"#);
        assert!(
            !s.contains(TEST_BEARER_TOKEN),
            "bearer leaked under login override: {s}"
        );
        assert!(
            !s.contains(TEST_COOKIE_VALUE),
            "cookie leaked under login override: {s}"
        );
        assert!(
            !s.contains(TEST_LOGIN_PASSWORD),
            "form password leaked: {s}"
        );
    }

    #[test]
    fn redact_for_json_login_does_not_leak_form_values_or_keys_or_url() {
        // Per locked schema, redact_for_json never serializes the
        // login form OR the URL. Pin all three: form values must not
        // appear (redaction), form keys must not appear (no-leak —
        // "password" as a field name reveals the auth shape), and the
        // URL must not appear (locked-schema guarantee). If a future
        // schema bump adds the URL, update this assertion AND the
        // redact_for_json doc-comment in lockstep.
        let cfg = AuthConfig {
            login: Some(login_with_sentinel_password()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert!(
            !s.contains(TEST_LOGIN_PASSWORD),
            "form password value leaked: {s}"
        );
        assert!(!s.contains("password"), "form key 'password' leaked: {s}");
        assert!(!s.contains("admin"), "form value 'admin' leaked: {s}");
        assert!(
            !s.contains("localhost:5000"),
            "login URL leaked under locked schema: {s}"
        );
    }

    // ----- CSRF-from coverage -----

    /// Sentinel CSRF token. Pinned unique so a substring match
    /// against the emitted JSON cannot false-positive on any other
    /// surface (route URL, vector label, hash digest, etc.).
    const TEST_CSRF_TOKEN: &str = "arcis-test-csrf-DEADC0DE-1f7e3a";

    fn csrf_state_with_default_header() -> CsrfState {
        CsrfState {
            token: TEST_CSRF_TOKEN.into(),
            thread_header: "X-CSRF-Token".into(),
        }
    }

    #[test]
    fn redact_for_json_csrf_only_emits_methods_array_with_csrf_from() {
        let cfg = AuthConfig {
            csrf: Some(csrf_state_with_default_header()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["csrf-from"]}"#);
        assert!(
            !s.contains(TEST_CSRF_TOKEN),
            "CSRF token leaked under csrf-only redaction: {s}"
        );
    }

    #[test]
    fn redact_for_json_bearer_plus_csrf_emits_alphabetical_ordering() {
        // Locked: bearer < cookie < csrf-from. Pin the order.
        let cfg = AuthConfig {
            bearer: Some(TEST_BEARER_TOKEN.into()),
            csrf: Some(csrf_state_with_default_header()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["bearer","csrf-from"]}"#);
        assert!(!s.contains(TEST_BEARER_TOKEN), "bearer leaked: {s}");
        assert!(!s.contains(TEST_CSRF_TOKEN), "csrf token leaked: {s}");
    }

    #[test]
    fn redact_for_json_cookie_plus_csrf_emits_alphabetical_ordering() {
        let cfg = AuthConfig {
            cookie: Some(TEST_COOKIE_VALUE.into()),
            csrf: Some(csrf_state_with_default_header()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["cookie","csrf-from"]}"#);
        assert!(!s.contains(TEST_COOKIE_VALUE), "cookie leaked: {s}");
        assert!(!s.contains(TEST_CSRF_TOKEN), "csrf token leaked: {s}");
    }

    #[test]
    fn redact_for_json_all_three_manual_methods_emits_full_array() {
        let cfg = AuthConfig {
            bearer: Some(TEST_BEARER_TOKEN.into()),
            cookie: Some(TEST_COOKIE_VALUE.into()),
            csrf: Some(csrf_state_with_default_header()),
            ..Default::default()
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["bearer","cookie","csrf-from"]}"#);
        // Triple sentinel pin — none of the three values may appear.
        assert!(!s.contains(TEST_BEARER_TOKEN));
        assert!(!s.contains(TEST_COOKIE_VALUE));
        assert!(!s.contains(TEST_CSRF_TOKEN));
    }

    #[test]
    fn redact_for_json_login_with_csrf_emits_login_then_csrf_from() {
        // Login-overrides-bearer/cookie semantics still hold; CSRF
        // is additive — appears AFTER the login marker.
        let cfg = AuthConfig {
            bearer: Some(TEST_BEARER_TOKEN.into()),
            cookie: Some(TEST_COOKIE_VALUE.into()),
            login: Some(login_with_sentinel_password()),
            csrf: Some(csrf_state_with_default_header()),
        };
        let v = cfg.redact_for_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"methods":["login","csrf-from"]}"#);
        // Every sentinel absent.
        assert!(!s.contains(TEST_BEARER_TOKEN));
        assert!(!s.contains(TEST_COOKIE_VALUE));
        assert!(!s.contains(TEST_LOGIN_PASSWORD));
        assert!(!s.contains(TEST_CSRF_TOKEN));
    }

    #[test]
    fn to_header_map_emits_csrf_header_with_default_name() {
        let cfg = AuthConfig {
            csrf: Some(csrf_state_with_default_header()),
            ..Default::default()
        };
        let headers = cfg.to_header_map();
        assert_eq!(
            headers.get("x-csrf-token").map(|v| v.to_str().unwrap()),
            Some(TEST_CSRF_TOKEN)
        );
    }

    #[test]
    fn to_header_map_emits_csrf_header_with_custom_name() {
        // Per --csrf-header override path: thread_header carries
        // the user-chosen name. Angular uses X-XSRF-TOKEN, Django
        // uses X-CSRFToken — pin support for both.
        let cfg = AuthConfig {
            csrf: Some(CsrfState {
                token: TEST_CSRF_TOKEN.into(),
                thread_header: "X-XSRF-TOKEN".into(),
            }),
            ..Default::default()
        };
        let headers = cfg.to_header_map();
        assert_eq!(
            headers.get("x-xsrf-token").map(|v| v.to_str().unwrap()),
            Some(TEST_CSRF_TOKEN)
        );
        // Default name must NOT be set when override was used.
        assert!(headers.get("x-csrf-token").is_none());
    }

    #[test]
    fn to_header_map_csrf_composes_with_bearer_and_cookie() {
        // Three distinct header names — composition is automatic.
        let cfg = AuthConfig {
            bearer: Some("token-foo".into()),
            cookie: Some("session=abc".into()),
            csrf: Some(csrf_state_with_default_header()),
            ..Default::default()
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
        assert_eq!(
            headers.get("x-csrf-token").map(|v| v.to_str().unwrap()),
            Some(TEST_CSRF_TOKEN)
        );
    }

    #[test]
    fn to_header_map_silently_skips_invalid_csrf_header_name() {
        // Defensive posture parallel to bearer/cookie: bad-bytes in
        // the thread_header (e.g. control chars from a direct API
        // misuse) are silently dropped rather than panicking the
        // scan. CLI parser is the authoritative validator.
        let cfg = AuthConfig {
            csrf: Some(CsrfState {
                token: "ok".into(),
                thread_header: "X-Bad\r\nHeader".into(),
            }),
            ..Default::default()
        };
        let headers = cfg.to_header_map();
        // No CSRF header emitted; map is empty.
        assert!(headers.is_empty());
    }
}
