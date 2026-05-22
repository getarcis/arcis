//! CSRF token grab for `arcis scan --csrf-from`.
//!
//! Backs Phase B item 6 — fetch a CSRF token from a GET endpoint
//! (auto-detect from cookie or JSON body, or with an explicit
//! strategy), then thread the captured value as a request header on
//! every subsequent scan probe via [`super::auth::AuthConfig`].
//!
//! ## Spec syntax — `METHOD:PATH[:STRATEGY:NAME]`
//!
//! - **Short form** `GET:/csrf` — auto-detect cascade. Cookie first
//!   (any `Set-Cookie` whose name contains `csrf` / `xsrf`,
//!   case-insensitive), then JSON body keys
//!   (`csrfToken`, `csrf_token`, `_csrf` — first hit wins).
//!   Deliberately omits a generic `token` key to avoid false matches
//!   on OAuth / API responses.
//! - **Long form** `GET:/csrf:json:csrfToken` — explicit strategy.
//!   STRATEGY ∈ `{json, cookie, header}`; NAME is the JSON key,
//!   cookie name, or response header name as appropriate.
//! - URL may be absolute (`http://x/path`, `https://x/path`) or
//!   relative (`/path`, joined to the scan target at fetch time).
//! - METHOD is **GET-only in v1**. The parser rejects every other
//!   method; reserved field on [`CsrfSpec`] for forward compatibility.
//!
//! ## Composition with auth
//!
//! [`fetch_csrf`] is called AFTER [`super::login::execute_login`]
//! (when both are configured) so the login session cookie is
//! available to the CSRF fetch. Auth headers from the base
//! [`AuthConfig`] (bearer + cookie + login-captured artifact) are
//! forwarded on the GET request — many real CSRF endpoints
//! (Django, Laravel sanctum) require an authenticated session.
//!
//! ## Cookie-strategy double-write (intentional)
//!
//! When the strategy is `cookie` (or auto-detect picks cookie), the
//! captured `name=value` is appended to [`AuthConfig::cookie`] AND
//! the value lands in [`CsrfState::token`] for header threading.
//! This is the double-submit pattern Angular / Laravel sanctum
//! rely on: server reads the cookie + the header, compares them.
//! The append uses verbatim no-parse policy — if the user already
//! pasted the same cookie name via `--cookie`, we do NOT dedupe.
//! HTTP servers honor the LAST occurrence on the wire, so the
//! freshly-fetched value wins server-side. Pinned by tests.
//!
//! ## Refetch cadence
//!
//! Once per scan. CSRF tokens are session-lived in real frameworks
//! (Express csurf default 1hr); per-route refetch would inflate the
//! request count by ~27× under `--thorough`.

use std::time::Duration;

use reqwest::{header::SET_COOKIE, redirect, Client};
use serde_json::Value;

use super::auth::AuthConfig;

/// Default outbound header used to thread the captured token on
/// state-changing scan requests. Override via the CLI's
/// `--csrf-header` flag (see arcis-cli `scan.rs`).
pub const DEFAULT_THREAD_HEADER: &str = "X-CSRF-Token";

/// Where to find the token in the GET response.
///
/// `Auto` cascades cookie → JSON; the explicit variants name the
/// exact extraction surface. See module-level docs for the full
/// auto-detect contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsrfStrategy {
    Auto,
    Json(String),
    Cookie(String),
    Header(String),
}

/// Parsed CSRF endpoint spec — the parsed form of
/// `--csrf-from <SPEC>`. `url` may be absolute (`http://...`) or a
/// relative path (`/csrf`, joined to the scan target at fetch time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfSpec {
    pub method: String,
    pub url: String,
    pub strategy: CsrfStrategy,
    pub thread_header: String,
}

/// Live CSRF state attached to a scan run after a successful fetch.
/// Stored on [`AuthConfig::csrf`]; the token rides as a request
/// header on every subsequent probe via
/// [`AuthConfig::to_header_map`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfState {
    pub token: String,
    pub thread_header: String,
}

/// Outcome of a CSRF fetch — the live state, plus an optional
/// cookie payload the caller MUST append to
/// [`AuthConfig::cookie`] when the strategy was `cookie` or
/// auto-detect resolved to cookie. Returning the cookie payload as
/// a separate field keeps [`fetch_csrf`] pure (no `&mut AuthConfig`
/// in its signature) and lets the CLI orchestrate auth-state
/// updates in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfFetchOutcome {
    pub state: CsrfState,
    /// `Some(name=value)` when a cookie was captured; caller appends
    /// to `AuthConfig.cookie` joined with `; `. `None` for json /
    /// header strategies.
    pub cookie_to_append: Option<String>,
}

/// Parser + fetch errors. All map to CLI exit code 2 with an
/// `arcis scan: <message>` prefix at the call site.
#[derive(Debug, thiserror::Error)]
pub enum CsrfError {
    #[error("--csrf-from parse error: {0}")]
    ParseError(String),
    #[error("--csrf-from endpoint unreachable: {0}")]
    Unreachable(reqwest::Error),
    #[error("--csrf-from {url} returned {status}")]
    BadStatus { url: String, status: u16 },
    #[error(
        "--csrf-from could not extract a token from the response (no matching cookie or JSON key)"
    )]
    ExtractFailed,
}

/// Parse a `--csrf-from` SPEC string. Recognises both the short
/// (`GET:/path`) and long (`GET:/path:strategy:name`) forms. METHOD
/// is GET-only in v1; everything else is rejected at parse time.
///
/// `thread_header` is left as [`DEFAULT_THREAD_HEADER`]; the CLI
/// rewrites it from `--csrf-header` if that flag is present.
pub fn parse_spec(input: &str) -> Result<CsrfSpec, CsrfError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CsrfError::ParseError(
            "value cannot be empty or whitespace-only".into(),
        ));
    }

    // Method prefix must be present and exactly `GET:` (case
    // insensitive). v1 supports GET only; the spec field is
    // reserved for forward compat but the parser refuses anything
    // else so users get a clear failure rather than silent wrong
    // behaviour.
    let Some(after_method) = trimmed
        .find(':')
        .map(|i| (&trimmed[..i], &trimmed[i + 1..]))
    else {
        // cli-test round-1 bug 8 (improved UX): pilots tried `cookie`
        // and `response-header` as bare values (auto-extract modes that
        // don't fetch a CSRF endpoint). Those aren't supported in v1
        // — the only mode is "fetch a URL, extract token" — but the
        // error must surface the supported shape clearly enough that a
        // user self-corrects without docs. Three lines: what was given,
        // what's expected, and a worked example.
        return Err(CsrfError::ParseError(format!(
            "--csrf-from value '{trimmed}' is not a fetchable spec. \
             Expected: GET:/path[:strategy:name] (the URL to fetch and \
             extract the token from). Example: --csrf-from GET:/csrf, \
             or --csrf-from GET:/csrf:json:csrfToken if the token comes \
             back as a JSON field. Cookie-based and response-header \
             extraction are not supported in v1."
        )));
    };
    let (method_raw, rest) = after_method;
    let method = method_raw.trim().to_ascii_uppercase();
    if method != "GET" {
        return Err(CsrfError::ParseError(format!(
            "only GET is supported in v1, got: {method_raw}"
        )));
    }
    if rest.is_empty() {
        return Err(CsrfError::ParseError(
            "URL or path is required after METHOD:".into(),
        ));
    }

    // Detect long form by scanning from the right: take the last
    // two `:`-segments only when the second-to-last is a valid
    // strategy keyword. URLs with embedded `:` (port numbers,
    // scheme separators) round-trip safely because the second-to-
    // last colon-segment of `http://host:port/path` is `//host`,
    // which is not a strategy keyword.
    let (url, strategy) = split_strategy(rest)?;
    validate_url(&url)?;

    Ok(CsrfSpec {
        method,
        url,
        strategy,
        thread_header: DEFAULT_THREAD_HEADER.to_string(),
    })
}

/// Split the URL portion from an optional `:strategy:name` suffix.
/// Returns the URL and the parsed strategy (or `Auto` if absent).
fn split_strategy(rest: &str) -> Result<(String, CsrfStrategy), CsrfError> {
    let parts: Vec<&str> = rest.rsplitn(3, ':').collect();
    // rsplitn returns rightmost pieces first, so for
    // `http://x/csrf:json:csrfToken`:
    //   parts[0] = "csrfToken", parts[1] = "json", parts[2] = "http://x/csrf"
    if parts.len() == 3 {
        let strategy_keyword = parts[1];
        let name = parts[0];
        match strategy_keyword {
            "json" => {
                if name.is_empty() {
                    return Err(CsrfError::ParseError(
                        "json strategy requires a key name (e.g. GET:/csrf:json:csrfToken)".into(),
                    ));
                }
                return Ok((parts[2].to_string(), CsrfStrategy::Json(name.to_string())));
            }
            "cookie" => {
                if name.is_empty() {
                    return Err(CsrfError::ParseError(
                        "cookie strategy requires a cookie name (e.g. GET:/csrf:cookie:XSRF-TOKEN)"
                            .into(),
                    ));
                }
                return Ok((parts[2].to_string(), CsrfStrategy::Cookie(name.to_string())));
            }
            "header" => {
                if name.is_empty() {
                    return Err(CsrfError::ParseError(
                        "header strategy requires a header name (e.g. GET:/csrf:header:X-Csrf-Response)".into(),
                    ));
                }
                return Ok((parts[2].to_string(), CsrfStrategy::Header(name.to_string())));
            }
            _ => {
                // Fall through to short-form interpretation: the
                // second-to-last `:`-segment is part of the URL,
                // not a strategy keyword. Reconstruct verbatim.
            }
        }
    }
    // Short form. The full `rest` IS the URL.
    Ok((rest.to_string(), CsrfStrategy::Auto))
}

/// Validate that the URL is either an absolute http(s) URL or an
/// absolute path (`/...`). Relative paths without a leading slash
/// are rejected so users get a clear error rather than a silent
/// concat to an unexpected base.
fn validate_url(url: &str) -> Result<(), CsrfError> {
    if url.starts_with("http://") || url.starts_with("https://") {
        return Ok(());
    }
    if url.starts_with('/') {
        return Ok(());
    }
    Err(CsrfError::ParseError(format!(
        "URL must start with http://, https://, or / (relative path), got: {url}"
    )))
}

/// Resolve a (possibly relative) spec URL against the scan target.
fn resolve_url(spec_url: &str, base_url: &str) -> String {
    if spec_url.starts_with("http://") || spec_url.starts_with("https://") {
        spec_url.to_string()
    } else {
        format!("{}{}", base_url.trim_end_matches('/'), spec_url)
    }
}

/// Execute the CSRF fetch. GETs the configured URL with the base
/// auth headers attached, extracts a token per the configured
/// strategy, returns the live state plus an optional cookie
/// payload the caller appends to [`AuthConfig::cookie`].
pub async fn fetch_csrf(
    spec: &CsrfSpec,
    base_auth: &AuthConfig,
    base_url: &str,
    timeout: Duration,
) -> Result<CsrfFetchOutcome, CsrfError> {
    // Use the same transport posture as `execute_login`:
    // `redirect::Policy::none()` so a CSRF endpoint that returns
    // `302 + Set-Cookie` (Laravel sanctum pattern) doesn't drop the
    // Set-Cookie when reqwest follows the redirect.
    let mut builder = Client::builder()
        .timeout(timeout)
        .redirect(redirect::Policy::none());
    // Inherit base auth headers (bearer + cookie + any login
    // artifact). `to_header_map` excludes CSRF naturally because
    // base_auth.csrf is None when this function is called — we're
    // in the middle of populating it.
    builder = builder.default_headers(base_auth.to_header_map());

    let client = builder.build().map_err(CsrfError::Unreachable)?;
    let url = resolve_url(&spec.url, base_url);

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(CsrfError::Unreachable)?;
    let status = response.status();

    // 2xx and 3xx are both "request proceeded; look for a token".
    // 4xx + 5xx are unrecoverable — we never proceed silently with
    // no token, which would invalidate every POST in the scan.
    if status.is_client_error() || status.is_server_error() {
        return Err(CsrfError::BadStatus {
            url: url.clone(),
            status: status.as_u16(),
        });
    }

    let headers = response.headers().clone();
    let body_bytes = response.bytes().await.unwrap_or_default();

    match &spec.strategy {
        CsrfStrategy::Cookie(name) => {
            let (token, name_value) =
                extract_cookie_by_name(&headers, name).ok_or(CsrfError::ExtractFailed)?;
            Ok(outcome_from_cookie(
                token,
                Some(name_value),
                &spec.thread_header,
            ))
        }
        CsrfStrategy::Json(key) => {
            let token = extract_json_by_key(&body_bytes, key).ok_or(CsrfError::ExtractFailed)?;
            Ok(outcome_no_cookie(token, &spec.thread_header))
        }
        CsrfStrategy::Header(name) => {
            let token = extract_response_header(&headers, name).ok_or(CsrfError::ExtractFailed)?;
            Ok(outcome_no_cookie(token, &spec.thread_header))
        }
        CsrfStrategy::Auto => {
            // Cascade: cookie first (more reliable when present —
            // most real-world CSRF servers set it as a side
            // effect), then JSON body.
            if let Some((token, name_value)) = extract_cookie_auto(&headers) {
                return Ok(outcome_from_cookie(
                    token,
                    Some(name_value),
                    &spec.thread_header,
                ));
            }
            if let Some(token) = extract_json_auto(&body_bytes) {
                return Ok(outcome_no_cookie(token, &spec.thread_header));
            }
            Err(CsrfError::ExtractFailed)
        }
    }
}

fn outcome_from_cookie(
    token: String,
    name_value: Option<String>,
    thread_header: &str,
) -> CsrfFetchOutcome {
    CsrfFetchOutcome {
        state: CsrfState {
            token,
            thread_header: thread_header.to_string(),
        },
        cookie_to_append: name_value,
    }
}

fn outcome_no_cookie(token: String, thread_header: &str) -> CsrfFetchOutcome {
    CsrfFetchOutcome {
        state: CsrfState {
            token,
            thread_header: thread_header.to_string(),
        },
        cookie_to_append: None,
    }
}

/// Extract a specific cookie by name from `Set-Cookie` headers.
/// Returns `(value, "name=value")` — the raw value AND the
/// `name=value` form ready to append to the cookie jar.
fn extract_cookie_by_name(
    headers: &reqwest::header::HeaderMap,
    name: &str,
) -> Option<(String, String)> {
    for hv in headers.get_all(SET_COOKIE).iter() {
        let raw = hv.to_str().ok()?;
        // Per RFC 6265: Set-Cookie = name=value; attr=val; ...
        let head = raw.split(';').next()?.trim();
        let (n, v) = head.split_once('=')?;
        if n.eq_ignore_ascii_case(name) {
            return Some((v.to_string(), format!("{n}={v}")));
        }
    }
    None
}

/// Auto-detect a CSRF cookie. Matches any `Set-Cookie` whose name
/// contains `csrf` or `xsrf` substring, case-insensitive. First
/// match wins. Documented as "may false-match on `csrf_enabled=true`
/// — use explicit cookie strategy as the escape hatch."
fn extract_cookie_auto(headers: &reqwest::header::HeaderMap) -> Option<(String, String)> {
    for hv in headers.get_all(SET_COOKIE).iter() {
        let Some(raw) = hv.to_str().ok() else {
            continue;
        };
        let Some(head) = raw.split(';').next() else {
            continue;
        };
        let head = head.trim();
        let Some((n, v)) = head.split_once('=') else {
            continue;
        };
        let lower = n.to_ascii_lowercase();
        if lower.contains("csrf") || lower.contains("xsrf") {
            return Some((v.to_string(), format!("{n}={v}")));
        }
    }
    None
}

/// Extract a top-level string value from a JSON response body.
/// Nested-path lookups are out of scope for v1; users with
/// non-default keys pass them via the explicit `json:keyName` form.
fn extract_json_by_key(body: &[u8], key: &str) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let s = v.get(key).and_then(Value::as_str)?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Auto-detect a CSRF token in a JSON response body. Tries known
/// keys in priority order; first hit wins. Deliberately does NOT
/// include a generic `token` key — that would false-match OAuth
/// and API-token responses.
fn extract_json_auto(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    for key in ["csrfToken", "csrf_token", "_csrf"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Extract a token from a named response header. Returns the
/// header value verbatim. Trim whitespace defensively but do not
/// otherwise transform.
fn extract_response_header(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    let v = headers.get(name)?;
    let s = v.to_str().ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::test_server::{MockResponse, MockServer};

    // ----- parse_spec coverage -----

    #[test]
    fn parse_spec_short_form_returns_auto_strategy() {
        let s = parse_spec("GET:/csrf").unwrap();
        assert_eq!(s.method, "GET");
        assert_eq!(s.url, "/csrf");
        assert_eq!(s.strategy, CsrfStrategy::Auto);
        assert_eq!(s.thread_header, DEFAULT_THREAD_HEADER);
    }

    #[test]
    fn parse_spec_short_form_with_absolute_url() {
        let s = parse_spec("GET:http://localhost:5000/csrf").unwrap();
        // Embedded port colon must NOT be misread as a strategy.
        assert_eq!(s.url, "http://localhost:5000/csrf");
        assert_eq!(s.strategy, CsrfStrategy::Auto);
    }

    #[test]
    fn parse_spec_long_form_json_with_key() {
        let s = parse_spec("GET:/csrf:json:csrfToken").unwrap();
        assert_eq!(s.url, "/csrf");
        assert_eq!(s.strategy, CsrfStrategy::Json("csrfToken".into()));
    }

    #[test]
    fn parse_spec_long_form_cookie_with_name() {
        let s = parse_spec("GET:/csrf:cookie:XSRF-TOKEN").unwrap();
        assert_eq!(s.url, "/csrf");
        assert_eq!(s.strategy, CsrfStrategy::Cookie("XSRF-TOKEN".into()));
    }

    #[test]
    fn parse_spec_long_form_header_with_name() {
        let s = parse_spec("GET:/csrf:header:X-Csrf-Response").unwrap();
        assert_eq!(s.url, "/csrf");
        assert_eq!(s.strategy, CsrfStrategy::Header("X-Csrf-Response".into()));
    }

    #[test]
    fn parse_spec_long_form_with_absolute_url_round_trips() {
        // `http://host:8080/csrf:json:csrfToken` — embedded port
        // colon must not corrupt the parse. Strategy and URL both
        // recover correctly.
        let s = parse_spec("GET:http://host:8080/csrf:json:csrfToken").unwrap();
        assert_eq!(s.url, "http://host:8080/csrf");
        assert_eq!(s.strategy, CsrfStrategy::Json("csrfToken".into()));
    }

    #[test]
    fn parse_spec_lowercase_method_accepted() {
        let s = parse_spec("get:/csrf").unwrap();
        assert_eq!(s.method, "GET");
    }

    #[test]
    fn parse_spec_non_get_method_rejected_in_v1() {
        // POST/PUT/etc. all rejected — error must name the rejected
        // method so the user can correct without re-reading help.
        for bad in &["POST:/csrf", "PUT:/csrf", "DELETE:/csrf", "OPTIONS:/csrf"] {
            match parse_spec(bad) {
                Err(CsrfError::ParseError(msg)) => {
                    assert!(msg.contains("only GET"), "for {bad}: {msg}");
                }
                other => panic!("expected ParseError for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_spec_invalid_strategy_falls_through_to_short_form() {
        // `GET:/csrf:bogus:value` — `bogus` is not a known strategy
        // keyword. Parser interprets the whole thing as a URL
        // (short form). This is a deliberate choice: it's how the
        // parser handles URLs with embedded `:` (e.g. ports).
        // Validation will then reject the URL since `:` isn't a
        // valid path char in our short-form URL grammar.
        let result = parse_spec("GET:/csrf:bogus:value");
        // Short-form interpretation: URL = "/csrf:bogus:value",
        // which DOES start with `/`, so passes validate_url. We
        // accept it. Servers will fail at runtime if the path is
        // genuinely invalid — runtime failure is acceptable here
        // since strategy keywords are documented in help text.
        let s = result.unwrap();
        assert_eq!(s.strategy, CsrfStrategy::Auto);
        assert_eq!(s.url, "/csrf:bogus:value");
    }

    #[test]
    fn parse_spec_empty_rejected() {
        assert!(matches!(parse_spec(""), Err(CsrfError::ParseError(_))));
        assert!(matches!(parse_spec("   "), Err(CsrfError::ParseError(_))));
    }

    #[test]
    fn parse_spec_no_method_rejected() {
        // No `:` means no method separator.
        assert!(matches!(parse_spec("/csrf"), Err(CsrfError::ParseError(_))));
    }

    #[test]
    fn parse_spec_method_with_empty_path_rejected() {
        match parse_spec("GET:") {
            Err(CsrfError::ParseError(msg)) => {
                assert!(msg.contains("URL or path"), "got: {msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_spec_relative_path_without_leading_slash_rejected() {
        match parse_spec("GET:csrf") {
            Err(CsrfError::ParseError(msg)) => {
                assert!(msg.contains("must start with"), "got: {msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn parse_spec_long_form_empty_name_rejected() {
        for (input, kind) in &[
            ("GET:/csrf:json:", "json"),
            ("GET:/csrf:cookie:", "cookie"),
            ("GET:/csrf:header:", "header"),
        ] {
            match parse_spec(input) {
                Err(CsrfError::ParseError(msg)) => {
                    assert!(msg.contains(kind), "for {input}: {msg}");
                }
                other => panic!("expected ParseError for {input}, got {other:?}"),
            }
        }
    }

    // ----- resolve_url coverage -----

    #[test]
    fn resolve_url_keeps_absolute_url_intact() {
        assert_eq!(
            resolve_url("http://other/csrf", "http://target"),
            "http://other/csrf"
        );
        assert_eq!(
            resolve_url("https://other/csrf", "http://target"),
            "https://other/csrf"
        );
    }

    #[test]
    fn resolve_url_joins_relative_path_to_target() {
        assert_eq!(resolve_url("/csrf", "http://target/"), "http://target/csrf");
        assert_eq!(
            resolve_url("/api/csrf", "http://target"),
            "http://target/api/csrf"
        );
    }

    // ----- fetch_csrf integration coverage -----

    /// Sentinel CSRF token. Pinned unique so substring absence
    /// checks never false-positive on URLs / hashes / labels.
    const TEST_CSRF_TOKEN: &str = "arcis-test-csrf-DEADC0DE-1f7e3a";

    #[tokio::test]
    async fn extracts_csrf_from_json_body_with_default_key() {
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::json(format!(r#"{{"csrfToken":"{TEST_CSRF_TOKEN}"}}"#))
        });

        let spec = parse_spec(&format!("GET:{}/csrf", server.url())).unwrap();
        let auth = AuthConfig::default();
        let outcome = fetch_csrf(&spec, &auth, "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
        assert_eq!(outcome.state.thread_header, DEFAULT_THREAD_HEADER);
        assert!(outcome.cookie_to_append.is_none());
    }

    #[tokio::test]
    async fn extracts_csrf_from_json_with_custom_key_long_form() {
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::json(format!(r#"{{"my_token":"{TEST_CSRF_TOKEN}"}}"#))
        });

        let spec = parse_spec(&format!("GET:{}/csrf:json:my_token", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
    }

    #[tokio::test]
    async fn extracts_csrf_from_set_cookie_via_auto_detect() {
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::ok("").set_cookie(&format!("XSRF-TOKEN={TEST_CSRF_TOKEN}; Path=/"))
        });

        let spec = parse_spec(&format!("GET:{}/csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
        // Double-write: cookie payload must be returned for the
        // CLI to append to AuthConfig.cookie.
        assert_eq!(
            outcome.cookie_to_append.as_deref(),
            Some(format!("XSRF-TOKEN={TEST_CSRF_TOKEN}").as_str())
        );
    }

    #[tokio::test]
    async fn extracts_csrf_from_set_cookie_with_explicit_name() {
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::ok("").set_cookie(&format!("_csrf={TEST_CSRF_TOKEN}; Path=/"))
        });

        let spec = parse_spec(&format!("GET:{}/csrf:cookie:_csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
        assert_eq!(
            outcome.cookie_to_append.as_deref(),
            Some(format!("_csrf={TEST_CSRF_TOKEN}").as_str())
        );
    }

    #[tokio::test]
    async fn extracts_csrf_from_response_header_long_form() {
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::ok("").with_header("X-Csrf-Response", TEST_CSRF_TOKEN)
        });

        let spec =
            parse_spec(&format!("GET:{}/csrf:header:X-Csrf-Response", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
        // Header strategy never produces a cookie payload.
        assert!(outcome.cookie_to_append.is_none());
    }

    #[tokio::test]
    async fn auto_detect_prefers_cookie_over_json_body_when_both_present() {
        let server = MockServer::start().await;
        let cookie_token = format!("{TEST_CSRF_TOKEN}-from-cookie");
        let json_token = format!("{TEST_CSRF_TOKEN}-from-json");
        let cookie_token_clone = cookie_token.clone();
        let json_token_clone = json_token.clone();
        server.on("GET", "/csrf", move |_req| {
            MockResponse::json(format!(r#"{{"csrfToken":"{json_token_clone}"}}"#))
                .set_cookie(&format!("XSRF-TOKEN={cookie_token_clone}; Path=/"))
        });

        let spec = parse_spec(&format!("GET:{}/csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        // Cookie wins per the locked cascade. Pinned: changing this
        // is a behaviour change users would notice.
        assert_eq!(outcome.state.token, cookie_token);
    }

    #[tokio::test]
    async fn auto_detect_json_keys_in_priority_order() {
        // Priority order: csrfToken > csrf_token > _csrf. The
        // `token` key is deliberately NOT in the cascade — would
        // false-match OAuth/API responses.
        let server = MockServer::start().await;
        // All three keys present with distinct values.
        server.on("GET", "/all3", |_req| {
            MockResponse::json(r#"{"csrfToken":"A","csrf_token":"B","_csrf":"C","token":"D"}"#)
        });
        let spec = parse_spec(&format!("GET:{}/all3", server.url())).unwrap();
        let r = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(r.state.token, "A", "csrfToken should win");

        // csrf_token wins over _csrf when csrfToken absent.
        let server2 = MockServer::start().await;
        server2.on("GET", "/two", |_req| {
            MockResponse::json(r#"{"csrf_token":"B","_csrf":"C","token":"D"}"#)
        });
        let spec2 = parse_spec(&format!("GET:{}/two", server2.url())).unwrap();
        let r2 = fetch_csrf(&spec2, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(r2.state.token, "B", "csrf_token should win");

        // `token` is NOT in the cascade — auto-detect must fail
        // when only `token` is present.
        let server3 = MockServer::start().await;
        server3.on("GET", "/only-token", |_req| {
            MockResponse::json(r#"{"token":"D"}"#)
        });
        let spec3 = parse_spec(&format!("GET:{}/only-token", server3.url())).unwrap();
        let r3 = fetch_csrf(&spec3, &AuthConfig::default(), "", Duration::from_secs(2)).await;
        assert!(
            matches!(r3, Err(CsrfError::ExtractFailed)),
            "generic `token` key must NOT auto-match (false-positive risk on OAuth)"
        );
    }

    #[tokio::test]
    async fn fetch_csrf_404_returns_bad_status_with_url() {
        let server = MockServer::start().await;
        // No handler registered — every request returns 404.
        let url = format!("{}/missing", server.url());
        let spec = parse_spec(&format!("GET:{url}")).unwrap();
        let err = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap_err();
        match err {
            CsrfError::BadStatus {
                url: u,
                status: 404,
            } => {
                assert_eq!(u, url, "BadStatus must carry the URL the user passed");
            }
            other => panic!("expected BadStatus 404, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_csrf_no_capturable_returns_extract_failed() {
        // 200 with no body, no Set-Cookie — auto-detect cascade
        // produces nothing.
        let server = MockServer::start().await;
        server.on("GET", "/blank", |_req| MockResponse::ok(""));
        let spec = parse_spec(&format!("GET:{}/blank", server.url())).unwrap();
        let err = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, CsrfError::ExtractFailed), "got: {err:?}");
    }

    #[tokio::test]
    async fn fetch_csrf_unreachable_returns_unreachable_error() {
        // Bind a port then drop — no server listens at the URL.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let spec = parse_spec(&format!("GET:http://{addr}/csrf")).unwrap();
        let err = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, CsrfError::Unreachable(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn fetch_csrf_inherits_auth_cookie_from_base_auth() {
        // Composition test (refined per session direction): the
        // CSRF endpoint asserts the inbound request carries the
        // base auth cookie. Without inheritance, this would 401
        // mid-test rather than respond 200 with a token.
        let server = MockServer::start().await;
        server.on("GET", "/api/csrf", |req| {
            // Login-issued session cookie MUST be present on the
            // CSRF GET. Otherwise the endpoint would (in real
            // life) reject as unauthenticated.
            let cookie = req.headers.get("cookie").cloned().unwrap_or_default();
            assert!(
                cookie.contains("session=login-session"),
                "CSRF fetch must carry login session cookie; got: {cookie}"
            );
            MockResponse::json(format!(r#"{{"csrfToken":"{TEST_CSRF_TOKEN}"}}"#))
        });

        let auth = AuthConfig::with_cookie("session=login-session").unwrap();
        let spec = parse_spec(&format!("GET:{}/api/csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &auth, "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
    }

    #[tokio::test]
    async fn fetch_csrf_chained_with_login_inherits_session_cookie() {
        // End-to-end chained integration: simulate the runtime
        // ordering CLI's `run()` does — execute_login first, then
        // fetch_csrf with the login-populated AuthConfig as the
        // base. Pins the order-of-operations contract that the CLI
        // relies on.
        use crate::scan::login::{execute_login, LoginConfig};
        let server = MockServer::start().await;
        server.on("POST", "/auth/login", |_req| {
            MockResponse::ok("").set_cookie("session=chained-flow; Path=/")
        });
        server.on("GET", "/api/csrf", |req| {
            let cookie = req.headers.get("cookie").cloned().unwrap_or_default();
            // Login chain-of-trust: the login's Set-Cookie must
            // ride the CSRF GET. Without the chain, this fails.
            assert!(
                cookie.contains("session=chained-flow"),
                "chained CSRF fetch did not inherit login session cookie; got: {cookie}"
            );
            MockResponse::json(format!(r#"{{"csrfToken":"{TEST_CSRF_TOKEN}"}}"#))
        });

        // Step 1: login.
        let login_cfg = LoginConfig {
            url: format!("{}/auth/login", server.url()),
            form: vec![("user".into(), "x".into())],
            json: false,
        };
        let auth_after_login = execute_login(&login_cfg, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(
            auth_after_login.cookie.as_deref(),
            Some("session=chained-flow")
        );

        // Step 2: CSRF fetch using the login-populated auth.
        let spec = parse_spec(&format!("GET:{}/api/csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &auth_after_login, "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
    }

    #[tokio::test]
    async fn fetch_csrf_redirect_response_keeps_set_cookie_observable() {
        // 302 + Set-Cookie pattern (Laravel sanctum). The fetch
        // client uses redirect::Policy::none() so the Set-Cookie on
        // the 302 is not lost behind the redirect.
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::ok("")
                .status(302)
                .with_header("Location", "/elsewhere")
                .set_cookie(&format!("XSRF-TOKEN={TEST_CSRF_TOKEN}; Path=/"))
        });
        let spec = parse_spec(&format!("GET:{}/csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &AuthConfig::default(), "", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
    }

    #[tokio::test]
    async fn fetch_csrf_resolves_relative_path_against_base_url() {
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::json(format!(r#"{{"csrfToken":"{TEST_CSRF_TOKEN}"}}"#))
        });
        // Spec uses bare path; fetch must join with base_url.
        let spec = parse_spec("GET:/csrf").unwrap();
        let outcome = fetch_csrf(
            &spec,
            &AuthConfig::default(),
            &server.url(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(outcome.state.token, TEST_CSRF_TOKEN);
    }

    #[tokio::test]
    async fn cookie_strategy_does_not_duplicate_when_user_cookie_already_set() {
        // Verbatim no-parse policy: when the CSRF fetch captures a
        // cookie whose name already appears in `base_auth.cookie`, the
        // engine STILL returns the freshly-fetched `name=value` for
        // the caller to append — no dedup, no merge, no rewrite.
        //
        // The CLI (6b) appends the returned `cookie_to_append` to the
        // existing `AuthConfig.cookie` joined with `; `, producing a
        // wire payload like `XSRF-TOKEN=stale; XSRF-TOKEN=fresh`.
        // HTTP servers honor the LAST occurrence — so the freshly-
        // fetched value wins server-side without engine-layer logic.
        // This test pins both halves:
        //   1. The engine returns the fresh value unconditionally
        //      (no inspection of base_auth.cookie).
        //   2. AuthConfig::to_header_map preserves the joined cookie
        //      verbatim so both occurrences land on the wire.
        let server = MockServer::start().await;
        server.on("GET", "/csrf", |_req| {
            MockResponse::ok("").set_cookie("XSRF-TOKEN=fresh-token-from-server; Path=/")
        });

        // Base auth already has a cookie under the SAME name.
        let base_auth = AuthConfig::with_cookie("XSRF-TOKEN=stale-value-from-user").unwrap();
        let spec = parse_spec(&format!("GET:{}/csrf", server.url())).unwrap();
        let outcome = fetch_csrf(&spec, &base_auth, "", Duration::from_secs(2))
            .await
            .unwrap();

        // (1) Engine does NOT inspect base_auth.cookie. It returns the
        //     fresh value, full stop.
        assert_eq!(outcome.state.token, "fresh-token-from-server");
        assert_eq!(
            outcome.cookie_to_append.as_deref(),
            Some("XSRF-TOKEN=fresh-token-from-server"),
            "engine MUST NOT dedupe: caller appends verbatim, last-occurrence wins server-side"
        );

        // (2) Simulate the CLI append step: join with `; `, hand to
        //     to_header_map, assert both occurrences appear on the wire
        //     in user-then-csrf order.
        let mut auth_after = base_auth.clone();
        auth_after.cookie = Some(format!(
            "{}; {}",
            base_auth.cookie.as_deref().unwrap(),
            outcome.cookie_to_append.as_deref().unwrap()
        ));
        let headers = auth_after.to_header_map();
        assert_eq!(
            headers.get("cookie").map(|v| v.to_str().unwrap()),
            Some("XSRF-TOKEN=stale-value-from-user; XSRF-TOKEN=fresh-token-from-server"),
            "AuthConfig::to_header_map must emit the joined cookie verbatim — both values, no dedup"
        );
    }

    // ----- auto-detect cookie matcher -----

    #[test]
    fn auto_cookie_matches_csrf_substring_case_insensitive() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(SET_COOKIE, "MY_CSRF_TOKEN=abc; Path=/".parse().unwrap());
        let m = extract_cookie_auto(&headers).unwrap();
        assert_eq!(m, ("abc".into(), "MY_CSRF_TOKEN=abc".into()));
    }

    #[test]
    fn auto_cookie_matches_xsrf_token_exact() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(SET_COOKIE, "XSRF-TOKEN=abc; Path=/".parse().unwrap());
        let m = extract_cookie_auto(&headers).unwrap();
        assert_eq!(m, ("abc".into(), "XSRF-TOKEN=abc".into()));
    }

    #[test]
    fn auto_cookie_skips_non_csrf_names() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(SET_COOKIE, "session=abc; Path=/".parse().unwrap());
        headers.append(SET_COOKIE, "auth=xyz".parse().unwrap());
        assert!(extract_cookie_auto(&headers).is_none());
    }
}
