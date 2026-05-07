//! Login flow for `arcis scan --login`.
//!
//! Backs commit #4 of Phase B item 5. Single-shot async function:
//! POSTs credentials to the configured URL, captures an auth artifact
//! from the response, returns a fully-populated [`AuthConfig`] that
//! the rest of the scan run uses (probe + every vector inherits the
//! captured headers via `Client::builder().default_headers`).
//!
//! ## Capture priority (deterministic, first hit wins)
//!
//! 1. Any `Set-Cookie` header(s) on the response → strip per-cookie
//!    attributes (`Path`, `HttpOnly`, etc.), join the bare `name=value`
//!    pairs with `; `, populate [`AuthConfig::cookie`].
//! 2. Else parse the response body as JSON; look up `access_token`,
//!    then `token`, then `jwt`. The first that is a string populates
//!    [`AuthConfig::bearer`]. JWT shape is NOT validated — the value
//!    is treated as opaque.
//! 3. Else [`LoginError::NoCapturable`].
//!
//! ## Redirect handling
//!
//! The login client is built with `redirect::Policy::none()` so we
//! observe the FIRST response directly. This is deliberately different
//! from the scan client (which follows redirects). Login flows often
//! return `302 + Set-Cookie` and immediately hand off to the new
//! session — if we followed the redirect, the Set-Cookie from the 302
//! would be invisible to us by the time we read `resp.headers()`.
//! Treating 2xx AND 3xx as artifact-capturable lets us capture the
//! cookie from the redirect-set-cookie pattern.
//!
//! ## TLS
//!
//! Same `Client::builder()` base as the scan client — strict TLS via
//! rustls (workspace `Cargo.toml` `rustls-tls` feature). No `--insecure`
//! flag exists for either path; both paths are strict in lockstep.
//!
//! ## Timeout
//!
//! Caller passes the same `Duration` used for scan probes (the CLI's
//! `--timeout` flag). No separate `--login-timeout` — if login takes
//! longer than scan, the user already has the knob.

use std::time::Duration;

use reqwest::{header::SET_COOKIE, redirect, Client};
use serde_json::Value;

use super::auth::AuthConfig;

/// Caller-supplied login spec. `form` is an ordered list of key/value
/// pairs; the request body encoding switches on `json` (false =
/// `application/x-www-form-urlencoded`, true = `application/json`).
#[derive(Debug, Clone)]
pub struct LoginConfig {
    pub url: String,
    pub form: Vec<(String, String)>,
    pub json: bool,
}

/// Errors from the login flow. All map to CLI exit code 2 with a
/// human-readable message at the call site.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("login URL unreachable: {0}")]
    Unreachable(reqwest::Error),
    #[error("login failed: POST {url} returned {status}")]
    BadStatus { url: String, status: u16 },
    #[error(
        "login response had no Set-Cookie header or recognized token field (access_token, token, jwt)"
    )]
    NoCapturable,
}

/// Execute the configured login flow. Returns an [`AuthConfig`] whose
/// `login` field is populated (so [`AuthConfig::redact_for_json`]
/// reports `methods=["login"]`) AND whose `bearer` or `cookie` field
/// carries the captured artifact (so
/// [`AuthConfig::to_header_map`] emits the right header on every
/// subsequent scan request).
pub async fn execute_login(cfg: &LoginConfig, timeout: Duration) -> Result<AuthConfig, LoginError> {
    let client = Client::builder()
        .timeout(timeout)
        .redirect(redirect::Policy::none())
        .build()
        .map_err(LoginError::Unreachable)?;

    let mut request = client.post(&cfg.url);
    if cfg.json {
        // Build a JSON object preserving registration order via
        // serde_json::Map (with `preserve_order` workspace feature).
        let mut body = serde_json::Map::new();
        for (k, v) in &cfg.form {
            body.insert(k.clone(), Value::String(v.clone()));
        }
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(Value::Object(body).to_string());
    } else {
        // form-urlencoded — reqwest's `.form()` does the encoding.
        request = request.form(&cfg.form);
    }

    let response = request.send().await.map_err(LoginError::Unreachable)?;
    let status = response.status();

    // 2xx + 3xx are both "login proceeded; look for an artifact".
    // 4xx + 5xx are credential / server failures — no point
    // continuing.
    if status.is_client_error() || status.is_server_error() {
        return Err(LoginError::BadStatus {
            url: cfg.url.clone(),
            status: status.as_u16(),
        });
    }

    // Capture priority 1: Set-Cookie header(s).
    if let Some(cookie_header) = extract_set_cookies(response.headers()) {
        return Ok(AuthConfig {
            cookie: Some(cookie_header),
            login: Some(cfg.clone()),
            ..Default::default()
        });
    }

    // Capture priority 2: JSON body with recognized token field.
    let body_bytes = response.bytes().await.unwrap_or_default();
    if let Some(token) = extract_token_from_json(&body_bytes) {
        return Ok(AuthConfig {
            bearer: Some(token),
            login: Some(cfg.clone()),
            ..Default::default()
        });
    }

    Err(LoginError::NoCapturable)
}

/// Pull the `name=value` part of every `Set-Cookie` header on the
/// response and join them with `; `. Returns `None` if no `Set-Cookie`
/// header is present. The result is a verbatim `Cookie` request header
/// value suitable for [`AuthConfig::cookie`].
fn extract_set_cookies(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let parts: Vec<String> = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
        .map(|raw| {
            // Per RFC 6265 a Set-Cookie value is `name=value` followed
            // by `;`-separated attributes. Take only the first piece.
            let head = raw.split(';').next().unwrap_or("").trim();
            head.to_string()
        })
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// Try to extract an opaque token string from a JSON response body.
/// Looks up `access_token`, then `token`, then `jwt` (priority order,
/// first hit that is a non-empty string wins). No JWT shape validation
/// — the token is treated as an opaque bearer string.
fn extract_token_from_json(body: &[u8]) -> Option<String> {
    let v: Value = serde_json::from_slice(body).ok()?;
    for key in ["access_token", "token", "jwt"] {
        if let Some(s) = v.get(key).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::test_server::{MockResponse, MockServer};

    fn login_cfg(url: String, form: Vec<(&str, &str)>, json: bool) -> LoginConfig {
        LoginConfig {
            url,
            form: form
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            json,
        }
    }

    #[tokio::test]
    async fn execute_login_captures_set_cookie_into_auth_cookie() {
        let server = MockServer::start().await;
        server.on("POST", "/auth/login", |_req| {
            MockResponse::ok("").set_cookie("session=abc123; Path=/; HttpOnly")
        });
        let cfg = login_cfg(
            format!("{}/auth/login", server.url()),
            vec![("user", "admin"), ("pass", "hunter2")],
            false,
        );
        let result = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();
        // Per-cookie attributes stripped — only `name=value`.
        assert_eq!(result.cookie.as_deref(), Some("session=abc123"));
        assert!(result.bearer.is_none());
        assert!(result.login.is_some());
    }

    #[tokio::test]
    async fn execute_login_joins_multiple_set_cookies_with_semicolons() {
        let server = MockServer::start().await;
        server.on("POST", "/auth/login", |_req| {
            MockResponse::ok("")
                .set_cookie("session=abc; Path=/; HttpOnly")
                .set_cookie("csrf=xyz; SameSite=Strict")
        });
        let cfg = login_cfg(
            format!("{}/auth/login", server.url()),
            vec![("u", "x")],
            false,
        );
        let result = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();
        assert_eq!(result.cookie.as_deref(), Some("session=abc; csrf=xyz"));
    }

    #[tokio::test]
    async fn execute_login_captures_set_cookie_from_302_redirect_response() {
        // Common pattern: form-style login returns 302 + Set-Cookie,
        // expects the client to follow Location. Our login client uses
        // `redirect::Policy::none()` precisely so the Set-Cookie from
        // the 302 is observable. Without that policy, reqwest would
        // follow the redirect and we'd see only the final response's
        // (likely empty) Set-Cookie header set.
        let server = MockServer::start().await;
        server.on("POST", "/auth/login", |_req| {
            MockResponse::ok("")
                .status(302)
                .with_header("Location", "/dashboard")
                .set_cookie("session=redirect-flow-cookie; Path=/")
        });
        let cfg = login_cfg(
            format!("{}/auth/login", server.url()),
            vec![("u", "x")],
            false,
        );
        let result = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();
        assert_eq!(
            result.cookie.as_deref(),
            Some("session=redirect-flow-cookie")
        );
    }

    #[tokio::test]
    async fn execute_login_captures_access_token_into_auth_bearer() {
        let server = MockServer::start().await;
        server.on("POST", "/auth/login", |_req| {
            MockResponse::json(r#"{"access_token":"jwt.payload.sig","other":"ignored"}"#)
        });
        let cfg = login_cfg(
            format!("{}/auth/login", server.url()),
            vec![("u", "x")],
            false,
        );
        let result = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();
        assert_eq!(result.bearer.as_deref(), Some("jwt.payload.sig"));
        assert!(result.cookie.is_none());
    }

    #[tokio::test]
    async fn execute_login_token_field_priority_access_token_then_token_then_jwt() {
        // access_token wins.
        let server = MockServer::start().await;
        server.on("POST", "/auth/multi", |_req| {
            MockResponse::json(r#"{"access_token":"A","token":"B","jwt":"C"}"#)
        });
        let cfg = login_cfg(
            format!("{}/auth/multi", server.url()),
            vec![("u", "x")],
            false,
        );
        let result = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();
        assert_eq!(result.bearer.as_deref(), Some("A"));

        // token beats jwt when access_token is absent.
        let server2 = MockServer::start().await;
        server2.on("POST", "/auth/two", |_req| {
            MockResponse::json(r#"{"token":"B","jwt":"C"}"#)
        });
        let cfg2 = login_cfg(
            format!("{}/auth/two", server2.url()),
            vec![("u", "x")],
            false,
        );
        let r2 = execute_login(&cfg2, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r2.bearer.as_deref(), Some("B"));

        // jwt is the last fallback.
        let server3 = MockServer::start().await;
        server3.on("POST", "/auth/jwt", |_req| {
            MockResponse::json(r#"{"jwt":"C"}"#)
        });
        let cfg3 = login_cfg(
            format!("{}/auth/jwt", server3.url()),
            vec![("u", "x")],
            false,
        );
        let r3 = execute_login(&cfg3, Duration::from_secs(2)).await.unwrap();
        assert_eq!(r3.bearer.as_deref(), Some("C"));
    }

    #[tokio::test]
    async fn execute_login_set_cookie_wins_over_json_body() {
        // Both present — Set-Cookie has priority. The response body
        // token would NOT be captured; we never even read the body.
        let server = MockServer::start().await;
        server.on("POST", "/auth/both", |_req| {
            MockResponse::json(r#"{"access_token":"would-be-bearer"}"#)
                .set_cookie("session=wins; Path=/")
        });
        let cfg = login_cfg(
            format!("{}/auth/both", server.url()),
            vec![("u", "x")],
            false,
        );
        let result = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();
        assert_eq!(result.cookie.as_deref(), Some("session=wins"));
        assert!(result.bearer.is_none());
    }

    #[tokio::test]
    async fn execute_login_sends_form_urlencoded_body_by_default() {
        use std::sync::{Arc, Mutex};
        let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
        let cap = captured.clone();
        let server = MockServer::start().await;
        server.on("POST", "/auth/echo", move |req| {
            let ct = req.headers.get("content-type").cloned().unwrap_or_default();
            *cap.lock().unwrap() = Some((ct, req.body.clone()));
            MockResponse::ok("").set_cookie("session=ok")
        });
        let cfg = login_cfg(
            format!("{}/auth/echo", server.url()),
            vec![("user", "admin"), ("pass", "hunter2")],
            false,
        );
        let _ = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();

        let snapshot = captured.lock().unwrap().clone().unwrap();
        let (ct, body) = snapshot;
        assert!(
            ct.starts_with("application/x-www-form-urlencoded"),
            "content-type: {ct}"
        );
        assert_eq!(body, "user=admin&pass=hunter2");
    }

    #[tokio::test]
    async fn execute_login_sends_json_body_when_json_flag_set() {
        use std::sync::{Arc, Mutex};
        let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
        let cap = captured.clone();
        let server = MockServer::start().await;
        server.on("POST", "/auth/echo", move |req| {
            let ct = req.headers.get("content-type").cloned().unwrap_or_default();
            *cap.lock().unwrap() = Some((ct, req.body.clone()));
            MockResponse::ok("").set_cookie("session=ok")
        });
        let cfg = login_cfg(
            format!("{}/auth/echo", server.url()),
            vec![("user", "admin"), ("pass", "hunter2")],
            true,
        );
        let _ = execute_login(&cfg, Duration::from_secs(2)).await.unwrap();

        let snapshot = captured.lock().unwrap().clone().unwrap();
        let (ct, body) = snapshot;
        assert!(ct.starts_with("application/json"), "content-type: {ct}");
        // Field order preserved via serde_json's `preserve_order`
        // workspace feature.
        assert_eq!(body, r#"{"user":"admin","pass":"hunter2"}"#);
    }

    #[tokio::test]
    async fn execute_login_status_4xx_returns_bad_status() {
        let server = MockServer::start().await;
        server.on("POST", "/auth/badcreds", |_req| {
            MockResponse::ok("").status(401)
        });
        let url = format!("{}/auth/badcreds", server.url());
        let cfg = login_cfg(url.clone(), vec![("u", "x")], false);
        let err = execute_login(&cfg, Duration::from_secs(2))
            .await
            .unwrap_err();
        match err {
            LoginError::BadStatus {
                url: u,
                status: 401,
            } => assert_eq!(u, url),
            other => panic!("expected BadStatus 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn execute_login_no_artifact_returns_no_capturable() {
        let server = MockServer::start().await;
        server.on("POST", "/auth/blank", |_req| MockResponse::ok(""));
        let cfg = login_cfg(
            format!("{}/auth/blank", server.url()),
            vec![("u", "x")],
            false,
        );
        let err = execute_login(&cfg, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(err, LoginError::NoCapturable), "got: {err:?}");
    }

    #[tokio::test]
    async fn execute_login_unreachable_returns_unreachable_error() {
        // Bind a port then drop it — the URL resolves but nothing
        // listens, so the connection attempt fails fast.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let cfg = login_cfg(format!("http://{addr}/auth/login"), vec![("u", "x")], false);
        let err = execute_login(&cfg, Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(matches!(err, LoginError::Unreachable(_)), "got: {err:?}");
    }
}
