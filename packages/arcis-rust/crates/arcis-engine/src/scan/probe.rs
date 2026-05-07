//! Async HTTP probe for `arcis scan`.
//!
//! Direct port of the `_send` + `scan_route` halves of
//! `packages/arcis-python/arcis/cli/scan.py`. The threading model differs
//! from Python's `concurrent.futures.ThreadPoolExecutor(max_workers=10)`:
//! we use a `tokio::sync::Semaphore` of capacity 10 around `reqwest`
//! futures spawned via `tokio::spawn`. Original-task ordering is preserved
//! by tagging each future with its index and slotting completions back
//! into a fixed-size result vector — same approach as Python's
//! `results_map[idx]`.
//!
//! Connection errors map to `status == 0` so [`super::classifier::classify`]
//! sees the same shape as Python.

use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Method};
use serde_json::Value;
use tokio::sync::Semaphore;

use super::auth::AuthConfig;
use super::classifier::classify;
use super::payloads::{attack_categories, slug};

/// Body sent with each probe-step request before the real attack payloads
/// fan out. Matches Python's `_send(url, method, field, "hello", ...)`.
const PROBE_PAYLOAD: &str = "hello";

/// Same cap as Python's `ThreadPoolExecutor(max_workers=10)`.
const MAX_CONCURRENCY: usize = 10;

/// Result of one attack vector against one route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorResult {
    pub category: String,
    pub label: String,
    pub payload: String,
    pub status: u16,
    pub blocked: bool,
    pub note: String,
}

/// Result of scanning one route (probe + all active vectors).
///
/// `field` is the JSON body / query key the probe step settled on; empty
/// string when the route never reached the vector dispatch stage. Carried
/// here so renderers (human + JSON) can build a faithful `curl`
/// reproducer per vector — see `scan::repro::format_curl`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteResult {
    pub method: String,
    pub path: String,
    pub reachable: bool,
    pub error: Option<String>,
    pub field: String,
    pub vectors: Vec<VectorResult>,
}

/// Caller-supplied options for [`scan_route`]. Names mirror the Python
/// `argparse.Namespace` fields one-to-one.
pub struct ScanOptions<'a> {
    pub fields: &'a [&'a str],
    pub timeout: Duration,
    /// Lowercase, whitespace-stripped category slugs. `None` = all
    /// categories. Compare via [`slug`] for ergonomics matching Python's
    /// `c.lower().replace(" ", "")`.
    pub categories: Option<&'a [String]>,
    pub thorough: bool,
    /// Optional auth state. `None` is the zero-cost no-auth path
    /// (no header-map allocation, no `default_headers` call). Carries
    /// the bearer token (and, in follow-up commits, cookies + login
    /// artifacts) injected on every probe + vector request.
    pub auth: Option<&'a AuthConfig>,
}

/// Send one HTTP request with `payload` injected into `field`. Returns
/// `(status, body)` where `status == 0` means connection error / timeout
/// — the convention `_classify` keys off.
///
/// GET: `payload` URL-encoded into `?{field}={payload}` (or `&` if the
/// base URL already has a query string). POST/PUT/PATCH/DELETE: JSON
/// body `{field: payload}` with `payload` parsed as JSON when valid (so
/// NoSQL payloads stay nested) or wrapped as a string otherwise.
pub async fn send_one(
    client: &Client,
    base_url: &str,
    method: &str,
    field: &str,
    payload: &str,
    timeout: Duration,
) -> (u16, String) {
    // Mirrors Python: try json.loads first; on parse failure use the
    // raw string. NoSQL payloads (`{"$gt": ""}` etc.) round-trip nested.
    let json_value: Value =
        serde_json::from_str(payload).unwrap_or_else(|_| Value::String(payload.to_string()));

    let result = if method.eq_ignore_ascii_case("GET") {
        let encoded = urlencoding::encode(payload);
        let sep = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{sep}{field}={encoded}");
        client.get(&url).timeout(timeout).send().await
    } else {
        let m = Method::from_bytes(method.as_bytes()).unwrap_or(Method::POST);
        let body = serde_json::json!({ field: json_value }).to_string();
        client
            .request(m, base_url)
            .header("Content-Type", "application/json")
            .body(body)
            .timeout(timeout)
            .send()
            .await
    };

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (status, body)
        }
        Err(_) => (0, String::new()),
    }
}

fn build_tasks(categories: Option<&[String]>, thorough: bool) -> Vec<(String, String, String)> {
    let filter: Option<Vec<String>> = categories.map(|cats| cats.iter().map(|c| slug(c)).collect());
    let mut tasks: Vec<(String, String, String)> = Vec::new();
    for cat in attack_categories() {
        if let Some(slugs) = &filter {
            if !slugs.contains(&slug(cat.name)) {
                continue;
            }
        }
        let vectors: &[_] = if thorough || cat.vectors.is_empty() {
            cat.vectors
        } else {
            &cat.vectors[..1]
        };
        for v in vectors {
            tasks.push((
                cat.name.to_string(),
                v.label.to_string(),
                v.payload.to_string(),
            ));
        }
    }
    tasks
}

/// Scan one route end-to-end. Probes for a working field, then fans
/// every active vector out with a concurrency cap of 10. Returns the
/// per-route result with vectors in original-task order.
pub async fn scan_route(
    base_url: &str,
    method: &str,
    path: &str,
    options: &ScanOptions<'_>,
) -> RouteResult {
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let mut result = RouteResult {
        method: method.to_string(),
        path: path.to_string(),
        ..Default::default()
    };

    // Single header-injection site for all auth flags. `default_headers`
    // is set once on the Client; probe step + every vector inherits.
    // No-auth path skips the call entirely (no allocation, no copy).
    let mut builder = Client::builder().timeout(options.timeout);
    if let Some(auth) = options.auth {
        builder = builder.default_headers(auth.to_header_map());
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            result.error = Some(format!("client init failed: {e}"));
            return result;
        }
    };

    // Probe step — find a field that isn't 404. Bail on connection error.
    let mut working_field = options.fields.first().copied().unwrap_or("q").to_string();
    let mut found_working = false;
    for field in options.fields {
        let (status, _) =
            send_one(&client, &url, method, field, PROBE_PAYLOAD, options.timeout).await;
        if status == 0 {
            result.error = Some("unreachable - is the server running?".into());
            return result;
        }
        if status != 404 {
            working_field = (*field).to_string();
            found_working = true;
            break;
        }
    }
    if !found_working {
        result.error = Some("404 not found".into());
        return result;
    }
    result.reachable = true;
    result.field = working_field.clone();

    let tasks = build_tasks(options.categories, options.thorough);

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENCY));
    let client = Arc::new(client);
    let url = Arc::new(url);
    let field = Arc::new(working_field);
    let method = Arc::new(method.to_string());
    let timeout = options.timeout;

    let mut handles: Vec<tokio::task::JoinHandle<(usize, VectorResult)>> =
        Vec::with_capacity(tasks.len());
    for (idx, (cat, label, payload)) in tasks.into_iter().enumerate() {
        let sem = sem.clone();
        let client = client.clone();
        let url = url.clone();
        let field = field.clone();
        let method = method.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            let (status, body) = send_one(&client, &url, &method, &field, &payload, timeout).await;
            let cls = classify(status, &body, &payload);
            (
                idx,
                VectorResult {
                    category: cat,
                    label,
                    payload,
                    status,
                    blocked: cls.blocked,
                    note: cls.note,
                },
            )
        }));
    }

    let mut slots: Vec<Option<VectorResult>> = (0..handles.len()).map(|_| None).collect();
    for handle in handles {
        if let Ok((idx, vr)) = handle.await {
            if idx < slots.len() {
                slots[idx] = Some(vr);
            }
        }
    }
    result.vectors = slots.into_iter().flatten().collect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Minimal mock server. Reads a request, returns the configured
    /// response. `responder` decides the status + body per request.
    async fn spawn_mock<F>(responder: F) -> SocketAddr
    where
        F: Fn(&str) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = Arc::new(responder);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let r = responder.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match sock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let (status, body) = r(&req);
                    let reason = match status {
                        200 => "OK",
                        400 => "Bad Request",
                        403 => "Forbidden",
                        404 => "Not Found",
                        429 => "Too Many Requests",
                        500 => "Internal Server Error",
                        _ => "Status",
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    fn make_client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn send_one_returns_zero_on_closed_port() {
        // Bind a port then drop the listener — port is closed by the
        // time we probe. Tolerant to OS races: assert the contract is
        // (status_zero) OR (timeout fallback).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = make_client();
        let url = format!("http://{addr}/");
        let (status, body) =
            send_one(&client, &url, "POST", "q", "x", Duration::from_millis(500)).await;
        assert_eq!(status, 0);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn send_one_get_encodes_payload_in_query() {
        let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let cap = captured.clone();
        let addr = spawn_mock(move |req: &str| {
            *cap.lock().unwrap() = Some(req.to_string());
            (200, "ok".into())
        })
        .await;

        let client = make_client();
        let (status, body) = send_one(
            &client,
            &format!("http://{addr}/api/search"),
            "GET",
            "q",
            "<script>alert(1)</script>",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");
        let req = captured.lock().unwrap().clone().unwrap();
        // URL-encoded payload appears in the request line.
        assert!(req.contains("q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"));
        assert!(req.starts_with("GET /api/search?"));
    }

    #[tokio::test]
    async fn send_one_post_sends_json_body() {
        let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let cap = captured.clone();
        let addr = spawn_mock(move |req: &str| {
            *cap.lock().unwrap() = Some(req.to_string());
            (200, "ok".into())
        })
        .await;

        let client = make_client();
        let (status, _body) = send_one(
            &client,
            &format!("http://{addr}/api/login"),
            "POST",
            "username",
            "<script>alert(1)</script>",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(status, 200);
        let req = captured.lock().unwrap().clone().unwrap();
        let lower = req.to_lowercase();
        assert!(req.starts_with("POST /api/login"));
        // hyper/reqwest may lowercase headers on the wire — match case-insensitively.
        assert!(lower.contains("content-type: application/json"));
        assert!(req.contains("\"username\""));
        assert!(req.contains("\"<script>alert(1)</script>\""));
    }

    #[tokio::test]
    async fn send_one_post_keeps_nosql_payload_nested() {
        let captured: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let cap = captured.clone();
        let addr = spawn_mock(move |req: &str| {
            *cap.lock().unwrap() = Some(req.to_string());
            (200, "ok".into())
        })
        .await;

        let client = make_client();
        let _ = send_one(
            &client,
            &format!("http://{addr}/api/login"),
            "POST",
            "username",
            "{\"$gt\": \"\"}",
            Duration::from_secs(2),
        )
        .await;
        let req = captured.lock().unwrap().clone().unwrap();
        // The body should round-trip the inner object, not stringify it.
        assert!(req.contains(r#""username":{"$gt":"""#));
    }

    #[tokio::test]
    async fn scan_route_marks_unreachable_when_port_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_millis(500),
            categories: None,
            thorough: false,
            auth: None,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/login", &opts).await;
        assert!(!rr.reachable);
        assert!(rr.error.unwrap().contains("unreachable"));
        assert!(rr.vectors.is_empty());
    }

    #[tokio::test]
    async fn scan_route_records_404_when_every_field_misses() {
        let addr = spawn_mock(|_req: &str| (404, "not found".into())).await;
        let opts = ScanOptions {
            fields: &["q", "search"],
            timeout: Duration::from_secs(2),
            categories: None,
            thorough: false,
            auth: None,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/missing", &opts).await;
        assert!(!rr.reachable);
        assert_eq!(rr.error.as_deref(), Some("404 not found"));
        assert!(rr.vectors.is_empty());
    }

    #[tokio::test]
    async fn scan_route_blocks_when_server_rejects_with_400() {
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let addr = spawn_mock(move |_req: &str| {
            let n = c.fetch_add(1, Ordering::SeqCst);
            // First request is the harmless probe — answer 200 so the
            // route is marked reachable. Subsequent payload requests
            // get 400 (rejected).
            if n == 0 {
                (200, "ok".into())
            } else {
                (400, "blocked".into())
            }
        })
        .await;
        // One category to keep the test fast and deterministic.
        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: None,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        assert!(rr.reachable);
        assert!(rr.error.is_none());
        assert_eq!(
            rr.vectors.len(),
            1,
            "non-thorough = one primary vector per category"
        );
        let v = &rr.vectors[0];
        assert_eq!(v.category, "XSS");
        assert!(v.blocked);
        assert_eq!(v.note, "rejected (400)");
    }

    #[tokio::test]
    async fn scan_route_preserves_task_order_under_concurrency() {
        // Server returns 400 for every request after the probe so all
        // vectors are classified identically. We only check ordering.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let addr = spawn_mock(move |_req: &str| {
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                (200, "ok".into())
            } else {
                (400, String::new())
            }
        })
        .await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: None, // all categories
            thorough: false,
            auth: None,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        assert!(rr.reachable);
        // 8 categories x primary vector = 8 ordered results.
        let categories: Vec<&str> = rr.vectors.iter().map(|v| v.category.as_str()).collect();
        assert_eq!(
            categories,
            vec![
                "XSS",
                "SQL Injection",
                "SQL Blind",
                "NoSQL Injection",
                "Path Traversal",
                "Command Injection",
                "Prototype Pollution",
                "LDAP Injection",
            ]
        );
    }

    #[test]
    fn build_tasks_default_picks_one_per_category() {
        let tasks = build_tasks(None, false);
        // 8 categories x 1 primary vector each.
        assert_eq!(tasks.len(), 8);
    }

    #[test]
    fn build_tasks_thorough_picks_every_vector() {
        let tasks = build_tasks(None, true);
        // 4+4+3+4+4+4+2+2 = 27.
        assert_eq!(tasks.len(), 27);
    }

    #[test]
    fn build_tasks_filters_by_slug() {
        let cats = vec!["xss".to_string(), "sqlinjection".to_string()];
        let tasks = build_tasks(Some(&cats), false);
        assert_eq!(tasks.len(), 2);
        let names: std::collections::HashSet<&str> =
            tasks.iter().map(|(c, _, _)| c.as_str()).collect();
        assert!(names.contains("XSS"));
        assert!(names.contains("SQL Injection"));
    }

    #[test]
    fn build_tasks_filter_is_case_insensitive_and_space_stripped() {
        let cats = vec!["NoSQL Injection".to_string(), "Sql Blind".to_string()];
        let tasks = build_tasks(Some(&cats), false);
        let names: std::collections::HashSet<&str> =
            tasks.iter().map(|(c, _, _)| c.as_str()).collect();
        assert!(names.contains("NoSQL Injection"));
        assert!(names.contains("SQL Blind"));
        assert_eq!(names.len(), 2);
    }

    // The two tests below use the per-route mock server from
    // `super::test_server` rather than `spawn_mock`, since they assert
    // against captured request headers — a surface the single-responder
    // mock doesn't expose.
    #[tokio::test]
    async fn scan_route_with_bearer_sends_authorization_on_every_request() {
        use crate::scan::test_server::{MockResponse, MockServer};

        let server = MockServer::start().await;
        // Every request: 200 OK so the probe step succeeds and vector
        // dispatch fires.
        server.on("POST", "/api/test", |_req| MockResponse::ok("{}"));

        let auth = AuthConfig::with_bearer("test-bearer-token-xyz").unwrap();
        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: Some(&auth),
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty(), "expected at least one request");
        for req in &captured {
            assert_eq!(
                req.headers.get("authorization").map(String::as_str),
                Some("Bearer test-bearer-token-xyz"),
                "every probe + vector request must carry the bearer header; got: {req:?}"
            );
        }
    }

    #[tokio::test]
    async fn scan_route_without_auth_omits_authorization_header() {
        use crate::scan::test_server::{MockResponse, MockServer};

        let server = MockServer::start().await;
        server.on("POST", "/api/test", |_req| MockResponse::ok("{}"));

        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: None,
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty(), "expected at least one request");
        for req in &captured {
            assert!(
                !req.headers.contains_key("authorization"),
                "no-auth runs must NOT send an Authorization header; got: {req:?}"
            );
        }
    }
}
