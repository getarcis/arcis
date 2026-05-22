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
use tokio::sync::{watch, Semaphore};

use super::auth::AuthConfig;
use super::classifier::classify;
use super::payloads::{attack_categories, slug};

/// Body sent with each probe-step request before the real attack payloads
/// fan out. Matches Python's `_send(url, method, field, "hello", ...)`.
const PROBE_PAYLOAD: &str = "hello";

/// Same cap as Python's `ThreadPoolExecutor(max_workers=10)`.
const MAX_CONCURRENCY: usize = 10;

/// Cancel-trigger policy for one scan run. `FirstVuln` (default) cuts
/// the per-route fan-out short as soon as any vector lands as confirmed
/// vulnerable (reflection in a 2xx response — see [`classify`]); `Never`
/// runs every active vector to completion regardless. Connection
/// errors, 3xx, 4xx (including 404), and 5xx do NOT trigger cancel —
/// only the "got through" reflection case does, so the cancel signal
/// never fires on infrastructure noise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CancelMode {
    /// Cancel siblings on first confirmed reflection finding.
    #[default]
    FirstVuln,
    /// Disable cancellation; run every vector to completion.
    Never,
}

/// How a vector got cancelled. Two cases — see
/// [`VectorResult::cancelled_kind`] for the full schema contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelKind {
    /// Permit-blocked vector that was never started; cancel fired
    /// while the task was waiting for a semaphore permit. No request
    /// was sent.
    Skipped,
    /// Vector whose request was in flight when cancel fired; the
    /// future was dropped at a `select!` await point. The request may
    /// or may not have reached the server.
    InFlight,
}

impl CancelKind {
    /// Wire-format string. Stable contract — pinned by tests against
    /// the literal output. New variants MUST extend this `match` AND
    /// the [`VectorResult::cancelled_kind`] doc-comment in lockstep.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skipped => "skipped",
            Self::InFlight => "in_flight",
        }
    }
}

/// Identity of the finding that triggered route-level cancellation
/// plus the count of vectors that did not run as a result. Surfaces
/// in JSON output as the per-route `cancelled_after` block; see
/// [`RouteResult::cancelled_after`] for the locked schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelInfo {
    pub category: String,
    pub label: String,
    pub vectors_skipped: usize,
}

/// Result of one attack vector against one route.
///
/// `cancelled_kind` is `None` for vectors that completed normally
/// (request sent, classifier ran). It's `Some` only when the vector
/// was short-circuited by [`CancelMode::FirstVuln`] cancellation —
/// either skipped pre-permit or aborted in flight. See
/// [`CancelKind`] for the variant contract.
///
/// **Locked schema (JSON output).** `cancelled_kind` is rendered into
/// the per-vector JSON object as `"cancelled_kind"` (snake_case) when
/// `Some`. The string values are exactly `"skipped"` or `"in_flight"`,
/// matching [`CancelKind::as_str`]. The key is **omitted entirely**
/// when `None` so prior JSON output stays byte-equal for non-cancel
/// runs. Future cancel kinds MUST extend the `CancelKind` enum AND
/// add a bullet to that doc-comment — never add sibling keys to the
/// vector object.
///
/// On cancelled vectors: `status == 0`, `blocked == false`,
/// `note == "skipped (cancelled)"` or `"cancelled in-flight"`. These
/// rows still occupy their original index in `RouteResult::vectors`
/// so consumers see the full task set in original order — slot
/// preservation is a load-bearing contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorResult {
    pub category: String,
    pub label: String,
    pub payload: String,
    pub status: u16,
    pub blocked: bool,
    pub note: String,
    pub cancelled_kind: Option<CancelKind>,
}

/// Result of scanning one route (probe + all active vectors).
///
/// `field` is the JSON body / query key the probe step settled on; empty
/// string when the route never reached the vector dispatch stage. Carried
/// here so renderers (human + JSON) can build a faithful `curl`
/// reproducer per vector — see `scan::repro::format_curl`.
///
/// **Locked schema (JSON output).** `cancelled_after` is rendered into
/// the per-route JSON object as `"cancelled_after"` (snake_case) when
/// `Some`, with shape `{"category": String, "label": String,
/// "vectors_skipped": Number}`. The key is **omitted entirely** when
/// `None` so prior JSON output stays byte-equal for runs that did not
/// trigger cancellation. Future cancel-related metadata MUST extend
/// this struct AND update this doc-comment in lockstep — never add
/// sibling keys to the route object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteResult {
    pub method: String,
    pub path: String,
    pub reachable: bool,
    pub error: Option<String>,
    pub field: String,
    pub vectors: Vec<VectorResult>,
    pub cancelled_after: Option<CancelInfo>,
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
    /// Speculative-cancellation policy. See [`CancelMode`]. The CLI
    /// surfaces this as `--cancel-on first-vuln|never`.
    pub cancel_on: CancelMode,
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
        Err(err) => {
            // cli-test round-1 bug 9: distinguish TLS verification
            // failures from raw connection errors. When body is "" the
            // caller emits the legacy "unreachable" message; when it's
            // a "tls:*" classifier the caller emits a TLS-specific one.
            // Heuristic on the debug format of the error chain so the
            // classifier survives whichever TLS backend reqwest picked
            // (rustls vs native-tls).
            let class = classify_send_error(&err);
            (0, class.to_string())
        }
    }
}

/// Classify a reqwest send error well enough for a CLI message.
/// Returns one of:
/// * `""` — generic connection error (refused, timeout, DNS fail).
///   Caller emits "unreachable - is the server running?".
/// * `"tls:expired"` — server certificate is past `notAfter`.
/// * `"tls:self-signed"` — server cert is not signed by a trusted CA.
/// * `"tls:hostname"` — cert is valid but the SAN doesn't include the
///   requested hostname.
/// * `"tls"` — TLS error of some other shape.
pub(crate) fn classify_send_error(err: &reqwest::Error) -> &'static str {
    // Connection-level errors take precedence — a connect-refused is
    // not a TLS error even if the URL is https.
    if err.is_connect() || err.is_timeout() {
        return "";
    }
    let chain = format!("{err:?}").to_lowercase();
    // Don't mark non-TLS errors as TLS just because the URL was https.
    let mentions_tls = chain.contains("certificate")
        || chain.contains("tls")
        || chain.contains("ssl")
        || chain.contains("handshake");
    if !mentions_tls {
        return "";
    }
    // Order matters — "notvalidforname" + "expired" can both appear on
    // multi-issue certs; check the strongest signal first.
    if chain.contains("expired") {
        return "tls:expired";
    }
    if chain.contains("notvalidforname")
        || chain.contains("name doesn't match")
        || chain.contains("hostname")
    {
        return "tls:hostname";
    }
    if chain.contains("unknownissuer")
        || chain.contains("self-signed")
        || chain.contains("self signed")
        || chain.contains("untrusted")
    {
        return "tls:self-signed";
    }
    "tls"
}

/// Format an error classifier back into a human message.
pub(crate) fn format_send_error(class: &str) -> String {
    match class {
        "tls:expired" => {
            "TLS verification failed: server certificate has expired".to_string()
        }
        "tls:hostname" => {
            "TLS verification failed: certificate hostname does not match the requested URL"
                .to_string()
        }
        "tls:self-signed" => {
            "TLS verification failed: certificate is self-signed or signed by an untrusted CA"
                .to_string()
        }
        "tls" => "TLS verification failed".to_string(),
        // Empty classifier = generic connection error (refused / timeout / DNS).
        _ => "unreachable - is the server running?".to_string(),
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
    // cli-test round-1 bug 9: send_one classifies TLS failures in the
    // body slot when status is 0. `format_send_error` turns that into a
    // user-facing message — "TLS verification failed: expired" for
    // expired.badssl.com, etc.
    let mut working_field = options.fields.first().copied().unwrap_or("q").to_string();
    let mut found_working = false;
    for field in options.fields {
        let (status, body) =
            send_one(&client, &url, method, field, PROBE_PAYLOAD, options.timeout).await;
        if status == 0 {
            result.error = Some(format_send_error(&body));
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
    let cancel_mode = options.cancel_on;

    // Cancellation channel. `watch` retains the latest value so a task
    // that subscribes after `tx.send(true)` still sees `true` on the
    // initial `rx.borrow()` check — the property `Notify::notify_waiters`
    // does not have. `Sender::send` returns `Err` only after every
    // receiver drops, which never happens while spawned tasks live;
    // ignored via `.ok()` either way (idempotent, multi-fire safe).
    let (cancel_tx, _initial_rx) = watch::channel(false);
    let cancel_tx = Arc::new(cancel_tx);

    let mut handles: Vec<tokio::task::JoinHandle<(usize, VectorResult)>> =
        Vec::with_capacity(tasks.len());
    for (idx, (cat, label, payload)) in tasks.into_iter().enumerate() {
        let sem = sem.clone();
        let client = client.clone();
        let url = url.clone();
        let field = field.clone();
        let method = method.clone();
        let cancel_tx = cancel_tx.clone();
        let mut cancel_rx = cancel_tx.subscribe();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");

            // Pre-flight check: cancel may have fired while this task
            // was permit-blocked. Skip the request entirely and emit a
            // synthetic `Skipped` row so original-task ordering is
            // preserved in the result vector.
            if *cancel_rx.borrow() {
                return (
                    idx,
                    cancelled_vector_result(cat, label, payload, CancelKind::Skipped),
                );
            }

            // `biased` so the cancel arm wins ties — when both are
            // ready in the same poll, we prefer to abort the request
            // rather than record a normal completion.
            tokio::select! {
                biased;
                _ = cancel_rx.changed() => {
                    (idx, cancelled_vector_result(cat, label, payload, CancelKind::InFlight))
                }
                (status, body) = send_one(&client, &url, &method, &field, &payload, timeout) => {
                    let cls = classify(status, &body, &payload);
                    let blocked = cls.blocked;
                    let vr = VectorResult {
                        category: cat,
                        label,
                        payload,
                        status,
                        blocked,
                        note: cls.note,
                        cancelled_kind: None,
                    };
                    // Fire cancel signal on confirmed reflection: a 2xx
                    // response that was NOT classified as blocked. This
                    // excludes connection errors (status==0), 3xx, 4xx
                    // (including 404), and 5xx — none of which are
                    // confirmed bypasses. Idempotent across concurrent
                    // hits (watch retains "true" once set).
                    if matches!(cancel_mode, CancelMode::FirstVuln)
                        && !blocked
                        && (200..300).contains(&status)
                    {
                        let _ = cancel_tx.send(true);
                    }
                    (idx, vr)
                }
            }
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

    // Identify the cancellation trigger by walking the original-order
    // slots and picking the first vulnerable finding. Race-free even
    // if multiple tasks completed with vuln before the watch propagated:
    // the lowest-indexed one wins, which is deterministic on re-run.
    if matches!(cancel_mode, CancelMode::FirstVuln) {
        let skipped = result
            .vectors
            .iter()
            .filter(|v| v.cancelled_kind.is_some())
            .count();
        if skipped > 0 {
            if let Some(trigger) = result.vectors.iter().find(|v| {
                v.cancelled_kind.is_none() && !v.blocked && (200..300).contains(&v.status)
            }) {
                result.cancelled_after = Some(CancelInfo {
                    category: trigger.category.clone(),
                    label: trigger.label.clone(),
                    vectors_skipped: skipped,
                });
            }
        }
    }

    result
}

/// Build a synthetic `VectorResult` for a cancellation-short-circuited
/// vector. Status zeroed (no request reached the wire reliably);
/// `blocked` is `false` because we did NOT confirm the server blocks
/// this payload — the row is a placeholder that preserves task order
/// without claiming a fact we never tested.
fn cancelled_vector_result(
    category: String,
    label: String,
    payload: String,
    kind: CancelKind,
) -> VectorResult {
    let note = match kind {
        CancelKind::Skipped => "skipped (cancelled)".into(),
        CancelKind::InFlight => "cancelled in-flight".into(),
    };
    VectorResult {
        category,
        label,
        payload,
        status: 0,
        blocked: false,
        note,
        cancelled_kind: Some(kind),
    }
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
        assert!(
            body.is_empty(),
            "closed-port error must NOT be classified as TLS (bug 9 \
             regression). Connection-level errors return empty body \
             so the caller emits the legacy 'unreachable' message."
        );
    }

    #[test]
    fn format_send_error_translates_classifiers_to_human_strings() {
        // cli-test round-1 bug 9: each TLS classifier maps to a
        // specific user-facing message. Pin the strings so a wording
        // change doesn't accidentally regress the differentiation.
        assert!(format_send_error("tls:expired").contains("expired"));
        assert!(
            format_send_error("tls:hostname").to_lowercase().contains("hostname"),
            "hostname classifier must surface the hostname-mismatch case"
        );
        assert!(
            format_send_error("tls:self-signed")
                .to_lowercase()
                .contains("self-signed")
                || format_send_error("tls:self-signed")
                    .to_lowercase()
                    .contains("untrusted")
        );
        // Generic TLS — still a TLS message, not "unreachable".
        let generic_tls = format_send_error("tls");
        assert!(
            generic_tls.contains("TLS"),
            "generic tls classifier must still produce a TLS-specific message: {generic_tls}"
        );
        // Empty classifier = generic connection error -> legacy message.
        assert_eq!(
            format_send_error(""),
            "unreachable - is the server running?"
        );
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
            cancel_on: CancelMode::FirstVuln,
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
            cancel_on: CancelMode::FirstVuln,
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
            cancel_on: CancelMode::FirstVuln,
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
            cancel_on: CancelMode::FirstVuln,
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
            cancel_on: CancelMode::FirstVuln,
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
            cancel_on: CancelMode::FirstVuln,
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty(), "expected at least one request");
        for req in &captured {
            assert!(
                !req.headers.contains_key("authorization"),
                "no-auth runs must NOT send an Authorization header; got: {req:?}"
            );
            assert!(
                !req.headers.contains_key("cookie"),
                "no-auth runs must NOT send a Cookie header; got: {req:?}"
            );
        }
    }

    #[tokio::test]
    async fn scan_route_with_cookie_sends_cookie_header_verbatim() {
        use crate::scan::test_server::{MockResponse, MockServer};

        let server = MockServer::start().await;
        server.on("POST", "/api/test", |_req| MockResponse::ok("{}"));

        // Multi-cookie semicolon form must round-trip on the wire
        // exactly as the user pasted it — no parsing, no reordering.
        let cookie = "session=abc; csrf=xyz; flavor=chocolate";
        let auth = AuthConfig::with_cookie(cookie).unwrap();
        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: Some(&auth),
            cancel_on: CancelMode::FirstVuln,
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty(), "expected at least one request");
        for req in &captured {
            assert_eq!(
                req.headers.get("cookie").map(String::as_str),
                Some(cookie),
                "every probe + vector request must carry the cookie verbatim; got: {req:?}"
            );
            assert!(
                !req.headers.contains_key("authorization"),
                "cookie-only run must NOT carry Authorization; got: {req:?}"
            );
        }
    }

    #[tokio::test]
    async fn scan_route_with_bearer_and_cookie_sends_both_headers() {
        // Composition test: per session direction, assert presence and
        // per-header value equality independently. HTTP treats headers
        // as orderless, HeaderMap iteration order is not stable —
        // never compare full sequences.
        use crate::scan::test_server::{MockResponse, MockServer};

        let server = MockServer::start().await;
        server.on("POST", "/api/test", |_req| MockResponse::ok("{}"));

        let auth = AuthConfig {
            bearer: Some("test-bearer-token-xyz".into()),
            cookie: Some("session=abc; csrf=xyz".into()),
            ..Default::default()
        };
        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: Some(&auth),
            cancel_on: CancelMode::FirstVuln,
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty(), "expected at least one request");
        for req in &captured {
            // Presence — independent checks per header.
            assert!(
                req.headers.contains_key("authorization"),
                "missing authorization header; got: {req:?}"
            );
            assert!(
                req.headers.contains_key("cookie"),
                "missing cookie header; got: {req:?}"
            );
            // Value equality — per-header, no order assumptions.
            assert_eq!(
                req.headers.get("authorization").map(String::as_str),
                Some("Bearer test-bearer-token-xyz")
            );
            assert_eq!(
                req.headers.get("cookie").map(String::as_str),
                Some("session=abc; csrf=xyz")
            );
        }
    }

    #[tokio::test]
    async fn scan_route_threads_csrf_header_on_every_request_when_set() {
        // Load-bearing contract: when AuthConfig.csrf is populated, the
        // CSRF token rides as a request header on EVERY request — the
        // probe step PLUS every vector dispatch. Same shape as the
        // bearer / cookie threading tests above.
        use crate::scan::csrf::CsrfState;
        use crate::scan::test_server::{MockResponse, MockServer};

        let server = MockServer::start().await;
        server.on("POST", "/api/test", |_req| MockResponse::ok("{}"));

        let auth = AuthConfig {
            csrf: Some(CsrfState {
                token: "csrf-tok-arcis-test-7e1f4d".into(),
                thread_header: "X-CSRF-Token".into(),
            }),
            ..Default::default()
        };
        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: Some(&auth),
            cancel_on: CancelMode::FirstVuln,
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty(), "expected at least one request");
        for req in &captured {
            assert_eq!(
                req.headers.get("x-csrf-token").map(String::as_str),
                Some("csrf-tok-arcis-test-7e1f4d"),
                "every probe + vector request must carry the CSRF header; got: {req:?}"
            );
        }
    }

    #[tokio::test]
    async fn scan_route_default_csrf_header_is_x_csrf_token() {
        // Pin the default thread-header NAME at the probe layer too,
        // not just at the unit-test layer. `DEFAULT_THREAD_HEADER`
        // resolves to `X-CSRF-Token`; the Express csurf middleware
        // default + the X-XSRF-TOKEN/Laravel-sanctum reference axis
        // assume that exact name. Renaming would break the integration
        // without obvious test failure unless this is pinned.
        use crate::scan::csrf::{CsrfState, DEFAULT_THREAD_HEADER};
        use crate::scan::test_server::{MockResponse, MockServer};

        assert_eq!(DEFAULT_THREAD_HEADER, "X-CSRF-Token");

        let server = MockServer::start().await;
        server.on("POST", "/api/test", |_req| MockResponse::ok("{}"));

        let auth = AuthConfig {
            csrf: Some(CsrfState {
                token: "csrf-default-name-test".into(),
                thread_header: DEFAULT_THREAD_HEADER.into(),
            }),
            ..Default::default()
        };
        let cats = vec!["xss".to_string()];
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: Some(&cats),
            thorough: false,
            auth: Some(&auth),
            cancel_on: CancelMode::FirstVuln,
        };
        let _ = scan_route(&server.url(), "POST", "/api/test", &opts).await;

        let captured = server.requests();
        assert!(!captured.is_empty());
        for req in &captured {
            assert!(
                req.headers.contains_key("x-csrf-token"),
                "default CSRF header must be `X-CSRF-Token`; got: {req:?}"
            );
        }
    }

    // -------- speculative-cancellation tests --------

    #[test]
    fn cancel_kind_as_str_pins_wire_format() {
        // The `as_str` strings are the JSON wire format. Pinned here so
        // a refactor that renames a variant doesn't silently break the
        // documented schema downstream consumers depend on.
        assert_eq!(CancelKind::Skipped.as_str(), "skipped");
        assert_eq!(CancelKind::InFlight.as_str(), "in_flight");
    }

    #[test]
    fn cancel_mode_default_is_first_vuln() {
        // Default-on cancellation is the locked policy (item 9). If
        // someone flips this default, every existing call site that
        // omits the field changes behaviour silently — pin it.
        assert_eq!(CancelMode::default(), CancelMode::FirstVuln);
    }

    /// Mock that reflects the request body verbatim in its response so
    /// the classifier sees the payload and rules `reflected (200)` —
    /// the only classifier outcome that triggers cancellation. Adds a
    /// configurable per-request delay to model slow vector probes.
    async fn spawn_reflecting_mock(delay: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16_384];
                    let n = match sock.read(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    // Echo the request back as the response body so any
                    // payload contained in the request is "reflected".
                    let body = req;
                    tokio::time::sleep(delay).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn cancel_fires_on_first_vuln_in_thorough_mode_with_wall_clock_budget() {
        // Reflecting server with an 800ms per-request delay — so a scan
        // that fires every vector serially would take many seconds.
        // With cancellation on, the first reflected vuln (~800ms,
        // limited by the slowest in the first concurrency batch) fires
        // cancel, and the remaining vectors short-circuit. Budget is
        // a loose 2.0s ceiling that cleanly separates "cancelled"
        // (~800ms) from "all 27 ran" (~3 batches × 800ms ≈ 2.4s+).
        // Loose enough to survive Windows-under-load jitter.
        let addr = spawn_reflecting_mock(Duration::from_millis(800)).await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(5),
            categories: None,
            thorough: true,
            auth: None,
            cancel_on: CancelMode::FirstVuln,
        };

        let start = std::time::Instant::now();
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        let elapsed = start.elapsed();

        assert!(rr.reachable);
        assert!(rr.error.is_none());
        // Cancellation must have fired — the reflecting server makes
        // every payload classify as vulnerable.
        let info = rr.cancelled_after.expect("cancel should have triggered");
        assert!(info.vectors_skipped > 0, "expected non-zero skipped count");
        // Wall-clock: well under "all 27 vectors ran" budget.
        assert!(
            elapsed < Duration::from_secs(2),
            "cancellation did not save wall-clock time: elapsed={elapsed:?}"
        );

        // At least one vector must carry a cancellation marker so JSON
        // consumers can see what was short-circuited.
        let cancelled_count = rr
            .vectors
            .iter()
            .filter(|v| v.cancelled_kind.is_some())
            .count();
        assert!(cancelled_count > 0, "no vectors were marked cancelled");
        assert_eq!(cancelled_count, info.vectors_skipped);
    }

    #[tokio::test]
    async fn cancel_disabled_runs_all_vectors_even_when_vulnerable() {
        // Same reflecting server but with --cancel-on never. Every
        // vector must run to completion — full coverage path.
        let addr = spawn_reflecting_mock(Duration::from_millis(20)).await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(5),
            categories: None,
            thorough: true,
            auth: None,
            cancel_on: CancelMode::Never,
        };

        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        assert!(rr.reachable);
        assert!(
            rr.cancelled_after.is_none(),
            "Never mode must not produce cancelled_after; got: {:?}",
            rr.cancelled_after
        );
        // No vector may carry a cancellation marker.
        let cancelled = rr
            .vectors
            .iter()
            .filter(|v| v.cancelled_kind.is_some())
            .count();
        assert_eq!(cancelled, 0, "Never mode left {cancelled} cancelled rows");
        // Thorough = 27 vectors total (4+4+3+4+4+4+2+2). All must be
        // present, in original task order.
        assert_eq!(rr.vectors.len(), 27);
    }

    #[tokio::test]
    async fn cancelled_vectors_emit_synthetic_rows_in_original_task_order() {
        // Run thorough mode against a reflecting server with a longish
        // delay (so the concurrency window leaves clear skipped rows).
        // Then assert: every result slot is filled (no flatten loss),
        // categories appear in the original order, and every cancelled
        // row keeps its category/label/payload from the task descriptor.
        let addr = spawn_reflecting_mock(Duration::from_millis(400)).await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(5),
            categories: None,
            thorough: true,
            auth: None,
            cancel_on: CancelMode::FirstVuln,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;

        // Thorough = 27 task descriptors. Every slot must be present —
        // even cancelled ones. This pins the "skipped emit synthetic"
        // contract.
        assert_eq!(rr.vectors.len(), 27);

        // Original-task-order categories — same expected sequence as
        // `scan_route_preserves_task_order_under_concurrency`. The
        // synthetic cancelled rows must keep their category from the
        // task descriptor, not collapse to a placeholder.
        let first_per_category: Vec<&str> = {
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for v in &rr.vectors {
                if seen.insert(v.category.clone()) {
                    out.push(v.category.as_str());
                }
            }
            out
        };
        assert_eq!(
            first_per_category,
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

        // Cancelled rows: status 0, blocked false, note matches one of
        // the two locked strings, payload non-empty.
        for v in &rr.vectors {
            if let Some(kind) = v.cancelled_kind {
                assert_eq!(v.status, 0);
                assert!(!v.blocked);
                assert!(!v.payload.is_empty());
                match kind {
                    CancelKind::Skipped => assert_eq!(v.note, "skipped (cancelled)"),
                    CancelKind::InFlight => assert_eq!(v.note, "cancelled in-flight"),
                }
            }
        }
    }

    #[tokio::test]
    async fn cancel_does_not_fire_when_all_vectors_blocked() {
        // 400 to every payload — nothing classifies as vulnerable, no
        // cancel fires. Pin the happy-path no-cancel contract.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let addr = spawn_mock(move |_req: &str| {
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                (200, "ok".into())
            } else {
                (400, "blocked".into())
            }
        })
        .await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: None,
            thorough: false,
            auth: None,
            cancel_on: CancelMode::FirstVuln,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        assert!(rr.reachable);
        assert!(rr.cancelled_after.is_none());
        let cancelled = rr
            .vectors
            .iter()
            .filter(|v| v.cancelled_kind.is_some())
            .count();
        assert_eq!(cancelled, 0);
    }

    #[tokio::test]
    async fn cancel_does_not_fire_on_404_or_500_responses() {
        // 200/empty for the probe so the route is reachable, then 500
        // for every payload. 5xx is `!blocked` per classifier (note:
        // "status 500") but is NOT a confirmed bypass — the cancel
        // trigger is restricted to the 2xx-reflection case to avoid
        // firing on infrastructure noise.
        let counter = Arc::new(AtomicUsize::new(0));
        let c = counter.clone();
        let addr = spawn_mock(move |_req: &str| {
            let n = c.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                (200, String::new())
            } else {
                (500, "boom".into())
            }
        })
        .await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(2),
            categories: None,
            thorough: false,
            auth: None,
            cancel_on: CancelMode::FirstVuln,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        assert!(rr.reachable);
        assert!(
            rr.cancelled_after.is_none(),
            "5xx must not trigger cancel; got: {:?}",
            rr.cancelled_after
        );
        // Every vector ran to completion with the 500 classification.
        for v in &rr.vectors {
            assert!(v.cancelled_kind.is_none());
            assert_eq!(v.status, 500);
            assert!(!v.blocked);
            assert_eq!(v.note, "status 500");
        }
    }

    #[tokio::test]
    async fn cancel_info_identifies_first_vulnerable_finding_by_original_order() {
        // The `cancelled_after` trigger is the LOWEST-indexed
        // vulnerable finding, regardless of which task fired the
        // watch first. With original task order = [XSS, SQL, ...],
        // XSS is index 0. Reflecting server makes XSS vulnerable
        // (and every other vector too, but the trigger reports the
        // first by index). Pins the deterministic-rerun contract.
        let addr = spawn_reflecting_mock(Duration::from_millis(50)).await;
        let opts = ScanOptions {
            fields: &["q"],
            timeout: Duration::from_secs(5),
            categories: None,
            thorough: false,
            auth: None,
            cancel_on: CancelMode::FirstVuln,
        };
        let rr = scan_route(&format!("http://{addr}"), "POST", "/api/x", &opts).await;
        let info = rr.cancelled_after.expect("cancel should have fired");
        // First task descriptor in the table is XSS primary vector;
        // its label is "script tag" (see payloads.rs).
        assert_eq!(info.category, "XSS");
        assert_eq!(info.label, "script tag");
        assert!(info.vectors_skipped > 0);
    }
}
