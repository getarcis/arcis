//! In-process mock HTTP server for scan-module unit tests.
//!
//! Lives alongside `probe::spawn_mock` (single-responder, fixed headers)
//! because Phase B items 5/6/9 need:
//!
//! * Per-route routing — login flow expects different responses on
//!   `POST /auth/login` vs `GET /api/secret`.
//! * Custom response headers — `Set-Cookie`, repeatable for multi-cookie
//!   logins. Headers are stored as `Vec<(String, String)>` so duplicate
//!   names round-trip as separate header lines on the wire.
//! * Request capture — assertion-side reads of every header/body that
//!   reached the server, in arrival order.
//! * Sequence-aware closures — handlers can capture their own
//!   `Arc<Mutex<State>>` and vary response on subsequent calls. No
//!   bespoke server-state API needed.
//!
//! Hand-rolled HTTP/1.1 (no `axum`/`wiremock`) to stay zero-dep — same
//! pattern as `probe::spawn_mock` plus the surface above. Listener binds
//! `127.0.0.1:0`; the ephemeral port is exposed via [`MockServer::url`].
//!
//! `pub(crate)` and gated `#[cfg(test)]` at the include site, so any
//! scan submodule's `#[cfg(test)] mod tests` can reach it (today
//! `probe`, soon `auth`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One request as observed by the server. `headers` keys are lowercased
/// (last-write-wins on duplicates — fine for assertion-side reads in
/// tests). `path` is the request-target verbatim, query string included.
#[derive(Debug, Clone, Default)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// Server response built by a handler closure. Headers are an ordered
/// `Vec` (not a map) so duplicates such as multi-cookie `Set-Cookie:`
/// emit multiple lines on the wire in registration order.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl MockResponse {
    /// 200 OK with the given body. No `Content-Type` set — caller adds
    /// via [`MockResponse::with_header`] or uses [`MockResponse::json`].
    pub fn ok(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// 200 OK with `Content-Type: application/json` set automatically.
    /// The body is sent verbatim — caller is responsible for emitting
    /// valid JSON. The `Content-Type` header IS part of this method's
    /// contract; tests assert it on the wire so it can't quietly drift.
    pub fn json(body: impl Into<String>) -> Self {
        Self::ok(body).with_header("Content-Type", "application/json")
    }

    pub fn status(mut self, code: u16) -> Self {
        self.status = code;
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Sugar for `with_header("Set-Cookie", cookie)`. Repeatable —
    /// chain to emit multiple cookies on one response.
    pub fn set_cookie(self, cookie: &str) -> Self {
        self.with_header("Set-Cookie", cookie)
    }
}

type Handler = Arc<dyn Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static>;

struct Route {
    method: String,
    path: String,
    handler: Handler,
}

struct MockState {
    routes: Mutex<Vec<Route>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

/// Mock server bound to an ephemeral port on `127.0.0.1`. The accept
/// loop is implicit on the surrounding tokio runtime; drop the instance
/// when the test ends.
pub struct MockServer {
    addr: SocketAddr,
    state: Arc<MockState>,
}

impl MockServer {
    /// Bind `127.0.0.1:0` and spawn the accept loop. Returns once the
    /// listener is ready.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener bind");
        let addr = listener.local_addr().expect("test listener local_addr");
        let state = Arc::new(MockState {
            routes: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        });
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                let st = st.clone();
                tokio::spawn(async move {
                    handle_connection(sock, st).await;
                });
            }
        });
        Self { addr, state }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Register a handler for `(method, path)`. Method match is
    /// case-insensitive; path match is exact (no pattern syntax — tests
    /// pass concrete paths). First registered handler that matches wins.
    pub fn on<F>(&self, method: &str, path: &str, handler: F)
    where
        F: Fn(&RecordedRequest) -> MockResponse + Send + Sync + 'static,
    {
        self.state.routes.lock().unwrap().push(Route {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
            handler: Arc::new(handler),
        });
    }

    /// Snapshot of every request received so far, in arrival order.
    /// Cloned out so the caller doesn't hold the internal mutex.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.requests.lock().unwrap().clone()
    }
}

async fn handle_connection(mut sock: tokio::net::TcpStream, state: Arc<MockState>) {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    // Read until end of headers. Bound at 64 KB to keep test surface
    // bounded — production HTTP allows more, but tests don't.
    let header_end = loop {
        let n = match sock.read(&mut tmp).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = find_double_crlf(&buf) {
            break idx;
        }
        if buf.len() > 65_536 {
            return;
        }
    };

    let head = match std::str::from_utf8(&buf[..header_end]) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut lines = head.split("\r\n");
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    // HTTP version (`parts.next()` third field) ignored — tests don't
    // exercise it.

    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let body_start = header_end + 4; // skip the CRLFCRLF
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    while buf.len() < body_start + content_length {
        let n = match sock.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return,
        };
        buf.extend_from_slice(&tmp[..n]);
    }

    let body_end = (body_start + content_length).min(buf.len());
    let body = String::from_utf8_lossy(&buf[body_start..body_end]).to_string();

    let request = RecordedRequest {
        method: method.clone(),
        path: path.clone(),
        headers,
        body,
    };

    state.requests.lock().unwrap().push(request.clone());

    let response = {
        let routes = state.routes.lock().unwrap();
        let matched = routes
            .iter()
            .find(|r| r.method.eq_ignore_ascii_case(&method) && path_matches(&r.path, &path));
        match matched {
            Some(route) => {
                let h = route.handler.clone();
                drop(routes);
                h(&request)
            }
            None => MockResponse {
                status: 404,
                headers: Vec::new(),
                body: String::new(),
            },
        }
    };

    let _ = write_response(&mut sock, &response).await;
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn path_matches(registered: &str, actual: &str) -> bool {
    let actual_path = actual.split_once('?').map(|(p, _)| p).unwrap_or(actual);
    registered == actual_path
}

async fn write_response(
    sock: &mut tokio::net::TcpStream,
    resp: &MockResponse,
) -> std::io::Result<()> {
    let reason = match resp.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, reason);
    let mut has_content_length = false;
    for (name, value) in &resp.headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if !has_content_length {
        out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    sock.write_all(out.as_bytes()).await?;
    sock.write_all(resp.body.as_bytes()).await?;
    sock.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn raw_request(addr: SocketAddr, request: &str) -> String {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        sock.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        sock.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn mock_server_url_returns_loopback_with_ephemeral_port() {
        let server = MockServer::start().await;
        let url = server.url();
        assert!(url.starts_with("http://127.0.0.1:"), "url was: {url}");
        assert_eq!(url, format!("http://{}", server.addr()));
    }

    #[tokio::test]
    async fn mock_server_returns_404_for_unregistered_route() {
        let server = MockServer::start().await;
        let response = raw_request(server.addr(), "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
        let captured = server.requests();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].path, "/nope");
    }

    #[tokio::test]
    async fn mock_server_get_returns_configured_response_with_json_content_type() {
        let server = MockServer::start().await;
        server.on("GET", "/api/me", |_req| MockResponse::json(r#"{"id":42}"#));
        let response = raw_request(server.addr(), "GET /api/me HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        // `MockResponse::json` MUST emit Content-Type — explicit assertion
        // so this contract doesn't quietly drift later.
        assert!(
            response
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "json() must emit Content-Type: application/json header; got:\n{response}"
        );
        assert!(response.ends_with(r#"{"id":42}"#));
    }

    #[tokio::test]
    async fn mock_server_post_captures_body_and_returns_set_cookie() {
        let server = MockServer::start().await;
        server.on("POST", "/auth/login", |req| {
            assert!(req.body.contains("user=admin"));
            MockResponse::ok("")
                .set_cookie("session=abc123; HttpOnly")
                .set_cookie("flavor=chocolate")
        });
        let body = "user=admin&pass=hunter2";
        let request = format!(
            "POST /auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n{body}",
            body.len()
        );
        let response = raw_request(server.addr(), &request).await;

        // Multi-cookie wire emission — both Set-Cookie headers must
        // appear as separate lines, in registration order. This pins
        // the `Vec<(String, String)>` preservation contract.
        let cookie_lines: Vec<&str> = response
            .lines()
            .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
            .collect();
        assert_eq!(cookie_lines.len(), 2, "got: {response}");
        assert!(cookie_lines[0].contains("session=abc123"));
        assert!(cookie_lines[1].contains("flavor=chocolate"));

        let captured = server.requests();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].method, "POST");
        assert_eq!(captured[0].path, "/auth/login");
        assert_eq!(captured[0].body, body);
    }

    #[tokio::test]
    async fn mock_server_records_multiple_requests_in_order() {
        let server = MockServer::start().await;
        server.on("GET", "/a", |_| MockResponse::ok("A"));
        server.on("GET", "/b", |_| MockResponse::ok("B"));
        let _ = raw_request(server.addr(), "GET /a HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let _ = raw_request(server.addr(), "GET /b HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let _ = raw_request(server.addr(), "GET /a?q=1 HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let captured = server.requests();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].path, "/a");
        assert_eq!(captured[1].path, "/b");
        assert_eq!(captured[2].path, "/a?q=1");
    }

    #[tokio::test]
    async fn mock_server_sequence_aware_handler_uses_captured_state() {
        // Closure captures `Arc<Mutex<...>>` and varies response between
        // calls. Proves that the auth login-then-cookie flow can be
        // modeled without a bespoke server-state API.
        let server = MockServer::start().await;
        let logged_in = Arc::new(Mutex::new(false));

        let li = logged_in.clone();
        server.on("POST", "/auth/login", move |_req| {
            *li.lock().unwrap() = true;
            MockResponse::ok("").set_cookie("session=abc123")
        });

        let li = logged_in.clone();
        server.on("GET", "/api/secret", move |req| {
            if !*li.lock().unwrap() {
                return MockResponse::ok("").status(401);
            }
            let cookie = req.headers.get("cookie").cloned().unwrap_or_default();
            MockResponse::ok(format!("hello, cookie={cookie}"))
        });

        // First call without auth: handler returns 401.
        let r1 = raw_request(server.addr(), "GET /api/secret HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(r1.starts_with("HTTP/1.1 401"));

        // Login flips the captured state.
        let _ = raw_request(
            server.addr(),
            "POST /auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;

        // Now allowed; cookie header is read by the handler.
        let r2 = raw_request(
            server.addr(),
            "GET /api/secret HTTP/1.1\r\nHost: x\r\nCookie: session=abc123\r\n\r\n",
        )
        .await;
        assert!(r2.starts_with("HTTP/1.1 200"));
        assert!(r2.contains("hello, cookie=session=abc123"));
    }
}
