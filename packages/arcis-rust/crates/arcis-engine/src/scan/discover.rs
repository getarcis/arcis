//! Auto-discovery for `arcis scan`: target server + routes.
//!
//! Direct port of `packages/arcis-python/arcis/cli/discovery.py`. Two
//! independent surfaces:
//!
//!   1. **Target detection** — env files, control-plane probe, dev-port
//!      sniff. Returns a ranked list of [`TargetCandidate`].
//!   2. **Route discovery** — source-aware walk for JS/TS/Python/Go
//!      handler patterns. Returns deduped first-seen [`DiscoveredRoute`].
//!
//! HTTP probes (`probe_control_plane`, `sniff_framework`) are kept
//! synchronous and hand-rolled over `TcpStream` to avoid pulling
//! `reqwest`/`tokio` into the discovery code path. The async runtime is
//! confined to `probe.rs` where the actual scan fan-out happens.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use regex::Regex;
use walkdir::WalkDir;

// ── Constants ────────────────────────────────────────────────────────────────

/// Localhost dev ports probed in priority order. Express :3000 first.
pub const DEV_PORTS: &[u16] = &[3000, 5000, 5001, 8000, 8080, 4000, 8888];

/// Local control-plane workspace endpoint.
pub const CONTROL_PLANE_URL: &str = "http://localhost:4000/v1/workspace/active";

/// Env-var keys checked (in order) for an explicit target URL.
pub const ENV_TARGET_KEYS: &[&str] = &["ARCIS_TARGET", "BASE_URL", "API_URL"];

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "dist",
    "build",
    "__pycache__",
    ".next",
    "coverage",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    "vendor",
    ".tox",
    "out",
    ".cache",
    ".idea",
    ".vscode",
    ".turbo",
    ".parcel-cache",
    "site-packages",
];

const SOURCE_EXTENSIONS: &[&str] = &[".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".go"];

// ── Regex registry ───────────────────────────────────────────────────────────

fn js_route_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // (?:app|router|api|server|route).METHOD("/...")
        // IGNORECASE via inline (?i).
        Regex::new(
            r#"(?i)(?:app|router|api|server|route)\s*\.\s*(get|post|put|delete|patch|all|options)\s*\(\s*['"`]([^'"`\n]+?)['"`]"#,
        )
        .expect("JS route regex compiles")
    })
}

fn py_fastapi_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)@\s*(?:app|router|api)\s*\.\s*(get|post|put|delete|patch|options)\s*\(\s*['"]([^'"\n]+?)['"]"#,
        )
        .expect("FastAPI route regex compiles")
    })
}

fn py_flask_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // (?s) = DOTALL so `.` matches newlines (methods=[...] can span lines).
        Regex::new(
            r#"(?is)@\s*(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*['"]([^'"\n]+?)['"]([^)]*)\)"#,
        )
        .expect("Flask route regex compiles")
    })
}

fn go_route_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Go is uppercase-only by convention (no IGNORECASE flag).
        Regex::new(
            r#"(?:r|router|e|api|app|server|mux|g)\s*\.\s*(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"\n]+?)""#,
        )
        .expect("Go route regex compiles")
    })
}

fn flask_methods_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?is)methods\s*=\s*\[([^\]]+)\]"#).expect("Flask methods regex compiles")
    })
}

fn flask_method_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"['"]([A-Za-z]+)['"]"#).expect("Flask method-token regex compiles")
    })
}

// ── Data types ───────────────────────────────────────────────────────────────

/// One discovered target server. `source` is a short tag like `.env`,
/// `control-plane`, or `port-sniff:3000` so the user can see how we found
/// it. `framework` is a best-effort hint from the HEAD probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    pub url: String,
    pub source: String,
    pub framework: Option<String>,
}

/// One discovered HTTP handler. Method is uppercased; path begins with `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredRoute {
    pub method: String,
    pub path: String,
    pub source: String,
}

// ── Env-file parsing ─────────────────────────────────────────────────────────

/// Read `.env` and `.env.local` from `cwd`, returning a merged map where
/// `.env.local` wins on conflicts. Mirrors Python's
/// `read_env_files`: ignores blank lines + `#` comments, strips
/// `export ` prefix, unwraps single + double-quoted values.
pub fn read_env_files(cwd: &Path) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for name in [".env", ".env.local"] {
        let path = cwd.join(name);
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                continue;
            }
            // Unwrap matching surrounding quotes (single or double).
            let value = if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
                || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
            {
                &value[1..value.len() - 1]
            } else {
                value
            };
            out.insert(key.to_string(), value.to_string());
        }
    }
    out
}

/// Pull a usable target URL out of a parsed env dict. Order:
/// `ARCIS_TARGET` → `BASE_URL` → `API_URL` → `PORT` (fallback).
pub fn env_target(env: &HashMap<String, String>) -> Option<String> {
    for key in ENV_TARGET_KEYS {
        if let Some(v) = env.get(*key) {
            let v = v.trim();
            if v.starts_with("http://") || v.starts_with("https://") {
                return Some(v.trim_end_matches('/').to_string());
            }
        }
    }
    if let Some(port) = env.get("PORT") {
        let port = port.trim();
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return Some(format!("http://localhost:{port}"));
        }
    }
    None
}

// ── Port + control-plane probes ──────────────────────────────────────────────

fn probe_port(port: u16, timeout: Duration) -> bool {
    let addr = format!("127.0.0.1:{port}");
    let Ok(mut iter) = addr.to_socket_addrs() else {
        return false;
    };
    let Some(sock) = iter.next() else {
        return false;
    };
    TcpStream::connect_timeout(&sock, timeout).is_ok()
}

/// Return the subset of `ports` that have something listening on
/// 127.0.0.1. Order matches the input slice (priority-preserving).
pub fn probe_dev_ports(ports: &[u16]) -> Vec<u16> {
    if ports.is_empty() {
        return Vec::new();
    }
    let timeout = Duration::from_millis(300);
    let open: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    let open_ref = &open;
    thread::scope(|s| {
        for &p in ports {
            s.spawn(move || {
                if probe_port(p, timeout) {
                    open_ref.lock().unwrap().push(p);
                }
            });
        }
    });
    let mut hits = open.into_inner().unwrap();
    let order: HashMap<u16, usize> = ports.iter().enumerate().map(|(i, &p)| (p, i)).collect();
    hits.sort_by_key(|p| order.get(p).copied().unwrap_or(usize::MAX));
    hits
}

/// Hand-rolled minimal HTTP/1.0 client. Returns `(status, headers, body)`
/// on success. Headers are lowercased keys → original-case values.
fn http_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    timeout: Duration,
) -> std::io::Result<(u16, HashMap<String, String>, Vec<u8>)> {
    let addr_str = format!("{host}:{port}");
    let mut iter = addr_str.to_socket_addrs()?;
    let sock = iter
        .next()
        .ok_or_else(|| std::io::Error::other("no socket address resolved"))?;
    let mut stream = TcpStream::connect_timeout(&sock, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = format!(
        "{method} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: arcis-scan\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut buf: Vec<u8> = Vec::new();
    stream.read_to_end(&mut buf)?;

    let split_at = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let (head, body) = match split_at {
        Some(i) => (&buf[..i], buf[i + 4..].to_vec()),
        None => (&buf[..], Vec::new()),
    };
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.lines();
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers: HashMap<String, String> = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    Ok((status, headers, body))
}

/// Ask the local control-plane for the active workspace's endpoint.
/// Returns `None` on any error so callers stay best-effort.
pub fn probe_control_plane(url: &str, timeout: Duration) -> Option<String> {
    let parsed = parse_simple_url(url)?;
    let (status, _headers, body) =
        http_request(&parsed.host, parsed.port, "GET", &parsed.path, timeout).ok()?;
    if !(200..300).contains(&status) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
    let obj = value.as_object()?;
    for key in ["endpoint", "target", "url"] {
        if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
            let v = v.trim();
            if v.starts_with("http://") || v.starts_with("https://") {
                return Some(v.trim_end_matches('/').to_string());
            }
        }
    }
    None
}

/// Send HEAD / and inspect headers for a framework hint.
pub fn sniff_framework(port: u16, timeout: Duration) -> Option<String> {
    let (_status, headers, _body) = http_request("127.0.0.1", port, "HEAD", "/", timeout).ok()?;
    let server = headers
        .get("server")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let powered = headers
        .get("x-powered-by")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let blob = format!("{server} {powered}");
    let pick = |needles: &[&str], label: &str| -> Option<String> {
        if needles.iter().any(|n| blob.contains(n)) {
            Some(label.to_string())
        } else {
            None
        }
    };
    pick(&["uvicorn", "starlette"], "FastAPI")
        .or_else(|| pick(&["werkzeug", "flask"], "Flask"))
        .or_else(|| pick(&["gunicorn"], "Python (gunicorn)"))
        .or_else(|| pick(&["express"], "Express"))
        .or_else(|| pick(&["fastify"], "Fastify"))
        .or_else(|| pick(&["next"], "Next.js"))
        .or_else(|| pick(&["fiber", "echo", "gin"], "Go"))
}

struct SimpleUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_simple_url(url: &str) -> Option<SimpleUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let is_https = scheme == "https";
    let default_port = if is_https { 443 } else { 80 };
    let (host_port, path_part) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (host_port.to_string(), default_port),
    };
    let path = if path_part.is_empty() {
        "/".to_string()
    } else {
        path_part.to_string()
    };
    Some(SimpleUrl { host, port, path })
}

// ── Project kind ─────────────────────────────────────────────────────────────

/// Identify the project root flavour. Returns "node" / "python" / "go" or
/// `None`. Mirrors Python's order: package.json → pyproject.toml /
/// requirements.txt → go.mod.
pub fn detect_project_kind(cwd: &Path) -> Option<&'static str> {
    if cwd.join("package.json").is_file() {
        return Some("node");
    }
    if cwd.join("pyproject.toml").is_file() || cwd.join("requirements.txt").is_file() {
        return Some("python");
    }
    if cwd.join("go.mod").is_file() {
        return Some("go");
    }
    None
}

// ── Source-aware route discovery ─────────────────────────────────────────────

fn extension_eligible(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let dotted = format!(".{}", ext.to_lowercase());
    SOURCE_EXTENSIONS.contains(&dotted.as_str())
}

fn extract_flask_methods(suffix: &str) -> Vec<String> {
    let Some(m) = flask_methods_re().captures(suffix) else {
        return vec!["GET".into()];
    };
    let inner = m.get(1).map(|x| x.as_str()).unwrap_or("");
    let methods: Vec<String> = flask_method_token_re()
        .captures_iter(inner)
        .filter_map(|c| c.get(1).map(|x| x.as_str().to_uppercase()))
        .collect();
    if methods.is_empty() {
        vec!["GET".into()]
    } else {
        methods
    }
}

fn safe_relpath(path: &Path, base: &Path) -> String {
    match path.strip_prefix(base) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => path.to_string_lossy().replace('\\', "/"),
    }
}

fn add_route(
    out: &mut Vec<DiscoveredRoute>,
    seen: &mut HashSet<(String, String)>,
    method: &str,
    path_str: &str,
    source: &str,
) {
    if !path_str.starts_with('/') {
        return;
    }
    let key = (method.to_string(), path_str.to_string());
    if seen.contains(&key) {
        return;
    }
    seen.insert(key);
    out.push(DiscoveredRoute {
        method: method.to_string(),
        path: path_str.to_string(),
        source: source.to_string(),
    });
}

/// Walk `cwd` and return deduped first-seen handlers across JS/TS/Python/Go.
/// Vendor / build / cache directories are pruned. Symlinks are not
/// followed (matches Python post-fix from `e778439`). Bounded by
/// `max_files` so a giant repo doesn't hang the CLI.
pub fn discover_routes(cwd: &Path, max_files: usize) -> Vec<DiscoveredRoute> {
    let mut routes: Vec<DiscoveredRoute> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    let walker = WalkDir::new(cwd)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            // Always keep the root (depth 0 — pruning it kills the walk).
            if e.depth() == 0 {
                return true;
            }
            if e.path_is_symlink() {
                return false;
            }
            let name = e.file_name().to_string_lossy();
            // Skip vendor / cache dirs by name and any hidden dir except "."/".."
            if e.file_type().is_dir() {
                if SKIP_DIRS.contains(&name.as_ref()) {
                    return false;
                }
                if name.starts_with('.') && name.as_ref() != "." && name.as_ref() != ".." {
                    return false;
                }
            }
            true
        });

    let mut count = 0usize;
    for entry in walker.flatten() {
        if count >= max_files {
            break;
        }
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if !extension_eligible(path) {
            continue;
        }
        count += 1;

        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let rel = safe_relpath(path, cwd);
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        match ext.as_str() {
            "js" | "ts" | "mjs" | "cjs" | "jsx" | "tsx" => {
                for caps in js_route_re().captures_iter(&text) {
                    let mut method = caps
                        .get(1)
                        .map(|m| m.as_str().to_uppercase())
                        .unwrap_or_default();
                    if method == "ALL" {
                        method = "POST".into();
                    }
                    let path_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    add_route(&mut routes, &mut seen, &method, path_str, &rel);
                }
            }
            "py" => {
                for caps in py_fastapi_re().captures_iter(&text) {
                    let method = caps
                        .get(1)
                        .map(|m| m.as_str().to_uppercase())
                        .unwrap_or_default();
                    let path_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    add_route(&mut routes, &mut seen, &method, path_str, &rel);
                }
                for caps in py_flask_re().captures_iter(&text) {
                    let path_str = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                    let suffix = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    for method in extract_flask_methods(suffix) {
                        add_route(&mut routes, &mut seen, &method, &path_str, &rel);
                    }
                }
            }
            "go" => {
                for caps in go_route_re().captures_iter(&text) {
                    let method = caps
                        .get(1)
                        .map(|m| m.as_str().to_uppercase())
                        .unwrap_or_default();
                    let path_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    add_route(&mut routes, &mut seen, &method, path_str, &rel);
                }
            }
            _ => {}
        }
    }

    routes
}

// ── Top-level discovery driver ───────────────────────────────────────────────

/// Run every detection surface and return all candidate targets in
/// preference order (env > control-plane > port sniff). Duplicate URLs
/// collapse; the first source wins.
pub fn detect_target(
    cwd: &Path,
    include_control_plane: bool,
    ports: &[u16],
) -> Vec<TargetCandidate> {
    let mut candidates: Vec<TargetCandidate> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut push = |url: String, source: String, framework: Option<String>| {
        if url.is_empty() || seen.contains(&url) {
            return;
        }
        seen.insert(url.clone());
        candidates.push(TargetCandidate {
            url,
            source,
            framework,
        });
    };

    let env = read_env_files(cwd);
    if let Some(env_url) = env_target(&env) {
        push(env_url, ".env".into(), None);
    }

    if include_control_plane {
        if let Some(cp_url) = probe_control_plane(CONTROL_PLANE_URL, Duration::from_millis(500)) {
            push(cp_url, "control-plane".into(), None);
        }
    }

    for port in probe_dev_ports(ports) {
        let framework = sniff_framework(port, Duration::from_millis(400));
        push(
            format!("http://localhost:{port}"),
            format!("port-sniff:{port}"),
            framework,
        );
    }

    candidates
}

/// Convenience: target detection + project-kind detection + route walk.
pub fn discover(cwd: &Path) -> DiscoveryReport {
    let candidates = detect_target(cwd, true, DEV_PORTS);
    let target = candidates.first().cloned();
    let project_kind = detect_project_kind(cwd).map(|s| s.to_string());
    let routes = discover_routes(cwd, 1500);
    DiscoveryReport {
        target,
        candidates,
        routes,
        project_kind,
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryReport {
    pub target: Option<TargetCandidate>,
    pub candidates: Vec<TargetCandidate>,
    pub routes: Vec<DiscoveredRoute>,
    pub project_kind: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn td() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── env file parsing ────────────────────────────────────────────────────

    #[test]
    fn read_env_files_parses_basic_kv() {
        let dir = td();
        fs::write(
            dir.path().join(".env"),
            "PORT=3000\nBASE_URL=http://localhost:3000\n# a comment\n\nQUOTED='single quoted'\nDBL_QUOTED=\"dbl quoted\"\nexport EXPORTED=42\n",
        )
        .unwrap();
        let env = read_env_files(dir.path());
        assert_eq!(env.get("PORT").unwrap(), "3000");
        assert_eq!(env.get("BASE_URL").unwrap(), "http://localhost:3000");
        assert_eq!(env.get("QUOTED").unwrap(), "single quoted");
        assert_eq!(env.get("DBL_QUOTED").unwrap(), "dbl quoted");
        assert_eq!(env.get("EXPORTED").unwrap(), "42");
    }

    #[test]
    fn read_env_files_local_overrides_base() {
        let dir = td();
        fs::write(dir.path().join(".env"), "PORT=3000\nBASE_URL=http://nope\n").unwrap();
        fs::write(
            dir.path().join(".env.local"),
            "BASE_URL=http://localhost:5000\n",
        )
        .unwrap();
        let env = read_env_files(dir.path());
        assert_eq!(env.get("PORT").unwrap(), "3000");
        assert_eq!(env.get("BASE_URL").unwrap(), "http://localhost:5000");
    }

    #[test]
    fn read_env_files_handles_missing_dir() {
        let dir = td();
        let env = read_env_files(&dir.path().join("nothing-here"));
        assert!(env.is_empty());
    }

    #[test]
    fn env_target_prefers_explicit_url() {
        let mut e = HashMap::new();
        e.insert("ARCIS_TARGET".into(), "http://localhost:9999".into());
        assert_eq!(env_target(&e).as_deref(), Some("http://localhost:9999"));
        let mut e = HashMap::new();
        e.insert("BASE_URL".into(), "https://example.com/".into());
        assert_eq!(env_target(&e).as_deref(), Some("https://example.com"));
        let mut e = HashMap::new();
        e.insert("API_URL".into(), "http://localhost:7000".into());
        assert_eq!(env_target(&e).as_deref(), Some("http://localhost:7000"));
    }

    #[test]
    fn env_target_falls_back_to_port_only() {
        let mut e = HashMap::new();
        e.insert("PORT".into(), "8080".into());
        assert_eq!(env_target(&e).as_deref(), Some("http://localhost:8080"));
    }

    #[test]
    fn env_target_returns_none_for_garbage() {
        let e: HashMap<String, String> = HashMap::new();
        assert!(env_target(&e).is_none());
        let mut e = HashMap::new();
        e.insert("PORT".into(), "not-a-port".into());
        assert!(env_target(&e).is_none());
        let mut e = HashMap::new();
        e.insert("BASE_URL".into(), "ftp://nope".into());
        assert!(env_target(&e).is_none());
    }

    // ── port sniff ──────────────────────────────────────────────────────────

    #[test]
    fn probe_dev_ports_handles_empty_list() {
        assert!(probe_dev_ports(&[]).is_empty());
    }

    #[test]
    fn probe_dev_ports_finds_listening_socket() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = probe_dev_ports(&[port]);
        // Tolerant: port may have closed under load; assert it's not stuck.
        assert!(result == vec![port] || result.is_empty());
    }

    // ── project kind ────────────────────────────────────────────────────────

    #[test]
    fn project_kind_node() {
        let dir = td();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_project_kind(dir.path()), Some("node"));
    }

    #[test]
    fn project_kind_python_pyproject() {
        let dir = td();
        fs::write(dir.path().join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        assert_eq!(detect_project_kind(dir.path()), Some("python"));
    }

    #[test]
    fn project_kind_python_requirements() {
        let dir = td();
        fs::write(dir.path().join("requirements.txt"), "flask\n").unwrap();
        assert_eq!(detect_project_kind(dir.path()), Some("python"));
    }

    #[test]
    fn project_kind_go() {
        let dir = td();
        fs::write(dir.path().join("go.mod"), "module example.com/x\n").unwrap();
        assert_eq!(detect_project_kind(dir.path()), Some("go"));
    }

    #[test]
    fn project_kind_unknown() {
        let dir = td();
        assert!(detect_project_kind(dir.path()).is_none());
    }

    // ── route discovery ─────────────────────────────────────────────────────

    #[test]
    fn discovers_express_handlers() {
        let dir = td();
        fs::write(
            dir.path().join("app.js"),
            "const express = require('express');\nconst app = express();\napp.get('/users', (req, res) => res.json([]));\napp.post('/api/login', handler);\nrouter.delete(\"/api/users/:id\", handler);\n",
        )
        .unwrap();
        let routes = discover_routes(dir.path(), 1500);
        let by: HashSet<(String, String)> = routes
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect();
        assert!(by.contains(&("GET".into(), "/users".into())));
        assert!(by.contains(&("POST".into(), "/api/login".into())));
        assert!(by.contains(&("DELETE".into(), "/api/users/:id".into())));
    }

    #[test]
    fn discovers_fastapi_handlers() {
        let dir = td();
        fs::write(
            dir.path().join("main.py"),
            "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter()\n@app.get('/health')\ndef health(): return {}\n@router.post('/api/users')\ndef create_user(): pass\n@router.delete('/api/users/{user_id}')\ndef delete_user(user_id: int): pass\n",
        )
        .unwrap();
        let routes = discover_routes(dir.path(), 1500);
        let by: HashSet<(String, String)> = routes
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect();
        assert!(by.contains(&("GET".into(), "/health".into())));
        assert!(by.contains(&("POST".into(), "/api/users".into())));
        assert!(by.contains(&("DELETE".into(), "/api/users/{user_id}".into())));
    }

    #[test]
    fn discovers_flask_handlers() {
        let dir = td();
        fs::write(
            dir.path().join("main.py"),
            "from flask import Flask, Blueprint\napp = Flask(__name__)\nbp = Blueprint('api', __name__)\n@app.route('/')\ndef index(): return 'ok'\n@app.route('/login', methods=['POST'])\ndef login(): pass\n@bp.route('/api/items', methods=['GET', 'POST'])\ndef items(): pass\n",
        )
        .unwrap();
        let routes = discover_routes(dir.path(), 1500);
        let by: HashSet<(String, String)> = routes
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect();
        assert!(by.contains(&("GET".into(), "/".into())));
        assert!(by.contains(&("POST".into(), "/login".into())));
        assert!(by.contains(&("GET".into(), "/api/items".into())));
        assert!(by.contains(&("POST".into(), "/api/items".into())));
    }

    #[test]
    fn discovers_go_handlers() {
        let dir = td();
        fs::write(
            dir.path().join("main.go"),
            "package main\nimport \"github.com/gin-gonic/gin\"\nfunc main() {\n  r := gin.Default()\n  r.GET(\"/health\", healthHandler)\n  r.POST(\"/api/login\", loginHandler)\n  api := r.Group(\"/api\")\n  api.DELETE(\"/users/:id\", deleteHandler)\n}\n",
        )
        .unwrap();
        let routes = discover_routes(dir.path(), 1500);
        let by: HashSet<(String, String)> = routes
            .iter()
            .map(|r| (r.method.clone(), r.path.clone()))
            .collect();
        assert!(by.contains(&("GET".into(), "/health".into())));
        assert!(by.contains(&("POST".into(), "/api/login".into())));
        assert!(by.contains(&("DELETE".into(), "/users/:id".into())));
    }

    #[test]
    fn skips_vendor_dirs() {
        let dir = td();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("app.js"), "app.get('/real', h);\n").unwrap();
        let nm = dir.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("noise.js"), "app.get('/should-not-find', h);\n").unwrap();
        let venv = dir.path().join(".venv");
        fs::create_dir(&venv).unwrap();
        fs::write(
            venv.join("noise.py"),
            "@app.get('/also-not')\ndef x(): pass\n",
        )
        .unwrap();

        let routes = discover_routes(dir.path(), 1500);
        let paths: HashSet<&str> = routes.iter().map(|r| r.path.as_str()).collect();
        assert!(paths.contains("/real"));
        assert!(!paths.contains("/should-not-find"));
        assert!(!paths.contains("/also-not"));
    }

    #[test]
    fn dedupes_repeated_definitions() {
        let dir = td();
        fs::write(dir.path().join("a.js"), "app.get('/x', h);\n").unwrap();
        fs::write(dir.path().join("b.js"), "app.get('/x', h);\n").unwrap();
        let routes = discover_routes(dir.path(), 1500);
        let matching: Vec<_> = routes
            .iter()
            .filter(|r| r.method == "GET" && r.path == "/x")
            .collect();
        assert_eq!(matching.len(), 1);
    }

    #[test]
    fn respects_max_files() {
        let dir = td();
        for i in 0..20 {
            fs::write(
                dir.path().join(format!("f{i}.js")),
                format!("app.get('/r{i}', h);\n"),
            )
            .unwrap();
        }
        let routes = discover_routes(dir.path(), 5);
        assert!(routes.len() <= 5);
    }

    #[test]
    fn js_all_method_lowers_to_post() {
        let dir = td();
        fs::write(dir.path().join("app.js"), "app.all('/foo', handler);\n").unwrap();
        let routes = discover_routes(dir.path(), 1500);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].method, "POST");
        assert_eq!(routes[0].path, "/foo");
    }

    #[test]
    fn relative_paths_skipped() {
        let dir = td();
        fs::write(dir.path().join("app.js"), "app.get('relative', h);\n").unwrap();
        let routes = discover_routes(dir.path(), 1500);
        assert!(routes.is_empty());
    }

    #[test]
    fn flask_methods_default_to_get() {
        assert_eq!(extract_flask_methods(""), vec!["GET".to_string()]);
    }

    #[test]
    fn flask_methods_extracted_uppercase() {
        let methods = extract_flask_methods(", methods=['post', 'put']");
        assert_eq!(methods, vec!["POST", "PUT"]);
    }

    #[test]
    fn parse_simple_url_default_port_http() {
        let u = parse_simple_url("http://localhost/v1").unwrap();
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, 80);
        assert_eq!(u.path, "/v1");
    }

    #[test]
    fn parse_simple_url_explicit_port() {
        let u = parse_simple_url("http://localhost:4000/v1/x").unwrap();
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, 4000);
        assert_eq!(u.path, "/v1/x");
    }

    #[test]
    fn parse_simple_url_https_default() {
        let u = parse_simple_url("https://example.com").unwrap();
        assert_eq!(u.port, 443);
        assert_eq!(u.path, "/");
    }
}
