//! `curl` one-liner reproducer for a single (route, vector) probe.
//!
//! Mirrors the request shape `probe::send_one` actually puts on the wire
//! so the user can paste the line into a POSIX shell and reproduce the
//! exact probe — useful both for vulnerable findings ("show me what got
//! through") and blocked ones ("show me what the middleware rejected").

use serde_json::Value;

/// Format a portable POSIX-shell `curl` invocation that mirrors how
/// `probe::send_one` would dispatch the same probe.
///
/// * `GET`  → `curl -fsSL '<base>/<path>?<field>=<urlencoded payload>'`
/// * other  → `curl -fsSL -X <METHOD> '<base>/<path>'
///            -H 'Content-Type: application/json' --data-raw '<json body>'`
///
/// `target_url` is treated like `probe::scan_route` does — trailing `/`
/// trimmed, `path` leading `/` trimmed, then joined with a single `/`.
/// `field` is the JSON body / query key. NoSQL payloads that parse as
/// JSON stay nested in the body, just like `send_one`.
pub fn format_curl(
    target_url: &str,
    method: &str,
    path: &str,
    field: &str,
    payload: &str,
) -> String {
    let url = format!(
        "{}/{}",
        target_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    if method.eq_ignore_ascii_case("GET") {
        let encoded = urlencoding::encode(payload);
        let sep = if url.contains('?') { '&' } else { '?' };
        let full_url = format!("{url}{sep}{field}={encoded}");
        format!("curl -fsSL {}", shell_quote(&full_url))
    } else {
        let json_value: Value =
            serde_json::from_str(payload).unwrap_or_else(|_| Value::String(payload.to_string()));
        let body = serde_json::json!({ field: json_value }).to_string();
        format!(
            "curl -fsSL -X {} {} -H 'Content-Type: application/json' --data-raw {}",
            method.to_uppercase(),
            shell_quote(&url),
            shell_quote(&body),
        )
    }
}

/// Wrap `s` in single quotes for POSIX shell, escaping any embedded `'`
/// via the standard `'\''` close-quote / escaped-quote / re-open-quote
/// dance. Safe for arbitrary payload bytes.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_url_encodes_payload_into_query() {
        let s = format_curl(
            "http://localhost:5000",
            "GET",
            "/search",
            "q",
            "<script>alert(1)</script>",
        );
        assert_eq!(
            s,
            "curl -fsSL 'http://localhost:5000/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'"
        );
    }

    #[test]
    fn get_appends_with_ampersand_when_path_already_has_query() {
        let s = format_curl("http://h", "GET", "/p?x=1", "q", "y");
        assert!(
            s.contains("/p?x=1&q=y"),
            "expected & separator when path already has ?, got: {s}"
        );
    }

    #[test]
    fn post_emits_json_body_and_method_uppercased() {
        let s = format_curl("http://h", "post", "/api/login", "username", "admin");
        assert_eq!(
            s,
            "curl -fsSL -X POST 'http://h/api/login' -H 'Content-Type: application/json' --data-raw '{\"username\":\"admin\"}'"
        );
    }

    #[test]
    fn post_keeps_nosql_payload_nested() {
        let s = format_curl("http://h", "POST", "/login", "password", "{\"$gt\": \"\"}");
        assert!(
            s.contains("'{\"password\":{\"$gt\":\"\"}}'"),
            "NoSQL payload should round-trip nested in the body, got: {s}"
        );
    }

    #[test]
    fn payload_with_single_quote_is_shell_escaped() {
        // Classic SQLi payload contains literal single quotes — they must
        // be escaped inside the single-quoted shell argument.
        let s = format_curl("http://h", "POST", "/q", "user", "' OR '1'='1' --");
        // Body in JSON: {"user":"' OR '1'='1' --"} — every `'` in that
        // string must be replaced by the `'\''` escape sequence.
        let body_segment = "'{\"user\":\"'\\''  OR '\\''1'\\''='\\''1'\\'' --\"}'";
        // Allow either 1 or 2 spaces between OR — JSON serialiser preserves
        // whatever was in the input. We sent " OR " with one space, so
        // the asserted segment uses a single space too.
        let single_space = body_segment.replace("'\\''  OR", "'\\'' OR");
        assert!(
            s.ends_with(&single_space),
            "expected single-quote escape via '\\\\''  pattern, got tail: {}",
            &s[s.len().saturating_sub(120)..]
        );
    }

    #[test]
    fn put_method_honored() {
        let s = format_curl("http://h", "PUT", "/p", "f", "v");
        assert!(s.starts_with("curl -fsSL -X PUT "), "got: {s}");
    }

    #[test]
    fn trailing_slash_in_target_and_leading_slash_in_path_collapse() {
        let s = format_curl("http://h/", "GET", "/p", "q", "v");
        assert!(s.contains("'http://h/p?q=v'"), "got: {s}");
    }

    #[test]
    fn shell_quote_escapes_embedded_quote() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote(""), "''");
    }
}
