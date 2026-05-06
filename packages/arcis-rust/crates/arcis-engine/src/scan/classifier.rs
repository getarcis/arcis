//! Response classifier for `arcis scan`.
//!
//! Direct port of `_classify` in `packages/arcis-python/arcis/cli/scan.py`.
//! Decides whether a probed payload was blocked by the target. The four
//! cases (in order) are kept identical to Python so parity tests match
//! byte-for-byte:
//!
//!   1. status 0           -> not blocked, "connection error"
//!   2. status in BLOCKED  -> blocked, "rejected (<status>)"
//!   3. payload reflected  -> not blocked, "reflected in response (<status>)"
//!   4. 2xx, no reflection -> blocked, "sanitised (<status>)"
//!   5. anything else      -> not blocked, "status <status>"

use super::payloads::BLOCKED_STATUS_CODES;

/// Outcome of classifying one probe response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    pub blocked: bool,
    pub note: String,
}

/// Classify a probe response. `status == 0` is the convention used by
/// `_send` for connection errors (port closed, DNS failure, etc.).
pub fn classify(status: u16, body: &str, payload: &str) -> Classification {
    if status == 0 {
        return Classification {
            blocked: false,
            note: "connection error".into(),
        };
    }

    if BLOCKED_STATUS_CODES.contains(&status) {
        return Classification {
            blocked: true,
            note: format!("rejected ({status})"),
        };
    }

    // Reflection check: payload appears verbatim (case-insensitive,
    // trim-stripped) in the response body. Mirrors Python
    // `payload.strip().lower() in body.lower()`.
    let trimmed = payload.trim();
    if !trimmed.is_empty() {
        let needle = trimmed.to_lowercase();
        let haystack = body.to_lowercase();
        if haystack.contains(&needle) {
            return Classification {
                blocked: false,
                note: format!("reflected in response ({status})"),
            };
        }
    }

    if (200..300).contains(&status) {
        return Classification {
            blocked: true,
            note: format!("sanitised ({status})"),
        };
    }

    Classification {
        blocked: false,
        note: format!("status {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_error_is_not_blocked() {
        let c = classify(0, "", "<script>alert(1)</script>");
        assert!(!c.blocked);
        assert_eq!(c.note, "connection error");
    }

    #[test]
    fn rejected_400_is_blocked() {
        let c = classify(400, "Bad Request", "<script>alert(1)</script>");
        assert!(c.blocked);
        assert_eq!(c.note, "rejected (400)");
    }

    #[test]
    fn rejected_403_is_blocked() {
        let c = classify(403, "Forbidden", "anything");
        assert!(c.blocked);
        assert_eq!(c.note, "rejected (403)");
    }

    #[test]
    fn rejected_422_is_blocked() {
        let c = classify(422, "Unprocessable", "");
        assert!(c.blocked);
        assert_eq!(c.note, "rejected (422)");
    }

    #[test]
    fn rejected_429_is_blocked() {
        let c = classify(429, "Too Many Requests", "");
        assert!(c.blocked);
        assert_eq!(c.note, "rejected (429)");
    }

    #[test]
    fn reflected_payload_is_not_blocked() {
        let c = classify(
            200,
            "Hello <script>alert(1)</script> world",
            "<script>alert(1)</script>",
        );
        assert!(!c.blocked);
        assert_eq!(c.note, "reflected in response (200)");
    }

    #[test]
    fn reflection_is_case_insensitive() {
        let c = classify(
            200,
            "<SCRIPT>ALERT(1)</SCRIPT>",
            "<script>alert(1)</script>",
        );
        assert!(!c.blocked);
        assert_eq!(c.note, "reflected in response (200)");
    }

    #[test]
    fn sanitised_2xx_is_blocked() {
        let c = classify(200, "OK", "<script>alert(1)</script>");
        assert!(c.blocked);
        assert_eq!(c.note, "sanitised (200)");
    }

    #[test]
    fn sanitised_204_is_blocked() {
        let c = classify(204, "", "anything");
        assert!(c.blocked);
        assert_eq!(c.note, "sanitised (204)");
    }

    #[test]
    fn server_error_500_is_not_blocked() {
        let c = classify(500, "Internal Error", "<script>alert(1)</script>");
        assert!(!c.blocked);
        assert_eq!(c.note, "status 500");
    }

    #[test]
    fn redirect_3xx_is_not_blocked_and_does_not_reflect() {
        let c = classify(301, "", "anything");
        assert!(!c.blocked);
        assert_eq!(c.note, "status 301");
    }

    #[test]
    fn empty_payload_does_not_short_circuit_2xx_path() {
        // Strip-then-lower of an empty payload would otherwise match every
        // body via the empty-substring rule. Guard prevents that.
        let c = classify(200, "anything goes here", "");
        assert!(c.blocked);
        assert_eq!(c.note, "sanitised (200)");
    }

    #[test]
    fn rejected_takes_precedence_over_reflection() {
        // Even if the payload appears in a 400 response, the rejection
        // wins. Python's order-of-checks is the same.
        let c = classify(
            400,
            "your input was <script>alert(1)</script>",
            "<script>alert(1)</script>",
        );
        assert!(c.blocked);
        assert_eq!(c.note, "rejected (400)");
    }
}
