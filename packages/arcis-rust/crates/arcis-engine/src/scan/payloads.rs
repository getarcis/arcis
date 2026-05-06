//! Attack payload corpus for `arcis scan`.
//!
//! Direct port of `packages/arcis-python/arcis/cli/payloads.py`. Each
//! category maps to an ordered list of `(label, payload)` tuples; the
//! first entry in each is the primary test vector, with the rest only
//! exercised under `--thorough`. Order matters for the `--list` catalog
//! and for the request-fan-out so Python and Rust dispatch the same
//! vectors in the same order.

/// Single attack vector in a category.
///
/// `label` is the short human-readable tag printed in `--list` output and
/// in per-route summaries. `payload` is the raw string injected into the
/// request (URL-encoded for GET, JSON-quoted for POST/PUT/PATCH).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttackVector {
    pub label: &'static str,
    pub payload: &'static str,
}

/// Category of attacks (e.g. "XSS", "SQL Injection") with its vector list.
#[derive(Debug, Clone, Copy)]
pub struct AttackCategory {
    pub name: &'static str,
    pub vectors: &'static [AttackVector],
}

const XSS: &[AttackVector] = &[
    AttackVector {
        label: "script tag",
        payload: "<script>alert(1)</script>",
    },
    AttackVector {
        label: "img onerror",
        payload: "<img src=x onerror=alert(1)>",
    },
    AttackVector {
        label: "javascript URI",
        payload: "javascript:alert(document.cookie)",
    },
    AttackVector {
        label: "svg onload",
        payload: "<svg onload=alert(1)>",
    },
];

const SQL_INJECTION: &[AttackVector] = &[
    AttackVector {
        label: "OR bypass",
        payload: "' OR '1'='1' --",
    },
    AttackVector {
        label: "UNION select",
        payload: "' UNION SELECT null,null,null--",
    },
    AttackVector {
        label: "stacked query",
        payload: "'; DROP TABLE users--",
    },
    AttackVector {
        label: "comment bypass",
        payload: "1/**/OR/**/1=1",
    },
];

const SQL_BLIND: &[AttackVector] = &[
    AttackVector {
        label: "SLEEP",
        payload: "'; SLEEP(5)--",
    },
    AttackVector {
        label: "BENCHMARK",
        payload: "'; BENCHMARK(1000000,MD5(1))--",
    },
    AttackVector {
        label: "WAITFOR",
        payload: "1; WAITFOR DELAY '0:0:5'--",
    },
];

const NOSQL_INJECTION: &[AttackVector] = &[
    AttackVector {
        label: "$gt operator",
        payload: "{\"$gt\": \"\"}",
    },
    AttackVector {
        label: "$where operator",
        payload: "{\"$where\": \"1==1\"}",
    },
    AttackVector {
        label: "$ne operator",
        payload: "{\"$ne\": null}",
    },
    AttackVector {
        label: "$regex operator",
        payload: "{\"$regex\": \".*\"}",
    },
];

const PATH_TRAVERSAL: &[AttackVector] = &[
    AttackVector {
        label: "unix passwd",
        payload: "../../etc/passwd",
    },
    AttackVector {
        label: "windows system32",
        payload: "..\\..\\windows\\system32\\cmd.exe",
    },
    AttackVector {
        label: "url encoded",
        payload: "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    },
    AttackVector {
        label: "null byte",
        payload: "../../etc/passwd%00",
    },
];

const COMMAND_INJECTION: &[AttackVector] = &[
    AttackVector {
        label: "semicolon",
        payload: "; ls -la",
    },
    AttackVector {
        label: "pipe",
        payload: "| whoami",
    },
    AttackVector {
        label: "backtick",
        payload: "`id`",
    },
    AttackVector {
        label: "ampersand",
        payload: "&& cat /etc/passwd",
    },
];

const PROTOTYPE_POLLUTION: &[AttackVector] = &[
    AttackVector {
        label: "__proto__",
        payload: "{\"__proto__\": {\"admin\": true}}",
    },
    AttackVector {
        label: "constructor",
        payload: "{\"constructor\": {\"prototype\": {\"admin\": true}}}",
    },
];

const LDAP_INJECTION: &[AttackVector] = &[
    AttackVector {
        label: "wildcard",
        payload: "*)(uid=*))(|(uid=*",
    },
    AttackVector {
        label: "OR bypass",
        payload: "admin)(&(password=*)",
    },
];

/// Ordered list of attack categories. Iteration order matches Python's
/// `ATTACK_CATEGORIES` dict declaration order — load-bearing for
/// `--list` output and request-fan-out parity.
pub fn attack_categories() -> &'static [AttackCategory] {
    &[
        AttackCategory {
            name: "XSS",
            vectors: XSS,
        },
        AttackCategory {
            name: "SQL Injection",
            vectors: SQL_INJECTION,
        },
        AttackCategory {
            name: "SQL Blind",
            vectors: SQL_BLIND,
        },
        AttackCategory {
            name: "NoSQL Injection",
            vectors: NOSQL_INJECTION,
        },
        AttackCategory {
            name: "Path Traversal",
            vectors: PATH_TRAVERSAL,
        },
        AttackCategory {
            name: "Command Injection",
            vectors: COMMAND_INJECTION,
        },
        AttackCategory {
            name: "Prototype Pollution",
            vectors: PROTOTYPE_POLLUTION,
        },
        AttackCategory {
            name: "LDAP Injection",
            vectors: LDAP_INJECTION,
        },
    ]
}

/// JSON-field names tried in order when the user does not pass `--field`.
pub const DEFAULT_FIELDS: &[&str] = &[
    "q", "query", "search", "input", "name", "username", "email", "data", "value", "text", "id",
];

/// HTTP statuses treated as "request blocked / rejected" by `_classify`.
pub const BLOCKED_STATUS_CODES: &[u16] = &[400, 403, 422, 429];

/// Slug form of a category name (lowercase, spaces stripped). Mirrors
/// Python's `name.lower().replace(" ", "")` used in the `--categories`
/// flag matcher and in `_print_payload_catalog`.
pub fn slug(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_count_matches_python() {
        // 8 categories: XSS, SQL Injection, SQL Blind, NoSQL Injection,
        // Path Traversal, Command Injection, Prototype Pollution, LDAP.
        assert_eq!(attack_categories().len(), 8);
    }

    #[test]
    fn category_order_matches_python() {
        let names: Vec<&str> = attack_categories().iter().map(|c| c.name).collect();
        assert_eq!(
            names,
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
    fn each_category_has_at_least_one_vector() {
        for cat in attack_categories() {
            assert!(
                !cat.vectors.is_empty(),
                "category {} has no vectors",
                cat.name
            );
        }
    }

    #[test]
    fn xss_primary_vector_is_script_tag() {
        let xss = attack_categories()
            .iter()
            .find(|c| c.name == "XSS")
            .expect("XSS category present");
        assert_eq!(xss.vectors[0].label, "script tag");
        assert_eq!(xss.vectors[0].payload, "<script>alert(1)</script>");
    }

    #[test]
    fn nosql_payloads_are_valid_json() {
        let nosql = attack_categories()
            .iter()
            .find(|c| c.name == "NoSQL Injection")
            .expect("NoSQL Injection category present");
        for v in nosql.vectors {
            serde_json::from_str::<serde_json::Value>(v.payload)
                .unwrap_or_else(|e| panic!("payload {:?} should parse as JSON: {}", v.payload, e));
        }
    }

    #[test]
    fn total_vector_count_under_thorough_matches_python() {
        // 4 + 4 + 3 + 4 + 4 + 4 + 2 + 2 = 27
        let total: usize = attack_categories().iter().map(|c| c.vectors.len()).sum();
        assert_eq!(total, 27);
    }

    #[test]
    fn default_fields_match_python() {
        assert_eq!(
            DEFAULT_FIELDS,
            &[
                "q", "query", "search", "input", "name", "username", "email", "data", "value",
                "text", "id",
            ]
        );
    }

    #[test]
    fn blocked_status_set_matches_python() {
        assert_eq!(BLOCKED_STATUS_CODES, &[400, 403, 422, 429]);
    }

    #[test]
    fn slug_strips_spaces_and_lowercases() {
        assert_eq!(slug("XSS"), "xss");
        assert_eq!(slug("SQL Injection"), "sqlinjection");
        assert_eq!(slug("NoSQL Injection"), "nosqlinjection");
        assert_eq!(slug("Prototype Pollution"), "prototypepollution");
    }

    #[test]
    fn slug_round_trip_for_user_filter_matching() {
        // The --categories flag matcher does case-insensitive,
        // whitespace-stripped equality. Round-trip every category name.
        for cat in attack_categories() {
            let s = slug(cat.name);
            assert_eq!(s, slug(&s.to_uppercase()));
        }
    }
}
