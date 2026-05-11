//! Version range matcher.
//!
//! Direct port of `_version_key` / `_suffix_segments` / `_matches_constraint`
//! / `_matches_range` / `_matches_any_range` from
//! `packages/arcis-python/arcis/cli/sca.py`. The contract is byte-equal
//! ordering for every fixture in `tests/cli/test_sca_ranges.py`, including
//! the rc1-vs-rc10 fix from commit `e778439`.
//!
//! The Python implementation builds a tuple of mixed-tag slots and relies on
//! Python's natural tuple comparison. We model that as `Vec<Slot>` where
//! `Slot` is an enum whose variant declaration order encodes the tag
//! precedence:
//!
//!   tag 0, str payload    < tag 0, suffix payload
//!                         < tag 1, int payload
//!                         < tag 2, end marker
//!
//! Two slots at the same tag with different payload kinds (string vs.
//! suffix-tuple) only ever align across versions when one input is malformed;
//! the ordering is still deterministic.

use std::cmp::Ordering;

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Slot {
    /// `(0, str)` — non-numeric base segment (e.g. `"a"` from `"1.0a"`).
    Tag0Str(String),
    /// `(0, suffix_tuple)` — pre-release suffix terminator. Sorts below the
    /// release `Tag2End` so `1.0.0-rc1 < 1.0.0`.
    Tag0Suffix(Vec<(String, u64)>),
    /// `(1, int)` — numeric base segment.
    Tag1Num(u64),
    /// `(2, ())` — terminator when there is no pre-release suffix.
    Tag2End,
}

pub type VersionKey = Vec<Slot>;

/// Split a single dotted suffix segment into `(letters, number)` per the
/// Python regex `^([A-Za-z\-]*)(\d+)?$`.
///
/// Returns `None` when the segment doesn't match (e.g. has digits then
/// letters, or non-alphanumeric chars). The caller falls back to
/// `(seg.lower(), 0)` in that case to mirror Python's behavior.
fn parse_suffix_segment(seg: &str) -> Option<(String, u64)> {
    // Letters/dashes prefix.
    let mut letters_end = 0usize;
    for (i, c) in seg.char_indices() {
        if c.is_ascii_alphabetic() || c == '-' {
            letters_end = i + c.len_utf8();
        } else {
            break;
        }
    }
    let (letters, rest) = seg.split_at(letters_end);

    if rest.is_empty() {
        return Some((letters.to_ascii_lowercase(), 0));
    }
    if rest.bytes().all(|b| b.is_ascii_digit()) {
        let n: u64 = rest.parse().unwrap_or(0);
        return Some((letters.to_ascii_lowercase(), n));
    }
    None
}

/// Split a full pre-release suffix (everything after the first `-`) into
/// segments, dot-separated.
fn suffix_segments(suf: &str) -> Vec<(String, u64)> {
    suf.split('.')
        .map(|seg| parse_suffix_segment(seg).unwrap_or_else(|| (seg.to_ascii_lowercase(), 0)))
        .collect()
}

/// Build the comparable key for a version string.
pub fn version_key(v: &str) -> VersionKey {
    let trimmed = v.trim();
    if trimmed.is_empty() {
        // Mirrors the Python `((0, ""), (0, ""))` sentinel for the empty
        // string. Two-slot key sorts below any non-empty version.
        return vec![Slot::Tag0Str(String::new()), Slot::Tag0Str(String::new())];
    }

    // Strip optional leading v / V (only if there's content after it).
    let mut s: &str = trimmed;
    if let Some(rest) = s.strip_prefix(|c| c == 'v' || c == 'V') {
        if !rest.is_empty() {
            s = rest;
        }
    }

    // Drop build metadata after the first `+`.
    if let Some(plus) = s.find('+') {
        s = &s[..plus];
    }

    // Partition on first `-` into base / suffix.
    let (base, suffix) = match s.find('-') {
        Some(i) => (&s[..i], Some(&s[i + 1..])),
        None => (s, None),
    };

    let mut parts: Vec<Slot> = Vec::new();
    for p in base.split('.') {
        if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
            parts.push(Slot::Tag1Num(p.parse().unwrap_or(0)));
            continue;
        }
        let digits: String = p.chars().filter(|c| c.is_ascii_digit()).collect();
        let tail: String = p.chars().filter(|c| !c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            parts.push(Slot::Tag1Num(digits.parse().unwrap_or(0)));
            if !tail.is_empty() {
                parts.push(Slot::Tag0Str(tail));
            }
        } else {
            parts.push(Slot::Tag0Str(p.to_string()));
        }
    }

    match suffix {
        Some(suf) => parts.push(Slot::Tag0Suffix(suffix_segments(suf))),
        None => parts.push(Slot::Tag2End),
    }
    parts
}

/// Compare two version strings via their keys. Convenience wrapper.
pub fn cmp_versions(a: &str, b: &str) -> Ordering {
    version_key(a).cmp(&version_key(b))
}

/// Predicate over an `Ordering` — used to test the result of a single
/// `cmp` call against the operator's expectation.
type CmpPredicate = fn(&Ordering) -> bool;

/// Constraint operators recognised in single-constraint strings such as
/// `<4.22.4`, `>=1.0.0`, `==1.7.0`, `!=2.0.0`. Order matters for prefix
/// matching: two-character ops must be tried before one-character ops.
const OPS: &[(&str, CmpPredicate)] = &[
    ("<=", |o| matches!(o, Ordering::Less | Ordering::Equal)),
    (">=", |o| matches!(o, Ordering::Greater | Ordering::Equal)),
    ("!=", |o| !matches!(o, Ordering::Equal)),
    ("==", |o| matches!(o, Ordering::Equal)),
    ("<", |o| matches!(o, Ordering::Less)),
    (">", |o| matches!(o, Ordering::Greater)),
];

/// Match a single constraint such as `<4.22.4` or `==1.7.0`.
///
/// An empty constraint returns `true` (mirrors Python). A bare version
/// (no operator) is treated as exact-match.
pub fn matches_constraint(version: &str, constraint: &str) -> bool {
    let constraint = constraint.trim();
    if constraint.is_empty() {
        return true;
    }
    for (prefix, op) in OPS {
        if let Some(target) = constraint.strip_prefix(prefix) {
            let target = target.trim();
            let order = cmp_versions(version, target);
            return op(&order);
        }
    }
    cmp_versions(version, constraint) == Ordering::Equal
}

/// Match a comma-separated AND of constraints, e.g. `>=4.0.0,<4.22.4`.
/// Empty range expression evaluates to `false`.
pub fn matches_range(version: &str, range_expr: &str) -> bool {
    let parts: Vec<&str> = range_expr
        .split(',')
        .filter(|c| !c.trim().is_empty())
        .collect();
    if parts.is_empty() {
        return false;
    }
    parts.iter().all(|c| matches_constraint(version, c))
}

/// OR across multiple range expressions.
pub fn matches_any_range<S: AsRef<str>>(version: &str, ranges: &[S]) -> bool {
    ranges.iter().any(|r| matches_range(version, r.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── version_key ────────────────────────────────────────────────────────

    #[test]
    fn version_key_orders_numeric_parts() {
        assert!(version_key("1.0.0") < version_key("1.0.1"));
        assert!(version_key("1.0.0") < version_key("1.1.0"));
        assert!(version_key("1.0.0") < version_key("2.0.0"));
        assert!(version_key("1.10.0") > version_key("1.9.0"));
    }

    #[test]
    fn pre_release_below_release() {
        assert!(version_key("1.0.0-rc1") < version_key("1.0.0"));
        assert!(version_key("4.22.4-beta") < version_key("4.22.4"));
    }

    #[test]
    fn pre_release_segments_compare_numerically() {
        // The rc1-vs-rc10 fix from commit e778439.
        assert!(version_key("1.0.0-rc1") < version_key("1.0.0-rc2"));
        assert!(version_key("1.0.0-rc2") < version_key("1.0.0-rc10"));
        assert!(version_key("1.0.0-rc10") < version_key("1.0.0-rc11"));
    }

    #[test]
    fn pre_release_alpha_beta_rc_order() {
        assert!(version_key("1.0.0-alpha") < version_key("1.0.0-beta"));
        assert!(version_key("1.0.0-beta") < version_key("1.0.0-rc"));
        assert!(version_key("1.0.0-rc") < version_key("1.0.0"));
    }

    #[test]
    fn dotted_pre_release_segments() {
        assert!(version_key("1.0.0-alpha") < version_key("1.0.0-alpha.1"));
        assert!(version_key("1.0.0-alpha.1") < version_key("1.0.0-alpha.2"));
        assert!(version_key("1.0.0-alpha.2") < version_key("1.0.0-alpha.10"));
        // Pure-numeric segment sorts below alphanumeric.
        assert!(version_key("1.0.0-1") < version_key("1.0.0-rc1"));
    }

    #[test]
    fn handles_v_prefix() {
        assert_eq!(version_key("v1.2.3"), version_key("1.2.3"));
        assert_eq!(version_key("V1.2.3"), version_key("1.2.3"));
    }

    #[test]
    fn build_metadata_is_stripped() {
        assert_eq!(version_key("1.2.3+build.42"), version_key("1.2.3"));
    }

    #[test]
    fn empty_string_stable() {
        // Empty maps to the sentinel; two empty calls must produce the same key.
        assert_eq!(version_key(""), version_key(""));
    }

    // ── matches_constraint ────────────────────────────────────────────────

    #[test]
    fn constraint_matrix() {
        let cases = [
            ("4.22.3", "<4.22.4", true),
            ("4.22.4", "<4.22.4", false),
            ("4.22.5", "<4.22.4", false),
            ("4.22.4", "<=4.22.4", true),
            ("4.22.5", "<=4.22.4", false),
            ("4.22.4", ">=4.22.4", true),
            ("4.22.3", ">=4.22.4", false),
            ("4.22.4", ">4.22.3", true),
            ("4.22.3", ">4.22.3", false),
            ("1.0.0", "==1.0.0", true),
            ("1.0.1", "==1.0.0", false),
            ("1.0.0", "!=1.0.0", false),
            ("1.0.1", "!=1.0.0", true),
            // Bare version → exact match.
            ("1.0.0", "1.0.0", true),
            ("1.0.1", "1.0.0", false),
        ];
        for (v, c, expected) in cases {
            assert_eq!(
                matches_constraint(v, c),
                expected,
                "matches_constraint({v:?}, {c:?})"
            );
        }
    }

    #[test]
    fn empty_constraint_is_true() {
        assert!(matches_constraint("1.0.0", ""));
        assert!(matches_constraint("1.0.0", "   "));
    }

    // ── matches_range ─────────────────────────────────────────────────────

    #[test]
    fn range_anded_constraints() {
        let rng = ">=4.0.0,<4.22.4";
        assert!(matches_range("4.22.3", rng));
        assert!(matches_range("4.0.0", rng));
        assert!(!matches_range("3.99.99", rng));
        assert!(!matches_range("4.22.4", rng));
    }

    #[test]
    fn range_handles_whitespace_and_empty() {
        assert!(matches_range("1.0.0", " >=1.0.0 ,  <2.0.0 "));
        assert!(!matches_range("1.0.0", ""));
        assert!(!matches_range("1.0.0", "  "));
    }

    #[test]
    fn any_range_ors_multiple() {
        let ranges = [">=2.0.0,<2.2.2".to_string(), ">=1.0.0,<1.26.19".to_string()];
        assert!(matches_any_range("1.26.18", &ranges));
        assert!(matches_any_range("2.2.1", &ranges));
        assert!(!matches_any_range("2.2.2", &ranges));
        assert!(!matches_any_range("1.26.19", &ranges));
    }
}
