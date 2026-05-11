//! Suppress-comment directive parser. cli-audit.md item 6.
//!
//! Recognised forms:
//!
//! ```text
//! // arcis-audit: ignore                  any rule, this line
//! // arcis-audit: ignore RULE-ID          one specific rule
//! // arcis-audit: ignore A,B,C            comma list
//! // arcis-audit: ignore-file             whole file, any rule
//! ```
//!
//! Both `//` (JS / TS) and `#` (Python) markers are recognised; nothing
//! else. Block-comment forms (`/* ... */`, `<!-- ... -->`) are NOT
//! recognised — adds parser complexity for zero current demand and
//! invites multi-line directive ambiguity. Document-and-defer.
//!
//! ## Suppression scope
//!
//! Standard SAST semantics (matches Semgrep, NOT permissive-Bandit):
//!
//! 1. **Same-line directive** — applies to its own line. Trailing
//!    comment-directive on a code line is the most common form:
//!    `result = eval(x)  // arcis-audit: ignore EVAL-EXEC`.
//! 2. **Preceding-line directive** — applies to the next line ONLY when
//!    the directive sits on a comment-only line (first non-whitespace
//!    char is `//` or `#`). A trailing inline directive on a code line
//!    suppresses ONLY its own line; it never bleeds into the next.
//! 3. **File-level directive** — `arcis-audit: ignore-file` anywhere in
//!    the file suppresses every finding in that file.
//!
//! Why the comment-only-line restriction (not "any preceding line"):
//! a directive like `eval(x) // arcis-audit: ignore` says "this eval is
//! OK." Letting it also silently suppress a finding on the next line is
//! the classic SAST footgun — security tooling must be predictable, not
//! convenient. If someone wants to suppress two adjacent lines, they
//! write two directives.
//!
//! ## Out-of-scope (today)
//!
//! - `--show-suppressed` flag — wait for a real ask.
//! - Per-file `noqa`-style end-of-line directive without rule scoping
//!   beyond what's documented here.
//! - Block-comment hosts.

use std::sync::OnceLock;

use regex::Regex;

/// One parsed suppression directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// `arcis-audit: ignore` (any rule) or `arcis-audit: ignore A,B,C`
    /// (specific rules). `None` rules → matches every rule_id.
    Line { rules: Option<Vec<String>> },
    /// `arcis-audit: ignore-file` — whole file, any rule.
    File,
}

static LINE_RE: OnceLock<Regex> = OnceLock::new();
static FILE_RE: OnceLock<Regex> = OnceLock::new();

fn line_re() -> &'static Regex {
    LINE_RE.get_or_init(|| {
        // `(?://|#)` — comment marker (JS-family or Python).
        // `\s*arcis-audit:\s*ignore` — directive token.
        // `(?:\s+(.+?))?` — optional whitespace-separated rule list.
        // `\s*$` — anchored to end of line; with `\s*` after the rule
        //          capture, this correctly fails to match `ignore-file`
        //          (no whitespace before `-file`).
        Regex::new(r"(?://|#)\s*arcis-audit:\s*ignore(?:\s+(.+?))?\s*$").unwrap()
    })
}

fn file_re() -> &'static Regex {
    FILE_RE.get_or_init(|| Regex::new(r"(?://|#)\s*arcis-audit:\s*ignore-file\b").unwrap())
}

/// Parse one source line into a directive, or `None` if it carries
/// none. The file-level form takes precedence over the line form when
/// both could in theory match.
pub fn parse_line(line: &str) -> Option<Directive> {
    if file_re().is_match(line) {
        return Some(Directive::File);
    }
    let cap = line_re().captures(line)?;
    let rules = cap.get(1).map(|m| {
        m.as_str()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    });
    // An empty captured group (e.g. directive with trailing whitespace
    // but no rule) collapses back to "any rule" semantics.
    let rules = match rules {
        Some(v) if v.is_empty() => None,
        v => v,
    };
    Some(Directive::Line { rules })
}

/// True if `line`'s first non-whitespace char begins a comment marker
/// (`//` or `#`). Used to gate preceding-line directive scope per the
/// module-level scope rules.
pub fn is_comment_only_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('#')
}

/// True if `directive` covers `rule_id`.
pub fn matches(directive: &Directive, rule_id: &str) -> bool {
    match directive {
        Directive::File => true,
        Directive::Line { rules: None } => true,
        Directive::Line { rules: Some(ids) } => ids.iter().any(|r| r == rule_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(rules: Option<Vec<&str>>) -> Directive {
        Directive::Line {
            rules: rules.map(|v| v.into_iter().map(String::from).collect()),
        }
    }

    // ── parse_line: line-level forms ─────────────────────────────────────

    #[test]
    fn parses_bare_double_slash_directive_as_any_rule() {
        assert_eq!(parse_line("// arcis-audit: ignore"), Some(line(None)));
    }

    #[test]
    fn parses_bare_hash_directive_as_any_rule_for_python() {
        assert_eq!(parse_line("# arcis-audit: ignore"), Some(line(None)));
    }

    #[test]
    fn parses_single_rule_list() {
        assert_eq!(
            parse_line("// arcis-audit: ignore EVAL-EXEC"),
            Some(line(Some(vec!["EVAL-EXEC"])))
        );
    }

    #[test]
    fn parses_comma_rule_list_with_whitespace_between() {
        assert_eq!(
            parse_line("# arcis-audit: ignore EVAL-EXEC, YAML-UNSAFE , PICKLE-LOAD"),
            Some(line(Some(vec!["EVAL-EXEC", "YAML-UNSAFE", "PICKLE-LOAD"])))
        );
    }

    #[test]
    fn parses_trailing_comment_directive_after_code() {
        // The most common form: trailing comment on a code line.
        assert_eq!(
            parse_line("    result = eval(x)  // arcis-audit: ignore EVAL-EXEC"),
            Some(line(Some(vec!["EVAL-EXEC"])))
        );
    }

    #[test]
    fn parses_trailing_hash_directive_after_python_code() {
        assert_eq!(
            parse_line("    result = eval(x)  # arcis-audit: ignore EVAL-EXEC"),
            Some(line(Some(vec!["EVAL-EXEC"])))
        );
    }

    // ── parse_line: file-level form ──────────────────────────────────────

    #[test]
    fn parses_double_slash_file_directive() {
        assert_eq!(
            parse_line("// arcis-audit: ignore-file"),
            Some(Directive::File)
        );
    }

    #[test]
    fn parses_hash_file_directive() {
        assert_eq!(
            parse_line("# arcis-audit: ignore-file"),
            Some(Directive::File)
        );
    }

    #[test]
    fn file_directive_takes_priority_over_line_directive_form() {
        // `ignore-file` must NOT be parsed as `ignore` with rule `-file`.
        match parse_line("// arcis-audit: ignore-file").unwrap() {
            Directive::File => {}
            other => panic!("expected File directive, got {other:?}"),
        }
    }

    // ── parse_line: rejection cases ──────────────────────────────────────

    #[test]
    fn rejects_non_directive_comment() {
        assert_eq!(parse_line("// regular comment"), None);
        assert_eq!(parse_line("# also regular"), None);
    }

    #[test]
    fn rejects_typo_in_directive_token() {
        // The token must be exactly `arcis-audit:`. `arcis:`, `arcisaudit:`,
        // `arcis-audit ` (no colon) all bounce.
        assert_eq!(parse_line("// arcis: ignore"), None);
        assert_eq!(parse_line("// arcisaudit: ignore"), None);
        assert_eq!(parse_line("// arcis-audit ignore"), None);
    }

    #[test]
    fn rejects_string_literal_with_directive_text_no_comment_marker() {
        // No `//` or `#` anywhere → not a directive even if the body
        // contains the magic words. Prevents string-literal false matches.
        assert_eq!(parse_line(r#"const s = "arcis-audit: ignore EVAL""#), None);
    }

    #[test]
    fn rejects_plain_code_line() {
        assert_eq!(parse_line("result = eval(user_input)"), None);
        assert_eq!(parse_line(""), None);
    }

    // ── is_comment_only_line ─────────────────────────────────────────────

    #[test]
    fn is_comment_only_line_recognises_double_slash() {
        assert!(is_comment_only_line("// hi"));
        assert!(is_comment_only_line("    // hi"));
        assert!(is_comment_only_line("\t// hi"));
    }

    #[test]
    fn is_comment_only_line_recognises_hash() {
        assert!(is_comment_only_line("# hi"));
        assert!(is_comment_only_line("    # hi"));
    }

    #[test]
    fn is_comment_only_line_rejects_inline_comment() {
        // `eval(x) // ...` is NOT a comment-only line.
        assert!(!is_comment_only_line("eval(x) // arcis-audit: ignore"));
        assert!(!is_comment_only_line("eval(x) # arcis-audit: ignore"));
    }

    #[test]
    fn is_comment_only_line_rejects_non_comment_lines() {
        assert!(!is_comment_only_line("eval(x)"));
        assert!(!is_comment_only_line(""));
        assert!(!is_comment_only_line("   "));
    }

    // ── matches ──────────────────────────────────────────────────────────

    #[test]
    fn matches_file_directive_covers_anything() {
        assert!(matches(&Directive::File, "EVAL-EXEC"));
        assert!(matches(&Directive::File, "ANYTHING"));
    }

    #[test]
    fn matches_line_directive_with_no_rules_is_wildcard() {
        assert!(matches(&line(None), "EVAL-EXEC"));
        assert!(matches(&line(None), "YAML-UNSAFE"));
    }

    #[test]
    fn matches_line_directive_only_for_listed_rule() {
        let d = line(Some(vec!["EVAL-EXEC", "YAML-UNSAFE"]));
        assert!(matches(&d, "EVAL-EXEC"));
        assert!(matches(&d, "YAML-UNSAFE"));
        assert!(!matches(&d, "PICKLE-LOAD"));
        assert!(!matches(&d, "XSS-RAW"));
    }

    #[test]
    fn matches_is_case_sensitive_on_rule_id() {
        // Rule IDs in this codebase are uppercase (EVAL-EXEC, etc.).
        // Lowercase / mixed case in a directive is treated as a typo,
        // not a fuzzy match — silent suppression is worse than a missed
        // suppression hint.
        let d = line(Some(vec!["eval-exec"]));
        assert!(!matches(&d, "EVAL-EXEC"));
    }
}
