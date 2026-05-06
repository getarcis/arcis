//! Audit rule registry.
//!
//! Direct port of the `Rule` dataclass and `RULES` table from
//! `packages/arcis-python/arcis/cli/audit.py`. 23 rules total: 14
//! original (v1.4.0) + 9 Phase B (v1.5.0).
//!
//! Patterns are stored as `&'static str` and compiled lazily into a
//! `Vec<Rule>` cached in a `OnceLock`. First call to [`rules`] pays the
//! compile cost; subsequent calls are pointer reads.
//!
//! The Python source uses `re.IGNORECASE` for two rules
//! (`WEAK-RANDOM-FOR-SECURITY`, `SECRET-IN-LOG`); we translate that to
//! the inline `(?i)` flag rather than carrying a separate flag column,
//! which keeps the spec table flat.

use std::sync::OnceLock;

use regex::Regex;

// ── Severity ────────────────────────────────────────────────────────────────

/// Finding severity. Variant order encodes the Python severity_key dict
/// (`{"critical": 0, "high": 1, "medium": 2, "low": 3}`) — `derive(Ord)`
/// matches that ordering for free, so sort comparisons against it stay
/// byte-equal with Python's `sorted(... key=severity_key.get)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub const ALL: [Severity; 4] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

// ── Language ────────────────────────────────────────────────────────────────

/// Source language. Mirrors `LANGUAGE_MAP` keys in `audit.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Python,
    JavaScript,
    TypeScript,
}

impl Language {
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Python => "python",
            Language::JavaScript => "javascript",
            Language::TypeScript => "typescript",
        }
    }

    pub fn parse(s: &str) -> Option<Language> {
        match s.to_ascii_lowercase().as_str() {
            "python" => Some(Language::Python),
            "javascript" => Some(Language::JavaScript),
            "typescript" => Some(Language::TypeScript),
            _ => None,
        }
    }

    /// Map a file extension (with or without leading `.`) to a language.
    /// Matches `LANGUAGE_MAP` in `audit.py`:
    ///   .py → python
    ///   .js / .mjs / .cjs / .jsx → javascript
    ///   .ts / .tsx → typescript
    pub fn from_extension(ext: &str) -> Option<Language> {
        let trimmed = ext.strip_prefix('.').unwrap_or(ext).to_ascii_lowercase();
        match trimmed.as_str() {
            "py" => Some(Language::Python),
            "js" | "mjs" | "cjs" | "jsx" => Some(Language::JavaScript),
            "ts" | "tsx" => Some(Language::TypeScript),
            _ => None,
        }
    }
}

// ── Rule registry ───────────────────────────────────────────────────────────

/// Immutable rule spec — what's listed in the source table.
struct RuleSpec {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    pattern: &'static str,
    languages: &'static [Language],
    safe_pattern: Option<&'static str>,
}

/// Compiled rule. The patterns are eagerly compiled once at startup
/// (via [`rules`]) so per-line scanning never pays compile cost.
pub struct Rule {
    pub id: &'static str,
    pub severity: Severity,
    pub message: &'static str,
    pub pattern: Regex,
    pub languages: &'static [Language],
    /// If a line matches `pattern` but ALSO matches `safe_pattern`, the
    /// finding is suppressed. Mirrors the `safe_pattern` exemption in
    /// `audit.py:scan_file` (`yaml.load(..., Loader=SafeLoader)` etc).
    pub safe_pattern: Option<Regex>,
}

const PY: &[Language] = &[Language::Python];
const JS_TS: &[Language] = &[Language::JavaScript, Language::TypeScript];
const TS_ONLY: &[Language] = &[Language::TypeScript];
const PY_JS_TS: &[Language] = &[Language::Python, Language::JavaScript, Language::TypeScript];
const JS_TS_PY: &[Language] = &[Language::JavaScript, Language::TypeScript, Language::Python];

const RULE_SPECS: &[RuleSpec] = &[
    // ── Python rules ────────────────────────────────────────────────────
    RuleSpec {
        id: "YAML-UNSAFE",
        severity: Severity::High,
        message: "yaml.load() without SafeLoader \u{2014} use yaml.safe_load() or yaml.load(data, Loader=SafeLoader)",
        pattern: r"\byaml\.load\s*\(",
        languages: PY,
        safe_pattern: Some(r"yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader"),
    },
    RuleSpec {
        id: "SHELL-TRUE",
        severity: Severity::High,
        message: "subprocess call with shell=True \u{2014} use shell=False with a list of arguments",
        pattern: r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
        languages: PY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "PICKLE-LOAD",
        severity: Severity::Critical,
        message: "pickle.loads() / pickle.load() on potentially untrusted data \u{2014} use JSON or a safe serialization format",
        pattern: r"\bpickle\.loads?\s*\(",
        languages: PY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "EVAL-EXEC",
        severity: Severity::Critical,
        message: "eval() or exec() detected \u{2014} avoid dynamic code execution on user input",
        pattern: r"\b(?:eval|exec)\s*\(",
        languages: PY_JS_TS,
        safe_pattern: None,
    },

    // ── JavaScript / TypeScript rules ──────────────────────────────────
    RuleSpec {
        id: "INNERHTML",
        severity: Severity::High,
        message: ".innerHTML assignment \u{2014} use textContent or a sanitization library",
        pattern: r"\.innerHTML\s*=",
        languages: JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "DOCUMENT-WRITE",
        severity: Severity::High,
        message: "document.write() detected \u{2014} use DOM manipulation instead",
        pattern: r"\bdocument\.write(?:ln)?\s*\(",
        languages: JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "ANGULAR-TRUST",
        severity: Severity::High,
        message: "bypassSecurityTrust*() \u{2014} verify the input is truly trusted before bypassing Angular sanitization",
        pattern: r"\bbypassSecurityTrust(?:Html|Style|Script|Url|ResourceUrl)\s*\(",
        languages: TS_ONLY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "JWT-NO-ALG",
        severity: Severity::High,
        message: "jwt.verify() / jwt.decode() without explicit algorithms \u{2014} always specify algorithms to prevent alg:none attacks",
        pattern: r"\bjwt\.(?:verify|decode)\s*\(",
        languages: JS_TS,
        safe_pattern: Some(r"jwt\.(?:verify|decode)\s*\([^)]*algorithms"),
    },

    // ── Cross-language rules ────────────────────────────────────────────
    RuleSpec {
        id: "JSONP-CALLBACK",
        severity: Severity::Medium,
        message: "JSONP callback parameter detected \u{2014} validate callback names with sanitizeJsonpCallback()",
        pattern: r#"(?:request\.(?:args|query|GET)\.get\s*\(\s*["']callback["']|req\.query\.callback|params\[["']callback["']\])"#,
        languages: PY_JS_TS,
        safe_pattern: None,
    },

    // ── New rules (v1.4.0) ─────────────────────────────────────────────
    RuleSpec {
        id: "SQL-CONCAT",
        severity: Severity::Critical,
        message: "SQL query built with string concatenation \u{2014} use parameterized queries to prevent SQL injection",
        pattern: r#"(?:cursor\.execute|db\.execute|connection\.execute|conn\.execute|query\.execute)\s*\(\s*(?:f["']|["'][^"']*["']\s*\+|["'][^"']*\+|["'][^"']*%\s*(?:request|req|params|data|input|user))"#,
        languages: PY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "ORM-RAW",
        severity: Severity::High,
        message: "Raw ORM query detected \u{2014} verify no user input is interpolated into this query",
        pattern: r#"(?:\$queryRaw|\.query\s*\(\s*["'`]|\bsequelize\.query\s*\(|typeorm.*\.query\s*\(|knex\.raw\s*\()"#,
        languages: JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "FS-USER-PATH",
        severity: Severity::High,
        message: "File system operation with potentially user-controlled path \u{2014} use path.resolve() and validate against allowed directories",
        pattern: r#"(?:fs\.(?:readFile|writeFile|appendFile|readFileSync|writeFileSync|unlink|unlinkSync|stat|statSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)|open\s*\(\s*(?:request\.|req\.|f["'].*\+))"#,
        languages: JS_TS_PY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "FETCH-USER-URL",
        severity: Severity::High,
        message: "HTTP request with potentially user-controlled URL \u{2014} validate with validateUrl() to prevent SSRF",
        pattern: r"(?:fetch\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`[^`]*\$\{)|(?:http|https|axios|got|superagent)\.(?:get|post|request)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)|requests\.(?:get|post|request)\s*\(\s*(?:request\.|req\.))",
        languages: JS_TS_PY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "UNSAFE-DESERIALIZE",
        severity: Severity::Critical,
        message: "Unsafe deserialization detected \u{2014} never deserialize untrusted data with marshal, shelve, or jsonpickle",
        pattern: r"\b(?:marshal\.loads?\s*\(|shelve\.open\s*\(|jsonpickle\.decode\s*\()",
        languages: PY,
        safe_pattern: None,
    },

    // ── Phase B rules (v1.5.0) ─────────────────────────────────────────
    RuleSpec {
        id: "HARDCODED-SECRET",
        severity: Severity::High,
        message: "Hardcoded credential pattern detected \u{2014} move secrets to environment variables, never commit to source",
        pattern: r"(?:AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36,}|gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82}|sk_live_[A-Za-z0-9]{24,}|rk_live_[A-Za-z0-9]{24,}|xox[bpoa]-[A-Za-z0-9\-]{10,}|-----BEGIN (?:RSA|EC|DSA|PGP|OPENSSH) PRIVATE KEY-----)",
        languages: PY_JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "WEAK-CRYPTO",
        severity: Severity::High,
        message: "MD5 or SHA-1 used for hashing \u{2014} vulnerable to collisions; use SHA-256+ for passwords / signatures / integrity",
        pattern: r#"(?:hashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|crypto\.createCipher\s*\(\s*['"](?:des|des-ede|rc4)['"])"#,
        languages: PY_JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "WEAK-RANDOM-FOR-SECURITY",
        severity: Severity::High,
        message: "Math.random() / random.random() assigned to a security-named variable \u{2014} use crypto.randomBytes / secrets.token_hex for tokens, secrets, keys",
        pattern: r"(?i)\b\w*(?:csrf|token|secret|password|passwd|nonce|otp|salt|session|api_?key|access_?key|jwt)\w*\s*=\s*(?:Math\.random|random\.random|random\.randint|random\.choice|random\.sample|random\.uniform)\s*\(",
        languages: PY_JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "INSECURE-REDIRECT",
        severity: Severity::Medium,
        message: "Redirect to user-controlled URL \u{2014} validate against an allowed-host list (Arcis: validateUrl() / validate_redirect())",
        pattern: r"(?:\bres\.redirect\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|`\$\{|\$\{)|\bredirect\s*\(\s*(?:request\.(?:GET|POST|args|form|query)|req\.|params\.))",
        languages: PY_JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "XML-EXTERNAL-ENTITY",
        severity: Severity::High,
        message: "XML parser without secure config \u{2014} disable external entities (lxml: resolve_entities=False, no_network=True; xml2js: secure mode)",
        pattern: r"(?:lxml\.etree\.parse\s*\(|xml\.dom\.minidom\.parse\s*\(|xml\.etree\.ElementTree\.parse\s*\(|new\s+(?:xml2js\.Parser|XMLParser|DOMParser)\s*\()",
        languages: PY_JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "SECRET-IN-LOG",
        severity: Severity::High,
        message: "Logging output references a credential-named variable \u{2014} credentials in logs leak via aggregators / stdout / disk",
        pattern: r"(?i)(?:console\.(?:log|info|debug|warn|error)|logger?\.(?:log|info|debug|warn|error)|\bprint)\s*\([^)]*\b(?:password|passwd|secret|token|api_?key|access_?key|private_?key|auth_?token|client_?secret|bearer)\b",
        languages: PY_JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "JWT-WEAK-SECRET",
        severity: Severity::High,
        message: "jwt.sign() with a hardcoded or fallback string secret \u{2014} load JWT secrets from a managed secret store; never bake them into source",
        pattern: r#"\bjwt\.sign\s*\([^,)]+,\s*(?:["'][^"']*["']|[^,)]*\|\|\s*["'][^"']+["'])"#,
        languages: JS_TS,
        safe_pattern: None,
    },
    RuleSpec {
        id: "MASS-ASSIGNMENT",
        severity: Severity::Medium,
        message: "Bulk-assigning request body / params to a model \u{2014} attacker can set fields like is_admin / role; whitelist allowed fields explicitly",
        pattern: r"(?:Object\.assign\s*\([^,)]+,\s*(?:req\.|request\.|params\.|query\.|body\.)|setattr\s*\([^,)]+,\s*\*\*\s*(?:request\.|req\.))",
        languages: JS_TS_PY,
        safe_pattern: None,
    },
    RuleSpec {
        id: "PATH-CONFUSION",
        severity: Severity::High,
        message: "path.join() with user-controlled segment \u{2014} attacker can break out with ../; use path.resolve() and assert the result is under the allowed base",
        pattern: r"(?:\bpath\.join\s*\([^,)]+,\s*(?:req\.|request\.|params\.|query\.|body\.)|\bos\.path\.join\s*\([^,)]+,\s*(?:request\.(?:GET|POST|args|form|query)|req\.|params\.))",
        languages: PY_JS_TS,
        safe_pattern: None,
    },
];

// ── Lazy compilation ────────────────────────────────────────────────────────

static COMPILED: OnceLock<Vec<Rule>> = OnceLock::new();

/// Return the full compiled rule list. First call compiles all 23 regex
/// patterns; subsequent calls return the cached slice.
pub fn rules() -> &'static [Rule] {
    COMPILED.get_or_init(compile_all).as_slice()
}

fn compile_all() -> Vec<Rule> {
    RULE_SPECS
        .iter()
        .map(|spec| Rule {
            id: spec.id,
            severity: spec.severity,
            message: spec.message,
            pattern: Regex::new(spec.pattern)
                .unwrap_or_else(|e| panic!("rule {} pattern failed to compile: {}", spec.id, e)),
            languages: spec.languages,
            safe_pattern: spec.safe_pattern.map(|p| {
                Regex::new(p).unwrap_or_else(|e| {
                    panic!("rule {} safe_pattern failed to compile: {}", spec.id, e)
                })
            }),
        })
        .collect()
}

/// Apply the optional language filter Python's `--language` flag uses:
/// keep rules that include the requested language. With `None`, returns
/// every rule.
pub fn rules_for(lang: Option<Language>) -> Vec<&'static Rule> {
    match lang {
        None => rules().iter().collect(),
        Some(l) => rules()
            .iter()
            .filter(|r| r.languages.contains(&l))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Severity ────────────────────────────────────────────────────────

    #[test]
    fn severity_ordering_matches_python_severity_key() {
        // Python: {"critical": 0, "high": 1, "medium": 2, "low": 3}.
        // Rust: derive(Ord) over declaration order.
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
    }

    #[test]
    fn severity_str_round_trip() {
        for s in Severity::ALL {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
        assert_eq!(Severity::parse("nope"), None);
    }

    // ── Language ────────────────────────────────────────────────────────

    #[test]
    fn language_parse() {
        assert_eq!(Language::parse("python"), Some(Language::Python));
        assert_eq!(Language::parse("Python"), Some(Language::Python));
        assert_eq!(Language::parse("javascript"), Some(Language::JavaScript));
        assert_eq!(Language::parse("typescript"), Some(Language::TypeScript));
        assert_eq!(Language::parse("rust"), None);
    }

    #[test]
    fn language_from_extension_matches_python_map() {
        // Mirrors LANGUAGE_MAP in audit.py:
        //   .py → python
        //   .js / .mjs / .cjs / .jsx → javascript
        //   .ts / .tsx → typescript
        let cases = [
            (".py", Some(Language::Python)),
            ("py", Some(Language::Python)),
            (".PY", Some(Language::Python)),
            (".js", Some(Language::JavaScript)),
            (".mjs", Some(Language::JavaScript)),
            (".cjs", Some(Language::JavaScript)),
            (".jsx", Some(Language::JavaScript)),
            (".ts", Some(Language::TypeScript)),
            (".tsx", Some(Language::TypeScript)),
            (".rs", None),
            (".go", None),
            ("", None),
        ];
        for (ext, expected) in cases {
            assert_eq!(Language::from_extension(ext), expected, "ext={}", ext);
        }
    }

    // ── Rule registry ──────────────────────────────────────────────────

    #[test]
    fn rule_count_matches_python() {
        // 14 original (v1.4.0) + 9 Phase B (v1.5.0) = 23.
        assert_eq!(rules().len(), 23);
    }

    #[test]
    fn all_rule_ids_are_unique() {
        let mut ids: Vec<&str> = rules().iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "duplicate rule id detected");
    }

    #[test]
    fn all_rule_patterns_compile() {
        // Forces compile_all() to run. If any pattern is invalid, this
        // panics with the rule id in the message.
        let _ = rules();
    }

    #[test]
    fn rules_for_python_filter() {
        let py_rules = rules_for(Some(Language::Python));
        assert!(py_rules
            .iter()
            .all(|r| r.languages.contains(&Language::Python)));
        // YAML-UNSAFE is python-only and should appear.
        assert!(py_rules.iter().any(|r| r.id == "YAML-UNSAFE"));
        // INNERHTML is JS/TS-only and should NOT appear.
        assert!(!py_rules.iter().any(|r| r.id == "INNERHTML"));
    }

    #[test]
    fn rules_for_none_returns_all() {
        assert_eq!(rules_for(None).len(), rules().len());
    }

    // ── Spot-checks: each rule fires on a known-positive line ──────────
    //
    // Not exhaustive — those live in `tests/cli/test_audit.py` on the
    // Python side and parity fixtures over here. These guard against
    // regex-translation typos: if a Rust raw-string boundary loses a `\`
    // or an alternation arm, the corresponding case here breaks.

    #[test]
    fn yaml_unsafe_fires_and_safe_pattern_exempts() {
        let r = rules().iter().find(|r| r.id == "YAML-UNSAFE").unwrap();
        assert!(r.pattern.is_match("data = yaml.load(f)"));
        // Same line satisfies safe_pattern → caller suppresses.
        let safe = r.safe_pattern.as_ref().unwrap();
        assert!(safe.is_match("yaml.load(f, Loader=SafeLoader)"));
        assert!(safe.is_match("yaml.load(f, Loader=yaml.SafeLoader)"));
    }

    #[test]
    fn shell_true_fires() {
        let r = rules().iter().find(|r| r.id == "SHELL-TRUE").unwrap();
        assert!(r.pattern.is_match("subprocess.run(cmd, shell=True)"));
        assert!(r
            .pattern
            .is_match("subprocess.Popen(['x'], shell=True, env=e)"));
        assert!(!r.pattern.is_match("subprocess.run(['ls'])"));
    }

    #[test]
    fn pickle_load_fires_on_loads_and_load() {
        let r = rules().iter().find(|r| r.id == "PICKLE-LOAD").unwrap();
        assert!(r.pattern.is_match("pickle.loads(data)"));
        assert!(r.pattern.is_match("pickle.load(f)"));
    }

    #[test]
    fn eval_exec_fires() {
        let r = rules().iter().find(|r| r.id == "EVAL-EXEC").unwrap();
        assert!(r.pattern.is_match("eval(user_input)"));
        assert!(r.pattern.is_match("exec(code)"));
    }

    #[test]
    fn innerhtml_fires() {
        let r = rules().iter().find(|r| r.id == "INNERHTML").unwrap();
        assert!(r.pattern.is_match("el.innerHTML = userInput"));
    }

    #[test]
    fn jwt_no_alg_safe_pattern_exempts_when_algorithms_listed() {
        let r = rules().iter().find(|r| r.id == "JWT-NO-ALG").unwrap();
        assert!(r.pattern.is_match("jwt.verify(token, secret)"));
        let safe = r.safe_pattern.as_ref().unwrap();
        assert!(safe.is_match("jwt.verify(token, secret, { algorithms: ['RS256'] })"));
    }

    #[test]
    fn hardcoded_secret_catches_aws_key_and_pem() {
        let r = rules().iter().find(|r| r.id == "HARDCODED-SECRET").unwrap();
        let aws = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP");
        assert!(r.pattern.is_match(&aws));
        assert!(r.pattern.is_match("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!r.pattern.is_match("just some random text"));
    }

    #[test]
    fn weak_crypto_fires_case_sensitively_on_md5_sha1() {
        let r = rules().iter().find(|r| r.id == "WEAK-CRYPTO").unwrap();
        assert!(r.pattern.is_match("hashlib.md5(b'x')"));
        assert!(r.pattern.is_match("hashlib.sha1(data)"));
        assert!(r.pattern.is_match(r#"createHash("md5")"#));
    }

    #[test]
    fn weak_random_for_security_uses_case_insensitive() {
        // Pattern carries (?i). `Token = random.random()` should match
        // even though `Token` is not lowercase.
        let r = rules()
            .iter()
            .find(|r| r.id == "WEAK-RANDOM-FOR-SECURITY")
            .unwrap();
        assert!(r.pattern.is_match("Token = random.random()"));
        assert!(r.pattern.is_match("api_key = Math.random()"));
        assert!(!r.pattern.is_match("price = random.random()"));
    }

    #[test]
    fn secret_in_log_uses_case_insensitive() {
        let r = rules().iter().find(|r| r.id == "SECRET-IN-LOG").unwrap();
        assert!(r
            .pattern
            .is_match("console.log('user password is', password)"));
        assert!(r.pattern.is_match("logger.info(f'token={api_key}')"));
        assert!(r.pattern.is_match("print(secret)"));
    }

    #[test]
    fn jsonp_callback_handles_quote_styles() {
        let r = rules().iter().find(|r| r.id == "JSONP-CALLBACK").unwrap();
        assert!(r.pattern.is_match(r#"request.args.get("callback")"#));
        assert!(r.pattern.is_match("request.args.get('callback')"));
        assert!(r.pattern.is_match("req.query.callback"));
        assert!(r.pattern.is_match(r#"params["callback"]"#));
    }
}
