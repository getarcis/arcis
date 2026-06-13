/**
 * @module @arcis/node/core/constants
 * Named constants for Arcis - no magic numbers
 */

// =============================================================================
// INPUT LIMITS
// =============================================================================
export const INPUT = {
  /** Default maximum input size (1MB) */
  DEFAULT_MAX_SIZE: 1_000_000,
  /** Maximum recursion depth for nested objects */
  MAX_RECURSION_DEPTH: 10,
} as const;

// =============================================================================
// RATE LIMITING
// =============================================================================
export const RATE_LIMIT = {
  /** Default window size (1 minute) */
  DEFAULT_WINDOW_MS: 60_000,
  /** Default max requests per window */
  DEFAULT_MAX_REQUESTS: 100,
  /** Default HTTP status code for rate limited responses */
  DEFAULT_STATUS_CODE: 429,
  /** Default error message */
  DEFAULT_MESSAGE: 'Too many requests, please try again later.',
  /** Minimum window size (1 second) */
  MIN_WINDOW_MS: 1_000,
  /** Maximum window size (24 hours) */
  MAX_WINDOW_MS: 86_400_000,
} as const;

// =============================================================================
// SECURITY HEADERS
// =============================================================================
export const HEADERS = {
  /** Default Content Security Policy */
  DEFAULT_CSP: [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  /** Default HSTS max age (1 year in seconds) */
  HSTS_MAX_AGE: 31_536_000,
  /** Default X-Frame-Options value */
  FRAME_OPTIONS: 'DENY' as const,
  /** Default X-Content-Type-Options value */
  CONTENT_TYPE_OPTIONS: 'nosniff',
  /** Default Referrer-Policy value */
  REFERRER_POLICY: 'strict-origin-when-cross-origin',
  /** Default Permissions-Policy value */
  PERMISSIONS_POLICY: 'geolocation=(), microphone=(), camera=()',
  /** Default Cache-Control value for security */
  CACHE_CONTROL: 'no-store, no-cache, must-revalidate, proxy-revalidate',
} as const;

// =============================================================================
// XSS PATTERNS (ReDoS-safe)
// =============================================================================

/**
 * Detection patterns — used to flag whether a string contains XSS payloads.
 * Must stay in sync with XSS_REMOVE_PATTERNS below.
 */
export const XSS_PATTERNS = [
  /** Script tags (ReDoS-safe version) */
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /** javascript: protocol. Optional spaces before the colon; requires a
   *  non-space char after it so prose like "JavaScript: Basics" is not flagged
   *  while javascript:alert(1) still is. Mirrors xss-javascript-protocol in
   *  packages/core/patterns.json. */
  /javascript\s*:[^\s]/gi,
  /** vbscript: protocol */
  /vbscript\s*:/gi,
  /** Event handlers (onclick, onerror, etc.) — any separator before attribute */
  /(?:[\s/])on\w+\s*=/gi,
  /** iframe tags */
  /<iframe/gi,
  /** object tags */
  /<object/gi,
  /** embed tags */
  /<embed/gi,
  /** data: URIs (only dangerous ones, avoid false positives) */
  /(?:^|[\s"'=])data:/gi,
  /** URL-encoded script tags */
  /%3Cscript/gi,
  /** SVG with onload */
  /<svg[^>]*onload/gi,
  /** form tags — phishing/credential harvesting via action= redirection */
  /<form[\s>]/gi,
  /** meta tags — http-equiv refresh redirects or CSP bypass */
  /<meta[\s>]/gi,
  /** base href hijacking — redirects all relative URLs to attacker domain */
  /<base[\s>]/gi,
  /** link tag injection — stylesheet or preload CSRF attacks */
  /<link[\s>]/gi,
  /** style tag — CSS expression() / behavior: / IE-era attacks. Mirrors
   *  Python's xss-style-tag from packages/core/patterns.json. */
  /<style[\s>]/gi,
  /** CSS expression() in a style ATTRIBUTE (no <style> tag), e.g.
   *  `<div style="x:expression(alert(1))">`. Legacy IE but still a live
   *  vector on old renderers. Mirrors `xss-css-expression` in
   *  patterns.json. Benchmark xss-style-expression. */
  /expression\s*\(/gi,
] as const;

/**
 * Removal patterns — used by sanitizeXss() to strip dangerous content.
 * More targeted than XSS_PATTERNS: each pattern captures the full dangerous
 * substring (tag, attribute + value, protocol) so it can be replaced safely.
 * Must stay in sync with XSS_PATTERNS above.
 */
export const XSS_REMOVE_PATTERNS = [
  /** Full script blocks (content + tags) */
  /<script[^>]*>[\s\S]*?<\/script>/gi,
  /** Standalone/unclosed script tags */
  /<script[^>]*>/gi,
  /** style — CSS expression() and behavior: attacks (IE-era but still relevant) */
  /<style[^>]*>[\s\S]*?<\/style>/gi,
  /<style[^>]*/gi,
  /** iframe — full block and partial/unclosed */
  /<iframe[^>]*>[\s\S]*?<\/iframe>/gi,
  /<iframe[^>]*/gi,
  /** object — full block and partial/unclosed */
  /<object[^>]*>[\s\S]*?<\/object>/gi,
  /<object[^>]*/gi,
  /** embed tags */
  /<embed[^>]*/gi,
  /** SVG with inline event handlers */
  /<svg[^>]*onload[^>]*>/gi,
  /** URL-encoded script tags */
  /%3Cscript/gi,
  /** Event handlers with quoted values: onclick="...", onerror='...' */
  /(?:[\s/])on\w+\s*=\s*["'][^"']*["']/gi,
  /** Event handlers with unquoted values: onload=value */
  /(?:[\s/])on\w+\s*=\s*[^\s>]*/gi,
  /** javascript: and vbscript: protocols (allow optional spaces before colon) */
  /javascript\s*:/gi,
  /vbscript\s*:/gi,
  /** data: URIs with HTML or SVG content (SVG can run JS via inline event handlers) */
  /data\s*:\s*(?:text\/html|image\/svg)[^>\s]*/gi,
  /** form tag injection — phishing via action= redirection */
  /<form[\s>][^>]*/gi,
  /** meta tag injection — http-equiv refresh or CSP bypass */
  /<meta[\s>][^>]*/gi,
  /** base href hijacking */
  /<base[\s>][^>]*/gi,
  /** link tag injection — stylesheet or preload attacks */
  /<link[\s>][^>]*/gi,
] as const;

// =============================================================================
// SQL INJECTION PATTERNS
// =============================================================================
export const SQL_PATTERNS = [
  /**
   * Multi-token SQL attack shapes that never appear in normal English.
   * Replaces the older bare-keyword pattern `\b(SELECT|INSERT|...)\b`
   * which false-positived on natural language ("please select an option",
   * "I'll update you tomorrow", "delete this file"). Each shape below
   * is a token combination that real attackers use and benign users
   * essentially never type. Matches `sqli-keywords` in
   * packages/core/patterns.json. Benchmark FP class B3, 2026-06-07.
   *
   * Catches:
   *   UNION SELECT / UNION ALL SELECT          (data exfiltration)
   *   DROP|TRUNCATE TABLE|DATABASE|INDEX|...   (DDL destruction)
   *   INTO OUTFILE / INTO DUMPFILE             (MySQL file write RCE)
   *   ATTACH DATABASE                          (SQLite hijack)
   *   CREATE USER|FUNCTION|TRIGGER|PROCEDURE   (privilege escalation)
   *   GRANT ALL|SELECT|INSERT|...              (privilege grant)
   *   xp_cmdshell / sp_executesql              (SQL Server RCE)
   *   SHUTDOWN                                 (DoS)
   */
  /(\bUNION\s+(?:ALL\s+)?SELECT\b)|(\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA)\b)|(\bINTO\s+(?:OUTFILE|DUMPFILE)\b)|(\bATTACH\s+DATABASE\b)|(\bCREATE\s+(?:USER|FUNCTION|TRIGGER|PROCEDURE)\b)|(\bGRANT\s+(?:ALL|SELECT|INSERT|UPDATE|DELETE)\b)|(\bSHUTDOWN\b)|(\bxp_cmdshell\b)|(\bsp_executesql\b)/gi,
  /**
   * SQL comments: ANSI (--), C-style (slash-star ... star-slash).
   * MySQL `#` line comment intentionally excluded: a bare `#` matches
   * every hex color (#FF5300), hashtag (#trending), issue ref (#123),
   * markdown heading (# Title). Real `admin' #`-style injections are
   * already caught by the quote/semicolon + keyword/boolean patterns
   * below — `#` adds nothing as a primary signal and a lot of FP noise.
   * Matches `sqli-comments` rule in packages/core/patterns.json (which
   * also excludes `#`). Benchmark FP class B1, found 2026-06-07.
   */
  /**
   * SQL comments. ANSI `--` requires a trailing space / dash / end-of-string
   * so it matches a real trailing comment (`1=1--`, `-- -`) but not CLI
   * flags like `--max-retries`. The `--` must also not be immediately preceded
   * by `!`, so HTML comments (`<!-- ... -->`) are not flagged as SQL. C-style
   * block comments kept. MySQL `#` excluded (see the quote-anchored rule below).
   * Mirrors `sqli-comments` in packages/core/patterns.json. FPR pass 2026-06-08.
   */
  /((?:^|[^!])--(?:[\s-]|$)|\/\*|\*\/)/g,
  /** Boolean injection: OR 1=1 */
  /\bOR\s+\d+\s*=\s*\d+/gi,
  /** Boolean injection: OR 'a'='a' or OR "a"="a" (including mixed quotes).
   * Trailing close-quote is optional (`\2?`): the classic tautology
   * `1' OR '1'='1` arrives with the final quote unterminated (the app's own
   * closing quote completes it), so this catches `'1'='1` and `'1'='1'`. */
  /\bOR\s+(['"])[^'"]*\1\s*=\s*(['"])[^'"]*\2?/gi,
  /\bOR\s+('[^']*'|"[^"]*")\s*=\s*('[^']*'|"[^"]*")/gi,
  /** Boolean injection: AND 1=1 */
  /\bAND\s+\d+\s*=\s*\d+/gi,
  /** Boolean injection: AND 'a'='a' or AND "a"="a" (including mixed quotes).
   * Trailing close-quote optional, same as the OR case above. */
  /\bAND\s+(['"])[^'"]*\1\s*=\s*(['"])[^'"]*\2?/gi,
  /\bAND\s+('[^']*'|"[^"]*")\s*=\s*('[^']*'|"[^"]*")/gi,
  /** Time-based blind: SLEEP() */
  /\bSLEEP\s*\(\s*\d+\s*\)/gi,
  /** Time-based blind: BENCHMARK() */
  /\bBENCHMARK\s*\(/gi,
  /** Time-based blind: PostgreSQL pg_sleep() */
  /\bpg_sleep\s*\(/gi,
  /** Time-based blind: MSSQL WAITFOR DELAY */
  /\bWAITFOR\s+DELAY\b/gi,
  /**
   * Oracle DBMS_* stdlib packages used for time-based blind SQLi
   * (DBMS_LOCK.SLEEP, DBMS_PIPE.RECEIVE_MESSAGE) and other Oracle
   * abuse paths. No legitimate user input contains these. Mirrors
   * `sqli-oracle-dbms-packages` in packages/core/patterns.json —
   * improvements.md §1.1.e Q3. Must stay in sync until Node
   * migrates to patterns.json-at-runtime (planned v1.7).
   */
  /\bDBMS_(?:LOCK|PIPE|UTILITY|XSLPROCESSOR|JAVA|OUTPUT|SCHEDULER)\b/gi,
  /**
   * Long hex-encoded blob (8+ bytes / 16+ hex chars) used to smuggle a
   * SQL string past keyword filters, e.g. `0x53454C...` = "SELECT...".
   * Far longer than any hex color (#FF5300 is 6). Mirrors `sqli-hex-blob`
   * in patterns.json. Benchmark sql-hex-encoded.
   */
  /\b0x[0-9a-fA-F]{16,}\b/gi,
  /**
   * Single-quote immediately followed by a MySQL `#` line comment
   * (`admin' #`). The quote anchor is what makes `#` safe here — a bare
   * `#` matches hex colors / hashtags / issue refs, but `'` directly
   * before `#` is an injection shape. Mirrors `sqli-comment-quote` in
   * patterns.json. Benchmark sql-comment-hash.
   */
  /'\s*#/g,
] as const;

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================
export const PATH_PATTERNS = [
  /** Unix path traversal */
  /\.\.\//g,
  /** Windows path traversal */
  /\.\.\\/g,
  /** URL-encoded traversal (%2e%2e) */
  /%2e%2e/gi,
  /** Double URL-encoded traversal (%252e) */
  /%252e/gi,
  /** Mixed encoding: ..%2F */
  /\.\.%2F/gi,
  /** Mixed encoding: %2e./ and .%2e/ */
  /%2e\.[\\/]/gi,
  /\.%2e[\\/]/gi,
  /** Fully URL-encoded: %2e%2e%2f */
  /%2e%2e%2f/gi,
  /** Double URL-encoded forward slash: %252f */
  /%252f/gi,
  /** Dotdotslash bypass: ....// or ....\\ */
  /\.{2,}[/\\]{2,}/g,
  /** Null byte injection in paths */
  /\0/g,
  /**
   * Mixed encoding: literal `..` + URL-encoded slash (`..%2F`).
   * Existed in old Node SQL_PATTERNS history; restated explicitly here
   * for parity with patterns.json `path-mixed-encoded`. Benchmark B6.
   */
  /\.\.%2[fF]/g,
  /**
   * Overlong UTF-8 encoding of `.` (`%C0%AE`). Historic IIS/Apache
   * decoder bypass — legitimate `.` is always `%2E`; overlong-form
   * encoding only appears in evasion attempts. Benchmark B6 gap that
   * neither SDK caught before 2026-06-07.
   */
  /%[Cc]0%[Aa][Ee]/g,
  /**
   * Overlong UTF-8 encoding of `/` (`%C0%AF`). Same IIS/Apache decoder
   * bypass class as the overlong dot above. Legitimate `/` is always
   * `%2F`; the overlong form (`..%c0%af..%c0%af`) only appears in
   * evasion. Mirrors `path-overlong-utf8-slash` in patterns.json.
   */
  /%[Cc]0%[Aa][Ff]/g,
  /**
   * Windows UNC paths (`\\server\share`) in user input. Legitimate
   * web-app inputs never contain UNC references; attacker UNC
   * payloads leak SMB auth or pull remote payloads. Benchmark B6.
   */
  /\\\\[A-Za-z0-9_.-]+\\/g,
] as const;

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================
export const COMMAND_PATTERNS = [
  /**
   * Shell command chained after a metacharacter (`; cat`, `| nc`,
   * `& curl`). Replaces the old bare `[;&|`]` rule, which flagged every
   * semicolon in code (`const x = 1;`), ampersand in a URL query
   * (`?a=1&b=2`), and backtick in markdown (`` `npm install` ``). Now the
   * metacharacter must be followed by a known command. FPR pass 2026-06-08.
   */
  /[;&|]\s*(?:cat|ls|dir|rm|cp|mv|wget|curl|nc|ncat|bash|sh|zsh|ksh|chmod|chown|kill|ps|id|touch|ping|dig|su|head|tail|php|sed|whoami|nslookup|nmap|python3?|perl|ruby|node|eval|exec|sudo|telnet|ssh|ftp|tftp|scp|awk|xxd|base64)\b/gi,
  /**
   * Backtick command substitution wrapping a known command (`` `whoami` ``).
   * Avoids the FP on markdown inline code like `` `npm install` ``.
   * FPR pass 2026-06-08.
   */
  /`\s*(?:cat|ls|dir|rm|cp|mv|wget|curl|nc|ncat|bash|sh|zsh|ksh|chmod|chown|kill|ps|id|touch|ping|dig|su|head|tail|php|sed|whoami|nslookup|nmap|python3?|perl|ruby|node|eval|exec|sudo|telnet|ssh|ftp|tftp|scp|awk|xxd|base64)\b/gi,
  /** Command substitution: $( ... ) — matched as a pair to reduce false positives */
  /\$\(/g,
  /**
   * POSIX shell IFS-substitution: ${IFS} or ${IFS%??}.
   * Attackers use this to inject spaces past metacharacter filters
   * in payloads like `;cat${IFS}/etc/passwd`. Mirrors
   * `cmdi-ifs-bypass` in packages/core/patterns.json — improvements.md
   * §1.1.e Q5. Must stay in sync until Node migrates to
   * patterns.json-at-runtime (planned v1.7).
   */
  /\$\{IFS(?:%[^}]*)?\}/g,
  /** URL-encoded control characters (%00-%0F): null, tab, vtab, formfeed, LF, CR */
  /%0[0-9a-f]/gi,
  /**
   * Dangerous environment-variable assignment used to smuggle code into
   * a spawned process (`LD_PRELOAD=/tmp/evil.so /bin/ls`). Mirrors
   * `cmdi-env-assign` in patterns.json. Benchmark cmd-env-var-smuggling.
   */
  /\b(?:LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|PYTHONPATH|PERL5LIB|DYLD_INSERT_LIBRARIES)\s*=/gi,
  /**
   * Shell output redirect to a system directory (`> /var/www/shell.php`).
   * Anchored to known system dirs so math/text (`5 > 3`) doesn't trip it.
   * Mirrors `cmdi-redirect-syspath` in patterns.json. Benchmark
   * cmd-redirect-overwrite.
   */
  />\s*\/(?:etc|var|tmp|usr|bin|sbin|root|home|dev|proc|opt)\b/g,
  /**
   * Newline followed by a shell command (`host\ncat /etc/passwd`) —
   * argument-to-command injection via an embedded newline. Mirrors
   * `cmdi-newline-command` in patterns.json. Benchmark cmd-newline-injection.
   */
  /[\n\r]\s*(?:cat|ls|dir|rm|cp|mv|wget|curl|nc|ncat|bash|sh|zsh|ksh|chmod|chown|kill|ps|id|touch|ping|dig|su|head|tail|php|sed|whoami|nslookup|nmap|python3?|perl|ruby|node|eval|exec|sudo|telnet|ssh|ftp|tftp|scp|awk|xxd|base64)\b/gi,
  /**
   * JNDI lookup used by Log4Shell, e.g. `${jndi:ldap://attacker/a}`.
   * Mirrors `cmdi-jndi-lookup` in packages/core/patterns.json.
   */
  /\$\{jndi:/gi,
  /**
   * Server-side include (SSI) directive, e.g. `<!--#exec cmd="id"-->`. The
   * directive keyword after `#` keeps benign comments like `<!-- #note -->`
   * from matching. Mirrors `cmdi-ssi-directive` in packages/core/patterns.json.
   */
  /<!--\s*#\s*(?:exec|include|echo|config|fsize|flastmod|printenv)\b/gi,
] as const;

// =============================================================================
// DANGEROUS KEYS
// =============================================================================

/**
 * Prototype pollution keys to block.
 * Stored lowercase — always compare with key.toLowerCase().
 *
 * Includes:
 * - __proto__: direct prototype assignment
 * - constructor: access to constructor.prototype chain
 * - prototype: direct prototype property
 * - __defineGetter__/__defineSetter__: legacy property definition (can override getters/setters)
 * - __lookupGetter__/__lookupSetter__: legacy property introspection
 */
export const DANGEROUS_PROTO_KEYS = new Set([
  '__proto__',
  'constructor',
  'prototype',
  '__definegetter__',
  '__definesetter__',
  '__lookupgetter__',
  '__lookupsetter__',
]);

/** MongoDB operators to block */
export const NOSQL_DANGEROUS_KEYS = new Set([
  // Comparison
  '$gt', '$gte', '$lt', '$lte', '$ne', '$eq', '$in', '$nin',
  // Logical
  '$and', '$or', '$not', '$nor',
  // Element / evaluation
  '$exists', '$type', '$regex', '$where', '$expr', '$mod', '$text', '$jsonSchema',
  // Array
  '$elemMatch', '$all', '$size',
  // JavaScript execution (critical)
  '$function', '$accumulator',
  // Aggregation pipeline operators (injectable via $lookup etc.)
  '$lookup', '$match', '$project', '$group', '$sort', '$limit', '$skip',
  '$unwind', '$addFields', '$replaceRoot',
]);

/**
 * String-form NoSQL operator detection (block-mode scanThreats).
 *
 * NOSQL_DANGEROUS_KEYS catches operators that arrive as OBJECT KEYS
 * (`{"$gt": ""}`). But MongoDB operators also bypass as STRING VALUES —
 * query params like `?username[$ne]=1` arrive as the literal string
 * `$ne` before the body parser ever builds an object, and mongo-shell
 * payloads (`$where: '1==1'`) are plain strings. Node previously had no
 * string-level NoSQL check, so GoTestWAF scored NoSQL at 0% while Python
 * (which loads the shared `nosql-operators` rule) caught these. This
 * closes that Pattern-7 parity gap.
 *
 * Mirrors `nosql-operators` in packages/core/patterns.json. The trailing
 * `\b` is the word boundary that keeps `$invoice`/`$order`/`$index` from
 * matching `$in`/`$or` (a false-positive class the un-bounded rule had).
 * Keep in sync until Node migrates to patterns.json-at-runtime.
 */
export const NOSQL_STRING_PATTERN =
  /\$(?:gt|gte|lt|lte|ne|eq|in|nin|and|or|not|nor|exists|type|regex|where|expr|mod|text|jsonSchema|function|accumulator|elemMatch|all|size|lookup|match|project|group|sort|limit|skip|unwind|addFields|replaceRoot)\b/i;

/**
 * Identity/auth field names that must hold a scalar value. A field here
 * carrying an array or object is a NoSQL type-juggling operator-injection
 * shape (e.g. {"username":["admin"]}). v1.7 nosql-type-juggle.
 */
export const AUTH_FIELDS = new Set([
  'username', 'user', 'userid', 'user_id', 'login', 'email',
  'password', 'pass', 'passwd', 'pwd', 'token', 'apikey', 'api_key',
  'secret', 'otp', 'pin',
]);

// =============================================================================
// REDACTION
// =============================================================================
export const REDACTION = {
  /** Replacement text for redacted values */
  REPLACEMENT: '[REDACTED]',
  /** Truncation indicator */
  TRUNCATED: '[TRUNCATED]',
  /** Max depth indicator */
  MAX_DEPTH: '[MAX_DEPTH]',
  /** Default max message length */
  DEFAULT_MAX_LENGTH: 10_000,
  /** Default sensitive keys to redact */
  SENSITIVE_KEYS: new Set([
    'password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
    'api_key', 'apiKey', 'auth', 'authorization', 'credit_card',
    'creditcard', 'cc', 'ssn', 'social_security', 'private_key',
    'privateKey', 'access_token', 'accessToken', 'refresh_token',
    'refreshToken', 'bearer', 'jwt', 'session', 'cookie',
    'credentials', 'x-api-key', 'x-auth-token',
  ]),
} as const;

// =============================================================================
// VALIDATION PATTERNS
// =============================================================================
export const VALIDATION = {
  /**
   * Email regex pattern.
   * Rejects consecutive dots in local part (e.g. test..foo@example.com),
   * leading/trailing dots, and other common invalid forms.
   */
  EMAIL: /^[^\s@.][^\s@]*(?:\.[^\s@.][^\s@]*)*@[^\s@]+\.[^\s@]+$/,
  /**
   * URL regex pattern.
   * Only allows http:// and https:// (case-insensitive scheme per
   * RFC 3986); explicitly rejects javascript:, data:, vbscript:, and
   * other dangerous URI schemes.
   */
  URL: /^https?:\/\/[^\s/$.?#][^\s]*$/i,
  /** UUID regex pattern (v4) */
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
} as const;

// =============================================================================
// ERROR MESSAGES
// =============================================================================
export const ERRORS = {
  /** Generic error message (production) */
  INTERNAL_SERVER_ERROR: 'Internal Server Error',
  /** Input too large error */
  INPUT_TOO_LARGE: (maxSize: number) => `Input exceeds maximum size of ${maxSize} bytes`,
  /** Validation error messages */
  VALIDATION: {
    REQUIRED: (field: string) => `${field} is required`,
    INVALID_TYPE: (field: string, type: string) => `${field} must be a ${type}`,
    MIN_LENGTH: (field: string, min: number) => `${field} must be at least ${min} characters`,
    MAX_LENGTH: (field: string, max: number) => `${field} must be at most ${max} characters`,
    MIN_VALUE: (field: string, min: number) => `${field} must be at least ${min}`,
    MAX_VALUE: (field: string, max: number) => `${field} must be at most ${max}`,
    INVALID_FORMAT: (field: string) => `${field} format is invalid`,
    INVALID_EMAIL: (field: string) => `${field} must be a valid email`,
    INVALID_URL: (field: string) => `${field} must be a valid URL`,
    INVALID_UUID: (field: string) => `${field} must be a valid UUID`,
    INVALID_ENUM: (field: string, values: unknown[]) => `${field} must be one of: ${values.join(', ')}`,
    MIN_ITEMS: (field: string, min: number) => `${field} must have at least ${min} items`,
    MAX_ITEMS: (field: string, max: number) => `${field} must have at most ${max} items`,
  },
} as const;

// =============================================================================
// BLOCKED TEXT (for sanitizer replacements)
// =============================================================================
export const BLOCKED = '[BLOCKED]' as const;
