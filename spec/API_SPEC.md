# Arcis API Specification v1.0

## Overview

This document defines the **language-agnostic API** that all Arcis implementations must follow. Each implementation should feel native to its language while maintaining identical security behavior.

---

## Core Modules

All implementations MUST include these modules:

| Module | Purpose |
|--------|---------|
| `sanitize` | Input sanitization (XSS, SQL, NoSQL, Path, Prototype) |
| `rateLimit` | Rate limiting middleware |
| `headers` | Security headers |
| `validate` | Request validation & schema enforcement |
| `logger` | Safe logging with redaction |
| `errorHandler` | Production-safe error handling |

---

## 1. Sanitizer

### Purpose
Sanitize untrusted input to prevent injection attacks.

### Configuration Options

```
SanitizeOptions {
  xss: boolean      // Default: true - Encode HTML entities, remove dangerous tags
  sql: boolean      // Default: true - Remove SQL injection patterns
  nosql: boolean    // Default: true - Remove MongoDB operator patterns ($gt, $where, etc.)
  path: boolean     // Default: true - Remove path traversal patterns (../)
  proto: boolean    // Default: true - Block prototype pollution keys
}
```

### Functions

#### `sanitize_string(value: string, options?: SanitizeOptions) -> string`
Sanitizes a single string value.

**Behavior:**
- If `xss=true`: Encode `<>&"'` as HTML entities, remove `<script>`, `javascript:`, `on*=` patterns
- If `sql=true`: Remove `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `UNION`, `--`, `/*`
- If `path=true`: Remove `../`, `..\`, `%2e%2e`

#### `sanitize_object(obj: any, options?: SanitizeOptions) -> any`
Recursively sanitizes all string values in an object.

**Behavior:**
- Recursively process nested objects and arrays
- If `proto=true`: Skip keys `__proto__`, `constructor`, `prototype`
- If `nosql=true`: Skip keys starting with `$` (MongoDB operators)

#### `create_sanitizer(options?: SanitizeOptions) -> Middleware`
Creates a middleware that sanitizes `request.body`, `request.query`, and `request.params`.

---

## 2. Rate Limiter

### Purpose
Prevent abuse by limiting requests per client.

### Configuration Options

```
RateLimitOptions {
  max: number           // Default: 100 - Max requests per window
  windowMs: number      // Default: 60000 - Window size in milliseconds
  message: string       // Default: "Too many requests, please try again later."
  keyGenerator: fn      // Default: (req) => req.ip - How to identify clients
  skip: fn              // Default: () => false - Skip rate limiting for certain requests
}
```

### Functions

#### `create_rate_limiter(options?: RateLimitOptions) -> Middleware`

**Behavior:**
- Track requests per key (usually IP address)
- Reset count after `windowMs` milliseconds
- Set response headers:
  - `X-RateLimit-Limit`: Max requests allowed
  - `X-RateLimit-Remaining`: Requests remaining in window
  - `X-RateLimit-Reset`: Seconds until window resets
- If limit exceeded: Return HTTP 429 with JSON error

---

## 3. Security Headers

### Purpose
Add security headers to all responses.

### Configuration Options

```
HeaderOptions {
  contentSecurityPolicy: boolean | string  // Default: true
  xssFilter: boolean                       // Default: true
  noSniff: boolean                         // Default: true
  frameOptions: 'DENY' | 'SAMEORIGIN' | false  // Default: 'DENY'
  hsts: boolean | { maxAge: number, includeSubDomains?: boolean }  // Default: true
}
```

### Functions

#### `create_headers(options?: HeaderOptions) -> Middleware`

**Headers Set (defaults):**
- `Content-Security-Policy: default-src 'self'; script-src 'self'; ...`
- `X-XSS-Protection: 0`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `X-Permitted-Cross-Domain-Policies: none`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), microphone=(), camera=()`

**Headers Removed:**
- `X-Powered-By`

---

## 4. Validator

### Purpose
Validate request data and prevent mass assignment.

### Schema Definition

```
ValidationSchema {
  [fieldName]: {
    type: 'string' | 'number' | 'boolean' | 'email' | 'url' | 'array' | 'object'
    required?: boolean      // Default: false
    min?: number            // Min length (string/array) or min value (number)
    max?: number            // Max length (string/array) or max value (number)
    pattern?: regex         // Regex pattern for strings
    enum?: array            // Allowed values
    sanitize?: boolean      // Default: true - Sanitize string values
  }
}
```

### Functions

#### `validate(schema: ValidationSchema, source?: 'body' | 'query' | 'params') -> Middleware`

**Behavior:**
- Validate each field against its rules
- If validation fails: Return HTTP 400 with `{ errors: [...] }`
- Replace request data with ONLY validated fields (prevents mass assignment)
- Sanitize string fields unless `sanitize: false`

---

## 5. Safe Logger

### Purpose
Log safely without exposing secrets or allowing log injection.

### Configuration Options

```
LogOptions {
  redactKeys: string[]   // Keys to redact (default: password, token, secret, apikey, etc.)
  maxLength: number      // Max string length before truncation (default: 10000)
}
```

### Functions

#### `create_logger(options?: LogOptions) -> Logger`

Returns a logger with methods: `log(level, message, data?)`, `info(...)`, `warn(...)`, `error(...)`

**Behavior:**
- Remove newlines and control characters from strings (prevents log injection)
- Redact values for sensitive keys (replace with `[REDACTED]`)
- Truncate strings longer than `maxLength`
- Output as structured JSON

---

## 6. Error Handler

### Purpose
Handle errors without leaking stack traces in production.

### Functions

#### `create_error_handler(isDev?: boolean) -> ErrorMiddleware`

**Behavior:**
- If `isDev=false` (production): Return generic error message, no stack trace
- If `isDev=true`: Include full error message and stack trace

---

## 7. Main Entry Point

### `arcis(options?: ArcisOptions) -> Middleware[]`

**Options:**
```
ArcisOptions {
  sanitize?: boolean | SanitizeOptions  // Default: true
  rateLimit?: boolean | RateLimitOptions  // Default: true
  headers?: boolean | HeaderOptions  // Default: true
}
```

**Returns:** Array of middlewares in order:
1. Security headers
2. Rate limiter
3. Sanitizer

---

## Attack Patterns Database

### XSS Patterns to Block
```
<script>...</script>
javascript:
on*= (onerror, onclick, etc.)
<iframe
<object
<embed
data:
vbscript:
```

### SQL Injection Patterns to Block
```
SELECT, INSERT, UPDATE, DELETE, DROP, UNION, ALTER, CREATE, TRUNCATE
--, /*, */
;, ||, &&
' OR '1'='1
```

### NoSQL Injection Patterns to Block (in keys)
```
$gt, $gte, $lt, $lte, $ne, $eq
$in, $nin, $and, $or, $not
$exists, $type, $regex, $where, $expr
```

### Path Traversal Patterns to Block
```
../
..\
%2e%2e
%252e
```

### Prototype Pollution Keys to Block
```
__proto__
constructor
prototype
```

---

## 8. Context-Aware Encoding

### Purpose
Encode untrusted input for safe output in specific rendering contexts. A single `sanitize()` is not enough — output embedded in JavaScript, CSS, or HTML attributes requires context-specific encoding to prevent XSS.

### Functions

#### `encode_for_html(value: string) -> string`
HTML body context. Entity-encodes characters that have special meaning in HTML.

**Characters encoded:** `& < > " '`
**Use when:** Outputting to HTML element content (e.g., `<p>{output}</p>`)

#### `encode_for_attribute(value: string) -> string`
HTML attribute context. Encodes all non-alphanumeric characters as hex entities.

**Encoding:** Non-alphanumeric characters → `&#xHH;`
**Use when:** Outputting to HTML attributes (e.g., `<div title="{output}">`)

#### `encode_for_js(value: string) -> string`
JavaScript string context. Escapes characters using `\xHH` or `\uHHHH` notation.

**Encoding:** Non-alphanumeric characters → `\xHH` (ASCII) or `\uHHHH` (Unicode)
**Use when:** Embedding in JS string literals (e.g., `var x = '{output}';`)

#### `encode_for_url(value: string) -> string`
URL parameter context. Percent-encodes characters unsafe for URL components.

**Encoding:** Non-unreserved characters → `%HH`
**Use when:** Building query strings or URL path segments

#### `encode_for_css(value: string) -> string`
CSS value context. Hex-encodes non-alphanumeric characters with CSS escape syntax.

**Encoding:** Non-alphanumeric characters → `\HH `  (trailing space per CSS spec)
**Use when:** Embedding in CSS values (e.g., `content: '{output}';`)

### Guarantees

- All functions are **idempotent** for safe input (alphanumeric strings pass through unchanged)
- Empty string input returns empty string
- All functions work on plain strings — no framework dependencies

---

## Language-Specific Conventions

Each implementation should follow its language's conventions:

| Language | Naming Style | Middleware Pattern |
|----------|--------------|-------------------|
| Node.js | camelCase | Express middleware |
| Python | snake_case | WSGI/ASGI middleware, decorators |
| Java | camelCase | Spring Filter/Interceptor |
| Go | CamelCase (exported) | http.Handler wrapper |
| C# | PascalCase | ASP.NET middleware |
| Rust | snake_case | Tower/Actix middleware |
| PHP | snake_case | PSR-15 middleware |
| C++ | snake_case | Function wrappers |

---

## Version History

- **v1.0** (2024): Initial specification
