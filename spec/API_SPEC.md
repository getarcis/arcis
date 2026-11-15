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
  block: boolean    // Default: false - When true, scan body/query/path for attacks and
                    //                   respond 403 with { code: "SECURITY_THREAT", vector }
                    //                   instead of silently sanitizing. Writes telemetry
                    //                   marker (decision=deny) for dashboard attribution.
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

#### Detection helpers (block-mode primitives)

All three SDKs expose pure detection functions that return `true` on threat
without modifying input. These power `block: true` mode.

- `detect_xss(value: string) -> bool`
- `detect_sql(value: string) -> bool`
- `detect_path_traversal(value: string) -> bool`
- `detect_command_injection(value: string) -> bool`
- `detect_nosql(data) -> bool` — walks string/dict/list, matches MongoDB operators
- `detect_prototype_pollution(data) -> bool` — walks dict/list for `__proto__`, `constructor`, etc.
- `scan_threats(data) -> ThreatHit | None` — walks any value, returns the first
  `(vector, rule, matched_pattern)` triple. Vector ordering matches across SDKs:
  key-based `prototype` → `nosql` (any nesting), then per-string
  `xss` → `ssti` → `xxe` → `sql` → `path` → `command` → `nosql`.

  **NOT scanned at the request boundary** (sink-context vectors that produce
  too many false positives on arbitrary body strings):
  - `ldap` — LDAP filter metacharacters `*()` appear in nearly every string
  - `header` — CRLF/null bytes are only attacks when reflected into a
    response header. Use `detect_header_injection` at the response-write
    site, not on inbound request bodies.

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

The defaults above are the `legacy` profile, which stays the default
throughout 1.x so existing applications see no change.

### Baseline profile (Helmet 8 compatible)

`profile: "baseline"` selects defaults and options that match Helmet 8.3.0,
plus Arcis extensions. Every SDK must produce the same headers for the same
options. `TEST_VECTORS.json` → `security_headers.baseline` holds the shared
cases; cases marked `helmet_compatible` were generated by running Helmet, and
the Node suite re-checks them against Helmet on every run.

**Default headers (no options):**

```
Content-Security-Policy: default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
```

`X-Powered-By` is removed. Not set by default: `Cross-Origin-Embedder-Policy`
(breaks third-party embeds), `Permissions-Policy`, `Reporting-Endpoints`,
`Cache-Control`, `Pragma`, `Expires`. HSTS is sent on every response, as in
Helmet; browsers ignore it over plain HTTP (RFC 6797 section 8.1).

**Options.** Each option accepts: omitted or `true` (default on), `false` (off),
or a configuration object. Exception: `crossOriginEmbedderPolicy` is off unless
set; `true` sends `require-corp`.

| Option (Node) | Legacy alias | Configuration |
| --- | --- | --- |
| `contentSecurityPolicy` | | `useDefaults` (true), `directives`, `reportOnly` (false), `nonce` (false, Arcis) |
| `crossOriginEmbedderPolicy` | | `policy`: `require-corp`, `credentialless`, `unsafe-none` |
| `crossOriginOpenerPolicy` | | `policy`: `same-origin`, `same-origin-allow-popups`, `noopener-allow-popups`, `unsafe-none` |
| `crossOriginResourcePolicy` | | `policy`: `same-origin`, `same-site`, `cross-origin` |
| `originAgentCluster` | | none |
| `referrerPolicy` | | `policy`: token or list of tokens, joined with `,` |
| `strictTransportSecurity` | `hsts` | `maxAge` (31536000, floored, `0` allowed), `includeSubDomains` (true), `preload` (false) |
| `xContentTypeOptions` | `noSniff` | none |
| `xDnsPrefetchControl` | `dnsPrefetchControl` | `allow` (false gives `off`, true gives `on`) |
| `xDownloadOptions` | `ieNoOpen` | none |
| `xFrameOptions` | `frameguard` | `action`: `deny` or `sameorigin` (case-insensitive; `same-origin` accepted) |
| `xPermittedCrossDomainPolicies` | `permittedCrossDomainPolicies` | `permittedPolicies`: `none`, `master-only`, `by-content-type`, `all` |
| `xPoweredBy` | `hidePoweredBy` | none; `false` leaves `X-Powered-By` untouched |
| `xXssProtection` | `xssFilter` | none |
| `permissionsPolicy` (Arcis) | | feature name to allowlist (`self`, `src`, `*`, or an `http(s)` origin) |
| `reportingEndpoints` (Arcis) | | endpoint name to `https` URL |

Setting an option and its legacy alias together is an error. Unknown option
names are ignored, as in Helmet.

**Naming per SDK.** Python uses the snake_case form of every option and
configuration key (`content_security_policy={"use_defaults": False}`,
`strict_transport_security={"max_age": 0}`). Go uses exported struct fields
with ordered slices for directives, Permissions-Policy features and reporting
endpoints, because CSP directive order is part of the wire output. Error
messages use each SDK's own option spelling. CSP directive names are given in
kebab-case or camelCase in every SDK.

**CSP rules (identical to Helmet unless noted):**

1. Start from the default directives unless `useDefaults` is false. A
   directive that overrides a default keeps the default's position; new
   directives are appended in the order given. Directives are joined with
   `;` and no space; values with one space. An empty list emits the bare name.
2. A `null` (Python `None`, Go `Remove: true`) directive removes a default.
   `default-src` can only be removed with `dangerouslyDisableDefaultSrc`.
3. Directive names must match `^[a-z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$` before
   camelCase conversion. Duplicates after conversion are errors.
4. These keywords must be quoted: `none`, `self`, `strict-dynamic`,
   `report-sample`, `inline-speculation-rules`, `unsafe-inline`, `unsafe-eval`,
   `unsafe-hashes`, `wasm-unsafe-eval`, and values starting `nonce-`,
   `sha256-`, `sha384-`, `sha512-`.
5. A value containing `;` or `,` is an error. Arcis also rejects control
   characters (CR, LF and others), which Helmet accepts at startup and then
   fails on every response.
6. Policies with no directives, or without `default-src` (unless disabled
   with `dangerouslyDisableDefaultSrc`), are errors.
7. `reportOnly` sends `Content-Security-Policy-Report-Only` instead.
8. Function values (Node functions, Python callables, Go funcs) are evaluated
   per response. An invalid result is reported through the framework's error
   path for that request, as Helmet does with `next(err)`.

**Nonce extension.** With `nonce: true`, every response gets a fresh nonce of
16 random bytes, base64-encoded, appended to `script-src` as `'nonce-<value>'`.
Only `script-src` receives it, because a nonce makes browsers ignore
`'unsafe-inline'` and would block inline styles under the default
`style-src`. The nonce is exposed before the handler runs:

| SDK / adapter | Where the nonce is available |
| --- | --- |
| Node Express (`createHeaders`, `arcis()`) | `res.locals.cspNonce` |
| Node Fastify, Koa, Hono, Next.js, SvelteKit, Astro, Nuxt, Bun | Not available; configuring it throws at startup |
| Python Starlette/FastAPI, Litestar | `request.state.csp_nonce` |
| Python Flask | `flask.g.csp_nonce` |
| Python Django | `request.csp_nonce` |
| Go (all adapters) | `arcis.CSPNonce(ctx)` on the request context |

A nonce option without a `script-src` directive is an error.

**Validation.** All configuration is validated when the middleware is
constructed. Invalid configuration fails there, with the messages listed in
`security_headers.baseline.invalid`.

**Route-set headers win.** A header the application sets on a response is
kept. Adapters that apply headers after the handler skip headers already
present (legacy keeps its historical overwrite behavior).

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
  block?: boolean                       // Default: false
  dryRun?: boolean                      // Default: false
  onSanitize?: (event: SanitizeEvent) => void
}
```

**Dry-run contract:**

- `dryRun=true` overrides every Arcis enforcement and transformation path.
- Precedence is `dryRun` first, then `block` or reject behavior, then transform
  behavior. When `dryRun=true`, block/reject and transform outcomes are observed
  only. When `dryRun=false`, the configured enforcement or transform mode applies.
- Arcis MUST NOT return a deny, challenge, or rate-limit response in dry-run mode.
- Arcis MUST NOT replace or rewrite request bodies, query values, route parameters,
  headers, or framework-specific sanitized-body fields in dry-run mode.
- Configured request detectors that support observation continue to evaluate
  when their result can be reported through `onSanitize` or telemetry.
- A request that would have been rejected is reported with telemetry decision
  `"would_deny"` and the response status produced by the application.

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

## 9. Telemetry

### Purpose

Stream decision events (`allow`, `deny`, `challenge`, `would_deny`) from the middleware to a user-owned control-plane endpoint. Telemetry is **opt-in** — if no endpoint is configured, the SDK emits nothing and has zero overhead.

### Configuration Options

```
TelemetryOptions {
  endpoint: string              // Required, e.g. "https://arcis.mycompany.com/v1/events"
  apiKey?: string               // Optional, sent as "Authorization: Bearer <apiKey>"
  workspaceId?: string          // Optional, sent as "x-workspace-id" header (default: "default")
  batchSize?: number            // Default: 50 — flush when queue reaches this size
  flushIntervalMs?: number      // Default: 5000 — periodic flush
  onError?: (err: Error) => void // Optional error hook. Default: swallow silently
}
```

### Event Shape

```
TelemetryEvent {
  ts?: string               // ISO-8601 timestamp. SDK should populate; server generates if missing.
  ip: string                // Client IP extracted by SDK (Required)
  method: string            // HTTP method: GET/POST/PUT/PATCH/DELETE (Required)
  path: string              // "[redacted]" for current producers; legacy producers sent concrete paths
  decision: "allow" | "deny" | "challenge" | "would_deny"  // Final or observed middleware decision (Required)
  vector?: string           // Attack family: "xss", "sql", "ssrf", etc. Optional for allowed requests.
  rule?: string             // Specific rule fired, e.g. "sql/union-select"
  severity?: "critical" | "high" | "medium" | "low"
  country?: string          // ISO 3166-1 alpha-2 country code. Optional — filled by server if SDK skips.
  userAgent?: string        // Legacy input only; current clients omit it
  reason?: string           // Legacy input only; current clients omit free-form explanations
  status: number            // Actual final HTTP response status; 0 means unavailable
  matchedPattern?: string   // Legacy input only; current clients omit matched request evidence
  latencyMs?: number        // Middleware processing time in milliseconds, measured by the SDK
  schemaVersion?: "1.1"     // Current producer contract; absent on legacy events
  sdk?: "node" | "python" | "go" // Set by the client, never inferred from request data
  routeId?: string          // Optional application-configured stable route label
  policyId?: string         // Optional application-configured policy revision label
}
```

For a given finding, observation and enforcement MUST carry the same stable
`vector`, `rule`, and `severity`. These identifiers must be attached by the
detecting policy, not inferred from its HTTP response. Shared examples live
under `telemetry.finding_attribution` in `TEST_VECTORS.json`.
Sensitive scanner-path findings use `scanner-path/sensitive` with medium
severity across SDKs. Earlier Go producers used `scanner-path/probe` and high
severity; ingestion must still accept those historical values without
rewriting stored events during the v1.x compatibility window.

### Telemetry privacy

Current SDK clients MUST create a separate, redacted event before queueing.
The caller's event and the application's request MUST remain unchanged.
The same redaction applies to allow, deny, challenge and would_deny:

- Omit `matchedPattern`, `reason` and `userAgent`. Matched text and free-form
  explanations can contain request values, and User-Agent is caller-controlled.
- Replace every concrete `path` with the literal `[redacted]`. Removing a
  query string alone does not protect credentials or identifiers in URL paths.
- Serialize only declared contract fields. Never forward extra object
  properties such as bodies, headers, cookies or authorization.
- Preserve the decision, rule, vector, severity and actual HTTP outcome.
  Redaction must not turn an observation into an enforced block.
- Emit `ip` only when it is an IPv4 or IPv6 literal without a zone identifier.
  Use `0.0.0.0` for invalid values so an arbitrary forwarded-header value cannot
  carry secrets into the IP field. This validates syntax only; it does not
  establish proxy trust or prove caller identity.

These are intentional reductions in diagnostic detail. A rule identifies the
finding without shipping the triggering request text. The API key configured
for collector authentication is still sent in the transport Authorization
header; it is separate from the protected request's authorization header.

This does not make telemetry anonymous. A valid client IP and timestamp remain
part of the contract. Deployers must choose a collector and retention policy
appropriate to that data. Current clients do not offer a raw-evidence opt-out.
Legacy evidence fields remain accepted throughout v1.x for older producers,
but current clients omit them even when a manually supplied event contains
them. Stored historical events are not silently rewritten.
Shared collector fixtures live under `telemetry.privacy`.

### Sampling, queueing and retention

- **No sampling.** Every decision event is queued, including `allow`. Observed
  and enforced events are treated identically, so their counts stay comparable.
- **Bounded memory.** The queue holds at most `maxQueueSize` events (default
  10,000). On overflow the oldest events are dropped first and
  `onQueueOverflow` reports the dropped count.
- **Best-effort delivery.** A batch that fails (network error, timeout or
  non-2xx response) is dropped and reported through `onError`. There is no
  retry and no disk persistence, so the SDK never stores events locally.
- **Retention belongs to the collector.** SDKs keep nothing after delivery.
  The receiving collector defines how long events are stored and must apply
  that policy to observed and enforced events alike.

### Stable producer and policy identifiers

Current clients set `schemaVersion: "1.1"` and their own `sdk` identifier.
They ignore producer identifiers supplied on an event. This identifies the
emitting SDK family and contract, not a verified package version.

Telemetry configuration accepts optional `routeId` and `policyId`
(`route_id` / `policy_id` in Python, `RouteID` / `PolicyID` in Go).
These are static labels chosen by the application, for example
`invoice-write` and `invoice-policy-v3`. Use a route-scoped middleware/client
to attribute one route; a client shared across routes should omit `routeId`.
Do not populate them from request values, customer identifiers or secrets.
An omitted label remains omitted, meaning unknown, with no inferred default.
The same configured labels apply in enforcement and observation modes.

Labels must be 1-128 ASCII letters, digits, dots, underscores or hyphens,
starting with a letter or digit. Empty/unset labels are omitted. Invalid
configuration fails at client construction with an error that does not echo
the supplied value. Clients snapshot the labels at construction and ignore
per-event overrides. Concrete paths remain redacted even when a route label
is configured.

Legacy v1.x producers may omit these fields and retain the original decision
values. Consumers must accept that omission, show unknown metadata, and
preserve observed/enforced semantics per event in a mixed batch. Schema 1.1
adds optional metadata and reduces emitted evidence; it does not rename
decisions or require a destructive storage migration. Consumer support must
be verified separately before claiming dashboard storage/display parity.

### Batch Ingest Contract

SDKs MUST POST batches — never single events — to `POST <endpoint>`.

**Request:**
```
POST /v1/events
Content-Type: application/json
x-workspace-id: <workspaceId>           # optional, defaults to "default"
Authorization: Bearer <apiKey>          # optional

{
  "events": [ TelemetryEvent, TelemetryEvent, ... ]
}
```

**Constraints:**
- `events` array MUST contain 1-500 elements
- Per-event field validation is applied server-side via Zod; invalid events cause the whole batch to fail with HTTP 400
- Server returns `{ "inserted": <count> }` on success (HTTP 200)

### SDK Client Behavior

All SDK telemetry clients MUST follow these rules:

1. **In-memory queue.** `record(event)` pushes synchronously, returns immediately — never blocks the request.
2. **Two flush triggers:** queue reaches `batchSize`, OR `flushIntervalMs` elapses since last flush.
3. **Fail-open.** Network errors, non-2xx responses, and timeouts call `onError` (if provided) but MUST NOT throw, retry indefinitely, or backpressure the middleware.
4. **Drop on failure.** If a batch POST fails, the batch is discarded. No disk persistence, no exponential backoff in v1.
5. **Graceful shutdown.** On `SIGTERM` / `SIGINT` (or equivalent lifecycle hook), the client MUST attempt one final flush before the process exits.
6. **Non-blocking timer.** The flush interval MUST NOT hold the process open (`timer.unref()` in Node, daemon thread in Python, background goroutine in Go).

### When to Emit

The middleware SHOULD emit a `TelemetryEvent` after each of these decision points:

| Middleware stage | Trigger | `decision` |
|------------------|---------|------------|
| Rate limiter | Over limit | `"deny"` |
| Rate limiter | Over threshold but under block | `"challenge"` |
| Sanitizer / validator | Pattern matched an attack | `"deny"` |
| Sanitizer / validator | Input flagged but allowed through | `"challenge"` |
| Any enforcement stage in dry-run mode | Would reject but request proceeds | `"would_deny"` |
| Pass-through | No match, request proceeds | `"allow"` |

Latency MUST be measured from the start of the Arcis middleware chain to the emit call, in milliseconds (fractional).

### Observation and HTTP outcome accounting

The decision and the application response are independent facts. `would_deny`
means Arcis observed a finding without enforcing a rejection. It MUST NOT be
rewritten to `deny` when the application itself returns 4xx or 5xx. Conversely,
an observed finding MUST NOT imply that the application request succeeded.

- `status` records the actual final response, including application errors and
  redirects. SDKs MUST NOT substitute a hypothetical 403 or 429 during dry-run.
- When an exception or returned error escapes to an outer application handler
  before the response is finalized, emit `status: 0` if the adapter cannot
  observe that handler's final response. Do not infer a status from the error,
  a provisional response, or the framework's default 200. Preserve the Arcis
  decision and finding, and propagate the original error without invoking,
  replacing, or bypassing the application's error handling.
  Express observes response completion and can report the final status.
  Starlette's outer server-error handler and Echo/Fiber's outer error handlers
  run outside the middleware's reporting scope. Their unresolved responses
  use 0. Echo responses already committed before an error retain their known
  status. An unavailable status is not a successful request.
- The same rule applies when a Go application panics before committing a
  response and an outer recovery handler later writes it. Preserve the panic
  for that handler and retain any observed finding with status 0. If the
  adapter has already observed a committed response, retain its known status.
  Fiber responses remain buffered until the outer handler completes.
- Only an explicit Arcis enforcement decision may produce `deny`. An
  application-generated 400, 403 or 429 without an Arcis finding is `allow`
  with that actual status, not an Arcis block. SDKs MUST NOT invent rate-limit
  metadata from a 429 response. Genuine Arcis rate-limit rejections retain
  explicit `deny`, vector `rate-limit`, rule `rate-limit/exceeded` and medium
  severity, including when a custom rejection status is configured.
- Successful-request accounting includes only `allow` or `would_deny` events
  with a known final status from 200 through 399. Status 0 (unavailable), 1xx,
  4xx and 5xx do not contribute. A successful redirect is not an Arcis challenge.
- `allowed`, `observed`, `blocked` and `challenged` count their respective Arcis
  decisions, independent of HTTP status. Only `deny` contributes to actual-block
  totals. All `would_deny` events contribute to `observed` and stay out of
  attacker rankings. Existing challenge classification remains unchanged.
- For compatibility, the dashboard API field `allowRate` is the percentage of
  successful requests as defined above, not the complement of `blockRate`.
  Its denominator is all events in the same workspace and reporting window.
  Current and previous 24-hour statistics and the `allow` trend use this same
  definition. A separate `observed` trend counts observations of every status.
- Legacy `allow`, `deny` and `challenge` producers remain accepted throughout
  the v1.x compatibility window. Their omitted status retains the historical
  server default of 200; this is a compatibility assumption, not proof of the
  response. New `would_deny` events without a status use 0, never an invented
  success. Existing stored events are not rewritten or reclassified.
- Unknown historical decisions remain visible as unknown, without being
  counted as an allow, observation, challenge or block. New unknown decision
  values are rejected at ingestion rather than silently coerced.

Shared accounting examples live in `TEST_VECTORS.json` under
`telemetry.observation_accounting`.

### Guarantees

- **Zero-overhead when disabled.** If no `telemetry` option is passed to `arcis({...})`, the SDK MUST NOT allocate a queue, start a timer, or open any network connection.
- **Fail-open by design.** Telemetry failures MUST never cause the protected request to fail or slow down.
- **Parity across SDKs.** Node, Python, and Go implementations MUST produce identical event shapes for the same input. See `spec/TEST_VECTORS.json` → `telemetry`.
- **Minimized request data.** The SDK MUST apply the telemetry privacy rules
  above before queueing. Request secrets must not be sent as finding evidence.

---

## 10. Cloud Intelligence (opt-in)

### Purpose

Let the SDK consume continuously-curated intelligence the local bundle can't
have: per-request **IP reputation** and a **bot corpus** that refreshes outside
the SDK release cycle. Served by an Arcis intelligence endpoint (the control
plane's `/v1/intel/*` routes). **Opt-in** — with no `intelligence` config the
SDK does zero network work and is fully local.

### Configuration Options

```
IntelligenceOptions {
  endpoint: string          // base URL; the SDK appends /v1/intel/...
  apiKey?: string           // sent as Authorization: Bearer <apiKey>
  workspaceId?: string      // sent as x-workspace-id
  cloudDecisions: string[]  // any of: "ip-rep", "bot-corpus"
  blockThreshold?: number   // ip-rep: block when severity >= this (1-10); omitted = observe-only
  cacheMax?, cacheTtlMs?, timeoutMs?, botCorpusRefreshMs?
}
```

### Endpoints consumed

```
GET /v1/intel/ip-reputation/:ip        -> { ip, found, severity, categories, sources, ... }
GET /v1/intel/bot-corpus/snapshot      -> { schema_version, count, entries: [BotCorpusEntry] }
```

(The control plane also serves `POST /v1/intel/ip-reputation/bulk`,
`GET /v1/intel/threat-db/{snapshot,deltas}` for the CLI's `sca --refresh-db`,
and `*/status`. All `/v1/intel/*` routes are auth-gated + per-key rate limited.)

### SDK Behavior

- **ip-rep**: cache-first, non-blocking. On a cache miss the SDK returns
  "unknown" for the current request and schedules a background refresh (LRU +
  TTL, default 1000 / 1h); later requests from that IP read the cached verdict.
  Private/loopback/unresolved IPs are never looked up. Blocking requires an
  explicit `blockThreshold` — reputation is a signal in a multi-signal decision,
  not a standalone gate.
- **bot-corpus**: fetch the snapshot on startup (and every `botCorpusRefreshMs`,
  default weekly), merge it by id on top of the bundled corpus. New ids append;
  existing ids are replaced. Idempotent.

### Guarantees

- **Zero-overhead when disabled.** No `intelligence` config = no client, no
  timer, no network.
- **Fail-open by design.** Any lookup/refresh error (timeout, non-2xx, network)
  MUST resolve to "no data" and MUST NOT block or slow the protected request.
  An unreachable intelligence service never degrades local protection.
- **Parity across SDKs.** Node, Python, and Go MUST implement the same config,
  endpoints, cache semantics, and fail-open behavior.

### CLI (`arcis sca --refresh-db`)

The CLI consumes the threat-db feed (not a runtime-SDK concern): fetch
`GET /v1/intel/threat-db/snapshot`, cache at `~/.arcis/threat-db-cache.json`
(24h TTL), merge over the embedded DB (dedup `ecosystem:name:cve`, fetched
wins). Fail-open: any error keeps the embedded DB. Endpoint + key from
`ARCIS_INTEL_ENDPOINT` / `ARCIS_INTEL_KEY`.

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
