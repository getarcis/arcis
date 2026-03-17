
# Arcis

[![npm version](https://img.shields.io/npm/v/@arcis/node.svg)](https://www.npmjs.com/package/@arcis/node)
[![PyPI version](https://img.shields.io/pypi/v/arcis.svg)](https://pypi.org/project/arcis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Gagancm/arcis/actions/workflows/ci.yml/badge.svg)](https://github.com/Gagancm/arcis/actions/workflows/ci.yml)

One-line security middleware for Node.js, Python, and Go.

Arcis protects your code like how Dependabot protects your dependencies.

**17 attack vectors handled. 1700+ tests. Zero dependencies.**

| Category | What it stops |
|----------|--------------|
| XSS | Script injection, event handlers, `javascript:` URIs, SVG/iframe payloads |
| SQL Injection | Keywords, boolean logic, comments, time-based blind (`SLEEP`, `BENCHMARK`) |
| NoSQL Injection | MongoDB operators (`$gt`, `$where`, `$regex`, 25+ blocked operators) |
| Command Injection | Shell metacharacters, dangerous commands, redirections |
| Path Traversal | `../`, encoded variants (`%2e%2e`), null byte injection |
| Prototype Pollution | `__proto__`, `constructor`, `__defineGetter__`, 7 keys blocked (case-insensitive) |
| HTTP Header Injection | CRLF injection, response splitting, null bytes |
| SSRF | Private IPs, loopback, link-local, cloud metadata, dangerous protocols |
| Open Redirect | Absolute URLs, `javascript:`, protocol-relative, backslash/control char bypass |
| Error Leakage | Stack traces, DB errors, connection strings, internal IPs scrubbed in production |
| CORS Misconfiguration | Whitelist-based origins, `null` origin blocked, `Vary: Origin` enforced |
| Cookie Security | HttpOnly, Secure, SameSite enforced on all cookies |
| Rate Limiting | Per-IP, sliding window, token bucket, in-memory or Redis, `X-RateLimit-*` headers |
| Bot Detection | 80+ patterns, 7 categories (crawlers, scrapers, AI bots, etc.), behavioral signals |
| CSRF | Double-submit cookie, token generation and validation |
| Security Headers | CSP, HSTS, X-Frame-Options, 10 headers out of the box |
| Input Validation | Type checking, ranges, enums, email (disposable blocklist, typo suggestions, MX verify), mass assignment prevention |

## Install

```bash
npm install @arcis/node          # Node.js
pip install arcis                # Python
go get github.com/GagancM/arcis  # Go
```

## Quick Start

### Node.js

Arcis has two layers: **framework-agnostic core functions** that work anywhere, and **middleware adapters** for specific frameworks.

#### With Express (built-in adapter)

```js
import { arcis } from '@arcis/node';

app.use(arcis());
// That's it. Sanitization, rate limiting, and security headers are on.
```

#### With any framework (Fastify, Koa, Hono, etc.)

The core sanitization, validation, and logging functions have zero framework dependencies. Use them directly in any Node.js project:

```js
import {
  sanitizeString,
  sanitizeObject,
  detectXss,
  detectSql,
  detectCommandInjection,
  detectPathTraversal,
  createSafeLogger,
  createRedactor,
} from '@arcis/node';

// Sanitize user input — works anywhere
const clean = sanitizeString(userInput);
const cleanBody = sanitizeObject(requestBody);

// Detect threats without sanitizing
if (detectXss(value)) { /* reject */ }
if (detectSql(value)) { /* reject */ }

// Safe logging — no framework needed
const logger = createSafeLogger();
logger.info('User login', { email, password: 'will-be-redacted' });
```

**Writing your own middleware is straightforward.** Here's a Fastify example:

```js
import { sanitizeObject } from '@arcis/node';

fastify.addHook('preHandler', async (request, reply) => {
  if (request.body) request.body = sanitizeObject(request.body);
  if (request.query) request.query = sanitizeObject(request.query);
});
```

Koa:

```js
import { sanitizeObject } from '@arcis/node';

app.use(async (ctx, next) => {
  if (ctx.request.body) ctx.request.body = sanitizeObject(ctx.request.body);
  if (ctx.query) ctx.query = sanitizeObject(ctx.query);
  await next();
});
```

Hono:

```js
import { sanitizeObject } from '@arcis/node';

app.use('*', async (c, next) => {
  const body = await c.req.json().catch(() => null);
  if (body) c.set('sanitizedBody', sanitizeObject(body));
  await next();
});
```

> Built-in adapters for Fastify, Koa, and Hono are on the roadmap. The core functions work today.

### Python

```python
# Flask
from arcis import Arcis
Arcis(app)

# FastAPI
from arcis import ArcisMiddleware
app.add_middleware(ArcisMiddleware)

# Django — add to MIDDLEWARE in settings.py
'arcis.django.ArcisMiddleware'
```

### Go

```go
// Gin
r.Use(arcisgin.Middleware())

// Echo
e.Use(arcisecho.Middleware())
```

## What It Does

One `app.use(arcis())` gives you all 17 categories above. Or use individual functions for fine-grained control:

- **Sanitize** — `sanitizeString()`, `sanitizeObject()` strip dangerous patterns
- **Detect** — `detectXss()`, `detectSql()`, `detectHeaderInjection()` flag threats without modifying input
- **Validate** — `validateUrl()` blocks SSRF, `validateRedirect()` blocks open redirects, `validateEmail()` with disposable blocklist and typo suggestions
- **Protect** — sliding window + token bucket rate limiting, bot detection, CSRF, security headers, safe logging, error handling
- **Utilities** — platform-aware IP detection, request fingerprinting, duration parsing (`"5m"` -> ms)

## Architecture

Arcis separates **core security logic** from **framework adapters**:

```
@arcis/node
├── Core (framework-agnostic)
│   ├── sanitizeString / sanitizeObject   — clean any input
│   ├── detectXss / detectSql / ...       — threat detection
│   ├── createSafeLogger / createRedactor — safe logging
│   ├── MemoryStore / RedisStore          — rate limit backends
│   └── Error classes and constants
│
└── Adapters (framework-specific)
    └── Express middleware (arcis(), arcis.sanitize(), arcis.rateLimit(), ...)
```

The core functions are pure — no `req`, `res`, or `next`. They take values in and return values out. This means they work with Express, Fastify, Koa, Hono, Nest, raw `http.createServer`, Bun, Deno, serverless functions, or anything else.

Subpath imports are available for tree-shaking:

```js
import { sanitizeString } from '@arcis/node/sanitizers';
import { createSafeLogger } from '@arcis/node/logging';
import { MemoryStore } from '@arcis/node/stores';
```

## Supported Frameworks

| SDK | Built-in Adapters | Core Functions | Status |
|-----|-------------------|----------------|--------|
| Node.js | Express | Work with any framework | Stable |
| Python | Flask, FastAPI, Django | Work standalone | Stable |
| Go | net/http, Gin, Echo | Work standalone | Stable |
| Java | Spring Boot | — | Planned |
| C# | ASP.NET Core | — | Planned |

**Node.js roadmap:** Built-in adapters for Fastify, Koa, and Hono are planned. The core functions already work with these frameworks — you just wire a short middleware wrapper (see examples above).


## How It Works

All SDKs load security patterns from a shared `patterns.json` at runtime. A shared spec (`API_SPEC.md`) and test vectors (`TEST_VECTORS.json`) enforce identical behavior across languages.

## Documentation

Detailed configuration, API reference, Redis setup, granular middleware usage, and architecture docs are in the [Wiki](https://github.com/Gagancm/arcis/wiki).

## Contributing

1. Fork the repo and create your branch from `nwl` (the active development branch)
2. All PRs target `nwl` — `main` is release-only
3. All changes must pass existing tests (CI runs automatically on PRs)
4. New features require test cases aligned with `spec/TEST_VECTORS.json`
5. Pattern changes in `packages/core/patterns.json` must be reflected in all SDKs

## License

MIT
