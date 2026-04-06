# @arcis/node

[![npm version](https://img.shields.io/npm/v/@arcis/node.svg)](https://www.npmjs.com/package/@arcis/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Gagancm/arcis/actions/workflows/ci.yml/badge.svg)](https://github.com/Gagancm/arcis/actions/workflows/ci.yml)

**One-line security middleware for Node.js.**

Part of the [Arcis](https://github.com/Gagancm/arcis) ecosystem with implementations for Node.js, Python, and Go.

**45+ security flaws covered. 1,264+ tests. Zero dependencies.**

## Installation

```bash
npm install @arcis/node
```

## Quick Start

### With Express (built-in adapter)

```js
import { arcis } from '@arcis/node';

app.use(arcis());
// That's it. Sanitization, rate limiting, and security headers are on.
```

### With any framework (Fastify, Koa, Hono, etc.)

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

## What It Protects Against

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

## Documentation

Detailed configuration, API reference, Redis setup, and architecture docs are in the [Wiki](https://github.com/Gagancm/arcis/wiki).

## Contributing

1. Fork the repo and create your branch from `nwl` (the active development branch)
2. All PRs target `nwl` — `main` is release-only
3. All changes must pass existing tests
4. New features require test cases aligned with `spec/TEST_VECTORS.json`

## License

MIT
