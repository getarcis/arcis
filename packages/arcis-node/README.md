# @arcis/node

[![npm version](https://img.shields.io/npm/v/@arcis/node.svg?label=npm&color=00996D)](https://www.npmjs.com/package/@arcis/node)
[![npm downloads](https://img.shields.io/npm/dm/@arcis/node.svg?label=downloads&color=00996D)](https://www.npmjs.com/package/@arcis/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Inside-the-app security middleware for Node.js. One line of code, 30+ attack vectors handled, zero runtime dependencies.**

```bash
npm install @arcis/node
```

```js
import { arcis } from '@arcis/node';
app.use(arcis({ block: true }));
```

What `arcis({ block: true })` actually wires into the request path: XSS, SQL injection, NoSQL injection, command injection, path traversal, prototype pollution, SSTI, XXE, LDAP injection, XPath injection, email-header injection. Plus rate limiting, security headers, and error scrubbing. Pattern matches return 403 before your handler runs.

Available as opt-in helpers (not auto-wired into `arcis()`): bot detection (695-pattern corpus, `botProtection()`), per-IP correlation window (`new CorrelationWindow(...)`), HPP guard (`hppProtection()`), CSRF (`csrfProtection()`), V32 toolcall-injection signatures (`detectPromptInjection`), V33 deserialization markers (`detectDeserialization`), V34 GraphQL alias bomb / fragment cycle (`graphqlGuard`), SSRF URL validation (`validateUrl`). Compose as needed.

**Docs**: [Quickstart](https://arcis-website.pages.dev/documentation/getting-started.html) · [Detector reference](https://arcis-website.pages.dev/documentation/detectors/) · [Framework adapters](https://arcis-website.pages.dev/documentation/frameworks.html) · [Why Arcis](https://arcis-website.pages.dev/documentation/why-arcis.html) · [Release notes](https://arcis-website.pages.dev/documentation/release-notes.html)

**Part of the [Arcis](https://github.com/getarcis/arcis) ecosystem.** Node + Python + Go SDKs at full parity from one shared specification. **2,116+ Node tests · 1,688+ Python · 483+ Go.** All passing in CI on every PR.

## Framework support

10 first-party framework adapters as subpath imports. The core sanitizers work standalone with any framework.

| Framework | Import | Status |
|---|---|---|
| Express | `import { arcis } from '@arcis/node'` | Built-in |
| Fastify | `@arcis/node/fastify` | Adapter |
| Koa | `@arcis/node/koa` | Adapter |
| Hono | `@arcis/node/hono` | Adapter |
| Next.js | `@arcis/node/nextjs` | Adapter |
| NestJS | `@arcis/node/nestjs` | Adapter |
| SvelteKit | `@arcis/node/sveltekit` | Adapter |
| Astro | `@arcis/node/astro` | Adapter |
| Nuxt | `@arcis/node/nuxt` | Adapter |
| Bun | `@arcis/node/bun` | Adapter |

## What's new in v1.6.0

- **NFKC normalization + multi-decode chain** at the top of `sanitizeString`. Fullwidth glyphs, encoded `<script>`, and triple-encoded payloads now match the same patterns as their plain forms.
- **Modern deserialization detection (V33)**: new `detectDeserialization(payload)` returns `'python_pickle'`, `'java_fastjson'`, `'php_unserialize'`, `'ruby_marshal'`, `'dotnet_binary_formatter'`, or `null`. Detection-only because the right response is to refuse the request, not strip the bytes.
- **GraphQL alias bomb + fragment cycle (V34)**: `graphqlGuard` accepts `maxAliases` (default 50) and `blockFragmentCycles` (default `true`). Brace-matched fragment dependency-graph walker catches self-reference and longer cycles.
- **Toolcall-injection patterns (V32)**: 5 new patterns in `detectPromptInjection` covering `"tool_call"` / `"function_call"` markers, ANSI escapes, Claude `<tool_use>` tags, tool-name spoofing.
- **`CorrelationWindow` middleware**: stateful per-IP rolling window (60s default) with scanner / credential-stuffing / race-window detection. Memory-capped at 10,000 IPs, 200 events per IP, LRU eviction.
- **`protectLogin / protectSignup / protectApi` correlation wireup**: pass `correlation: { window }` to the existing helper and the stack records each request and refuses on a detection hit.
- **Mutation tester**: 142 case-flip / URL-encode / HTML-entity / fullwidth variants ran against the XSS / SQLi / path corpora. Catches future pattern or normalization regressions that would re-open a bypass class.

## What was new in v1.5.0

- **10 first-party framework adapters**: Express + Fastify (`@arcis/node/fastify`) + Koa (`@arcis/node/koa`) + Hono (`@arcis/node/hono`) + Next.js (`@arcis/node/nextjs`) + NestJS + SvelteKit + Astro + Nuxt + Bun. Each subpath import keeps the framework SDK as a type-only dependency.
- **9 new attack vectors**: GraphQL depth-bombs (`graphqlGuard`), LDAP / XPath / email-header injection wired into block-mode, mass assignment (`massAssign`), HTTP method tampering (`methodAllowlist`), response splitting (`responseSplittingGuard`), event-loop overload (`eventLoopProtection`), SSRF DNS TOCTOU (`validateUrlAsync` + `pinnedDnsLookup` + `safeFollowRedirect`).
- **AI-era protections**: 28-signature prompt-injection library (`detectPromptInjection`), per-key `tokenBudget` middleware, 695-pattern bot corpus.
- **Composite helpers**: `protectLogin`, `protectSignup`, `protectApi`.
- **Dry-run / `onSanitize` mode**: observe attack surface without enforcing.
- **Guards API**: `arcis.guard({ input, context })` for queue consumers + agent tool handlers.

## What was new in v1.4.4

- **Detect-and-block middleware**: opt in with `arcis({ block: true })`. Returns 403 + tags telemetry on attack-pattern match instead of silently sanitizing.
- **Telemetry queue cap**: sustained dashboard outage no longer OOMs the worker. Drop-oldest semantics, optional `onQueueOverflow` callback.
- See the full release history at [arcis-website.pages.dev/changelog.html](https://arcis-website.pages.dev/changelog.html).

## Installation

```bash
npm install @arcis/node dotenv
```

> **Install in your backend project, not the frontend.** Arcis is server-side middleware. For separated stacks (Next.js + Express, React + FastAPI, etc.), this package goes in the server folder. A frontend bundle would leak the API key into client JS and the middleware never runs there anyway.
>
> **`.env` lives next to your server entry point.** Add `ARCIS_KEY=...`, `ARCIS_WORKSPACE_ID=...`, `ARCIS_ENDPOINT=...`. Do **not** prefix with `NEXT_PUBLIC_`, `VITE_`, or `REACT_APP_`. Those expose values to the browser. Add `.env` to `.gitignore`.

### CLI (audit / scan / sca) ships separately as a native binary

The Arcis SDK ships in this Node package. The Arcis **CLI** scanners (`arcis audit`, `arcis scan`, `arcis sca`) ship as a single static binary distributed on npm:

```bash
npm install -g @arcis/cli
arcis --version
```

The npm SDK package (`@arcis/node`) does not put a CLI on your PATH on its own. Install `@arcis/cli` (separate package) for the scanner. The CLI works regardless of whether your app is Node, Python, or Go.

## Quick Start

### With Express (built-in adapter)

```js
import express from 'express';
import { arcis } from '@arcis/node';
import 'dotenv/config';

const app = express();

// block: true returns 403 on detected attacks. Defaults to false
// (sanitize + observe) so existing apps don't break on rollout.
app.use(arcis({ block: true }));

app.listen(3000);
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

// Sanitize user input: works anywhere
const clean = sanitizeString(userInput);
const cleanBody = sanitizeObject(requestBody);

// Detect threats without sanitizing
if (detectXss(value)) { /* reject */ }
if (detectSql(value)) { /* reject */ }

// Safe logging: no framework needed
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
| Bot Detection | 695 patterns, 7 categories (crawlers, scrapers, AI bots, etc.), behavioral signals |
| Deserialization (v1.6) | `detectDeserialization()` flags Python pickle, Java FastJSON `@type`, PHP `unserialize`, Ruby Marshal, .NET BinaryFormatter payloads |
| GraphQL Abuse | `graphqlGuard` with `maxDepth`, `maxAliases`, `blockIntrospection`, `blockFragmentCycles` (v1.6) |
| Stateful Correlation (v1.6) | `CorrelationWindow` detects scanners, credential stuffing, race-window probes per IP |
| CSRF | Double-submit cookie, token generation and validation |
| Security Headers | CSP, HSTS, X-Frame-Options, 10 headers out of the box |
| Input Validation | Type checking, ranges, enums, email (disposable blocklist, typo suggestions, MX verify), mass assignment prevention |

## Architecture

Arcis separates **core security logic** from **framework adapters**:

```
@arcis/node
├── Core (framework-agnostic)
│   ├── sanitizeString / sanitizeObject   - clean any input
│   ├── detectXss / detectSql / ...       - threat detection
│   ├── createSafeLogger / createRedactor - safe logging
│   ├── MemoryStore / RedisStore          - rate limit backends
│   └── Error classes and constants
│
└── Adapters (framework-specific)
    └── Express middleware (arcis(), arcis.sanitize(), arcis.rateLimit(), ...)
```

The core functions are pure: no `req`, `res`, or `next`. They take values in and return values out. This means they work with Express, Fastify, Koa, Hono, Nest, raw `http.createServer`, Bun, Deno, serverless functions, or anything else.

Subpath imports are available for tree-shaking:

```js
import { sanitizeString } from '@arcis/node/sanitizers';
import { createSafeLogger } from '@arcis/node/logging';
import { MemoryStore } from '@arcis/node/stores';
```

## Documentation

Detailed configuration, API reference, Redis setup, and architecture docs are in the [Wiki](https://github.com/getarcis/arcis/wiki).

## Contributing

1. Fork the repo and create your branch from `nwl` (the active development branch)
2. All PRs target `nwl`; `main` is release-only
3. All changes must pass existing tests
4. New features require test cases aligned with `spec/TEST_VECTORS.json`

## License

MIT
