# Arcis Python

[![PyPI version](https://img.shields.io/pypi/v/arcis.svg?label=pypi&color=00996D)](https://pypi.org/project/arcis/)
[![PyPI downloads](https://img.shields.io/pypi/dm/arcis.svg?label=downloads&color=00996D)](https://pypi.org/project/arcis/)
[![Python 3.9+](https://img.shields.io/pypi/pyversions/arcis.svg)](https://pypi.org/project/arcis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**Inside-the-app security middleware for Python. One line of code, 20+ attack vectors handled, zero runtime dependencies.**

```bash
pip install arcis
```

```python
# FastAPI
from arcis.fastapi import ArcisMiddleware
app.add_middleware(ArcisMiddleware, block=True)

# Flask (sanitize-only at the middleware layer)
from arcis import Arcis
Arcis(app)

# Django: settings.py MIDDLEWARE -> 'arcis.django.ArcisMiddleware'

# Litestar (and any ASGI host)
from arcis.litestar import ArcisMiddleware as ArcisLitestarMiddleware
```

What `ArcisMiddleware` actually wires into the request path: XSS, SQL injection, NoSQL injection, command injection, path traversal, SSTI, XXE, LDAP injection, XPath injection, email-header injection, prototype pollution. Plus rate limiting, security headers, and error handling. With `block=True` (FastAPI / Django / Litestar), pattern matches return 403 before your handler runs. Flask runs in sanitize-only mode at the middleware layer; block-mode for Flask is a v1.7 item.

Available as opt-in helpers (not auto-wired into `ArcisMiddleware`): bot detection (695-pattern corpus, `arcis.middleware.BotProtection`), per-IP correlation window (`arcis.middleware.CorrelationWindow`), HPP guard (`arcis.middleware.HppProtection`), CSRF (`arcis.middleware.CsrfProtection`), V32 toolcall-injection signatures (`arcis.detect_prompt_injection`), V33 deserialization markers (`arcis.detect_deserialization`), V34 GraphQL alias bomb / fragment cycle (`arcis.sanitizers.graphql.inspect_graphql_query`), SSRF URL validation (`arcis.validate_url_ssrf`). Compose as needed.

**Docs**: [Quickstart](https://arcis-website.pages.dev/documentation/getting-started.html) · [Detector reference](https://arcis-website.pages.dev/documentation/detectors/) · [Framework adapters](https://arcis-website.pages.dev/documentation/frameworks.html) · [Why Arcis](https://arcis-website.pages.dev/documentation/why-arcis.html) · [Release notes](https://arcis-website.pages.dev/documentation/release-notes.html)

**Part of the [Arcis](https://github.com/getarcis/arcis) ecosystem.** Node + Python + Go SDKs at full parity from one shared specification. **1,688+ Python tests · 2,116+ Node · 483+ Go.** All passing in CI on every PR.

## Framework support

| Framework | Import | Block mode | Notes |
|---|---|---|---|
| FastAPI | `from arcis.fastapi import ArcisMiddleware` | Yes (`block=True`) | Full pipeline: sanitize, scan-and-block, rate-limit, headers |
| Django | `'arcis.django.ArcisMiddleware'` in `MIDDLEWARE` | Yes (`block=True`) | Full pipeline |
| Litestar (and any ASGI host) | `from arcis.litestar import ArcisMiddleware` | Yes (`block=True`) | Full pipeline, plus opt-in `bot=True` |
| Flask | `from arcis import Arcis` | No (v1.7) | Sanitize-only at middleware. Block-mode landing in v1.7. Compose `scan_threats` manually in a `before_request` handler for now. |

## What's new in v1.6.0

- **NFKC normalization + multi-decode chain** at the top of `sanitize_string`. Fullwidth glyphs, URL-encoded `<script>`, and triple-encoded payloads now match the same patterns as their plain forms.
- **Modern deserialization detection (V33)**: new `detect_deserialization(payload)` returns `'python_pickle'`, `'java_fastjson'`, `'php_unserialize'`, `'ruby_marshal'`, `'dotnet_binary_formatter'`, or `None`. Detection-only because the right response is to refuse the request, not strip the bytes.
- **GraphQL alias bomb + fragment cycle (V34)**: `GraphqlGuardOptions` gains `max_aliases` (default 50) and `block_fragment_cycles` (default `True`). Brace-matched fragment dependency-graph walker catches self-reference and longer cycles.
- **Toolcall-injection patterns (V32)**: 5 new patterns in `detect_prompt_injection` covering `"tool_call"` / `"function_call"` markers, ANSI escapes, Claude `<tool_use>` tags, tool-name spoofing.
- **`CorrelationWindow` middleware**: stateful per-IP rolling window (60s default) with scanner / credential-stuffing / race-window detection. Memory-capped at 10,000 IPs, 200 events per IP, LRU eviction.
- **`check_login` / `check_api` correlation wireup**: pass `correlation_window=` + `client_ip=` + `route=` and the helper records the attempt and returns `reason="correlation"` on a detection hit.
- **Mutation tester**: 142 case-flip / URL-encode / HTML-entity / fullwidth variants ran against the XSS / SQLi / path corpora. Catches future pattern or normalization regressions that would re-open a bypass class.
- **Interactive REPL (via `@arcis/cli`)**: `arcis` with no args drops into a full-screen TUI with persistent welcome banner, scrollback, slash commands, history file at `~/.arcis/history`, F2 jump-to-finding.

## What was new in v1.5.0

- **SDK-only release.** `pip install arcis` ships the runtime middleware with zero runtime dependencies. The CLI moved to its own package: `npm install -g @arcis/cli`.
- **Litestar adapter** (`arcis.litestar.ArcisMiddleware`). Pure-ASGI, type-only `litestar` import. Composes with Litestar via `DefineMiddleware` and with any other ASGI host (Starlette, Quart, Hypercorn) via direct instantiation.
- **`verify_email_mx_async`**. Async-safe MX verification. The sync `verify_email_mx` was the one user-facing call that blocked the event loop on FastAPI handlers; the async variant uses `dns.asyncresolver` natively (or threads to `asyncio.to_thread` as fallback).
- **AI-era protections**: 28-signature prompt-injection library, per-key `tokenBudget` middleware, 695-pattern bot corpus, `Guards` API for non-HTTP contexts.
- **Composite helpers**: `signup_protection` (rate-limit + bot + email-MX). Full recipe for protecting account creation.
- The middleware API is unchanged. Existing `Arcis(app)` / `app.add_middleware(ArcisMiddleware, ...)` code keeps working.
- See the full release history at [arcis-website.pages.dev/changelog.html](https://arcis-website.pages.dev/changelog.html).

## Installation

```bash
# Core middleware (zero runtime deps)
pip install arcis python-dotenv

# With framework integrations
pip install arcis[flask]
pip install arcis[fastapi]
pip install arcis[django]

# All frameworks + dev tools
pip install arcis[dev]
```

> **Install in your backend project, not the frontend.** Arcis is server-side middleware. Bundling it into a frontend build would leak the API key into client JS and the middleware never runs there.
>
> **`.env` lives next to your server entry point.** Add `ARCIS_KEY=...`, `ARCIS_WORKSPACE_ID=...`, `ARCIS_ENDPOINT=...` and call `load_dotenv()` at startup. Add `.env` to `.gitignore`.

## CLI

The Arcis scanner (`arcis audit`, `arcis scan`, `arcis sca`) is now a standalone native binary distributed via npm:

```bash
npm install -g @arcis/cli
arcis --help
```

This works regardless of whether your app is Node, Python, or Go. The CLI is a single static binary with the threat database embedded. No Python required.

If you previously relied on `pip install arcis` shipping the `arcis` command, switch to the npm install above.

## Quick Start

### Flask

```python
from flask import Flask
from arcis import Arcis
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
Arcis(app, block=True)  # block=True returns 403 on detected attacks.

@app.route('/')
def hello():
    return 'Hello, World!'
```

### FastAPI

```python
from fastapi import FastAPI
from arcis.fastapi import ArcisMiddleware
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()
# block=True returns 403 on detected attacks. Default is False
# (sanitize + observe) so existing apps don't break on rollout.
app.add_middleware(ArcisMiddleware, block=True)

@app.get('/')
async def hello():
    return {'message': 'Hello, World!'}
```

### Django

```python
# settings.py
MIDDLEWARE = [
    'arcis.django.ArcisMiddleware',
    # ... other middleware
]

# Optional configuration
ARCIS_CONFIG = {
    'rate_limit_max': 100,
    'rate_limit_window_ms': 60000,
    'sanitize_xss': True,
    'sanitize_sql': True,
}
```

## Features

### Input Sanitization
Automatically sanitize user input to prevent:
- **XSS** (Cross-Site Scripting)
- **SQL Injection**
- **NoSQL Injection** (MongoDB operators)
- **Path Traversal** (`../` attacks)
- **Prototype Pollution** (`__proto__`, `constructor`)
- **HTTP Header Injection** (CRLF, response splitting)
- **SSRF** (private IPs, cloud metadata, dangerous protocols)
- **Open Redirect** (absolute URLs, `javascript:`, protocol-relative)

```python
from arcis import sanitize_string, sanitize_dict

# Sanitize a string
clean = sanitize_string("<script>alert('xss')</script>")
# Result: "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

# Sanitize a dictionary (including nested objects)
data = {"name": "<script>xss</script>", "$gt": ""}
clean = sanitize_dict(data)
# Result: {"name": "&lt;script&gt;..."}  ($gt key removed)
```

### Rate Limiting
Protect against brute force and DDoS attacks with fixed window, sliding window, or token bucket:

```python
from arcis import RateLimiter
from arcis.middleware import SlidingWindowLimiter, TokenBucketLimiter

# Fixed window
limiter = RateLimiter(max_requests=100, window_ms=60000)

# Sliding window: smoother rate enforcement
sliding = SlidingWindowLimiter(max_requests=100, window_ms=60000)

# Token bucket: burst-friendly
bucket = TokenBucketLimiter(capacity=100, refill_rate=10)  # 10 tokens/sec
```

### Bot Detection
Detect and categorize bots with 695 patterns across 7 categories:

```python
from arcis.middleware import BotDetector

detector = BotDetector()
result = detector.detect(user_agent, request_headers)
# result.is_bot, result.category, result.confidence
```

### CSRF Protection
Double-submit cookie pattern with token generation and validation:

```python
from arcis.middleware import CsrfProtection

csrf = CsrfProtection(secret="your-secret-key")
```

### Security Headers
Automatically add security headers to all responses:
- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`
- `X-XSS-Protection: 0`

### Input Validation

```python
from arcis import Validator, validate_email, validate_url

# Quick validation
if validate_email(user_input):
    print("Valid email!")

# Full validator
assert Validator.email("test@example.com")  # True
assert Validator.url("https://example.com")  # True
assert Validator.uuid("550e8400-e29b-41d4-a716-446655440000")  # True
assert Validator.length("hello", min_len=3, max_len=10)  # True
```

### Safe Logging
Log safely without exposing secrets:

```python
from arcis import SafeLogger

logger = SafeLogger()

# Automatically redacts sensitive fields
logger.info("User login", {"email": "user@test.com", "password": "secret"})
# Output: {"email": "user@test.com", "password": "[REDACTED]"}

# Prevents log injection (removes newlines/control characters)
logger.info("User: attacker\nAdmin: true")  # Newlines stripped
```

## Configuration

All frameworks support the same configuration options:

```python
# Flask
Arcis(
    app,
    sanitize=True,
    sanitize_xss=True,
    sanitize_sql=True,
    sanitize_nosql=True,
    sanitize_path=True,
    rate_limit=True,
    rate_limit_max=100,
    rate_limit_window_ms=60000,
    headers=True,
    csp="default-src 'self'",
)

# FastAPI
app.add_middleware(
    ArcisMiddleware,
    rate_limit_max=50,
    sanitize_sql=False,
)

# Django (settings.py)
ARCIS_CONFIG = {
    'rate_limit_max': 50,
    'sanitize_sql': False,
}
```

## Standalone Middleware (Django)

Use individual components if you only need specific protection:

```python
MIDDLEWARE = [
    'arcis.django.ArcisSanitizeMiddleware',   # Only sanitization
    'arcis.django.ArcisRateLimitMiddleware',  # Only rate limiting
    'arcis.django.ArcisHeadersMiddleware',    # Only security headers
]
```

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=arcis --cov-report=html
```

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `Arcis` | Main class - configures all protections |
| `Sanitizer` | Input sanitization |
| `RateLimiter` | Fixed window rate limiting |
| `SlidingWindowLimiter` | Sliding window rate limiting |
| `TokenBucketLimiter` | Token bucket rate limiting |
| `BotDetector` | Bot detection with 695 patterns |
| `CsrfProtection` | CSRF double-submit cookie protection |
| `SecurityHeaders` | Security headers |
| `Validator` | Input validation |
| `SafeLogger` | Safe logging with redaction |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `RateLimitExceeded` | Raised when rate limit is exceeded |
| `ValidationError` | Raised when validation fails |

### Convenience Functions

| Function | Description |
|----------|-------------|
| `sanitize_string(value)` | Sanitize a single string |
| `sanitize_dict(data)` | Sanitize a dictionary |
| `sanitize_xss(value)` | XSS sanitization only |
| `sanitize_sql(value)` | SQL injection sanitization only |
| `sanitize_nosql(data)` | NoSQL injection sanitization only |
| `sanitize_path(value)` | Path traversal sanitization only |
| `validate_email(value)` | Email validation with disposable blocklist, typo suggestions, MX verify |
| `validate_url(value)` | Validate URL format |
| `validate_url_ssrf(value)` | URL validation with SSRF protection |
| `validate_redirect(value)` | Open redirect prevention |
| `validate_uuid(value)` | Validate UUID format |

### Utilities

| Function | Description |
|----------|-------------|
| `parse_duration(value)` | Parse duration strings (`"5m"`, `"1h"`) to milliseconds |
| `get_client_ip(request)` | Platform-aware IP detection (proxy headers, etc.) |
| `fingerprint_request(request)` | Generate request fingerprint for tracking |

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repo and create your branch from `nwl` (the active development branch)
2. All PRs target `nwl`. `main` is release-only.
3. All changes must pass existing tests
4. New features require test cases aligned with `spec/TEST_VECTORS.json`
