# Arcis Python

[![PyPI version](https://img.shields.io/pypi/v/arcis.svg?label=pypi&color=00996D)](https://pypi.org/project/arcis/)
[![PyPI downloads](https://img.shields.io/pypi/dm/arcis.svg?label=downloads&color=00996D)](https://pypi.org/project/arcis/)
[![GitHub stars](https://img.shields.io/github/stars/GagancM/arcis?style=flat&color=00996D)](https://github.com/GagancM/arcis/stargazers)
[![Python 3.9+](https://img.shields.io/pypi/pyversions/arcis.svg)](https://pypi.org/project/arcis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

**One-line security middleware for Python web applications. Zero runtime dependencies.**

Arcis is a cross-platform security library that provides drop-in protection against common web vulnerabilities. Part of the [Arcis](https://github.com/Gagancm/arcis) ecosystem with implementations for Node.js, Python, and Go.

## What's new in v2.0.0

- **SDK-only release.** `pip install arcis` now ships the runtime middleware only — zero runtime dependencies. The CLI moved to its own package: `npm install -g @arcis/cli`. See "CLI" below.
- The middleware API is unchanged. Existing `Arcis(app)` / `app.add_middleware(ArcisMiddleware, ...)` code keeps working.
- See the full release history at [gagancm.github.io/arcis/changelog.html](https://gagancm.github.io/arcis/changelog.html).

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

# Sliding window — smoother rate enforcement
sliding = SlidingWindowLimiter(max_requests=100, window_ms=60000)

# Token bucket — burst-friendly
bucket = TokenBucketLimiter(capacity=100, refill_rate=10)  # 10 tokens/sec
```

### Bot Detection
Detect and categorize bots with 80+ patterns across 7 categories:

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
| `BotDetector` | Bot detection with 80+ patterns |
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
2. All PRs target `nwl` — `main` is release-only
3. All changes must pass existing tests
4. New features require test cases aligned with `spec/TEST_VECTORS.json`
