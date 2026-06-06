# Arcis — Go SDK

Security middleware for Go web applications. The core is stdlib-only;
Gin, Echo, chi, and Fiber adapters each import their respective router
(chi works with any router that accepts stdlib `http.Handler`
middleware via the chi adapter; a thin `nethttp` re-export covers users
without any third-party router). Detects + sanitizes XSS, SQL
injection, NoSQL injection, path traversal, command injection,
prototype pollution, SSTI, XXE, and more across the same surface as the
Node and Python SDKs.

```bash
go get github.com/GagancM/arcis@latest
```

## What's new in v1.6.2 (shipped 2026-05-24)

- **V32 toolcall injection patterns** in `DetectPromptInjection`. Five new signatures: `agent-toolcall-marker`, `agent-tool-name-spoof`, `agent-tool-result-marker`, `ansi-escape-sequence`, `claude-tool-use-tags`.
- **V33 deserialization markers**: new `sanitizers.DetectDeserialization` returns `python_pickle` / `java_fastjson` / `php_unserialize` / `ruby_marshal` / `dotnet_binary_formatter` / empty string. Head-byte markers use `strings.HasPrefix` (Go regexp would interpret `\x80` as the rune U+0080 in UTF-8 and miss raw pickle blobs).
- **V34 GraphQL alias bomb + fragment cycle**: `GraphqlGuardOptions` gains `MaxAliases` (default 50) and `BlockFragmentCycles` (default true). DFS with brace-matched body extraction so query-op spreads do not pollute fragment dep graph.
- **`CorrelationWindow` middleware** in `middleware/correlation.go`. First stateful primitive in the Go SDK. 60s rolling per-IP window, LRU eviction (max 10,000 IPs), per-IP cap (200 events). Detectors: scanner sweep, credential stuffing, race window.
- **Mutation tester** in `sanitizers/mutation_resistance_test.go`. 8 mutators × XSS / SQL / path corpora.
- **Q8 LDAP NOT-bypass + Q10 mail-header bare-newline patterns** added to the shared `patterns.json`. The runtime loader picks them up automatically.

These helpers are accessible from their sub-packages today (`arcis/middleware`, `arcis/sanitizers`). Root-level re-exports from the `arcis` package land in v1.7.

## What's new in v1.6.0

- **`patterns.json` shared with Node + Python**. The Go SDK now embeds and parses the canonical `packages/core/patterns.json` at `init()` via `//go:embed`. Hardcoded var blocks (XSS / SQL / path / command) removed from `sanitize.go`; the SHA-256 sync-check test (`TestBundledPatternsMatchCanonical`) gates drift between the canonical file and the bundled copy. Pattern 2 (Shared Pattern Repository) now holds for Go too.
- **Oracle `DBMS_*` + shell `${IFS}` patterns** added to the shared corpus.

## What was new in v1.5.0

- **chi adapter** (`github.com/GagancM/arcis/chi`). Granular helpers (Headers / Sanitizer / Validate / Csrf / SecureCookies / Cors / ErrorHandler) plus the bundle middleware. Stdlib-only at runtime; composes with any router that accepts `func(http.Handler) http.Handler`.
- **Fiber adapter** (`github.com/GagancM/arcis/fiber`). Bundle middleware + standalone `RateLimit` helpers + `WithTelemetry` option. The Fiber adapter does NOT yet expose the granular Headers / Sanitizer / Validate / Csrf / SecureCookies / Cors / ErrorHandler helpers that the chi adapter does; that surface lands in v1.7. For granular composition today, use chi (also stdlib-only).
- **net/http stdlib helper** (`github.com/GagancM/arcis/nethttp`). Drop-in for users without a third-party router. Re-exports the chi adapter's bundle middleware and rate-limit helpers, no chi dep needed at runtime. For chi's granular helpers (CSRF, CORS, cookies, error handler) today, import `arcis/chi` directly.
- **Telemetry parity** with Node + Python. `telemetry.NewClient` + `MiddlewareWithConfig`'s `Telemetry` field stream allow / deny decisions to a self-hosted dashboard from gin / echo / chi / fiber / nethttp middleware.
- **Guards API** (`arcis.NewGuards`). Non-HTTP rule engine for queue consumers, agent tool handlers, background jobs.
- **AI-era protections**: 28-signature prompt-injection library (`DetectPromptInjection`), per-key `TokenBudget`, 695-pattern bot corpus (635 from `getarcis/well-known-bots` + 15 Arcis additions for Selenium / Puppeteer / Playwright / Cypress / WebDriver / headless browser fakes).

## Quick start (Gin)

```go
import (
    "github.com/gin-gonic/gin"
    arcisgin "github.com/GagancM/arcis/gin"
)

func main() {
    r := gin.Default()
    cfg := arcisgin.DefaultConfig()
    cfg.Block = true   // 403 on attack payloads (opt-in)
    r.Use(arcisgin.MiddlewareWithConfig(cfg))
    r.GET("/", handler)
    r.Run(":8080")
}
```

## Quick start (chi)

```go
import (
    "net/http"

    "github.com/go-chi/chi/v5"
    arcischi "github.com/GagancM/arcis/chi"
)

func main() {
    r := chi.NewRouter()
    cfg := arcischi.DefaultConfig()
    cfg.Block = true
    r.Use(arcischi.MiddlewareWithConfig(cfg))
    r.Get("/", handler)
    http.ListenAndServe(":8080", r)
}
```

The chi adapter is stdlib-only at runtime — `chi/v5` is only required
in test builds. The adapter's middleware signature is the standard
`func(next http.Handler) http.Handler`, so it composes with any router
that accepts stdlib middleware (gorilla/mux, plain `net/http`, etc.).

## Quick start (Fiber)

```go
import (
    "github.com/gofiber/fiber/v2"
    arcisfiber "github.com/GagancM/arcis/fiber"
)

func main() {
    app := fiber.New()
    cfg := arcisfiber.DefaultConfig()
    cfg.Block = true
    app.Use(arcisfiber.MiddlewareWithConfig(cfg))
    app.Get("/", handler)
    app.Listen(":8080")
}
```

## Quick start (Echo)

```go
import (
    "github.com/labstack/echo/v4"
    arcisecho "github.com/GagancM/arcis/echo"
)

func main() {
    e := echo.New()
    cfg := arcisecho.DefaultConfig()
    cfg.Block = true
    e.Use(arcisecho.MiddlewareWithConfig(cfg))
    e.GET("/", handler)
    e.Start(":8080")
}
```

## Quick start (plain net/http)

For users without a third-party router, the `nethttp` subpackage exposes
the same middleware shape as a `func(http.Handler) http.Handler`
decorator. No router dependency.

```go
import (
    "net/http"
    archttp "github.com/GagancM/arcis/nethttp"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", handler)

    cfg := archttp.DefaultConfig()
    cfg.Block = true
    var h http.Handler = mux
    h = archttp.MiddlewareWithConfig(cfg)(h)

    http.ListenAndServe(":8080", h)
}
```

Composes with any router that accepts stdlib middleware (chi, gorilla/mux,
or hand-rolled).

## Block mode (v1.4.4+)

By default (`Block: false`) the middleware exposes a `*Sanitizer` in the request context (`c.Get("arcis_sanitizer")` on gin / equivalent on the other adapters) for handlers to sanitize on demand. Setting `Config.Block = true` switches the middleware to scan body / query / URL path against `arcis.ScanThreats` and respond 403 with a `SECURITY_THREAT` body when an attack pattern is detected, before the handler runs. The 403 response includes the matched vector so clients can see why the request was rejected.

```json
{
  "error": "Request blocked for security reasons",
  "code": "SECURITY_THREAT",
  "vector": "xss"
}
```

Block-mode scans (the `scanRequestForThreats` path) walk JSON request bodies, form-urlencoded request bodies, query parameters, and the URL path, calling `arcis.ScanThreats`. The detectors that fire today are: XSS, SSTI, XXE, email-header, LDAP-strict, SQL, XPath, path, command, NoSQL-keys, prototype pollution. The newer v1.6 detectors (`DetectDeserialization`, `InspectGraphqlQuery`, `DetectPromptInjection`) are NOT yet folded into the request-boundary `ScanThreats` walk. Call them directly from your handler if you want them gating the response.

Body is read once and restored unconditionally so handlers can re-bind the request without parser issues.

## Status

The Go SDK ships **detection + block middleware + standalone detectors + telemetry**. v1.6.2 added the new helper APIs (`CorrelationWindow`, `DetectDeserialization`, GraphQL V34, mutation tester). These are not yet re-exported from the root `arcis` package; import them from `arcis/middleware` and `arcis/sanitizers` directly. Root re-exports land in v1.7.

## Telemetry (v1.5.0+)

Stream allow / deny decisions from the gin, echo, chi, fiber, or nethttp middleware to a self-hosted Arcis dashboard. Stdlib only; opt-in (nil = zero overhead).

```go
import "github.com/GagancM/arcis/telemetry"

tc, _ := telemetry.NewClient(telemetry.Options{
    Endpoint: "https://arcis.mycorp.com/v1/events",
})
defer tc.Close(context.Background())

cfg := arcisgin.DefaultConfig()
cfg.Telemetry = tc
r.Use(arcisgin.MiddlewareWithConfig(cfg))
```

(Same shape for echo: `arcisecho.MiddlewareWithConfig(cfg)`, and for
chi: `arcischi.MiddlewareWithConfig(cfg)`.) Each request emits one
`TelemetryEvent` matching `spec/API_SPEC.md` §9 — same wire shape Node
and Python ship, batched and POSTed in the background.

For granular composition, the standalone `RateLimit` /
`RateLimitWithStore` / `RateLimitWithSkip` helpers accept a
`WithTelemetry(tc)` option and emit on 429:

```go
r.Use(arcisgin.RateLimit(100, time.Minute, arcisgin.WithTelemetry(tc)))
```

Same option shape on every framework adapter: `arcisecho.RateLimit(...)`, `arcischi.RateLimit(...)`, `arcisfiber.RateLimit(...)`, `archttp.RateLimit(...)`. Standalone helpers emit on deny only. Composing several of them with the same client does not multiply
per-request events.

### No native SCA scanner

The `arcis sca` supply-chain command ships as a single static binary via npm:

```bash
npm install -g @arcis/cli
arcis sca .   # works on any project — Python, Node, Go — by reading lockfiles
```

`arcis sca` is language-agnostic at the lockfile layer. It reads
`go.sum`, `package-lock.json`, `requirements.txt`, etc. directly. The
binary is the canonical install path regardless of which SDK you deploy
in your app. (Before v1.5.0, the CLI shipped inside the Python SDK; that's
no longer the case.)

## See also

- [API spec](../../spec/API_SPEC.md) — function contracts shared across SDKs
- [Test vectors](../../spec/TEST_VECTORS.json) — payloads every SDK must
  classify identically (`detect_parity` block)
- [Node SDK](../arcis-node/) — same surface in TypeScript
- [Python SDK](../arcis-python/) — same surface + the `arcis` CLI tools
