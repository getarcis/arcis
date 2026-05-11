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

## What's new in v1.5.0

- **chi adapter** (`github.com/GagancM/arcis/chi`) — granular helpers (Headers / Sanitizer / Validate / Csrf / SecureCookies / Cors / ErrorHandler) plus the bundle middleware. Stdlib-only at runtime; composes with any router that accepts `func(http.Handler) http.Handler`.
- **Fiber adapter** (`github.com/GagancM/arcis/fiber`) — bundle middleware + standalone `RateLimit` helpers + `WithTelemetry` option, mirroring gin/echo/chi.
- **net/http stdlib helper** (`github.com/GagancM/arcis/nethttp`) — drop-in for users without a third-party router. Re-exports the chi adapter (which is itself stdlib-only), no chi dep needed at runtime.
- **Telemetry parity** with Node + Python — `telemetry.NewClient` + `MiddlewareWithConfig`'s `Telemetry` field stream allow / deny decisions to a self-hosted dashboard.
- **Guards API** (`arcis.NewGuards`) — non-HTTP rule engine for queue consumers, agent tool handlers, background jobs.
- **AI-era protections**: 28-signature prompt-injection library (`DetectPromptInjection`), per-key `TokenBudget`, 646-pattern bot corpus from `getarcis/well-known-bots`.

## Quick start (Gin)

```go
import (
    "github.com/gin-gonic/gin"
    arcisgin "github.com/GagancM/arcis/gin"
)

func main() {
    r := gin.Default()
    cfg := arcisgin.DefaultConfig()
    cfg.Block = true   // 403 on attack payloads (opt-in for v1.4.4)
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

Setting `Config.Block = true` flips the middleware from "silently sanitize
in place" to "respond 403 with a `SECURITY_THREAT` body when an attack
payload is detected". The 403 response includes the matched vector so
clients can see why the request was rejected.

```json
{
  "error": "Request blocked for security reasons",
  "code": "SECURITY_THREAT",
  "vector": "xss"
}
```

Block-mode scans:

- JSON request bodies (`Content-Type: application/json`)
- Form-urlencoded request bodies (`Content-Type: application/x-www-form-urlencoded`)
- Query parameters
- The URL path itself

Body is read once and restored unconditionally so handlers can re-bind
the request without parser issues.

## Status

The Go SDK ships **detection + block middleware + standalone detectors +
telemetry**. One surface present in the Node and Python SDKs is not yet
shipped in Go:

## Telemetry (v1.5.0+)

Stream allow / deny decisions from the gin, echo, or chi middleware to
a self-hosted Arcis dashboard. Stdlib only; opt-in (nil = zero overhead).

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

Same option shape on echo (`arcisecho.RateLimit(...)`) and chi
(`arcischi.RateLimit(...)`). Standalone helpers emit on deny only —
composing several of them with the same client doesn't multiply
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
