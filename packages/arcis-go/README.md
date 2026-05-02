# Arcis — Go SDK

Zero-dependency security middleware for Go web applications. Adapters
ship for Gin and Echo. Detects + sanitizes XSS, SQL injection, NoSQL
injection, path traversal, command injection, prototype pollution,
SSTI, XXE, and more across the same surface as the Node and Python SDKs.

```bash
go get github.com/GagancM/arcis@latest
```

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

The Go SDK ships **detection + block middleware + standalone detectors**.
Two surfaces present in the Node and Python SDKs are not yet shipped in
Go:

### No telemetry pipeline yet

The Node and Python SDKs ship a `TelemetryClient` that batches + flushes
decision events to a self-hosted Arcis dashboard. The Go SDK does **not**
include this yet — block-mode 403s in Go services are real but don't
appear on the dashboard's Live Requests page.

If you need dashboard visibility today, front Go services with a
Node/Python proxy that runs the Arcis middleware. Native Go telemetry is
planned for v1.5.0.

### No native SCA scanner

The `arcis sca` supply-chain command is shipped only as a Python CLI:

```bash
pip install arcis
arcis sca .   # works on any project — Python, Node, Go — by reading lockfiles
```

`arcis sca` is language-agnostic at the lockfile layer. It reads
`go.sum`, `package-lock.json`, `requirements.txt`, etc. directly, so
installing it via `pip` is the canonical install path regardless of
which SDK you deploy. A native Go binary for `arcis sca` will land when
a customer asks; until then, `pip install arcis` is the recommended
companion install for Go shops.

## See also

- [API spec](../../spec/API_SPEC.md) — function contracts shared across SDKs
- [Test vectors](../../spec/TEST_VECTORS.json) — payloads every SDK must
  classify identically (`detect_parity` block)
- [Node SDK](../arcis-node/) — same surface in TypeScript
- [Python SDK](../arcis-python/) — same surface + the `arcis` CLI tools
