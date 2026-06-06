package fiber_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	arcisfiber "github.com/getarcis/arcis/v2/fiber"
)

// makeApp returns a fiber app with the bundle middleware applied and a
// `/echo` GET / POST handler that returns the request body or "ok".
func makeApp(cfg arcisfiber.Config) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})
	app.Use(arcisfiber.MiddlewareWithConfig(cfg))
	app.All("/echo", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})
	return app
}

func sendJSON(t *testing.T, app *fiber.App, method, path string, body any) *http.Response {
	t.Helper()
	var buf io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, buf)
	if body != nil {
		req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	}
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return res
}

func TestMiddleware_AllowsCleanRequest(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := makeApp(arcisfiber.DefaultConfig())

	res := sendJSON(t, app, "GET", "/echo", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", res.StatusCode)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options: got %q want DENY", got)
	}
	if res.Header.Get("Server") != "" {
		t.Fatalf("Server header should be stripped, got %q", res.Header.Get("Server"))
	}
}

func TestMiddleware_BlockMode_RejectsXSS(t *testing.T) {
	defer arcisfiber.Cleanup()
	cfg := arcisfiber.DefaultConfig()
	cfg.Block = true
	app := makeApp(cfg)

	res := sendJSON(t, app, "POST", "/echo", map[string]any{
		"q": "<script>alert(1)</script>",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", res.StatusCode)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var payload struct {
		Code   string `json:"code"`
		Vector string `json:"vector"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("body decode: %v", err)
	}
	if payload.Code != "SECURITY_THREAT" {
		t.Fatalf("code: got %q want SECURITY_THREAT", payload.Code)
	}
	if payload.Vector != "xss" {
		t.Fatalf("vector: got %q want xss", payload.Vector)
	}
}

func TestMiddleware_BlockMode_AllowsCleanBody(t *testing.T) {
	defer arcisfiber.Cleanup()
	cfg := arcisfiber.DefaultConfig()
	cfg.Block = true
	app := makeApp(cfg)

	res := sendJSON(t, app, "POST", "/echo", map[string]any{"name": "Gagan"})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", res.StatusCode)
	}
}

func TestMiddleware_BlockMode_RejectsQueryPathTraversal(t *testing.T) {
	defer arcisfiber.Cleanup()
	cfg := arcisfiber.DefaultConfig()
	cfg.Block = true
	app := makeApp(cfg)

	req := httptest.NewRequest("GET", "/echo?f=../../etc/passwd", nil)
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", res.StatusCode)
	}
}

func TestRateLimit_Standalone_BlocksAfterCap(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.RateLimit(2, time.Minute))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString("ok") })

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		res, _ := app.Test(req, -1)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("call %d: got %d want 200", i, res.StatusCode)
		}
	}
	req := httptest.NewRequest("GET", "/", nil)
	res, _ := app.Test(req, -1)
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third call: got %d want 429", res.StatusCode)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Fatalf("Retry-After header missing on 429")
	}
}

func TestRateLimit_WithSkip_ExemptsHealthcheck(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.RateLimitWithSkip(1, time.Minute, func(c *fiber.Ctx) bool {
		return c.Path() == "/healthz"
	}))
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.SendString("ok") })
	app.Get("/api", func(c *fiber.Ctx) error { return c.SendString("ok") })

	// Five healthz calls, all 200.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/healthz", nil)
		res, _ := app.Test(req, -1)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("healthz %d: got %d want 200", i, res.StatusCode)
		}
	}
	// First /api passes the cap-of-1 limiter.
	req1 := httptest.NewRequest("GET", "/api", nil)
	res1, _ := app.Test(req1, -1)
	if res1.StatusCode != http.StatusOK {
		t.Fatalf("first /api: got %d want 200", res1.StatusCode)
	}
	// Second /api hits 429 (limit is 1; skip only exempts /healthz).
	req2 := httptest.NewRequest("GET", "/api", nil)
	res2, _ := app.Test(req2, -1)
	if res2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second /api: got %d want 429", res2.StatusCode)
	}
}

func TestMiddlewareWithConfig_HeadersOnly(t *testing.T) {
	defer arcisfiber.Cleanup()
	cfg := arcisfiber.Config{
		Headers:        true,
		FrameOptions:   "SAMEORIGIN",
		ReferrerPolicy: "no-referrer",
		HSTSMaxAge:     63072000,
		HSTSSubdomains: true,
		CSP:            "default-src 'none'",
	}
	app := makeApp(cfg)

	req := httptest.NewRequest("GET", "/echo", nil)
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if got := res.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("X-Frame-Options: got %q want SAMEORIGIN", got)
	}
	if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy: got %q", got)
	}
	if got := res.Header.Get("Content-Security-Policy"); got != "default-src 'none'" {
		t.Fatalf("CSP: got %q", got)
	}
	hsts := res.Header.Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=63072000") || !strings.Contains(hsts, "includeSubDomains") {
		t.Fatalf("HSTS: got %q", hsts)
	}
}

func TestGetSanitizer_ReturnsInstance(t *testing.T) {
	defer arcisfiber.Cleanup()
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(arcisfiber.Middleware())
	var seen bool
	app.Get("/", func(c *fiber.Ctx) error {
		s := arcisfiber.GetSanitizer(c)
		if s != nil {
			seen = true
		}
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/", nil)
	if _, err := app.Test(req, -1); err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if !seen {
		t.Fatalf("expected GetSanitizer to return non-nil Sanitizer when middleware is in the chain")
	}
}
