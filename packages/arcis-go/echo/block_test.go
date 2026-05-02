package echo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
)

func blockApp() *echo.Echo {
	e := echo.New()
	cfg := DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	e.Use(MiddlewareWithConfig(cfg))
	e.POST("/echo", func(c echo.Context) error {
		var body map[string]interface{}
		_ = c.Bind(&body)
		return c.JSON(http.StatusOK, map[string]interface{}{"received": body})
	})
	e.GET("/items", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{"ok": true})
	})
	return e
}

func TestBlock_CleanRequestPasses(t *testing.T) {
	e := blockApp()
	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestBlock_AttackPayloads(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		vector string
	}{
		{"xss", `{"q":"<script>alert(1)</script>"}`, "xss"},
		{"sql", `{"q":"1' OR '1'='1'"}`, "sql"},
		{"path", `{"q":"../../etc/passwd"}`, "path"},
		{"command", `{"q":"$(whoami)"}`, "command"},
		{"nosql", `{"$where":"function(){return true}"}`, "nosql"},
		{"prototype", `{"__proto__":{"x":1}}`, "prototype"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := blockApp()
			req := httptest.NewRequest(http.MethodPost, "/echo", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			e.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("expected 403, got %d (body=%s)", w.Code, w.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("invalid json: %v", err)
			}
			if resp["code"] != "SECURITY_THREAT" {
				t.Errorf("expected SECURITY_THREAT code, got %v", resp["code"])
			}
			if resp["vector"] != tc.vector {
				t.Errorf("expected vector %q, got %v", tc.vector, resp["vector"])
			}
		})
	}
}

func TestBlock_DisabledByDefault(t *testing.T) {
	e := echo.New()
	cfg := DefaultConfig()
	cfg.RateLimit = false
	e.Use(MiddlewareWithConfig(cfg))
	e.POST("/echo", func(c echo.Context) error {
		var body map[string]interface{}
		_ = c.Bind(&body)
		return c.JSON(http.StatusOK, map[string]interface{}{"received": body})
	})
	req := httptest.NewRequest(http.MethodPost, "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 in default mode, got %d", w.Code)
	}
}
