package gin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// E1 — dry-run + OnSanitize tests for the Gin adapter.
//
// Mirrors arcis-python/tests/integration/test_dry_run_on_sanitize.py.
// Same three buckets: block-mode no regression, dry-run skips deny,
// OnSanitize callback fires + survives panics.

func init() {
	gin.SetMode(gin.TestMode)
}

func buildE1App(cfg Config) *gin.Engine {
	r := gin.New()
	r.Use(MiddlewareWithConfig(cfg))
	r.POST("/echo", func(c *gin.Context) {
		var body map[string]interface{}
		_ = c.ShouldBindJSON(&body)
		c.JSON(http.StatusOK, gin.H{"ok": true, "received": body})
	})
	return r
}

func TestE1_BlockModeNoRegression(t *testing.T) {
	r := buildE1App(Config{Block: true, RateLimit: false, Headers: false})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"POST", "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "SECURITY_THREAT" {
		t.Errorf("expected SECURITY_THREAT code, got %v", resp)
	}
}

func TestE1_DryRunSkipsDeny(t *testing.T) {
	r := buildE1App(Config{
		Block: true, DryRun: true, RateLimit: false, Headers: false,
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"POST", "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("dry-run should pass through with 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["ok"] != true {
		t.Errorf("expected ok=true from handler, got %v", resp)
	}
}

func TestE1_OnSanitizeFiresOnThreat(t *testing.T) {
	var mu sync.Mutex
	events := []SanitizeEvent{}
	r := buildE1App(Config{
		Block:      true,
		RateLimit:  false,
		Headers:    false,
		OnSanitize: func(e SanitizeEvent) { mu.Lock(); defer mu.Unlock(); events = append(events, e) },
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"POST", "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Vector != "xss" {
		t.Errorf("expected vector=xss, got %q", events[0].Vector)
	}
	if events[0].Path != "/echo" {
		t.Errorf("expected path=/echo, got %q", events[0].Path)
	}
	if events[0].DryRun != false {
		t.Errorf("expected DryRun=false, got true")
	}
}

func TestE1_OnSanitizeDryRunFlagTrueInDryMode(t *testing.T) {
	var mu sync.Mutex
	events := []SanitizeEvent{}
	r := buildE1App(Config{
		Block:      true,
		DryRun:     true,
		RateLimit:  false,
		Headers:    false,
		OnSanitize: func(e SanitizeEvent) { mu.Lock(); defer mu.Unlock(); events = append(events, e) },
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"POST", "/echo",
		strings.NewReader(`{"username":"*)(uid=*))(|(uid=*"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].DryRun != true {
		t.Error("expected DryRun=true on event from dry-run config")
	}
	if events[0].Vector != "ldap" {
		t.Errorf("expected vector=ldap, got %q", events[0].Vector)
	}
}

func TestE1_OnSanitizeDoesNotFireOnClean(t *testing.T) {
	var mu sync.Mutex
	events := []SanitizeEvent{}
	r := buildE1App(Config{
		Block:      true,
		RateLimit:  false,
		Headers:    false,
		OnSanitize: func(e SanitizeEvent) { mu.Lock(); defer mu.Unlock(); events = append(events, e) },
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"POST", "/echo",
		strings.NewReader(`{"q":"hello world"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 0 {
		t.Errorf("expected no events on clean traffic, got %d", len(events))
	}
}

func TestE1_OnSanitizePanicDoesNotCrash(t *testing.T) {
	r := buildE1App(Config{
		Block:     true,
		RateLimit: false,
		Headers:   false,
		OnSanitize: func(e SanitizeEvent) {
			panic("callback exploded")
		},
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(
		"POST", "/echo",
		strings.NewReader(`{"q":"<script>alert(1)</script>"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	// Should not crash; should still produce the 403.
	r.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Errorf("middleware should survive callback panic + still 403, got %d", w.Code)
	}
}
