// Telemetry-shaped chi adapter tests. Mirrors gin/telemetry_test.go and
// echo/telemetry_test.go file-by-file:
//
//   - allow path: bundle MiddlewareWithConfig with Telemetry set, single
//     event with empty vector/rule/severity, 200 status.
//   - bundle deny path: Block=true + XSS payload, single event with
//     vector="xss" / rule="xss/match" / severity="high" / status=403.
//   - standalone RateLimit deny: variadic WithTelemetry option, 429 emits
//     vector="rate-limit" / rule="rate-limit/exceeded" / severity="medium"
//     and the preceding allow does NOT emit (Phase 2b deny-only semantic).
//
// `recordingServer` here is the FOURTH copy in the repo (gin, echo,
// telemetry/client_test). Extracting it to a shared `telemetrytest`
// helper conflicts with the file-ownership boundary; deferred to a
// janitor session that can touch all four files at once.
package chi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	chirouter "github.com/go-chi/chi/v5"

	"github.com/getarcis/arcis/telemetry"
)

func recordingServer(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ch := make(chan []byte, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, ch
}

func decodeFirstEvent(t *testing.T, body []byte) telemetry.Event {
	t.Helper()
	var env struct {
		Events []telemetry.Event `json:"events"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decode batch: %v (body=%q)", err, body)
	}
	if len(env.Events) != 1 {
		t.Fatalf("got %d events, want 1", len(env.Events))
	}
	return env.Events[0]
}

func mustReceiveBody(t *testing.T, ch <-chan []byte, deadline time.Duration) []byte {
	t.Helper()
	select {
	case b := <-ch:
		return b
	case <-time.After(deadline):
		t.Fatal("timeout waiting for telemetry POST")
		return nil
	}
}

func TestChiTelemetry_AllowPath(t *testing.T) {
	url, reqs := recordingServer(t)
	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      url,
		BatchSize:     1, // flush per-event for deterministic tests
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.RateLimit = false // isolate from rate-limit interference
	cfg.Block = false
	cfg.Telemetry = tc

	r := chirouter.NewRouter()
	r.Use(MiddlewareWithConfig(cfg))
	r.Get("/ok", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	t.Cleanup(Cleanup)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("User-Agent", "test-ua-allow")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("response code = %d, want 200", w.Code)
	}

	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	evt := decodeFirstEvent(t, mustReceiveBody(t, reqs, time.Second))

	if evt.Decision != telemetry.DecisionAllow {
		t.Errorf("Decision = %q, want allow", evt.Decision)
	}
	if evt.Vector != "" {
		t.Errorf("Vector = %q, want empty", evt.Vector)
	}
	if evt.Rule != "" {
		t.Errorf("Rule = %q, want empty", evt.Rule)
	}
	if evt.Severity != "" {
		t.Errorf("Severity = %q, want empty", evt.Severity)
	}
	if evt.Status != http.StatusOK {
		t.Errorf("Status = %d, want 200", evt.Status)
	}
	if evt.Method != http.MethodGet {
		t.Errorf("Method = %q, want GET", evt.Method)
	}
	if evt.Path != "/ok" {
		t.Errorf("Path = %q, want /ok", evt.Path)
	}
	if evt.UserAgent != "test-ua-allow" {
		t.Errorf("UserAgent = %q, want test-ua-allow", evt.UserAgent)
	}
	if evt.LatencyMs < 0 {
		t.Errorf("LatencyMs = %v, want >= 0", evt.LatencyMs)
	}
	if evt.Ts == "" {
		t.Errorf("Ts is empty, want RFC3339 timestamp")
	}
}

func TestChiTelemetry_BlockDenyPath(t *testing.T) {
	url, reqs := recordingServer(t)
	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      url,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.RateLimit = false
	cfg.Block = true
	cfg.Telemetry = tc

	r := chirouter.NewRouter()
	r.Use(MiddlewareWithConfig(cfg))
	r.Post("/api", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("should-not-reach"))
	})
	t.Cleanup(Cleanup)

	body := `{"q":"<script>alert(1)</script>"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-ua-deny")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("response code = %d, want 403", w.Code)
	}

	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	evt := decodeFirstEvent(t, mustReceiveBody(t, reqs, time.Second))

	if evt.Decision != telemetry.DecisionDeny {
		t.Errorf("Decision = %q, want deny", evt.Decision)
	}
	if evt.Vector != "xss" {
		t.Errorf("Vector = %q, want xss", evt.Vector)
	}
	if evt.Rule != "xss/match" {
		t.Errorf("Rule = %q, want xss/match", evt.Rule)
	}
	if evt.Severity != telemetry.SeverityHigh {
		t.Errorf("Severity = %q, want high", evt.Severity)
	}
	if evt.MatchedPattern == "" {
		t.Errorf("MatchedPattern is empty, want a sample of the attack string")
	}
	if evt.Reason != "Detected xss pattern" {
		t.Errorf("Reason = %q, want Detected xss pattern", evt.Reason)
	}
	if evt.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", evt.Status)
	}
	if evt.Path != "/api" {
		t.Errorf("Path = %q, want /api", evt.Path)
	}
}

// TestChiTelemetry_StandaloneRateLimitDeny pins the Phase 2b semantic:
// standalone RateLimit + WithTelemetry emits on deny only. Two requests
// (allow then deny) must produce exactly ONE telemetry POST with the
// 429-shaped event — no duplicates from composing RateLimit with other
// middleware.
func TestChiTelemetry_StandaloneRateLimitDeny(t *testing.T) {
	url, reqs := recordingServer(t)
	tc, err := telemetry.NewClient(telemetry.Options{
		Endpoint:      url,
		BatchSize:     1,
		FlushInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := chirouter.NewRouter()
	r.Use(RateLimit(1, time.Minute, WithTelemetry(tc)))
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	})
	t.Cleanup(Cleanup)

	// Same RemoteAddr → same rate-limit key. First passes, second 429s.
	hit := func() int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req.RemoteAddr = "10.0.0.1:5555"
		req.Header.Set("User-Agent", "test-ua-rl")
		r.ServeHTTP(w, req)
		return w.Code
	}
	if got := hit(); got != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", got)
	}
	if got := hit(); got != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", got)
	}

	if err := tc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Deny-only emit: two requests, one deny = exactly one telemetry POST.
	evt := decodeFirstEvent(t, mustReceiveBody(t, reqs, time.Second))
	select {
	case extra := <-reqs:
		t.Fatalf("unexpected second telemetry POST (allow should not emit): body=%q", extra)
	case <-time.After(150 * time.Millisecond):
	}

	if evt.Decision != telemetry.DecisionDeny {
		t.Errorf("Decision = %q, want deny", evt.Decision)
	}
	if evt.Vector != "rate-limit" {
		t.Errorf("Vector = %q, want rate-limit", evt.Vector)
	}
	if evt.Rule != "rate-limit/exceeded" {
		t.Errorf("Rule = %q, want rate-limit/exceeded", evt.Rule)
	}
	if evt.Severity != telemetry.SeverityMedium {
		t.Errorf("Severity = %q, want medium", evt.Severity)
	}
	if evt.Status != http.StatusTooManyRequests {
		t.Errorf("Status = %d, want 429", evt.Status)
	}
	if evt.Reason != "Rate limit exceeded" {
		t.Errorf("Reason = %q, want Rate limit exceeded", evt.Reason)
	}
}
