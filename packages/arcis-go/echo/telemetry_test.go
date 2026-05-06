package echo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/GagancM/arcis/telemetry"
)

// recordingServer captures every request body to ch and replies 200.
// Duplicated (~10 lines) into gin/telemetry_test.go and telemetry/client_test.go;
// extract to a shared `telemetrytest` package only when a fourth caller appears.
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

func TestEchoTelemetry_AllowPath(t *testing.T) {
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
	cfg.Block = false
	cfg.Telemetry = tc

	e := echo.New()
	e.Use(MiddlewareWithConfig(cfg))
	e.GET("/ok", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	req.Header.Set("User-Agent", "test-ua-allow")
	e.ServeHTTP(w, req)

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

func TestEchoTelemetry_BlockDenyPath(t *testing.T) {
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

	e := echo.New()
	e.Use(MiddlewareWithConfig(cfg))
	e.POST("/api", func(c echo.Context) error { return c.String(http.StatusOK, "should-not-reach") })

	body := `{"q":"<script>alert(1)</script>"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-ua-deny")
	e.ServeHTTP(w, req)

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
