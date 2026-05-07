package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func newReq(method, body string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, "/chat", bytes.NewBufferString(body))
	if body != "" {
		req.ContentLength = int64(len(body))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// ─── default behavior ────────────────────────────────────────────────────

func TestTokenBudget_Passthrough(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 1000})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec := httptest.NewRecorder()
	req := newReq("POST", "short", nil)
	req.RemoteAddr = "10.0.0.1:443"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("X-Token-Budget-Limit") != "1000" {
		t.Errorf("missing X-Token-Budget-Limit, got %q", rec.Header().Get("X-Token-Budget-Limit"))
	}
	insp := tb.Inspect("10.0.0.1")
	if insp == nil || insp.Used == 0 {
		t.Errorf("expected non-zero usage charged, got %+v", insp)
	}
}

func TestTokenBudget_ResponseHeaders(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 1000})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec := httptest.NewRecorder()
	req := newReq("POST", "short", nil)
	h.ServeHTTP(rec, req)

	for _, key := range []string{
		"X-Token-Budget-Limit",
		"X-Token-Budget-Used",
		"X-Token-Budget-Remaining",
		"X-Token-Budget-Reset",
		"X-Token-Budget-Request-Cost",
	} {
		if rec.Header().Get(key) == "" {
			t.Errorf("expected header %s set", key)
		}
	}
}

// ─── 429 on exhaustion ───────────────────────────────────────────────────

func TestTokenBudget_429OnExhaustion(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 1})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec := httptest.NewRecorder()
	req := newReq("POST", "this is more than 1 token worth of body", nil)
	req.RemoteAddr = "5.5.5.5:443"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if body["maxTokens"] != float64(1) {
		t.Errorf("expected maxTokens=1, got %v", body["maxTokens"])
	}
}

func TestTokenBudget_PerKeyIsolation(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 5})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec1 := httptest.NewRecorder()
	r1 := newReq("POST", "hi", nil)
	r1.RemoteAddr = "1.1.1.1:443"
	h.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first key blocked unexpectedly: %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	r2 := newReq("POST", "hi", nil)
	r2.RemoteAddr = "2.2.2.2:443"
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second key blocked unexpectedly: %d", rec2.Code)
	}
}

// ─── 413 on per-request oversize ─────────────────────────────────────────

func TestTokenBudget_413OnOversize(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 100_000, MaxRequestTokens: 2})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec := httptest.NewRecorder()
	req := newReq("POST", "this body is way larger than two tokens worth", nil)
	req.RemoteAddr = "7.7.7.7:443"
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rec.Code)
	}
	// Budget should NOT have been charged for the oversized request
	if tb.Inspect("7.7.7.7") != nil {
		t.Errorf("oversized request should not charge budget; inspect returned %+v", tb.Inspect("7.7.7.7"))
	}
}

// ─── custom key + estimator ──────────────────────────────────────────────

func TestTokenBudget_CustomKeyGenerator(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{
		MaxTokens: 1,
		KeyGenerator: func(r *http.Request) string {
			if k := r.Header.Get("X-Api-Key"); k != "" {
				return k
			}
			return "anon"
		},
	})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec1 := httptest.NewRecorder()
	r1 := newReq("POST", "this body is large enough to blow the budget", map[string]string{"X-Api-Key": "tenant-A"})
	h.ServeHTTP(rec1, r1)
	if rec1.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for tenant-A, got %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	r2 := newReq("POST", "this body is large enough to blow the budget", map[string]string{"X-Api-Key": "tenant-B"})
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for tenant-B, got %d", rec2.Code)
	}

	if tb.Inspect("tenant-A") == nil || tb.Inspect("tenant-B") == nil {
		t.Error("expected per-tenant buckets to exist")
	}
}

func TestTokenBudget_CustomEstimator(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{
		MaxTokens:      100,
		EstimateTokens: func(*http.Request) int { return 50 },
	})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := newReq("POST", "anything", nil)
		req.RemoteAddr = "9.9.9.9:443"
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("iteration %d: expected 200, got %d", i, rec.Code)
		}
	}
	insp := tb.Inspect("9.9.9.9")
	if insp == nil || insp.Used != 100 {
		t.Errorf("expected used=100, got %+v", insp)
	}
}

// ─── skip ────────────────────────────────────────────────────────────────

func TestTokenBudget_SkipBypassesEnforcement(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{
		MaxTokens: 1,
		Skip:      func(r *http.Request) bool { return r.URL.Path == "/health" },
	})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/health", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on skipped path, got %d", rec.Code)
	}
	// Skip path: no headers and no charge
	if rec.Header().Get("X-Token-Budget-Limit") != "" {
		t.Errorf("skipped requests should not get budget headers, got %q", rec.Header().Get("X-Token-Budget-Limit"))
	}
}

// ─── X-Forwarded-For preference ──────────────────────────────────────────

func TestTokenBudget_XForwardedForPreferred(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 1})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	// First request from real client behind proxy — XFF identifies the client
	rec1 := httptest.NewRecorder()
	r1 := newReq("POST", "this body is large enough to blow the budget", map[string]string{"X-Forwarded-For": "203.0.113.5, 10.0.0.1"})
	r1.RemoteAddr = "10.0.0.1:443"
	h.ServeHTTP(rec1, r1)

	// Second from same XFF client (different proxy hop) — should be the same key
	rec2 := httptest.NewRecorder()
	r2 := newReq("POST", "this body is large enough to blow the budget", map[string]string{"X-Forwarded-For": "203.0.113.5, 10.0.0.2"})
	r2.RemoteAddr = "10.0.0.2:443"
	h.ServeHTTP(rec2, r2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 (same XFF client throttled), got %d", rec2.Code)
	}
}

// ─── lifecycle ───────────────────────────────────────────────────────────

func TestTokenBudget_InspectUnknownReturnsNil(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{})
	defer tb.Close()
	if tb.Inspect("nobody") != nil {
		t.Error("expected nil for unknown key")
	}
}

func TestTokenBudget_ResetClearsKey(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 100})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	rec := httptest.NewRecorder()
	req := newReq("POST", "spend", nil)
	req.RemoteAddr = "1.2.3.4:443"
	h.ServeHTTP(rec, req)
	if tb.Inspect("1.2.3.4") == nil {
		t.Fatal("expected bucket to exist after request")
	}
	tb.Reset("1.2.3.4")
	if tb.Inspect("1.2.3.4") != nil {
		t.Error("expected bucket cleared after Reset")
	}
}

func TestTokenBudget_CloseIdempotent(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{})
	tb.Close()
	tb.Close() // must not panic
}

// ─── header / status numerics sanity ─────────────────────────────────────

func TestTokenBudget_RemainingCannotGoNegative(t *testing.T) {
	tb := NewTokenBudget(TokenBudgetOptions{MaxTokens: 1, Window: time.Hour})
	defer tb.Close()
	h := tb.Middleware()(okHandler())

	// Overshoot with a single big request — server returns 429 with X-Token-Budget-Remaining 0 or higher.
	rec := httptest.NewRecorder()
	req := newReq("POST", "a really really really long body to blow past the limit", nil)
	req.RemoteAddr = "1.1.1.1:443"
	h.ServeHTTP(rec, req)
	if got, _ := strconv.Atoi(rec.Header().Get("X-Token-Budget-Remaining")); got < 0 {
		t.Errorf("X-Token-Budget-Remaining should be >= 0, got %d", got)
	}
}
