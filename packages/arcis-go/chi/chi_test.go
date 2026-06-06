// Package chi tests — bundle middleware + granular helpers driven via
// a real chi.Router with httptest. The chi/v5 dep enters the module
// here in commit 3 alongside the first file that needs it.
//
// Telemetry-shaped tests live in `telemetry_test.go` (commit 4).
package chi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	chirouter "github.com/go-chi/chi/v5"

	arcis "github.com/getarcis/arcis/v2"
)

// newRouter is a small helper so each test gets a fresh chi router with
// a single attached middleware (or stack). Keeps the per-test boilerplate
// to one line and the setup intent obvious.
func newRouter(mw ...func(http.Handler) http.Handler) *chirouter.Mux {
	r := chirouter.NewRouter()
	for _, m := range mw {
		r.Use(m)
	}
	return r
}

// ── Middleware bundle ─────────────────────────────────────────────────

func TestMiddleware_AllowPathSetsSecurityHeaders(t *testing.T) {
	r := newRouter(Middleware())
	r.Get("/ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	t.Cleanup(Cleanup)

	res, err := http.Get(srv.URL + "/ping")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Content-Security-Policy"); got == "" {
		t.Errorf("CSP header missing on allow path")
	}
	if got := res.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestMiddleware_RateLimitReturns429AfterCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimitMax = 2
	cfg.RateLimitWindow = time.Minute
	cfg.Headers = false // Trim noise — we're only after the rate-limit branch.

	r := newRouter(MiddlewareWithConfig(cfg))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	t.Cleanup(Cleanup)

	// Two requests succeed, third blows the limiter.
	for i := 0; i < 2; i++ {
		res, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("req %d failed: %v", i, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("req %d status = %d, want 200", i, res.StatusCode)
		}
	}
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("third request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", res.StatusCode)
	}
	// Retry-After surfaces the reset window so clients can back off.
	if res.Header.Get("Retry-After") == "" {
		t.Errorf("Retry-After header missing on 429")
	}
}

func TestMiddleware_BlockModeReturns403OnAttack(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Block = true
	cfg.RateLimit = false // Take rate-limit out of the picture for this assertion.
	cfg.Headers = false

	r := newRouter(MiddlewareWithConfig(cfg))
	r.Post("/items", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	t.Cleanup(Cleanup)

	body := strings.NewReader(`{"name": "<script>alert(1)</script>"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/items", body)
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
}

func TestMiddleware_StashesSanitizerOnContext(t *testing.T) {
	r := newRouter(Middleware())
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		s := GetSanitizer(req)
		if s == nil {
			t.Fatal("GetSanitizer returned nil under bundle middleware")
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	t.Cleanup(Cleanup)

	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
}

// ── Headers helper ────────────────────────────────────────────────────

func TestHeaders_SetsHeadersWithoutRateLimit(t *testing.T) {
	r := newRouter(Headers())
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	// Hammer the endpoint past any rate limit — Headers helper must NOT
	// engage the limiter, so all 5 stay 200.
	for i := 0; i < 5; i++ {
		res, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("req %d failed: %v", i, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("req %d status = %d, want 200", i, res.StatusCode)
		}
		if got := res.Header.Get("Content-Security-Policy"); got == "" {
			t.Errorf("req %d: CSP header missing", i)
		}
	}
}

// ── Sanitizer / SanitizeJSON / SanitizeString ─────────────────────────

func TestSanitizer_StashesSanitizerOnContext(t *testing.T) {
	r := newRouter(Sanitizer())
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		if GetSanitizer(req) == nil {
			t.Fatal("GetSanitizer returned nil under Sanitizer() middleware")
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = res.Body.Close()
}

func TestSanitizeJSON_StripsScript(t *testing.T) {
	r := newRouter(Sanitizer())
	r.Post("/echo", func(w http.ResponseWriter, req *http.Request) {
		var data map[string]interface{}
		_ = json.NewDecoder(req.Body).Decode(&data)
		clean := SanitizeJSON(req, data)
		writeJSON(w, http.StatusOK, clean)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	body := bytes.NewReader([]byte(`{"name":"<script>alert(1)</script>hi"}`))
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/echo", body)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()

	var out map[string]interface{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	name, _ := out["name"].(string)
	if strings.Contains(name, "<script>") {
		t.Errorf("name still contains <script>: %q", name)
	}
}

func TestSanitizeString_StripsScript(t *testing.T) {
	r := newRouter(Sanitizer())
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		out := SanitizeString(req, req.URL.Query().Get("q"))
		_, _ = w.Write([]byte(out))
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/?q=" + "%3Cscript%3Ehi%3C%2Fscript%3E")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if strings.Contains(string(body), "<script>") {
		t.Errorf("response still contains <script>: %q", string(body))
	}
}

// ── Validate / GetValidatedBody ──────────────────────────────────────

func TestValidate_400OnInvalidJSON(t *testing.T) {
	schema := arcis.ValidationSchema{
		"name": {Type: arcis.TypeString, Required: true},
	}
	r := newRouter(Validate(schema))
	r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Post(srv.URL+"/", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.StatusCode)
	}
}

func TestValidate_400OnSchemaFail(t *testing.T) {
	schema := arcis.ValidationSchema{
		"name": {Type: arcis.TypeString, Required: true},
	}
	r := newRouter(Validate(schema))
	r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	// Empty object — required field missing.
	res, err := http.Post(srv.URL+"/", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.StatusCode)
	}
	var out map[string]interface{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if _, ok := out["errors"]; !ok {
		t.Errorf(`response missing "errors" key: %v`, out)
	}
}

func TestValidate_200AndStashesValidatedBody(t *testing.T) {
	schema := arcis.ValidationSchema{
		"name": {Type: arcis.TypeString, Required: true},
	}
	var seen map[string]interface{}
	r := newRouter(Validate(schema))
	r.Post("/", func(w http.ResponseWriter, req *http.Request) {
		seen = GetValidatedBody(req)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Post(srv.URL+"/", "application/json", strings.NewReader(`{"name":"alice"}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if seen == nil {
		t.Fatal("GetValidatedBody returned nil after Validate succeeded")
	}
	if seen["name"] != "alice" {
		t.Errorf("validated body name = %v, want alice", seen["name"])
	}
}

func TestGetValidatedBody_NilWithoutMiddleware(t *testing.T) {
	// No Validate middleware in the stack — GetValidatedBody must not
	// panic and must return nil (no key in context).
	r := newRouter()
	r.Get("/", func(w http.ResponseWriter, req *http.Request) {
		if GetValidatedBody(req) != nil {
			t.Errorf("GetValidatedBody = non-nil without Validate middleware")
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	_ = res.Body.Close()
}

// ── CsrfProtection ────────────────────────────────────────────────────

func TestCsrfProtection_PostWithoutTokenIs403(t *testing.T) {
	r := newRouter(CsrfProtection(arcis.CsrfOptions{}))
	r.Post("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Post(srv.URL+"/", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", res.StatusCode)
	}
}

func TestCsrfProtection_GetIssuesCookie(t *testing.T) {
	r := newRouter(CsrfProtection(arcis.CsrfOptions{}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Errorf("CSRF middleware did not set a cookie on safe method GET")
	}
}

// ── SecureCookies ────────────────────────────────────────────────────

func TestSecureCookies_AddsSecureAttribute(t *testing.T) {
	r := newRouter(SecureCookies(arcis.SecureCookieOptions{}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "abc"})
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	cookieRaw := res.Header.Get("Set-Cookie")
	if cookieRaw == "" {
		t.Fatal("no Set-Cookie header on response")
	}
	if !strings.Contains(cookieRaw, "Secure") {
		t.Errorf("Set-Cookie missing Secure attribute: %q", cookieRaw)
	}
	if !strings.Contains(cookieRaw, "HttpOnly") {
		t.Errorf("Set-Cookie missing HttpOnly attribute: %q", cookieRaw)
	}
}

// ── Cors ──────────────────────────────────────────────────────────────

func TestCors_PreflightShortCircuits204(t *testing.T) {
	r := newRouter(Cors(arcis.CorsOptions{
		Origin: "https://app.example.com",
	}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("preflight should not reach the handler")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", res.StatusCode)
	}
	if got := res.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Errorf("Access-Control-Allow-Origin missing on preflight response")
	}
}

func TestCors_NormalRequestGetsHeaders(t *testing.T) {
	r := newRouter(Cors(arcis.CorsOptions{
		Origin: "https://app.example.com",
	}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", res.StatusCode)
	}
	if got := res.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Errorf("Access-Control-Allow-Origin missing on normal response")
	}
}

// ── ErrorHandler ──────────────────────────────────────────────────────

func TestErrorHandler_RecoversFromPanicError(t *testing.T) {
	r := newRouter(ErrorHandler(false))
	r.Get("/", func(_ http.ResponseWriter, _ *http.Request) {
		panic(errors.New("boom"))
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", res.StatusCode)
	}
}

func TestErrorHandler_RecoversFromPanicString(t *testing.T) {
	// `panic("string")` is a separate code path through the type
	// switch — pin it explicitly so a future refactor can't drop the
	// string arm without test failure.
	r := newRouter(ErrorHandler(false))
	r.Get("/", func(_ http.ResponseWriter, _ *http.Request) {
		panic("kaboom")
	})

	srv := httptest.NewServer(r)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", res.StatusCode)
	}
}
