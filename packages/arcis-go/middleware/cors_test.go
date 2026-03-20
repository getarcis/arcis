package middleware

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// --- isOriginAllowed tests ---

func TestIsOriginAllowed_ExactString(t *testing.T) {
	if !isOriginAllowed("https://example.com", "https://example.com") {
		t.Error("should allow exact match")
	}
	if isOriginAllowed("https://evil.com", "https://example.com") {
		t.Error("should reject non-matching origin")
	}
}

func TestIsOriginAllowed_StringSlice(t *testing.T) {
	allowed := []string{"https://a.com", "https://b.com"}
	if !isOriginAllowed("https://a.com", allowed) {
		t.Error("should allow listed origin")
	}
	if !isOriginAllowed("https://b.com", allowed) {
		t.Error("should allow second listed origin")
	}
	if isOriginAllowed("https://c.com", allowed) {
		t.Error("should reject unlisted origin")
	}
}

func TestIsOriginAllowed_Regexp(t *testing.T) {
	re := regexp.MustCompile(`^https://.*\.example\.com$`)
	if !isOriginAllowed("https://app.example.com", re) {
		t.Error("should allow matching regex")
	}
	if isOriginAllowed("https://evil.com", re) {
		t.Error("should reject non-matching regex")
	}
}

func TestIsOriginAllowed_Function(t *testing.T) {
	fn := func(origin string) bool {
		return origin == "https://custom.com"
	}
	if !isOriginAllowed("https://custom.com", fn) {
		t.Error("should allow when function returns true")
	}
	if isOriginAllowed("https://other.com", fn) {
		t.Error("should reject when function returns false")
	}
}

func TestIsOriginAllowed_BoolTrue(t *testing.T) {
	if !isOriginAllowed("https://anything.com", true) {
		t.Error("should allow any origin when true")
	}
}

func TestIsOriginAllowed_BoolFalse(t *testing.T) {
	if isOriginAllowed("https://anything.com", false) {
		t.Error("should reject all origins when false")
	}
}

func TestIsOriginAllowed_NullAlwaysBlocked(t *testing.T) {
	cases := []CorsOrigin{
		true,
		"null",
		[]string{"null", "https://example.com"},
		func(origin string) bool { return true },
	}
	for _, allowed := range cases {
		if isOriginAllowed("null", allowed) {
			t.Errorf("should block null origin even with allowed=%T", allowed)
		}
	}
}

func TestIsOriginAllowed_NullCaseInsensitive(t *testing.T) {
	if isOriginAllowed("Null", true) {
		t.Error("should block 'Null' (case-insensitive)")
	}
	if isOriginAllowed("NULL", true) {
		t.Error("should block 'NULL' (case-insensitive)")
	}
}

func TestIsOriginAllowed_UnsupportedType(t *testing.T) {
	if isOriginAllowed("https://example.com", 42) {
		t.Error("should reject unsupported origin type")
	}
}

// --- SafeCors.GetHeaders tests ---

func TestGetHeaders_NoOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("", "GET")

	if headers["Vary"] != "Origin" {
		t.Error("should always set Vary: Origin")
	}
	if _, ok := headers["Access-Control-Allow-Origin"]; ok {
		t.Error("should not set ACAO when no origin")
	}
}

func TestGetHeaders_AllowedOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("https://example.com", "GET")

	if headers["Access-Control-Allow-Origin"] != "https://example.com" {
		t.Errorf("expected origin https://example.com, got %s", headers["Access-Control-Allow-Origin"])
	}
	if headers["Vary"] != "Origin" {
		t.Error("should set Vary: Origin")
	}
}

func TestGetHeaders_RejectedOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("https://evil.com", "GET")

	if _, ok := headers["Access-Control-Allow-Origin"]; ok {
		t.Error("should not set ACAO for rejected origin")
	}
	if headers["Vary"] != "Origin" {
		t.Error("should still set Vary: Origin for cache correctness")
	}
}

func TestGetHeaders_Credentials(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin:      "https://example.com",
		Credentials: true,
	})
	headers := cors.GetHeaders("https://example.com", "GET")

	if headers["Access-Control-Allow-Credentials"] != "true" {
		t.Error("should set credentials header")
	}
}

func TestGetHeaders_NoCredentialsByDefault(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("https://example.com", "GET")

	if _, ok := headers["Access-Control-Allow-Credentials"]; ok {
		t.Error("should not set credentials by default")
	}
}

func TestGetHeaders_ExposedHeaders(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin:         "https://example.com",
		ExposedHeaders: []string{"X-Request-Id", "X-Total-Count"},
	})
	headers := cors.GetHeaders("https://example.com", "GET")

	expected := "X-Request-Id, X-Total-Count"
	if headers["Access-Control-Expose-Headers"] != expected {
		t.Errorf("expected %q, got %q", expected, headers["Access-Control-Expose-Headers"])
	}
}

func TestGetHeaders_Preflight(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("https://example.com", "OPTIONS")

	if headers["Access-Control-Allow-Methods"] != "GET, HEAD, PUT, PATCH, POST, DELETE" {
		t.Errorf("unexpected methods: %s", headers["Access-Control-Allow-Methods"])
	}
	if headers["Access-Control-Allow-Headers"] != "Content-Type, Authorization" {
		t.Errorf("unexpected headers: %s", headers["Access-Control-Allow-Headers"])
	}
	if headers["Access-Control-Max-Age"] != "600" {
		t.Errorf("expected max-age 600, got %s", headers["Access-Control-Max-Age"])
	}
}

func TestGetHeaders_PreflightNotSetForGET(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("https://example.com", "GET")

	if _, ok := headers["Access-Control-Allow-Methods"]; ok {
		t.Error("should not set preflight headers for GET")
	}
	if _, ok := headers["Access-Control-Allow-Headers"]; ok {
		t.Error("should not set preflight headers for GET")
	}
	if _, ok := headers["Access-Control-Max-Age"]; ok {
		t.Error("should not set preflight headers for GET")
	}
}

func TestGetHeaders_CustomMethods(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin:  "https://example.com",
		Methods: []string{"GET", "POST"},
	})
	headers := cors.GetHeaders("https://example.com", "OPTIONS")

	if headers["Access-Control-Allow-Methods"] != "GET, POST" {
		t.Errorf("expected 'GET, POST', got %s", headers["Access-Control-Allow-Methods"])
	}
}

func TestGetHeaders_CustomAllowedHeaders(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin:         "https://example.com",
		AllowedHeaders: []string{"X-Custom", "Authorization"},
	})
	headers := cors.GetHeaders("https://example.com", "OPTIONS")

	if headers["Access-Control-Allow-Headers"] != "X-Custom, Authorization" {
		t.Errorf("expected custom headers, got %s", headers["Access-Control-Allow-Headers"])
	}
}

func TestGetHeaders_CustomMaxAge(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin: "https://example.com",
		MaxAge: 3600,
	})
	headers := cors.GetHeaders("https://example.com", "OPTIONS")

	if headers["Access-Control-Max-Age"] != "3600" {
		t.Errorf("expected max-age 3600, got %s", headers["Access-Control-Max-Age"])
	}
}

func TestGetHeaders_PreflightRejectedOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	headers := cors.GetHeaders("https://evil.com", "OPTIONS")

	if _, ok := headers["Access-Control-Allow-Methods"]; ok {
		t.Error("should not set preflight headers for rejected origin")
	}
}

func TestGetHeaders_WhitelistOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin: []string{"https://a.com", "https://b.com"},
	})

	h1 := cors.GetHeaders("https://a.com", "GET")
	if h1["Access-Control-Allow-Origin"] != "https://a.com" {
		t.Error("should allow first whitelisted origin")
	}

	h2 := cors.GetHeaders("https://b.com", "GET")
	if h2["Access-Control-Allow-Origin"] != "https://b.com" {
		t.Error("should allow second whitelisted origin")
	}

	h3 := cors.GetHeaders("https://c.com", "GET")
	if _, ok := h3["Access-Control-Allow-Origin"]; ok {
		t.Error("should reject non-whitelisted origin")
	}
}

func TestGetHeaders_RegexpOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin: regexp.MustCompile(`^https://.*\.myapp\.com$`),
	})

	h := cors.GetHeaders("https://api.myapp.com", "GET")
	if h["Access-Control-Allow-Origin"] != "https://api.myapp.com" {
		t.Error("should allow regex-matching origin")
	}

	h2 := cors.GetHeaders("https://evil.com", "GET")
	if _, ok := h2["Access-Control-Allow-Origin"]; ok {
		t.Error("should reject non-matching origin")
	}
}

func TestGetHeaders_FunctionOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin: func(o string) bool { return o == "https://dynamic.com" },
	})

	h := cors.GetHeaders("https://dynamic.com", "GET")
	if h["Access-Control-Allow-Origin"] != "https://dynamic.com" {
		t.Error("should allow function-approved origin")
	}
}

func TestGetHeaders_ReflectOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: true})

	h := cors.GetHeaders("https://any.com", "GET")
	if h["Access-Control-Allow-Origin"] != "https://any.com" {
		t.Error("should reflect origin when true")
	}
}

func TestGetHeaders_NullOriginBlocked(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: true})
	h := cors.GetHeaders("null", "GET")

	if _, ok := h["Access-Control-Allow-Origin"]; ok {
		t.Error("should block null origin even with reflect=true")
	}
}

// --- HTTP Handler tests ---

func TestHandler_SetsHeadersOnAllowedOrigin(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("should set ACAO header")
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("should set Vary header")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHandler_RejectedOriginNoHeaders(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("should not set ACAO for rejected origin")
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("should still set Vary")
	}
}

func TestHandler_PreflightReturns204(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	nextCalled := false
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204 on preflight, got %d", rec.Code)
	}
	if nextCalled {
		t.Error("should not call next handler on preflight")
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("should set preflight methods")
	}
}

func TestHandler_PreflightRejectedCallsNext(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	nextCalled := false
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest("OPTIONS", "/", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("should call next for rejected preflight (not a CORS preflight)")
	}
}

func TestHandler_NoOriginCallsNext(t *testing.T) {
	cors := NewSafeCors(CorsOptions{Origin: "https://example.com"})
	nextCalled := false
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("should call next when no origin")
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("should set Vary even without origin")
	}
}

func TestHandler_CredentialsHeader(t *testing.T) {
	cors := NewSafeCors(CorsOptions{
		Origin:      "https://example.com",
		Credentials: true,
	})
	handler := cors.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("should set credentials header")
	}
}

// --- SafeCorsMiddleware factory test ---

func TestSafeCorsMiddleware(t *testing.T) {
	mw := SafeCorsMiddleware(CorsOptions{Origin: "https://example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Error("factory should produce working middleware")
	}
}
