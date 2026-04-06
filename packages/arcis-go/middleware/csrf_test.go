package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- GenerateCsrfToken tests ---

func TestGenerateCsrfToken_Length(t *testing.T) {
	token, err := GenerateCsrfToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("expected 64 hex chars, got %d", len(token))
	}
}

func TestGenerateCsrfToken_Unique(t *testing.T) {
	t1, _ := GenerateCsrfToken(32)
	t2, _ := GenerateCsrfToken(32)
	if t1 == t2 {
		t.Error("tokens should be unique")
	}
}

func TestGenerateCsrfToken_CustomLength(t *testing.T) {
	token, _ := GenerateCsrfToken(16)
	if len(token) != 32 {
		t.Errorf("expected 32 hex chars for 16 bytes, got %d", len(token))
	}
}

// --- ValidateCsrfToken tests ---

func TestValidateCsrfToken_Match(t *testing.T) {
	if !ValidateCsrfToken("abc123", "abc123") {
		t.Error("should match identical tokens")
	}
}

func TestValidateCsrfToken_Mismatch(t *testing.T) {
	if ValidateCsrfToken("abc123", "xyz789") {
		t.Error("should not match different tokens")
	}
}

func TestValidateCsrfToken_EmptyCookie(t *testing.T) {
	if ValidateCsrfToken("", "abc123") {
		t.Error("should reject empty cookie token")
	}
}

func TestValidateCsrfToken_EmptyRequest(t *testing.T) {
	if ValidateCsrfToken("abc123", "") {
		t.Error("should reject empty request token")
	}
}

func TestValidateCsrfToken_BothEmpty(t *testing.T) {
	if ValidateCsrfToken("", "") {
		t.Error("should reject both empty")
	}
}

func TestValidateCsrfToken_DifferentLength(t *testing.T) {
	if ValidateCsrfToken("short", "muchlongertoken") {
		t.Error("should reject different lengths")
	}
}

// --- CsrfProtection.Check tests ---

func TestCheck_SafeMethodAllowed(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	if !csrf.Check("GET", "/", "", "") {
		t.Error("GET should be allowed without token")
	}
	if !csrf.Check("HEAD", "/", "", "") {
		t.Error("HEAD should be allowed without token")
	}
	if !csrf.Check("OPTIONS", "/", "", "") {
		t.Error("OPTIONS should be allowed without token")
	}
}

func TestCheck_ProtectedMethodNeedsToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	if csrf.Check("POST", "/", "", "") {
		t.Error("POST should be rejected without tokens")
	}
	if csrf.Check("PUT", "/", "", "") {
		t.Error("PUT should be rejected without tokens")
	}
	if csrf.Check("PATCH", "/", "", "") {
		t.Error("PATCH should be rejected without tokens")
	}
	if csrf.Check("DELETE", "/", "", "") {
		t.Error("DELETE should be rejected without tokens")
	}
}

func TestCheck_ValidToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	token, _ := GenerateCsrfToken(32)
	if !csrf.Check("POST", "/", token, token) {
		t.Error("should allow matching tokens")
	}
}

func TestCheck_InvalidToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	t1, _ := GenerateCsrfToken(32)
	t2, _ := GenerateCsrfToken(32)
	if csrf.Check("POST", "/", t1, t2) {
		t.Error("should reject mismatched tokens")
	}
}

func TestCheck_ExcludedPath(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		ExcludePaths: []string{"/api/webhooks"},
	})
	if !csrf.Check("POST", "/api/webhooks", "", "") {
		t.Error("excluded exact path should be allowed")
	}
	if !csrf.Check("POST", "/api/webhooks/stripe", "", "") {
		t.Error("excluded subpath should be allowed")
	}
	if csrf.Check("POST", "/api/other", "", "") {
		t.Error("non-excluded path should still need token")
	}
}

func TestCheck_MissingCookieToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	if csrf.Check("POST", "/", "", "sometoken") {
		t.Error("should reject missing cookie token")
	}
}

func TestCheck_MissingRequestToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	if csrf.Check("POST", "/", "sometoken", "") {
		t.Error("should reject missing request token")
	}
}

// --- Handler tests ---

func TestHandler_SafeMethodSetsCookie(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Error("should set CSRF cookie on safe method")
	}
	if len(cookies) > 0 && !containsSubstring(cookies[0], "_csrf=") {
		t.Errorf("cookie should contain _csrf=, got %q", cookies[0])
	}
}

func TestHandler_SafeMethodNoDuplicateCookie(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "existing-token"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) > 0 {
		t.Error("should not set cookie when one already exists")
	}
}

func TestHandler_ProtectedMethodNoToken403(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "CSRF token validation failed" {
		t.Errorf("unexpected error message: %q", body["error"])
	}
}

func TestHandler_ProtectedMethodValidToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	nextCalled := false
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	token, _ := GenerateCsrfToken(32)
	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	req.Header.Set("X-Csrf-Token", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !nextCalled {
		t.Error("should call next handler with valid token")
	}
}

func TestHandler_ProtectedMethodInvalidToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "token-a"})
	req.Header.Set("X-Csrf-Token", "token-b")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched tokens, got %d", rec.Code)
	}
}

func TestHandler_ExcludedPathSkipsValidation(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		ExcludePaths: []string{"/webhooks"},
	})
	nextCalled := false
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/webhooks/stripe", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for excluded path, got %d", rec.Code)
	}
	if !nextCalled {
		t.Error("should call next for excluded path")
	}
}

func TestHandler_CustomOnError(t *testing.T) {
	called := false
	csrf := NewCsrfProtection(CsrfOptions{
		OnError: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusTeapot)
		},
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("should call custom error handler")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("expected custom status, got %d", rec.Code)
	}
}

func TestHandler_QueryStringToken(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token, _ := GenerateCsrfToken(32)
	req := httptest.NewRequest("POST", "/?_csrf="+token, nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with query token, got %d", rec.Code)
	}
}

func TestHandler_CustomCookieName(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		CookieName: "my-csrf",
		HeaderName: "X-My-Csrf",
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token, _ := GenerateCsrfToken(32)
	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(&http.Cookie{Name: "my-csrf", Value: token})
	req.Header.Set("X-My-Csrf", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with custom names, got %d", rec.Code)
	}
}

func TestHandler_CookieAttributes(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		Cookie: CsrfCookieOptions{
			SameSite: "Strict",
			Domain:   "example.com",
		},
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header")
	}
	c := cookies[0]
	if !containsSubstring(c, "SameSite=Strict") {
		t.Errorf("expected SameSite=Strict in %q", c)
	}
	if !containsSubstring(c, "Domain=example.com") {
		t.Errorf("expected Domain=example.com in %q", c)
	}
	if !containsSubstring(c, "Secure") {
		t.Errorf("expected Secure in %q", c)
	}
}

// --- CsrfMiddleware factory test ---

func TestCsrfMiddleware_Factory(t *testing.T) {
	mw := CsrfMiddleware(CsrfOptions{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("factory middleware should reject POST without token, got %d", rec.Code)
	}
}

// --- SkipCsrf tests ---

func TestHandler_SkipCsrf_BypassesValidation(t *testing.T) {
	nextCalled := false
	csrf := NewCsrfProtection(CsrfOptions{
		SkipCsrf: func(r *http.Request) bool {
			return r.Header.Get("X-Api-Key") != ""
		},
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	// POST without CSRF token — but has API key, so should pass
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Api-Key", "secret")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when SkipCsrf returns true, got %d", rec.Code)
	}
	if !nextCalled {
		t.Error("next should be called when SkipCsrf returns true")
	}
}

func TestHandler_SkipCsrf_FalseStillValidates(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		SkipCsrf: func(r *http.Request) bool {
			return false
		},
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 when SkipCsrf returns false, got %d", rec.Code)
	}
}

func TestHandler_SkipCsrf_NilByDefault(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	if csrf.skipCsrf != nil {
		t.Error("skipCsrf should be nil by default")
	}
}

func TestHandler_SkipCsrf_TakesPriorityOverExcludePaths(t *testing.T) {
	nextCalled := false
	csrf := NewCsrfProtection(CsrfOptions{
		// No excludePaths — but SkipCsrf returns true
		SkipCsrf: func(r *http.Request) bool { return true },
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/any/path", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("SkipCsrf true should skip everything including token check")
	}
}

func TestHandler_SkipCsrf_NoApiKey_StillBlocked(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		SkipCsrf: func(r *http.Request) bool {
			return r.Header.Get("X-Api-Key") != ""
		},
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", nil)
	// No X-Api-Key header
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 without API key, got %d", rec.Code)
	}
}

// --- UseHostPrefix tests ---

func TestNewCsrfProtection_HostPrefix_AppliedToCookieName(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{UseHostPrefix: true})
	if !strings.HasPrefix(csrf.cookieName, "__Host-") {
		t.Errorf("expected __Host- prefix, got %q", csrf.cookieName)
	}
}

func TestNewCsrfProtection_HostPrefix_DefaultOff(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{})
	if strings.HasPrefix(csrf.cookieName, "__Host-") {
		t.Error("should not have __Host- prefix by default")
	}
}

func TestNewCsrfProtection_HostPrefix_CustomCookieName(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{
		CookieName:    "xsrf",
		UseHostPrefix: true,
	})
	if csrf.cookieName != "__Host-xsrf" {
		t.Errorf("expected __Host-xsrf, got %q", csrf.cookieName)
	}
}

func TestHandler_HostPrefix_SetsCookieWithPrefix(t *testing.T) {
	secure := false
	csrf := NewCsrfProtection(CsrfOptions{
		UseHostPrefix: true,
		Cookie: CsrfCookieOptions{
			Secure: &secure,
		},
	})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) == 0 {
		t.Fatal("expected Set-Cookie header")
	}
	if !containsSubstring(cookies[0], "__Host-_csrf=") {
		t.Errorf("expected __Host-_csrf= in cookie, got %q", cookies[0])
	}
}

func TestHandler_HostPrefix_ValidatesWithPrefixedCookieName(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{UseHostPrefix: true})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token, _ := GenerateCsrfToken(32)
	req := httptest.NewRequest("POST", "/", nil)
	req.AddCookie(&http.Cookie{Name: "__Host-_csrf", Value: token})
	req.Header.Set("X-Csrf-Token", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with __Host- prefixed cookie, got %d", rec.Code)
	}
}

func TestHandler_HostPrefix_RejectsStandardCookieName(t *testing.T) {
	csrf := NewCsrfProtection(CsrfOptions{UseHostPrefix: true})
	handler := csrf.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	token, _ := GenerateCsrfToken(32)
	req := httptest.NewRequest("POST", "/", nil)
	// Using _csrf instead of __Host-_csrf — should fail
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	req.Header.Set("X-Csrf-Token", token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 when using wrong cookie name, got %d", rec.Code)
	}
}

func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}
