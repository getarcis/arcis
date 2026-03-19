package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- EnforceSecureCookie tests ---

func TestEnforceSecureCookie_AddsHttpOnly(t *testing.T) {
	result := EnforceSecureCookie("session=abc", true, false, "", "")
	if result != "session=abc; HttpOnly" {
		t.Errorf("expected HttpOnly, got %q", result)
	}
}

func TestEnforceSecureCookie_NoDuplicateHttpOnly(t *testing.T) {
	result := EnforceSecureCookie("session=abc; HttpOnly", true, false, "", "")
	if result != "session=abc; HttpOnly" {
		t.Errorf("should not duplicate HttpOnly, got %q", result)
	}
}

func TestEnforceSecureCookie_HttpOnlyDisabled(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "", "")
	if result != "session=abc" {
		t.Errorf("should not add HttpOnly when disabled, got %q", result)
	}
}

func TestEnforceSecureCookie_AddsSecure(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, true, "", "")
	if result != "session=abc; Secure" {
		t.Errorf("expected Secure, got %q", result)
	}
}

func TestEnforceSecureCookie_NoDuplicateSecure(t *testing.T) {
	result := EnforceSecureCookie("session=abc; Secure", false, true, "", "")
	if result != "session=abc; Secure" {
		t.Errorf("should not duplicate Secure, got %q", result)
	}
}

func TestEnforceSecureCookie_SecureDisabled(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "", "")
	if result != "session=abc" {
		t.Errorf("should not add Secure when disabled, got %q", result)
	}
}

func TestEnforceSecureCookie_SameSiteLax(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "Lax", "")
	if result != "session=abc; SameSite=Lax" {
		t.Errorf("expected SameSite=Lax, got %q", result)
	}
}

func TestEnforceSecureCookie_SameSiteStrict(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "Strict", "")
	if result != "session=abc; SameSite=Strict" {
		t.Errorf("expected SameSite=Strict, got %q", result)
	}
}

func TestEnforceSecureCookie_SameSiteNoneAddsSecure(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "None", "")
	expected := "session=abc; SameSite=None; Secure"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestEnforceSecureCookie_SameSiteNoneNoDoubleSecure(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, true, "None", "")
	// Secure added first, then SameSite=None, should not duplicate
	expected := "session=abc; Secure; SameSite=None"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestEnforceSecureCookie_NoDuplicateSameSite(t *testing.T) {
	result := EnforceSecureCookie("session=abc; SameSite=Strict", false, false, "Lax", "")
	if result != "session=abc; SameSite=Strict" {
		t.Errorf("should not duplicate SameSite, got %q", result)
	}
}

func TestEnforceSecureCookie_SameSiteDisabled(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "", "")
	if result != "session=abc" {
		t.Errorf("should not add SameSite when disabled, got %q", result)
	}
}

func TestEnforceSecureCookie_AddsPath(t *testing.T) {
	result := EnforceSecureCookie("session=abc", false, false, "", "/app")
	if result != "session=abc; Path=/app" {
		t.Errorf("expected Path=/app, got %q", result)
	}
}

func TestEnforceSecureCookie_OverridesPath(t *testing.T) {
	result := EnforceSecureCookie("session=abc; Path=/old", false, false, "", "/new")
	if result != "session=abc; Path=/new" {
		t.Errorf("expected path override, got %q", result)
	}
}

func TestEnforceSecureCookie_AllDefaults(t *testing.T) {
	result := EnforceSecureCookie("session=abc", true, true, "Lax", "")
	expected := "session=abc; HttpOnly; Secure; SameSite=Lax"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestEnforceSecureCookie_AlreadySecure(t *testing.T) {
	result := EnforceSecureCookie("session=abc; HttpOnly; Secure; SameSite=Lax", true, true, "Lax", "")
	expected := "session=abc; HttpOnly; Secure; SameSite=Lax"
	if result != expected {
		t.Errorf("should not modify already secure cookie, got %q", result)
	}
}

func TestEnforceSecureCookie_CaseInsensitiveDetection(t *testing.T) {
	// Existing attributes with different casing should be detected
	result := EnforceSecureCookie("session=abc; HTTPONLY; SECURE; SAMESITE=Strict", true, true, "Lax", "")
	if result != "session=abc; HTTPONLY; SECURE; SAMESITE=Strict" {
		t.Errorf("should detect case-insensitive attrs, got %q", result)
	}
}

// --- SecureCookieDefaults tests ---

func TestSecureCookieDefaults_Enforce(t *testing.T) {
	sc := NewSecureCookieDefaults(SecureCookieOptions{})
	result := sc.Enforce("session=abc")
	expected := "session=abc; HttpOnly; Secure; SameSite=Lax"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestSecureCookieDefaults_CustomOptions(t *testing.T) {
	httpOnly := false
	sameSite := "Strict"
	sc := NewSecureCookieDefaults(SecureCookieOptions{
		HttpOnly: &httpOnly,
		SameSite: &sameSite,
	})
	result := sc.Enforce("session=abc")
	expected := "session=abc; Secure; SameSite=Strict"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestSecureCookieDefaults_DisableSecure(t *testing.T) {
	secure := false
	sc := NewSecureCookieDefaults(SecureCookieOptions{
		Secure: &secure,
	})
	result := sc.Enforce("session=abc")
	expected := "session=abc; HttpOnly; SameSite=Lax"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestSecureCookieDefaults_WithPath(t *testing.T) {
	sc := NewSecureCookieDefaults(SecureCookieOptions{
		Path: "/api",
	})
	result := sc.Enforce("session=abc")
	expected := "session=abc; HttpOnly; Secure; SameSite=Lax; Path=/api"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

// --- HTTP Handler middleware tests ---

func TestCookieHandler_EnforcesOnSetCookie(t *testing.T) {
	sc := NewSecureCookieDefaults(SecureCookieOptions{})
	handler := sc.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie, got %d", len(cookies))
	}
	expected := "session=abc123; HttpOnly; Secure; SameSite=Lax"
	if cookies[0] != expected {
		t.Errorf("expected %q, got %q", expected, cookies[0])
	}
}

func TestCookieHandler_EnforcesMultipleCookies(t *testing.T) {
	sc := NewSecureCookieDefaults(SecureCookieOptions{})
	handler := sc.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc")
		w.Header().Add("Set-Cookie", "theme=dark")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie, got %d", len(cookies))
	}

	if cookies[0] != "session=abc; HttpOnly; Secure; SameSite=Lax" {
		t.Errorf("first cookie wrong: %q", cookies[0])
	}
	if cookies[1] != "theme=dark; HttpOnly; Secure; SameSite=Lax" {
		t.Errorf("second cookie wrong: %q", cookies[1])
	}
}

func TestCookieHandler_NoCookiesUnchanged(t *testing.T) {
	sc := NewSecureCookieDefaults(SecureCookieOptions{})
	handler := sc.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Error("should not add Set-Cookie when none present")
	}
}

func TestCookieHandler_ImplicitWrite(t *testing.T) {
	sc := NewSecureCookieDefaults(SecureCookieOptions{})
	handler := sc.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "token=xyz")
		w.Write([]byte("hello"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie, got %d", len(cookies))
	}
	if cookies[0] != "token=xyz; HttpOnly; Secure; SameSite=Lax" {
		t.Errorf("expected enforced cookie on implicit write, got %q", cookies[0])
	}
}

// --- SecureCookieMiddleware factory test ---

func TestSecureCookieMiddleware_Factory(t *testing.T) {
	mw := SecureCookieMiddleware(SecureCookieOptions{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "id=1")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	cookies := rec.Header().Values("Set-Cookie")
	if len(cookies) != 1 || cookies[0] != "id=1; HttpOnly; Secure; SameSite=Lax" {
		t.Errorf("factory middleware failed: %v", cookies)
	}
}
