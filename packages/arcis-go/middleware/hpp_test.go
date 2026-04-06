package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// --- Query normalization ---

func TestHpp_SingleValueUnchanged(t *testing.T) {
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("role"); got != "user" {
			t.Errorf("expected role=user, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?role=user", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestHpp_DuplicateQueryLastWins(t *testing.T) {
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("role")
		if got != "admin" {
			t.Errorf("expected last value 'admin', got %q", got)
		}
		vals := r.URL.Query()["role"]
		if len(vals) != 1 {
			t.Errorf("expected single value after normalization, got %v", vals)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?role=user&role=admin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

func TestHpp_MultipleDuplicateParams(t *testing.T) {
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("role") != "admin" {
			t.Errorf("expected role=admin, got %q", q.Get("role"))
		}
		if q.Get("sort") != "desc" {
			t.Errorf("expected sort=desc, got %q", q.Get("sort"))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?role=user&role=admin&sort=asc&sort=desc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

func TestHpp_ThreeValuesLastWins(t *testing.T) {
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("role"); got != "superadmin" {
			t.Errorf("expected superadmin, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?role=user&role=admin&role=superadmin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

// --- Whitelist ---

func TestHpp_WhitelistedParamPreservesArray(t *testing.T) {
	handler := HppMiddleware(HppOptions{Whitelist: []string{"tags"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()["tags"]
		if len(vals) != 2 {
			t.Errorf("expected 2 tag values, got %d: %v", len(vals), vals)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?tags=python&tags=security", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

func TestHpp_WhitelistedPreserved_NonWhitelistedNormalized(t *testing.T) {
	handler := HppMiddleware(HppOptions{Whitelist: []string{"tags"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q["tags"]) != 2 {
			t.Errorf("expected 2 tag values, got %v", q["tags"])
		}
		if q.Get("role") != "admin" {
			t.Errorf("expected role=admin, got %q", q.Get("role"))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?tags=a&tags=b&role=user&role=admin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

// --- DisableQueryCheck ---

func TestHpp_DisableQueryCheck_LeavesArrays(t *testing.T) {
	handler := HppMiddleware(HppOptions{DisableQueryCheck: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vals := r.URL.Query()["role"]
		if len(vals) != 2 {
			t.Errorf("expected 2 values when query check disabled, got %d", len(vals))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?role=user&role=admin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

// --- Form body normalization ---

func TestHpp_FormBodyDuplicateLastWins(t *testing.T) {
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got := r.PostFormValue("role")
		if got != "admin" {
			t.Errorf("expected form role=admin, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := url.Values{"role": {"user", "admin"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

func TestHpp_FormBodyDisabled_PreservesArray(t *testing.T) {
	handler := HppMiddleware(HppOptions{DisableFormCheck: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		vals := r.PostForm["role"]
		if len(vals) != 2 {
			t.Errorf("expected 2 form values when form check disabled, got %d", len(vals))
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := url.Values{"role": {"user", "admin"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}

func TestHpp_JsonBodyNotParsedAsForm(t *testing.T) {
	nextCalled := false
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next should always be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// --- Always calls next ---

func TestHpp_AlwaysCallsNext(t *testing.T) {
	nextCalled := false
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?role=user&role=admin", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Error("next handler should always be called")
	}
}

func TestHpp_CleanRequestUnchanged(t *testing.T) {
	handler := HppMiddleware(HppOptions{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "alice" {
			t.Errorf("expected alice, got %q", got)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/?name=alice", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}
