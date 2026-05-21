package middleware

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── mass-assignment ───────────────────────────────────────────────────

func TestMassAssign_StripsDisallowedKeysInStripMode(t *testing.T) {
	var received map[string]interface{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(MassAssign(MassAssignOptions{
		Allow: []string{"email", "name"},
	})(handler))
	defer srv.Close()

	body := strings.NewReader(`{"email":"x@y.z","is_admin":true,"role":"admin"}`)
	resp, err := http.Post(srv.URL, "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if _, ok := received["is_admin"]; ok {
		t.Error("is_admin should have been stripped")
	}
	if _, ok := received["role"]; ok {
		t.Error("role should have been stripped")
	}
	if received["email"] != "x@y.z" {
		t.Errorf("expected email preserved, got %+v", received)
	}
}

func TestMassAssign_RejectMode(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(MassAssign(MassAssignOptions{
		Allow: []string{"email"},
		Mode:  MassAssignReject,
	})(handler))
	defer srv.Close()

	body := strings.NewReader(`{"email":"x@y.z","is_admin":true}`)
	resp, err := http.Post(srv.URL, "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	var payload map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if payload["error"] != "Disallowed fields" {
		t.Errorf("expected error message, got %+v", payload)
	}
	fields, ok := payload["fields"].([]interface{})
	if !ok || len(fields) != 1 || fields[0] != "is_admin" {
		t.Errorf("expected fields=[is_admin], got %+v", payload["fields"])
	}
}

func TestMassAssign_NonJSONContentTypePassesThrough(t *testing.T) {
	var bodyReceived string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodyReceived = string(b)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(MassAssign(MassAssignOptions{
		Allow: []string{"email"},
	})(handler))
	defer srv.Close()

	resp, err := http.Post(srv.URL, "application/x-www-form-urlencoded",
		strings.NewReader("raw=form-data&is_admin=true"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.Contains(bodyReceived, "is_admin=true") {
		t.Errorf("form body should have passed through unfiltered, got %q", bodyReceived)
	}
}

func TestMassAssign_EmptyAllowlistFailsLoud(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(MassAssign(MassAssignOptions{
		Allow: nil,
	})(handler))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Errorf("expected 500 on empty allowlist, got %d", resp.StatusCode)
	}
}

// ─── method-allowlist ──────────────────────────────────────────────────

func TestMethodAllowlist_DefaultsAllowStandardMethods(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(MethodAllowlist(MethodAllowlistOptions{})(handler))
	defer srv.Close()

	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		req, _ := http.NewRequest(m, srv.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Errorf("%s should be allowed by default, got %d", m, resp.StatusCode)
		}
	}
}

func TestMethodAllowlist_TraceAndConnectRejected(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(MethodAllowlist(MethodAllowlistOptions{})(handler))
	defer srv.Close()

	for _, m := range []string{"TRACE", "CONNECT"} {
		req, _ := http.NewRequest(m, srv.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 405 {
			t.Errorf("%s should be 405, got %d", m, resp.StatusCode)
		}
		if !strings.Contains(resp.Header.Get("Allow"), "GET") {
			t.Errorf("Allow header missing GET, got %q", resp.Header.Get("Allow"))
		}
	}
}

func TestMethodAllowlist_StripsOverrideHeaders(t *testing.T) {
	var sawOverride bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-HTTP-Method-Override") != "" {
			sawOverride = true
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(MethodAllowlist(MethodAllowlistOptions{
		Allow: []string{"GET"},
	})(handler))
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if sawOverride {
		t.Error("X-HTTP-Method-Override should have been stripped before handler")
	}
}

// ─── response-splitting ────────────────────────────────────────────────

func TestResponseSplittingGuard_CleanRedirectPasses(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusFound)
	})
	srv := httptest.NewServer(
		ResponseSplittingGuard(ResponseSplittingOptions{})(handler))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/home" {
		t.Errorf("expected location=/home, got %q", resp.Header.Get("Location"))
	}
}

func TestResponseSplittingGuard_StripsCRLFInLocation(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handler that "forgets" to sanitize — pipes attacker input
		// into a header directly.
		bad := r.URL.Query().Get("to")
		w.Header().Set("Location", bad)
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(
		ResponseSplittingGuard(ResponseSplittingOptions{})(handler))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/?to=/home%0d%0aSet-Cookie:+admin=true")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "\r") || strings.Contains(loc, "\n") {
		t.Errorf("CRLF should have been stripped, got %q", loc)
	}
}

func TestResponseSplittingGuard_OnDetectFires(t *testing.T) {
	var detected []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/home\r\nX-Injected: pwned")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(
		ResponseSplittingGuard(ResponseSplittingOptions{
			OnDetect: func(header, value string) {
				detected = append(detected, header)
			},
		})(handler))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Get(srv.URL)
	_ = resp.Body.Close()
	if len(detected) == 0 {
		t.Error("OnDetect should have fired on injected Location header")
	}
}

// ─── graphql ───────────────────────────────────────────────────────────

func TestGraphqlGuard_CleanQueryPasses(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b) // echo
	})
	srv := httptest.NewServer(
		GraphqlGuard(GraphqlGuardMiddlewareOptions{})(handler))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		strings.NewReader(`{"query":"{ user { name } }"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGraphqlGuard_DepthBombBlocked(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(
		GraphqlGuard(GraphqlGuardMiddlewareOptions{})(handler))
	defer srv.Close()

	// 12 levels, default limit 10.
	deep := `{"query":"query { ` + strings.Repeat("x { ", 11) + "x" +
		strings.Repeat(" }", 12) + `"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		strings.NewReader(deep))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
	var payload map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&payload)
	if payload["reason"] != "depth" {
		t.Errorf("expected reason=depth, got %+v", payload)
	}
}

func TestGraphqlGuard_IntrospectionBlocked(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(
		GraphqlGuard(GraphqlGuardMiddlewareOptions{})(handler))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		strings.NewReader(`{"query":"{ __schema { types { name } } }"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestGraphqlGuard_BatchedQueryAnyBadBlocksAll(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(
		GraphqlGuard(GraphqlGuardMiddlewareOptions{})(handler))
	defer srv.Close()

	batch := `[
		{"query":"{ user { name } }"},
		{"query":"{ __schema { types { name } } }"},
		{"query":"{ posts { title } }"}
	]`
	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		strings.NewReader(batch))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("expected 400 on batched with bad query, got %d", resp.StatusCode)
	}
}

func TestGraphqlGuard_NonGraphqlPathPassesThrough(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(
		GraphqlGuard(GraphqlGuardMiddlewareOptions{})(handler))
	defer srv.Close()

	// __schema in body, but path is /other — middleware should not act.
	resp, err := http.Post(srv.URL+"/other", "application/json",
		strings.NewReader(`{"query":"{ __schema { types { name } } }"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 on non-graphql path, got %d", resp.StatusCode)
	}
}

func TestGraphqlGuard_GetMethodPassesThrough(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(
		GraphqlGuard(GraphqlGuardMiddlewareOptions{})(handler))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/graphql")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200 on GET, got %d", resp.StatusCode)
	}
}
