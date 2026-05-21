package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── LoginProtection ───────────────────────────────────────────────────────────

func TestLoginProtection_AllowsHumanWithCredentials(t *testing.T) {
	lp := NewLoginProtection(DefaultLoginProtectionOptions())
	defer lp.Close()

	req := httptest.NewRequest("POST", "/login", strings.NewReader(""))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")

	res := lp.Check(req, "alice", "hunter2pwd!")
	if !res.Allowed {
		t.Fatalf("expected allow, got reason=%q details=%v", res.Reason, res.Details)
	}
}

func TestLoginProtection_BlocksCurlBot(t *testing.T) {
	lp := NewLoginProtection(DefaultLoginProtectionOptions())
	defer lp.Close()

	req := httptest.NewRequest("POST", "/login", strings.NewReader(""))
	req.Header.Set("User-Agent", "curl/7.85.0")

	res := lp.Check(req, "alice", "hunter2pwd!")
	if res.Allowed {
		t.Fatalf("expected curl to be denied as bot, got allow")
	}
	if res.Reason != LoginReasonBot {
		t.Fatalf("expected reason=bot, got %q", res.Reason)
	}
}

func TestLoginProtection_MissingCredentialsRejected(t *testing.T) {
	opts := DefaultLoginProtectionOptions()
	opts.RequireCredentialsCheck = true
	lp := NewLoginProtection(opts)
	defer lp.Close()

	req := httptest.NewRequest("POST", "/login", strings.NewReader(""))
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept-Language", "en-US")

	res := lp.Check(req, "alice", "")
	if res.Allowed {
		t.Fatalf("expected missing-credentials denial")
	}
	if res.Reason != LoginReasonMissingCredentials {
		t.Fatalf("expected reason=missing_credentials, got %q", res.Reason)
	}
}

func TestLoginProtection_RateLimits(t *testing.T) {
	opts := DefaultLoginProtectionOptions()
	opts.RateLimitMax = 2
	lp := NewLoginProtection(opts)
	defer lp.Close()

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/login", strings.NewReader(""))
		req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
		req.Header.Set("Accept-Language", "en-US")
		req.RemoteAddr = "10.1.2.3:443"

		res := lp.Check(req, "alice", "hunter2pwd!")
		if i < 2 && !res.Allowed {
			t.Fatalf("request %d should have been allowed, got reason=%q", i, res.Reason)
		}
		if i == 2 && res.Allowed {
			t.Fatalf("3rd request should have been rate-limited, got allow")
		}
	}
}

func TestLoginProtection_OnBlockedFires(t *testing.T) {
	fired := 0
	opts := DefaultLoginProtectionOptions()
	opts.OnBlocked = func(_ *http.Request, _ LoginCheckResult) { fired++ }
	lp := NewLoginProtection(opts)
	defer lp.Close()

	req := httptest.NewRequest("POST", "/login", strings.NewReader(""))
	req.Header.Set("User-Agent", "curl/7.85.0")

	lp.Check(req, "alice", "hunter2pwd!")
	if fired != 1 {
		t.Fatalf("expected OnBlocked to fire once on bot deny, got %d", fired)
	}
}

// ─── ApiProtection ─────────────────────────────────────────────────────────────

func TestApiProtection_AllowsCleanHumanRequest(t *testing.T) {
	ap := NewApiProtection(DefaultApiProtectionOptions())

	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(""))
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept-Language", "en-US")

	res := ap.Check(req, map[string]interface{}{"action": "transfer"})
	if !res.Allowed {
		t.Fatalf("expected allow, got reason=%q", res.Reason)
	}
}

func TestApiProtection_BlocksBadOrigin(t *testing.T) {
	opts := DefaultApiProtectionOptions()
	opts.ExpectedOrigins = []string{"https://app.example.com"}
	ap := NewApiProtection(opts)

	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(""))
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Origin", "https://evil.com")

	res := ap.Check(req, map[string]interface{}{"x": 1})
	if res.Allowed {
		t.Fatalf("expected bad_origin block, got allow")
	}
	if res.Reason != ApiReasonBadOrigin {
		t.Fatalf("expected reason=bad_origin, got %q", res.Reason)
	}
}

func TestApiProtection_AcceptsMatchingOrigin(t *testing.T) {
	opts := DefaultApiProtectionOptions()
	opts.ExpectedOrigins = []string{"https://app.example.com"}
	ap := NewApiProtection(opts)

	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(""))
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Origin", "https://app.example.com/")

	res := ap.Check(req, map[string]interface{}{"x": 1})
	if !res.Allowed {
		t.Fatalf("expected allow, got reason=%q details=%v", res.Reason, res.Details)
	}
}

func TestApiProtection_BlocksXssInBody(t *testing.T) {
	ap := NewApiProtection(DefaultApiProtectionOptions())

	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(""))
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept-Language", "en-US")

	res := ap.Check(req, map[string]interface{}{"comment": "<script>alert(1)</script>"})
	if res.Allowed {
		t.Fatalf("expected xss threat block, got allow")
	}
	if res.Reason != ApiReasonThreat {
		t.Fatalf("expected reason=threat, got %q", res.Reason)
	}
	if res.Details["vector"] != "xss" {
		t.Fatalf("expected vector=xss, got %v", res.Details["vector"])
	}
}

func TestApiProtection_NilBodySkipsScan(t *testing.T) {
	ap := NewApiProtection(DefaultApiProtectionOptions())

	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept-Language", "en-US")

	res := ap.Check(req, nil)
	if !res.Allowed {
		t.Fatalf("expected allow, got reason=%q", res.Reason)
	}
}

func TestApiProtection_BotCategoryAllowlistBypass(t *testing.T) {
	opts := DefaultApiProtectionOptions()
	opts.AllowedBotCategories = append(opts.AllowedBotCategories, BotCategoryAutomated, BotCategoryScraper)
	ap := NewApiProtection(opts)

	req := httptest.NewRequest("POST", "/api/x", strings.NewReader(""))
	req.Header.Set("User-Agent", "curl/7.85.0")

	res := ap.Check(req, map[string]interface{}{"x": 1})
	if !res.Allowed {
		t.Fatalf("expected allowlist bypass to admit curl, got reason=%q", res.Reason)
	}
}
