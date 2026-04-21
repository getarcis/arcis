package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// browserReq returns a request with a typical human-browser header set so
// DetectBot does not flag it on missing-header heuristics.
func browserReq(ua string) *http.Request {
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0"
	}
	req := httptest.NewRequest("POST", "/signup", nil)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	req.RemoteAddr = "1.2.3.4:1234"
	return req
}

func TestSignupProtection_AllowsValidHumanSignup(t *testing.T) {
	sp := NewSignupProtection(DefaultSignupProtectionOptions())
	defer sp.Close()

	res := sp.Check(browserReq(""), "alice@gmail.com")
	if !res.Allowed {
		t.Errorf("expected allowed, got reason=%s", res.Reason)
	}
}

func TestSignupProtection_BlocksMissingEmail(t *testing.T) {
	sp := NewSignupProtection(DefaultSignupProtectionOptions())
	defer sp.Close()

	res := sp.Check(browserReq(""), "")
	if res.Allowed || res.Reason != SignupReasonMissingEmail {
		t.Errorf("expected missing_email, got allowed=%v reason=%s", res.Allowed, res.Reason)
	}
}

func TestSignupProtection_BlocksInvalidSyntax(t *testing.T) {
	sp := NewSignupProtection(DefaultSignupProtectionOptions())
	defer sp.Close()

	res := sp.Check(browserReq(""), "not-an-email")
	if res.Allowed || res.Reason != SignupReasonInvalidEmail {
		t.Errorf("expected invalid_email, got allowed=%v reason=%s", res.Allowed, res.Reason)
	}
}

func TestSignupProtection_BlocksDisposable(t *testing.T) {
	sp := NewSignupProtection(DefaultSignupProtectionOptions())
	defer sp.Close()

	res := sp.Check(browserReq(""), "throwaway@mailinator.com")
	if res.Allowed || res.Reason != SignupReasonDisposableEmail {
		t.Errorf("expected disposable_email, got allowed=%v reason=%s", res.Allowed, res.Reason)
	}
}

func TestSignupProtection_BlocksAutomatedBot(t *testing.T) {
	sp := NewSignupProtection(DefaultSignupProtectionOptions())
	defer sp.Close()

	res := sp.Check(browserReq("curl/8.0"), "alice@gmail.com")
	if res.Allowed || res.Reason != SignupReasonBot {
		t.Errorf("expected bot, got allowed=%v reason=%s", res.Allowed, res.Reason)
	}
}

func TestSignupProtection_AllowedBotCategoriesLetsThrough(t *testing.T) {
	opts := DefaultSignupProtectionOptions()
	opts.AllowedBotCategories = []BotCategory{BotCategorySearchEngine}
	sp := NewSignupProtection(opts)
	defer sp.Close()

	req := browserReq("Mozilla/5.0 (compatible; Googlebot/2.1)")
	res := sp.Check(req, "alice@gmail.com")
	if !res.Allowed {
		t.Errorf("expected Googlebot to be allowed by whitelist, got reason=%s", res.Reason)
	}
}

func TestSignupProtection_RateLimitsRepeatedSignups(t *testing.T) {
	opts := DefaultSignupProtectionOptions()
	opts.RateLimitMax = 2
	opts.RateLimitWindow = time.Minute
	sp := NewSignupProtection(opts)
	defer sp.Close()

	allowed := 0
	rateLimited := false
	for i := 0; i < 4; i++ {
		res := sp.Check(browserReq(""), "alice@gmail.com")
		if res.Allowed {
			allowed++
		} else if res.Reason == SignupReasonRateLimited {
			rateLimited = true
		}
	}
	if allowed != 2 {
		t.Errorf("expected exactly 2 allowed, got %d", allowed)
	}
	if !rateLimited {
		t.Error("expected at least one rate_limited rejection")
	}
}

func TestSignupProtection_OnBlockedFires(t *testing.T) {
	var reasons []SignupBlockReason
	opts := DefaultSignupProtectionOptions()
	opts.RateLimitMax = 0 // disable rate limit path
	opts.OnBlocked = func(r *http.Request, res SignupCheckResult) {
		reasons = append(reasons, res.Reason)
	}
	sp := NewSignupProtection(opts)
	defer sp.Close()

	sp.Check(browserReq(""), "bad")
	if len(reasons) != 1 || reasons[0] != SignupReasonInvalidEmail {
		t.Errorf("expected [invalid_email], got %v", reasons)
	}
}

func TestSignupProtection_AllowedDomainBypassesDisposable(t *testing.T) {
	opts := DefaultSignupProtectionOptions()
	opts.AllowedEmailDomains = []string{"mailinator.com"}
	sp := NewSignupProtection(opts)
	defer sp.Close()

	res := sp.Check(browserReq(""), "ci@mailinator.com")
	if !res.Allowed {
		t.Errorf("expected allow via whitelist, got reason=%s", res.Reason)
	}
}

func TestSignupProtection_CloseIsIdempotent(t *testing.T) {
	sp := NewSignupProtection(DefaultSignupProtectionOptions())
	sp.Close()
	sp.Close() // must not panic
}
