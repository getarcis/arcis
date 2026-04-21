package middleware

import (
	"net/http"
	"time"

	"github.com/GagancM/arcis/validation"
)

// SignupBlockReason is one of the documented reasons a signup is rejected.
type SignupBlockReason string

const (
	SignupReasonOK              SignupBlockReason = "ok"
	SignupReasonMissingEmail    SignupBlockReason = "missing_email"
	SignupReasonInvalidEmail    SignupBlockReason = "invalid_email"
	SignupReasonDisposableEmail SignupBlockReason = "disposable_email"
	SignupReasonBot             SignupBlockReason = "bot"
	SignupReasonRateLimited     SignupBlockReason = "rate_limited"
)

// SignupCheckResult is the verdict from SignupProtection.Check.
type SignupCheckResult struct {
	Allowed bool
	Reason  SignupBlockReason
	Details map[string]interface{}
}

// SignupProtectionOptions configures SignupProtection.
//
// Mirrors the Node.js `signupProtection()` API: combines email validation,
// bot detection, and a dedicated per-IP rate limit into one call. Fully
// local — no cloud lookups.
type SignupProtectionOptions struct {
	// CheckEmail runs email syntax + disposable validation. Default: true.
	CheckEmail bool
	// BlockDisposable rejects disposable mail domains. Default: true.
	BlockDisposable bool
	// CheckBot runs bot detection on User-Agent + behavioral headers. Default: true.
	CheckBot bool
	// AllowedBotCategories lets specific bot classes through (e.g. SEARCH_ENGINE).
	AllowedBotCategories []BotCategory
	// AllowedEmailDomains bypasses disposable check for these domains.
	AllowedEmailDomains []string
	// BlockedEmailDomains always rejects these domains.
	BlockedEmailDomains []string
	// RateLimitMax — set to 0 to disable rate limiting. Default: 5.
	RateLimitMax int
	// RateLimitWindow. Default: 60s.
	RateLimitWindow time.Duration
	// OnBlocked is invoked on every rejection (for telemetry/logging).
	OnBlocked func(r *http.Request, result SignupCheckResult)
}

// SignupProtection bundles bot, email, and rate-limit checks for signup endpoints.
type SignupProtection struct {
	opts    SignupProtectionOptions
	limiter *RateLimiter
}

// DefaultSignupProtectionOptions returns options with every check enabled
// and sensible rate-limit defaults (5 requests per 60 seconds).
func DefaultSignupProtectionOptions() SignupProtectionOptions {
	return SignupProtectionOptions{
		CheckEmail:      true,
		BlockDisposable: true,
		CheckBot:        true,
		RateLimitMax:    5,
		RateLimitWindow: 60 * time.Second,
	}
}

// NewSignupProtection builds a SignupProtection with the given options.
// Zero values in the options struct are replaced with defaults.
func NewSignupProtection(opts SignupProtectionOptions) *SignupProtection {
	// Apply defaults for zero-values that should NOT be interpreted as
	// "user asked to disable this check". Use explicit helpers if you want
	// to disable individual checks.
	if opts.RateLimitWindow == 0 {
		opts.RateLimitWindow = 60 * time.Second
	}
	if opts.RateLimitMax == 0 {
		opts.RateLimitMax = 5
	}

	sp := &SignupProtection{opts: opts}
	if opts.RateLimitMax > 0 {
		sp.limiter = NewRateLimiter(opts.RateLimitMax, opts.RateLimitWindow)
	}
	return sp
}

// Check runs all configured checks against the request and email.
// The caller extracts `email` from the request body (framework-specific).
func (sp *SignupProtection) Check(r *http.Request, email string) SignupCheckResult {
	if sp.opts.CheckBot {
		bot := DetectBot(r)
		if bot.IsBot && !containsCategory(sp.opts.AllowedBotCategories, bot.Category) {
			return sp.block(r, SignupCheckResult{
				Reason: SignupReasonBot,
				Details: map[string]interface{}{
					"category":   string(bot.Category),
					"name":       bot.Name,
					"confidence": bot.Confidence,
				},
			})
		}
	}

	if sp.opts.CheckEmail {
		if email == "" {
			return sp.block(r, SignupCheckResult{Reason: SignupReasonMissingEmail})
		}
		emailOpts := &validation.EmailValidationOptions{
			CheckDisposable: sp.opts.BlockDisposable,
			AllowedDomains:  sp.opts.AllowedEmailDomains,
			BlockedDomains:  sp.opts.BlockedEmailDomains,
		}
		v := validation.ValidateEmail(email, emailOpts)
		if !v.Valid {
			reason := SignupReasonInvalidEmail
			if v.Reason == "disposable" {
				reason = SignupReasonDisposableEmail
			}
			return sp.block(r, SignupCheckResult{
				Reason:  reason,
				Details: map[string]interface{}{"emailReason": v.Reason},
			})
		}
	}

	if sp.limiter != nil {
		rl := sp.limiter.Check(r)
		if !rl.Allowed {
			return sp.block(r, SignupCheckResult{
				Reason: SignupReasonRateLimited,
				Details: map[string]interface{}{
					"retryAfter": rl.Reset.Seconds(),
				},
			})
		}
	}

	return SignupCheckResult{Allowed: true, Reason: SignupReasonOK}
}

// Close releases the rate-limiter's cleanup goroutine.
func (sp *SignupProtection) Close() {
	if sp.limiter != nil {
		sp.limiter.Close()
	}
}

func (sp *SignupProtection) block(r *http.Request, res SignupCheckResult) SignupCheckResult {
	res.Allowed = false
	if sp.opts.OnBlocked != nil {
		sp.opts.OnBlocked(r, res)
	}
	return res
}

func containsCategory(list []BotCategory, c BotCategory) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}
