package middleware

import (
	"net/http"
	"time"
)

// LoginBlockReason is one of the documented reasons a login attempt is rejected.
type LoginBlockReason string

const (
	LoginReasonOK                 LoginBlockReason = "ok"
	LoginReasonBot                LoginBlockReason = "bot"
	LoginReasonRateLimited        LoginBlockReason = "rate_limited"
	LoginReasonMissingCredentials LoginBlockReason = "missing_credentials"
)

// LoginCheckResult is the verdict from LoginProtection.Check.
type LoginCheckResult struct {
	Allowed bool
	Reason  LoginBlockReason
	Details map[string]interface{}
}

// LoginProtectionOptions configures LoginProtection.
//
// Composite primitive combining bot detection and per-IP rate limiting on
// login attempts. Matches the Arcjet protectLogin convenience API while
// staying fully local (no cloud lookups).
//
// Defaults are tuned for the credential-stuffing surface: tight per-IP
// rate limit (5/min) plus bot deny.
type LoginProtectionOptions struct {
	// CheckBot runs bot detection on User-Agent + behavioral headers. Default: true.
	CheckBot bool
	// AllowedBotCategories lets specific bot classes through.
	AllowedBotCategories []BotCategory
	// RateLimitMax — set to 0 to disable rate limiting. Default: 5.
	RateLimitMax int
	// RateLimitWindow. Default: 60s.
	RateLimitWindow time.Duration
	// RequireCredentialsCheck flips on a missing-credential rejection from
	// the Check call. When false (default), the caller is expected to verify
	// presence/length themselves and call Check just for rate + bot.
	RequireCredentialsCheck bool
	// OnBlocked is invoked on every rejection (for telemetry/logging).
	OnBlocked func(r *http.Request, result LoginCheckResult)
}

// LoginProtection bundles bot detection and per-IP rate limiting for login endpoints.
type LoginProtection struct {
	opts    LoginProtectionOptions
	limiter *RateLimiter
}

// DefaultLoginProtectionOptions returns options with bot + rate-limit checks
// enabled and sensible defaults (5 requests per 60 seconds).
func DefaultLoginProtectionOptions() LoginProtectionOptions {
	return LoginProtectionOptions{
		CheckBot:        true,
		RateLimitMax:    5,
		RateLimitWindow: 60 * time.Second,
	}
}

// NewLoginProtection builds a LoginProtection with the given options.
// Zero values are replaced with defaults.
func NewLoginProtection(opts LoginProtectionOptions) *LoginProtection {
	if opts.RateLimitWindow == 0 {
		opts.RateLimitWindow = 60 * time.Second
	}
	if opts.RateLimitMax == 0 {
		opts.RateLimitMax = 5
	}
	lp := &LoginProtection{opts: opts}
	if opts.RateLimitMax > 0 {
		lp.limiter = NewRateLimiter(opts.RateLimitMax, opts.RateLimitWindow)
	}
	return lp
}

// Check runs bot + rate-limit checks against the request.
// Caller passes empty strings if credentials are not yet extracted; presence
// is only enforced when RequireCredentialsCheck is true.
func (lp *LoginProtection) Check(r *http.Request, username, password string) LoginCheckResult {
	if lp.opts.CheckBot {
		bot := DetectBot(r)
		if bot.IsBot && !containsCategory(lp.opts.AllowedBotCategories, bot.Category) {
			return lp.block(r, LoginCheckResult{
				Reason: LoginReasonBot,
				Details: map[string]interface{}{
					"category":   string(bot.Category),
					"name":       bot.Name,
					"confidence": bot.Confidence,
				},
			})
		}
	}

	if lp.opts.RequireCredentialsCheck {
		if username == "" || password == "" {
			return lp.block(r, LoginCheckResult{Reason: LoginReasonMissingCredentials})
		}
	}

	if lp.limiter != nil {
		rl := lp.limiter.Check(r)
		if !rl.Allowed {
			return lp.block(r, LoginCheckResult{
				Reason: LoginReasonRateLimited,
				Details: map[string]interface{}{
					"retryAfter": rl.Reset.Seconds(),
				},
			})
		}
	}

	return LoginCheckResult{Allowed: true, Reason: LoginReasonOK}
}

// Close releases the rate-limiter's cleanup goroutine.
func (lp *LoginProtection) Close() {
	if lp.limiter != nil {
		lp.limiter.Close()
	}
}

func (lp *LoginProtection) block(r *http.Request, res LoginCheckResult) LoginCheckResult {
	res.Allowed = false
	if lp.opts.OnBlocked != nil {
		lp.opts.OnBlocked(r, res)
	}
	return res
}
