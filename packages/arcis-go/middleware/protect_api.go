package middleware

import (
	"net/http"
	"strings"

	"github.com/getarcis/arcis/sanitizers"
)

// ApiBlockReason is one of the documented reasons an API call is rejected.
type ApiBlockReason string

const (
	ApiReasonOK        ApiBlockReason = "ok"
	ApiReasonBot       ApiBlockReason = "bot"
	ApiReasonBadOrigin ApiBlockReason = "bad_origin"
	ApiReasonThreat    ApiBlockReason = "threat"
)

// ApiCheckResult is the verdict from ApiProtection.Check.
type ApiCheckResult struct {
	Allowed bool
	Reason  ApiBlockReason
	Details map[string]interface{}
}

// DefaultAllowedApiBots is the subset of bot categories that should pass
// through API endpoints by default. API endpoints often serve legitimate
// non-browser clients (SDKs, mobile apps, server-to-server).
var DefaultAllowedApiBots = []BotCategory{
	BotCategoryMonitoring,
}

// ApiProtectionOptions configures ApiProtection.
//
// Composite primitive combining bot detection (with sane allowlist for
// legitimate API clients), Origin allowlisting, and request-body threat
// scanning. Mirrors the Node.js protectApi convenience API.
type ApiProtectionOptions struct {
	// CheckBot runs bot detection. Default: true.
	CheckBot bool
	// AllowedBotCategories — when nil, uses DefaultAllowedApiBots.
	AllowedBotCategories []BotCategory
	// ExpectedOrigins — when non-nil, the Origin header must be in this
	// list. Empty slice means "deny ALL Origin-bearing requests". Nil
	// means "do not check Origin".
	ExpectedOrigins []string
	// ScanBody runs sanitizers.ScanThreats on a body value passed to Check.
	// Default: true (Check still no-ops on nil body).
	ScanBody bool
	// OnBlocked is invoked on every rejection (for telemetry/logging).
	OnBlocked func(r *http.Request, result ApiCheckResult)
}

// ApiProtection bundles bot + origin + threat-scan checks for API endpoints.
type ApiProtection struct {
	opts ApiProtectionOptions
}

// DefaultApiProtectionOptions returns options with bot + threat-scan enabled
// (Origin check off — caller decides which origins are legitimate).
func DefaultApiProtectionOptions() ApiProtectionOptions {
	return ApiProtectionOptions{
		CheckBot:             true,
		AllowedBotCategories: append([]BotCategory(nil), DefaultAllowedApiBots...),
		ScanBody:             true,
	}
}

// NewApiProtection builds an ApiProtection with the given options.
func NewApiProtection(opts ApiProtectionOptions) *ApiProtection {
	if opts.AllowedBotCategories == nil {
		opts.AllowedBotCategories = append([]BotCategory(nil), DefaultAllowedApiBots...)
	}
	return &ApiProtection{opts: opts}
}

// Check runs bot, origin, and body-threat checks. Pass nil body to skip
// scan_threats when the route's body isn't available yet.
func (ap *ApiProtection) Check(r *http.Request, body interface{}) ApiCheckResult {
	// Origin first — fail fast on cross-origin attacks that don't carry a
	// legitimate Origin.
	if ap.opts.ExpectedOrigins != nil {
		origin := strings.ToLower(strings.TrimRight(r.Header.Get("Origin"), "/"))
		matched := false
		for _, allowed := range ap.opts.ExpectedOrigins {
			if origin != "" && origin == strings.ToLower(strings.TrimRight(allowed, "/")) {
				matched = true
				break
			}
		}
		if !matched {
			return ap.block(r, ApiCheckResult{
				Reason:  ApiReasonBadOrigin,
				Details: map[string]interface{}{"origin": r.Header.Get("Origin")},
			})
		}
	}

	if ap.opts.CheckBot {
		bot := DetectBot(r)
		if bot.IsBot && !containsCategory(ap.opts.AllowedBotCategories, bot.Category) {
			return ap.block(r, ApiCheckResult{
				Reason: ApiReasonBot,
				Details: map[string]interface{}{
					"category":   string(bot.Category),
					"name":       bot.Name,
					"confidence": bot.Confidence,
				},
			})
		}
	}

	if ap.opts.ScanBody && body != nil {
		if hit := sanitizers.ScanThreats(body); hit != nil {
			return ap.block(r, ApiCheckResult{
				Reason: ApiReasonThreat,
				Details: map[string]interface{}{
					"vector":  hit.Vector,
					"rule":    hit.Rule,
					"matched": hit.MatchedPattern,
				},
			})
		}
	}

	return ApiCheckResult{Allowed: true, Reason: ApiReasonOK}
}

func (ap *ApiProtection) block(r *http.Request, res ApiCheckResult) ApiCheckResult {
	res.Allowed = false
	if ap.opts.OnBlocked != nil {
		ap.opts.OnBlocked(r, res)
	}
	return res
}
