// Package guards extends Arcis decisions to non-HTTP contexts where there's
// no http.Request to feed the middleware: job queue workers, agent tool-call
// handlers, gRPC handlers, background processors.
//
// Mirrors the Node and Python implementations.
//
// Example (job worker):
//
//	g := guards.New(guards.Config{
//	    RateLimit:   &guards.RateLimitOptions{Max: 50, Window: time.Minute},
//	    TokenBudget: &guards.TokenBudgetOptions{MaxTokens: 100_000, Window: time.Hour},
//	    PromptInjection: &guards.PromptInjectionOptions{DenyAt: "medium"},
//	})
//	defer g.Close()
//
//	d := g.Run(guards.Input{Key: jobUserID, Text: prompt, Tokens: estimate})
//	if !d.OK {
//	    return fmt.Errorf("guards %s: %s", d.Vector, d.Reason)
//	}
package guards

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/GagancM/arcis/middleware"
	"github.com/GagancM/arcis/sanitizers"
)

// ─── Public types ─────────────────────────────────────────────────────────

type Vector string

const (
	VectorRateLimit       Vector = "rate-limit"
	VectorTokenBudget     Vector = "token-budget"
	VectorPromptInjection Vector = "prompt-injection"
	VectorBot             Vector = "bot"
)

type Severity string

const (
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// RateLimitOptions configures the rate-limit vector.
type RateLimitOptions struct {
	Max    int           // Max events per window per key. Default: 100.
	Window time.Duration // Window length. Default: 1 minute.
}

// TokenBudgetOptions configures the token-budget vector.
type TokenBudgetOptions struct {
	MaxTokens        int           // Max tokens per window per key. Default: 100_000.
	Window           time.Duration // Window length. Default: 1 hour.
	MaxRequestTokens int           // Per-call cap. 0 disables.
}

// PromptInjectionOptions configures the prompt-injection vector.
type PromptInjectionOptions struct {
	// DenyAt is the minimum severity that triggers a deny. Defaults to
	// "medium" (HIGH and MEDIUM matches deny, LOW matches surface in
	// Decision.Matches but don't deny). Use "high", "medium", or "low".
	DenyAt Severity
}

// BotOptions configures the bot vector.
type BotOptions struct {
	// Allow lists categories that pass through. Empty == default
	// (SEARCH_ENGINE, SOCIAL, MONITORING).
	Allow []middleware.BotCategory
	// Deny lists categories that always deny. Empty == default (AUTOMATED).
	Deny []middleware.BotCategory
	// DefaultAction for uncategorized bots. "allow" (default) or "deny".
	DefaultAction string
}

// Config selects which vectors are active. Pass nil for any vector to
// disable it.
type Config struct {
	RateLimit       *RateLimitOptions
	TokenBudget     *TokenBudgetOptions
	PromptInjection *PromptInjectionOptions
	Bot             *BotOptions
}

// Input is what each Run() call evaluates.
type Input struct {
	Key       string // Required identifier for rate-limit / token-budget bucketing.
	Text      string // Optional text payload for prompt-injection scanning.
	Tokens    int    // Optional token cost for token-budget accounting.
	UserAgent string // Optional User-Agent for bot detection.
}

// Decision is what Run() returns.
type Decision struct {
	OK                bool                              `json:"ok"`
	Vector            Vector                            `json:"vector,omitempty"`
	Reason            string                            `json:"reason,omitempty"`
	Severity          Severity                          `json:"severity,omitempty"`
	RetryAfterSeconds int                               `json:"retryAfterSeconds,omitempty"`
	Matches           []sanitizers.PromptInjectionMatch `json:"matches,omitempty"`
}

// ─── Implementation ───────────────────────────────────────────────────────

const (
	defaultMax            = 100
	defaultWindow         = time.Minute
	defaultMaxTokens      = 100_000
	defaultTokenWindow    = time.Hour
	defaultPromptDenyRank = 2 // medium
)

var severityRank = map[Severity]int{
	SeverityLow:    1,
	SeverityMedium: 2,
	SeverityHigh:   3,
}

var defaultBotAllow = map[middleware.BotCategory]bool{
	middleware.BotCategorySearchEngine: true,
	middleware.BotCategorySocial:       true,
	middleware.BotCategoryMonitoring:   true,
}
var defaultBotDeny = map[middleware.BotCategory]bool{
	middleware.BotCategoryAutomated: true,
}

type rlEntry struct {
	count     int
	resetTime time.Time
}

type tbEntry struct {
	used      int
	resetTime time.Time
}

// Guards holds in-memory bucket state for the rate-limit and token-budget
// vectors. Construct once, call Run() per event, Close() when done.
type Guards struct {
	cfg Config

	mu      sync.Mutex
	rlStore map[string]*rlEntry
	tbStore map[string]*tbEntry

	piDenyRank int
	stop       chan struct{}
}

// New builds a Guards instance from the given Config. The returned value is
// safe for concurrent use. Call Close() to release the cleanup goroutine.
func New(cfg Config) *Guards {
	g := &Guards{
		cfg:        cfg,
		rlStore:    make(map[string]*rlEntry),
		tbStore:    make(map[string]*tbEntry),
		piDenyRank: defaultPromptDenyRank,
		stop:       make(chan struct{}),
	}
	if cfg.PromptInjection != nil && cfg.PromptInjection.DenyAt != "" {
		if r, ok := severityRank[cfg.PromptInjection.DenyAt]; ok {
			g.piDenyRank = r
		}
	}
	// Start the cleanup loop only when at least one time-windowed vector
	// is configured. PI / bot don't accumulate state.
	if cfg.RateLimit != nil || cfg.TokenBudget != nil {
		go g.sweepLoop()
	}
	return g
}

// Run evaluates every configured vector against input. Returns a decision;
// the first denying vector short-circuits the rest, so a prompt-injection
// deny does NOT charge the per-key token budget.
func (g *Guards) Run(input Input) Decision {
	if input.Key == "" {
		return Decision{OK: false, Reason: "guards: missing required Input.Key"}
	}

	// 1. Rate limit
	if g.cfg.RateLimit != nil {
		if d := g.checkRateLimit(input.Key); !d.OK {
			return d
		}
	}

	// 2. Bot detection (only when a UA was supplied)
	if g.cfg.Bot != nil && input.UserAgent != "" {
		if d := g.checkBot(input.UserAgent); !d.OK {
			return d
		}
	}

	// 3. Prompt injection (only when text was supplied)
	var piMatches []sanitizers.PromptInjectionMatch
	if g.cfg.PromptInjection != nil && input.Text != "" {
		r := sanitizers.DetectPromptInjection(input.Text)
		piMatches = r.Matches
		if r.Detected && r.Severity != "none" {
			rank := severityRank[Severity(r.Severity)]
			if rank >= g.piDenyRank {
				topRule := ""
				topDesc := ""
				for _, m := range r.Matches {
					if string(m.Severity) == r.Severity {
						topRule = m.Rule
						topDesc = m.Description
						break
					}
				}
				reason := fmt.Sprintf("Prompt injection detected (%s): %s", topRule, topDesc)
				return Decision{
					OK:       false,
					Vector:   VectorPromptInjection,
					Severity: Severity(r.Severity),
					Reason:   reason,
					Matches:  piMatches,
				}
			}
		}
	}

	// 4. Token budget (last so a denied request hasn't charged anything).
	// We process every call that reaches here regardless of input.Tokens
	// sign so cross-SDK parity holds: Node's `typeof tokens === 'number'`
	// and Python's `isinstance(tokens, (int, float))` accept negatives and
	// clamp to 0 inside the check, creating an entry with used=0.
	if g.cfg.TokenBudget != nil {
		if d := g.checkTokenBudget(input.Key, input.Tokens); !d.OK {
			d.Matches = piMatches
			return d
		}
	}

	return Decision{OK: true, Matches: piMatches}
}

// InspectRateLimit returns the current count + reset time for a key, or nil
// if the key has no entry (or its window has expired).
func (g *Guards) InspectRateLimit(key string) (int, time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.rlStore[key]; ok {
		return e.count, e.resetTime, true
	}
	return 0, time.Time{}, false
}

// InspectTokenBudget returns the current usage + reset time for a key.
func (g *Guards) InspectTokenBudget(key string) (int, time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.tbStore[key]; ok {
		return e.used, e.resetTime, true
	}
	return 0, time.Time{}, false
}

// Reset clears one key's state, or all keys if key is empty.
func (g *Guards) Reset(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if key == "" {
		g.rlStore = make(map[string]*rlEntry)
		g.tbStore = make(map[string]*tbEntry)
	} else {
		delete(g.rlStore, key)
		delete(g.tbStore, key)
	}
}

// Close releases the background cleanup goroutine. Safe to call multiple times.
func (g *Guards) Close() {
	select {
	case <-g.stop:
		// already closed
	default:
		close(g.stop)
	}
}

// ─── internals ────────────────────────────────────────────────────────────

func (g *Guards) checkRateLimit(key string) Decision {
	max := g.cfg.RateLimit.Max
	if max <= 0 {
		max = defaultMax
	}
	window := g.cfg.RateLimit.Window
	if window <= 0 {
		window = defaultWindow
	}
	now := time.Now()

	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.rlStore[key]
	if !ok || now.After(entry.resetTime) {
		entry = &rlEntry{count: 0, resetTime: now.Add(window)}
		g.rlStore[key] = entry
	}
	entry.count++
	if entry.count > max {
		retry := int(entry.resetTime.Sub(now).Seconds() + 0.999)
		if retry < 0 {
			retry = 0
		}
		return Decision{
			OK:                false,
			Vector:            VectorRateLimit,
			Severity:          SeverityMedium,
			Reason:            fmt.Sprintf("Rate limit exceeded (%d/%d per %s)", entry.count, max, window),
			RetryAfterSeconds: retry,
		}
	}
	return Decision{OK: true}
}

func (g *Guards) checkTokenBudget(key string, tokens int) Decision {
	cost := tokens
	if cost < 0 {
		cost = 0
	}
	maxT := g.cfg.TokenBudget.MaxTokens
	if maxT <= 0 {
		maxT = defaultMaxTokens
	}
	window := g.cfg.TokenBudget.Window
	if window <= 0 {
		window = defaultTokenWindow
	}
	perReq := g.cfg.TokenBudget.MaxRequestTokens

	if perReq > 0 && cost > perReq {
		return Decision{
			OK:       false,
			Vector:   VectorTokenBudget,
			Severity: SeverityHigh,
			Reason:   fmt.Sprintf("Per-call token budget exceeded (%d > %d)", cost, perReq),
		}
	}

	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.tbStore[key]
	if !ok || now.After(entry.resetTime) {
		entry = &tbEntry{used: 0, resetTime: now.Add(window)}
		g.tbStore[key] = entry
	}
	projected := entry.used + cost
	if projected > maxT {
		retry := int(entry.resetTime.Sub(now).Seconds() + 0.999)
		if retry < 0 {
			retry = 0
		}
		return Decision{
			OK:                false,
			Vector:            VectorTokenBudget,
			Severity:          SeverityMedium,
			Reason:            fmt.Sprintf("Window token budget exceeded (%d + %d > %d)", entry.used, cost, maxT),
			RetryAfterSeconds: retry,
		}
	}
	entry.used = projected
	return Decision{OK: true}
}

func (g *Guards) checkBot(userAgent string) Decision {
	// Build a minimal http.Request the existing detector can read off.
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")
	result := middleware.DetectBot(req)
	if !result.IsBot {
		return Decision{OK: true}
	}

	allow := defaultBotAllow
	if g.cfg.Bot.Allow != nil {
		allow = make(map[middleware.BotCategory]bool, len(g.cfg.Bot.Allow))
		for _, c := range g.cfg.Bot.Allow {
			allow[c] = true
		}
	}
	deny := defaultBotDeny
	if g.cfg.Bot.Deny != nil {
		deny = make(map[middleware.BotCategory]bool, len(g.cfg.Bot.Deny))
		for _, c := range g.cfg.Bot.Deny {
			deny[c] = true
		}
	}

	if allow[result.Category] {
		return Decision{OK: true}
	}
	if deny[result.Category] {
		reason := fmt.Sprintf("Bot denied (%s)", result.Category)
		if result.Name != "" {
			reason = fmt.Sprintf("Bot denied: %s", result.Name)
		}
		return Decision{OK: false, Vector: VectorBot, Severity: SeverityMedium, Reason: reason}
	}
	if g.cfg.Bot.DefaultAction == "deny" {
		return Decision{
			OK:       false,
			Vector:   VectorBot,
			Severity: SeverityLow,
			Reason:   "Uncategorized bot under DefaultAction=deny",
		}
	}
	return Decision{OK: true}
}

func (g *Guards) sweepLoop() {
	interval := time.Minute
	if g.cfg.RateLimit != nil && g.cfg.RateLimit.Window > 0 {
		interval = g.cfg.RateLimit.Window
	} else if g.cfg.TokenBudget != nil && g.cfg.TokenBudget.Window > 0 {
		interval = g.cfg.TokenBudget.Window
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-g.stop:
			return
		case now := <-t.C:
			g.mu.Lock()
			for k, e := range g.rlStore {
				if now.After(e.resetTime) {
					delete(g.rlStore, k)
				}
			}
			for k, e := range g.tbStore {
				if now.After(e.resetTime) {
					delete(g.tbStore, k)
				}
			}
			g.mu.Unlock()
		}
	}
}
