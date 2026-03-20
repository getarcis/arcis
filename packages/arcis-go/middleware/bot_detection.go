package middleware

import (
	"math"
	"net/http"
	"strings"
)

// BotCategory represents the type of bot detected.
type BotCategory string

const (
	BotCategorySearchEngine BotCategory = "SEARCH_ENGINE"
	BotCategorySocial       BotCategory = "SOCIAL"
	BotCategoryMonitoring   BotCategory = "MONITORING"
	BotCategoryAICrawler    BotCategory = "AI_CRAWLER"
	BotCategoryScraper      BotCategory = "SCRAPER"
	BotCategoryAutomated    BotCategory = "AUTOMATED"
	BotCategoryUnknown      BotCategory = "UNKNOWN"
	BotCategoryHuman        BotCategory = "HUMAN"
)

// BotDetectionResult holds the result of bot detection.
type BotDetectionResult struct {
	IsBot      bool        `json:"isBot"`
	Category   BotCategory `json:"category"`
	Name       string      `json:"name,omitempty"`
	Confidence float64     `json:"confidence"`
	Signals    []string    `json:"signals"`
}

// BotProtectionOptions configures the bot protection middleware.
type BotProtectionOptions struct {
	Allow         []BotCategory // Categories to always allow (default: SEARCH_ENGINE, SOCIAL, MONITORING)
	Deny          []BotCategory // Categories to always deny (default: AUTOMATED)
	DefaultAction string        // "allow" or "deny" for uncategorized bots (default: "allow")
	StatusCode    int           // HTTP status for denied bots (default: 403)
	Message       string        // Denial message (default: "Access denied.")
}

const maxUALength = 2048

type botPattern struct {
	pattern  string
	name     string
	category BotCategory
}

var botPatterns = []botPattern{
	// Search engines (specific variants first)
	{"googlebot-image", "Googlebot-Image", BotCategorySearchEngine},
	{"googlebot-video", "Googlebot-Video", BotCategorySearchEngine},
	{"googlebot-news", "Googlebot-News", BotCategorySearchEngine},
	{"googlebot", "Googlebot", BotCategorySearchEngine},
	{"adsbot-google", "AdsBot-Google", BotCategorySearchEngine},
	{"mediapartners-google", "Mediapartners-Google", BotCategorySearchEngine},
	{"bingbot", "Bingbot", BotCategorySearchEngine},
	{"msnbot", "msnbot", BotCategorySearchEngine},
	{"slurp", "Yahoo Slurp", BotCategorySearchEngine},
	{"duckduckbot", "DuckDuckBot", BotCategorySearchEngine},
	{"baiduspider", "Baiduspider", BotCategorySearchEngine},
	{"yandexbot", "YandexBot", BotCategorySearchEngine},
	{"yandeximages", "YandexImages", BotCategorySearchEngine},
	{"sogou", "Sogou", BotCategorySearchEngine},
	{"exabot", "Exabot", BotCategorySearchEngine},
	{"ia_archiver", "Alexa", BotCategorySearchEngine},
	{"applebot", "Applebot", BotCategorySearchEngine},
	{"qwantify", "Qwantify", BotCategorySearchEngine},
	{"petalbot", "PetalBot", BotCategorySearchEngine},
	{"seznambot", "SeznamBot", BotCategorySearchEngine},

	// Social
	{"twitterbot", "Twitterbot", BotCategorySocial},
	{"facebookexternalhit", "Facebook", BotCategorySocial},
	{"facebot", "Facebot", BotCategorySocial},
	{"linkedinbot", "LinkedInBot", BotCategorySocial},
	{"pinterest", "Pinterest", BotCategorySocial},
	{"slackbot", "Slackbot", BotCategorySocial},
	{"telegrambot", "TelegramBot", BotCategorySocial},
	{"whatsapp", "WhatsApp", BotCategorySocial},
	{"discordbot", "Discordbot", BotCategorySocial},
	{"redditbot", "Redditbot", BotCategorySocial},
	{"embedly", "Embedly", BotCategorySocial},
	{"quora", "Quora", BotCategorySocial},
	{"mastodon", "Mastodon", BotCategorySocial},

	// Monitoring
	{"uptimerobot", "UptimeRobot", BotCategoryMonitoring},
	{"pingdom", "Pingdom", BotCategoryMonitoring},
	{"site24x7", "Site24x7", BotCategoryMonitoring},
	{"statuscake", "StatusCake", BotCategoryMonitoring},
	{"datadog", "Datadog", BotCategoryMonitoring},
	{"newrelicpinger", "New Relic", BotCategoryMonitoring},
	{"better uptime", "Better Uptime", BotCategoryMonitoring},
	{"gtmetrix", "GTmetrix", BotCategoryMonitoring},
	{"pagespeed", "PageSpeed Insights", BotCategoryMonitoring},

	// AI crawlers
	{"gptbot", "GPTBot", BotCategoryAICrawler},
	{"chatgpt-user", "ChatGPT-User", BotCategoryAICrawler},
	{"claude-web", "Claude-Web", BotCategoryAICrawler},
	{"claudebot", "ClaudeBot", BotCategoryAICrawler},
	{"anthropic-ai", "Anthropic", BotCategoryAICrawler},
	{"bytespider", "Bytespider", BotCategoryAICrawler},
	{"ccbot", "CCBot", BotCategoryAICrawler},
	{"cohere-ai", "Cohere", BotCategoryAICrawler},
	{"perplexitybot", "PerplexityBot", BotCategoryAICrawler},
	{"youbot", "YouBot", BotCategoryAICrawler},
	{"google-extended", "Google-Extended", BotCategoryAICrawler},
	{"diffbot", "Diffbot", BotCategoryAICrawler},
	{"amazonbot", "Amazonbot", BotCategoryAICrawler},
	{"meta-externalagent", "Meta AI", BotCategoryAICrawler},

	// Automated (headless browsers / testing)
	{"headlesschrome", "HeadlessChrome", BotCategoryAutomated},
	{"phantomjs", "PhantomJS", BotCategoryAutomated},
	{"selenium", "Selenium", BotCategoryAutomated},
	{"puppeteer", "Puppeteer", BotCategoryAutomated},
	{"playwright", "Playwright", BotCategoryAutomated},
	{"cypress", "Cypress", BotCategoryAutomated},
	{"webdriver", "WebDriver", BotCategoryAutomated},
	{"msie 6.0", "Fake IE6", BotCategoryAutomated},

	// Scrapers / HTTP clients
	{"curl", "curl", BotCategoryScraper},
	{"wget", "wget", BotCategoryScraper},
	{"python-requests", "python-requests", BotCategoryScraper},
	{"python-httpx", "python-httpx", BotCategoryScraper},
	{"python-urllib", "Python-urllib", BotCategoryScraper},
	{"aiohttp", "aiohttp", BotCategoryScraper},
	{"go-http-client", "Go-http-client", BotCategoryScraper},
	{"java httpclient", "Java HttpClient", BotCategoryScraper},
	{"apache-httpclient", "Apache-HttpClient", BotCategoryScraper},
	{"okhttp", "OkHttp", BotCategoryScraper},
	{"node-fetch", "node-fetch", BotCategoryScraper},
	{"axios", "axios", BotCategoryScraper},
	{"got", "got", BotCategoryScraper},
	{"libwww-perl", "libwww-perl", BotCategoryScraper},
	{"scrapy", "Scrapy", BotCategoryScraper},
	{"postman", "Postman", BotCategoryScraper},
	{"insomnia", "Insomnia", BotCategoryScraper},
	{"httpie", "HTTPie", BotCategoryScraper},
}

// DetectBot analyzes a request to determine if it's from a bot.
func DetectBot(r *http.Request) BotDetectionResult {
	ua := r.Header.Get("User-Agent")

	// Truncate to prevent CPU abuse
	if len(ua) > maxUALength {
		ua = ua[:maxUALength]
	}

	uaLower := strings.ToLower(ua)

	// 1. Pattern matching
	for _, p := range botPatterns {
		if strings.Contains(uaLower, p.pattern) {
			return BotDetectionResult{
				IsBot:      true,
				Category:   p.category,
				Name:       p.name,
				Confidence: 0.95,
				Signals:    []string{"user_agent_match"},
			}
		}
	}

	// 2. Behavioral signal analysis
	var signals []string

	if ua == "" {
		signals = append(signals, "missing_user_agent")
	}
	if r.Header.Get("Accept") == "" {
		signals = append(signals, "missing_accept")
	}
	if r.Header.Get("Accept-Language") == "" {
		signals = append(signals, "missing_accept_language")
	}
	if r.Header.Get("Accept-Encoding") == "" {
		signals = append(signals, "missing_accept_encoding")
	}
	if strings.ToLower(r.Header.Get("Connection")) == "close" {
		signals = append(signals, "connection_close")
	}

	if len(signals) >= 3 {
		confidence := math.Min(1.0, 0.6+float64(len(signals))*0.1)
		return BotDetectionResult{
			IsBot:      true,
			Category:   BotCategoryUnknown,
			Confidence: confidence,
			Signals:    signals,
		}
	}

	// 3. Human
	confidence := math.Max(0.0, 1.0-float64(len(signals))*0.15)
	return BotDetectionResult{
		IsBot:      false,
		Category:   BotCategoryHuman,
		Confidence: confidence,
		Signals:    signals,
	}
}

// BotProtection creates an http.Handler middleware that blocks or allows bots based on options.
func BotProtection(opts *BotProtectionOptions) func(http.Handler) http.Handler {
	o := defaultBotProtectionOptions()
	if opts != nil {
		if len(opts.Allow) > 0 {
			o.Allow = opts.Allow
		}
		if len(opts.Deny) > 0 {
			o.Deny = opts.Deny
		}
		if opts.DefaultAction != "" {
			o.DefaultAction = opts.DefaultAction
		}
		if opts.StatusCode > 0 {
			o.StatusCode = opts.StatusCode
		}
		if opts.Message != "" {
			o.Message = opts.Message
		}
	}

	allowSet := make(map[BotCategory]bool)
	for _, c := range o.Allow {
		allowSet[c] = true
	}
	denySet := make(map[BotCategory]bool)
	for _, c := range o.Deny {
		denySet[c] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result := DetectBot(r)

			if !result.IsBot {
				next.ServeHTTP(w, r)
				return
			}

			if allowSet[result.Category] {
				next.ServeHTTP(w, r)
				return
			}

			if denySet[result.Category] {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(o.StatusCode)
				w.Write([]byte(`{"error":"` + o.Message + `"}`))
				return
			}

			// Uncategorized bot
			if o.DefaultAction == "deny" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(o.StatusCode)
				w.Write([]byte(`{"error":"` + o.Message + `"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func defaultBotProtectionOptions() BotProtectionOptions {
	return BotProtectionOptions{
		Allow:         []BotCategory{BotCategorySearchEngine, BotCategorySocial, BotCategoryMonitoring},
		Deny:          []BotCategory{BotCategoryAutomated},
		DefaultAction: "allow",
		StatusCode:    http.StatusForbidden,
		Message:       "Access denied.",
	}
}
