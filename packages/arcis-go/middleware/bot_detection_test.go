package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── DetectBot tests ─────────────────────────────────────────────────────────

func TestDetectBot_Googlebot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

	result := DetectBot(req)
	if !result.IsBot {
		t.Error("Should detect Googlebot")
	}
	if result.Category != BotCategorySearchEngine {
		t.Errorf("Expected SEARCH_ENGINE, got %s", result.Category)
	}
	if result.Name != "Googlebot" {
		t.Errorf("Expected 'Googlebot', got %q", result.Name)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Expected confidence 0.95, got %f", result.Confidence)
	}
}

func TestDetectBot_Bingbot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategorySearchEngine {
		t.Error("Should detect Bingbot as SEARCH_ENGINE")
	}
}

func TestDetectBot_TwitterBot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Twitterbot/1.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategorySocial {
		t.Error("Should detect Twitterbot as SOCIAL")
	}
}

func TestDetectBot_FacebookBot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "facebookexternalhit/1.1")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategorySocial {
		t.Error("Should detect Facebook as SOCIAL")
	}
}

func TestDetectBot_UptimeRobot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "UptimeRobot/2.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryMonitoring {
		t.Error("Should detect UptimeRobot as MONITORING")
	}
}

func TestDetectBot_GPTBot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "GPTBot/1.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryAICrawler {
		t.Error("Should detect GPTBot as AI_CRAWLER")
	}
}

func TestDetectBot_ClaudeBot(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "ClaudeBot/1.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryAICrawler {
		t.Error("Should detect ClaudeBot as AI_CRAWLER")
	}
}

func TestDetectBot_Curl(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryScraper {
		t.Error("Should detect curl as SCRAPER")
	}
}

func TestDetectBot_PythonRequests(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "python-requests/2.28.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryScraper {
		t.Error("Should detect python-requests as SCRAPER")
	}
}

func TestDetectBot_GoHTTPClient(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Go-http-client/1.1")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryScraper {
		t.Error("Should detect Go-http-client as SCRAPER")
	}
}

func TestDetectBot_HeadlessChrome(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 HeadlessChrome/90.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryAutomated {
		t.Error("Should detect HeadlessChrome as AUTOMATED")
	}
}

func TestDetectBot_Selenium(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Selenium/4.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryAutomated {
		t.Error("Should detect Selenium as AUTOMATED")
	}
}

func TestDetectBot_Postman(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "PostmanRuntime/7.29.0")

	result := DetectBot(req)
	if !result.IsBot || result.Category != BotCategoryScraper {
		t.Errorf("Should detect Postman as SCRAPER, got %s", result.Category)
	}
}

func TestDetectBot_HumanBrowser(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	result := DetectBot(req)
	if result.IsBot {
		t.Error("Should not detect human browser as bot")
	}
	if result.Category != BotCategoryHuman {
		t.Errorf("Expected HUMAN, got %s", result.Category)
	}
}

func TestDetectBot_CaseInsensitive(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "GOOGLEBOT/2.1")

	result := DetectBot(req)
	if !result.IsBot {
		t.Error("Bot detection should be case insensitive")
	}
}

// ─── Behavioral signal tests ────────────────────────────────────────────────

func TestDetectBot_MissingUA(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	// No UA, no Accept, no Accept-Language → 3 signals = bot

	result := DetectBot(req)
	if !result.IsBot {
		t.Error("Missing UA + missing headers should trigger behavioral detection")
	}
	if result.Category != BotCategoryUnknown {
		t.Errorf("Expected UNKNOWN, got %s", result.Category)
	}
}

func TestDetectBot_FewMissingHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "SomeBrowser/1.0")
	req.Header.Set("Accept", "text/html")
	// Missing Accept-Language and Accept-Encoding = 2 signals < 3

	result := DetectBot(req)
	if result.IsBot {
		t.Error("Only 2 signals should not be enough to flag as bot")
	}
}

func TestDetectBot_AllMissing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	// 5 signals: missing UA, Accept, Accept-Language, Accept-Encoding, no Connection

	result := DetectBot(req)
	if !result.IsBot {
		t.Error("All missing headers should flag as bot")
	}
	if result.Confidence < 0.9 {
		t.Errorf("Expected high confidence, got %f", result.Confidence)
	}
}

func TestDetectBot_TruncatesLongUA(t *testing.T) {
	longUA := strings.Repeat("a", 5000)
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", longUA)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Accept-Encoding", "gzip")

	result := DetectBot(req)
	// Should not panic or hang
	if result.IsBot {
		t.Error("Long UA without bot patterns should be human")
	}
}

// ─── Specific pattern coverage ──────────────────────────────────────────────

func TestDetectBot_AllCategories(t *testing.T) {
	tests := []struct {
		ua       string
		category BotCategory
	}{
		{"Googlebot/2.1", BotCategorySearchEngine},
		{"Twitterbot/1.0", BotCategorySocial},
		{"UptimeRobot/2.0", BotCategoryMonitoring},
		{"GPTBot/1.0", BotCategoryAICrawler},
		{"curl/7.68.0", BotCategoryScraper},
		{"HeadlessChrome/90.0", BotCategoryAutomated},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("User-Agent", tt.ua)

		result := DetectBot(req)
		if !result.IsBot {
			t.Errorf("UA %q should be detected as bot", tt.ua)
		}
		if result.Category != tt.category {
			t.Errorf("UA %q: expected %s, got %s", tt.ua, tt.category, result.Category)
		}
	}
}

func TestDetectBot_SpecificVariantsFirst(t *testing.T) {
	// Googlebot-Image should match before Googlebot
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Googlebot-Image/1.0")

	result := DetectBot(req)
	if result.Name != "Googlebot-Image" {
		t.Errorf("Expected 'Googlebot-Image', got %q", result.Name)
	}
}

// ─── BotProtection middleware tests ─────────────────────────────────────────

func TestBotProtection_AllowsHuman(t *testing.T) {
	handler := BotProtection(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Accept-Encoding", "gzip")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Human should be allowed, got %d", rr.Code)
	}
}

func TestBotProtection_AllowsSearchEngine(t *testing.T) {
	handler := BotProtection(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Googlebot/2.1")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Search engine should be allowed by default, got %d", rr.Code)
	}
}

func TestBotProtection_BlocksAutomated(t *testing.T) {
	handler := BotProtection(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "HeadlessChrome/90.0")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Automated should be blocked, got %d", rr.Code)
	}
}

func TestBotProtection_CustomDeny(t *testing.T) {
	handler := BotProtection(&BotProtectionOptions{
		Deny: []BotCategory{BotCategoryScraper},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Denied category should be blocked, got %d", rr.Code)
	}
}

func TestBotProtection_CustomAllow(t *testing.T) {
	handler := BotProtection(&BotProtectionOptions{
		Allow: []BotCategory{BotCategoryAutomated},
		Deny:  []BotCategory{},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "HeadlessChrome/90.0")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Explicitly allowed category should pass, got %d", rr.Code)
	}
}

func TestBotProtection_DefaultDeny(t *testing.T) {
	handler := BotProtection(&BotProtectionOptions{
		DefaultAction: "deny",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0") // SCRAPER — not in default allow or deny

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Uncategorized bot should be denied with defaultAction=deny, got %d", rr.Code)
	}
}

func TestBotProtection_CustomMessage(t *testing.T) {
	handler := BotProtection(&BotProtectionOptions{
		Deny:    []BotCategory{BotCategoryScraper},
		Message: "Go away bot!",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), "Go away bot!") {
		t.Errorf("Response should contain custom message, got %q", rr.Body.String())
	}
}

func TestBotProtection_CustomStatusCode(t *testing.T) {
	handler := BotProtection(&BotProtectionOptions{
		Deny:       []BotCategory{BotCategoryScraper},
		StatusCode: http.StatusTeapot,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/7.68.0")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTeapot {
		t.Errorf("Expected status 418, got %d", rr.Code)
	}
}
