"""
Bot Detection Tests
Tests for arcis/middleware/bot_detection.py
"""

import pytest
from arcis.middleware.bot_detection import (
    detect_bot,
    BotProtection,
    BotDenied,
    BotDetectionResult,
)


# =============================================================================
# HELPERS
# =============================================================================

class FakeRequest:
    """Minimal request object for testing."""

    def __init__(self, headers=None):
        self._headers = {}
        if headers:
            # Normalize: store lowercase keys
            for k, v in headers.items():
                self._headers[k.lower()] = v
        # Also expose as .headers dict (for get_request_header fallback)
        self.headers = self._headers
        # Django-style META
        self.META = {}
        for k, v in self._headers.items():
            django_key = 'HTTP_' + k.upper().replace('-', '_')
            self.META[django_key] = v


def make_request(ua=None, extra_headers=None):
    """Create a request with standard browser headers."""
    headers = {
        'accept': 'text/html',
        'accept-language': 'en-US',
        'accept-encoding': 'gzip',
    }
    if ua is not None:
        headers['user-agent'] = ua
    if extra_headers:
        headers.update(extra_headers)
    return FakeRequest(headers)


def bare_request(ua=None):
    """Create a request with minimal headers."""
    headers = {}
    if ua is not None:
        headers['user-agent'] = ua
    return FakeRequest(headers)


# =============================================================================
# SEARCH ENGINE DETECTION
# =============================================================================

class TestSearchEngines:
    @pytest.mark.parametrize("ua,expected_name", [
        ('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Googlebot'),
        ('Mozilla/5.0 (compatible; Bingbot/2.0)', 'Bingbot'),
        ('DuckDuckBot/1.0', 'DuckDuckBot'),
        ('Mozilla/5.0 (compatible; YandexBot/3.0)', 'YandexBot'),
        ('Mozilla/5.0 (compatible; Baiduspider/2.0)', 'Baiduspider'),
        ('Applebot/0.3', 'Applebot'),
    ])
    def test_search_engine_bots(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'SEARCH_ENGINE'
        assert result.name == expected_name
        assert result.confidence >= 0.9


# =============================================================================
# SOCIAL BOTS
# =============================================================================

class TestSocialBots:
    @pytest.mark.parametrize("ua,expected_name", [
        ('Twitterbot/1.0', 'Twitterbot'),
        ('facebookexternalhit/1.1', 'Facebook'),
        ('LinkedInBot/1.0', 'LinkedInBot'),
        ('Slackbot-LinkExpanding 1.0', 'Slackbot'),
        ('WhatsApp/2.21', 'WhatsApp'),
        ('Discordbot/2.0', 'Discordbot'),
    ])
    def test_social_bots(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'SOCIAL'
        assert result.name == expected_name


# =============================================================================
# MONITORING BOTS
# =============================================================================

class TestMonitoringBots:
    @pytest.mark.parametrize("ua,expected_name", [
        ('UptimeRobot/2.0', 'UptimeRobot'),
        ('Pingdom.com_bot', 'Pingdom'),
        ('Datadog/Synthetics', 'Datadog'),
    ])
    def test_monitoring_bots(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'MONITORING'
        assert result.name == expected_name


# =============================================================================
# AI CRAWLERS
# =============================================================================

class TestAICrawlers:
    @pytest.mark.parametrize("ua,expected_name", [
        ('GPTBot/1.0', 'GPTBot'),
        ('ClaudeBot/1.0', 'ClaudeBot'),
        ('anthropic-ai', 'Anthropic'),
        ('CCBot/2.0', 'CCBot'),
        ('PerplexityBot/1.0', 'PerplexityBot'),
        ('Bytespider', 'Bytespider'),
        ('meta-externalagent/1.0', 'Meta AI'),
    ])
    def test_ai_crawlers(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'AI_CRAWLER'
        assert result.name == expected_name


# =============================================================================
# AUTOMATED TOOLS
# =============================================================================

class TestAutomatedTools:
    @pytest.mark.parametrize("ua,expected_name", [
        ('Mozilla/5.0 HeadlessChrome/90.0', 'Headless Chrome'),
        ('PhantomJS/2.1', 'PhantomJS'),
        ('Mozilla/5.0 Selenium/4.0', 'Selenium'),
        ('Puppeteer/1.0', 'Puppeteer'),
        ('Playwright/1.0', 'Playwright'),
    ])
    def test_automated_tools(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'AUTOMATED'
        assert result.name == expected_name


# =============================================================================
# SCRAPERS / CLI TOOLS
# =============================================================================

class TestScrapers:
    @pytest.mark.parametrize("ua,expected_name", [
        ('curl/7.68.0', 'curl'),
        ('wget/1.21', 'wget'),
        ('python-requests/2.25.1', 'python-requests'),
        ('python-httpx/0.23.0', 'python-httpx'),
        ('Go-http-client/1.1', 'Go-http-client'),
        ('axios/0.21.1', 'axios'),
        ('Postman Runtime/7.28', 'Postman'),
        ('HTTPie/3.0', 'HTTPie'),
        ('Scrapy/2.5', 'Scrapy'),
    ])
    def test_scrapers(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'SCRAPER'
        assert result.name == expected_name


# =============================================================================
# SECURITY SCANNERS
# =============================================================================

class TestSecurityScanners:
    @pytest.mark.parametrize("ua,expected_name", [
        ('Mozilla/5.0 [en] (X11, U; OpenVAS-VT 22.4.1)', 'openvas'),
        ('Fuzz Faster U Fool v2.0.0', 'ffuf'),
        ('feroxbuster/2.7', 'feroxbuster'),
        ('sqlmap/1.7', 'sqlmap'),
        ('Nikto/2.1.6', 'nikto'),
    ])
    def test_security_scanners(self, ua, expected_name):
        result = detect_bot(make_request(ua))
        assert result.is_bot is True
        assert result.category == 'SECURITY_SCANNER'
        assert result.name == expected_name


# =============================================================================
# HUMAN DETECTION
# =============================================================================

class TestHumanDetection:
    def test_chrome_browser(self):
        result = detect_bot(make_request(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        ))
        assert result.is_bot is False
        assert result.category == 'HUMAN'
        assert result.name is None

    def test_firefox_browser(self):
        result = detect_bot(make_request(
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0'
        ))
        assert result.is_bot is False
        assert result.category == 'HUMAN'

    def test_safari_browser(self):
        result = detect_bot(make_request(
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15'
        ))
        assert result.is_bot is False
        assert result.category == 'HUMAN'

    def test_mobile_browser(self):
        result = detect_bot(make_request(
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1'
        ))
        assert result.is_bot is False
        assert result.category == 'HUMAN'

    def test_human_confidence_high(self):
        result = detect_bot(make_request('Mozilla/5.0 Chrome/120.0'))
        assert result.confidence > 0.5


# =============================================================================
# MISSING USER-AGENT
# =============================================================================

class TestMissingUserAgent:
    def test_no_ua_header(self):
        req = FakeRequest({'accept': 'text/html'})
        result = detect_bot(req)
        assert result.is_bot is True
        assert result.category == 'UNKNOWN'
        assert result.confidence >= 0.8
        assert 'missing_user_agent' in result.signals

    def test_empty_ua(self):
        result = detect_bot(make_request(''))
        assert result.is_bot is True
        assert result.category == 'UNKNOWN'


# =============================================================================
# BEHAVIORAL SIGNALS
# =============================================================================

class TestBehavioralSignals:
    def test_missing_accept_headers(self):
        req = bare_request('SomeUnknownUA/1.0')
        result = detect_bot(req)
        assert 'missing_accept' in result.signals
        assert 'missing_accept_language' in result.signals
        assert 'missing_accept_encoding' in result.signals

    def test_3_plus_missing_headers_flagged_as_bot(self):
        req = bare_request('CustomApp/1.0')
        result = detect_bot(req)
        assert result.is_bot is True
        assert result.category == 'UNKNOWN'
        assert result.confidence > 0.6

    def test_connection_close_signal(self):
        req = make_request('SomeUA/1.0', {'connection': 'close'})
        result = detect_bot(req)
        assert 'connection_close' in result.signals

    def test_few_missing_headers_stays_human(self):
        req = FakeRequest({
            'user-agent': 'NormalBrowser/1.0',
            'accept': 'text/html',
        })
        result = detect_bot(req)
        assert result.is_bot is False
        assert result.category == 'HUMAN'
        assert result.confidence < 1.0


# =============================================================================
# CASE INSENSITIVITY
# =============================================================================

class TestCaseInsensitivity:
    def test_lowercase(self):
        result = detect_bot(make_request('googlebot/2.1'))
        assert result.is_bot is True
        assert result.category == 'SEARCH_ENGINE'

    def test_uppercase(self):
        result = detect_bot(make_request('GPTBOT/1.0'))
        assert result.is_bot is True
        assert result.category == 'AI_CRAWLER'


# =============================================================================
# RESULT STRUCTURE
# =============================================================================

class TestResultStructure:
    def test_all_fields_present(self):
        result = detect_bot(make_request('Googlebot/2.1'))
        assert isinstance(result, BotDetectionResult)
        assert isinstance(result.is_bot, bool)
        assert isinstance(result.category, str)
        assert isinstance(result.confidence, float)
        assert isinstance(result.signals, list)

    def test_confidence_range(self):
        for ua in ['Googlebot/2.1', 'curl/7.0', '']:
            result = detect_bot(make_request(ua))
            assert 0 <= result.confidence <= 1


# =============================================================================
# BOT PROTECTION CLASS
# =============================================================================

class TestBotProtection:
    def test_allows_humans(self):
        guard = BotProtection()
        result = guard.check(make_request('Mozilla/5.0 Chrome/120.0'))
        assert result.is_bot is False

    def test_allows_search_engines_by_default(self):
        guard = BotProtection()
        result = guard.check(make_request('Googlebot/2.1'))
        assert result.is_bot is True
        assert result.category == 'SEARCH_ENGINE'
        # No exception raised

    def test_allows_social_by_default(self):
        guard = BotProtection()
        result = guard.check(make_request('Twitterbot/1.0'))
        assert result.category == 'SOCIAL'

    def test_allows_monitoring_by_default(self):
        guard = BotProtection()
        result = guard.check(make_request('UptimeRobot/2.0'))
        assert result.category == 'MONITORING'

    def test_blocks_automated_by_default(self):
        guard = BotProtection()
        with pytest.raises(BotDenied):
            guard.check(make_request('HeadlessChrome/90.0'))

    def test_custom_deny_list(self):
        guard = BotProtection(deny=['SCRAPER', 'AUTOMATED'])
        with pytest.raises(BotDenied):
            guard.check(make_request('curl/7.68.0'))

    def test_custom_allow_list(self):
        guard = BotProtection(
            allow=['AUTOMATED', 'SEARCH_ENGINE'],
            deny=[],
        )
        result = guard.check(make_request('HeadlessChrome/90.0'))
        assert result.category == 'AUTOMATED'
        # No exception

    def test_default_deny(self):
        guard = BotProtection(
            allow=['SEARCH_ENGINE'],
            deny=[],
            default_action='deny',
        )
        with pytest.raises(BotDenied):
            guard.check(make_request('GPTBot/1.0'))

    def test_default_deny_still_allows_allowed(self):
        guard = BotProtection(
            allow=['SEARCH_ENGINE'],
            default_action='deny',
        )
        result = guard.check(make_request('Googlebot/2.1'))
        assert result.category == 'SEARCH_ENGINE'

    def test_custom_message(self):
        guard = BotProtection(deny=['AUTOMATED'], message='Go away')
        with pytest.raises(BotDenied, match='Go away'):
            guard.check(make_request('HeadlessChrome/90.0'))

    def test_bot_denied_has_result(self):
        guard = BotProtection(deny=['AUTOMATED'])
        with pytest.raises(BotDenied) as exc_info:
            guard.check(make_request('HeadlessChrome/90.0'))
        assert exc_info.value.result is not None
        assert exc_info.value.result.category == 'AUTOMATED'

    def test_ai_crawlers_allowed_by_default(self):
        guard = BotProtection()
        result = guard.check(make_request('GPTBot/1.0'))
        assert result.category == 'AI_CRAWLER'

    def test_scrapers_allowed_by_default(self):
        guard = BotProtection()
        result = guard.check(make_request('curl/7.68.0'))
        assert result.category == 'SCRAPER'
