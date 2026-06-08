"""
Arcis Django Integration Tests
================================

Tests for Django middleware integration.
Run with: pytest tests/test_django.py -v
"""

import pytest
import json

# Skip these tests if Django is not installed
pytest.importorskip("django")

import django
from django.conf import settings

# Configure Django settings before importing Arcis Django module
if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={},
        INSTALLED_APPS=[
            'django.contrib.contenttypes',
            'django.contrib.auth',
        ],
        MIDDLEWARE=[],
        ROOT_URLCONF='',
        SECRET_KEY='test-secret-key-for-arcis-tests',
    )
    django.setup()

from django.test import RequestFactory, override_settings
from django.http import JsonResponse

from arcis.django import (
    ArcisMiddleware,
    ArcisSanitizeMiddleware,
    ArcisRateLimitMiddleware,
    ArcisHeadersMiddleware,
    get_sanitized_body,
    get_client_ip,
)
from arcis.stores.memory import InMemoryStore


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def rf():
    """Request factory for creating test requests."""
    return RequestFactory()


@pytest.fixture
def simple_view():
    """Simple view that returns JSON."""
    def view(request):
        return JsonResponse({"message": "Hello"})
    return view


@pytest.fixture
def middleware(simple_view):
    """Arcis middleware instance."""
    return ArcisMiddleware(simple_view)


# ============================================================================
# UTILITY FUNCTION TESTS
# ============================================================================

class TestGetClientIP:
    """Test client IP extraction."""
    
    def test_extracts_remote_addr(self, rf):
        request = rf.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'
        
        ip = get_client_ip(request)
        assert ip == '192.168.1.1'
    
    def test_extracts_x_forwarded_for(self, rf):
        request = rf.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '10.0.0.1, 192.168.1.1'
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        ip = get_client_ip(request)
        assert ip == '10.0.0.1'  # First IP in chain
    
    def test_returns_unknown_when_no_ip(self, rf):
        request = rf.get('/')
        if 'REMOTE_ADDR' in request.META:
            del request.META['REMOTE_ADDR']
        
        ip = get_client_ip(request)
        assert ip == 'unknown'


# ============================================================================
# MAIN MIDDLEWARE TESTS
# ============================================================================

class TestArcisMiddleware:
    """Test the main ArcisMiddleware."""

    def test_adds_security_headers(self, rf, middleware):
        request = rf.get('/')
        response = middleware(request)

        assert 'Content-Security-Policy' in response
        assert response['X-Content-Type-Options'] == 'nosniff'
        assert response['X-Frame-Options'] == 'DENY'

    def test_adds_rate_limit_headers(self, rf, middleware):
        request = rf.get('/')
        response = middleware(request)

        assert 'X-RateLimit-Limit' in response
        assert 'X-RateLimit-Remaining' in response
        assert 'X-RateLimit-Reset' in response

    def test_returns_200_for_normal_request(self, rf, middleware):
        request = rf.get('/')
        response = middleware(request)

        assert response.status_code == 200

    def test_sanitizes_json_body(self, rf, simple_view):
        middleware = ArcisMiddleware(simple_view)
        
        request = rf.post(
            '/',
            data=json.dumps({"name": "<script>xss</script>"}),
            content_type='application/json'
        )
        
        middleware(request)
        
        sanitized = get_sanitized_body(request)
        assert sanitized is not None
        assert '<script>' not in sanitized['name']


class TestArcisMiddlewareRateLimiting:
    """Test rate limiting in Arcis middleware."""

    def setup_method(self):
        # The rate limiter and its store are cached at class scope (shared
        # across requests in production). Reset both before each test so
        # one test's config and counters do not leak into the next, and so
        # override_settings can bind a fresh limiter (it cannot rebind one
        # that an earlier test already created).
        ArcisMiddleware._rate_limiter = None
        ArcisMiddleware._rate_limit_store = InMemoryStore()

    @override_settings(ARCIS_CONFIG={'rate_limit_max': 3, 'rate_limit_window_ms': 60000})
    def test_blocks_over_limit(self, rf, simple_view):
        middleware = ArcisMiddleware(simple_view)
        
        # Make 3 requests (all should pass)
        for i in range(3):
            request = rf.get('/')
            request.META['REMOTE_ADDR'] = '192.168.1.100'
            response = middleware(request)
            assert response.status_code == 200, f"Request {i+1} should pass"
        
        # 4th request should be blocked
        request = rf.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.100'
        response = middleware(request)
        
        assert response.status_code == 429
        data = json.loads(response.content)
        assert 'error' in data
    
    @override_settings(ARCIS_CONFIG={'rate_limit_max': 2, 'rate_limit_window_ms': 60000})
    def test_different_ips_have_separate_limits(self, rf, simple_view):
        # Construct through the normal __init__ so every attribute the
        # middleware relies on is set. The limiter keys on client IP, so
        # two different IPs each get their own counter.
        middleware = ArcisMiddleware(simple_view)

        # Each IP makes 2 requests, all under its own per-IP cap of 2, so
        # all pass. A shared counter would block the 3rd request overall.
        for ip in ['192.168.1.1', '192.168.1.2']:
            for _ in range(2):
                request = rf.get('/')
                request.META['REMOTE_ADDR'] = ip
                response = middleware(request)
                assert response.status_code == 200


# ============================================================================
# STANDALONE MIDDLEWARE TESTS
# ============================================================================

class TestArcisSanitizeMiddleware:
    """Test standalone sanitization middleware."""

    def test_sanitizes_xss(self, rf, simple_view):
        middleware = ArcisSanitizeMiddleware(simple_view)
        
        request = rf.post(
            '/',
            data=json.dumps({"html": "<script>evil()</script>"}),
            content_type='application/json'
        )
        
        middleware(request)
        
        sanitized = get_sanitized_body(request)
        assert '<script>' not in sanitized['html']
    
    def test_sanitizes_sql(self, rf, simple_view):
        middleware = ArcisSanitizeMiddleware(simple_view)
        
        request = rf.post(
            '/',
            data=json.dumps({"query": "'; DROP TABLE users; --"}),
            content_type='application/json'
        )
        
        middleware(request)
        
        sanitized = get_sanitized_body(request)
        assert 'DROP' not in sanitized['query'].upper()
    
    def test_ignores_non_json_requests(self, rf, simple_view):
        middleware = ArcisSanitizeMiddleware(simple_view)
        
        request = rf.post('/', data={'name': '<script>xss</script>'})
        response = middleware(request)
        
        assert response.status_code == 200
        assert get_sanitized_body(request) is None


class TestArcisRateLimitMiddleware:
    """Test standalone rate limiting middleware."""

    def test_adds_rate_limit_headers(self, rf, simple_view):
        middleware = ArcisRateLimitMiddleware(simple_view)
        
        request = rf.get('/')
        response = middleware(request)
        
        assert 'X-RateLimit-Limit' in response
        assert 'X-RateLimit-Remaining' in response


class TestArcisHeadersMiddleware:
    """Test standalone security headers middleware."""

    def test_adds_all_security_headers(self, rf, simple_view):
        middleware = ArcisHeadersMiddleware(simple_view)
        
        request = rf.get('/')
        response = middleware(request)
        
        assert 'Content-Security-Policy' in response
        assert 'X-Content-Type-Options' in response
        assert 'X-Frame-Options' in response
        assert 'Strict-Transport-Security' in response
    
    def test_removes_server_header(self, rf, simple_view):
        def view_with_server_header(request):
            response = JsonResponse({"message": "Hello"})
            response['Server'] = 'Apache/2.4.41'
            return response
        
        middleware = ArcisHeadersMiddleware(view_with_server_header)
        
        request = rf.get('/')
        response = middleware(request)
        
        assert 'Server' not in response


# ============================================================================
# CONFIGURATION TESTS
# ============================================================================

class TestArcisConfiguration:
    """Test middleware configuration via Django settings."""

    @override_settings(ARCIS_CONFIG={'sanitize': False})
    def test_can_disable_sanitization(self, rf, simple_view):
        middleware = ArcisMiddleware(simple_view)
        assert middleware.sanitizer is None

    @override_settings(ARCIS_CONFIG={'rate_limit': False})
    def test_can_disable_rate_limiting(self, rf, simple_view):
        middleware = ArcisMiddleware(simple_view)
        assert middleware.rate_limiter is None

    @override_settings(ARCIS_CONFIG={'headers': False})
    def test_can_disable_headers(self, rf, simple_view):
        middleware = ArcisMiddleware(simple_view)
        assert middleware.security_headers is None

    @override_settings(ARCIS_CONFIG={'csp': "default-src 'none'"})
    def test_custom_csp(self, rf, simple_view):
        middleware = ArcisMiddleware(simple_view)
        
        request = rf.get('/')
        response = middleware(request)
        
        assert response['Content-Security-Policy'] == "default-src 'none'"
