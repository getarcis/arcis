"""
Arcis FastAPI Integration Tests
=================================

Tests for FastAPI middleware integration.
Run with: pytest tests/test_fastapi.py -v
"""

import pytest
import time
import asyncio
from unittest.mock import MagicMock

# Skip these tests if FastAPI is not installed
pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from arcis.fastapi import ArcisMiddleware


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def app():
    """Create a FastAPI app with Arcis middleware."""
    app = FastAPI()
    app.add_middleware(ArcisMiddleware)
    
    @app.get("/")
    async def root():
        return {"message": "Hello World"}
    
    @app.post("/echo")
    async def echo(data: dict):
        return data
    
    @app.get("/health")
    async def health():
        return {"status": "ok"}
    
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def rate_limited_app():
    """Create app with low rate limit for testing."""
    app = FastAPI()
    app.add_middleware(ArcisMiddleware, rate_limit_max=3, rate_limit_window_ms=60000)
    
    @app.get("/")
    async def root():
        return {"message": "Hello"}
    
    return app


@pytest.fixture
def rate_limited_client(rate_limited_app):
    return TestClient(rate_limited_app)


# ============================================================================
# SECURITY HEADERS TESTS
# ============================================================================

class TestFastAPISecurityHeaders:
    """Test security headers are applied to responses."""
    
    def test_csp_header_present(self, client):
        response = client.get("/")
        assert "content-security-policy" in response.headers
    
    def test_x_content_type_options_present(self, client):
        response = client.get("/")
        assert response.headers.get("x-content-type-options") == "nosniff"
    
    def test_x_frame_options_present(self, client):
        response = client.get("/")
        assert response.headers.get("x-frame-options") == "DENY"
    
    def test_hsts_header_present(self, client):
        response = client.get("/")
        hsts = response.headers.get("strict-transport-security", "")
        assert "max-age=" in hsts


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

class TestFastAPIRateLimiting:
    """Test rate limiting in FastAPI middleware."""
    
    def test_rate_limit_headers_present(self, client):
        response = client.get("/")
        assert "x-ratelimit-limit" in response.headers
        assert "x-ratelimit-remaining" in response.headers
        assert "x-ratelimit-reset" in response.headers
    
    def test_allows_requests_under_limit(self, rate_limited_client):
        for _ in range(3):
            response = rate_limited_client.get("/")
            assert response.status_code == 200
    
    def test_blocks_requests_over_limit(self, rate_limited_client):
        # Make 3 requests (all should pass)
        for _ in range(3):
            response = rate_limited_client.get("/")
            assert response.status_code == 200
        
        # 4th request should be blocked
        response = rate_limited_client.get("/")
        assert response.status_code == 429
        assert "error" in response.json()
    
    def test_rate_limit_response_has_retry_after(self, rate_limited_client):
        # Exhaust rate limit
        for _ in range(4):
            response = rate_limited_client.get("/")
        
        assert response.status_code == 429
        assert "retry-after" in response.headers


# ============================================================================
# SANITIZATION TESTS
# ============================================================================

class TestFastAPISanitization:
    """Test request body sanitization."""
    
    def test_sanitizes_xss_in_body(self, client):
        data = {"name": "<script>alert('xss')</script>"}
        response = client.post("/echo", json=data)
        # Note: The echo endpoint returns the original data from the route
        # The sanitized version is stored in request.state.sanitized_body
        assert response.status_code == 200
    
    def test_allows_normal_requests(self, client):
        data = {"name": "John Doe", "email": "john@example.com"}
        response = client.post("/echo", json=data)
        assert response.status_code == 200


# ============================================================================
# CUSTOM CONFIGURATION TESTS
# ============================================================================

class TestFastAPICustomConfig:
    """Test custom middleware configuration."""
    
    def test_custom_csp(self):
        app = FastAPI()
        app.add_middleware(ArcisMiddleware, csp="default-src 'none'")
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        response = client.get("/")
        
        assert response.headers.get("content-security-policy") == "default-src 'none'"
    
    def test_disable_sanitization(self):
        app = FastAPI()
        app.add_middleware(ArcisMiddleware, sanitize=False)
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
    
    def test_disable_rate_limiting(self):
        app = FastAPI()
        app.add_middleware(ArcisMiddleware, rate_limit=False)
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        response = client.get("/")
        
        # Rate limit headers should not be present
        assert "x-ratelimit-limit" not in response.headers
    
    def test_disable_headers(self):
        app = FastAPI()
        app.add_middleware(ArcisMiddleware, headers=False)
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        response = client.get("/")
        
        # CSP header should not be present
        assert "content-security-policy" not in response.headers


# ============================================================================
# ASYNC RATE LIMITER TESTS
# ============================================================================

from arcis.fastapi import (
    AsyncInMemoryStore,
    AsyncRateLimiter,
    AsyncRateLimitExceeded,
    create_rate_limit_dependency,
)


class TestAsyncInMemoryStore:
    """Test AsyncInMemoryStore class."""
    
    @pytest.mark.asyncio
    async def test_get_returns_none_for_nonexistent_key(self):
        store = AsyncInMemoryStore()
        result = await store.get("nonexistent")
        assert result is None
        await store.close()
    
    @pytest.mark.asyncio
    async def test_set_and_get(self):
        store = AsyncInMemoryStore()
        await store.set("test_key", 5, time.time() + 60)
        result = await store.get("test_key")
        assert result is not None
        assert result.count == 5
        await store.close()
    
    @pytest.mark.asyncio
    async def test_get_returns_none_for_expired_entry(self):
        store = AsyncInMemoryStore()
        # Set entry that's already expired
        await store.set("expired_key", 1, time.time() - 10)
        result = await store.get("expired_key")
        assert result is None
        await store.close()
    
    @pytest.mark.asyncio
    async def test_increment(self):
        store = AsyncInMemoryStore()
        await store.set("counter", 3, time.time() + 60)
        new_count = await store.increment("counter")
        assert new_count == 4
        result = await store.get("counter")
        assert result.count == 4
        await store.close()
    
    @pytest.mark.asyncio
    async def test_increment_nonexistent_returns_one(self):
        store = AsyncInMemoryStore()
        new_count = await store.increment("new_key")
        assert new_count == 1
        await store.close()
    
    @pytest.mark.asyncio
    async def test_cleanup_removes_expired(self):
        store = AsyncInMemoryStore()
        # Set one expired and one valid
        await store.set("expired", 1, time.time() - 10)
        await store.set("valid", 1, time.time() + 60)
        
        # Force store the expired one (bypass get's auto-cleanup)
        async with store._lock:
            from arcis.core.types import RateLimitEntry
            store._store["expired"] = RateLimitEntry(count=1, reset_time=time.time() - 10)
        
        await store.cleanup()
        
        # Expired should be gone, valid should remain
        async with store._lock:
            assert "expired" not in store._store
            assert "valid" in store._store
        await store.close()
    
    @pytest.mark.asyncio
    async def test_clear_removes_all(self):
        store = AsyncInMemoryStore()
        await store.set("key1", 1, time.time() + 60)
        await store.set("key2", 2, time.time() + 60)
        await store.clear()
        
        async with store._lock:
            assert len(store._store) == 0
        await store.close()
    
    @pytest.mark.asyncio
    async def test_close_marks_closed(self):
        store = AsyncInMemoryStore()
        assert store._closed is False
        await store.close()
        assert store._closed is True


class TestAsyncRateLimitExceeded:
    """Test AsyncRateLimitExceeded exception."""
    
    def test_default_message(self):
        exc = AsyncRateLimitExceeded()
        assert exc.message == "Rate limit exceeded"
        assert exc.retry_after == 0
    
    def test_custom_message_and_retry_after(self):
        exc = AsyncRateLimitExceeded(message="Too many requests", retry_after=30)
        assert exc.message == "Too many requests"
        assert exc.retry_after == 30
        assert str(exc) == "Too many requests"


class TestAsyncRateLimiter:
    """Test AsyncRateLimiter class."""
    
    @pytest.fixture
    def mock_request(self):
        """Create a mock request with a client IP."""
        request = MagicMock()
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        request.headers = {}
        return request
    
    @pytest.mark.asyncio
    async def test_allows_under_limit(self, mock_request):
        limiter = AsyncRateLimiter(max_requests=5, window_ms=60000)
        
        for i in range(5):
            result = await limiter.check(mock_request)
            assert result["allowed"] is True
            assert result["remaining"] == 5 - (i + 1)
        
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_blocks_over_limit(self, mock_request):
        limiter = AsyncRateLimiter(max_requests=3, window_ms=60000)
        
        # Use up the limit
        for _ in range(3):
            await limiter.check(mock_request)
        
        # Next request should raise
        with pytest.raises(AsyncRateLimitExceeded) as exc_info:
            await limiter.check(mock_request)
        
        assert exc_info.value.retry_after >= 0
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_different_ips_have_separate_limits(self):
        limiter = AsyncRateLimiter(max_requests=2, window_ms=60000)
        
        request1 = MagicMock()
        request1.client = MagicMock()
        request1.client.host = "192.168.1.1"
        request1.headers = {}
        
        request2 = MagicMock()
        request2.client = MagicMock()
        request2.client.host = "192.168.1.2"
        request2.headers = {}
        
        # Both should get their own limits
        for _ in range(2):
            result1 = await limiter.check(request1)
            result2 = await limiter.check(request2)
            assert result1["allowed"] is True
            assert result2["allowed"] is True
        
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_custom_key_function(self):
        def user_key(request):
            return request.headers.get("x-user-id", "anonymous")
        
        limiter = AsyncRateLimiter(max_requests=2, window_ms=60000, key_func=user_key)
        
        request = MagicMock()
        request.headers = {"x-user-id": "user123"}
        
        result = await limiter.check(request)
        assert result["allowed"] is True
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_skip_function(self, mock_request):
        def skip_admin(request):
            return request.headers.get("x-admin") == "true"
        
        limiter = AsyncRateLimiter(max_requests=1, window_ms=60000, skip_func=skip_admin)
        
        # First non-admin request uses the limit
        await limiter.check(mock_request)
        
        # Second non-admin request should fail
        with pytest.raises(AsyncRateLimitExceeded):
            await limiter.check(mock_request)
        
        # Admin request should skip rate limiting
        admin_request = MagicMock()
        admin_request.client = MagicMock()
        admin_request.client.host = "192.168.1.1"  # Same IP
        admin_request.headers = {"x-admin": "true"}
        
        result = await limiter.check(admin_request)
        assert result["allowed"] is True
        
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_async_skip_function(self, mock_request):
        async def async_skip(request):
            await asyncio.sleep(0)  # Simulate async check
            return request.headers.get("x-admin") == "true"

        limiter = AsyncRateLimiter(max_requests=1, window_ms=60000, skip_func=async_skip)

        admin_request = MagicMock()
        admin_request.client = MagicMock()
        admin_request.client.host = "192.168.1.1"
        admin_request.headers = {"x-admin": "true"}

        result = await limiter.check(admin_request)
        assert result["allowed"] is True

        await limiter.close()

    @pytest.mark.asyncio
    async def test_async_key_function_is_awaited(self):
        """Regression: an async key_func used to leak a coroutine object as the
        rate-limit key, breaking per-key isolation silently. Now awaited like
        skip_func.
        """
        async def async_key(request):
            await asyncio.sleep(0)
            return request.headers.get("x-tenant", "default")

        limiter = AsyncRateLimiter(max_requests=2, window_ms=60000, key_func=async_key)

        req_a = MagicMock()
        req_a.client = MagicMock()
        req_a.client.host = "1.1.1.1"
        req_a.headers = {"x-tenant": "tenant-a"}

        req_b = MagicMock()
        req_b.client = MagicMock()
        req_b.client.host = "1.1.1.1"
        req_b.headers = {"x-tenant": "tenant-b"}

        # Two requests under tenant-a, third must trip; meanwhile tenant-b
        # has its own counter and stays allowed. If the coroutine were used
        # as the key, all three would share a key and the test would behave
        # incorrectly (or raise TypeError on dict lookup).
        await limiter.check(req_a)
        await limiter.check(req_a)
        with pytest.raises(AsyncRateLimitExceeded):
            await limiter.check(req_a)
        result = await limiter.check(req_b)
        assert result["allowed"] is True

        await limiter.close()

    def test_default_key_func_uses_xff_from_right(self):
        """Regression: _default_key_func used to read X-Forwarded-For from the
        left, allowing trivial IP spoofing via attacker-prepended values. It
        now delegates to detect_client_ip which parses XFF from the right
        (proxy-appended end) and prefers spoofproof platform headers.
        """
        from types import SimpleNamespace

        limiter = AsyncRateLimiter(max_requests=10, window_ms=60000)

        # Use SimpleNamespace so hasattr returns False for framework-specific
        # attrs we did not set (META, remote_addr). MagicMock auto-creates
        # those, sending detect_client_ip down the wrong branch.
        request = SimpleNamespace(
            client=None,  # No socket peer
            headers={"x-forwarded-for": "spoofed.attacker, 203.0.113.50"},
        )

        key = limiter._default_key_func(request)
        # Rightmost trusted IP must win, never the spoofed left value.
        assert key != "spoofed.attacker"
        assert "203.0.113.50" in key
    
    @pytest.mark.asyncio
    async def test_close_stops_limiter(self, mock_request):
        limiter = AsyncRateLimiter(max_requests=5, window_ms=60000)
        
        # Make a request to start the cleanup task
        await limiter.check(mock_request)
        
        await limiter.close()
        assert limiter._closed is True
        
        # After close, requests should still pass (fail-open)
        result = await limiter.check(mock_request)
        assert result["allowed"] is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_info_returned(self, mock_request):
        limiter = AsyncRateLimiter(max_requests=10, window_ms=60000)
        
        result = await limiter.check(mock_request)
        
        assert "allowed" in result
        assert "limit" in result
        assert "remaining" in result
        assert "reset" in result
        assert result["limit"] == 10
        assert result["remaining"] == 9
        
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_x_forwarded_for_header(self):
        limiter = AsyncRateLimiter(max_requests=2, window_ms=60000)
        
        request = MagicMock()
        request.client = None
        request.headers = {"x-forwarded-for": "10.0.0.1, 10.0.0.2"}
        
        result = await limiter.check(request)
        assert result["allowed"] is True
        
        await limiter.close()
    
    @pytest.mark.asyncio
    async def test_x_real_ip_header(self):
        limiter = AsyncRateLimiter(max_requests=2, window_ms=60000)
        
        request = MagicMock()
        request.client = None
        request.headers = {"x-real-ip": "10.0.0.5"}
        
        result = await limiter.check(request)
        assert result["allowed"] is True
        
        await limiter.close()


class TestAsyncRateLimiterWithMiddleware:
    """Test AsyncRateLimiter with actual FastAPI middleware."""
    
    @pytest.fixture
    def async_rate_limited_app(self):
        """Create app using async rate limiter explicitly."""
        app = FastAPI()
        app.add_middleware(
            ArcisMiddleware,
            rate_limit_max=3,
            rate_limit_window_ms=60000,
            use_async_rate_limiter=True
        )
        
        @app.get("/")
        async def root():
            return {"message": "Hello"}
        
        return app
    
    @pytest.fixture
    def async_client(self, async_rate_limited_app):
        return TestClient(async_rate_limited_app)
    
    def test_async_middleware_allows_under_limit(self, async_client):
        for _ in range(3):
            response = async_client.get("/")
            assert response.status_code == 200
    
    def test_async_middleware_blocks_over_limit(self, async_client):
        # Exhaust the limit
        for _ in range(3):
            async_client.get("/")
        
        # Next request should be blocked
        response = async_client.get("/")
        assert response.status_code == 429
        assert "error" in response.json()
        assert "retry_after" in response.json()
    
    def test_async_middleware_has_rate_limit_headers(self, async_client):
        response = async_client.get("/")
        assert "x-ratelimit-limit" in response.headers
        assert "x-ratelimit-remaining" in response.headers
        assert "x-ratelimit-reset" in response.headers


class TestCreateRateLimitDependency:
    """Test create_rate_limit_dependency function."""
    
    def test_dependency_allows_requests(self):
        from fastapi import Depends
        
        app = FastAPI()
        rate_limit = create_rate_limit_dependency(max_requests=5, window_ms=60000)
        
        @app.get("/", dependencies=[Depends(rate_limit)])
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
    
    def test_dependency_blocks_over_limit(self):
        from fastapi import Depends
        
        app = FastAPI()
        rate_limit = create_rate_limit_dependency(max_requests=2, window_ms=60000)
        
        @app.get("/", dependencies=[Depends(rate_limit)])
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        
        # Use up the limit
        for _ in range(2):
            response = client.get("/")
            assert response.status_code == 200
        
        # Next request should fail
        response = client.get("/")
        assert response.status_code == 429
    
    def test_dependency_with_custom_key_func(self):
        from fastapi import Depends
        
        def api_key_limiter(request):
            return request.headers.get("x-api-key", "anonymous")
        
        app = FastAPI()
        rate_limit = create_rate_limit_dependency(
            max_requests=2,
            window_ms=60000,
            key_func=api_key_limiter
        )
        
        @app.get("/", dependencies=[Depends(rate_limit)])
        async def root():
            return {"message": "Hello"}
        
        client = TestClient(app)
        
        # Different API keys get separate limits
        response1 = client.get("/", headers={"x-api-key": "key1"})
        response2 = client.get("/", headers={"x-api-key": "key2"})
        assert response1.status_code == 200
        assert response2.status_code == 200
    
    def test_dependency_stores_info_in_request_state(self):
        from fastapi import Depends, Request
        
        app = FastAPI()
        rate_limit = create_rate_limit_dependency(max_requests=10, window_ms=60000)
        
        @app.get("/")
        async def root(request: Request, _: dict = Depends(rate_limit)):
            info = request.state.rate_limit_info
            return {"remaining": info["remaining"]}
        
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["remaining"] == 9

