"""
Platform-aware IP detection tests.
Tests for arcis/utils/ip.py
"""

import os
import pytest
from arcis.utils.ip import (
    detect_client_ip,
    is_private_ip,
    _parse_forwarded_for,
    _detect_platform,
    _reset_platform_cache,
)


# --- Mock request objects ---

class FlaskRequest:
    """Mock Flask request."""
    def __init__(self, headers=None, remote_addr='127.0.0.1'):
        self.headers = headers or {}
        self.remote_addr = remote_addr


class DjangoRequest:
    """Mock Django request."""
    def __init__(self, meta=None):
        self.META = meta or {}


class FastAPIRequest:
    """Mock FastAPI/Starlette request."""
    def __init__(self, headers=None, client_host=None):
        self.headers = headers or {}
        self.client = type('Client', (), {'host': client_host})() if client_host else None


# --- Platform header tests ---

class TestDetectClientIPPlatformHeaders:
    """Test platform-specific header extraction."""

    def test_cloudflare(self):
        req = FlaskRequest(headers={'cf-connecting-ip': '203.0.113.50'})
        ip = detect_client_ip(req, platform='cloudflare')
        assert ip == '203.0.113.50'

    def test_vercel(self):
        req = FlaskRequest(headers={'x-real-ip': '198.51.100.10'})
        ip = detect_client_ip(req, platform='vercel')
        assert ip == '198.51.100.10'

    def test_flyio(self):
        req = FlaskRequest(headers={'fly-client-ip': '192.0.2.1'})
        ip = detect_client_ip(req, platform='flyio')
        assert ip == '192.0.2.1'

    def test_render(self):
        req = FlaskRequest(headers={'x-render-client-ip': '10.0.0.1'})
        ip = detect_client_ip(req, platform='render')
        assert ip == '10.0.0.1'

    def test_firebase(self):
        req = FlaskRequest(headers={'x-appengine-user-ip': '172.16.0.1'})
        ip = detect_client_ip(req, platform='firebase')
        assert ip == '172.16.0.1'

    def test_aws_alb_uses_xff(self):
        req = FlaskRequest(headers={'x-forwarded-for': '203.0.113.50, 10.0.0.1'})
        ip = detect_client_ip(req, platform='aws-alb')
        assert ip == '10.0.0.1'

    def test_platform_header_strips_whitespace(self):
        req = FlaskRequest(headers={'cf-connecting-ip': '  203.0.113.50  '})
        ip = detect_client_ip(req, platform='cloudflare')
        assert ip == '203.0.113.50'


class TestDetectClientIPFallbacks:
    """Test fallback chain: XFF -> X-Real-IP -> remote addr -> unknown."""

    def test_xff_fallback(self):
        req = FlaskRequest(headers={'x-forwarded-for': '203.0.113.50'})
        ip = detect_client_ip(req, platform='generic')
        assert ip == '203.0.113.50'

    def test_x_real_ip_fallback(self):
        req = FlaskRequest(headers={'x-real-ip': '198.51.100.10'})
        ip = detect_client_ip(req, platform='generic')
        assert ip == '198.51.100.10'

    def test_flask_remote_addr(self):
        req = FlaskRequest(remote_addr='10.0.0.5')
        ip = detect_client_ip(req, platform='generic')
        assert ip == '10.0.0.5'

    def test_fastapi_client_host(self):
        req = FastAPIRequest(client_host='172.16.0.5')
        ip = detect_client_ip(req, platform='generic')
        assert ip == '172.16.0.5'

    def test_django_remote_addr(self):
        req = DjangoRequest(meta={'REMOTE_ADDR': '10.0.0.99'})
        ip = detect_client_ip(req, platform='generic')
        assert ip == '10.0.0.99'

    def test_unknown_when_no_ip_found(self):
        """Should return 'unknown' when no IP can be resolved."""
        req = type('Bare', (), {})()
        ip = detect_client_ip(req, platform='generic')
        assert ip == 'unknown'


class TestDetectClientIPDjango:
    """Test Django META header extraction."""

    def test_django_xff(self):
        req = DjangoRequest(meta={'HTTP_X_FORWARDED_FOR': '203.0.113.50, 10.0.0.1'})
        ip = detect_client_ip(req, platform='generic')
        assert ip == '10.0.0.1'

    def test_django_cloudflare(self):
        req = DjangoRequest(meta={'HTTP_CF_CONNECTING_IP': '203.0.113.50'})
        ip = detect_client_ip(req, platform='cloudflare')
        assert ip == '203.0.113.50'


class TestParseForwardedFor:
    """Test X-Forwarded-For parsing from the right."""

    def test_single_ip(self):
        assert _parse_forwarded_for('203.0.113.50') == '203.0.113.50'

    def test_two_ips_one_proxy(self):
        """With 1 trusted proxy, pick the IP just before the proxy."""
        assert _parse_forwarded_for('203.0.113.50, 10.0.0.1', trusted_proxy_count=1) == '10.0.0.1'

    def test_three_ips_two_proxies(self):
        result = _parse_forwarded_for('1.1.1.1, 2.2.2.2, 3.3.3.3', trusted_proxy_count=2)
        assert result == '2.2.2.2'

    def test_empty_string(self):
        assert _parse_forwarded_for('') is None

    def test_whitespace_handling(self):
        result = _parse_forwarded_for('  203.0.113.50 ,  10.0.0.1 ')
        assert result == '10.0.0.1'

    def test_trusted_proxy_count_larger_than_list(self):
        """When proxy count >= list length, return first IP."""
        result = _parse_forwarded_for('1.1.1.1', trusted_proxy_count=5)
        assert result == '1.1.1.1'


class TestAutoDetectPlatform:
    """Test auto-detection via environment variables."""

    def setup_method(self):
        _reset_platform_cache()
        self._original_env = os.environ.copy()

    def teardown_method(self):
        os.environ.clear()
        os.environ.update(self._original_env)
        _reset_platform_cache()

    def test_detects_cloudflare(self):
        os.environ['CF_PAGES'] = '1'
        assert _detect_platform() == 'cloudflare'

    def test_detects_vercel(self):
        os.environ['VERCEL'] = '1'
        assert _detect_platform() == 'vercel'

    def test_detects_flyio(self):
        os.environ['FLY_APP_NAME'] = 'my-app'
        assert _detect_platform() == 'flyio'

    def test_detects_render(self):
        os.environ['RENDER'] = 'true'
        assert _detect_platform() == 'render'

    def test_detects_firebase(self):
        os.environ['FIREBASE_CONFIG'] = '{}'
        assert _detect_platform() == 'firebase'

    def test_detects_aws(self):
        os.environ['AWS_LAMBDA_FUNCTION_NAME'] = 'my-func'
        assert _detect_platform() == 'aws-alb'

    def test_falls_back_to_generic(self):
        assert _detect_platform() == 'generic'


class TestIsPrivateIP:
    """Test private/internal IP detection."""

    @pytest.mark.parametrize("ip", [
        '127.0.0.1',
        '127.255.255.255',
        '10.0.0.1',
        '10.255.255.255',
        '172.16.0.1',
        '172.31.255.255',
        '192.168.0.1',
        '192.168.255.255',
        '169.254.0.1',
        '0.0.0.0',
        '::1',
        'fe80::1',
        'fc00::1',
        'fd00::1',
    ])
    def test_private_ips(self, ip):
        assert is_private_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        '8.8.8.8',
        '203.0.113.50',
        '1.1.1.1',
        '198.51.100.1',
        '172.32.0.1',
        '2001:db8::1',
    ])
    def test_public_ips(self, ip):
        assert is_private_ip(ip) is False

    def test_empty_string(self):
        assert is_private_ip('') is False
