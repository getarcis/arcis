"""
Platform-aware IP detection tests.
Tests for detect_client_ip in arcis/utils/ip.py. The resolver itself is
covered by tests/utils/test_client_ip.py against the shared fixtures.
"""

import pytest
from arcis.utils.ip import detect_client_ip, is_private_ip


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
    """Platform headers count only when chosen and sent by a trusted peer."""

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

    def test_aws_alb_uses_xff_walk(self):
        req = FlaskRequest(headers={'x-forwarded-for': '203.0.113.50, 10.0.0.1'})
        ip = detect_client_ip(req, platform='aws-alb')
        assert ip == '203.0.113.50'

    def test_platform_header_strips_whitespace(self):
        req = FlaskRequest(headers={'cf-connecting-ip': '  203.0.113.50  '})
        ip = detect_client_ip(req, platform='cloudflare')
        assert ip == '203.0.113.50'

    def test_platform_header_ignored_from_public_peer(self):
        req = FlaskRequest(
            headers={'cf-connecting-ip': '198.51.100.9'}, remote_addr='203.0.113.5'
        )
        assert detect_client_ip(req, platform='cloudflare') == '203.0.113.5'

    def test_platform_header_ignored_when_proxies_not_trusted(self):
        req = FlaskRequest(headers={'cf-connecting-ip': '198.51.100.9'})
        assert detect_client_ip(req, platform='cloudflare', trusted_proxies=[]) == '127.0.0.1'

    def test_invalid_platform_header_falls_back_to_walk(self):
        req = FlaskRequest(headers={'cf-connecting-ip': 'not-an-ip'})
        assert detect_client_ip(req, platform='cloudflare') == '127.0.0.1'

    def test_auto_ignores_platform_headers(self):
        req = FlaskRequest(headers={'cf-connecting-ip': '198.51.100.9'})
        assert detect_client_ip(req) == '127.0.0.1'


class TestDetectClientIPFallbacks:
    """Trust walk: XFF from a trusted peer, else the peer, else 'unknown'."""

    def test_xff_from_trusted_peer(self):
        req = FlaskRequest(headers={'x-forwarded-for': '203.0.113.50'})
        ip = detect_client_ip(req, platform='generic')
        assert ip == '203.0.113.50'

    def test_xff_from_public_peer_ignored(self):
        req = FlaskRequest(headers={'x-forwarded-for': '1.1.1.1'}, remote_addr='203.0.113.9')
        assert detect_client_ip(req) == '203.0.113.9'

    def test_x_real_ip_not_used_without_platform(self):
        req = FlaskRequest(headers={'x-real-ip': '198.51.100.10'})
        ip = detect_client_ip(req, platform='generic')
        assert ip == '127.0.0.1'

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

    def test_unknown_when_only_headers(self):
        """Without a peer address, forwarded headers are never trusted."""
        req = FastAPIRequest(headers={'x-forwarded-for': '203.0.113.50'})
        assert detect_client_ip(req) == 'unknown'


class TestDetectClientIPDjango:
    """Test Django META header extraction."""

    def test_django_xff(self):
        req = DjangoRequest(meta={
            'REMOTE_ADDR': '127.0.0.1',
            'HTTP_X_FORWARDED_FOR': '203.0.113.50, 10.0.0.1',
        })
        ip = detect_client_ip(req, platform='generic')
        assert ip == '203.0.113.50'

    def test_django_cloudflare(self):
        req = DjangoRequest(meta={
            'REMOTE_ADDR': '10.0.0.2',
            'HTTP_CF_CONNECTING_IP': '203.0.113.50',
        })
        ip = detect_client_ip(req, platform='cloudflare')
        assert ip == '203.0.113.50'


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
