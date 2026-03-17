"""
Arcis Utilities - Platform-Aware IP Detection

Prevents IP spoofing by reading platform-specific headers
instead of blindly trusting X-Forwarded-For.

Examples:
    # Auto-detect platform
    ip = detect_client_ip(request)

    # Explicit platform
    ip = detect_client_ip(request, platform='cloudflare')
"""

import os
import re
from typing import Optional, Literal

Platform = Literal[
    'auto', 'cloudflare', 'vercel', 'flyio', 'render',
    'firebase', 'aws-alb', 'generic',
]

# Platform-specific headers that cannot be spoofed by the client
_PLATFORM_HEADERS = {
    'cloudflare': 'cf-connecting-ip',
    'vercel': 'x-real-ip',
    'flyio': 'fly-client-ip',
    'render': 'x-render-client-ip',
    'firebase': 'x-appengine-user-ip',
    'aws-alb': 'x-forwarded-for',
}

_cached_platform: Optional[str] = None

# Private IP patterns
_PRIVATE_IPV4_PATTERNS = [
    re.compile(r'^127\.'),              # Loopback
    re.compile(r'^10\.'),               # Class A private
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),  # Class B private
    re.compile(r'^192\.168\.'),         # Class C private
    re.compile(r'^169\.254\.'),         # Link-local
    re.compile(r'^0\.'),               # Current network
]

_PRIVATE_IPV6_PATTERNS = [
    re.compile(r'^fe80:', re.IGNORECASE),   # Link-local
    re.compile(r'^fc00:', re.IGNORECASE),   # Unique local
    re.compile(r'^fd', re.IGNORECASE),      # Unique local
]


def _detect_platform() -> str:
    """Auto-detect the hosting platform from environment variables."""
    if os.environ.get('CF_PAGES') or os.environ.get('CF_WORKERS'):
        return 'cloudflare'
    if os.environ.get('VERCEL'):
        return 'vercel'
    if os.environ.get('FLY_APP_NAME'):
        return 'flyio'
    if os.environ.get('RENDER'):
        return 'render'
    if os.environ.get('FIREBASE_CONFIG') or os.environ.get('GCLOUD_PROJECT'):
        return 'firebase'
    if os.environ.get('AWS_EXECUTION_ENV') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
        return 'aws-alb'
    return 'generic'


def _get_cached_platform() -> str:
    """Get cached platform detection result."""
    global _cached_platform
    if _cached_platform is None:
        _cached_platform = _detect_platform()
    return _cached_platform


def _parse_forwarded_for(header: str, trusted_proxy_count: int = 1) -> Optional[str]:
    """
    Parse the rightmost trusted IP from X-Forwarded-For.

    Reading from the right prevents client spoofing — the rightmost entry
    is added by the closest trusted proxy.
    """
    ips = [ip.strip() for ip in header.split(',') if ip.strip()]
    if not ips:
        return None
    client_index = max(0, len(ips) - trusted_proxy_count)
    return ips[client_index] if client_index < len(ips) else None


_MAX_IP_LENGTH = 45  # IPv6 max length


def _sanitize_ip(ip: str) -> str:
    """Sanitize an IP string: trim and truncate to prevent unbounded map keys."""
    trimmed = ip.strip()
    return trimmed[:_MAX_IP_LENGTH] if len(trimmed) > _MAX_IP_LENGTH else trimmed


def _get_header(request, name: str) -> Optional[str]:
    """Get a header value from a request object."""
    from .request import get_request_header
    return get_request_header(request, name)


def detect_client_ip(
    request,
    platform: Platform = 'auto',
    trusted_proxy_count: int = 1,
) -> str:
    """
    Detect the real client IP address from a request.

    Uses platform-specific headers when available to prevent IP spoofing.
    Falls back to X-Forwarded-For (parsed from the right) and then
    the socket remote address.

    Args:
        request: HTTP request object (Flask, Django, FastAPI).
        platform: Hosting platform. Default: 'auto' (detect from env vars).
        trusted_proxy_count: Number of trusted proxies for XFF parsing. Default: 1.

    Returns:
        Client IP address, or 'unknown' if unresolvable.

    Examples:
        >>> detect_client_ip(request)
        '203.0.113.50'

        >>> detect_client_ip(request, platform='cloudflare')
        '203.0.113.50'
    """
    resolved = platform if platform != 'auto' else _get_cached_platform()

    # 1. Platform-specific header (most trusted)
    if resolved != 'generic' and resolved in _PLATFORM_HEADERS:
        header_name = _PLATFORM_HEADERS[resolved]

        if resolved == 'aws-alb':
            xff = _get_header(request, 'x-forwarded-for')
            if xff:
                ip = _parse_forwarded_for(xff, trusted_proxy_count)
                if ip:
                    return _sanitize_ip(ip)
        else:
            val = _get_header(request, header_name)
            if val:
                return _sanitize_ip(val)

    # 2. X-Forwarded-For (parsed from the right)
    xff = _get_header(request, 'x-forwarded-for')
    if xff:
        ip = _parse_forwarded_for(xff, trusted_proxy_count)
        if ip:
            return _sanitize_ip(ip)

    # 3. X-Real-IP
    real_ip = _get_header(request, 'x-real-ip')
    if real_ip:
        return _sanitize_ip(real_ip)

    # 4. Framework-specific remote address
    # Django
    if hasattr(request, 'META'):
        addr = request.META.get('REMOTE_ADDR')
        if addr:
            return _sanitize_ip(addr)

    # Flask
    if hasattr(request, 'remote_addr') and request.remote_addr:
        return _sanitize_ip(request.remote_addr)

    # FastAPI/Starlette
    if hasattr(request, 'client') and request.client:
        return _sanitize_ip(request.client.host)

    return 'unknown'


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is a private/internal address.

    Detects: loopback, private ranges (RFC 1918), link-local, IPv6 equivalents,
    IPv4-mapped IPv6 (::ffff:127.0.0.1).
    """
    # Strip IPv4-mapped IPv6 prefix
    normalized = ip[7:] if ip.startswith('::ffff:') else ip

    if normalized == '::1':
        return True

    for pattern in _PRIVATE_IPV4_PATTERNS:
        if pattern.match(normalized):
            return True

    for pattern in _PRIVATE_IPV6_PATTERNS:
        if pattern.match(normalized):
            return True

    return False


def _reset_platform_cache() -> None:
    """Reset cached platform (for testing)."""
    global _cached_platform
    _cached_platform = None
