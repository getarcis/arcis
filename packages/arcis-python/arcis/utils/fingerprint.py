"""
Arcis Utilities - Request Fingerprinting

Deterministic request fingerprinting via SHA-256.
Generates a stable hash from request characteristics for
rate limiting keys, abuse detection, and analytics.

Examples:
    >>> fp = fingerprint(request)
    >>> print(fp)  # "a3f2b8c1d4e5..."
"""

import hashlib
from typing import List, Optional

from .ip import detect_client_ip


def _get_header(request, name: str) -> str:
    """Get a header value from a request object."""
    from .request import get_request_header
    return get_request_header(request, name, default='') or ''


def fingerprint(
    request,
    *,
    ip: bool = True,
    user_agent: bool = True,
    accept: bool = True,
    accept_language: bool = True,
    accept_encoding: bool = True,
    custom: Optional[List[str]] = None,
    platform: str = 'auto',
    trusted_proxy_count: int = 1,
) -> str:
    """
    Generate a deterministic fingerprint for a request.

    Creates a SHA-256 hash from configurable request components.
    The fingerprint is stable across requests from the same client.

    Args:
        request: HTTP request object (Flask, Django, FastAPI).
        ip: Include IP address. Default: True.
        user_agent: Include User-Agent header. Default: True.
        accept: Include Accept header. Default: True.
        accept_language: Include Accept-Language header. Default: True.
        accept_encoding: Include Accept-Encoding header. Default: True.
        custom: Additional custom string components to include.
        platform: Platform for IP detection. Default: 'auto'.
        trusted_proxy_count: Number of trusted proxies for IP detection.

    Returns:
        Hex-encoded SHA-256 hash (64 characters).

    Examples:
        >>> fp = fingerprint(request)
        >>> fp = fingerprint(request, custom=['user_123'])
    """
    components = []

    if ip:
        client_ip = detect_client_ip(
            request, platform=platform, trusted_proxy_count=trusted_proxy_count
        )
        components.append(f'ip:{client_ip}')

    if user_agent:
        components.append(f'ua:{_get_header(request, "user-agent")}')

    if accept:
        components.append(f'accept:{_get_header(request, "accept")}')

    if accept_language:
        components.append(f'lang:{_get_header(request, "accept-language")}')

    if accept_encoding:
        components.append(f'enc:{_get_header(request, "accept-encoding")}')

    if custom:
        for c in custom:
            if c is not None:
                components.append(f'custom:{c}')

    # Sort for deterministic ordering
    components.sort()

    data = '|'.join(components)
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
