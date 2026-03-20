"""
Arcis SSRF (Server-Side Request Forgery) prevention.

Validates URLs to ensure they don't target private/internal networks,
localhost, cloud metadata endpoints, or use dangerous protocols.

Example:
    from arcis import validate_url_ssrf, is_url_safe

    result = validate_url_ssrf("http://169.254.169.254/latest/meta-data/")
    # ValidateUrlResult(safe=False, reason='link-local address (169.254.0.0/16)')

    if is_url_safe(user_provided_url):
        response = requests.get(user_provided_url)
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse


@dataclass
class ValidateUrlOptions:
    """Options for URL validation."""

    allowed_protocols: List[str] = field(default_factory=lambda: ["http", "https"])
    """Allowed protocols (without colon). Default: ['http', 'https']"""

    blocked_hosts: List[str] = field(default_factory=list)
    """Additional hostnames to block (e.g., internal service names)."""

    allowed_hosts: List[str] = field(default_factory=list)
    """Additional hostnames to always allow (bypass IP checks)."""

    allow_localhost: bool = False
    """Allow localhost/loopback. Default: False"""

    allow_private: bool = False
    """Allow private/internal IPs. Default: False"""


@dataclass
class ValidateUrlResult:
    """Result of URL validation."""

    safe: bool
    """Whether the URL is safe to fetch."""

    reason: Optional[str] = None
    """Reason the URL was blocked (only set when safe=False)."""


# Compiled regex patterns for IP checks
_RE_LOOPBACK = re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_10 = re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_RE_172 = re.compile(r"^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$")
_RE_192 = re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$")
_RE_LINK_LOCAL = re.compile(r"^169\.254\.\d{1,3}\.\d{1,3}$")
_RE_CURRENT_NET = re.compile(r"^0\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _check_private_ip(hostname: str) -> Optional[str]:
    """Check if a hostname is a private/internal IP. Returns reason or None."""
    # 10.0.0.0/8
    if _RE_10.match(hostname):
        return "private address (10.0.0.0/8)"

    # 172.16.0.0/12
    m = _RE_172.match(hostname)
    if m:
        second = int(m.group(1))
        if 16 <= second <= 31:
            return "private address (172.16.0.0/12)"

    # 192.168.0.0/16
    if _RE_192.match(hostname):
        return "private address (192.168.0.0/16)"

    # 169.254.0.0/16 — link-local, includes cloud metadata
    if _RE_LINK_LOCAL.match(hostname):
        return "link-local address (169.254.0.0/16)"

    # 0.0.0.0/8 (current network)
    if _RE_CURRENT_NET.match(hostname):
        return "current network address (0.0.0.0/8)"

    # Cloud metadata hostnames
    if hostname in ("metadata.google.internal", "metadata.internal", "metadata.azure.internal"):
        return "cloud metadata endpoint"

    # IPv6 private ranges
    ipv6 = hostname.strip("[]")
    if ipv6 in ("::1", "::"):
        return "private IPv6 address"
    if ipv6.startswith(("fc", "fd", "fe80")):
        return "private IPv6 address"

    # IPv6-mapped IPv4 (::ffff:127.0.0.1, ::ffff:10.0.0.1, etc.)
    mapped_match = re.match(r"^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", ipv6, re.IGNORECASE)
    if mapped_match:
        mapped_ip = mapped_match.group(1)
        mapped_reason = _check_private_ip(mapped_ip)
        if mapped_reason:
            return f"IPv6-mapped {mapped_reason}"
        if _RE_LOOPBACK.match(mapped_ip):
            return "IPv6-mapped loopback address"

    return None


_RE_DECIMAL_IP = re.compile(r"^\d+$")
_RE_OCTAL_PART = re.compile(r"^0[0-7]+$")
_RE_HEX_PART = re.compile(r"^0x[0-9a-fA-F]+$", re.IGNORECASE)


def _check_decimal_ip(hostname: str, allow_localhost: bool, allow_private: bool) -> Optional[str]:
    """Parse a decimal integer as IPv4 and check if it's private/loopback."""
    if not _RE_DECIMAL_IP.match(hostname):
        return None

    try:
        num = int(hostname)
    except ValueError:
        return None

    if num < 0 or num > 0xFFFFFFFF:
        return None

    a = (num >> 24) & 0xFF
    b = (num >> 16) & 0xFF
    c = (num >> 8) & 0xFF
    d = num & 0xFF
    dotted = f"{a}.{b}.{c}.{d}"

    if not allow_localhost and a == 127:
        return f"loopback address (decimal IP: {dotted})"

    if not allow_private:
        reason = _check_private_ip(dotted)
        if reason:
            return f"{reason} (decimal IP: {dotted})"

    return None


def _check_octal_ip(hostname: str, allow_localhost: bool, allow_private: bool) -> Optional[str]:
    """Parse octal-notation IPv4 and check if it's private/loopback."""
    parts = hostname.split(".")
    if len(parts) != 4:
        return None

    has_alt = any(_RE_OCTAL_PART.match(p) or _RE_HEX_PART.match(p) for p in parts)
    if not has_alt:
        return None

    octets = []
    for part in parts:
        if _RE_HEX_PART.match(part):
            val = int(part, 16)
        elif _RE_OCTAL_PART.match(part):
            val = int(part, 8)
        elif re.match(r"^\d+$", part):
            val = int(part)
        else:
            return None
        if val < 0 or val > 255:
            return None
        octets.append(val)

    dotted = ".".join(str(o) for o in octets)

    if not allow_localhost and octets[0] == 127:
        return f"loopback address (octal IP: {dotted})"

    if not allow_private:
        reason = _check_private_ip(dotted)
        if reason:
            return f"{reason} (octal IP: {dotted})"

    return None


def validate_url_ssrf(
    url: str,
    options: Optional[ValidateUrlOptions] = None,
) -> ValidateUrlResult:
    """
    Validate a URL for SSRF safety.

    Checks:
    1. Valid URL format
    2. Allowed protocol (default: http, https only)
    3. Not localhost/loopback (127.x.x.x, ::1, localhost)
    4. Not private IP (10.x, 172.16-31.x, 192.168.x)
    5. Not link-local (169.254.x.x — includes cloud metadata endpoints)
    6. Not blocked hostname
    7. No credentials in URL (user:pass@host)

    Args:
        url: The URL string to validate.
        options: Validation options. Uses safe defaults if None.

    Returns:
        ValidateUrlResult with safe flag and optional reason.
    """
    if options is None:
        options = ValidateUrlOptions()

    if not isinstance(url, str) or url.strip() == "":
        return ValidateUrlResult(safe=False, reason="invalid URL: empty or not a string")

    # Parse URL
    try:
        parsed = urlparse(url)
    except Exception:
        return ValidateUrlResult(safe=False, reason="invalid URL: failed to parse")

    # Must have scheme and netloc
    if not parsed.scheme or not parsed.netloc:
        return ValidateUrlResult(safe=False, reason="invalid URL: failed to parse")

    # Check protocol
    if parsed.scheme not in options.allowed_protocols:
        return ValidateUrlResult(
            safe=False,
            reason=f"disallowed protocol: {parsed.scheme}:",
        )

    # Check for credentials
    if parsed.username or parsed.password:
        return ValidateUrlResult(safe=False, reason="URL contains credentials")

    hostname = parsed.hostname or ""
    hostname = hostname.lower()

    # Check explicit allowlist (bypasses IP checks)
    if any(hostname == h.lower() for h in options.allowed_hosts):
        return ValidateUrlResult(safe=True)

    # Check explicit blocklist
    if any(hostname == h.lower() for h in options.blocked_hosts):
        return ValidateUrlResult(safe=False, reason=f"blocked host: {hostname}")

    # Check localhost/loopback
    if not options.allow_localhost:
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return ValidateUrlResult(safe=False, reason="loopback address")
        if hostname.endswith(".localhost"):
            return ValidateUrlResult(safe=False, reason="loopback address")
        if _RE_LOOPBACK.match(hostname):
            return ValidateUrlResult(safe=False, reason="loopback address")

    # Check decimal IP (e.g., 2130706433 = 127.0.0.1)
    if not options.allow_localhost or not options.allow_private:
        decimal_reason = _check_decimal_ip(hostname, options.allow_localhost, options.allow_private)
        if decimal_reason:
            return ValidateUrlResult(safe=False, reason=decimal_reason)

    # Check octal IP (e.g., 0177.0.0.1 = 127.0.0.1)
    if not options.allow_localhost or not options.allow_private:
        octal_reason = _check_octal_ip(hostname, options.allow_localhost, options.allow_private)
        if octal_reason:
            return ValidateUrlResult(safe=False, reason=octal_reason)

    # Check private IPs
    if not options.allow_private:
        private_reason = _check_private_ip(hostname)
        if private_reason:
            return ValidateUrlResult(safe=False, reason=private_reason)

    return ValidateUrlResult(safe=True)


def is_url_safe(
    url: str,
    options: Optional[ValidateUrlOptions] = None,
) -> bool:
    """
    Convenience wrapper that returns True/False.

    Args:
        url: The URL to check.
        options: Validation options.

    Returns:
        True if the URL is safe to fetch.
    """
    return validate_url_ssrf(url, options).safe
