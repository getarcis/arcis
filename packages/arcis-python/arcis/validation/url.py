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
import socket
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse, urljoin
from urllib.request import build_opener, HTTPRedirectHandler, Request
from urllib.error import HTTPError, URLError


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

    resolve_and_pin: bool = False
    """When True, resolve hostname via DNS, validate IP, and return pinned URL
    with IP instead of hostname. Prevents DNS TOCTOU attacks.
    WARNING: Adds network latency for DNS resolution. Opt-in only (default: False)."""

    follow_redirects: bool = False
    """When True, perform a HEAD request and follow up to max_redirects to
    detect redirect chains targeting private IPs.
    WARNING: Adds network latency for the HEAD request. Opt-in only (default: False)."""

    max_redirects: int = 5
    """Maximum redirects to follow when follow_redirects=True. Default: 5"""


@dataclass
class ValidateUrlResult:
    """Result of URL validation."""

    safe: bool
    """Whether the URL is safe to fetch."""

    reason: Optional[str] = None
    """Reason the URL was blocked (only set when safe=False)."""

    resolved_ip: Optional[str] = None
    """Resolved IP address from DNS resolution (only when resolve_and_pin=True)."""

    pinned_url: Optional[str] = None
    """URL with hostname replaced by resolved IP (only when resolve_and_pin=True)."""

    redirect_chain: Optional[List[str]] = None
    """List of URLs followed in the redirect chain (only when follow_redirects=True)."""


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


def _resolve_hostname(hostname: str) -> List[str]:
    """Resolve a hostname to IP addresses.

    Returns a list of IP address strings (both IPv4 and IPv6).
    On resolution failure, returns an empty list.

    WARNING: This performs an actual DNS lookup and adds network latency.
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
        ips: List[str] = []
        seen: set = set()
        for family, _type, _proto, _canonname, sockaddr in addrinfo:
            ip = sockaddr[0]
            # Strip IPv6 zone IDs (e.g., fe80::1%eth0 → fe80::1)
            if family == socket.AF_INET6 and "%" in ip:
                ip = ip.split("%")[0]
            if ip not in seen:
                seen.add(ip)
                ips.append(ip)
        return ips
    except (socket.gaierror, OSError):
        return []


def _make_pinned_url(url: str, resolved_ip: str) -> str:
    """Replace the hostname in a URL with a resolved IP address.

    Preserves scheme, port, path, query, and fragment.
    If the hostname was an IPv6 address, wrap the IP in brackets.
    """
    parsed = urlparse(url)
    if ":" in resolved_ip and not resolved_ip.startswith("["):
        ip_for_url = f"[{resolved_ip}]"
    else:
        ip_for_url = resolved_ip

    # Reconstruct the netloc with the IP and original port
    if parsed.port:
        new_netloc = f"{ip_for_url}:{parsed.port}"
    else:
        new_netloc = ip_for_url

    # URL reconstruction: scheme://netloc/path?query#fragment
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{parsed.scheme}://{new_netloc}{path}{query}{fragment}"


def _check_all_dns_ips(
    resolved_ips: List[str],
    options: ValidateUrlOptions,
) -> Optional[str]:
    """Check all resolved IPs against private IP checks.

    Returns a reason string if any IP is unsafe, or None if all are safe.
    """
    for ip in resolved_ips:
        # Check localhost/loopback
        if not options.allow_localhost:
            if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                return "DNS resolved to loopback address"
            if _RE_LOOPBACK.match(ip):
                return "DNS resolved to loopback address"

        # Check private IPs
        if not options.allow_private:
            private_reason = _check_private_ip(ip)
            if private_reason:
                return f"DNS resolved to {private_reason}"

    return None


class _RedirectTracker(HTTPRedirectHandler):
    """HTTPRedirectHandler that tracks redirect URLs without following them."""

    def __init__(self) -> None:
        self.redirect_urls: List[str] = []

    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        """Record the redirect target and return None to prevent following."""
        self.redirect_urls.append(newurl)
        return None


def _follow_redirect_chain(url: str, max_redirects: int = 5) -> List[str]:
    """Perform a HEAD request and follow redirects, returning the redirect chain.

    Returns a list of URLs in the order they were visited. The first element
    is the original URL. Does NOT follow redirects automatically — each redirect
    target is captured manually.

    WARNING: This performs actual network requests and adds latency.
    """
    tracker = _RedirectTracker()
    opener = build_opener(tracker)
    redirect_chain: List[str] = [url]
    current_url = url

    for _ in range(max_redirects):
        try:
            req = Request(current_url, method="HEAD")
            resp = opener.open(req, timeout=10)
            # Check for Location header in the response
            location = resp.headers.get("Location")
            if location:
                resolved = urljoin(current_url, location)
                redirect_chain.append(resolved)
                current_url = resolved
            else:
                break
        except HTTPError as e:
            # Redirect status codes may raise HTTPError; check Location header
            location = e.headers.get("Location")
            if location and e.code in (301, 302, 303, 307, 308):
                resolved = urljoin(current_url, location)
                redirect_chain.append(resolved)
                current_url = resolved
            else:
                break
        except (URLError, ValueError, OSError):
            break

    return redirect_chain


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

    When options.resolve_and_pin=True (opt-in):
    8. Resolve hostname via DNS and validate resolved IP through checks 3-5
    9. Return resolved_ip and pinned_url on success

    When options.follow_redirects=True (opt-in):
    10. After initial validation, perform HEAD request and follow redirects
    11. Validate each redirect target URL through checks 1-7
    12. Track all redirect URLs in redirect_chain

    WARNING: Features 8-12 add network latency (DNS and/or HTTP requests).
    They are OFF by default and must be explicitly enabled.

    Args:
        url: The URL string to validate.
        options: Validation options. Uses safe defaults if None.

    Returns:
        ValidateUrlResult with safe flag, optional reason, and optional
        resolved_ip/pinned_url/redirect_chain.
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
        result = ValidateUrlResult(safe=True)
        return _apply_dns_and_redirects(url, result, options, parsed)

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

    # Base result: safe
    result = ValidateUrlResult(safe=True)

    # Apply opt-in DNS resolution + IP pinning
    if options.resolve_and_pin:
        resolved_ips = _resolve_hostname(hostname)
        if not resolved_ips:
            return ValidateUrlResult(
                safe=False,
                reason="DNS resolution failed for hostname",
            )

        ip_check_reason = _check_all_dns_ips(resolved_ips, options)
        if ip_check_reason:
            return ValidateUrlResult(
                safe=False,
                reason=ip_check_reason,
                resolved_ip=resolved_ips[0],
            )

        # Use the first resolved IP for pinning
        result.resolved_ip = resolved_ips[0]
        result.pinned_url = _make_pinned_url(url, resolved_ips[0])

    # Apply opt-in redirect following
    if options.follow_redirects:
        target_url = result.pinned_url if result.pinned_url else url
        redirect_chain = _follow_redirect_chain(target_url, options.max_redirects)
        result.redirect_chain = redirect_chain

        # Validate each redirect destination (skip the original URL)
        for redirect_url in redirect_chain[1:]:
            # Use a copy of options without resolve_and_pin/follow_redirects
            # to avoid infinite recursion and extra network calls
            redirect_opts = ValidateUrlOptions(
                allowed_protocols=options.allowed_protocols,
                blocked_hosts=options.blocked_hosts,
                allowed_hosts=options.allowed_hosts,
                allow_localhost=options.allow_localhost,
                allow_private=options.allow_private,
            )
            redirect_result = validate_url_ssrf(redirect_url, redirect_opts)
            if not redirect_result.safe:
                result.safe = False
                result.reason = f"redirect target unsafe: {redirect_result.reason}"
                break

    return result


def _apply_dns_and_redirects(
    url: str,
    result: ValidateUrlResult,
    options: ValidateUrlOptions,
    parsed: object = None,
) -> ValidateUrlResult:
    """Apply DNS resolution and/or redirect following to an already-safe result.

    This is extracted so that the allowlist bypass path can also opt into
    resolve_and_pin and follow_redirects behavior.
    """
    if options.resolve_and_pin or options.follow_redirects:
        return validate_url_ssrf(
            url,
            ValidateUrlOptions(
                allowed_protocols=options.allowed_protocols,
                blocked_hosts=options.blocked_hosts,
                allowed_hosts=options.allowed_hosts,
                allow_localhost=options.allow_localhost,
                allow_private=options.allow_private,
                resolve_and_pin=options.resolve_and_pin,
                follow_redirects=options.follow_redirects,
                max_redirects=options.max_redirects,
            ),
        )
    return result


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
