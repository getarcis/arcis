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
from typing import Any, List, Optional
from urllib.parse import urlparse

# Matches a string beginning with a URL scheme + "://" (or scheme:/ for
# the file:///path form). Used by scan_for_ssrf to pick out URL-shaped
# string values worth validating. RFC 3986 scheme charset.
_RE_URL_SHAPED = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.IGNORECASE)


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


def _check_hex_ip(hostname: str, allow_localhost: bool, allow_private: bool) -> Optional[str]:
    """Parse a single hex integer as IPv4 (e.g. 0x7f000001 = 127.0.0.1).

    Python's ``urlparse`` does not normalize numeric hosts the way the
    WHATWG URL parser does, so a hex-encoded loopback like
    ``http://0x7f000001/`` arrives here as the literal hostname
    ``0x7f000001`` and would otherwise fall through to "safe".
    """
    if not re.match(r"^0x[0-9a-f]+$", hostname):
        return None
    try:
        num = int(hostname, 16)
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
        return f"loopback address (hex IP: {dotted})"

    if not allow_private:
        reason = _check_private_ip(dotted)
        if reason:
            return f"{reason} (hex IP: {dotted})"

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

    # Check hex IP (e.g., 0x7f000001 = 127.0.0.1)
    if not options.allow_localhost or not options.allow_private:
        hex_reason = _check_hex_ip(hostname, options.allow_localhost, options.allow_private)
        if hex_reason:
            return ValidateUrlResult(safe=False, reason=hex_reason)

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


@dataclass
class SsrfScanResult:
    """Outcome of scanning a request body for SSRF-shaped URL values."""

    detected: bool
    """True if any URL-shaped string value failed validation."""

    url: Optional[str] = None
    """The offending URL string, or None."""

    reason: Optional[str] = None
    """Why it was blocked (from validate_url_ssrf), or None."""


# Body-scan profile (v1.7 W5). The body scan allows http/https/ftp/ftps
# and the localhost hostname (ubiquitous in dev/config payloads) while
# still blocking private/internal IPs, loopback expressed as an IP
# (127.x / decimal / hex), metadata endpoints, and file-read schemes
# (file/gopher/dict). Mirrors the Node SSRF_BODY_SCAN_PROTOCOLS policy.
_SSRF_BODY_SCAN_PROTOCOLS = ["http", "https", "ftp", "ftps"]

# Schemes the body scan evaluates: the fetchable ones plus the classic
# SSRF-amplifying ones (file, gopher, dict, ...). A URL-shaped string with any
# other scheme is a typo or a custom app scheme (lhttps://, myapp://) that no
# server-side fetch would act on, so it is skipped rather than flagged.
_SSRF_RELEVANT_SCHEMES = {
    "http", "https", "ftp", "ftps", "file", "gopher", "dict",
    "ldap", "ldaps", "tftp", "sftp", "ssh", "smb", "jar", "netdoc",
}


def _is_localhost_hostname(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host == "localhost" or host.endswith(".localhost")


def scan_for_ssrf(
    body: Any,
    options: Optional[ValidateUrlOptions] = None,
    max_depth: int = 8,
) -> SsrfScanResult:
    """Recursively walk a parsed body and validate URL-shaped strings.

    Runs ``validate_url_ssrf`` on every string value that looks like a
    URL (``scheme://...``). Returns the first unsafe URL found. Public
    URLs pass, so a body carrying ``{"website": "https://example.com"}``
    is not flagged; only private / loopback-IP / link-local / metadata /
    file-read-scheme URLs trip it. The ``localhost`` hostname and the
    http/https/ftp/ftps schemes are allowed. v1.7 W5 wire-up.

    Args:
        body: Parsed request body (dict, list, or scalar).
        options: Forwarded to ``validate_url_ssrf``. When
            ``allowed_protocols`` is unset, the body-scan profile is used.
        max_depth: Max recursion depth. Default 8.

    Returns:
        ``SsrfScanResult`` with the first offending URL, if any.
    """
    if options is None:
        scan_options = ValidateUrlOptions(allowed_protocols=list(_SSRF_BODY_SCAN_PROTOCOLS))
    else:
        scan_options = options

    def walk(value: Any, depth: int) -> Optional[SsrfScanResult]:
        if depth > max_depth:
            return None
        if isinstance(value, str):
            stripped = value.strip()
            if _RE_URL_SHAPED.match(stripped):
                # Skip schemes a server-side fetch would never act on (typos
                # like lhttps://, custom app schemes). Not an SSRF vector.
                scheme = stripped.split(":", 1)[0].lower()
                if scheme not in _SSRF_RELEVANT_SCHEMES:
                    return None
                # localhost hostname allowed (dev config); loopback IPs not.
                if _is_localhost_hostname(stripped):
                    return None
                result = validate_url_ssrf(stripped, scan_options)
                if not result.safe:
                    return SsrfScanResult(
                        detected=True, url=value, reason=result.reason or "unsafe URL"
                    )
            return None
        if isinstance(value, dict):
            for v in value.values():
                hit = walk(v, depth + 1)
                if hit is not None:
                    return hit
            return None
        if isinstance(value, list):
            for item in value:
                hit = walk(item, depth + 1)
                if hit is not None:
                    return hit
        return None

    return walk(body, 0) or SsrfScanResult(detected=False)


# ── Async SSRF with DNS-rebinding protection ───────────────────────────


async def validate_url_async(
    url: str,
    options: Optional[ValidateUrlOptions] = None,
    *,
    timeout_seconds: float = 2.0,
) -> ValidateUrlResult:
    """Async SSRF check that resolves DNS and validates every returned IP.

    The sync ``validate_url_ssrf`` validates the literal hostname only.
    That's NOT enough against DNS rebinding: an attacker controls
    ``7f000001.rebind.it``, whose first resolve returns a public IP
    (passes the literal-hostname check) and whose second resolve at
    fetch time returns 127.0.0.1. Validating the hostname at request
    time and then fetching at handler time opens a TOCTOU window.

    This function closes the window by resolving the hostname upfront
    and rejecting the URL if ANY returned address is private / loopback
    / link-local / cloud-metadata. Callers should pin the returned IP
    (use ``pinned_dns_lookup`` style adapters in the underlying HTTP
    client) so the actual fetch hits the same address that was
    validated.

    Args:
        url: The URL string to validate.
        options: Standard SSRF options (allowed protocols, allow/block
            hosts, allow_localhost, allow_private).
        timeout_seconds: Cap on DNS resolution wall-clock. Default 2.0
            to keep the request hot path snappy under DNS slowness.

    Returns:
        ``ValidateUrlResult`` with safe + reason. Safe is True only
        when (a) the URL passes the sync check AND (b) every resolved
        IP is also safe.

    Example::

        result = await validate_url_async("http://7f000001.rebind.it/")
        # ValidateUrlResult(safe=False, reason='resolved to loopback ...')

    The implementation prefers ``dns.asyncresolver`` (dnspython) when
    available since it's natively async. Falls back to
    ``asyncio.to_thread(socket.getaddrinfo, ...)`` when dnspython is
    not installed, which keeps the function async-correct (doesn't
    block the loop) at the cost of a thread per call.
    """
    import asyncio

    if options is None:
        options = ValidateUrlOptions()

    # Run the sync literal-hostname check first. If that says no, no
    # point doing DNS work.
    sync_result = validate_url_ssrf(url, options)
    if not sync_result.safe:
        return sync_result

    # Re-parse so we can extract just the hostname for resolution.
    try:
        parsed = urlparse(url)
    except Exception:
        return ValidateUrlResult(safe=False, reason="invalid URL: failed to parse")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return ValidateUrlResult(safe=False, reason="invalid URL: no hostname")

    # Allowlisted host? Skip resolution entirely — the user explicitly
    # opted into trusting this name even if it resolves elsewhere later.
    if any(hostname == h.lower() for h in options.allowed_hosts):
        return ValidateUrlResult(safe=True)

    # If the hostname is already an IP (sync check would have caught
    # private ones), no DNS to do.
    if _is_ip_literal(hostname):
        return ValidateUrlResult(safe=True)

    # Resolve. Try dnspython native-async first, fall back to
    # to_thread(getaddrinfo).
    try:
        ips = await asyncio.wait_for(
            _resolve_async(hostname), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        return ValidateUrlResult(
            safe=False,
            reason=f"DNS resolution timed out after {timeout_seconds}s",
        )
    except Exception as err:
        return ValidateUrlResult(
            safe=False, reason=f"DNS resolution failed: {err}"
        )

    if not ips:
        return ValidateUrlResult(
            safe=False, reason="DNS resolution returned no addresses"
        )

    # Validate each resolved IP. Fail-closed on ANY private hit.
    for ip in ips:
        if not options.allow_localhost:
            if ip in ("127.0.0.1", "::1", "0.0.0.0"):
                return ValidateUrlResult(
                    safe=False, reason=f"resolved to loopback ({ip})"
                )
            if _RE_LOOPBACK.match(ip):
                return ValidateUrlResult(
                    safe=False, reason=f"resolved to loopback ({ip})"
                )
        if not options.allow_private:
            reason = _check_private_ip(ip)
            if reason:
                return ValidateUrlResult(
                    safe=False, reason=f"resolved to {reason} ({ip})"
                )

    return ValidateUrlResult(safe=True)


async def _resolve_async(hostname: str) -> List[str]:
    """Resolve a hostname asynchronously to a list of A/AAAA addresses.

    Tries ``dns.asyncresolver`` first (dnspython, native async). Falls
    back to ``asyncio.to_thread(socket.getaddrinfo)`` when dnspython
    isn't installed.
    """
    import asyncio
    import socket

    # Path 1: dnspython native async resolver.
    try:
        import dns.asyncresolver  # type: ignore[import-not-found]

        ips: List[str] = []
        for record_type in ("A", "AAAA"):
            try:
                answers = await dns.asyncresolver.resolve(hostname, record_type)
                ips.extend(str(rdata) for rdata in answers)
            except Exception:
                # Missing AAAA / NXDOMAIN per-type is fine; we collect
                # whatever the resolver returns and let the empty-result
                # branch in the caller handle "nothing came back".
                continue
        return ips
    except ImportError:
        pass

    # Path 2: stdlib getaddrinfo, offloaded to a thread.
    def _sync_resolve() -> List[str]:
        try:
            infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return []
        ips: List[str] = []
        for family, _type, _proto, _canon, sockaddr in infos:
            if family == socket.AF_INET:
                ips.append(sockaddr[0])
            elif family == socket.AF_INET6:
                # Strip IPv6 zone identifier if present.
                addr = sockaddr[0]
                if "%" in addr:
                    addr = addr.split("%", 1)[0]
                ips.append(addr)
        return ips

    return await asyncio.to_thread(_sync_resolve)


def _is_ip_literal(hostname: str) -> bool:
    """True when ``hostname`` is a literal IPv4 / IPv6 address (no DNS)."""
    import ipaddress

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False
