"""
Arcis Utilities - Client IP resolution

One resolver for every feature that keys on the client address: rate
limiters, correlation windows, fingerprints and the telemetry ``ip`` field.
A client must never be able to choose its own key, so forwarded headers are
read only when the socket peer is a trusted proxy (spec/API_SPEC.md,
"Client IP resolution").

Algorithm:
    1. Build the chain: the socket peer, then the ``X-Forwarded-For`` entries
       from right to left (trimmed, ports stripped).
    2. Walk from the peer. The client is the first address that is not a
       valid IP or not trusted. If every address is trusted, the client is
       the left-most one.
    3. If the selected entry is not a valid IP, use the nearest valid address
       to its right (the trusted proxy that reported it).
    4. Normalize: drop an IPv6 zone, unwrap IPv4-mapped IPv6, lowercase and
       compress IPv6.

Trusted proxies default to loopback, link-local and unique-local ranges
(Express's ``loopback, linklocal, uniquelocal``). An empty list trusts
nothing. The literal ``"unix"`` trusts a peer that has no IP address, such
as a UNIX domain socket between nginx and gunicorn.

Servers that already applied proxy headers:
    The peer is the address the server reports (WSGI ``REMOTE_ADDR``, ASGI
    ``scope["client"]``). Werkzeug's ``ProxyFix`` is detected and its
    ``REMOTE_ADDR`` is used as is. uvicorn's and hypercorn's proxy-header
    support rewrites ``scope["client"]`` without a marker: a public client
    address is then used as is, but a private one would be walked again. If
    you enable proxy headers in the server, either pass
    ``trusted_proxies=[]`` so Arcis takes the server's answer, or turn the
    server option off and list your proxies here. Never run uvicorn with
    ``--forwarded-allow-ips='*'`` on a public port: it lets any client pick
    the address Arcis sees.

Examples:
    >>> resolve_client_ip("10.0.0.2", "203.0.113.7")
    '203.0.113.7'
    >>> resolve_client_ip("203.0.113.5", "198.51.100.7")
    '203.0.113.5'
    >>> ip_key_generator("2001:db8:1234:56ff::9")
    '2001:db8:1234:5600::/56'
"""

import ipaddress
import logging
import re
import threading
from collections.abc import Mapping
from functools import lru_cache
from typing import Any, Iterable, List, Literal, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
TrustedProxies = Optional[Union[str, Iterable[Union[str, IPNetwork]]]]

Platform = Literal[
    'auto', 'cloudflare', 'vercel', 'flyio', 'render',
    'firebase', 'aws-alb', 'generic',
]

DEFAULT_TRUSTED_PROXIES: Tuple[str, ...] = (
    '127.0.0.0/8',
    '::1/128',
    '169.254.0.0/16',
    'fe80::/10',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    'fc00::/7',
)
"""Trust set used when ``trusted_proxies`` is not configured."""

UNIX_SOCKET_PEER = 'unix'
"""``trusted_proxies`` entry that trusts a peer without an IP address."""

UNKNOWN_CLIENT_KEY = 'unknown'
"""Shared key for requests whose client address cannot be determined."""

DEFAULT_IPV6_SUBNET = 56

# Client-IP headers set by a hosting platform. Honored only when chosen
# explicitly through ``detect_client_ip(platform=...)`` and only from a
# trusted peer. 'aws-alb' uses the X-Forwarded-For walk.
_PLATFORM_HEADERS = {
    'cloudflare': 'cf-connecting-ip',
    'vercel': 'x-real-ip',
    'flyio': 'fly-client-ip',
    'render': 'x-render-client-ip',
    'firebase': 'x-appengine-user-ip',
}

_BRACKETED = re.compile(r'^\[([^\]]+)\](?::[0-9]+)?$')
_IPV4_WITH_PORT = re.compile(r'^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):[0-9]+$')

# Private IP patterns (is_private_ip)
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

_warned: set = set()
_warn_lock = threading.Lock()


def _warn_once(code: str, message: str, *args: Any) -> None:
    """Log a configuration warning at most once per process."""
    with _warn_lock:
        if code in _warned:
            return
        _warned.add(code)
    logger.warning(message, *args)


def _reset_warnings() -> None:
    """Forget which one-time warnings were emitted (for tests)."""
    with _warn_lock:
        _warned.clear()


# ─── Trust set ──────────────────────────────────────────────────────────────


class _TrustSet:
    """Compiled ``trusted_proxies``: IPv4 and IPv6 networks plus the unix flag."""

    __slots__ = ('v4', 'v6', 'unix')

    def __init__(
        self,
        v4: Tuple[ipaddress.IPv4Network, ...],
        v6: Tuple[ipaddress.IPv6Network, ...],
        unix: bool,
    ) -> None:
        self.v4 = v4
        self.v6 = v6
        self.unix = unix

    def contains(self, address: IPAddress) -> bool:
        """Return True when ``address`` falls in a trusted network."""
        if address.version == 4:
            if any(address in network for network in self.v4):
                return True
            if not self.v6:
                return False
            # An IPv6 range can list IPv4 hosts in mapped form (::ffff:a.b.c.d).
            address = ipaddress.IPv6Address(0xFFFF00000000 | int(address))
        return any(address in network for network in self.v6)

    def trusts_peer(self, peer: Optional[IPAddress]) -> bool:
        """Trust check for the socket peer, which may have no IP address."""
        return self.unix if peer is None else self.contains(peer)


@lru_cache(maxsize=128)
def _compile_trust(entries: Tuple[Any, ...]) -> _TrustSet:
    v4: List[ipaddress.IPv4Network] = []
    v6: List[ipaddress.IPv6Network] = []
    unix = False
    for entry in entries:
        if isinstance(entry, str) and entry.strip().lower() == UNIX_SOCKET_PEER:
            unix = True
            continue
        try:
            if not isinstance(entry, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
                raise TypeError(type(entry).__name__)
            network = ipaddress.ip_network(
                entry.strip() if isinstance(entry, str) else entry, strict=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"trusted_proxies entry {entry!r} is not an IP address, CIDR range or 'unix'"
            ) from exc
        if isinstance(network, ipaddress.IPv6Network):
            mapped = network.network_address.ipv4_mapped
            if mapped is not None and network.prefixlen >= 96:
                network = ipaddress.IPv4Network((int(mapped), network.prefixlen - 96))
        if network.prefixlen == 0:
            _warn_once(
                'trust-all',
                'arcis: trusted_proxies contains %s, which trusts every address. Any '
                'client can then choose its own IP through X-Forwarded-For. List only '
                'the addresses of your own proxies.',
                network,
            )
        if isinstance(network, ipaddress.IPv4Network):
            v4.append(network)
        else:
            v6.append(network)
    return _TrustSet(tuple(v4), tuple(v6), unix)


def _trust_set(trusted_proxies: TrustedProxies) -> _TrustSet:
    if trusted_proxies is None:
        return _compile_trust(DEFAULT_TRUSTED_PROXIES)
    if isinstance(trusted_proxies, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return _compile_trust((trusted_proxies,))
    return _compile_trust(tuple(trusted_proxies))


def validate_trusted_proxies(trusted_proxies: TrustedProxies) -> None:
    """Raise ``ValueError`` when an entry is not an IP, a CIDR range or ``'unix'``.

    Limiters and adapters call this at construction so a typo fails at
    startup instead of on the first request.
    """
    _trust_set(trusted_proxies)


# ─── Parsing ────────────────────────────────────────────────────────────────


def _parse_ip(value: Any) -> Optional[IPAddress]:
    """Parse and normalize an address: drop an IPv6 zone, unwrap IPv4-mapped."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if ':' in text and '%' in text:
        text = text.split('%', 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _strip_port(value: str) -> str:
    """Strip a port from a forwarded entry: ``1.2.3.4:80``, ``[2001:db8::1]:443``."""
    text = value.strip()
    bracketed = _BRACKETED.match(text)
    if bracketed:
        return bracketed.group(1)
    with_port = _IPV4_WITH_PORT.match(text)
    if with_port:
        return with_port.group(1)
    return text


def _forwarded_hops(forwarded_for: Optional[Union[str, Sequence[str]]]) -> List[str]:
    """X-Forwarded-For entries from right to left, empty entries dropped."""
    if not forwarded_for:
        return []
    if not isinstance(forwarded_for, str):
        forwarded_for = ','.join(forwarded_for)
    hops = [_strip_port(entry) for entry in forwarded_for.split(',')]
    return [hop for hop in reversed(hops) if hop]


def _format(address: Optional[IPAddress]) -> Optional[str]:
    # str() of an IPv6Address is the lowercase compressed form.
    return None if address is None else str(address)


# ─── Resolver ───────────────────────────────────────────────────────────────


def resolve_client_ip(
    peer: Optional[str],
    forwarded_for: Optional[Union[str, Sequence[str]]] = None,
    trusted_proxies: TrustedProxies = None,
) -> Optional[str]:
    """Resolve the client IP from the socket peer and ``X-Forwarded-For``.

    Args:
        peer: The address the server sees (WSGI ``REMOTE_ADDR``, ASGI
            ``scope["client"][0]``), never a header value.
        forwarded_for: The ``X-Forwarded-For`` value, or a list of values
            when the header was sent more than once.
        trusted_proxies: IPs and CIDR ranges of your proxies, plus ``'unix'``
            for a socket peer without an address. None uses
            :data:`DEFAULT_TRUSTED_PROXIES`; an empty list trusts nothing.

    Returns:
        The normalized client IP, or None when no address can be determined.

    Examples:
        >>> resolve_client_ip("127.0.0.1", "198.51.100.7, 10.0.0.3")
        '198.51.100.7'
        >>> resolve_client_ip("203.0.113.5", "1.1.1.1")
        '203.0.113.5'
    """
    trust = _trust_set(trusted_proxies)
    peer_address = _parse_ip(peer)
    hops = _forwarded_hops(forwarded_for)
    peer_trusted = trust.trusts_peer(peer_address)

    if hops and not peer_trusted:
        _warn_once(
            'untrusted-forwarded-for',
            'arcis: X-Forwarded-For was sent by %s, which is not in trusted_proxies, '
            'so the header is ignored and the peer address is used. If this app runs '
            'behind a proxy, add its address to trusted_proxies (or "unix" for a '
            'UNIX socket).',
            peer if peer else 'a peer without an IP address',
        )
    if not peer_trusted or not hops:
        return _format(peer_address)

    last_valid = peer_address
    for index, hop in enumerate(hops):
        address = _parse_ip(hop)
        if address is None:
            # The trusted proxy to the right reported a value that is not an IP.
            return _format(last_valid)
        if index == len(hops) - 1 or not trust.contains(address):
            return _format(address)
        last_valid = address
    return _format(last_valid)


def _from_environ(environ: Mapping) -> Tuple[Optional[str], Optional[str]]:
    peer = environ.get('REMOTE_ADDR')
    if 'werkzeug.proxy_fix.orig' in environ:
        # ProxyFix already resolved REMOTE_ADDR from X-Forwarded-For. Use its
        # answer as the peer and do not walk the header a second time.
        return peer, None
    return peer, environ.get('HTTP_X_FORWARDED_FOR')


def _from_scope(scope: Mapping) -> Tuple[Optional[str], Optional[str]]:
    client = scope.get('client')
    peer = client[0] if isinstance(client, (list, tuple)) and client else None
    values = [
        bytes(value).decode('latin-1')
        for name, value in scope.get('headers') or []
        if bytes(name).lower() == b'x-forwarded-for'
    ]
    return (str(peer) if peer is not None else None), (','.join(values) or None)


def _is_asgi_scope(value: Any) -> bool:
    return isinstance(value, Mapping) and 'type' in value and (
        'client' in value or 'headers' in value
    )


def _peer_and_forwarded_for(request: Any) -> Tuple[Optional[str], Optional[str]]:
    """Read the socket peer and raw X-Forwarded-For from a framework request.

    Supports ASGI scopes and Starlette / Litestar requests (``scope``),
    Django (``META``), Werkzeug / Flask (``environ``), raw WSGI environs, and
    duck-typed objects with ``remote_addr`` or ``client.host``.
    """
    if _is_asgi_scope(request):
        return _from_scope(request)
    if isinstance(request, Mapping):
        if 'REMOTE_ADDR' in request or 'wsgi.version' in request:
            return _from_environ(request)
        peer = request.get('remote_addr') or request.get('ip')
        return (peer if isinstance(peer, str) else None), None

    scope = getattr(request, 'scope', None)
    if _is_asgi_scope(scope):
        return _from_scope(scope)
    meta = getattr(request, 'META', None)
    if isinstance(meta, Mapping):
        return _from_environ(meta)
    environ = getattr(request, 'environ', None)
    if isinstance(environ, Mapping):
        return _from_environ(environ)

    from .request import get_request_header

    forwarded = get_request_header(request, 'x-forwarded-for')
    forwarded = forwarded if isinstance(forwarded, str) else None
    remote_addr = getattr(request, 'remote_addr', None)
    if isinstance(remote_addr, str):
        return remote_addr, forwarded
    client = getattr(request, 'client', None)
    host = getattr(client, 'host', None)
    if host is None and isinstance(client, (list, tuple)) and client:
        host = client[0]
    return (host if isinstance(host, str) else None), forwarded


def client_ip_from_request(request: Any, trusted_proxies: TrustedProxies = None) -> Optional[str]:
    """Resolve the client IP of a framework request with :func:`resolve_client_ip`.

    Args:
        request: An ASGI scope, Starlette / FastAPI / Litestar / Django /
            Flask request, or WSGI environ.
        trusted_proxies: See :func:`resolve_client_ip`.

    Returns:
        The normalized client IP, or None when it cannot be determined.
    """
    peer, forwarded_for = _peer_and_forwarded_for(request)
    return resolve_client_ip(peer, forwarded_for, trusted_proxies)


# ─── Rate-limit key ─────────────────────────────────────────────────────────


def validate_ipv6_subnet(ipv6_subnet: Union[int, bool]) -> Union[int, bool]:
    """Return ``ipv6_subnet`` when it is an int from 1 to 128 or False."""
    if ipv6_subnet is False:
        return False
    if isinstance(ipv6_subnet, bool) or not isinstance(ipv6_subnet, int) or not (
        1 <= ipv6_subnet <= 128
    ):
        raise ValueError(
            f"ipv6_subnet must be an integer from 1 to 128, or False, got {ipv6_subnet!r}"
        )
    return ipv6_subnet


def ip_key_generator(ip: str, ipv6_subnet: Union[int, bool] = DEFAULT_IPV6_SUBNET) -> str:
    """Turn a client IP into a rate-limit key.

    IPv4 (and IPv4-mapped IPv6) is returned as the IPv4 address. IPv6 is
    grouped to its ``/ipv6_subnet`` network, written ``<network>/<prefix>``,
    so one IPv6 allocation cannot mint unlimited keys. With
    ``ipv6_subnet=False`` the address is returned unchanged. A value that is
    not an IP is returned unchanged. Matches express-rate-limit's
    ``ipKeyGenerator``.

    Args:
        ip: The resolved client IP.
        ipv6_subnet: Prefix length from 1 to 128, or False. Default 56.

    Returns:
        The rate-limit key.

    Examples:
        >>> ip_key_generator("::ffff:1.2.3.4")
        '1.2.3.4'
        >>> ip_key_generator("2001:db8:1234:5600::1", 64)
        '2001:db8:1234:5600::/64'
    """
    validate_ipv6_subnet(ipv6_subnet)
    address = _parse_ip(ip)
    if address is None:
        return ip
    if isinstance(address, ipaddress.IPv4Address):
        return str(address)
    if ipv6_subnet is False:
        return ip
    network = ipaddress.IPv6Network((int(address), ipv6_subnet), strict=False)
    return f'{network.network_address}/{ipv6_subnet}'


def rate_limit_key(
    request: Any,
    trusted_proxies: TrustedProxies = None,
    ipv6_subnet: Union[int, bool] = DEFAULT_IPV6_SUBNET,
) -> str:
    """Default rate-limit key: resolved client IP through :func:`ip_key_generator`.

    Returns :data:`UNKNOWN_CLIENT_KEY` when no address can be determined.
    """
    ip = client_ip_from_request(request, trusted_proxies)
    if ip is None:
        return UNKNOWN_CLIENT_KEY
    return ip_key_generator(ip, ipv6_subnet)


# ─── Public helpers ─────────────────────────────────────────────────────────


def _header_value(request: Any, name: str) -> Optional[str]:
    scope = request if _is_asgi_scope(request) else getattr(request, 'scope', None)
    if _is_asgi_scope(scope):
        wanted = name.lower().encode('latin-1')
        for key, value in scope.get('headers') or []:
            if bytes(key).lower() == wanted:
                return bytes(value).decode('latin-1')
        return None
    from .request import get_request_header

    value = get_request_header(request, name)
    return value if isinstance(value, str) else None


def detect_client_ip(
    request: Any,
    platform: Platform = 'auto',
    trusted_proxies: TrustedProxies = None,
) -> str:
    """Detect the real client IP address from a request.

    Runs the trust-aware resolver (:func:`resolve_client_ip`). When
    ``platform`` names a hosting platform, that platform's client-IP header
    (``cf-connecting-ip``, ``x-real-ip``, ``fly-client-ip``,
    ``x-render-client-ip``, ``x-appengine-user-ip``) is used first, but only
    when the socket peer is a trusted proxy. ``'auto'``, ``'generic'`` and
    ``'aws-alb'`` use the X-Forwarded-For walk only.

    Args:
        request: HTTP request object (Flask, Django, FastAPI, Litestar) or
            ASGI scope.
        platform: Hosting platform whose client-IP header to honor.
        trusted_proxies: See :func:`resolve_client_ip`.

    Returns:
        Client IP address, or ``'unknown'`` if unresolvable.

    Examples:
        >>> detect_client_ip(request)
        '203.0.113.50'

        >>> detect_client_ip(request, platform='cloudflare')
        '203.0.113.50'
    """
    peer, forwarded_for = _peer_and_forwarded_for(request)
    header = _PLATFORM_HEADERS.get(platform)
    if header is not None and _trust_set(trusted_proxies).trusts_peer(_parse_ip(peer)):
        value = _header_value(request, header)
        address = _parse_ip(_strip_port(value)) if value else None
        if address is not None:
            return str(address)
    return resolve_client_ip(peer, forwarded_for, trusted_proxies) or UNKNOWN_CLIENT_KEY


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
