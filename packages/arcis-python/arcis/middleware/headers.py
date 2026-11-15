"""
Arcis Middleware - Security Headers

SecurityHeaders class for adding HTTP security headers to responses.

Two profiles:

- ``legacy`` (the default throughout 1.x): the historical Arcis header set.
- ``baseline``: Helmet 8.3.0 compatible defaults and options plus Arcis
  extensions (CSP nonce, Permissions-Policy, Reporting-Endpoints).

See spec/API_SPEC.md "Security Headers" for the shared contract.
"""

import json
import math
import re
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple, Union
from urllib.parse import urlsplit

from ..core.constants import PATTERNS, HSTS_DEFAULT_MAX_AGE
from .csp import (
    DANGEROUSLY_DISABLE_DEFAULT_SRC,
    NormalizedCsp,
    generate_csp_nonce,
    normalize_csp,
    render_csp,
)

__all__ = [
    "DANGEROUSLY_DISABLE_DEFAULT_SRC",
    "HeaderPlan",
    "SecurityHeaders",
    "build_security_headers",
]


class HeaderPlan(NamedTuple):
    """Security headers for one response."""

    headers: Tuple[Tuple[str, str], ...]
    """Header name/value pairs, in emission order."""
    remove: Tuple[str, ...]
    """Header names to remove from the response."""
    nonce: Optional[str] = None
    """The CSP nonce used in this response, when the nonce extension is on."""


class SecurityHeaders:
    """
    Security headers middleware component.

    Legacy profile (default), unchanged keyword options::

        headers = SecurityHeaders(content_security_policy="default-src 'self'")
        headers.apply(response)

    Baseline profile (Helmet 8 compatible). Every option accepts None or True
    (default), False (off) or a dict (configured)::

        headers = SecurityHeaders(
            profile="baseline",
            content_security_policy={"directives": {"script-src": ["'self'", "cdn.example.com"]}},
            strict_transport_security={"max_age": 63072000, "preload": True},
        )

    Baseline options: ``content_security_policy`` (``use_defaults``,
    ``directives``, ``report_only``, ``nonce``), ``cross_origin_embedder_policy``
    (off unless set), ``cross_origin_opener_policy``,
    ``cross_origin_resource_policy`` (``policy``), ``origin_agent_cluster``,
    ``referrer_policy`` (``policy``: str or list), ``strict_transport_security``
    or ``hsts`` (``max_age``, ``include_sub_domains``, ``preload``),
    ``x_content_type_options`` or ``no_sniff``, ``x_dns_prefetch_control`` or
    ``dns_prefetch_control`` (``allow``), ``x_download_options`` or
    ``ie_no_open``, ``x_frame_options`` or ``frameguard`` (``action``),
    ``x_permitted_cross_domain_policies`` or ``permitted_cross_domain_policies``
    (``permitted_policies``), ``x_powered_by`` or ``hide_powered_by``,
    ``x_xss_protection`` or ``xss_filter``, ``permissions_policy`` (feature to
    allowlist) and ``reporting_endpoints`` (name to https URL). Invalid
    configuration raises ValueError here, at construction.

    Directive names may be kebab-case or camelCase. A directive value of None
    removes a default directive; ``DANGEROUSLY_DISABLE_DEFAULT_SRC`` removes
    ``default-src``. Callable directive entries run once per response and
    receive the adapter's request object.
    """

    DEFAULT_HEADERS = PATTERNS.get("security_headers", {})

    def __init__(self, *args: Any, profile: str = "legacy", **options: Any) -> None:
        self.profile = profile
        self._baseline: Optional[_BaselinePolicy] = None
        if profile == "baseline":
            if args:
                raise TypeError("SecurityHeaders(profile='baseline') takes keyword options only")
            self._baseline = _BaselinePolicy(**options)
        elif profile == "legacy":
            self._init_legacy(*args, **options)
        else:
            raise ValueError(f"Security headers received an unknown profile {_show(profile)}")

    def _init_legacy(
        self,
        content_security_policy: Optional[str] = None,
        x_frame_options: str = "DENY",
        x_content_type_options: str = "nosniff",
        xss_filter: bool = True,
        hsts: bool = True,
        hsts_max_age: int = HSTS_DEFAULT_MAX_AGE,
        hsts_include_subdomains: bool = True,
        referrer_policy: str = "strict-origin-when-cross-origin",
        permissions_policy: str = "geolocation=(), microphone=(), camera=()",
        cache_control: Union[bool, str] = True,
        cross_origin_opener_policy: Union[str, bool] = "same-origin",
        cross_origin_resource_policy: Union[str, bool] = "same-origin",
        cross_origin_embedder_policy: Union[str, bool] = "require-corp",
        origin_agent_cluster: bool = True,
        dns_prefetch_control: bool = True,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        # Resolve every configurable header from the supplied options. Starting
        # with DEFAULT_HEADERS made false or empty options ineffective because
        # the pre-populated value remained in the map.
        self.headers: Dict[str, str] = {}

        if content_security_policy is None:
            default_csp = self.DEFAULT_HEADERS.get("Content-Security-Policy")
            if default_csp:
                self.headers["Content-Security-Policy"] = default_csp
        elif content_security_policy:
            self.headers["Content-Security-Policy"] = content_security_policy

        if x_frame_options:
            self.headers["X-Frame-Options"] = x_frame_options

        if x_content_type_options:
            self.headers["X-Content-Type-Options"] = x_content_type_options

        # X-XSS-Protection: 0 disables the legacy XSS auditor which was itself
        # an attack vector (could be abused to selectively block legitimate scripts)
        if xss_filter:
            self.headers["X-XSS-Protection"] = "0"

        if hsts:
            hsts_value = f"max-age={hsts_max_age}"
            if hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            self.headers["Strict-Transport-Security"] = hsts_value

        if referrer_policy:
            self.headers["Referrer-Policy"] = referrer_policy

        if permissions_policy:
            self.headers["Permissions-Policy"] = permissions_policy

        # Cache-Control headers
        if cache_control:
            cache_control_value = (
                cache_control
                if isinstance(cache_control, str)
                else "no-store, no-cache, must-revalidate, proxy-revalidate"
            )
            self.headers["Cache-Control"] = cache_control_value
            self.headers["Pragma"] = "no-cache"
            self.headers["Expires"] = "0"

        self.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Cross-origin isolation headers (Spectre mitigation)
        if cross_origin_opener_policy:
            value = cross_origin_opener_policy if isinstance(cross_origin_opener_policy, str) else "same-origin"
            self.headers["Cross-Origin-Opener-Policy"] = value

        if cross_origin_resource_policy:
            value = cross_origin_resource_policy if isinstance(cross_origin_resource_policy, str) else "same-origin"
            self.headers["Cross-Origin-Resource-Policy"] = value

        if cross_origin_embedder_policy:
            value = cross_origin_embedder_policy if isinstance(cross_origin_embedder_policy, str) else "require-corp"
            self.headers["Cross-Origin-Embedder-Policy"] = value

        # Request origin-keyed process isolation
        if origin_agent_cluster:
            self.headers["Origin-Agent-Cluster"] = "?1"

        # Prevent DNS prefetching (privacy leak vector)
        if dns_prefetch_control:
            self.headers["X-DNS-Prefetch-Control"] = "off"

        if custom_headers:
            self.headers.update(custom_headers)

    @property
    def uses_nonce(self) -> bool:
        """True when the baseline CSP nonce extension is enabled."""
        return self._baseline is not None and self._baseline.uses_nonce

    def new_nonce(self) -> Optional[str]:
        """Return a fresh CSP nonce when the nonce extension is on, else None.

        Adapters call this at request start, expose the value to the
        application and pass it back to ``apply`` so the header matches.
        """
        return generate_csp_nonce() if self.uses_nonce else None

    def plan(self, request: Any = None, nonce: Optional[str] = None) -> HeaderPlan:
        """Return the headers for one response.

        Args:
            request: Adapter request object, passed to callable CSP values.
            nonce: Nonce from ``new_nonce``. Generated when the nonce
                extension is on and none is given.
        """
        if self._baseline is None:
            return HeaderPlan(tuple(self.headers.items()), ())
        return self._baseline.plan(request, nonce)

    def apply(self, response: Any, request: Any = None, nonce: Optional[str] = None) -> None:
        """Apply security headers to a response object.

        The legacy profile overwrites existing headers. The baseline profile
        keeps a header the route already set (as with Helmet, whose headers
        are set before the handler runs) and removes ``X-Powered-By`` unless
        ``x_powered_by=False``.
        """
        if self._baseline is None:
            for header, value in self.headers.items():
                if hasattr(response, 'headers'):
                    response.headers[header] = value
                elif hasattr(response, '__setitem__'):
                    response[header] = value
            return

        plan = self._baseline.plan(request, nonce)
        target = response.headers if hasattr(response, "headers") else response
        for name, value in plan.headers:
            if name not in target:
                target[name] = value
        for name in plan.remove:
            if name in target:
                del target[name]

    def get_headers(self, request: Any = None, nonce: Optional[str] = None) -> Dict[str, str]:
        """Get all security headers as a dict."""
        if self._baseline is None:
            return dict(self.headers)
        return dict(self._baseline.plan(request, nonce).headers)


HeadersOption = Union[bool, Mapping[str, Any], SecurityHeaders, None]


def build_security_headers(
    headers: HeadersOption = True, csp: Optional[str] = None
) -> Optional[SecurityHeaders]:
    """Resolve an adapter's ``headers`` and ``csp`` arguments.

    Args:
        headers: A ``SecurityHeaders`` instance (used as is), a dict of
            ``SecurityHeaders`` keyword options such as
            ``{"profile": "baseline", "strict_transport_security": {"max_age": 0}}``,
            True for the legacy profile, or False for no security headers.
        csp: Legacy Content-Security-Policy string, used only with
            ``headers=True``.

    Returns:
        The configured component, or None when headers are disabled.
    """
    if isinstance(headers, (SecurityHeaders, Mapping)) and csp is not None:
        raise ValueError(
            "csp is only used with headers=True; set the policy in the headers options instead"
        )
    if isinstance(headers, SecurityHeaders):
        return headers
    if isinstance(headers, Mapping):
        return SecurityHeaders(**headers)
    if headers:
        return SecurityHeaders(content_security_policy=csp)
    return None


# ─── Baseline profile (Helmet 8 compatible + Arcis extensions) ─────────

def _show(value: Any) -> str:
    """Render a configured value for an error message, as Node's JSON.stringify does."""
    return json.dumps(value, default=repr)


def _get(config: Mapping[str, Any], key: str, default: Any) -> Any:
    """Read a nested option where None means omitted."""
    value = config.get(key)
    return default if value is None else value


def _choose(option: str, value: Any, enabled_by_default: bool) -> Tuple[bool, Mapping[str, Any]]:
    """Helmet semantics: None uses the default, True enables, False disables, a dict configures."""
    if value is None:
        return enabled_by_default, {}
    if isinstance(value, bool):
        return value, {}
    if isinstance(value, Mapping):
        return True, value
    raise ValueError(
        f"{option} option must be True, False, None or a dict, not {type(value).__name__}"
    )


def _pick(header: str, value: Any, alias: str, alias_value: Any) -> Any:
    """Read an option that also has a Helmet legacy alias. Setting both is an error."""
    if value is not None and alias_value is not None:
        raise ValueError(
            f"{header} option was specified twice. Remove the `{alias}` option to fix this error."
        )
    return alias_value if value is None else value


def _one_of(header: str, value: Any, allowed: Tuple[str, ...]) -> str:
    if value not in allowed:
        raise ValueError(f"{header} does not support the {_show(value)} policy")
    return str(value)


_REFERRER_TOKENS = frozenset({
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "origin",
    "strict-origin",
    "origin-when-cross-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
    "",
})


def _referrer_policy_value(config: Mapping[str, Any]) -> str:
    policy = _get(config, "policy", ["no-referrer"])
    tokens = [policy] if isinstance(policy, str) else policy
    if not isinstance(tokens, (list, tuple)):
        raise ValueError(f"Referrer-Policy received an unexpected policy token {_show(policy)}")
    if not tokens:
        raise ValueError("Referrer-Policy received no policy tokens")
    seen = set()
    for token in tokens:
        if not isinstance(token, str) or token not in _REFERRER_TOKENS:
            raise ValueError(f"Referrer-Policy received an unexpected policy token {_show(token)}")
        if token in seen:
            raise ValueError(f"Referrer-Policy received a duplicate policy token {_show(token)}")
        seen.add(token)
    return ",".join(tokens)


def _hsts_value(config: Mapping[str, Any]) -> str:
    if "maxage" in config:
        raise ValueError(
            "Strict-Transport-Security received an unsupported property, `maxage`. "
            "Did you mean to pass `max_age`?"
        )
    if "include_subdomains" in config:
        raise ValueError(
            "Strict-Transport-Security should use `include_sub_domains` instead of "
            "`include_subdomains`."
        )
    max_age = _get(config, "max_age", HSTS_DEFAULT_MAX_AGE)
    is_number = isinstance(max_age, (int, float)) and not isinstance(max_age, bool)
    if not (is_number and math.isfinite(max_age) and max_age >= 0):
        raise ValueError(
            f"Strict-Transport-Security: {_show(max_age)} is not a valid value for max_age. "
            "Please choose a positive integer."
        )
    directives = [f"max-age={math.floor(max_age)}"]
    if _get(config, "include_sub_domains", True):
        directives.append("includeSubDomains")
    if config.get("preload"):
        directives.append("preload")
    return "; ".join(directives)


def _frame_options_value(config: Mapping[str, Any]) -> str:
    action = _get(config, "action", "sameorigin")
    normalized = action.upper() if isinstance(action, str) else None
    if normalized == "SAME-ORIGIN":
        return "SAMEORIGIN"
    if normalized in ("DENY", "SAMEORIGIN"):
        return normalized
    raise ValueError(f"X-Frame-Options received an invalid action {_show(action)}")


def _cross_domain_value(config: Mapping[str, Any]) -> str:
    value = _get(config, "permitted_policies", "none")
    if value not in ("none", "master-only", "by-content-type", "all"):
        raise ValueError(f"X-Permitted-Cross-Domain-Policies does not support {_show(value)}")
    return str(value)


# Permissions-Policy is a structured-field dictionary: feature=(allowlist).
_FEATURE_NAME = re.compile(r"[a-z][a-z0-9-]*")
_HOST = re.compile(r"[a-z0-9_.-]+")
_IPV6_HOST = re.compile(r"[0-9a-f:.]+")


def _parse_origin(header: str, value: Any) -> str:
    """Accept only a serialized http(s) origin, exactly as a browser would print it.

    SECURITY: origins are emitted inside a quoted structured-field string, so
    they must be plain origins with no quotes, spaces or delimiters.
    """
    error = ValueError(f"{header} received an invalid origin {_show(value)}")
    if not isinstance(value, str):
        raise error
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise error from None
    if parts.scheme not in ("http", "https"):
        raise error
    host = parts.hostname or ""
    if ":" in host and _IPV6_HOST.fullmatch(host):
        host = f"[{host}]"
    elif not _HOST.fullmatch(host):
        raise error
    default_port = 443 if parts.scheme == "https" else 80
    origin = f"{parts.scheme}://{host}"
    if port is not None and port != default_port:
        origin += f":{port}"
    if origin != value:
        raise error
    return origin


def _permissions_policy_value(policy: Any) -> str:
    if not isinstance(policy, Mapping):
        raise ValueError("Permissions-Policy option must be a dict of feature name to allowlist")
    if not policy:
        raise ValueError("Permissions-Policy received no features")
    features = []
    for feature, allowlist in policy.items():
        if not isinstance(feature, str) or not _FEATURE_NAME.fullmatch(feature):
            raise ValueError(f"Permissions-Policy received an invalid feature name {_show(feature)}")
        if not isinstance(allowlist, (list, tuple)):
            raise ValueError(f"Permissions-Policy received an invalid allowlist for {_show(feature)}")
        members = [
            item if item in ("self", "src", "*") else f'"{_parse_origin("Permissions-Policy", item)}"'
            for item in allowlist
        ]
        features.append(f"{feature}=({' '.join(members)})")
    return ", ".join(features)


_ENDPOINT_NAME = re.compile(r"[a-z][a-z0-9_-]*")
_UNSAFE_URL_CHARS = re.compile(r'["\\\s\x00-\x1f\x7f]')


def _reporting_endpoints_value(endpoints: Any) -> str:
    if not isinstance(endpoints, Mapping):
        raise ValueError("Reporting-Endpoints option must be a dict of endpoint name to https URL")
    if not endpoints:
        raise ValueError("Reporting-Endpoints received no endpoints")
    items = []
    for name, url in endpoints.items():
        if not isinstance(name, str) or not _ENDPOINT_NAME.fullmatch(name):
            raise ValueError(f"Reporting-Endpoints received an invalid endpoint name {_show(name)}")
        invalid_url = ValueError(f"Reporting-Endpoints received an invalid URL for {_show(name)}")
        if not isinstance(url, str):
            raise invalid_url
        try:
            parts = urlsplit(url)
        except ValueError:
            raise invalid_url from None
        if not parts.hostname:
            raise invalid_url
        # Browsers only deliver reports to secure endpoints. The URL is emitted
        # inside a quoted string, so quotes, backslashes and whitespace are out.
        if parts.scheme != "https" or not url.isascii() or _UNSAFE_URL_CHARS.search(url):
            raise ValueError(f"Reporting-Endpoints requires an https URL for {_show(name)}")
        items.append(f'{name}="{url}"')
    return ", ".join(items)


_COEP_POLICIES = ("require-corp", "credentialless", "unsafe-none")
_COOP_POLICIES = ("same-origin", "same-origin-allow-popups", "noopener-allow-popups", "unsafe-none")
_CORP_POLICIES = ("same-origin", "same-site", "cross-origin")


class _BaselinePolicy:
    """Baseline options validated once at construction; ``plan`` runs per response."""

    def __init__(
        self,
        *,
        content_security_policy: Any = None,
        cross_origin_embedder_policy: Any = None,
        cross_origin_opener_policy: Any = None,
        cross_origin_resource_policy: Any = None,
        origin_agent_cluster: Any = None,
        referrer_policy: Any = None,
        strict_transport_security: Any = None,
        hsts: Any = None,
        x_content_type_options: Any = None,
        no_sniff: Any = None,
        x_dns_prefetch_control: Any = None,
        dns_prefetch_control: Any = None,
        x_download_options: Any = None,
        ie_no_open: Any = None,
        x_frame_options: Any = None,
        frameguard: Any = None,
        x_permitted_cross_domain_policies: Any = None,
        permitted_cross_domain_policies: Any = None,
        x_powered_by: Any = None,
        hide_powered_by: Any = None,
        x_xss_protection: Any = None,
        xss_filter: Any = None,
        permissions_policy: Any = None,
        reporting_endpoints: Any = None,
        **_unknown: Any,  # unknown option names are ignored, as in Helmet
    ) -> None:
        headers: List[Tuple[str, str]] = []
        self.csp: Optional[NormalizedCsp] = None
        self._csp_index = -1

        enabled, config = _choose("content_security_policy", content_security_policy, True)
        if enabled:
            self.csp = normalize_csp(config)
            self._csp_index = len(headers)
            headers.append((self.csp.header_name, ""))  # rendered per response

        enabled, config = _choose("cross_origin_embedder_policy", cross_origin_embedder_policy, False)
        if enabled:
            policy = _get(config, "policy", "require-corp")
            headers.append((
                "Cross-Origin-Embedder-Policy",
                _one_of("Cross-Origin-Embedder-Policy", policy, _COEP_POLICIES),
            ))

        enabled, config = _choose("cross_origin_opener_policy", cross_origin_opener_policy, True)
        if enabled:
            policy = _get(config, "policy", "same-origin")
            headers.append((
                "Cross-Origin-Opener-Policy",
                _one_of("Cross-Origin-Opener-Policy", policy, _COOP_POLICIES),
            ))

        enabled, config = _choose("cross_origin_resource_policy", cross_origin_resource_policy, True)
        if enabled:
            policy = _get(config, "policy", "same-origin")
            headers.append((
                "Cross-Origin-Resource-Policy",
                _one_of("Cross-Origin-Resource-Policy", policy, _CORP_POLICIES),
            ))

        if _choose("origin_agent_cluster", origin_agent_cluster, True)[0]:
            headers.append(("Origin-Agent-Cluster", "?1"))

        enabled, config = _choose("referrer_policy", referrer_policy, True)
        if enabled:
            headers.append(("Referrer-Policy", _referrer_policy_value(config)))

        # Sent on every response, like Helmet. Browsers ignore HSTS received over
        # plain HTTP (RFC 6797 section 8.1), so no HTTPS detection is needed.
        hsts_option = _pick("Strict-Transport-Security", strict_transport_security, "hsts", hsts)
        enabled, config = _choose("strict_transport_security", hsts_option, True)
        if enabled:
            headers.append(("Strict-Transport-Security", _hsts_value(config)))

        nosniff = _pick("X-Content-Type-Options", x_content_type_options, "no_sniff", no_sniff)
        if _choose("x_content_type_options", nosniff, True)[0]:
            headers.append(("X-Content-Type-Options", "nosniff"))

        dns_option = _pick(
            "X-DNS-Prefetch-Control", x_dns_prefetch_control, "dns_prefetch_control", dns_prefetch_control
        )
        enabled, config = _choose("x_dns_prefetch_control", dns_option, True)
        if enabled:
            headers.append(("X-DNS-Prefetch-Control", "on" if config.get("allow") else "off"))

        download = _pick("X-Download-Options", x_download_options, "ie_no_open", ie_no_open)
        if _choose("x_download_options", download, True)[0]:
            headers.append(("X-Download-Options", "noopen"))

        frame = _pick("X-Frame-Options", x_frame_options, "frameguard", frameguard)
        enabled, config = _choose("x_frame_options", frame, True)
        if enabled:
            headers.append(("X-Frame-Options", _frame_options_value(config)))

        cross_domain = _pick(
            "X-Permitted-Cross-Domain-Policies",
            x_permitted_cross_domain_policies,
            "permitted_cross_domain_policies",
            permitted_cross_domain_policies,
        )
        enabled, config = _choose("x_permitted_cross_domain_policies", cross_domain, True)
        if enabled:
            headers.append(("X-Permitted-Cross-Domain-Policies", _cross_domain_value(config)))

        powered_by = _pick("X-Powered-By", x_powered_by, "hide_powered_by", hide_powered_by)
        removes_powered_by = _choose("x_powered_by", powered_by, True)[0]
        self._remove: Tuple[str, ...] = ("X-Powered-By",) if removes_powered_by else ()

        xss = _pick("X-XSS-Protection", x_xss_protection, "xss_filter", xss_filter)
        if _choose("x_xss_protection", xss, True)[0]:
            # '0' disables the legacy XSS auditor, which was itself an attack vector.
            headers.append(("X-XSS-Protection", "0"))

        if permissions_policy is not None and permissions_policy is not False:
            headers.append(("Permissions-Policy", _permissions_policy_value(permissions_policy)))
        if reporting_endpoints is not None and reporting_endpoints is not False:
            headers.append(("Reporting-Endpoints", _reporting_endpoints_value(reporting_endpoints)))

        self._headers = tuple(headers)

    @property
    def uses_nonce(self) -> bool:
        return self.csp is not None and self.csp.nonce

    def plan(self, request: Any, nonce: Optional[str]) -> HeaderPlan:
        if self.csp is None:
            return HeaderPlan(self._headers, self._remove)
        if not self.csp.nonce:
            nonce = None
        elif nonce is None:
            nonce = generate_csp_nonce()
        headers = list(self._headers)
        headers[self._csp_index] = (self.csp.header_name, render_csp(self.csp, request, nonce))
        return HeaderPlan(tuple(headers), self._remove, nonce)
