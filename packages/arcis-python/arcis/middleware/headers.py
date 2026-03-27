"""
Arcis Middleware - Security Headers

SecurityHeaders class for adding HTTP security headers to responses.
"""

from typing import Dict, Optional, Union

from ..core.constants import PATTERNS, HSTS_DEFAULT_MAX_AGE


class SecurityHeaders:
    """
    Security headers middleware component.

    Example:
        headers = SecurityHeaders(content_security_policy="default-src 'self'")
        headers.apply(response)
    """

    DEFAULT_HEADERS = PATTERNS.get("security_headers", {})

    def __init__(
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
    ):
        self.headers = dict(self.DEFAULT_HEADERS)

        if content_security_policy:
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

    def apply(self, response) -> None:
        """Apply security headers to a response object."""
        for header, value in self.headers.items():
            if hasattr(response, 'headers'):
                response.headers[header] = value
            elif hasattr(response, '__setitem__'):
                response[header] = value

    def get_headers(self) -> Dict[str, str]:
        """Get all security headers as a dict."""
        return dict(self.headers)
