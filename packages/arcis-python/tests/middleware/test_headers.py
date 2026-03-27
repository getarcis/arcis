"""
SecurityHeaders tests — extracted from tests/test_core.py.
"""

import pytest
from arcis.core import SecurityHeaders


class TestSecurityHeaders:
    """Test security headers functionality."""

    def test_default_headers_present(self):
        """Default security headers should be set."""
        headers = SecurityHeaders()
        h = headers.get_headers()

        assert "Content-Security-Policy" in h
        assert "X-Content-Type-Options" in h
        assert h["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in h
        assert h["X-Frame-Options"] == "DENY"
        assert "Strict-Transport-Security" in h
        assert "max-age=" in h["Strict-Transport-Security"]

    def test_xss_protection_disabled(self):
        """X-XSS-Protection should be 0 (disable legacy XSS auditor)."""
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert h["X-XSS-Protection"] == "0"

    def test_cross_origin_opener_policy_default(self):
        """Should set Cross-Origin-Opener-Policy to same-origin by default."""
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert h["Cross-Origin-Opener-Policy"] == "same-origin"

    def test_cross_origin_resource_policy_default(self):
        """Should set Cross-Origin-Resource-Policy to same-origin by default."""
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert h["Cross-Origin-Resource-Policy"] == "same-origin"

    def test_cross_origin_embedder_policy_default(self):
        """Should set Cross-Origin-Embedder-Policy to require-corp by default."""
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert h["Cross-Origin-Embedder-Policy"] == "require-corp"

    def test_origin_agent_cluster_default(self):
        """Should set Origin-Agent-Cluster to ?1 by default."""
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert h["Origin-Agent-Cluster"] == "?1"

    def test_dns_prefetch_control_default(self):
        """Should set X-DNS-Prefetch-Control to off by default."""
        headers = SecurityHeaders()
        h = headers.get_headers()
        assert h["X-DNS-Prefetch-Control"] == "off"

    def test_cross_origin_headers_custom_values(self):
        """Should allow custom cross-origin header values."""
        headers = SecurityHeaders(
            cross_origin_opener_policy="same-origin-allow-popups",
            cross_origin_resource_policy="cross-origin",
            cross_origin_embedder_policy="credentialless",
        )
        h = headers.get_headers()
        assert h["Cross-Origin-Opener-Policy"] == "same-origin-allow-popups"
        assert h["Cross-Origin-Resource-Policy"] == "cross-origin"
        assert h["Cross-Origin-Embedder-Policy"] == "credentialless"

    def test_cross_origin_headers_disabled(self):
        """Should allow disabling cross-origin headers."""
        headers = SecurityHeaders(
            cross_origin_opener_policy=False,
            cross_origin_resource_policy=False,
            cross_origin_embedder_policy=False,
            origin_agent_cluster=False,
            dns_prefetch_control=False,
        )
        h = headers.get_headers()
        assert "Cross-Origin-Opener-Policy" not in h
        assert "Cross-Origin-Resource-Policy" not in h
        assert "Cross-Origin-Embedder-Policy" not in h
        assert "Origin-Agent-Cluster" not in h
        assert "X-DNS-Prefetch-Control" not in h

    def test_custom_csp(self):
        """Should allow custom Content-Security-Policy."""
        custom_csp = "default-src 'none'"
        headers = SecurityHeaders(content_security_policy=custom_csp)
        h = headers.get_headers()

        assert h["Content-Security-Policy"] == custom_csp
