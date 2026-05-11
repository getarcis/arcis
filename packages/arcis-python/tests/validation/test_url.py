"""
SSRF Prevention — URL Validation Tests
Tests for arcis/validation/url.py
"""

import socket
from unittest.mock import Mock, patch, call

import pytest

from arcis.validation.url import (
    validate_url_ssrf,
    is_url_safe,
    ValidateUrlOptions,
    ValidateUrlResult,
    _resolve_hostname,
    _make_pinned_url,
    _check_all_dns_ips,
    _follow_redirect_chain,
)


class TestValidateUrlSafe:
    """Test that safe URLs pass validation."""

    def test_allows_https_url(self):
        result = validate_url_ssrf("https://api.example.com/data")
        assert result.safe is True

    def test_allows_http_url(self):
        result = validate_url_ssrf("http://example.com/path")
        assert result.safe is True

    def test_allows_url_with_port(self):
        result = validate_url_ssrf("https://api.example.com:8443/data")
        assert result.safe is True

    def test_allows_url_with_query_params(self):
        result = validate_url_ssrf("https://api.example.com/search?q=test&page=1")
        assert result.safe is True

    def test_allows_url_with_fragment(self):
        result = validate_url_ssrf("https://example.com/page#section")
        assert result.safe is True

    def test_allows_public_ip(self):
        result = validate_url_ssrf("http://8.8.8.8/api")
        assert result.safe is True


class TestValidateUrlInvalid:
    """Test that invalid URLs are rejected."""

    def test_rejects_empty_string(self):
        result = validate_url_ssrf("")
        assert result.safe is False
        assert "empty" in result.reason

    def test_rejects_non_string(self):
        result = validate_url_ssrf(123)
        assert result.safe is False

    def test_rejects_malformed_url(self):
        result = validate_url_ssrf("not-a-url")
        assert result.safe is False
        assert "failed to parse" in result.reason

    def test_rejects_whitespace_only(self):
        result = validate_url_ssrf("   ")
        assert result.safe is False


class TestValidateUrlProtocols:
    """Test protocol validation."""

    def test_blocks_file_protocol(self):
        result = validate_url_ssrf("file:///etc/passwd")
        assert result.safe is False
        # file:// URLs have no netloc, so they fail parsing before protocol check
        # Either way, they are blocked

    def test_blocks_file_protocol_with_host(self):
        result = validate_url_ssrf("file://localhost/etc/passwd")
        assert result.safe is False
        assert "disallowed protocol" in result.reason

    def test_blocks_ftp_protocol(self):
        result = validate_url_ssrf("ftp://internal.server/data")
        assert result.safe is False
        assert "disallowed protocol" in result.reason

    def test_allows_custom_protocols(self):
        opts = ValidateUrlOptions(allowed_protocols=["http", "https", "ftp"])
        result = validate_url_ssrf("ftp://files.example.com/data", opts)
        assert result.safe is True


class TestValidateUrlLoopback:
    """Test localhost/loopback blocking."""

    def test_blocks_localhost(self):
        result = validate_url_ssrf("http://localhost/admin")
        assert result.safe is False
        assert "loopback" in result.reason

    def test_blocks_127_0_0_1(self):
        result = validate_url_ssrf("http://127.0.0.1/admin")
        assert result.safe is False
        assert "loopback" in result.reason

    def test_blocks_127_x_x_x_range(self):
        result = validate_url_ssrf("http://127.0.0.2/api")
        assert result.safe is False
        assert "loopback" in result.reason

    def test_blocks_127_255_255_255(self):
        result = validate_url_ssrf("http://127.255.255.255/api")
        assert result.safe is False
        assert "loopback" in result.reason

    def test_blocks_ipv6_loopback(self):
        result = validate_url_ssrf("http://[::1]/admin")
        assert result.safe is False

    def test_blocks_0_0_0_0(self):
        result = validate_url_ssrf("http://0.0.0.0/admin")
        assert result.safe is False

    def test_blocks_subdomain_of_localhost(self):
        result = validate_url_ssrf("http://evil.localhost/admin")
        assert result.safe is False
        assert "loopback" in result.reason

    def test_allows_localhost_when_enabled(self):
        opts = ValidateUrlOptions(allow_localhost=True)
        result = validate_url_ssrf("http://localhost:3000/api", opts)
        assert result.safe is True


class TestValidateUrlPrivateIPs:
    """Test private IP range blocking."""

    def test_blocks_10_network(self):
        result = validate_url_ssrf("http://10.0.0.1/internal")
        assert result.safe is False
        assert "10.0.0.0/8" in result.reason

    def test_blocks_10_255_255_255(self):
        result = validate_url_ssrf("http://10.255.255.255/api")
        assert result.safe is False
        assert "10.0.0.0/8" in result.reason

    def test_blocks_172_16_network(self):
        result = validate_url_ssrf("http://172.16.0.1/internal")
        assert result.safe is False
        assert "172.16.0.0/12" in result.reason

    def test_blocks_172_31_network(self):
        result = validate_url_ssrf("http://172.31.255.255/api")
        assert result.safe is False
        assert "172.16.0.0/12" in result.reason

    def test_allows_172_15(self):
        result = validate_url_ssrf("http://172.15.0.1/api")
        assert result.safe is True

    def test_allows_172_32(self):
        result = validate_url_ssrf("http://172.32.0.1/api")
        assert result.safe is True

    def test_blocks_192_168_network(self):
        result = validate_url_ssrf("http://192.168.1.1/router")
        assert result.safe is False
        assert "192.168.0.0/16" in result.reason

    def test_blocks_192_168_255_255(self):
        result = validate_url_ssrf("http://192.168.255.255/api")
        assert result.safe is False

    def test_allows_private_when_enabled(self):
        opts = ValidateUrlOptions(allow_private=True)
        result = validate_url_ssrf("http://10.0.0.1/api", opts)
        assert result.safe is True


class TestValidateUrlLinkLocal:
    """Test link-local / cloud metadata blocking."""

    def test_blocks_aws_metadata(self):
        result = validate_url_ssrf("http://169.254.169.254/latest/meta-data/")
        assert result.safe is False
        assert "link-local" in result.reason

    def test_blocks_any_169_254(self):
        result = validate_url_ssrf("http://169.254.0.1/")
        assert result.safe is False
        assert "link-local" in result.reason

    def test_blocks_gcp_metadata_hostname(self):
        result = validate_url_ssrf("http://metadata.google.internal/computeMetadata/v1/")
        assert result.safe is False
        assert "cloud metadata" in result.reason

    def test_blocks_current_network(self):
        result = validate_url_ssrf("http://0.1.2.3/api")
        assert result.safe is False
        assert "current network" in result.reason


class TestValidateUrlIPv6Private:
    """Test IPv6 private range blocking."""

    def test_blocks_fc00(self):
        result = validate_url_ssrf("http://[fc00::1]/api")
        assert result.safe is False
        assert "private IPv6" in result.reason

    def test_blocks_fd00(self):
        result = validate_url_ssrf("http://[fd12::1]/api")
        assert result.safe is False
        assert "private IPv6" in result.reason

    def test_blocks_fe80_link_local(self):
        result = validate_url_ssrf("http://[fe80::1]/api")
        assert result.safe is False
        assert "private IPv6" in result.reason


class TestValidateUrlCredentials:
    """Test URL credential blocking."""

    def test_blocks_username(self):
        result = validate_url_ssrf("http://admin@internal.server/")
        assert result.safe is False
        assert "credentials" in result.reason

    def test_blocks_username_and_password(self):
        result = validate_url_ssrf("http://admin:***@internal.server/")
        assert result.safe is False
        assert "credentials" in result.reason


class TestValidateUrlBlockedHosts:
    """Test custom blocked hosts."""

    def test_blocks_custom_host(self):
        opts = ValidateUrlOptions(blocked_hosts=["internal-api.corp.net"])
        result = validate_url_ssrf("https://internal-api.corp.net/data", opts)
        assert result.safe is False
        assert "blocked host" in result.reason

    def test_case_insensitive_blocked(self):
        opts = ValidateUrlOptions(blocked_hosts=["internal-api.corp.net"])
        result = validate_url_ssrf("https://INTERNAL-API.Corp.Net/data", opts)
        assert result.safe is False


class TestValidateUrlAllowedHosts:
    """Test custom allowed hosts."""

    def test_allows_host_on_allowlist(self):
        opts = ValidateUrlOptions(allowed_hosts=["10.0.0.1"])
        result = validate_url_ssrf("http://10.0.0.1/api", opts)
        assert result.safe is True

    def test_case_insensitive_allowed(self):
        opts = ValidateUrlOptions(allowed_hosts=["internal.service.local"])
        result = validate_url_ssrf("http://INTERNAL.service.local/api", opts)
        assert result.safe is True


class TestValidateUrlDecimalIP:
    """Test decimal IP bypass detection."""

    def test_blocks_loopback_decimal(self):
        # 127.0.0.1 = 2130706433
        result = validate_url_ssrf("http://2130706433/")
        assert result.safe is False
        assert "loopback" in result.reason
        assert "decimal" in result.reason

    def test_blocks_private_10_decimal(self):
        # 10.0.0.1 = 167772161
        result = validate_url_ssrf("http://167772161/")
        assert result.safe is False
        assert "private" in result.reason
        assert "decimal" in result.reason

    def test_blocks_private_192_decimal(self):
        # 192.168.1.1 = 3232235777
        result = validate_url_ssrf("http://3232235777/")
        assert result.safe is False
        assert "private" in result.reason
        assert "decimal" in result.reason

    def test_blocks_link_local_decimal(self):
        # 169.254.169.254 = 2852039166
        result = validate_url_ssrf("http://2852039166/")
        assert result.safe is False
        assert "decimal" in result.reason

    def test_allows_safe_decimal(self):
        # 8.8.8.8 = 134744072
        result = validate_url_ssrf("http://134744072/")
        assert result.safe is True


class TestValidateUrlOctalIP:
    """Test octal IP bypass detection."""

    def test_blocks_loopback_octal(self):
        # 0177.0.0.1 = 127.0.0.1
        result = validate_url_ssrf("http://0177.0.0.1/")
        assert result.safe is False
        assert "loopback" in result.reason
        assert "octal" in result.reason

    def test_blocks_private_10_octal(self):
        # 012.0.0.1 = 10.0.0.1
        result = validate_url_ssrf("http://012.0.0.1/")
        assert result.safe is False
        assert "private" in result.reason
        assert "octal" in result.reason

    def test_blocks_private_192_octal(self):
        # 0300.0250.01.01 = 192.168.1.1
        result = validate_url_ssrf("http://0300.0250.01.01/")
        assert result.safe is False
        assert "private" in result.reason
        assert "octal" in result.reason

    def test_blocks_hex_notation(self):
        # 0x7f.0.0.1 = 127.0.0.1
        result = validate_url_ssrf("http://0x7f.0.0.1/")
        assert result.safe is False
        assert "loopback" in result.reason
        assert "octal" in result.reason


class TestValidateUrlIPv6MappedIPv4:
    """Test IPv6-mapped IPv4 bypass detection."""

    def test_blocks_mapped_loopback(self):
        result = validate_url_ssrf("http://[::ffff:127.0.0.1]/")
        assert result.safe is False
        assert "IPv6-mapped" in result.reason

    def test_blocks_mapped_private(self):
        result = validate_url_ssrf("http://[::ffff:10.0.0.1]/")
        assert result.safe is False
        assert "IPv6-mapped" in result.reason

    def test_blocks_mapped_link_local(self):
        result = validate_url_ssrf("http://[::ffff:169.254.169.254]/")
        assert result.safe is False
        assert "IPv6-mapped" in result.reason


class TestValidateUrlAzureMetadata:
    """Test Azure metadata endpoint blocking."""

    def test_blocks_azure_metadata(self):
        result = validate_url_ssrf("http://metadata.azure.internal/metadata/instance")
        assert result.safe is False
        assert "cloud metadata" in result.reason


class TestIsUrlSafe:
    """Test is_url_safe convenience function."""

    def test_returns_true_for_safe(self):
        assert is_url_safe("https://example.com") is True

    def test_returns_false_for_private(self):
        assert is_url_safe("http://10.0.0.1") is False

    def test_returns_false_for_localhost(self):
        assert is_url_safe("http://localhost") is False

    def test_passes_options(self):
        opts = ValidateUrlOptions(allow_localhost=True)
        assert is_url_safe("http://localhost:3000", opts) is True


# =============================================================================
# SSRF Hardening: DNS TOCTOU Prevention Tests
# =============================================================================


class TestResolveHostname:
    """Test the _resolve_hostname helper function."""

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_resolves_ipv4_address(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        ]
        result = _resolve_hostname("example.com")
        assert result == ["93.184.216.34"]
        mock_getaddrinfo.assert_called_once_with("example.com", None)

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_resolves_ipv6_address(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 80, 0, 0)),
        ]
        result = _resolve_hostname("example.com")
        assert result == ["2606:2800:220:1:248:1893:25c8:1946"]

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_resolves_both_ipv4_and_ipv6(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 80, 0, 0)),
        ]
        result = _resolve_hostname("example.com")
        assert "93.184.216.34" in result
        assert "2606:2800:220:1:248:1893:25c8:1946" in result

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_deduplicates_ips(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ]
        result = _resolve_hostname("example.com")
        assert result == ["93.184.216.34"]

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_strips_ipv6_zone_id(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%eth0", 80, 0, 0)),
        ]
        result = _resolve_hostname("link-local-host")
        assert result == ["fe80::1"]

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_returns_empty_list_on_failure(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        result = _resolve_hostname("nonexistent.example.invalid")
        assert result == []


class TestMakePinnedUrl:
    """Test the _make_pinned_url helper function."""

    def test_replaces_hostname_with_ip(self):
        result = _make_pinned_url("https://example.com/path?q=1#frag", "93.184.216.34")
        assert result == "https://93.184.216.34/path?q=1#frag"

    def test_preserves_port(self):
        result = _make_pinned_url("https://example.com:8443/api", "93.184.216.34")
        assert result == "https://93.184.216.34:8443/api"

    def test_preserves_path_only(self):
        result = _make_pinned_url("http://example.com/health", "1.2.3.4")
        assert result == "http://1.2.3.4/health"

    def test_wraps_ipv6_in_brackets(self):
        result = _make_pinned_url("https://example.com/path", "2606:2800:220:1:248:1893:25c8:1946")
        assert result == "https://[2606:2800:220:1:248:1893:25c8:1946]/path"

    def test_handles_ipv6_with_port(self):
        result = _make_pinned_url("https://example.com:443/path", "::1")
        # "::1" contains ":" so it should be wrapped in brackets
        assert "[::1]" in result
        assert result == "https://[::1]:443/path"

    def test_does_not_double_wrap(self):
        result = _make_pinned_url("http://[::1]/path", "::1")
        assert result == "http://[::1]/path"


class TestCheckAllDnsIps:
    """Test the _check_all_dns_ips helper function."""

    def test_public_ip_returns_none(self):
        opts = ValidateUrlOptions()
        result = _check_all_dns_ips(["93.184.216.34"], opts)
        assert result is None

    def test_public_ipv6_returns_none(self):
        opts = ValidateUrlOptions()
        result = _check_all_dns_ips(["2606:2800:220:1:248:1893:25c8:1946"], opts)
        assert result is None

    def test_private_ip_blocked(self):
        opts = ValidateUrlOptions()
        result = _check_all_dns_ips(["10.0.0.1"], opts)
        assert result is not None
        assert "private" in result.lower()

    def test_loopback_blocked(self):
        opts = ValidateUrlOptions()
        result = _check_all_dns_ips(["127.0.0.1"], opts)
        assert result is not None
        assert "loopback" in result.lower() or "private" in result.lower()

    def test_link_local_blocked(self):
        opts = ValidateUrlOptions()
        result = _check_all_dns_ips(["169.254.169.254"], opts)
        assert result is not None

    def test_private_ip_allowed_when_allow_private(self):
        opts = ValidateUrlOptions(allow_private=True)
        result = _check_all_dns_ips(["10.0.0.1"], opts)
        assert result is None

    def test_loopback_allowed_when_allow_localhost(self):
        opts = ValidateUrlOptions(allow_localhost=True)
        result = _check_all_dns_ips(["127.0.0.1"], opts)
        assert result is None

    def test_first_unsafe_ip_detected(self):
        """If there are multiple IPs and one is private, it should be detected."""
        opts = ValidateUrlOptions()
        result = _check_all_dns_ips(["93.184.216.34", "10.0.0.1", "8.8.8.8"], opts)
        assert result is not None
        assert "private" in result.lower()


class TestValidateUrlResolveAndPin:
    """Test the resolve_and_pin feature for DNS TOCTOU prevention."""

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_resolves_and_pins_public_domain(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        ]
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://example.com/path?q=1", opts)
        assert result.safe is True
        assert result.resolved_ip == "93.184.216.34"
        assert result.pinned_url == "https://93.184.216.34/path?q=1"

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_blocks_domain_pointing_to_private_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
        ]
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://internal.service/api", opts)
        assert result.safe is False
        assert "private" in result.reason.lower()
        assert result.resolved_ip == "10.0.0.1"

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_blocks_domain_pointing_to_loopback(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
        ]
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://evil.example.com/admin", opts)
        assert result.safe is False
        assert result.resolved_ip == "127.0.0.1"

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_blocks_domain_pointing_to_link_local(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80)),
        ]
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://metadata-endpoint/latest", opts)
        assert result.safe is False
        assert result.resolved_ip == "169.254.169.254"

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_blocks_domain_when_dns_fails(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("Name or service not known")
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://nonexistent.example.invalid/", opts)
        assert result.safe is False
        assert "DNS resolution failed" in result.reason

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_resolves_ipv6_address(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 80, 0, 0)),
        ]
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://ipv6.example.com/path", opts)
        assert result.safe is True
        assert result.resolved_ip == "2606:2800:220:1:248:1893:25c8:1946"
        assert "2606:2800:220:1:248:1893:25c8:1946" in result.pinned_url

    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_resolves_and_pins_with_port(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        ]
        opts = ValidateUrlOptions(resolve_and_pin=True)
        result = validate_url_ssrf("https://example.com:8443/api", opts)
        assert result.safe is True
        assert result.pinned_url == "https://93.184.216.34:8443/api"

    def test_opt_in_default_false(self):
        """resolve_and_pin must be opt-in (default False)."""
        opts = ValidateUrlOptions()
        assert opts.resolve_and_pin is False

    def test_does_not_resolve_when_disabled(self):
        """When resolve_and_pin=False, no DNS resolution should happen."""
        opts = ValidateUrlOptions(resolve_and_pin=False)
        result = validate_url_ssrf("https://example.com/path", opts)
        assert result.safe is True
        assert result.resolved_ip is None
        assert result.pinned_url is None


class TestFollowRedirectChain:
    """Test the _follow_redirect_chain helper function."""

    @patch("arcis.validation.url.build_opener")
    def test_no_redirect(self, mock_build_opener):
        """A single URL with no redirect should return just that URL."""
        mock_resp = Mock()
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_opener = Mock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        result = _follow_redirect_chain("https://example.com/", 5)
        assert result == ["https://example.com/"]

    @patch("arcis.validation.url.build_opener")
    def test_single_redirect(self, mock_build_opener):
        """A single redirect should return both URLs."""
        mock_resp_redirect = Mock()
        mock_resp_redirect.headers = {"Location": "https://example.com/redirected"}
        mock_resp_final = Mock()
        mock_resp_final.headers = {"Content-Type": "text/html"}

        mock_opener = Mock()
        # First call returns redirect, second call returns final (no more redirects)
        mock_opener.open.side_effect = [mock_resp_redirect, mock_resp_final]
        mock_build_opener.return_value = mock_opener

        result = _follow_redirect_chain("https://example.com/start", 5)
        assert result == [
            "https://example.com/start",
            "https://example.com/redirected",
        ]

    @patch("arcis.validation.url.build_opener")
    def test_multiple_redirects(self, mock_build_opener):
        """Multiple sequential redirects should all be tracked."""
        mock_resp1 = Mock()
        mock_resp1.headers = {"Location": "/step2"}
        mock_resp2 = Mock()
        mock_resp2.headers = {"Location": "https://final.example.com/done"}
        mock_resp3 = Mock()
        mock_resp3.headers = {"Content-Type": "text/html"}

        mock_opener = Mock()
        mock_opener.open.side_effect = [mock_resp1, mock_resp2, mock_resp3]
        mock_build_opener.return_value = mock_opener

        result = _follow_redirect_chain("https://example.com/start", 5)
        assert result == [
            "https://example.com/start",
            "https://example.com/step2",
            "https://final.example.com/done",
        ]

    @patch("arcis.validation.url.build_opener")
    def test_max_redirects_respected(self, mock_build_opener):
        """The max_redirects limit should prevent infinite redirects."""
        mock_resp = Mock()
        mock_resp.headers = {"Location": "https://example.com/loop"}

        mock_opener = Mock()
        mock_opener.open.return_value = mock_resp
        mock_build_opener.return_value = mock_opener

        result = _follow_redirect_chain("https://example.com/start", 3)
        # Should have max_redirects + 1 entries (original URL + 3 redirects)
        assert len(result) == 4
        assert result[0] == "https://example.com/start"
        # All follow-up URLs should be the Location header target
        for url in result[1:]:
            assert url == "https://example.com/loop"

    @patch("arcis.validation.url.build_opener")
    def test_handles_http_error_redirect(self, mock_build_opener):
        """HTTP redirect errors (301, 302, etc.) should still be followed."""
        from urllib.error import HTTPError

        mock_resp_final = Mock()
        mock_resp_final.headers = {"Content-Type": "text/html"}  # No Location = done
        mock_error = HTTPError(
            "https://example.com/old", 301, "Moved Permanently", {}, None,
        )
        mock_error.headers = {"Location": "https://new.example.com/target"}

        mock_opener = Mock()
        # First call raises HTTPError with redirect, second returns final (no redirect)
        mock_opener.open.side_effect = [mock_error, mock_resp_final]
        mock_build_opener.return_value = mock_opener

        result = _follow_redirect_chain("https://example.com/old", 5)
        assert result == [
            "https://example.com/old",
            "https://new.example.com/target",
        ]


class TestValidateUrlFollowRedirects:
    """Test the follow_redirects feature for redirect-to-private-IP detection."""

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_follows_redirects_when_enabled(self, mock_follow):
        """When follow_redirects=True, redirect chain should be tracked."""
        mock_follow.return_value = [
            "https://example.com/start",
            "https://example.com/step2",
            "https://final.example.com/done",
        ]
        opts = ValidateUrlOptions(follow_redirects=True)
        result = validate_url_ssrf("https://example.com/start", opts)
        assert result.safe is True
        assert result.redirect_chain == [
            "https://example.com/start",
            "https://example.com/step2",
            "https://final.example.com/done",
        ]

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_detects_redirect_to_private_ip(self, mock_follow):
        """If a redirect target is a private IP, the URL should be unsafe."""
        mock_follow.return_value = [
            "https://public.example.com/login",
            "https://10.0.0.1/admin",
        ]
        opts = ValidateUrlOptions(follow_redirects=True)
        result = validate_url_ssrf("https://public.example.com/login", opts)
        assert result.safe is False
        assert "redirect target" in result.reason.lower()
        assert result.redirect_chain is not None

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_detects_redirect_to_loopback(self, mock_follow):
        """If a redirect target is loopback, the URL should be unsafe."""
        mock_follow.return_value = [
            "https://public.example.com/redirect",
            "https://127.0.0.1/admin",
        ]
        opts = ValidateUrlOptions(follow_redirects=True)
        result = validate_url_ssrf("https://public.example.com/redirect", opts)
        assert result.safe is False
        assert "redirect target" in result.reason.lower()

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_detects_redirect_to_link_local(self, mock_follow):
        """If a redirect target is link-local, the URL should be unsafe."""
        mock_follow.return_value = [
            "https://public.example.com/redirect",
            "https://169.254.169.254/latest/meta-data/",
        ]
        opts = ValidateUrlOptions(follow_redirects=True)
        result = validate_url_ssrf("https://public.example.com/redirect", opts)
        assert result.safe is False
        assert "redirect target" in result.reason.lower()

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_public_redirect_chain_is_safe(self, mock_follow):
        """A chain of all-public redirect targets should be safe."""
        mock_follow.return_value = [
            "https://bit.ly/short",
            "https://example.com/real",
            "https://cdn.example.com/final",
        ]
        opts = ValidateUrlOptions(follow_redirects=True)
        result = validate_url_ssrf("https://bit.ly/short", opts)
        assert result.safe is True
        assert result.redirect_chain is not None

    def test_opt_in_default_false(self):
        """follow_redirects must be opt-in (default False)."""
        opts = ValidateUrlOptions()
        assert opts.follow_redirects is False

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_does_not_follow_when_disabled(self, mock_follow):
        """When follow_redirects=False, no redirect following should happen."""
        opts = ValidateUrlOptions(follow_redirects=False)
        result = validate_url_ssrf("https://example.com/path", opts)
        assert result.safe is True
        assert result.redirect_chain is None
        mock_follow.assert_not_called()

    @patch("arcis.validation.url._follow_redirect_chain")
    def test_handles_empty_redirect_chain(self, mock_follow):
        """An empty redirect chain (just the original URL) should be safe."""
        mock_follow.return_value = ["https://example.com/"]
        opts = ValidateUrlOptions(follow_redirects=True)
        result = validate_url_ssrf("https://example.com/", opts)
        assert result.safe is True


class TestValidateUrlResolveAndPinWithRedirects:
    """Test interaction between resolve_and_pin and follow_redirects."""

    @patch("arcis.validation.url._follow_redirect_chain")
    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_both_enabled_uses_pinned_url_for_redirects(
        self, mock_getaddrinfo, mock_follow,
    ):
        """When both are enabled, redirects should follow the pinned URL."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        ]
        mock_follow.return_value = [
            "https://93.184.216.34/start",
            "https://93.184.216.34/redirected",
        ]
        opts = ValidateUrlOptions(
            resolve_and_pin=True,
            follow_redirects=True,
        )
        result = validate_url_ssrf("https://example.com/start", opts)
        assert result.safe is True
        assert result.resolved_ip == "93.184.216.34"
        assert result.pinned_url == "https://93.184.216.34/start"
        assert result.redirect_chain is not None
        # Verify redirect chain used the pinned URL
        called_url = mock_follow.call_args[0][0]
        assert "93.184.216.34" in called_url

    @patch("arcis.validation.url._follow_redirect_chain")
    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_both_enabled_dns_fails(self, mock_getaddrinfo, mock_follow):
        """DNS failure should take priority and block before redirects."""
        mock_getaddrinfo.side_effect = socket.gaierror("Unknown host")
        opts = ValidateUrlOptions(
            resolve_and_pin=True,
            follow_redirects=True,
        )
        result = validate_url_ssrf("https://nonexistent.example/", opts)
        assert result.safe is False
        assert "DNS resolution failed" in result.reason
        mock_follow.assert_not_called()

    @patch("arcis.validation.url._follow_redirect_chain")
    @patch("arcis.validation.url.socket.getaddrinfo")
    def test_both_enabled_private_dns_detected_before_redirects(
        self, mock_getaddrinfo, mock_follow,
    ):
        """Private IP detected by DNS should block before any redirect check."""
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
        ]
        opts = ValidateUrlOptions(
            resolve_and_pin=True,
            follow_redirects=True,
        )
        result = validate_url_ssrf("https://internal.example.com/", opts)
        assert result.safe is False
        assert "private" in result.reason.lower()
        mock_follow.assert_not_called()
