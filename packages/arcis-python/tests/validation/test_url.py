"""
SSRF Prevention — URL Validation Tests
Tests for arcis/validation/url.py
"""

from arcis.validation.url import (
    validate_url_ssrf,
    is_url_safe,
    ValidateUrlOptions,
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
        result = validate_url_ssrf("http://admin:password@internal.server/")
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
