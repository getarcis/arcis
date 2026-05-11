"""
Open Redirect Prevention Tests
Tests for arcis/validation/redirect.py
"""

from arcis.validation.redirect import (
    validate_redirect,
    is_redirect_safe,
    ValidateRedirectOptions,
)


class TestValidateRedirectSafeRelative:
    """Test that safe relative paths pass validation."""

    def test_allows_simple_relative_path(self):
        assert validate_redirect("/dashboard").safe is True

    def test_allows_relative_path_with_query(self):
        assert validate_redirect("/users?page=2&sort=name").safe is True

    def test_allows_relative_path_with_fragment(self):
        assert validate_redirect("/page#section").safe is True

    def test_allows_relative_without_leading_slash(self):
        assert validate_redirect("settings/profile").safe is True

    def test_allows_parent_relative_path(self):
        assert validate_redirect("../settings").safe is True

    def test_allows_root_path(self):
        assert validate_redirect("/").safe is True


class TestValidateRedirectAbsoluteNoAllowed:
    """Test absolute URLs without allowed hosts."""

    def test_blocks_absolute_http(self):
        result = validate_redirect("http://evil.com/phishing")
        assert result.safe is False
        assert "absolute URL not in allowed hosts" in result.reason

    def test_blocks_absolute_https(self):
        result = validate_redirect("https://evil.com/phishing")
        assert result.safe is False
        assert "absolute URL not in allowed hosts" in result.reason


class TestValidateRedirectAbsoluteWithAllowed:
    """Test absolute URLs with allowed hosts configured."""

    def test_allows_absolute_to_allowed_host(self):
        opts = ValidateRedirectOptions(allowed_hosts=["myapp.com"])
        result = validate_redirect("https://myapp.com/home", opts)
        assert result.safe is True

    def test_blocks_absolute_to_non_allowed_host(self):
        opts = ValidateRedirectOptions(allowed_hosts=["myapp.com"])
        result = validate_redirect("https://evil.com/home", opts)
        assert result.safe is False
        assert "host not allowed" in result.reason

    def test_case_insensitive_allowed_hosts(self):
        opts = ValidateRedirectOptions(allowed_hosts=["myapp.com"])
        result = validate_redirect("https://MYAPP.COM/home", opts)
        assert result.safe is True

    def test_supports_multiple_allowed_hosts(self):
        opts = ValidateRedirectOptions(
            allowed_hosts=["myapp.com", "cdn.myapp.com", "api.myapp.com"]
        )
        assert validate_redirect("https://cdn.myapp.com/img.png", opts).safe is True
        assert validate_redirect("https://evil.com", opts).safe is False


class TestValidateRedirectProtocolRelative:
    """Test protocol-relative URL handling."""

    def test_blocks_by_default(self):
        result = validate_redirect("//evil.com/path")
        assert result.safe is False
        assert "protocol-relative" in result.reason

    def test_allows_to_allowed_host(self):
        opts = ValidateRedirectOptions(allowed_hosts=["myapp.com"])
        result = validate_redirect("//myapp.com/path", opts)
        assert result.safe is True

    def test_blocks_non_allowed_host_even_when_enabled(self):
        opts = ValidateRedirectOptions(
            allow_protocol_relative=True, allowed_hosts=["myapp.com"]
        )
        result = validate_redirect("//evil.com/path", opts)
        assert result.safe is False

    def test_allows_when_enabled_no_host_restriction(self):
        opts = ValidateRedirectOptions(allow_protocol_relative=True)
        result = validate_redirect("//cdn.example.com/path", opts)
        assert result.safe is True


class TestValidateRedirectDangerousProtocols:
    """Test dangerous protocol blocking."""

    def test_blocks_javascript(self):
        result = validate_redirect("javascript:alert(1)")
        assert result.safe is False
        assert "dangerous protocol" in result.reason
        assert "javascript:" in result.reason

    def test_blocks_javascript_case_insensitive(self):
        result = validate_redirect("JavaScript:alert(1)")
        assert result.safe is False

    def test_blocks_data(self):
        result = validate_redirect("data:text/html,<script>alert(1)</script>")
        assert result.safe is False
        assert "dangerous protocol" in result.reason

    def test_blocks_vbscript(self):
        result = validate_redirect('vbscript:MsgBox("xss")')
        assert result.safe is False

    def test_blocks_blob(self):
        result = validate_redirect("blob:http://example.com/file")
        assert result.safe is False


class TestValidateRedirectBackslash:
    """Test backslash bypass prevention."""

    def test_blocks_backslash_prefix(self):
        result = validate_redirect("\\evil.com")
        assert result.safe is False
        assert "backslash" in result.reason

    def test_blocks_double_backslash(self):
        result = validate_redirect("\\\\evil.com")
        assert result.safe is False


class TestValidateRedirectControlChars:
    """Test control character bypass prevention."""

    def test_strips_tabs_detects_javascript(self):
        result = validate_redirect("java\tscript:alert(1)")
        assert result.safe is False
        assert "dangerous protocol" in result.reason

    def test_strips_newlines_detects_javascript(self):
        result = validate_redirect("java\nscript:alert(1)")
        assert result.safe is False

    def test_strips_carriage_returns_detects_javascript(self):
        result = validate_redirect("java\rscript:alert(1)")
        assert result.safe is False


class TestValidateRedirectEdgeCases:
    """Test edge cases."""

    def test_rejects_empty_string(self):
        result = validate_redirect("")
        assert result.safe is False
        assert "empty" in result.reason

    def test_rejects_whitespace_only(self):
        result = validate_redirect("   ")
        assert result.safe is False

    def test_rejects_non_string(self):
        result = validate_redirect(123)
        assert result.safe is False

    def test_rejects_none(self):
        result = validate_redirect(None)
        assert result.safe is False

    def test_allows_url_encoded_paths(self):
        result = validate_redirect("/path%20with%20spaces")
        assert result.safe is True

    def test_blocks_ftp_by_default(self):
        result = validate_redirect("ftp://files.example.com/data")
        assert result.safe is False
        assert "disallowed protocol" in result.reason


class TestIsRedirectSafe:
    """Test is_redirect_safe convenience function."""

    def test_true_for_relative(self):
        assert is_redirect_safe("/dashboard") is True

    def test_false_for_absolute_no_allowed(self):
        assert is_redirect_safe("https://evil.com") is False

    def test_false_for_javascript(self):
        assert is_redirect_safe("javascript:alert(1)") is False

    def test_passes_options(self):
        opts = ValidateRedirectOptions(allowed_hosts=["myapp.com"])
        assert is_redirect_safe("https://myapp.com/home", opts) is True
