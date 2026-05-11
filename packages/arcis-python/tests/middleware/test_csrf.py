"""
CSRF Protection tests.
"""

from arcis.middleware.csrf import (
    generate_csrf_token,
    validate_csrf_token,
    CsrfProtection,
    CsrfCookieOptions,
    create_csrf,
)


class TestGenerateCsrfToken:
    """Test CSRF token generation."""

    def test_generates_hex_string(self):
        token = generate_csrf_token()
        assert all(c in "0123456789abcdef" for c in token)

    def test_default_length_64_chars(self):
        token = generate_csrf_token()
        assert len(token) == 64

    def test_custom_length(self):
        token = generate_csrf_token(16)
        assert len(token) == 32  # 16 bytes = 32 hex chars

    def test_unique_tokens(self):
        tokens = {generate_csrf_token() for _ in range(100)}
        assert len(tokens) == 100


class TestValidateCsrfToken:
    """Test CSRF token validation."""

    def test_matching_tokens(self):
        token = generate_csrf_token()
        assert validate_csrf_token(token, token) is True

    def test_mismatched_tokens(self):
        t1 = generate_csrf_token()
        t2 = generate_csrf_token()
        assert validate_csrf_token(t1, t2) is False

    def test_empty_cookie_token(self):
        assert validate_csrf_token("", "abc") is False

    def test_empty_request_token(self):
        assert validate_csrf_token("abc", "") is False

    def test_none_cookie_token(self):
        assert validate_csrf_token(None, "abc") is False

    def test_none_request_token(self):
        assert validate_csrf_token("abc", None) is False

    def test_constant_time_comparison(self):
        """Verify correctness — both near and far mismatches return False."""
        token = "a" * 64
        near = "a" * 63 + "b"
        far = "b" * 64
        assert validate_csrf_token(token, near) is False
        assert validate_csrf_token(token, far) is False


class TestCsrfProtectionCheck:
    """Test the generic check() method."""

    def setup_method(self):
        self.csrf = CsrfProtection()
        self.token = generate_csrf_token()

    def test_safe_methods_always_pass(self):
        for method in ("GET", "HEAD", "OPTIONS"):
            assert self.csrf.check(method, "/", None, None) is True

    def test_post_with_valid_tokens(self):
        assert self.csrf.check("POST", "/", self.token, self.token) is True

    def test_post_without_cookie_token(self):
        assert self.csrf.check("POST", "/", None, self.token) is False

    def test_post_without_request_token(self):
        assert self.csrf.check("POST", "/", self.token, None) is False

    def test_post_with_mismatched_tokens(self):
        other = generate_csrf_token()
        assert self.csrf.check("POST", "/", self.token, other) is False

    def test_put_protected(self):
        assert self.csrf.check("PUT", "/", None, None) is False

    def test_patch_protected(self):
        assert self.csrf.check("PATCH", "/", None, None) is False

    def test_delete_protected(self):
        assert self.csrf.check("DELETE", "/", None, None) is False

    def test_case_insensitive_method(self):
        assert self.csrf.check("post", "/", None, None) is False
        assert self.csrf.check("get", "/", None, None) is True


class TestCsrfProtectionExcludePaths:
    """Test path exclusion."""

    def setup_method(self):
        self.csrf = CsrfProtection(exclude_paths=["/api/webhooks", "/health"])

    def test_excluded_exact_path(self):
        assert self.csrf.check("POST", "/api/webhooks", None, None) is True

    def test_excluded_sub_path(self):
        assert self.csrf.check("POST", "/api/webhooks/stripe", None, None) is True

    def test_non_excluded_path(self):
        assert self.csrf.check("POST", "/api/users", None, None) is False

    def test_excluded_health(self):
        assert self.csrf.check("POST", "/health", None, None) is True

    def test_partial_match_not_excluded(self):
        # /api/webhooksExtra should NOT be excluded (no / separator)
        assert self.csrf.check("POST", "/api/webhooksExtra", None, None) is False


class TestCsrfProtectionCustomOptions:
    """Test custom configuration."""

    def test_custom_protected_methods(self):
        csrf = CsrfProtection(protected_methods=["POST"])
        token = generate_csrf_token()
        # DELETE should be allowed since only POST is protected
        assert csrf.check("DELETE", "/", None, None) is True
        # POST should still be protected
        assert csrf.check("POST", "/", None, None) is False

    def test_generate_token(self):
        csrf = CsrfProtection(token_length=16)
        token = csrf.generate_token()
        assert len(token) == 32  # 16 bytes = 32 hex chars

    def test_generate_token_default(self):
        csrf = CsrfProtection()
        token = csrf.generate_token()
        assert len(token) == 64


class TestCsrfCookieOptions:
    """Test cookie configuration."""

    def test_default_cookie_options(self):
        opts = CsrfCookieOptions()
        assert opts.path == "/"
        assert opts.http_only is False
        assert opts.secure is None
        assert opts.same_site == "Lax"
        assert opts.domain is None

    def test_custom_cookie_options(self):
        opts = CsrfCookieOptions(
            path="/app",
            http_only=True,
            secure=True,
            same_site="Strict",
            domain="example.com",
        )
        assert opts.path == "/app"
        assert opts.http_only is True
        assert opts.secure is True
        assert opts.same_site == "Strict"
        assert opts.domain == "example.com"


class TestCsrfBuildCookieHeader:
    """Test Set-Cookie header building."""

    def test_default_cookie_header(self):
        csrf = CsrfProtection(cookie=CsrfCookieOptions(secure=False))
        header = csrf._build_cookie_header("test-token")
        assert "_csrf=test-token" in header
        assert "Path=/" in header
        assert "SameSite=Lax" in header
        assert "HttpOnly" not in header

    def test_secure_cookie_header(self):
        csrf = CsrfProtection(cookie=CsrfCookieOptions(secure=True))
        header = csrf._build_cookie_header("test-token")
        assert "Secure" in header

    def test_httponly_cookie_header(self):
        csrf = CsrfProtection(cookie=CsrfCookieOptions(http_only=True, secure=False))
        header = csrf._build_cookie_header("test-token")
        assert "HttpOnly" in header

    def test_domain_cookie_header(self):
        csrf = CsrfProtection(
            cookie=CsrfCookieOptions(domain="example.com", secure=False)
        )
        header = csrf._build_cookie_header("test-token")
        assert "Domain=example.com" in header

    def test_strict_samesite(self):
        csrf = CsrfProtection(
            cookie=CsrfCookieOptions(same_site="Strict", secure=False)
        )
        header = csrf._build_cookie_header("test-token")
        assert "SameSite=Strict" in header


class TestCreateCsrf:
    """Test factory function."""

    def test_returns_csrf_protection(self):
        csrf = create_csrf()
        assert isinstance(csrf, CsrfProtection)

    def test_passes_options(self):
        csrf = create_csrf(
            cookie_name="my-csrf",
            header_name="x-xsrf-token",
            exclude_paths=["/webhooks"],
        )
        assert csrf.cookie_name == "my-csrf"
        assert csrf.header_name == "x-xsrf-token"
        assert csrf.exclude_paths == ["/webhooks"]


class TestSkipCsrf:
    """Test skip_csrf per-request callback."""

    def test_skip_csrf_bypasses_check(self):
        # skip_csrf returns True → POST without tokens should pass
        csrf = CsrfProtection(skip_csrf=lambda: True)
        # check() does not call skip_csrf — it's a flask hook concern.
        # Test that skip_csrf is stored and callable.
        assert csrf.skip_csrf() is True

    def test_skip_csrf_false_still_validates(self):
        csrf = CsrfProtection(skip_csrf=lambda: False)
        token = generate_csrf_token()
        # With skip=False, normal CSRF validation applies
        assert csrf.check("POST", "/", None, None) is False
        assert csrf.check("POST", "/", token, token) is True

    def test_skip_csrf_none_by_default(self):
        csrf = CsrfProtection()
        assert csrf.skip_csrf is None

    def test_create_csrf_passes_skip_csrf(self):
        cb = lambda: True
        csrf = create_csrf(skip_csrf=cb)
        assert csrf.skip_csrf is cb


class TestUseHostPrefix:
    """Test __Host- cookie prefix."""

    def test_host_prefix_applied_to_cookie_name(self):
        csrf = CsrfProtection(use_host_prefix=True)
        assert csrf.cookie_name.startswith("__Host-")

    def test_host_prefix_default_off(self):
        csrf = CsrfProtection()
        assert not csrf.cookie_name.startswith("__Host-")

    def test_host_prefix_prepended_to_custom_name(self):
        csrf = CsrfProtection(cookie_name="xsrf", use_host_prefix=True)
        assert csrf.cookie_name == "__Host-xsrf"

    def test_cookie_header_contains_host_prefix_name(self):
        csrf = CsrfProtection(use_host_prefix=True, cookie=CsrfCookieOptions(secure=False))
        header = csrf._build_cookie_header("tok")
        assert "__Host-_csrf=tok" in header

    def test_create_csrf_passes_use_host_prefix(self):
        csrf = create_csrf(use_host_prefix=True)
        assert csrf.cookie_name.startswith("__Host-")
