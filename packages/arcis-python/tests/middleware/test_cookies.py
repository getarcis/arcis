"""
Secure cookie defaults tests.
"""

from arcis.middleware.cookies import enforce_secure_cookie, SecureCookieDefaults, create_secure_cookies


class TestEnforceSecureCookie:
    """Test enforce_secure_cookie function."""

    def test_adds_httponly(self):
        result = enforce_secure_cookie("session=abc123")
        assert "; HttpOnly" in result

    def test_no_duplicate_httponly(self):
        result = enforce_secure_cookie("session=abc123; HttpOnly")
        assert result.lower().count("httponly") == 1

    def test_skip_httponly_when_disabled(self):
        result = enforce_secure_cookie("session=abc123", http_only=False)
        assert "HttpOnly" not in result

    def test_adds_secure(self):
        result = enforce_secure_cookie("session=abc123", secure=True)
        assert "; Secure" in result

    def test_no_duplicate_secure(self):
        result = enforce_secure_cookie("session=abc123; Secure", secure=True)
        assert result.lower().count("; secure") == 1

    def test_skip_secure_when_disabled(self):
        result = enforce_secure_cookie("session=abc123", secure=False)
        assert "; Secure" not in result

    def test_adds_samesite_lax_by_default(self):
        result = enforce_secure_cookie("session=abc123")
        assert "; SameSite=Lax" in result

    def test_samesite_strict(self):
        result = enforce_secure_cookie("session=abc123", same_site="Strict")
        assert "; SameSite=Strict" in result

    def test_samesite_none_forces_secure(self):
        result = enforce_secure_cookie("session=abc123", secure=False, same_site="None")
        assert "; SameSite=None" in result
        assert "; Secure" in result

    def test_no_duplicate_samesite(self):
        result = enforce_secure_cookie("session=abc123; SameSite=Strict")
        assert result.lower().count("samesite") == 1

    def test_skip_samesite_when_none_type(self):
        result = enforce_secure_cookie("session=abc123", same_site=None)
        assert "SameSite" not in result

    def test_adds_path(self):
        result = enforce_secure_cookie("session=abc123", path="/")
        assert "; Path=/" in result

    def test_overrides_existing_path(self):
        result = enforce_secure_cookie("session=abc123; Path=/old", path="/new")
        assert "; Path=/new" in result
        assert "/old" not in result

    def test_no_path_by_default(self):
        result = enforce_secure_cookie("session=abc123")
        assert "Path" not in result

    def test_all_defaults(self):
        result = enforce_secure_cookie("session=abc123", secure=True)
        assert "; HttpOnly" in result
        assert "; Secure" in result
        assert "; SameSite=Lax" in result

    def test_already_secure_cookie_unchanged(self):
        cookie = "session=abc123; HttpOnly; Secure; SameSite=Lax"
        result = enforce_secure_cookie(cookie, secure=True)
        assert result == cookie


class TestSecureCookieDefaults:
    """Test SecureCookieDefaults class."""

    def test_enforce_method(self):
        enforcer = SecureCookieDefaults(secure=True)
        result = enforcer.enforce("token=xyz")
        assert "; HttpOnly" in result
        assert "; Secure" in result
        assert "; SameSite=Lax" in result

    def test_strict_samesite(self):
        enforcer = SecureCookieDefaults(same_site="Strict", secure=True)
        result = enforcer.enforce("token=xyz")
        assert "; SameSite=Strict" in result


class TestCreateSecureCookies:
    """Test factory function."""

    def test_returns_instance(self):
        enforcer = create_secure_cookies(secure=True)
        assert isinstance(enforcer, SecureCookieDefaults)

    def test_passes_options(self):
        enforcer = create_secure_cookies(same_site="Strict", http_only=False, secure=True)
        assert enforcer.same_site == "Strict"
        assert enforcer.http_only is False
