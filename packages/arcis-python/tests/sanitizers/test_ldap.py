"""Tests for LDAP injection prevention."""
import pytest
from arcis.sanitizers.ldap import sanitize_ldap_filter, sanitize_ldap_dn, detect_ldap_injection


class TestSanitizeLdapFilter:
    def test_escapes_wildcard(self):
        assert sanitize_ldap_filter("admin*") == "admin\\2a"

    def test_escapes_open_paren(self):
        assert sanitize_ldap_filter("(admin") == "\\28admin"

    def test_escapes_close_paren(self):
        assert sanitize_ldap_filter("admin)") == "admin\\29"

    def test_escapes_backslash(self):
        assert sanitize_ldap_filter("ad\\min") == "ad\\5cmin"

    def test_escapes_nul_byte(self):
        assert sanitize_ldap_filter("ad\x00min") == "ad\\00min"

    def test_escapes_or_bypass_payload(self):
        payload = "*)(uid=*))(|(uid=*"
        result = sanitize_ldap_filter(payload)
        assert "*" not in result
        assert "(" not in result
        assert ")" not in result

    def test_leaves_safe_input_unchanged(self):
        assert sanitize_ldap_filter("johndoe") == "johndoe"
        assert sanitize_ldap_filter("john.doe@example.com") == "john.doe@example.com"

    def test_empty_string(self):
        assert sanitize_ldap_filter("") == ""

    def test_non_string_input(self):
        assert sanitize_ldap_filter(123) == "123"


class TestSanitizeLdapDn:
    def test_escapes_comma(self):
        assert "\\2c" in sanitize_ldap_dn("cn=admin,dc=example")

    def test_escapes_equals(self):
        assert "\\3d" in sanitize_ldap_dn("cn=admin")

    def test_escapes_plus(self):
        assert "\\2b" in sanitize_ldap_dn("a+b")

    def test_escapes_semicolon(self):
        assert "\\3b" in sanitize_ldap_dn("a;b")

    def test_escapes_angle_brackets(self):
        result = sanitize_ldap_dn("<admin>")
        assert "\\3c" in result
        assert "\\3e" in result

    def test_leaves_safe_input_unchanged(self):
        assert sanitize_ldap_dn("johndoe") == "johndoe"

    def test_empty_string(self):
        assert sanitize_ldap_dn("") == ""


class TestDetectLdapInjection:
    def test_detects_wildcard(self):
        assert detect_ldap_injection("*") is True

    def test_detects_or_bypass(self):
        assert detect_ldap_injection("*)(uid=*))(|(uid=*") is True

    def test_detects_parentheses(self):
        assert detect_ldap_injection("admin)(&(password=*)") is True

    def test_detects_backslash(self):
        assert detect_ldap_injection("ad\\min") is True

    def test_detects_nul_byte(self):
        assert detect_ldap_injection("ad\x00min") is True

    def test_returns_false_for_safe_input(self):
        assert detect_ldap_injection("johndoe") is False
        assert detect_ldap_injection("john.doe@example.com") is False
        assert detect_ldap_injection("John Doe") is False

    def test_returns_false_for_empty_string(self):
        assert detect_ldap_injection("") is False

    def test_returns_false_for_non_string(self):
        assert detect_ldap_injection(123) is False
