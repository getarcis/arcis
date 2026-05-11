"""
JSONP Callback sanitizer tests.
Tests for arcis/sanitizers/jsonp.py
"""

from arcis.sanitizers.jsonp import sanitize_jsonp_callback, detect_jsonp_injection


class TestSanitizeJsonpCallback:
    """Tests for sanitize_jsonp_callback()."""

    # --- Valid callbacks ---

    def test_simple_name(self):
        assert sanitize_jsonp_callback("callback") == "callback"

    def test_underscore_name(self):
        assert sanitize_jsonp_callback("my_callback") == "my_callback"

    def test_namespaced(self):
        assert sanitize_jsonp_callback("jQuery.ajax.callback") == "jQuery.ajax.callback"

    def test_dollar_prefix(self):
        assert sanitize_jsonp_callback("$callback") == "$callback"

    def test_underscore_prefix(self):
        assert sanitize_jsonp_callback("_cb") == "_cb"

    def test_bracket_notation_rejected(self):
        # M3 audit fix: brackets enable `cb[x` bypass and are never needed in practice
        assert sanitize_jsonp_callback("obj[0]") is None

    def test_jquery_style(self):
        assert sanitize_jsonp_callback("jQuery110209547534") == "jQuery110209547534"

    # --- XSS injection attempts ---

    def test_reject_alert(self):
        assert sanitize_jsonp_callback("alert(1)") is None

    def test_reject_semicolon(self):
        assert sanitize_jsonp_callback("foo;alert(1)//") is None

    def test_reject_angle_brackets(self):
        assert sanitize_jsonp_callback("<script>alert(1)</script>") is None

    def test_reject_parentheses(self):
        assert sanitize_jsonp_callback("eval(name)") is None

    def test_reject_curly_braces(self):
        assert sanitize_jsonp_callback("{alert(1)}") is None

    def test_reject_equals(self):
        assert sanitize_jsonp_callback("x=1") is None

    def test_reject_backtick(self):
        assert sanitize_jsonp_callback("`alert`") is None

    def test_reject_single_quotes(self):
        assert sanitize_jsonp_callback("foo'bar") is None

    def test_reject_double_quotes(self):
        assert sanitize_jsonp_callback('foo"bar') is None

    def test_reject_slash(self):
        assert sanitize_jsonp_callback("foo/bar") is None

    def test_reject_newline(self):
        assert sanitize_jsonp_callback("foo\nbar") is None

    def test_reject_crlf(self):
        assert sanitize_jsonp_callback("foo\r\nbar") is None

    def test_reject_prototype_traversal(self):
        assert sanitize_jsonp_callback("obj..constructor") is None

    # --- Edge cases ---

    def test_reject_empty(self):
        assert sanitize_jsonp_callback("") is None

    def test_reject_non_string(self):
        assert sanitize_jsonp_callback(123) is None
        assert sanitize_jsonp_callback(None) is None

    def test_reject_starts_with_number(self):
        assert sanitize_jsonp_callback("123callback") is None

    def test_reject_exceeds_max_length(self):
        assert sanitize_jsonp_callback("a" * 200) is None

    def test_accept_at_max_length(self):
        assert sanitize_jsonp_callback("a" * 128) == "a" * 128

    def test_custom_max_length(self):
        assert sanitize_jsonp_callback("abcdef", max_length=5) is None
        assert sanitize_jsonp_callback("abcde", max_length=5) == "abcde"


class TestDetectJsonpInjection:
    """Tests for detect_jsonp_injection()."""

    def test_detect_alert(self):
        assert detect_jsonp_injection("alert(1)") is True

    def test_detect_semicolon(self):
        assert detect_jsonp_injection("foo;alert(1)//") is True

    def test_detect_script_tag(self):
        assert detect_jsonp_injection("<script>alert(1)</script>") is True

    def test_detect_prototype_traversal(self):
        assert detect_jsonp_injection("obj..constructor") is True

    def test_safe_callback(self):
        assert detect_jsonp_injection("callback") is False

    def test_safe_namespaced(self):
        assert detect_jsonp_injection("jQuery.ajax.cb") is False

    def test_empty_string(self):
        assert detect_jsonp_injection("") is False

    def test_non_string(self):
        assert detect_jsonp_injection(123) is False
