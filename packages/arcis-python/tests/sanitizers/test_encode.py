"""Tests for context-aware encoding functions."""

from arcis.sanitizers.encode import (
    encode_for_html,
    encode_for_attribute,
    encode_for_js,
    encode_for_url,
    encode_for_css,
)


class TestEncodeForHtml:
    def test_encodes_dangerous_characters(self):
        assert encode_for_html("<script>") == "&lt;script&gt;"
        assert encode_for_html('"quotes"') == "&quot;quotes&quot;"
        assert encode_for_html("it's") == "it&#x27;s"
        assert encode_for_html("a & b") == "a &amp; b"

    def test_full_xss_payload(self):
        assert encode_for_html("<script>alert('xss')</script>") == (
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"
        )

    def test_safe_text_unchanged(self):
        assert encode_for_html("safe text 123") == "safe text 123"

    def test_empty_string(self):
        assert encode_for_html("") == ""

    def test_mixed_content(self):
        assert encode_for_html('"quotes" & <tags>') == (
            "&quot;quotes&quot; &amp; &lt;tags&gt;"
        )


class TestEncodeForAttribute:
    def test_encodes_non_alphanumeric(self):
        result = encode_for_attribute("onclick=alert(1)")
        assert "=" not in result
        assert "(" not in result
        assert ")" not in result
        assert "&#x" in result

    def test_alphanumeric_unchanged(self):
        assert encode_for_attribute("safe") == "safe"
        assert encode_for_attribute("ABC123") == "ABC123"

    def test_empty_string(self):
        assert encode_for_attribute("") == ""

    def test_encodes_spaces(self):
        assert encode_for_attribute("a b") == "a&#x20;b"

    def test_encodes_quotes(self):
        result = encode_for_attribute('"hello"')
        assert '"' not in result
        assert "&#x22;" in result

    def test_encodes_single_quotes(self):
        result = encode_for_attribute("it's")
        assert "'" not in result
        assert "&#x27;" in result


class TestEncodeForJs:
    def test_escapes_non_alphanumeric(self):
        result = encode_for_js("alert('xss')")
        assert "'" not in result
        assert "(" not in result
        assert "\\x" in result

    def test_escapes_script_close(self):
        result = encode_for_js("</script>")
        assert "<" not in result
        assert "/" not in result
        assert ">" not in result

    def test_alphanumeric_unchanged(self):
        assert encode_for_js("safe123") == "safe123"

    def test_empty_string(self):
        assert encode_for_js("") == ""

    def test_unicode_escaped(self):
        result = encode_for_js("hello\u2028world")
        assert "\\u2028" in result

    def test_backslash_escaped(self):
        result = encode_for_js("a\\b")
        assert "\\x5C" in result


class TestEncodeForUrl:
    def test_encodes_spaces_and_specials(self):
        assert encode_for_url("hello world&foo=bar") == "hello%20world%26foo%3Dbar"

    def test_alphanumeric_unchanged(self):
        assert encode_for_url("safe123") == "safe123"

    def test_empty_string(self):
        assert encode_for_url("") == ""

    def test_encodes_slashes_and_hashes(self):
        result = encode_for_url("a/b?c=d#e")
        assert "/" not in result
        assert "?" not in result
        assert "#" not in result


class TestEncodeForCss:
    def test_escapes_non_alphanumeric(self):
        result = encode_for_css("expression(alert(1))")
        assert "(" not in result
        assert ")" not in result
        assert "\\" in result

    def test_alphanumeric_unchanged(self):
        assert encode_for_css("red") == "red"

    def test_empty_string(self):
        assert encode_for_css("") == ""

    def test_trailing_space_per_css_spec(self):
        result = encode_for_css(";")
        # CSS spec: \HH followed by space
        assert result.endswith(" ")
        assert "\\" in result

    def test_prevents_css_injection(self):
        result = encode_for_css("red; background: url(evil)")
        assert ";" not in result
        assert ":" not in result
        assert "(" not in result
