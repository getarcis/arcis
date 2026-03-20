"""
SSTI (Server-Side Template Injection) sanitizer tests.
Tests for arcis/sanitizers/ssti.py
"""

import pytest
from arcis.sanitizers.ssti import detect_ssti, sanitize_ssti


class TestDetectSsti:
    """Tests for detect_ssti()."""

    # --- Jinja2 / Twig / Nunjucks ---

    def test_detect_jinja2_expression(self):
        assert detect_ssti("{{7*7}}") is True

    def test_detect_jinja2_with_spaces(self):
        assert detect_ssti("{{ 7 * 7 }}") is True

    def test_detect_config_items(self):
        assert detect_ssti("{{config.items()}}") is True

    def test_detect_config_secret_key(self):
        assert detect_ssti('{{config["SECRET_KEY"]}}') is True

    def test_detect_python_sandbox_escape(self):
        assert detect_ssti("{{''.__class__.__mro__[1].__subclasses__()}}") is True

    def test_detect_jinja2_self(self):
        assert detect_ssti("{{self._TemplateReference__context}}") is True

    def test_detect_jinja2_request(self):
        assert detect_ssti("{{request.application.__self__}}") is True

    def test_detect_lipsum_abuse(self):
        assert detect_ssti("{{lipsum.__globals__}}") is True

    def test_detect_cycler_abuse(self):
        assert detect_ssti("{{cycler.__init__.__globals__}}") is True

    # --- Freemarker / Thymeleaf / Spring EL ---

    def test_detect_freemarker(self):
        assert detect_ssti("${7*7}") is True

    def test_detect_spring_el_runtime(self):
        assert detect_ssti('${T(java.lang.Runtime).getRuntime().exec("id")}') is True

    def test_detect_spring_context(self):
        assert detect_ssti("${applicationContext}") is True

    # --- ERB / EJS ---

    def test_detect_erb(self):
        assert detect_ssti("<%= 7*7 %>") is True

    def test_detect_ejs_system(self):
        assert detect_ssti('<% system("id") %>') is True

    def test_detect_ejs_include(self):
        assert detect_ssti('<%- include("file") %>') is True

    # --- Pug / Jade ---

    def test_detect_pug(self):
        assert detect_ssti("#{7*7}") is True

    def test_detect_pug_rce(self):
        payload = '#{root.process.mainModule.require("child_process").execSync("id")}'
        assert detect_ssti(payload) is True

    # --- Python dunder chains ---

    def test_detect_class(self):
        assert detect_ssti("__class__") is True

    def test_detect_mro(self):
        assert detect_ssti("__mro__") is True

    def test_detect_subclasses(self):
        assert detect_ssti("__subclasses__") is True

    def test_detect_globals(self):
        assert detect_ssti("__globals__") is True

    def test_detect_builtins(self):
        assert detect_ssti("__builtins__") is True

    def test_detect_import(self):
        assert detect_ssti("__import__") is True

    def test_detect_dunder_case_insensitive(self):
        assert detect_ssti("__CLASS__") is True
        assert detect_ssti("__Globals__") is True

    # --- Safe inputs (no false positives) ---

    def test_safe_plain_text(self):
        assert detect_ssti("hello world") is False

    def test_safe_json(self):
        assert detect_ssti('{"key": "value"}') is False

    def test_safe_single_braces(self):
        assert detect_ssti("{name}") is False

    def test_safe_css(self):
        assert detect_ssti(".class { color: red; }") is False

    def test_safe_init_dunder(self):
        assert detect_ssti("__init__") is False

    def test_safe_name_dunder(self):
        assert detect_ssti("__name__") is False

    def test_non_string_input(self):
        assert detect_ssti(123) is False
        assert detect_ssti(None) is False


class TestSanitizeSsti:
    """Tests for sanitize_ssti()."""

    def test_remove_jinja2(self):
        assert sanitize_ssti("result: {{7*7}}") == "result: "

    def test_remove_freemarker(self):
        assert sanitize_ssti("result: ${7*7}") == "result: "

    def test_remove_erb(self):
        assert sanitize_ssti("result: <%= 7*7 %>") == "result: "

    def test_remove_pug(self):
        assert sanitize_ssti("result: #{7*7}") == "result: "

    def test_remove_dunder_chain(self):
        assert sanitize_ssti("foo.__class__.bar") == "foo..bar"

    def test_remove_multiple_expressions(self):
        assert sanitize_ssti("{{a}}+{{b}}") == "+"

    def test_remove_complex_jinja2(self):
        payload = "{{''.__class__.__mro__[1].__subclasses__()}}"
        assert sanitize_ssti(payload) == ""

    def test_preserve_plain_text(self):
        assert sanitize_ssti("hello world") == "hello world"

    def test_preserve_json(self):
        assert sanitize_ssti('{"key": "value"}') == '{"key": "value"}'

    def test_empty_string(self):
        assert sanitize_ssti("") == ""

    def test_non_string_raises(self):
        with pytest.raises(TypeError):
            sanitize_ssti(42)
