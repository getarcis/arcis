"""arcis.html public API: configuration, input types, reuse, and the parser
adjustments that keep JustHTML's trees equal to parse5's."""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

pytest.importorskip("justhtml")

from arcis.html import HtmlSanitizer, sanitize_html, sanitize_html_detailed
from arcis.html import _parse


# ─── Input types ─────────────────────────────────────────────────────────


def test_none_returns_empty_string() -> None:
    assert sanitize_html(None) == ""
    assert sanitize_html_detailed(None) == {"html": "", "removed": []}


@pytest.mark.parametrize("value", [42, b"<b>x</b>", ["<b>"], {"html": "<b>"}, True])
def test_non_string_input_raises_type_error(value: object) -> None:
    with pytest.raises(TypeError):
        sanitize_html(value)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        HtmlSanitizer().sanitize_detailed(value)  # type: ignore[arg-type]


def test_text_without_markup_is_returned_unchanged() -> None:
    # DOMPurify returns input without "<" as is, entities and all.
    assert sanitize_html("a & b > c") == "a & b > c"
    assert sanitize_html("") == ""


def test_detailed_result_lists_removed_elements_and_attributes() -> None:
    result = sanitize_html_detailed('<p onclick="x()">Hi<script>alert(1)</script></p>')
    assert result == {
        "html": "<p>Hi</p>",
        "removed": [{"attribute": "onclick", "from": "p"}, {"element": "script"}],
    }


# ─── Configuration ───────────────────────────────────────────────────────


def test_unknown_option_is_rejected_by_name() -> None:
    with pytest.raises(ValueError, match="allowed_tag"):
        HtmlSanitizer(allowed_tag=["b"])


@pytest.mark.parametrize(
    "key",
    [
        "in_place", "return_dom", "return_dom_fragment", "return_trusted_type",
        "trusted_types_policy", "parser_media_type", "namespace", "allowed_namespaces",
        "custom_element_handling", "html_integration_points", "mathml_text_integration_points",
    ],
)
def test_dom_only_options_are_rejected_by_name(key: str) -> None:
    with pytest.raises(ValueError, match=key):
        HtmlSanitizer(**{key: True})


@pytest.mark.parametrize(
    "options",
    [
        {"allowed_tags": "b"},
        {"allowed_tags": ["b", 1]},
        {"add_attr": {"href": True}},
        {"keep_content": "no"},
        {"safe_for_xml": 0},
        {"allowed_uri_regexp": 5},
        {"allowed_uri_regexp": "("},
        {"use_profiles": ["svg"]},
        {"use_profiles": {"svgfilters": True}},
        {"use_profiles": {"svg": "yes"}},
    ],
)
def test_badly_typed_options_are_rejected(options: dict[str, object]) -> None:
    with pytest.raises(ValueError, match=next(iter(options))):
        HtmlSanitizer(**options)


def test_removing_the_document_element_while_keeping_content_is_rejected() -> None:
    # DOMPurify (jsdom) throws HierarchyRequestError on every input here.
    with pytest.raises(ValueError, match="forbid_tags"):
        HtmlSanitizer(whole_document=True, forbid_tags=["html"])
    HtmlSanitizer(whole_document=True, forbid_tags=["html"], keep_content=False)


def test_options_follow_dompurify() -> None:
    dirty = '<p class="c" data-x="1" aria-label="a">Hi <a href="https://x.example">l</a></p>'
    assert sanitize_html(dirty, allowed_tags=["P"], allowed_attr=["CLASS"]) == (
        '<p class="c" data-x="1" aria-label="a">Hi l</p>'
    )
    assert sanitize_html(dirty, allow_data_attr=False, allow_aria_attr=False) == (
        '<p class="c">Hi <a href="https://x.example">l</a></p>'
    )
    assert sanitize_html('<svg><rect width="1"></rect></svg><b>x</b>', use_profiles={"svg": True}) == (
        '<svg><rect width="1"></rect></svg>x'
    )
    assert sanitize_html("<math><mi>x</mi></math>", use_profiles={"math_ml": True}) == (
        "<math><mi>x</mi></math>"
    )


@pytest.mark.parametrize(
    "pattern", [re.compile(r"^https:", re.IGNORECASE), "(?i)^https:"], ids=["compiled", "string"]
)
def test_allowed_uri_regexp_accepts_compiled_and_string_patterns(pattern: object) -> None:
    dirty = '<a href="HTTPS://a.example">a</a><a href="http://b.example">b</a>'
    assert sanitize_html(dirty, allowed_uri_regexp=pattern) == (
        '<a href="HTTPS://a.example">a</a><a>b</a>'
    )


# ─── Reuse and threads ───────────────────────────────────────────────────


def test_one_sanitizer_serves_many_threads() -> None:
    vectors = Path(__file__).parents[4] / "spec" / "html-sanitizer-vectors.json"
    cases = [
        case
        for case in json.loads(vectors.read_text(encoding="utf-8"))["cases"]
        if not case["config"]
    ]
    sanitizer = HtmlSanitizer()
    work = cases * 4
    with ThreadPoolExecutor(max_workers=8) as pool:
        outputs = list(pool.map(sanitizer.sanitize, [case["input"] for case in work]))
    assert outputs == [case["expected"] for case in work]


def test_configuration_does_not_leak_between_calls() -> None:
    strict = HtmlSanitizer(allowed_tags=["b"])
    assert strict.sanitize("<b>x</b><i>y</i>") == "<b>x</b>y"
    assert sanitize_html("<b>x</b><i>y</i>") == "<b>x</b><i>y</i>"
    assert strict.sanitize("<b>x</b><i>y</i>") == "<b>x</b>y"


# ─── Parser adjustments (JustHTML to parse5) ─────────────────────────────


def test_justhtml_engine_fixes_are_active() -> None:
    # If this fails, JustHTML's internal engine changed and the stock parser
    # is in use; the dompurify-206, -209 and fuzz-173 fixtures fail with it.
    assert _parse._PATCHED_ENGINE


def test_select_content_follows_the_legacy_insertion_mode() -> None:
    # parse5 8.1 ignores tags inside <select> other than option/optgroup/hr.
    assert sanitize_html("<select><b>x</b><option>y<div>z</div></option></select>") == (
        "<select>x<option>yz</option></select>"
    )
    # Tags that close the select in the old rules.
    assert sanitize_html("<select><option>a<input>b") == "<select><option>a</option></select><input>b"
    assert sanitize_html("<select><option>a<select>b") == "<select><option>a</option></select>b"


def test_select_inside_template_and_with_script() -> None:
    assert sanitize_html("<select><template><img src=x onerror=alert(1)></template></select>") == (
        '<select><template><img src="x"></template></select>'
    )
    assert sanitize_html("<select><script>'</select>'</script><b>x</b></select>") == "<select>x</select>"


def test_select_whose_parse_cannot_be_reproduced_is_dropped() -> None:
    # Table markup next to a select that may be foster-parented: removing
    # everything is the strict fallback.
    assert sanitize_html_detailed("<select><td>x</select><table></table>") == {"html": "", "removed": []}


def test_processing_instruction_syntax_parses_as_a_comment() -> None:
    assert sanitize_html("<p>x<?pi  y?>z</p>", add_tags=["#comment"]) == "<p>x<!--?pi  y?-->z</p>"
    # Left open at the end of the input, it still becomes a comment, so the
    # markup-like text next to it gets the <p> removed, as in DOMPurify.
    assert sanitize_html("<p>&lt;x<?abc") == ""


def test_leading_byte_order_mark_and_whitespace_are_kept() -> None:
    assert sanitize_html("\ufeff<p>x</p>") == "\ufeff<p>x</p>"
    assert sanitize_html("\r\n  <p>x</p>") == "\r\n  <p>x</p>"


def test_repeated_body_tags_overwrite_attribute_values() -> None:
    # jsdom copies each repeated <body> tag's attributes onto the element.
    result = sanitize_html_detailed("<body id=x><p>a<body id=location>")
    assert result == {"html": "<p>a</p>", "removed": [{"attribute": "id", "from": "body"}]}
    # A repeated <head> is ignored altogether.
    assert sanitize_html("<head id=h><head title=t><body class=a><body class=b>", whole_document=True) == (
        '<html><head id="h"></head><body class="b"></body></html>'
    )


def test_frameset_document_sanitizes_to_empty() -> None:
    assert sanitize_html("<frameset><frame></frameset>") == ""
