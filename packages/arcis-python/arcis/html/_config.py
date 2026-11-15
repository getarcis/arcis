"""Configuration validation and resolution, ported from DOMPurify's
``_parseConfig``. Keys are DOMPurify's option names in lowercase."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Optional, Union

from ._allowlists import (
    HTML_ATTRS,
    HTML_TAGS,
    MATHML_ATTRS,
    MATHML_TAGS,
    SVG_ATTRS,
    SVG_FILTER_TAGS,
    SVG_TAGS,
    TEXT_TAGS,
    XML_ATTRS,
)

# DOMPurify's default IS_ALLOWED_URI. JavaScript's `$` (without the m flag)
# only matches at the very end, which is `\Z` in Python; re.ASCII keeps
# case-insensitive [a-z] to the 52 ASCII letters, as in JavaScript.
DEFAULT_ALLOWED_URI = re.compile(
    r"^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|\Z))",
    re.IGNORECASE | re.ASCII,
)

_LIST_KEYS = (
    "allowed_tags", "allowed_attr", "add_tags", "add_attr", "forbid_tags", "forbid_attr",
    "forbid_contents", "add_forbid_contents", "add_uri_safe_attr", "add_data_uri_tags",
)
_BOOLEAN_KEYS = (
    "allow_data_attr", "allow_aria_attr", "allow_unknown_protocols", "allow_self_close_in_attr",
    "keep_content", "safe_for_templates", "safe_for_xml", "sanitize_dom", "sanitize_named_props",
    "whole_document", "force_body",
)
_SUPPORTED_KEYS = frozenset(_LIST_KEYS + _BOOLEAN_KEYS + ("allowed_uri_regexp", "use_profiles"))

# DOMPurify options that only apply to browser DOM objects or other parsers.
_REJECTED_KEYS = frozenset(
    {
        "in_place", "return_dom", "return_dom_fragment", "return_trusted_type",
        "trusted_types_policy", "parser_media_type", "namespace", "allowed_namespaces",
        "custom_element_handling", "html_integration_points", "mathml_text_integration_points",
    }
)

# Profile names as DOMPurify spells them, plus snake_case spellings.
_PROFILE_NAMES = {
    "html": "html", "svg": "svg", "svgFilters": "svgFilters", "svg_filters": "svgFilters",
    "mathMl": "mathMl", "math_ml": "mathMl",
}

DEFAULT_FORBID_CONTENTS = frozenset(
    {
        "annotation-xml", "audio", "colgroup", "desc", "foreignobject", "head", "iframe", "math",
        "mi", "mn", "mo", "ms", "mtext", "noembed", "noframes", "noscript", "plaintext", "script",
        "selectedcontent", "style", "svg", "template", "thead", "title", "video", "xmp",
    }
)
DEFAULT_DATA_URI_TAGS = frozenset({"audio", "video", "img", "source", "image", "track"})
DEFAULT_URI_SAFE_ATTRIBUTES = frozenset(
    {
        "alt", "class", "for", "id", "label", "name", "pattern", "placeholder", "role", "summary",
        "title", "value", "style", "xmlns",
    }
)


def _lower(values: Iterable[str]) -> set[str]:
    return {value.lower() for value in values}


DEFAULT_ALLOWED_TAGS = frozenset(
    _lower(HTML_TAGS + SVG_TAGS + SVG_FILTER_TAGS + MATHML_TAGS + TEXT_TAGS)
)
DEFAULT_ALLOWED_ATTR = frozenset(_lower(HTML_ATTRS + SVG_ATTRS + MATHML_ATTRS + XML_ATTRS))


class Config:
    """A validated configuration resolved into lookup sets. Immutable after
    construction, so one instance can serve concurrent calls."""

    __slots__ = (
        "allow_aria_attr", "allow_data_attr", "allow_self_close_in_attr",
        "allow_unknown_protocols", "allowed_attr", "allowed_tags", "allowed_uri", "data_uri_tags",
        "forbid_attr", "forbid_contents", "forbid_tags", "force_body", "keep_content",
        "safe_for_templates", "safe_for_xml", "sanitize_dom", "sanitize_named_props",
        "uri_safe_attributes", "whole_document",
    )

    allowed_tags: frozenset[str]
    allowed_attr: frozenset[str]
    forbid_tags: frozenset[str]
    forbid_attr: frozenset[str]
    forbid_contents: frozenset[str]
    uri_safe_attributes: frozenset[str]
    data_uri_tags: frozenset[str]
    allowed_uri: re.Pattern[str]
    allow_aria_attr: bool
    allow_data_attr: bool
    allow_unknown_protocols: bool
    allow_self_close_in_attr: bool
    safe_for_templates: bool
    safe_for_xml: bool
    sanitize_dom: bool
    sanitize_named_props: bool
    keep_content: bool
    whole_document: bool
    force_body: bool

    def __init__(self, options: Mapping[str, Any]) -> None:
        _validate(options)
        get = options.get

        allowed_tags = set(_optional_set(get("allowed_tags"), DEFAULT_ALLOWED_TAGS))
        allowed_attr = set(_optional_set(get("allowed_attr"), DEFAULT_ALLOWED_ATTR))
        uri_safe = DEFAULT_URI_SAFE_ATTRIBUTES | _optional_set(get("add_uri_safe_attr"), frozenset())
        data_uri_tags = DEFAULT_DATA_URI_TAGS | _optional_set(get("add_data_uri_tags"), frozenset())
        forbid_contents = _optional_set(get("forbid_contents"), DEFAULT_FORBID_CONTENTS)
        forbid_tags = _optional_set(get("forbid_tags"), frozenset())
        forbid_attr = _optional_set(get("forbid_attr"), frozenset())

        self.allow_aria_attr = get("allow_aria_attr") is not False
        self.allow_data_attr = get("allow_data_attr") is not False
        self.allow_unknown_protocols = get("allow_unknown_protocols") is True
        self.allow_self_close_in_attr = get("allow_self_close_in_attr") is not False
        self.safe_for_templates = get("safe_for_templates") is True
        self.safe_for_xml = get("safe_for_xml") is not False
        self.whole_document = get("whole_document") is True
        self.force_body = get("force_body") is True
        self.sanitize_dom = get("sanitize_dom") is not False
        self.sanitize_named_props = get("sanitize_named_props") is True
        self.keep_content = get("keep_content") is not False
        self.allowed_uri = _uri_pattern(get("allowed_uri_regexp"))

        if self.safe_for_templates:
            self.allow_data_attr = False

        profiles = get("use_profiles")
        if isinstance(profiles, Mapping):
            enabled = {_PROFILE_NAMES[name] for name, on in profiles.items() if on is True}
            allowed_tags, allowed_attr = _profile_sets(enabled)

        allowed_tags |= _optional_set(get("add_tags"), frozenset())
        allowed_attr |= _optional_set(get("add_attr"), frozenset())
        forbid_contents = forbid_contents | _optional_set(get("add_forbid_contents"), frozenset())
        if self.keep_content:
            allowed_tags.add("#text")
        if self.whole_document:
            allowed_tags.update(("html", "head", "body"))
        # DOMPurify adds tbody whenever tables are allowed (#286, #365).
        if "table" in allowed_tags:
            allowed_tags.add("tbody")
            forbid_tags = forbid_tags - {"tbody"}
        # Removing <html> while keeping its content moves <head> and <body>
        # next to it, into the document, which jsdom rejects with a
        # HierarchyRequestError on every call. Fail once, here, instead.
        if (
            self.whole_document
            and self.keep_content
            and "html" in forbid_tags
            and "html" not in forbid_contents
        ):
            raise ValueError(
                "HTML sanitizer options: forbid_tags contains 'html' while whole_document and "
                "keep_content are on; DOMPurify fails on every input with this configuration"
            )

        self.allowed_tags = frozenset(allowed_tags)
        self.allowed_attr = frozenset(allowed_attr)
        self.forbid_tags = frozenset(forbid_tags)
        self.forbid_attr = frozenset(forbid_attr)
        self.forbid_contents = frozenset(forbid_contents)
        self.uri_safe_attributes = frozenset(uri_safe)
        self.data_uri_tags = frozenset(data_uri_tags)


def _validate(options: Mapping[str, Any]) -> None:
    for key, value in options.items():
        if key in _REJECTED_KEYS:
            raise ValueError(
                f"HTML sanitizer option {key!r} is not supported: it applies only to browser "
                "DOM objects or other parsers"
            )
        if key not in _SUPPORTED_KEYS:
            raise ValueError(f"Unknown HTML sanitizer option: {key!r}")
        if value is None:
            continue
        if key in _LIST_KEYS:
            if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple, set, frozenset)):
                raise ValueError(f"HTML sanitizer option {key!r} must be a list of strings")
            if not all(isinstance(entry, str) for entry in value):
                raise ValueError(f"HTML sanitizer option {key!r} must be a list of strings")
        elif key in _BOOLEAN_KEYS:
            if not isinstance(value, bool):
                raise ValueError(f"HTML sanitizer option {key!r} must be a bool")
        elif key == "allowed_uri_regexp":
            if not isinstance(value, (str, re.Pattern)):
                raise ValueError(
                    "HTML sanitizer option 'allowed_uri_regexp' must be a compiled pattern or str"
                )
            if isinstance(value, str):
                try:
                    re.compile(value)
                except re.error as exc:
                    raise ValueError(f"HTML sanitizer option 'allowed_uri_regexp': {exc}") from exc
        else:
            _validate_profiles(value)


def _validate_profiles(value: Any) -> None:
    if value is False:
        return
    if not isinstance(value, Mapping):
        raise ValueError("HTML sanitizer option 'use_profiles' must be False or a dict")
    for name, enabled in value.items():
        if name not in _PROFILE_NAMES:
            raise ValueError(f"Unknown use_profiles profile: {name!r}")
        if not isinstance(enabled, bool):
            raise ValueError(f"use_profiles[{name!r}] must be a bool")


def _optional_set(value: Optional[Iterable[str]], default: frozenset[str]) -> frozenset[str]:
    """A configured list, lowercased like DOMPurify's addToSet, or the default."""
    if value is None:
        return default
    return frozenset(_lower(value))


def _uri_pattern(value: Union[None, str, re.Pattern[str]]) -> re.Pattern[str]:
    if value is None:
        return DEFAULT_ALLOWED_URI
    if isinstance(value, str):
        return re.compile(value)
    return value


def _profile_sets(enabled: set[str]) -> tuple[set[str], set[str]]:
    """ALLOWED_TAGS and ALLOWED_ATTR for USE_PROFILES."""
    tags = _lower(TEXT_TAGS)
    attrs: set[str] = set()
    if "html" in enabled:
        tags |= _lower(HTML_TAGS)
        attrs |= _lower(HTML_ATTRS)
    if "svg" in enabled:
        tags |= _lower(SVG_TAGS)
        attrs |= _lower(SVG_ATTRS + XML_ATTRS)
    if "svgFilters" in enabled:
        tags |= _lower(SVG_FILTER_TAGS)
        attrs |= _lower(SVG_ATTRS + XML_ATTRS)
    if "mathMl" in enabled:
        tags |= _lower(MATHML_TAGS)
        attrs |= _lower(MATHML_ATTRS + XML_ATTRS)
    return tags, attrs
