"""
Context-aware output encoding for XSS prevention.

Wrong-context encoding is the #1 cause of XSS bypasses in "protected" apps.
A single sanitize() is not enough when output goes to JS, CSS, or attribute contexts.
"""

from urllib.parse import quote as _url_quote


# HTML entity map — covers the 5 dangerous chars in HTML body context
_HTML_ENTITIES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
}


def _is_alphanumeric(ch: str) -> bool:
    """Check if a character is ASCII alphanumeric."""
    return ch.isascii() and ch.isalnum()


def encode_for_html(value: str) -> str:
    """Encode for HTML body context. Entity-encodes & < > " '

    Use when outputting to HTML element content::

        f"<p>{encode_for_html(user_input)}</p>"
    """
    if not value:
        return ""
    return "".join(_HTML_ENTITIES.get(ch, ch) for ch in value)


def encode_for_attribute(value: str) -> str:
    """Encode for HTML attribute context.

    All non-alphanumeric characters are encoded as ``&#xHH;`` hex entities.

    Use when outputting to HTML attributes::

        f'<div title="{encode_for_attribute(user_input)}">'
    """
    if not value:
        return ""
    result = []
    for ch in value:
        if _is_alphanumeric(ch):
            result.append(ch)
        else:
            result.append(f"&#x{ord(ch):X};")
    return "".join(result)


def encode_for_js(value: str) -> str:
    r"""Encode for JavaScript string context.

    Non-alphanumeric characters are escaped as ``\xHH`` (ASCII) or ``\uHHHH`` (Unicode).

    Use when embedding in JS string literals::

        f"var x = '{encode_for_js(user_input)}';"
    """
    if not value:
        return ""
    result = []
    for ch in value:
        code = ord(ch)
        if _is_alphanumeric(ch):
            result.append(ch)
        elif code < 0x100:
            result.append(f"\\x{code:02X}")
        else:
            result.append(f"\\u{code:04X}")
    return "".join(result)


def encode_for_url(value: str) -> str:
    """Encode for URL parameter context. Percent-encodes all non-unreserved chars.

    Use when building query strings::

        f"?q={encode_for_url(user_input)}"
    """
    if not value:
        return ""
    # quote with empty safe= encodes everything except unreserved chars (RFC 3986)
    return _url_quote(value, safe="")


def encode_for_css(value: str) -> str:
    r"""Encode for CSS value context.

    Non-alphanumeric characters are hex-escaped as ``\HH `` (trailing space per CSS spec).

    Use when embedding in CSS values::

        f"content: '{encode_for_css(user_input)}';"
    """
    if not value:
        return ""
    result = []
    for ch in value:
        if _is_alphanumeric(ch):
            result.append(ch)
        else:
            # CSS hex escape: backslash + hex code + trailing space
            result.append(f"\\{ord(ch):X} ")
    return "".join(result)
