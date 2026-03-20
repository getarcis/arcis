"""
Arcis SSTI (Server-Side Template Injection) prevention.

Detects and sanitizes template injection payloads for Jinja2, Twig,
Nunjucks, Freemarker, Thymeleaf, Spring EL, ERB, EJS, Pug/Jade,
and Python sandbox-escape dunder chains.
"""

import re
from typing import List, Optional

# Detection patterns — used by detect_ssti()
_SSTI_DETECT_PATTERNS = [
    # Jinja2 / Twig / Nunjucks: {{ ... }}
    re.compile(r"\{\{.*?\}\}", re.DOTALL),
    # Freemarker / Thymeleaf / Spring EL: ${ ... }
    re.compile(r"\$\{.*?\}"),
    # ERB / EJS: <%= ... %> or <% ... %>
    re.compile(r"<%[=\-]?.*?%>", re.DOTALL),
    # Pug / Jade / Slim: #{ ... }
    re.compile(r"#\{.*?\}"),
    # Python dunder sandbox escape
    re.compile(r"__(?:class|mro|subclasses|globals|builtins|import)__", re.IGNORECASE),
    # Jinja2 config leak: {{config.X}} or {{config['X']}}
    re.compile(r"\{\{\s*config[.\[]", re.IGNORECASE),
    # Jinja2 built-in objects
    re.compile(
        r"\{\{\s*(?:self|request|lipsum|cycler|joiner|namespace|range)\b",
        re.IGNORECASE,
    ),
]

# Removal patterns — used by sanitize_ssti()
_SSTI_REMOVE_PATTERNS = [
    re.compile(r"\{\{.*?\}\}", re.DOTALL),
    re.compile(r"\$\{.*?\}"),
    re.compile(r"<%[=\-]?.*?%>", re.DOTALL),
    re.compile(r"#\{.*?\}"),
    re.compile(r"__(?:class|mro|subclasses|globals|builtins|import)__", re.IGNORECASE),
]


def detect_ssti(value: str) -> bool:
    """
    Check if a string contains SSTI patterns.

    Returns True if any template injection pattern is detected.
    Does not modify the input — use sanitize_ssti() for that.
    """
    if not isinstance(value, str):
        return False

    for pattern in _SSTI_DETECT_PATTERNS:
        if pattern.search(value):
            return True

    return False


def sanitize_ssti(value: str) -> str:
    """
    Sanitize a string by removing SSTI payloads.

    Strips template expression syntax ({{ }}, ${ }, <% %>, #{ },
    and Python dunder chains).
    """
    if not isinstance(value, str):
        raise TypeError(f"sanitize_ssti expects str, got {type(value).__name__}")

    result = value
    for pattern in _SSTI_REMOVE_PATTERNS:
        result = pattern.sub("", result)

    return result
