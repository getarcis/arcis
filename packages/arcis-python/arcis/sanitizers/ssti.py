"""
Arcis SSTI (Server-Side Template Injection) prevention.

Detects and sanitizes template injection payloads for Jinja2, Twig,
Nunjucks, Freemarker, Thymeleaf, Spring EL, ERB, EJS, Pug/Jade,
and Python sandbox-escape dunder chains.
"""

import re

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
    # Velocity #set/#foreach directives and OGNL/Velocity method calls
    # ($rt.exec, .getRuntime). Benchmark ssti-velocity-runtime.
    re.compile(
        r"#set\s*\(\s*\$|#foreach\s*\(\s*\$"
        r"|\$\w+\.(?:exec|getClass|getRuntime|getMethod|invoke)\b",
        re.IGNORECASE,
    ),
    # Laravel Blade raw-PHP directive: @php(...) inline or @php ... @endphp block
    # (the {{ }} Blade echo form is already covered above). Requires @php( or the
    # @endphp close so it doesn't fire on the bare "@php" social handle.
    re.compile(r"@php\s*\(|@endphp\b", re.IGNORECASE),
]

# Removal patterns — used by sanitize_ssti()
#
# ${ and #{ are narrowed to only strip when the expression contains operators or
# method calls, avoiding false-positives on JS template literals (${name}) and
# Pug/Ruby output expressions (#{name}) in legitimate user content.
# The broad detection patterns above still flag these for detect_ssti().
_SSTI_REMOVE_PATTERNS = [
    # Jinja2 / Twig: {{ ... }} — always strip (not valid in any JS context)
    re.compile(r"\{\{.*?\}\}", re.DOTALL),
    # Freemarker / Spring EL: strip when expression contains operators/calls or dunders
    re.compile(r"\$\{[^}]*__\w+__[^}]*\}"),
    re.compile(r"\$\{[^}]*[?!()*+\-/][^}]*\}"),
    # ERB / EJS — always strip
    re.compile(r"<%[=\-]?.*?%>", re.DOTALL),
    # Pug / Jade: strip when expression contains operators/calls or dunders
    re.compile(r"#\{[^}]*__\w+__[^}]*\}"),
    re.compile(r"#\{[^}]*[?!()*+\-/][^}]*\}"),
    # Python dunder sandbox escape — always strip
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
