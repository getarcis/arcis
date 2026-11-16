"""
Arcis Middleware - Content-Security-Policy

CSP construction for the ``baseline`` security header profile.

Directive handling follows the Helmet 8 option surface so existing Helmet
configurations produce the same header: camelCase or kebab-case directive
names, default directives merged unless ``use_defaults`` is False, ``None`` to
drop a default directive, ``DANGEROUSLY_DISABLE_DEFAULT_SRC``, per-response
callable values and ``report_only``. Arcis adds an optional per-request nonce.
See spec/API_SPEC.md "Security Headers" for the shared contract.
"""

import base64
import json
import re
import secrets
from typing import Any, Callable, Dict, List, Mapping, NamedTuple, Optional, Union


class _DisableDefaultSrc:
    """Type of the ``DANGEROUSLY_DISABLE_DEFAULT_SRC`` marker."""

    def __repr__(self) -> str:
        return "DANGEROUSLY_DISABLE_DEFAULT_SRC"


DANGEROUSLY_DISABLE_DEFAULT_SRC = _DisableDefaultSrc()
"""Directive value that removes ``default-src``, mirroring Helmet's symbol of the same name."""

# A directive value entry: a source string, or a callable evaluated once per
# response with the adapter's request object.
CspEntry = Union[str, Callable[[Any], str]]

# Keywords that are only valid quoted. Helmet rejects them unquoted because a
# bare `self` is a host name, silently weakening the intended policy.
_SHOULD_BE_QUOTED = frozenset({
    "none",
    "self",
    "strict-dynamic",
    "report-sample",
    "inline-speculation-rules",
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
    "wasm-unsafe-eval",
})
_SHOULD_BE_QUOTED_PREFIXES = ("nonce-", "sha256-", "sha384-", "sha512-")

# Helmet's directive name rule: lowercase first letter, no trailing hyphen.
_DIRECTIVE_NAME = re.compile(r"[a-z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?")

# SECURITY: ';' or ',' would let a value inject extra directives or policies.
# Control characters (CR/LF included) would split or break the header.
_INVALID_VALUE = re.compile(r"[;,\x00-\x1f\x7f]")


def default_csp_directives() -> Dict[str, List[str]]:
    """Return the default directives, identical to Helmet 8's, in emission order."""
    return {
        "default-src": ["'self'"],
        "base-uri": ["'self'"],
        "font-src": ["'self'", "https:", "data:"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'self'"],
        "img-src": ["'self'", "data:"],
        "object-src": ["'none'"],
        "script-src": ["'self'"],
        "script-src-attr": ["'none'"],
        "style-src": ["'self'", "https:", "'unsafe-inline'"],
        "upgrade-insecure-requests": [],
    }


def generate_csp_nonce() -> str:
    """Return a fresh nonce: 16 random bytes, standard base64 with padding."""
    return base64.b64encode(secrets.token_bytes(16)).decode("ascii")


class NormalizedCsp(NamedTuple):
    """Validated CSP configuration, ready to render per response."""

    header_name: str
    directives: Dict[str, List[CspEntry]]
    nonce: bool


def _dashify(name: str) -> str:
    return re.sub(r"[A-Z]", lambda match: "-" + match.group(0).lower(), name)


def _invalid_value(directive: str) -> ValueError:
    return ValueError(
        f"Content-Security-Policy received an invalid directive value for {json.dumps(directive)}"
    )


def _check_value(directive: str, value: str) -> None:
    if _INVALID_VALUE.search(value):
        raise _invalid_value(directive)


def _check_quoted(directive: str, entry: str) -> None:
    if entry in _SHOULD_BE_QUOTED or entry.startswith(_SHOULD_BE_QUOTED_PREFIXES):
        raise ValueError(
            "Content-Security-Policy received an invalid directive value for "
            f"{json.dumps(directive)}. {json.dumps(entry)} should be quoted"
        )


def _directive_entries(name: str, raw_value: Any) -> List[CspEntry]:
    """Turn one configured directive value into a validated entry list."""
    if isinstance(raw_value, str):
        entries: List[Any] = [raw_value]
    elif isinstance(raw_value, (list, tuple)):
        entries = list(raw_value)
    else:
        raise _invalid_value(name)

    for entry in entries:
        if callable(entry):
            continue  # validated when it runs, per response
        if not isinstance(entry, str):
            raise _invalid_value(name)
        _check_value(name, entry)
        _check_quoted(name, entry)
    return entries


def normalize_csp(options: Optional[Mapping[str, Any]] = None) -> NormalizedCsp:
    """Validate CSP options once, at middleware construction.

    Args:
        options: ``use_defaults`` (default True), ``directives`` (name to value),
            ``report_only`` (default False) and ``nonce`` (default False).

    Returns:
        The normalized policy.

    Raises:
        ValueError: If the configuration is invalid.
    """
    options = options or {}
    use_defaults = options.get("use_defaults")
    raw_directives = options.get("directives") or {}
    if not isinstance(raw_directives, Mapping):
        raise ValueError("Content-Security-Policy directives must be a dict")

    # Start from the defaults so an override keeps the default's position and
    # new directives are appended, giving the same header string as Helmet.
    result: Dict[str, List[CspEntry]] = {}
    if use_defaults is None or use_defaults:
        result.update(default_csp_directives())

    seen = set()
    default_src_disabled = False
    for raw_name, raw_value in raw_directives.items():
        if not isinstance(raw_name, str) or not _DIRECTIVE_NAME.fullmatch(raw_name):
            raise ValueError(
                "Content-Security-Policy received an invalid directive name "
                f"{json.dumps(raw_name, default=repr)}"
            )
        name = _dashify(raw_name)
        if name in seen:
            raise ValueError(
                f"Content-Security-Policy received a duplicate directive {json.dumps(name)}"
            )
        seen.add(name)

        if raw_value is None:
            if name == "default-src":
                raise ValueError(
                    "Content-Security-Policy needs a default-src but it was set to `None`. "
                    "If you really want to disable it, set it to "
                    "`DANGEROUSLY_DISABLE_DEFAULT_SRC`."
                )
            result.pop(name, None)
            continue
        if raw_value is DANGEROUSLY_DISABLE_DEFAULT_SRC:
            if name != "default-src":
                raise ValueError(
                    f"Content-Security-Policy: tried to disable {json.dumps(name)} as if it "
                    "were default-src; simply omit the key"
                )
            result.pop("default-src", None)
            default_src_disabled = True
            continue

        result[name] = _directive_entries(name, raw_value)

    if not result:
        raise ValueError(
            "Content-Security-Policy has no directives. Either set some or disable the header"
        )
    if "default-src" not in result and not default_src_disabled:
        raise ValueError(
            "Content-Security-Policy needs a default-src but none was provided. "
            "If you really want to disable it, set it to `DANGEROUSLY_DISABLE_DEFAULT_SRC`."
        )

    nonce = options.get("nonce") is True
    if nonce and "script-src" not in result:
        raise ValueError("Content-Security-Policy nonce requires a script-src directive")

    header_name = (
        "Content-Security-Policy-Report-Only"
        if options.get("report_only")
        else "Content-Security-Policy"
    )
    return NormalizedCsp(header_name=header_name, directives=result, nonce=nonce)


def render_csp(csp: NormalizedCsp, request: Any = None, nonce: Optional[str] = None) -> str:
    """Render the header value for one response.

    Args:
        csp: Output of ``normalize_csp``.
        request: Adapter request object passed to callable directive values.
        nonce: Per-response nonce, appended to ``script-src`` when given.

    Raises:
        ValueError: If a callable directive value returns an invalid value.
    """
    parts = []
    for name, entries in csp.directives.items():
        value = ""
        for entry in entries:
            if callable(entry):
                computed = entry(request)
                if not isinstance(computed, str):
                    raise _invalid_value(name)
                _check_quoted(name, computed)
                value += " " + computed
            else:
                value += " " + entry
        if nonce and name == "script-src":
            value += f" 'nonce-{nonce}'"
        if value:
            _check_value(name, value)
            parts.append(name + value)
        else:
            parts.append(name)
    return ";".join(parts)
