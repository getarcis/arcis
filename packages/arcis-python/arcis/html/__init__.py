"""Parser-backed HTML sanitizer.

Cleans HTML that an application intentionally accepts (comments, rich text,
CMS content) so it can be rendered safely. Output matches DOMPurify 3.4 on
jsdom for the same configuration (see spec/API_SPEC.md section 11). It is an
explicit function for fields that hold HTML; nothing calls it implicitly.

    from arcis.html import HtmlSanitizer, sanitize_html

    sanitize_html('<p onclick="x()">Hi<script>alert(1)</script></p>')
    # '<p>Hi</p>'

    rich_text = HtmlSanitizer(allowed_tags=["p", "a", "b"], allowed_attr=["href"])
    rich_text.sanitize(comment_body)

Configuration keys are DOMPurify's option names in lowercase
(``allowed_tags``, ``add_attr``, ``use_profiles={"svg": True}``, ...).

Needs the JustHTML parser (Python 3.10+): ``pip install "arcis[html]"``.
"""

from __future__ import annotations

try:
    import justhtml  # noqa: F401
except ImportError as exc:  # pragma: no cover - exercised in a subprocess test
    raise ImportError(
        "arcis.html needs the JustHTML parser (Python 3.10+). "
        'Install it with: pip install "arcis[html]"'
    ) from exc

from typing import Any, Optional, TypedDict

from ._config import Config
from ._sanitizer import Sanitizer

__all__ = ["HtmlSanitizer", "SanitizeResult", "sanitize_html", "sanitize_html_detailed"]


class SanitizeResult(TypedDict):
    """Result of a detailed sanitize call.

    ``removed`` lists what was dropped, in document order: ``{"element": name}``
    (``#text`` and ``#comment`` included) or ``{"attribute": name, "from": tag}``.
    """

    html: str
    removed: list[dict[str, str]]


class HtmlSanitizer:
    """A sanitizer with a fixed configuration.

    The configuration is validated once, at construction; unknown keys and
    DOMPurify options that only apply to browser DOM objects raise
    ``ValueError``. Instances are immutable and safe to share across threads.

    Args:
        **config: DOMPurify options in lowercase, e.g. ``allowed_tags=["b"]``.
    """

    __slots__ = ("_sanitizer",)

    def __init__(self, **config: Any) -> None:
        self._sanitizer = Sanitizer(Config(config))

    def sanitize(self, dirty: Optional[str]) -> str:
        """Return ``dirty`` with everything unsafe removed.

        Args:
            dirty: The untrusted HTML. ``None`` returns ``""``.

        Raises:
            TypeError: If ``dirty`` is neither a string nor ``None``.
        """
        return self.sanitize_detailed(dirty)["html"]

    def sanitize_detailed(self, dirty: Optional[str]) -> SanitizeResult:
        """Like :meth:`sanitize`, and also report what was removed.

        Returns:
            ``{"html": ..., "removed": [...]}``. ``removed`` matches DOMPurify's
            ``DOMPurify.removed`` without its ``html``, ``head`` and ``body``
            entries.
        """
        if dirty is None:
            return {"html": "", "removed": []}
        if not isinstance(dirty, str):
            raise TypeError(f"HTML to sanitize must be a str or None, not {type(dirty).__name__}")
        html, removed = self._sanitizer.sanitize(dirty)
        return {"html": html, "removed": removed}


_DEFAULT = HtmlSanitizer()


def _sanitizer_for(config: dict[str, Any]) -> HtmlSanitizer:
    return HtmlSanitizer(**config) if config else _DEFAULT


def sanitize_html(dirty: Optional[str], **config: Any) -> str:
    """Sanitize ``dirty`` HTML with DOMPurify's defaults or the given options.

    Args:
        dirty: The untrusted HTML. ``None`` returns ``""``.
        **config: DOMPurify options in lowercase, e.g. ``forbid_tags=["style"]``.

    Returns:
        The sanitized HTML.

    Raises:
        TypeError: If ``dirty`` is neither a string nor ``None``.
        ValueError: If an option is unknown, unsupported or has the wrong type.
    """
    return _sanitizer_for(config).sanitize(dirty)


def sanitize_html_detailed(dirty: Optional[str], **config: Any) -> SanitizeResult:
    """Like :func:`sanitize_html`, returning ``{"html": ..., "removed": [...]}``."""
    return _sanitizer_for(config).sanitize_detailed(dirty)
