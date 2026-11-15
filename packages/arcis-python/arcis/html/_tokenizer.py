"""A data-state tokenizer, enough to find token boundaries.

Covers what the HTML tokenizer does from the data state: tags with their
attribute quoting, comments, bogus comments and doctypes. Character
references and raw text are not decoded or tracked; callers only use it
where the tokenizer stays in the data state.
"""

from __future__ import annotations

import re
from typing import Optional

SPACE = "\t\n\f\r "
_TAG_NAME_END = SPACE + "/>"
_COMMENT_CLOSE = re.compile(r"--!?>")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def token_at(markup: str, lt: int) -> tuple[str, str, Optional[int]]:
    """Classify the data-state token at ``markup[lt] == "<"``.

    Returns (kind, tag name, end offset); kind is "start", "end" or "other"
    (text, comments, doctypes). The end is None when the input ends inside
    a tag, which drops the tag.
    """
    following = markup[lt + 1:lt + 2]
    if following == "!":
        if markup.startswith("<!--", lt):
            return "other", "", _comment_end(markup, lt + 4)
        return "other", "", _bogus_comment_end(markup, lt + 2)
    if following == "?":
        return "other", "", _bogus_comment_end(markup, lt + 2)
    if following == "/":
        after = markup[lt + 2:lt + 3]
        if after.isascii() and after.isalpha():
            name_end = _name_end(markup, lt + 2)
            name = markup[lt + 2:name_end].translate(_ASCII_LOWER)
            return "end", name, tag_end(markup, name_end)
        if after == ">":
            return "other", "", lt + 3
        if not after:
            return "other", "", len(markup)
        return "other", "", _bogus_comment_end(markup, lt + 2)
    if following.isascii() and following.isalpha():
        name_end = _name_end(markup, lt + 1)
        name = markup[lt + 1:name_end].translate(_ASCII_LOWER)
        return "start", name, tag_end(markup, name_end)
    return "other", "", lt + 1


def _name_end(markup: str, pos: int) -> int:
    while pos < len(markup) and markup[pos] not in _TAG_NAME_END:
        pos += 1
    return pos


def tag_end(markup: str, pos: int) -> Optional[int]:
    """Offset just past the ``>`` that ends a tag whose name ends at ``pos``,
    following the attribute states of the tokenizer. None at end of input."""
    length = len(markup)
    while pos < length:
        char = markup[pos]
        if char in SPACE:
            pos += 1
        elif char == ">":
            return pos + 1
        elif char == "/":
            pos += 1
            if pos < length and markup[pos] == ">":
                return pos + 1
        else:
            # Attribute name; its first character may be "=".
            pos += 1
            while pos < length and markup[pos] not in SPACE and markup[pos] not in "/>=":
                pos += 1
            while pos < length and markup[pos] in SPACE:
                pos += 1
            if pos < length and markup[pos] == "=":
                pos += 1
                while pos < length and markup[pos] in SPACE:
                    pos += 1
                if pos < length and markup[pos] in "\"'":
                    close = markup.find(markup[pos], pos + 1)
                    if close == -1:
                        return None
                    pos = close + 1
                else:
                    while pos < length and markup[pos] not in SPACE and markup[pos] != ">":
                        pos += 1
    return None


def _comment_end(markup: str, pos: int) -> int:
    """End of a ``<!--`` comment whose content starts at ``pos``."""
    if markup.startswith(">", pos):
        return pos + 1
    if markup.startswith("->", pos):
        return pos + 2
    match = _COMMENT_CLOSE.search(markup, pos)
    return match.end() if match else len(markup)


def _bogus_comment_end(markup: str, pos: int) -> int:
    close = markup.find(">", pos)
    return len(markup) if close == -1 else close + 1
