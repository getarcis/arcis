"""Legacy ``<select>`` parsing on top of JustHTML.

parse5 8.1 parses ``<select>`` with the "in select" insertion mode, which
ignores every tag inside a select except ``option``, ``optgroup``, ``hr``
and a few that close it. JustHTML follows the newer customizable-select
rules, which build those tags into elements. To get parse5's tree from
JustHTML, the source of each select is rewritten the way the old insertion
mode reads it: ignored tags are deleted, and tags that close the select get
an explicit ``</select>``. JustHTML then sees only markup that both rule sets
handle alike.

Selects are located by tagging every ``<select`` in the source with a marker
attribute and parsing once: an attribute never changes the tree, and in any
other context (text, attribute values, comments) the marker is inert text.
The content after a select's start tag is tokenized here in the data state,
the only tokenizer state the old insertion mode uses until the select
closes. ``<script>`` and ``<template>`` content, which follows its own
rules, is skipped: its end is found by parsing up to each candidate end tag
followed by a probe element and checking where the probe lands.

Content that cannot be rewritten exactly (table markup next to a select that
may have been foster-parented, or a rewrite that does not settle) raises
UnsupportedMarkup, and the sanitizer returns an empty string for that input.
"""

from __future__ import annotations

import re
from typing import Any, Callable, NamedTuple, Optional

from ._tokenizer import tag_end, token_at

_SELECT_START = re.compile(r"<select(?=[\t\n\f\r />])", re.IGNORECASE | re.ASCII)
_MARKER_PREFIX = "data-arcis-select-"
_PROBE = "<arcis-probe>"

# The "in select" insertion mode, by token.
_KEPT_START_TAGS = frozenset({"html", "option", "optgroup", "hr"})
_CLOSING_START_TAGS = frozenset({"input", "keygen", "textarea"})
_KEPT_END_TAGS = frozenset({"option", "optgroup"})
_SKIPPED_ELEMENTS = frozenset({"script", "template"})
# Table markup closes a select opened in a table context ("in select in table").
_TABLE_TAGS = frozenset({"caption", "table", "tbody", "tfoot", "thead", "tr", "td", "th"})

_MAX_PASSES = 8
_MAX_END_TAG_CANDIDATES = 32

Parse = Callable[[str], Any]
Edit = tuple[int, int, str]


class UnsupportedMarkup(Exception):
    """The input needs a parse that cannot be reproduced exactly."""


class _Site(NamedTuple):
    """An HTML select in the parsed tree.

    ``template_depth`` counts the templates the select is nested in.
    ``table_stack`` holds the names of the HTML elements between the select
    and its nearest table (the table included) when it was opened in a table
    context, else None. ``maybe_fostered`` marks a select (or ancestor) that
    precedes a table among its siblings, which is either ordinary order or
    foster parenting; the tree alone cannot tell which.
    """

    offset: int
    template_depth: int
    table_stack: Optional[tuple[str, ...]]
    maybe_fostered: bool


def rewrite_selects(markup: str, parse: Parse) -> str:
    """Return ``markup`` with every HTML select rewritten to legacy semantics.

    ``parse`` parses a full document and returns JustHTML's root node.

    Raises:
        UnsupportedMarkup: A select's content cannot be rewritten exactly,
            e.g. table markup next to a select that may be foster-parented.
    """
    if not _SELECT_START.search(markup):
        return markup
    for _ in range(_MAX_PASSES):
        edits = _next_edits(markup, parse)
        if not edits:
            return markup
        for start, end, replacement in sorted(edits, reverse=True):
            markup = markup[:start] + replacement + markup[end:]
    raise UnsupportedMarkup("select rewrite did not settle")


def _next_edits(markup: str, parse: Parse) -> list[Edit]:
    """Edits for one pass over the selects.

    The most deeply templated selects go first, on their own: template
    content parses the same in any context, and a select inside a template
    can move where that template ends for a select around it. Selects at one
    depth are independent, except one starting inside another's rewritten
    content, which waits for the next pass.
    """
    by_depth: dict[int, list[_Site]] = {}
    for site in _locate_selects(markup, parse):
        by_depth.setdefault(site.template_depth, []).append(site)
    for depth in sorted(by_depth, reverse=True):
        edits: list[Edit] = []
        claimed_until = -1
        for site in sorted(by_depth[depth]):
            if site.offset < claimed_until:
                continue
            site_edits, region_end = _region_edits(markup, site, parse)
            if site_edits:
                edits.extend(site_edits)
                claimed_until = region_end
        if edits:
            return edits
    return []


def _locate_selects(markup: str, parse: Parse) -> list[_Site]:
    """Find the start tags that create HTML select elements."""
    pieces: list[str] = []
    last = 0
    for match in _SELECT_START.finditer(markup):
        pieces.append(markup[last:match.end()])
        pieces.append(f" {_MARKER_PREFIX}{match.start()}")
        last = match.end()
    pieces.append(markup[last:])
    root = parse("".join(pieces))

    sites: list[_Site] = []
    stack: list[Any] = [root]
    while stack:
        node = stack.pop()
        if node.name == "select" and node.namespace == "html":
            markers = [name for name in node.attrs or () if name.startswith(_MARKER_PREFIX)]
            if markers:
                sites.append(_site(node, int(markers[0][len(_MARKER_PREFIX):])))
        stack.extend(child for child in node.children or () if not child.name.startswith("#"))
        content = getattr(node, "template_content", None)
        if content is not None:
            stack.append(content)
    return sites


def _site(select: Any, offset: int) -> _Site:
    """Describe the context a select element was opened in."""
    names: list[str] = []
    reached_table = False
    maybe_fostered = False
    depth = 0
    node = select
    while node.parent is not None and node.parent.name != "#document":
        parent = node.parent
        if parent.name == "#document-fragment":
            depth += 1  # template content; its parent is the template element
        elif depth == 0:
            siblings = parent.children or []
            later = siblings[siblings.index(node) + 1:]
            if any(sibling.name == "table" and sibling.namespace == "html" for sibling in later):
                maybe_fostered = True
            if parent.namespace == "html" and not reached_table:
                names.append(parent.name)
                reached_table = parent.name == "table"
        node = parent
    table_stack = tuple(names) if any(name in _TABLE_TAGS for name in names) else None
    return _Site(offset, depth, table_stack, maybe_fostered)


def _region_edits(markup: str, site: _Site, parse: Parse) -> tuple[list[Edit], int]:
    """Tokenize from a select start tag until the old insertion mode closes
    the select. Returns the edits that make the new rules agree, and the
    offset where the select's content ends."""
    pos = tag_end(markup, site.offset + len("<select"))
    edits: list[Edit] = []
    length = len(markup)
    while pos is not None and pos < length:
        lt = markup.find("<", pos)
        if lt == -1:
            break
        kind, name, end = token_at(markup, lt)
        if end is None:  # end of input inside a tag: the tag is dropped
            break
        pos = end
        if kind == "start":
            if name in _KEPT_START_TAGS:
                continue
            if name in _SKIPPED_ELEMENTS:
                pos = _element_end(markup, lt, name, parse)
                continue
            if name == "select":
                edits.append((lt, end, "</select>"))
                return edits, end
            if name in _CLOSING_START_TAGS or (name in _TABLE_TAGS and _in_table(site)):
                edits.append((lt, lt, "</select>"))
                return edits, end
            edits.append((lt, end, ""))
        elif kind == "end":
            if name in _KEPT_END_TAGS:
                continue
            if name == "select" or (name == "template" and site.template_depth):
                return edits, end
            # A table end tag closes the select only if that element is open
            # in table scope; otherwise the old insertion mode ignores it.
            if name in _TABLE_TAGS and _in_table(site) and name in (site.table_stack or ()):
                edits.append((lt, lt, "</select>"))
                return edits, end
            if name != "template":  # an unmatched </template> is ignored by both
                edits.append((lt, end, ""))
    return edits, length


def _in_table(site: _Site) -> bool:
    """Whether table markup closes this select. Raises when the answer
    depends on foster parenting, which the tree does not record."""
    if site.table_stack is not None:
        return True
    if site.maybe_fostered:
        raise UnsupportedMarkup("table markup inside a select next to a table")
    return False


def _element_end(markup: str, start: int, name: str, parse: Parse) -> int:
    """Offset just past the end tag that closes the ``script`` or
    ``template`` element whose start tag is at ``start``.

    Both parse the same in any context, so ``markup[start:]`` is parsed on its
    own up to each ``</name`` candidate, followed by a probe element. The
    first candidate after which the probe falls outside the element closes
    it; inside a comment, attribute or raw text the probe stays inside.
    """
    closer = re.compile(rf"</{name}(?=[\t\n\f\r />])", re.IGNORECASE)
    for count, match in enumerate(closer.finditer(markup, start)):
        if count == _MAX_END_TAG_CANDIDATES:
            raise UnsupportedMarkup(f"too many </{name}> candidates inside <select>")
        end = tag_end(markup, match.end())
        if end is None:
            break
        if not _probe_inside(parse(markup[start:end] + _PROBE), name):
            return end
    return len(markup)


def _probe_inside(root: Any, name: str) -> bool:
    """Whether the probe sits in the first ``name`` element or its content."""
    stack: list[Any] = [root]
    while stack:
        node = stack.pop()
        if node.name == name and node.namespace == "html":
            return _contains_probe(node)
        stack.extend(reversed(node.children or []))
    return False


def _contains_probe(element: Any) -> bool:
    stack: list[Any] = [element]
    while stack:
        node = stack.pop()
        if node.name == "arcis-probe":
            return True
        if node.name in ("#text", "#comment"):
            if _PROBE in (node.data or ""):
                return True
            continue
        if any(_PROBE in (value or "") for value in (node.attrs or {}).values()):
            return True
        stack.extend(node.children or ())
        content = getattr(node, "template_content", None)
        if content is not None:
            stack.append(content)
    return False
