"""Parse markup with JustHTML into the sanitizer's DOM, the way jsdom's
``DOMParser`` (parse5, scripting disabled) would.

JustHTML follows the current WHATWG parsing rules, which differ from parse5
8.1 in a few places. Where the difference can be undone from the source
text it is undone here:

- JustHTML strips a leading U+FEFF; parse5 keeps it as text.
- ``<?target ...>`` becomes a processing instruction in JustHTML and a bogus
  comment in parse5. It is turned back into the comment parse5 builds.
- An unterminated ``<?...`` at the end of the input is dropped by JustHTML
  and kept as a comment by parse5.
- A repeated ``<html>`` or ``<body>`` start tag adds its attributes to the
  element; jsdom's tree adapter also overwrites values already there, while
  JustHTML keeps the first. A repeated ``<head>`` is ignored by parse5 and
  merged by JustHTML.
- ``<select>`` content is rewritten to the older parsing rules (``_select``).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict, deque
from typing import Any, Optional


from ._dom import (
    HTML_NS,
    MATHML_NS,
    SVG_NS,
    Comment,
    Element,
    Fragment,
    Parent,
    Text,
    append_child,
)
from ._select import rewrite_selects
from ._tokenizer import SPACE, tag_end, token_at

_NAMESPACES = {"html": HTML_NS, "svg": SVG_NS, "math": MATHML_NS}

# A terminated `<?...>` sequence; whether it is a processing instruction
# for JustHTML is decided by _pi_key below.
_PI_SOURCE = re.compile(r"<\?([^>]*)>")
_PI_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_PI_SPACE = " \t\n\f\r"
_EOF_PROBE = "<?arcis-eof-probe>"
_EOF_PROBE_KEY = "arcis-eof-probe "


# ─── Tree-construction fixes ─────────────────────────────────────────────
# Two places where JustHTML's tree builder departs from the WHATWG
# algorithm (and from parse5), fixed on a subclass of its parse engine:
#
# 1. An HTML end tag processed while HTML content is open inside a MathML or
#    SVG integration point (`<math><mtext><b></mtext>`) must not match the
#    foreign element: only HTML elements match, and the integration point
#    ends the scope ("any other end tag", 13.2.6.4.7).
# 2. `</form>` reached through the foreign-content end tag steps while the
#    form sits behind an integration point (`<form><math><mtext></form>`) is
#    handed to the "in body" rules, which clear the form element pointer even
#    though the form stays open (13.2.6.5, step 7).
#
# The engine is internal to JustHTML, so the fixes are checked when this
# module loads. If they do not take effect the import fails: both bugs sit in
# the form/MathML structures that mutation-XSS payloads rely on, so falling
# back to the unpatched parser would silently weaken sanitization.

_HTML_ELEMENT_NAMESPACES = frozenset({None, "html", "justhtml-parser-only"})

try:
    from justhtml.parser.engine import ParseEngine, compile_raw_engine_plan

    class _Engine(ParseEngine):
        def _find_open_index_before_boundary(self, name: str, boundaries: frozenset[str]) -> Any:
            index = super()._find_open_index_before_boundary(name, boundaries)
            if index is None or self._stack[index].namespace in _HTML_ELEMENT_NAMESPACES:
                return index
            # A foreign element matched by name; keep looking for an HTML one.
            stack = self._stack
            for position in range(index, 0, -1):
                node = stack[position]
                if node.namespace in _HTML_ELEMENT_NAMESPACES:
                    if node.name == name:
                        return position
                    if node.name in boundaries:
                        return None
                elif self._is_foreign_scope_boundary(node):
                    return None
            return None

        @staticmethod
        def _is_foreign_scope_boundary(node: Any) -> bool:
            if node.namespace == "math":
                return node.name in ("mi", "mo", "mn", "ms", "mtext", "annotation-xml")
            return node.namespace == "svg" and node.name in ("foreignObject", "desc", "title")

        def _end_tag_stays_in_foreign_context(self, name: str, tag_start: int, tag_end: int) -> Any:
            clears_form = False
            if name == "form" and not self._template_modes:
                stack = self._stack
                for position in range(len(stack) - 1, 0, -1):
                    if stack[position].name == "form":
                        clears_form = stack[position].namespace in _HTML_ELEMENT_NAMESPACES
                        break
            stays = super()._end_tag_stays_in_foreign_context(name, tag_start, tag_end)
            if stays and clears_form:
                self._form_element = None
            return stays

    _RAW_PLAN = compile_raw_engine_plan(False, False)

    def _engine_parse(markup: str) -> Any:
        engine = _Engine(markup, fragment=False, scripting_enabled=False, plan=_RAW_PLAN)
        return engine.parse()

    def _engine_fixes_work() -> bool:
        def first_path(root: Any, depth: int) -> Any:
            node = root.children[0]  # <html>
            node = node.children[1]  # <body>
            for _ in range(depth):
                node = node.children[0]
            return node

        try:
            # Expected: form > math > mtext > form, and math > mtext > b > i.
            mtext = first_path(_engine_parse("<form><math><mtext></form><form>"), 3)
            bold = first_path(_engine_parse("<math><mtext><b></mtext><i>"), 3)
            return bool(mtext.children[0].name == "form" and bold.children[0].name == "i")
        except Exception:  # pragma: no cover - only if JustHTML's internals change
            return False

    _PATCHED_ENGINE = _engine_fixes_work()
except Exception:  # pragma: no cover - only if JustHTML's internals change
    _PATCHED_ENGINE = False

if not _PATCHED_ENGINE:  # pragma: no cover - only if JustHTML's internals change
    raise ImportError(
        "arcis.html does not support the installed JustHTML version: its parser "
        "fixes could not be applied. Install the tested release with "
        'pip install "arcis[html]".'
    )


class ParsedDocument:
    """The parsed ``<html>`` element and the doctype name, if any."""

    __slots__ = ("doctype_name", "html")

    def __init__(self, html: Element, doctype_name: Optional[str]) -> None:
        self.html = html
        self.doctype_name = doctype_name


def _normalize(data: str) -> str:
    """Input stream preprocessing: newlines to LF, NUL to U+FFFD."""
    return data.replace("\r\n", "\n").replace("\r", "\n").replace("\0", "\ufffd")


def _pi_key(body: str) -> Optional[str]:
    """The data JustHTML gives a processing instruction for ``<?body>``, or
    None when JustHTML makes a comment of it (mirrors its parser)."""
    match = _PI_NAME.match(body)
    if match is None:
        return None
    target = body[: match.end()]
    if target.lower().startswith("xml"):
        return None
    rest = body[match.end():]
    if not rest:
        return _normalize(f"{target} ")
    if rest[0] in _PI_SPACE:
        rest = rest.lstrip(_PI_SPACE)
    elif rest[0] != "?":
        return None
    data = rest[:-1] if rest.endswith("?") else rest
    return _normalize(f"{target} {data}" if data else f"{target} ")


def _pi_comments(markup: str) -> dict[str, deque[str]]:
    """Map each processing-instruction value JustHTML would produce to the
    bogus-comment data parse5 produces for the same source, in source order."""
    comments: dict[str, deque[str]] = defaultdict(deque)
    for match in _PI_SOURCE.finditer(markup):
        key = _pi_key(match.group(1))
        if key is not None:
            comments[key].append(_normalize("?" + match.group(1)))
    return comments


def _justhtml(markup: str) -> Any:
    return _engine_parse(markup)


def _eof_comment_parse(markup: str) -> Optional[tuple[Any, str]]:
    """Handle ``<?...`` left open at the end of the input.

    parse5 emits it as a comment running to the end of the input. When the
    sequence starts in the data state, replacing it with a terminated probe
    makes JustHTML create a processing instruction in exactly that position;
    anywhere else the probe is plain text or part of a tag. Returns the probe
    tree and the comment data, or None when the probe did not land.
    """
    start = markup.rfind("<?")
    if start == -1 or markup.find(">", start) != -1:
        return None
    root = _justhtml(markup[:start] + _EOF_PROBE)
    if not _contains_probe(root):
        return None
    return root, _normalize(markup[start + 1:])


def _contains_probe(root: Any) -> bool:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.name == "#processing-instruction" and node.data == _EOF_PROBE_KEY:
            return True
        stack.extend(node.children or ())
        content = getattr(node, "template_content", None)
        if content is not None:
            stack.append(content)
    return False


# ─── Attributes of <html>, <head> and <body> ────────────────────────────

_ROOT_TAG = re.compile(r"<(html|head|body)(?=[\t\n\f\r />])", re.IGNORECASE | re.ASCII)
_ROOT_MARKER = "data-arcis-root-"
# Before <head> is created these tokens leave the parser waiting for it.
_PRE_HEAD_END_TAGS = frozenset({"head", "body", "html", "br"})


def _root_elements(root: Any) -> dict[str, Any]:
    """JustHTML's <html>, <head> and <body> elements, by name."""
    found: dict[str, Any] = {}
    for child in root.children:
        if child.name == "html" and child.namespace == "html":
            found["html"] = child
            for grandchild in child.children:
                if grandchild.name in ("head", "body") and grandchild.namespace == "html":
                    found.setdefault(grandchild.name, grandchild)
    return found


def _adjust_root_attributes(markup: str, root: Any) -> None:
    """Give <html>, <head> and <body> the attributes jsdom gives them.

    Which start tags contributed attributes is found by marking every
    ``<html``, ``<head`` and ``<body`` with a marker attribute and parsing
    again: each contributing tag leaves its marker on the element.
    """
    elements = _root_elements(root)
    counts = Counter(match.group(1).lower() for match in _ROOT_TAG.finditer(markup))
    pending = [
        name
        for name, element in elements.items()
        if element.attrs and (counts[name] > 1 or name == "head")
    ]
    if not pending:
        return
    marked = _root_elements(_justhtml(_ROOT_TAG.sub(_mark_root_tag, markup)))
    for name in pending:
        element = elements[name]
        marked_attrs = marked[name].attrs if name in marked else {}
        offsets = [
            int(attr[len(_ROOT_MARKER):]) for attr in marked_attrs if attr.startswith(_ROOT_MARKER)
        ]
        if name == "head":
            # parse5 keeps only the tag that created the head element.
            created_by = offsets[0] if offsets and _creates_head(markup, offsets[0]) else None
            kept = _tag_attributes(markup, created_by, name) if created_by is not None else {}
            element.attrs = {key: value for key, value in element.attrs.items() if key in kept}
            continue
        # jsdom: every contributing tag overwrites, in source order.
        for offset in offsets:
            for key, value in _tag_attributes(markup, offset, name).items():
                if key in element.attrs:
                    element.attrs[key] = value


def _mark_root_tag(match: re.Match[str]) -> str:
    return f"{match.group(0)} {_ROOT_MARKER}{match.start()}"


def _tag_attributes(markup: str, offset: int, name: str) -> dict[str, str]:
    """The attributes of the ``<html>``/``<head>``/``<body>`` tag at ``offset``,
    decoded by parsing that tag on its own."""
    end = tag_end(markup, offset + 1 + len(name))
    if end is None:
        return {}
    element = _root_elements(_justhtml(markup[offset:end])).get(name)
    attrs = element.attrs if element is not None else {}
    return {key: "" if value is None else value for key, value in attrs.items()}


def _creates_head(markup: str, offset: int) -> bool:
    """Whether the ``<head>`` tag at ``offset`` is the token that creates the
    head element: everything before it is whitespace, comments, doctypes,
    ``<html>`` tags or end tags the parser ignores at that point."""
    pos = 0
    while pos < offset:
        lt = markup.find("<", pos)
        if lt == -1 or markup[pos:lt].strip(SPACE):
            return False
        if lt == offset:
            return True
        kind, name, end = token_at(markup, lt)
        if end is None or end == lt + 1:  # a tag cut off by the end, or a bare "<"
            return False
        if kind == "start" and name != "html":
            return False
        if kind == "end" and name in _PRE_HEAD_END_TAGS:
            return False
        pos = end
    return pos == offset


def parse_document(markup: str) -> ParsedDocument:
    """Parse a full HTML document from ``markup``.

    Raises:
        UnsupportedMarkup: The markup needs a parse that JustHTML cannot be
            steered into reproducing (see ``_select``).
    """
    markup = rewrite_selects(markup, _justhtml)
    pi_comments = _pi_comments(markup)
    eof = _eof_comment_parse(markup)
    if eof is not None:
        root, eof_data = eof
        pi_comments[_EOF_PROBE_KEY].appendleft(eof_data)
    else:
        root = _justhtml(markup)
    _adjust_root_attributes(markup, root)

    html: Optional[Element] = None
    doctype_name: Optional[str] = None
    for child in root.children:
        if child.name == "!doctype":
            doctype_name = child.data.name
        elif child.name == "html" and child.namespace == "html":
            html = _convert(child, pi_comments)
    if html is None:  # pragma: no cover - the parser always creates <html>
        raise RuntimeError("HTML parser produced no document element")
    return ParsedDocument(html, doctype_name)


def _convert(jroot: Any, pi_comments: dict[str, deque[str]]) -> Element:
    """Copy a JustHTML subtree into the sanitizer DOM (iteratively)."""
    root = _element(jroot)
    stack: list[tuple[Any, Parent]] = [(jroot, root)]
    while stack:
        jparent, parent = stack.pop()
        content = getattr(jparent, "template_content", None)
        if content is not None and isinstance(parent, Element):
            fragment = Fragment()
            parent.content = fragment
            stack.append((content, fragment))
        for jchild in jparent.children or ():
            name = jchild.name
            if name == "#text":
                _append_text(parent, jchild.data or "")
            elif name == "#comment":
                append_child(parent, Comment(jchild.data or ""))
            elif name == "#processing-instruction":
                queued = pi_comments.get(jchild.data)
                data = queued.popleft() if queued else "?" + jchild.data
                append_child(parent, Comment(data))
            else:
                element = _element(jchild)
                append_child(parent, element)
                stack.append((jchild, element))
    return root


def _element(jnode: Any) -> Element:
    namespace = _NAMESPACES.get(jnode.namespace, jnode.namespace)
    attrs = {name: "" if value is None else value for name, value in (jnode.attrs or {}).items()}
    return Element(jnode.name, namespace, attrs)


def _append_text(parent: Parent, data: str) -> None:
    # parse5 merges text inserted next to an existing text node.
    if not data:
        return
    last = parent.children[-1] if parent.children else None
    if isinstance(last, Text):
        last.data += data
    else:
        append_child(parent, Text(data))
