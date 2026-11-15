"""A small mutable DOM and its HTML serializer.

The sanitizer works on this tree rather than on JustHTML's nodes so that
namespaces, attribute order and template contents behave exactly as they do
in jsdom, where DOMPurify runs. The serializer follows parse5's HTML fragment
serialization (the serializer jsdom uses for ``innerHTML``), since DOMPurify's
string output is that serialization.
"""

from __future__ import annotations

from typing import Optional, Union

HTML_NS = "http://www.w3.org/1999/xhtml"
SVG_NS = "http://www.w3.org/2000/svg"
MATHML_NS = "http://www.w3.org/1998/Math/MathML"


class Text:
    """A text node."""

    __slots__ = ("data", "parent")

    def __init__(self, data: str) -> None:
        self.data = data
        self.parent: Optional[Parent] = None


class Comment:
    """A comment node."""

    __slots__ = ("data", "parent")

    def __init__(self, data: str) -> None:
        self.data = data
        self.parent: Optional[Parent] = None


class Fragment:
    """A document fragment: the content of an HTML ``<template>``."""

    __slots__ = ("children", "parent")

    def __init__(self) -> None:
        self.children: list[Node] = []
        self.parent: Optional[Parent] = None


class Element:
    """An element. ``name`` is the qualified name as serialized (HTML names are
    lowercase, SVG names keep their adjusted case such as ``foreignObject``).
    ``attrs`` maps qualified attribute names to values in document order.
    """

    __slots__ = ("attrs", "children", "content", "name", "namespace", "parent")

    def __init__(self, name: str, namespace: str, attrs: dict[str, str]) -> None:
        self.name = name
        self.namespace = namespace
        self.attrs = attrs
        self.children: list[Node] = []
        self.parent: Optional[Parent] = None
        self.content: Optional[Fragment] = None


Node = Union[Element, Text, Comment]
Parent = Union[Element, Fragment]


def append_child(parent: Parent, node: Node) -> None:
    """Append ``node`` (already detached) as the last child of ``parent``."""
    node.parent = parent
    parent.children.append(node)


def node_name(node: Node) -> str:
    """The lowercase node name DOMPurify works with (``#text``, ``#comment``, tag)."""
    if isinstance(node, Text):
        return "#text"
    if isinstance(node, Comment):
        return "#comment"
    return node.name.lower()


def has_element_child(element: Element) -> bool:
    """Whether ``element`` has an element among its direct children."""
    return any(isinstance(child, Element) for child in element.children)


def text_content(element: Element) -> str:
    """``element.textContent``: all descendant text, template contents excluded."""
    parts: list[str] = []
    stack: list[Node] = [element]
    while stack:
        node = stack.pop()
        if isinstance(node, Text):
            parts.append(node.data)
        elif isinstance(node, Element):
            stack.extend(reversed(node.children))
    return "".join(parts)


# ─── Serialization (parse5 serializer as used by jsdom) ─────────────────

VOID_ELEMENTS = frozenset(
    {
        "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "img",
        "input", "keygen", "link", "meta", "param", "source", "track", "wbr",
    }
)

# Children of these HTML elements are serialized without escaping.
_UNESCAPED_TEXT_PARENTS = frozenset(
    {"style", "script", "xmp", "iframe", "noembed", "noframes", "plaintext"}
)

_TEXT_ESCAPES = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;", "\u00a0": "&nbsp;"})
_ATTR_ESCAPES = str.maketrans(
    {"&": "&amp;", '"': "&quot;", "<": "&lt;", ">": "&gt;", "\u00a0": "&nbsp;"}
)


def _children_of(element: Element) -> list[Node]:
    """Serialized children: a template's are those of its content."""
    if element.content is not None:
        return element.content.children
    return element.children


def _is_void(element: Element) -> bool:
    return element.namespace == HTML_NS and element.name in VOID_ELEMENTS


def _serialize_text(node: Text, scripting: bool) -> str:
    parent = node.parent
    if isinstance(parent, Element) and parent.namespace == HTML_NS:
        if parent.name in _UNESCAPED_TEXT_PARENTS or (scripting and parent.name == "noscript"):
            return node.data
    return node.data.translate(_TEXT_ESCAPES)


def _serialize_nodes(nodes: list[Node], scripting: bool) -> str:
    # Iterative, so deeply nested input cannot exhaust the Python stack.
    out: list[str] = []
    stack: list[tuple[list[Node], int, str]] = []
    index = 0
    while True:
        if index < len(nodes):
            node = nodes[index]
            index += 1
            if isinstance(node, Element):
                attrs = "".join(
                    f' {name}="{value.translate(_ATTR_ESCAPES)}"' for name, value in node.attrs.items()
                )
                out.append(f"<{node.name}{attrs}>")
                if not _is_void(node):
                    stack.append((nodes, index, f"</{node.name}>"))
                    nodes = _children_of(node)
                    index = 0
            elif isinstance(node, Text):
                out.append(_serialize_text(node, scripting))
            else:
                out.append(f"<!--{node.data}-->")
        elif stack:
            nodes, index, end_tag = stack.pop()
            out.append(end_tag)
        else:
            return "".join(out)


def inner_html(node: Parent, *, scripting: bool = False) -> str:
    """``innerHTML`` of an element or fragment.

    ``scripting`` is the serializing document's scripting flag: false for the
    parsed document, true inside template contents, whose owner document in
    jsdom is a separate inert document with default options.
    """
    if isinstance(node, Element):
        if _is_void(node):
            return ""
        return _serialize_nodes(_children_of(node), scripting)
    return _serialize_nodes(node.children, scripting)


def outer_html(element: Element) -> str:
    """``outerHTML`` of an element in the parsed document."""
    return _serialize_nodes([element], False)
