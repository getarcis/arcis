"""DOMPurify's string sanitization path, ported to Python.

Ported from DOMPurify 3.4.18 ``src/purify.ts`` (Apache-2.0, see
THIRDPARTY-LICENSES.md, Source H): document setup (``_initDocument``), the
node walk, ``_sanitizeElements``, ``_isUnsafeNode``, ``_sanitizeDisallowedNode``,
the namespace checks, ``_sanitizeAttributes``, ``_isValidAttribute`` and the
SAFE_FOR_TEMPLATES scrubbing. Paths that only exist for DOM input (IN_PLACE,
RETURN_DOM, Trusted Types, hooks, custom elements) are left out.

``_isClobbered`` has no counterpart: it only fires when a form's properties
are shadowed by named children, which jsdom (the reference environment) does
not implement, so it never triggers there.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from ._allowlists import DOM_CLOBBER_NAMES_LIST, MATHML_DISALLOWED_TAGS, MATHML_TAGS
from ._allowlists import SVG_DISALLOWED_TAGS, SVG_FILTER_TAGS, SVG_TAGS
from ._config import Config
from ._dom import (
    HTML_NS,
    MATHML_NS,
    SVG_NS,
    Comment,
    Element,
    Fragment,
    Node,
    Parent,
    Text,
    has_element_child,
    inner_html,
    node_name,
    outer_html,
    text_content,
)
from ._parse import parse_document
from ._select import UnsupportedMarkup

# ─── DOMPurify's expressions (src/regexp.ts) ────────────────────────────
# JavaScript `\w` is ASCII-only and `$` matches only at the end, hence
# re.ASCII and `\Z`. `\u00b7-\uffff` in a non-unicode JavaScript regex also
# covers astral characters (as surrogate halves), hence `\U0010FFFF`.

MUSTACHE_EXPR = re.compile(r"\{\{[\s\S]*|^[\s\S]*\}\}")
ERB_EXPR = re.compile(r"<%[\s\S]*|^[\s\S]*%>")
TMPLIT_EXPR = re.compile(r"\$\{[\s\S]*")
TMPL_MARKER_SERIALIZED = re.compile(r"\{\{|\}\}|\$\{|<%|%>|&lt;%|%&gt;")
DATA_ATTR = re.compile(r"^data-[\-\w.\u00b7-\U0010FFFF]+\Z", re.ASCII)
ARIA_ATTR = re.compile(r"^aria-[\-\w]+\Z", re.ASCII)
IS_SCRIPT_OR_DATA = re.compile(r"^(?:\w+script|data):", re.IGNORECASE | re.ASCII)
ATTR_WHITESPACE = re.compile("[\u0000-\u0020\u00a0\u1680\u180e\u2000-\u2029\u205f\u3000]")
DOCTYPE_NAME = re.compile(r"^html\Z", re.IGNORECASE | re.ASCII)
ELEMENT_MARKUP_PROBE = re.compile(r"<[/\w!]", re.ASCII)
COMMENT_MARKUP_PROBE = re.compile(r"<[/\w]", re.ASCII)
FALLBACK_TAG_CLOSE = re.compile(r"</no(script|embed|frames)", re.IGNORECASE | re.ASCII)
ATTR_VALUE_BREAKOUT = re.compile(
    r"((--!?|])>)|</(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)",
    re.IGNORECASE | re.ASCII,
)
LEADING_WHITESPACE = re.compile(r"^[\r\n\t ]+")

# String.prototype.trim() removes WhiteSpace and LineTerminator characters.
_JS_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009"
    "\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)

DOM_CLOBBER_NAMES = frozenset(DOM_CLOBBER_NAMES_LIST)
SANITIZE_NAMED_PROPS_PREFIX = "user-content-"

# HTML elements whose text children are serialized unescaped.
LITERAL_TEXT_ELEMENTS = frozenset(
    {"style", "script", "xmp", "iframe", "noembed", "noframes", "plaintext", "noscript"}
)
ALL_SVG_TAGS = frozenset(name.lower() for name in SVG_TAGS + SVG_FILTER_TAGS + SVG_DISALLOWED_TAGS)
ALL_MATHML_TAGS = frozenset(name.lower() for name in MATHML_TAGS + MATHML_DISALLOWED_TAGS)
MATHML_TEXT_INTEGRATION_POINTS = frozenset({"mi", "mo", "mn", "ms", "mtext"})
HTML_INTEGRATION_POINTS = frozenset({"annotation-xml"})
COMMON_SVG_AND_HTML_ELEMENTS = frozenset({"title", "style", "font", "a", "script"})
FALLBACK_ELEMENTS = frozenset({"noscript", "noembed", "noframes"})
ROOT_ELEMENTS = frozenset({"html", "head", "body"})

Removed = dict[str, str]


def _position(parent: Parent, node: Node, hint: int) -> int:
    """Index of ``node`` among its parent's children; ``hint`` is checked first."""
    if 0 <= hint < len(parent.children) and parent.children[hint] is node:
        return hint
    return parent.children.index(node)


def strip_template_expressions(value: str) -> str:
    """Replace mustache, ERB and template-literal syntax with a space."""
    value = MUSTACHE_EXPR.sub(" ", value)
    value = ERB_EXPR.sub(" ", value)
    return TMPLIT_EXPR.sub(" ", value)


class _Call:
    """State for one sanitize call: what was removed, in document order."""

    __slots__ = ("removed",)

    def __init__(self) -> None:
        self.removed: list[Removed] = []


class Sanitizer:
    """Runs DOMPurify's algorithm with one resolved configuration."""

    __slots__ = ("cfg",)

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    # ─── Entry point (DOMPurify.sanitize, string path) ─────────────────

    def sanitize(self, dirty: str) -> tuple[str, list[Removed]]:
        """Sanitize ``dirty``; returns the HTML and the removal records."""
        cfg = self.cfg
        call = _Call()
        if not dirty:
            dirty = "<!-->"
        if not cfg.safe_for_templates and not cfg.whole_document and "<" not in dirty:
            return dirty, call.removed

        try:
            root, doctype_name = self._init_document(dirty)
        except UnsupportedMarkup:
            # Markup whose parse5 tree cannot be reproduced is dropped whole:
            # removing everything is always at least as strict as DOMPurify.
            return "", call.removed
        if root is None:
            return "", call.removed
        if cfg.force_body and root.children:
            self._force_remove(call, root.children[0], 0, root)

        self._walk(call, root, in_template=False)

        html = outer_html(root) if cfg.whole_document else inner_html(root)
        if cfg.safe_for_templates and TMPL_MARKER_SERIALIZED.search(html):
            self._scrub_own_character_data(root)
            html = outer_html(root) if cfg.whole_document else inner_html(root)
        if (
            cfg.whole_document
            and "!doctype" in cfg.allowed_tags
            and doctype_name
            and DOCTYPE_NAME.search(doctype_name)
        ):
            html = f"<!DOCTYPE {doctype_name}>\n{html}"
        removed = [entry for entry in call.removed if entry.get("element") not in ROOT_ELEMENTS]
        return html, removed

    def _init_document(self, dirty: str) -> tuple[Optional[Element], Optional[str]]:
        """Parse ``dirty`` and return the walk root (body, or html for
        WHOLE_DOCUMENT), mirroring ``_initDocument``."""
        leading_whitespace = None
        if self.cfg.force_body:
            dirty = "<remove></remove>" + dirty
        else:
            match = LEADING_WHITESPACE.match(dirty)
            leading_whitespace = match.group(0) if match else None

        document = parse_document(dirty)
        html = document.html
        # document.body: the first <body> or <frameset> child of <html>.
        container = next(
            (
                child
                for child in html.children
                if isinstance(child, Element)
                and child.namespace == HTML_NS
                and child.name in ("body", "frameset")
            ),
            html,
        )
        if leading_whitespace:
            text = Text(leading_whitespace)
            text.parent = container
            container.children.insert(0, text)

        if self.cfg.whole_document:
            return html, document.doctype_name
        if isinstance(container, Element) and container.name == "body":
            return container, document.doctype_name
        # A frameset document has no <body>, so DOMPurify returns "".
        return None, None

    # ─── Tree walk (NodeIterator semantics) ────────────────────────────

    def _walk(self, call: _Call, root: Parent, *, in_template: bool) -> None:
        """Visit ``root`` (unless it is a fragment) and its descendants in tree
        order. A removed node's hoisted children take its place and are
        visited next, as with DOMPurify's NodeIterator."""
        if isinstance(root, Element):
            self._sanitize_node(call, root, -1, root, in_template)
        stack: list[list[Any]] = [[root, 0]]
        while stack:
            frame = stack[-1]
            parent, index = frame
            if index >= len(parent.children):
                stack.pop()
                if stack:
                    stack[-1][1] += 1
                continue
            node = parent.children[index]
            self._sanitize_node(call, node, index, root, in_template)
            if node.parent is not parent:
                continue  # removed: whatever now sits at `index` is next
            if isinstance(node, Element) and node.children:
                stack.append([node, 0])
            else:
                frame[1] = index + 1

    def _sanitize_node(
        self, call: _Call, node: Node, index: int, walk_root: Parent, in_template: bool
    ) -> None:
        self._sanitize_element(call, node, index, walk_root, in_template)
        if isinstance(node, Element):
            if node is walk_root or node.parent is not None:
                self._sanitize_attributes(call, node)
            if node.content is not None:
                self._sanitize_fragment(call, node.content)

    def _sanitize_fragment(self, call: _Call, fragment: Fragment) -> None:
        """``_sanitizeShadowDOM`` for template content."""
        self._walk(call, fragment, in_template=True)
        if self.cfg.safe_for_templates:
            self._scrub_own_character_data(fragment)

    # ─── Removal ───────────────────────────────────────────────────────

    def _force_remove(self, call: _Call, node: Node, index: int, walk_root: Parent) -> None:
        """Record and detach ``node`` (``index`` is its position, when known).
        The walk root is only recorded: DOMPurify detaches it from <html>, but
        keeps walking and serializing it."""
        call.removed.append({"element": node_name(node)})
        parent = node.parent
        if node is walk_root or parent is None:
            return
        del parent.children[_position(parent, node, index)]
        node.parent = None

    def _sanitize_disallowed_node(
        self, call: _Call, node: Node, index: int, tag: str, walk_root: Parent
    ) -> None:
        """Hoist the content of a disallowed node (KEEP_CONTENT), then remove it."""
        cfg = self.cfg
        parent = node.parent
        if (
            cfg.keep_content
            and tag not in cfg.forbid_contents
            and isinstance(node, Element)
            and node is not walk_root
            and node.children
            and parent is not None
        ):
            index = _position(parent, node, index)
            children = node.children
            node.children = []
            for child in children:
                child.parent = parent
            parent.children[index + 1:index + 1] = children
        self._force_remove(call, node, index, walk_root)

    # ─── Elements (_sanitizeElements) ──────────────────────────────────

    def _sanitize_element(
        self, call: _Call, node: Node, index: int, walk_root: Parent, in_template: bool
    ) -> None:
        cfg = self.cfg
        tag = node_name(node)

        if self._is_unsafe_node(node, tag, in_template):
            self._force_remove(call, node, index, walk_root)
            return

        if tag in cfg.forbid_tags or tag not in cfg.allowed_tags:
            self._sanitize_disallowed_node(call, node, index, tag, walk_root)
            return

        if isinstance(node, Element) and not self._check_valid_namespace(node):
            self._force_remove(call, node, index, walk_root)
            return

        if (
            tag in FALLBACK_ELEMENTS
            and isinstance(node, Element)
            and FALLBACK_TAG_CLOSE.search(inner_html(node, scripting=in_template))
        ):
            self._force_remove(call, node, index, walk_root)
            return

        if cfg.safe_for_templates and isinstance(node, Text):
            content = strip_template_expressions(node.data)
            if content != node.data:
                call.removed.append({"element": "#text"})
                node.data = content

    def _is_unsafe_node(self, node: Node, tag: str, in_template: bool) -> bool:
        """Structural threats that condemn a node regardless of allowlists."""
        if not self.cfg.safe_for_xml:
            return False
        if isinstance(node, Comment):
            return COMMENT_MARKUP_PROBE.search(node.data) is not None
        if not isinstance(node, Element):
            return False

        # mXSS via namespace confusion: markup-like text with no element children.
        if (
            node.children
            and not has_element_child(node)
            and ELEMENT_MARKUP_PROBE.search(text_content(node))
            and ELEMENT_MARKUP_PROBE.search(inner_html(node, scripting=in_template))
        ):
            return True

        # Literal-text elements holding an element child or markup-like text.
        return (
            tag in LITERAL_TEXT_ELEMENTS
            and node.namespace == HTML_NS
            and (has_element_child(node) or ELEMENT_MARKUP_PROBE.search(text_content(node)) is not None)
        )

    def _check_valid_namespace(self, element: Element) -> bool:
        """Whether a spec-compliant parser could have produced ``element``
        under its current parent (``_checkValidNamespace``)."""
        tag = element.name.lower()
        parent = element.parent
        if isinstance(parent, Element):
            parent_ns, parent_tag = parent.namespace, parent.name.lower()
        else:
            parent_ns, parent_tag = HTML_NS, "template"

        namespace = element.namespace
        if namespace == SVG_NS:
            if parent_ns == HTML_NS:
                return tag == "svg"
            if parent_ns == MATHML_NS:
                return tag == "svg" and (
                    parent_tag == "annotation-xml" or parent_tag in MATHML_TEXT_INTEGRATION_POINTS
                )
            return tag in ALL_SVG_TAGS

        if namespace == MATHML_NS:
            if parent_ns == HTML_NS:
                return tag == "math"
            if parent_ns == SVG_NS:
                return tag == "math" and parent_tag in HTML_INTEGRATION_POINTS
            return tag in ALL_MATHML_TAGS

        if namespace == HTML_NS:
            if parent_ns == SVG_NS and parent_tag not in HTML_INTEGRATION_POINTS:
                return False
            if parent_ns == MATHML_NS and parent_tag not in MATHML_TEXT_INTEGRATION_POINTS:
                return False
            return tag not in ALL_MATHML_TAGS and (
                tag in COMMON_SVG_AND_HTML_ELEMENTS or tag not in ALL_SVG_TAGS
            )

        return False

    # ─── Attributes (_sanitizeAttributes) ──────────────────────────────

    def _sanitize_attributes(self, call: _Call, element: Element) -> None:
        cfg = self.cfg
        attrs = element.attrs
        if not attrs:
            return
        lc_tag = element.name.lower()

        # Backwards over the attributes. Only the current one is ever removed
        # or rewritten, so iterating a snapshot matches the live NamedNodeMap.
        for name, init_value in reversed(list(attrs.items())):
            lc_name = name.lower()
            value = init_value if name == "value" else init_value.strip(_JS_WHITESPACE)
            recreated_named_prop = False

            if (
                cfg.sanitize_named_props
                and lc_name in ("id", "name")
                and not value.startswith(SANITIZE_NAMED_PROPS_PREFIX)
            ):
                # Remove, then re-create below with the prefixed value; the
                # re-created attribute moves to the end of the list.
                self._remove_attribute(call, element, name)
                value = SANITIZE_NAMED_PROPS_PREFIX + value
                recreated_named_prop = True

            if self._is_unsafe_attribute_value(name, value):
                self._remove_attribute(call, element, name)
                continue
            if not cfg.allow_self_close_in_attr and "/>" in value:
                self._remove_attribute(call, element, name)
                continue
            if cfg.safe_for_templates:
                value = strip_template_expressions(value)
            if not self._is_valid_attribute(lc_tag, lc_name, value):
                self._remove_attribute(call, element, name)
                continue

            if value != init_value:
                attrs[name] = value
                if recreated_named_prop:
                    call.removed.pop()

    def _remove_attribute(self, call: _Call, element: Element, name: str) -> None:
        call.removed.append({"attribute": name, "from": element.name.lower()})
        element.attrs.pop(name, None)
        # DOMPurify cannot remove `is` from a parsed element, so it empties it;
        # setAttribute appends the new attribute at the end.
        if name == "is":
            element.attrs["is"] = ""

    def _is_unsafe_attribute_value(self, name: str, value: str) -> bool:
        if self.cfg.safe_for_xml and ATTR_VALUE_BREAKOUT.search(value):
            return True
        return name.lower() == "attributename" and "href" in value

    def _is_valid_attribute(self, lc_tag: str, lc_name: str, value: str) -> bool:
        cfg = self.cfg
        if lc_name in cfg.forbid_attr:
            return False
        # Patch-linkage attributes of declarative partial updates.
        if cfg.safe_for_xml and (
            lc_name == "patchsrc" or (lc_name == "for" and lc_tag not in ("label", "output"))
        ):
            return False
        # DOM clobbering: id/name values that shadow document or form properties.
        if cfg.sanitize_dom and lc_name in ("id", "name") and value in DOM_CLOBBER_NAMES:
            return False

        if cfg.allow_data_attr and DATA_ATTR.search(lc_name):
            return True
        if cfg.allow_aria_attr and ARIA_ATTR.search(lc_name):
            return True
        if lc_name not in cfg.allowed_attr:
            return False
        if lc_name in cfg.uri_safe_attributes:
            return True

        compact_value = ATTR_WHITESPACE.sub("", value)
        if cfg.allowed_uri.search(compact_value):
            return True
        if (
            lc_name in ("src", "xlink:href", "href")
            and lc_tag != "script"
            and value.startswith("data:")
            and lc_tag in cfg.data_uri_tags
        ):
            return True
        if cfg.allow_unknown_protocols and not IS_SCRIPT_OR_DATA.search(compact_value):
            return True
        return not value

    # ─── SAFE_FOR_TEMPLATES (_scrubOwnCharacterData) ───────────────────

    def _scrub_own_character_data(self, root: Parent) -> None:
        """``normalize()`` the subtree, then strip template expressions from
        every text and comment node. Template contents are not entered."""
        stack: list[Parent] = [root]
        while stack:
            parent = stack.pop()
            merged: list[Node] = []
            for child in parent.children:
                if isinstance(child, Text):
                    if not child.data:
                        child.parent = None
                        continue
                    previous = merged[-1] if merged else None
                    if isinstance(previous, Text):
                        previous.data += child.data
                        child.parent = None
                        continue
                merged.append(child)
            parent.children = merged
            for child in merged:
                if isinstance(child, (Text, Comment)):
                    child.data = strip_template_expressions(child.data)
                else:
                    stack.append(child)
