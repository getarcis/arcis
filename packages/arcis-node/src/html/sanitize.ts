/**
 * The sanitizer: a port of DOMPurify 3.4.18's string path (`sanitize` with
 * string input and string output) onto the local tree. Function and step
 * names follow DOMPurify's `src/purify.ts` so the two can be read side by
 * side. Paths that only exist for DOM input or output (IN_PLACE, RETURN_DOM,
 * shadow roots, Trusted Types, hooks, custom element handling) are omitted.
 *
 * Two DOMPurify checks have no counterpart here. `_isClobbered` guards DOM
 * method and property reads that named form controls can shadow; this tree
 * is plain data, and jsdom (the reference) has no form named properties, so
 * no element is ever clobbered. Processing instructions and CDATA sections
 * cannot come out of the HTML parser, so their branches never apply.
 */
import type { CompiledConfig } from './config';
import { CLOBBERABLE_NAMES } from './dom-names';
import {
  ALL_MATHML_TAGS,
  ALL_SVG_TAGS,
  ARIA_ATTR,
  ATTR_VALUE_BREAKOUT,
  ATTR_WHITESPACE,
  COMMENT_MARKUP_PROBE,
  COMMON_SVG_AND_HTML_ELEMENTS,
  DATA_ATTR,
  DOCTYPE_NAME,
  ELEMENT_MARKUP_PROBE,
  ERB_EXPR,
  FALLBACK_TAG_CLOSE,
  HTML_INTEGRATION_POINTS,
  IS_SCRIPT_OR_DATA,
  LEADING_WHITESPACE,
  LITERAL_TEXT_ELEMENTS,
  MATHML_TEXT_INTEGRATION_POINTS,
  MUSTACHE_EXPR,
  SANITIZE_NAMED_PROPS_PREFIX,
  SELF_CLOSING_TAG,
  TMPLIT_EXPR,
  TMPL_MARKER_SERIALIZED,
} from './lists';
import { parseDocument } from './parse';
import { serializeChildren, serializeOuter } from './serialize';
import {
  type Attr,
  type DoctypeNode,
  type DocumentNode,
  type ElementNode,
  type FragmentNode,
  type TreeNode,
  DOCUMENT_FRAGMENT_NODE,
  DOCUMENT_NODE,
  DOCUMENT_TYPE_NODE,
  HTML_NAMESPACE,
  InvalidNameError,
  MATHML_NAMESPACE,
  NodeIterator,
  SVG_NAMESPACE,
  TextNode,
  detach,
  firstElementChild,
  getAttributeNode,
  isComment,
  isElement,
  isText,
  link,
  nextInTree,
  nodeName,
  qualifiedName,
  removeAttribute,
  removeAttributeNode,
  rootOf,
  setAttribute,
  setAttributeNS,
  textContent,
} from './tree';

/** Something the sanitizer dropped, in document order. */
export type HtmlRemovedItem =
  | { readonly element: string }
  | { readonly attribute: string; readonly from: string };

/** Output of one sanitizer run. */
export interface SanitizeOutput {
  readonly html: string;
  readonly removed: HtmlRemovedItem[];
}

/** Sanitizes `dirty` with a compiled configuration. */
export function sanitizeString(dirty: string, config: CompiledConfig): SanitizeOutput {
  return new SanitizeRun(config).run(dirty);
}

/** Replaces template expressions with a space: mustache, then ERB, then template literal. */
function stripTemplateExpressions(value: string): string {
  return value.replace(MUSTACHE_EXPR, ' ').replace(ERB_EXPR, ' ').replace(TMPLIT_EXPR, ' ');
}

function lowercaseName(node: TreeNode): string {
  return nodeName(node).toLowerCase();
}

/** Document.body: the html element's first body or frameset child. */
function bodyElement(document: DocumentNode): ElementNode | null {
  const html = firstElementChild(document);
  if (!html || html.namespaceURI !== HTML_NAMESPACE || html.localName !== 'html') {
    return null;
  }
  for (let child = html.firstChild; child; child = child.nextSibling) {
    if (
      isElement(child) &&
      child.namespaceURI === HTML_NAMESPACE &&
      (child.localName === 'body' || child.localName === 'frameset')
    ) {
      return child;
    }
  }
  return null;
}

/** Document.getElementsByTagName(name)[0] for a lowercase `name` in an HTML document. */
function firstElementByTagName(document: DocumentNode, name: string): ElementNode | null {
  for (let node = nextInTree(document, document); node; node = nextInTree(node, document)) {
    if (isElement(node) && node.localName === name) {
      return node;
    }
  }
  return null;
}

function doctypeOf(document: DocumentNode): DoctypeNode | null {
  for (let child = document.firstChild; child; child = child.nextSibling) {
    if (child.nodeType === DOCUMENT_TYPE_NODE) {
      return child as DoctypeNode;
    }
  }
  return null;
}

/** State of one `sanitize` call: the removed list and the live node iterators. */
class SanitizeRun {
  private readonly removed: HtmlRemovedItem[] = [];
  private readonly iterators: NodeIterator[] = [];

  constructor(private readonly cfg: CompiledConfig) {}

  run(input: string): SanitizeOutput {
    const { cfg } = this;
    // DOMPurify parses empty input as an empty comment.
    const dirty = input || '<!-->';

    // Exit directly if there is nothing to do.
    if (!cfg.safeForTemplates && !cfg.wholeDocument && dirty.indexOf('<') === -1) {
      return { html: dirty, removed: [] };
    }

    const document = this.initDocument(dirty);
    const root = firstElementByTagName(document, cfg.wholeDocument ? 'html' : 'body');
    if (!root) {
      return { html: '', removed: [] };
    }

    // Remove the <remove> element FORCE_BODY put first.
    if (cfg.forceBody && root.firstChild) {
      this.forceRemove(root.firstChild);
    }

    this.walk(root);

    const serialize = (): string =>
      cfg.wholeDocument ? serializeOuter(root, false) : serializeChildren(root, false);
    let html = serialize();

    // An expression can form across text nodes once a separating element is
    // removed, so scrub the tree again when the output holds a marker.
    if (cfg.safeForTemplates && TMPL_MARKER_SERIALIZED.test(html)) {
      this.scrubOwnCharacterData(root);
      html = serialize();
    }

    const doctype = doctypeOf(document);
    if (
      cfg.wholeDocument &&
      cfg.allowedTags.has('!doctype') &&
      doctype &&
      doctype.name &&
      DOCTYPE_NAME.test(doctype.name)
    ) {
      html = `<!DOCTYPE ${doctype.name}>\n${html}`;
    }

    return { html, removed: this.removed };
  }

  // ─── Document setup ─────────────────────────────────────────────────

  /** _initDocument: parse like DOMParser and preserve leading whitespace. */
  private initDocument(dirty: string): DocumentNode {
    let markup = dirty;
    let leadingWhitespace: string | null = null;
    if (this.cfg.forceBody) {
      markup = `<remove></remove>${markup}`;
    } else {
      // The parser drops leading whitespace, so it is put back by hand.
      const match = LEADING_WHITESPACE.exec(markup);
      leadingWhitespace = match ? match[0] : null;
    }

    const document = parseDocument(markup);
    if (leadingWhitespace) {
      const target = bodyElement(document) ?? firstElementChild(document);
      if (target) {
        this.insertBefore(target, new TextNode(leadingWhitespace), target.firstChild);
      }
    }
    return document;
  }

  // ─── Tree mutation with iterator bookkeeping ────────────────────────

  private removeNode(node: TreeNode): void {
    if (!node.parentNode) {
      return;
    }
    for (const iterator of this.iterators) {
      iterator.preRemove(node);
    }
    detach(node);
  }

  private insertBefore(parent: TreeNode, node: TreeNode, reference: TreeNode | null): void {
    this.removeNode(node);
    link(parent, node, reference);
  }

  /** _forceRemove */
  private forceRemove(node: TreeNode): void {
    this.removed.push({ element: lowercaseName(node) });
    this.removeNode(node);
  }

  // ─── Walk ───────────────────────────────────────────────────────────

  /** Sanitizes every node under `root` (root included unless it is a fragment). */
  private walk(root: TreeNode): void {
    const iterator = new NodeIterator(root);
    this.iterators.push(iterator);
    for (let node = iterator.nextNode(); node; node = iterator.nextNode()) {
      this.sanitizeNode(node, root);
    }
    this.iterators.pop();
  }

  /** _sanitizeNode: the node, its attributes and, for a template, its content. */
  private sanitizeNode(node: TreeNode, root: TreeNode): void {
    this.sanitizeElements(node, root);
    this.sanitizeAttributes(node, root);
    // Template content is sanitized even when the template was removed.
    if (isElement(node) && node.content) {
      this.sanitizeTemplateContent(node.content);
    }
  }

  /** _sanitizeShadowDOM, as used for template content. */
  private sanitizeTemplateContent(fragment: FragmentNode): void {
    this.walk(fragment);
    if (this.cfg.safeForTemplates) {
      this.scrubOwnCharacterData(fragment);
    }
  }

  // ─── Elements ───────────────────────────────────────────────────────

  /** innerHTML, serialized with the scripting flag of the node's document. */
  private innerHTML(node: TreeNode): string {
    // Template content lives in an inert document without jsdom's
    // scripting-disabled parse options, so it serializes with scripting on.
    const inTemplateContent = rootOf(node).nodeType === DOCUMENT_FRAGMENT_NODE;
    return serializeChildren(node, inTemplateContent);
  }

  /** _sanitizeElements */
  private sanitizeElements(node: TreeNode, root: TreeNode): void {
    const { cfg } = this;
    const tagName = lowercaseName(node);

    // Remove mXSS vectors and risky comments.
    if (this.isUnsafeNode(node, tagName)) {
      this.forceRemove(node);
      return;
    }

    // Remove the element if anything forbids its presence.
    if (cfg.forbidTags.has(tagName) || !cfg.allowedTags.has(tagName)) {
      this.sanitizeDisallowedNode(node, tagName, root);
      return;
    }

    // Remove elements a spec-compliant parser could not have produced here.
    if (isElement(node) && !this.checkValidNamespace(node)) {
      this.forceRemove(node);
      return;
    }

    // Fallback-tag mXSS in older browsers.
    if (
      (tagName === 'noscript' || tagName === 'noembed' || tagName === 'noframes') &&
      FALLBACK_TAG_CLOSE.test(this.innerHTML(node))
    ) {
      this.forceRemove(node);
      return;
    }

    if (cfg.safeForTemplates && isText(node)) {
      const content = stripTemplateExpressions(node.data);
      if (content !== node.data) {
        this.removed.push({ element: '#text' });
        node.data = content;
      }
    }
  }

  /** _isUnsafeNode: structural threats, regardless of the allowlists. */
  private isUnsafeNode(node: TreeNode, tagName: string): boolean {
    if (!this.cfg.safeForXml) {
      return false;
    }
    if (isComment(node)) {
      return COMMENT_MARKUP_PROBE.test(node.data);
    }
    if (!isElement(node)) {
      return false;
    }

    // Namespace confusion: markup-like text with no element children.
    if (
      node.firstChild &&
      !firstElementChild(node) &&
      ELEMENT_MARKUP_PROBE.test(textContent(node)) &&
      ELEMENT_MARKUP_PROBE.test(this.innerHTML(node))
    ) {
      return true;
    }

    // Literal-text elements holding an element child or markup-like text.
    return (
      LITERAL_TEXT_ELEMENTS.has(tagName) &&
      node.namespaceURI === HTML_NAMESPACE &&
      (firstElementChild(node) !== null || ELEMENT_MARKUP_PROBE.test(textContent(node)))
    );
  }

  /** _sanitizeDisallowedNode: hoist the content per KEEP_CONTENT, then remove. */
  private sanitizeDisallowedNode(node: TreeNode, tagName: string, root: TreeNode): void {
    const parent = node.parentNode;
    if (this.cfg.keepContent && !this.cfg.forbidContents.has(tagName) && parent) {
      if (node === root) {
        // DOMPurify copies the walk root's children next to the root, outside
        // the serialized subtree, so the output is unchanged. When the root's
        // parent is the document (WHOLE_DOCUMENT with html forbidden) the copy
        // is invalid and jsdom throws; so does this port.
        if (parent.nodeType === DOCUMENT_NODE && this.hasElementOrText(node)) {
          throw new Error(
            'HierarchyRequestError: cannot keep the content of the document element ' +
              '(FORBID_TAGS contains html while WHOLE_DOCUMENT and KEEP_CONTENT are on)',
          );
        }
      } else {
        // Move the children up, tail to head, right after the node.
        while (node.lastChild) {
          this.insertBefore(parent, node.lastChild, node.nextSibling);
        }
      }
    }
    this.forceRemove(node);
  }

  private hasElementOrText(node: TreeNode): boolean {
    for (let child = node.firstChild; child; child = child.nextSibling) {
      if (isElement(child) || isText(child)) {
        return true;
      }
    }
    return false;
  }

  /** _checkValidNamespace */
  private checkValidNamespace(element: ElementNode): boolean {
    const namespace = element.namespaceURI;
    const tagName = lowercaseName(element);

    // A non-element parent is treated as an HTML <template>.
    const parent = element.parentNode;
    let parentNamespace = HTML_NAMESPACE;
    let parentTagName = 'template';
    if (isElement(parent)) {
      parentNamespace = parent.namespaceURI;
      parentTagName = lowercaseName(parent);
    }

    if (namespace === SVG_NAMESPACE) {
      // Only <svg> switches from HTML to SVG, and from MathML only at an
      // annotation-xml or a MathML text integration point.
      if (parentNamespace === HTML_NAMESPACE) {
        return tagName === 'svg';
      }
      if (parentNamespace === MATHML_NAMESPACE) {
        return (
          tagName === 'svg' &&
          (parentTagName === 'annotation-xml' || MATHML_TEXT_INTEGRATION_POINTS.has(parentTagName))
        );
      }
      return ALL_SVG_TAGS.has(tagName);
    }

    if (namespace === MATHML_NAMESPACE) {
      // Only <math> switches from HTML to MathML, and from SVG only at an
      // HTML integration point.
      if (parentNamespace === HTML_NAMESPACE) {
        return tagName === 'math';
      }
      if (parentNamespace === SVG_NAMESPACE) {
        return tagName === 'math' && HTML_INTEGRATION_POINTS.has(parentTagName);
      }
      return ALL_MATHML_TAGS.has(tagName);
    }

    if (namespace === HTML_NAMESPACE) {
      if (parentNamespace === SVG_NAMESPACE && !HTML_INTEGRATION_POINTS.has(parentTagName)) {
        return false;
      }
      if (
        parentNamespace === MATHML_NAMESPACE &&
        !MATHML_TEXT_INTEGRATION_POINTS.has(parentTagName)
      ) {
        return false;
      }
      // SVG- and MathML-only names never belong to the HTML namespace.
      return (
        !ALL_MATHML_TAGS.has(tagName) &&
        (COMMON_SVG_AND_HTML_ELEMENTS.has(tagName) || !ALL_SVG_TAGS.has(tagName))
      );
    }

    return false;
  }

  // ─── Attributes ─────────────────────────────────────────────────────

  /** _sanitizeAttributes */
  private sanitizeAttributes(node: TreeNode, root: TreeNode): void {
    // A removed node is skipped (DOMPurify's _handleHookDetachedNode); the walk root is exempt.
    if (!isElement(node) || (node !== root && node.parentNode === null)) {
      return;
    }
    const { cfg } = this;
    const attributes = node.attributes;
    const lcTag = lowercaseName(node);

    // Go backwards over the live list; removals only shift later entries.
    let index = attributes.length;
    while (index--) {
      const attr = attributes[index];
      const name = qualifiedName(attr);
      const { namespace } = attr;
      const initValue = attr.value;
      const lcName = name.toLowerCase();
      let value = name === 'value' ? initValue : initValue.trim();
      let recreatedNamedProp = false;

      // Namespace isolation: prefix id and name with `user-content-`.
      if (
        cfg.sanitizeNamedProps &&
        (lcName === 'id' || lcName === 'name') &&
        value.indexOf(SANITIZE_NAMED_PROPS_PREFIX) !== 0
      ) {
        this.removeAttribute(name, node, attr);
        value = SANITIZE_NAMED_PROPS_PREFIX + value;
        recreatedNamedProp = true;
      }

      if (this.isUnsafeAttributeValue(name, value)) {
        this.removeAttribute(name, node, attr);
        continue;
      }

      // jQuery 3.0 mXSS through self-closing tags in attribute values.
      if (!cfg.allowSelfCloseInAttr && SELF_CLOSING_TAG.test(value)) {
        this.removeAttribute(name, node, attr);
        continue;
      }

      if (cfg.safeForTemplates) {
        value = stripTemplateExpressions(value);
      }

      if (!this.isValidAttribute(lcTag, lcName, value)) {
        this.removeAttribute(name, node, attr);
        continue;
      }

      if (value !== initValue) {
        const cleanWrite = this.setAttributeValue(node, name, namespace, value);
        // The recreated named prop is not a removal after all.
        if (cleanWrite && recreatedNamedProp) {
          this.removed.pop();
        }
      }
    }
  }

  /** _removeAttribute: record, remove, and blank an `is` attribute instead of dropping it. */
  private removeAttribute(name: string, element: ElementNode, attr: Attr): void {
    this.removed.push({ attribute: qualifiedName(attr), from: lowercaseName(element) });
    if (!removeAttributeNode(element, attr)) {
      removeAttribute(element, name);
    }
    if (name === 'is') {
      setAttribute(element, name, '');
    }
  }

  /** _setAttributeValue: write back a changed value; drop the attribute if the write fails. */
  private setAttributeValue(
    element: ElementNode,
    name: string,
    namespace: string | null,
    value: string,
  ): boolean {
    try {
      if (namespace) {
        setAttributeNS(element, namespace, name, value);
      } else {
        setAttribute(element, name, value);
      }
      return true;
    } catch (error) {
      if (!(error instanceof InvalidNameError)) {
        throw error;
      }
      const attr = getAttributeNode(element, name);
      if (attr) {
        this.removeAttribute(name, element, attr);
      }
      return false;
    }
  }

  /** _isUnsafeAttributeValue */
  private isUnsafeAttributeValue(name: string, value: string): boolean {
    // Comment closers and raw-text end tags re-contextualize on reparse.
    if (this.cfg.safeForXml && ATTR_VALUE_BREAKOUT.test(value)) {
      return true;
    }
    // No animated hrefs, even where animations are allowed.
    return name.toLowerCase() === 'attributename' && value.indexOf('href') !== -1;
  }

  /** _isValidAttribute */
  private isValidAttribute(lcTag: string, lcName: string, value: string): boolean {
    const { cfg } = this;
    if (cfg.forbidAttr.has(lcName)) {
      return false;
    }

    // Patch-linkage attributes of declarative partial updates.
    if (
      cfg.safeForXml &&
      (lcName === 'patchsrc' || (lcName === 'for' && lcTag !== 'label' && lcTag !== 'output'))
    ) {
      return false;
    }

    // An id or name that could clobber a document or form property.
    if (cfg.sanitizeDom && (lcName === 'id' || lcName === 'name') && CLOBBERABLE_NAMES.has(value)) {
      return false;
    }

    // data-* and aria-* values are always URI safe.
    if (cfg.allowDataAttr && DATA_ATTR.test(lcName)) {
      return true;
    }
    if (cfg.allowAriaAttr && ARIA_ATTR.test(lcName)) {
      return true;
    }
    if (!cfg.allowedAttr.has(lcName)) {
      return false;
    }
    if (cfg.uriSafeAttributes.has(lcName)) {
      return true;
    }

    // No script, data or unknown URIs unless the attribute is URI safe.
    const compactValue = value.replace(ATTR_WHITESPACE, '');
    cfg.allowedUriRegexp.lastIndex = 0;
    if (cfg.allowedUriRegexp.test(compactValue)) {
      return true;
    }

    // Image-like data URIs, never on script.
    if (
      (lcName === 'src' || lcName === 'xlink:href' || lcName === 'href') &&
      lcTag !== 'script' &&
      value.indexOf('data:') === 0 &&
      cfg.dataUriTags.has(lcTag)
    ) {
      return true;
    }

    if (cfg.allowUnknownProtocols && !IS_SCRIPT_OR_DATA.test(compactValue)) {
      return true;
    }

    // Only an empty value remains safe.
    return !value;
  }

  // ─── SAFE_FOR_TEMPLATES ─────────────────────────────────────────────

  /** _scrubOwnCharacterData: normalize, then strip expressions from text and comments. */
  private scrubOwnCharacterData(node: TreeNode): void {
    this.normalize(node);
    for (let current = nextInTree(node, node); current; current = nextInTree(current, node)) {
      if (isText(current) || isComment(current)) {
        current.data = stripTemplateExpressions(current.data);
      }
    }
  }

  /** Node.normalize: drop empty text nodes and merge adjacent ones. */
  private normalize(node: TreeNode): void {
    let current = nextInTree(node, node);
    while (current) {
      const following = nextInTree(current, node);
      if (!isText(current)) {
        current = following;
        continue;
      }
      if (current.data.length === 0) {
        this.removeNode(current);
        current = following;
        continue;
      }
      let sibling = current.nextSibling;
      while (isText(sibling)) {
        const next: TreeNode | null = sibling.nextSibling;
        current.data += sibling.data;
        this.removeNode(sibling);
        sibling = next;
      }
      current = nextInTree(current, node);
    }
  }
}
