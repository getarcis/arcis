/**
 * A minimal document tree with the DOM semantics the sanitizer relies on:
 * sibling links, attribute lists, template contents and a NodeIterator that
 * follows the DOM's pre-removing steps. Behavior mirrors jsdom, the
 * reference environment, wherever jsdom and the DOM standard are observable
 * through DOMPurify.
 */

export const ELEMENT_NODE = 1;
export const TEXT_NODE = 3;
export const COMMENT_NODE = 8;
export const DOCUMENT_NODE = 9;
export const DOCUMENT_TYPE_NODE = 10;
export const DOCUMENT_FRAGMENT_NODE = 11;

export const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
export const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
export const MATHML_NAMESPACE = 'http://www.w3.org/1998/Math/MathML';
const XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace';
const XMLNS_NAMESPACE = 'http://www.w3.org/2000/xmlns/';

// ─── Nodes ──────────────────────────────────────────────────────────────

/** Base node: parent and sibling links plus first/last child. */
export class TreeNode {
  parentNode: TreeNode | null = null;
  previousSibling: TreeNode | null = null;
  nextSibling: TreeNode | null = null;
  firstChild: TreeNode | null = null;
  lastChild: TreeNode | null = null;

  constructor(readonly nodeType: number) {}
}

export interface Attr {
  readonly localName: string;
  readonly prefix: string | null;
  readonly namespace: string | null;
  value: string;
}

export class ElementNode extends TreeNode {
  readonly attributes: Attr[] = [];
  /** Template contents; set for HTML `template` elements only. */
  content: FragmentNode | null = null;

  constructor(
    readonly localName: string,
    readonly namespaceURI: string,
  ) {
    super(ELEMENT_NODE);
  }
}

export class TextNode extends TreeNode {
  constructor(public data: string) {
    super(TEXT_NODE);
  }
}

export class CommentNode extends TreeNode {
  constructor(public data: string) {
    super(COMMENT_NODE);
  }
}

export class DoctypeNode extends TreeNode {
  constructor(
    readonly name: string,
    readonly publicId: string,
    readonly systemId: string,
  ) {
    super(DOCUMENT_TYPE_NODE);
  }
}

export class FragmentNode extends TreeNode {
  constructor() {
    super(DOCUMENT_FRAGMENT_NODE);
  }
}

export class DocumentNode extends TreeNode {
  mode = 'no-quirks';

  constructor() {
    super(DOCUMENT_NODE);
  }
}

export function isElement(node: TreeNode | null): node is ElementNode {
  return node !== null && node.nodeType === ELEMENT_NODE;
}

export function isText(node: TreeNode | null): node is TextNode {
  return node !== null && node.nodeType === TEXT_NODE;
}

export function isComment(node: TreeNode | null): node is CommentNode {
  return node !== null && node.nodeType === COMMENT_NODE;
}

function asciiLowercase(value: string): string {
  return value.replace(/[A-Z]+/g, (match) => match.toLowerCase());
}

function asciiUppercase(value: string): string {
  return value.replace(/[a-z]+/g, (match) => match.toUpperCase());
}

/** The DOM `nodeName`: HTML element names are uppercased, as in an HTML document. */
export function nodeName(node: TreeNode): string {
  switch (node.nodeType) {
    case ELEMENT_NODE: {
      const element = node as ElementNode;
      return element.namespaceURI === HTML_NAMESPACE
        ? asciiUppercase(element.localName)
        : element.localName;
    }
    case TEXT_NODE:
      return '#text';
    case COMMENT_NODE:
      return '#comment';
    case DOCUMENT_NODE:
      return '#document';
    case DOCUMENT_FRAGMENT_NODE:
      return '#document-fragment';
    default:
      return (node as DoctypeNode).name;
  }
}

export function qualifiedName(attr: Attr): string {
  return attr.prefix === null ? attr.localName : `${attr.prefix}:${attr.localName}`;
}

// ─── Traversal ──────────────────────────────────────────────────────────

/** True if `node` is `ancestor` or one of its descendants. */
export function contains(ancestor: TreeNode, node: TreeNode): boolean {
  for (let current: TreeNode | null = node; current; current = current.parentNode) {
    if (current === ancestor) {
      return true;
    }
  }
  return false;
}

/** The node after `node`'s subtree in tree order, within `root`. */
export function nextAfterSubtree(node: TreeNode, root: TreeNode): TreeNode | null {
  for (let current: TreeNode | null = node; current; current = current.parentNode) {
    if (current === root) {
      return null;
    }
    if (current.nextSibling) {
      return current.nextSibling;
    }
  }
  return null;
}

/** The node following `node` in tree order, within `root`. */
export function nextInTree(node: TreeNode, root: TreeNode): TreeNode | null {
  return node.firstChild ?? nextAfterSubtree(node, root);
}

function lastInclusiveDescendant(node: TreeNode): TreeNode {
  let current = node;
  while (current.lastChild) {
    current = current.lastChild;
  }
  return current;
}

export function firstElementChild(node: TreeNode): ElementNode | null {
  for (let child = node.firstChild; child; child = child.nextSibling) {
    if (isElement(child)) {
      return child;
    }
  }
  return null;
}

/** The DOM `textContent` of an element or fragment: its descendant text, comments excluded. */
export function textContent(node: TreeNode): string {
  let text = '';
  for (let current = nextInTree(node, node); current; current = nextInTree(current, node)) {
    if (isText(current)) {
      text += current.data;
    }
  }
  return text;
}

/** The root of `node`'s tree: a document, a template contents fragment, or a detached node. */
export function rootOf(node: TreeNode): TreeNode {
  let current = node;
  while (current.parentNode) {
    current = current.parentNode;
  }
  return current;
}

// ─── Mutation ───────────────────────────────────────────────────────────

/** Unlinks `node` from its parent. Callers that walk the tree notify iterators first. */
export function detach(node: TreeNode): void {
  const parent = node.parentNode;
  if (!parent) {
    return;
  }
  if (node.previousSibling) {
    node.previousSibling.nextSibling = node.nextSibling;
  } else {
    parent.firstChild = node.nextSibling;
  }
  if (node.nextSibling) {
    node.nextSibling.previousSibling = node.previousSibling;
  } else {
    parent.lastChild = node.previousSibling;
  }
  node.parentNode = null;
  node.previousSibling = null;
  node.nextSibling = null;
}

/** Links a parentless `node` into `parent` before `reference` (or last when null). */
export function link(parent: TreeNode, node: TreeNode, reference: TreeNode | null): void {
  const previous = reference ? reference.previousSibling : parent.lastChild;
  node.parentNode = parent;
  node.previousSibling = previous;
  node.nextSibling = reference;
  if (previous) {
    previous.nextSibling = node;
  } else {
    parent.firstChild = node;
  }
  if (reference) {
    reference.previousSibling = node;
  } else {
    parent.lastChild = node;
  }
}

// ─── Attributes (jsdom semantics) ───────────────────────────────────────

/** Element.getAttributeNode: first attribute with this qualified name. */
export function getAttributeNode(element: ElementNode, name: string): Attr | null {
  const wanted = element.namespaceURI === HTML_NAMESPACE ? asciiLowercase(name) : name;
  return element.attributes.find((attr) => qualifiedName(attr) === wanted) ?? null;
}

/** Element.removeAttributeNode; returns false where the DOM throws NotFoundError. */
export function removeAttributeNode(element: ElementNode, attr: Attr): boolean {
  const index = element.attributes.indexOf(attr);
  if (index === -1) {
    return false;
  }
  element.attributes.splice(index, 1);
  return true;
}

/** Element.removeAttribute. */
export function removeAttribute(element: ElementNode, name: string): void {
  const attr = getAttributeNode(element, name);
  if (attr) {
    removeAttributeNode(element, attr);
  }
}

/** The DOM's "set an attribute value": match on namespace and local name, else append. */
export function setAttributeValue(
  element: ElementNode,
  localName: string,
  value: string,
  prefix: string | null,
  namespace: string | null,
): void {
  const existing = element.attributes.find(
    (attr) => attr.namespace === namespace && attr.localName === localName,
  );
  if (existing) {
    existing.value = value;
    return;
  }
  element.attributes.push({ localName, prefix, namespace, value });
}

/** Error thrown where the DOM throws an InvalidCharacterError or NamespaceError. */
export class InvalidNameError extends Error {}

const INVALID_ATTRIBUTE_LOCAL_NAME = /[\0\t\n\f\r /=>]/;
const INVALID_NAMESPACE_PREFIX = /[\0\t\n\f\r />]/;

function assertAttributeLocalName(name: string): void {
  if (name.length === 0 || INVALID_ATTRIBUTE_LOCAL_NAME.test(name)) {
    throw new InvalidNameError(`"${name}" is not a valid attribute local name`);
  }
}

/** Element.setAttribute. Throws InvalidNameError where the DOM throws. */
export function setAttribute(element: ElementNode, name: string, value: string): void {
  assertAttributeLocalName(name);
  const qualified = element.namespaceURI === HTML_NAMESPACE ? asciiLowercase(name) : name;
  const existing = element.attributes.find((attr) => qualifiedName(attr) === qualified);
  if (existing) {
    existing.value = value;
    return;
  }
  element.attributes.push({ localName: qualified, prefix: null, namespace: null, value });
}

/** Element.setAttributeNS, with the DOM's "validate and extract". */
export function setAttributeNS(
  element: ElementNode,
  namespace: string,
  name: string,
  value: string,
): void {
  let prefix: string | null = null;
  let localName = name;
  const colon = name.indexOf(':');
  if (colon !== -1) {
    prefix = name.slice(0, colon);
    localName = name.slice(colon + 1);
    if (prefix.length === 0 || INVALID_NAMESPACE_PREFIX.test(prefix)) {
      throw new InvalidNameError(`"${prefix}" is not a valid namespace prefix`);
    }
  }
  assertAttributeLocalName(localName);
  const isXmlnsName = name === 'xmlns' || prefix === 'xmlns';
  if (
    (prefix === 'xml' && namespace !== XML_NAMESPACE) ||
    (isXmlnsName && namespace !== XMLNS_NAMESPACE) ||
    (namespace === XMLNS_NAMESPACE && !isXmlnsName)
  ) {
    throw new InvalidNameError(`"${name}" does not match namespace ${namespace}`);
  }
  setAttributeValue(element, localName, value, prefix, namespace);
}

// ─── NodeIterator ───────────────────────────────────────────────────────

/**
 * DOM NodeIterator over elements, text and comments (the node types
 * DOMPurify asks for that the HTML parser can produce). The owner calls
 * `preRemove` before any node is removed from the tree, which keeps the
 * iterator's position valid exactly as the DOM's pre-removing steps do.
 */
export class NodeIterator {
  private reference: TreeNode;
  private pointerBeforeReference = true;

  constructor(readonly root: TreeNode) {
    this.reference = root;
  }

  private static accepts(node: TreeNode): boolean {
    return (
      node.nodeType === ELEMENT_NODE || node.nodeType === TEXT_NODE || node.nodeType === COMMENT_NODE
    );
  }

  nextNode(): TreeNode | null {
    let node = this.reference;
    let beforeNode = this.pointerBeforeReference;
    for (;;) {
      if (beforeNode) {
        beforeNode = false;
      } else {
        const following = nextInTree(node, this.root);
        if (!following) {
          return null;
        }
        node = following;
      }
      if (NodeIterator.accepts(node)) {
        this.reference = node;
        this.pointerBeforeReference = false;
        return node;
      }
    }
  }

  preRemove(toBeRemoved: TreeNode): void {
    if (!contains(toBeRemoved, this.reference) || contains(toBeRemoved, this.root)) {
      return;
    }
    if (this.pointerBeforeReference) {
      const next = nextAfterSubtree(toBeRemoved, this.root);
      if (next) {
        this.reference = next;
        return;
      }
      this.pointerBeforeReference = false;
    }
    const previous = toBeRemoved.previousSibling;
    if (previous) {
      this.reference = lastInclusiveDescendant(previous);
    } else if (toBeRemoved.parentNode) {
      this.reference = toBeRemoved.parentNode;
    }
  }
}
