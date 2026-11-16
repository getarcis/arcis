/**
 * Parses markup into the local tree with parse5, configured the way jsdom's
 * `DOMParser.parseFromString(markup, 'text/html')` configures it: scripting
 * disabled, and a tree adapter that behaves like jsdom's (attributes are
 * copied per element, and a repeated `<html>` or `<body>` tag overwrites
 * existing attribute values, as jsdom's adoptAttributes does).
 */
import type { TreeAdapter, TreeAdapterTypeMap, Token, html } from 'parse5';
import { parse } from './load-parse5';
import {
  type TreeNode,
  CommentNode,
  DOCUMENT_TYPE_NODE,
  DoctypeNode,
  DocumentNode,
  ElementNode,
  FragmentNode,
  HTML_NAMESPACE,
  TextNode,
  detach,
  isComment,
  isElement,
  isText,
  link,
  qualifiedName,
  setAttributeValue,
} from './tree';

type TreeMap = TreeAdapterTypeMap<
  TreeNode,
  TreeNode,
  TreeNode,
  DocumentNode,
  FragmentNode,
  ElementNode,
  CommentNode,
  TextNode,
  ElementNode,
  DoctypeNode
>;

function insertBefore(parent: TreeNode, node: TreeNode, reference: TreeNode | null): void {
  detach(node);
  link(parent, node, reference);
}

function adoptAttributes(element: ElementNode, attrs: Token.Attribute[]): void {
  for (const attr of attrs) {
    const prefix = attr.prefix === undefined || attr.prefix === '' ? null : attr.prefix;
    setAttributeValue(element, attr.name, attr.value, prefix, attr.namespace ?? null);
  }
}

function childNodes(node: TreeNode): TreeNode[] {
  const children: TreeNode[] = [];
  for (let child = node.firstChild; child; child = child.nextSibling) {
    children.push(child);
  }
  return children;
}

const treeAdapter: TreeAdapter<TreeMap> = {
  createDocument: () => new DocumentNode(),
  createDocumentFragment: () => new FragmentNode(),
  createElement(tagName, namespaceURI, attrs) {
    const element = new ElementNode(tagName, namespaceURI);
    if (tagName === 'template' && namespaceURI === HTML_NAMESPACE) {
      element.content = new FragmentNode();
    }
    adoptAttributes(element, attrs);
    return element;
  },
  createCommentNode: (data) => new CommentNode(data),
  createTextNode: (value) => new TextNode(value),

  appendChild: (parent, node) => insertBefore(parent, node, null),
  insertBefore,
  setTemplateContent(template, content) {
    template.content = content;
  },
  getTemplateContent(template) {
    template.content ??= new FragmentNode();
    return template.content;
  },
  setDocumentType(document, name, publicId, systemId) {
    insertBefore(document, new DoctypeNode(name, publicId, systemId), null);
  },
  setDocumentMode(document, mode) {
    document.mode = mode;
  },
  getDocumentMode: (document) => document.mode as html.DOCUMENT_MODE,
  detachNode: detach,
  insertText(parent, text) {
    const last = parent.lastChild;
    if (isText(last)) {
      last.data += text;
    } else {
      insertBefore(parent, new TextNode(text), null);
    }
  },
  insertTextBefore(parent, text, reference) {
    const previous = reference.previousSibling;
    if (isText(previous)) {
      previous.data += text;
    } else {
      insertBefore(parent, new TextNode(text), reference);
    }
  },
  adoptAttributes,

  getFirstChild: (node) => node.firstChild,
  getChildNodes: childNodes,
  getParentNode: (node) => node.parentNode,
  getAttrList: (element) =>
    element.attributes.map((attr) => ({ name: qualifiedName(attr), value: attr.value })),

  getTagName: (element) => element.localName,
  getNamespaceURI: (element) => element.namespaceURI as html.NS,
  getTextNodeContent: (node) => node.data,
  getCommentNodeContent: (node) => node.data,
  getDocumentTypeNodeName: (node) => node.name,
  getDocumentTypeNodePublicId: (node) => node.publicId,
  getDocumentTypeNodeSystemId: (node) => node.systemId,

  isTextNode: (node): node is TextNode => isText(node),
  isCommentNode: (node): node is CommentNode => isComment(node),
  isDocumentTypeNode: (node): node is DoctypeNode => node.nodeType === DOCUMENT_TYPE_NODE,
  isElementNode: (node): node is ElementNode => isElement(node),

  setNodeSourceCodeLocation: () => undefined,
  getNodeSourceCodeLocation: () => undefined,
  updateNodeSourceCodeLocation: () => undefined,
};

/** Parses a complete HTML document from `markup`. */
export function parseDocument(markup: string): DocumentNode {
  return parse<TreeMap>(markup, { scriptingEnabled: false, treeAdapter });
}
