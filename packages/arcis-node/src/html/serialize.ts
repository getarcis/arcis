/**
 * HTML fragment serialization, as jsdom performs it for `innerHTML` and
 * `outerHTML` (parse5 8.1 serializer, entities 9 escaping). Kept local so
 * the output does not depend on which parse5 release is installed.
 */
import {
  type ElementNode,
  type TextNode,
  type TreeNode,
  HTML_NAMESPACE,
  isComment,
  isElement,
  isText,
  qualifiedName,
} from './tree';

const VOID_ELEMENTS: ReadonlySet<string> = new Set([
  'area', 'base', 'basefont', 'bgsound', 'br', 'col', 'embed', 'frame', 'hr', 'img', 'input',
  'keygen', 'link', 'meta', 'param', 'source', 'track', 'wbr',
]);

const UNESCAPED_TEXT_ELEMENTS: ReadonlySet<string> = new Set([
  'style', 'script', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext',
]);

function escapeText(value: string): string {
  return value.replace(/[&<>\u00A0]/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      default:
        return '&nbsp;';
    }
  });
}

function escapeAttribute(value: string): string {
  return value.replace(/["&<>\u00A0]/g, (char) => {
    switch (char) {
      case '"':
        return '&quot;';
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      default:
        return '&nbsp;';
    }
  });
}

function isVoidElement(element: ElementNode): boolean {
  return element.namespaceURI === HTML_NAMESPACE && VOID_ELEMENTS.has(element.localName);
}

/** The node whose children are serialized as `element`'s content. */
function contentContainer(element: ElementNode): TreeNode {
  if (element.namespaceURI === HTML_NAMESPACE && element.localName === 'template' && element.content) {
    return element.content;
  }
  return element;
}

function serializeText(node: TextNode, scriptingEnabled: boolean): string {
  const parent = node.parentNode;
  if (isElement(parent) && parent.namespaceURI === HTML_NAMESPACE) {
    const name = parent.localName;
    if (UNESCAPED_TEXT_ELEMENTS.has(name) || (scriptingEnabled && name === 'noscript')) {
      return node.data;
    }
  }
  return escapeText(node.data);
}

/**
 * Serializes `first` and, unless `single`, its following siblings. Uses an
 * explicit stack, so deeply nested input cannot overflow the call stack.
 */
function serializeNodes(first: TreeNode | null, single: boolean, scriptingEnabled: boolean): string {
  let html = '';
  const open: Array<{ resume: TreeNode | null; endTag: string }> = [];
  let cursor = first;
  for (;;) {
    if (!cursor) {
      const parent = open.pop();
      if (!parent) {
        return html;
      }
      html += parent.endTag;
      cursor = parent.resume;
      continue;
    }
    const node: TreeNode = cursor;
    cursor = single && open.length === 0 ? null : node.nextSibling;
    if (isElement(node)) {
      const name = node.localName;
      html += `<${name}`;
      for (const attr of node.attributes) {
        html += ` ${qualifiedName(attr)}="${escapeAttribute(attr.value)}"`;
      }
      html += '>';
      if (!isVoidElement(node)) {
        open.push({ resume: cursor, endTag: `</${name}>` });
        cursor = contentContainer(node).firstChild;
      }
    } else if (isText(node)) {
      html += serializeText(node, scriptingEnabled);
    } else if (isComment(node)) {
      html += `<!--${node.data}-->`;
    }
  }
}

/** `innerHTML` of an element or fragment. */
export function serializeChildren(node: TreeNode, scriptingEnabled: boolean): string {
  if (isElement(node)) {
    if (isVoidElement(node)) {
      return '';
    }
    return serializeNodes(contentContainer(node).firstChild, false, scriptingEnabled);
  }
  return serializeNodes(node.firstChild, false, scriptingEnabled);
}

/** `outerHTML` of an element. */
export function serializeOuter(node: ElementNode, scriptingEnabled: boolean): string {
  return serializeNodes(node, true, scriptingEnabled);
}
