/**
 * Allowlists, defaults and patterns of the HTML sanitizer.
 *
 * Ported from DOMPurify 3.4.18 (src/tags.ts, src/attrs.ts, src/regexp.ts and
 * the defaults in src/purify.ts), (c) Cure53 and other contributors, Apache
 * License 2.0. See THIRDPARTY-LICENSES.md. Names are stored in lowercase, as
 * DOMPurify lowercases every list entry when it builds its lookup tables.
 */

// ─── Elements ───────────────────────────────────────────────────────────

export const HTML_TAGS: readonly string[] = [
  'a', 'abbr', 'acronym', 'address', 'area', 'article', 'aside', 'audio', 'b', 'bdi', 'bdo', 'big',
  'blink', 'blockquote', 'body', 'br', 'button', 'canvas', 'caption', 'center', 'cite', 'code',
  'col', 'colgroup', 'content', 'data', 'datalist', 'dd', 'decorator', 'del', 'details', 'dfn',
  'dialog', 'dir', 'div', 'dl', 'dt', 'element', 'em', 'fieldset', 'figcaption', 'figure', 'font',
  'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'head', 'header', 'hgroup', 'hr', 'html',
  'i', 'img', 'input', 'ins', 'kbd', 'label', 'legend', 'li', 'main', 'map', 'mark', 'marquee',
  'menu', 'menuitem', 'meter', 'nav', 'nobr', 'ol', 'optgroup', 'option', 'output', 'p', 'picture',
  'pre', 'progress', 'q', 'rp', 'rt', 'ruby', 's', 'samp', 'search', 'section', 'select', 'shadow',
  'slot', 'small', 'source', 'spacer', 'span', 'strike', 'strong', 'style', 'sub', 'summary', 'sup',
  'table', 'tbody', 'td', 'template', 'textarea', 'tfoot', 'th', 'thead', 'time', 'tr', 'track',
  'tt', 'u', 'ul', 'var', 'video', 'wbr',
];

export const SVG_TAGS: readonly string[] = [
  'svg', 'a', 'altglyph', 'altglyphdef', 'altglyphitem', 'animatecolor', 'animatemotion',
  'animatetransform', 'circle', 'clippath', 'defs', 'desc', 'ellipse', 'filter', 'font', 'g',
  'glyph', 'glyphref', 'hkern', 'image', 'line', 'lineargradient', 'marker', 'mask', 'metadata',
  'mpath', 'path', 'pattern', 'polygon', 'polyline', 'radialgradient', 'rect', 'stop', 'style',
  'switch', 'symbol', 'text', 'textpath', 'title', 'tref', 'tspan', 'view', 'vkern',
];

export const SVG_FILTER_TAGS: readonly string[] = [
  'feblend', 'fecolormatrix', 'fecomponenttransfer', 'fecomposite', 'feconvolvematrix',
  'fediffuselighting', 'fedisplacementmap', 'fedistantlight', 'fedropshadow', 'feflood', 'fefunca',
  'fefuncb', 'fefuncg', 'fefuncr', 'fegaussianblur', 'feimage', 'femerge', 'femergenode',
  'femorphology', 'feoffset', 'fepointlight', 'fespecularlighting', 'fespotlight', 'fetile',
  'feturbulence',
];

/** SVG elements that are never allowed by default but must be known for namespace checks. */
const SVG_DISALLOWED_TAGS: readonly string[] = [
  'animate', 'color-profile', 'cursor', 'discard', 'font-face', 'font-face-format',
  'font-face-name', 'font-face-src', 'font-face-uri', 'foreignobject', 'hatch', 'hatchpath', 'mesh',
  'meshgradient', 'meshpatch', 'meshrow', 'missing-glyph', 'script', 'set', 'solidcolor', 'unknown',
  'use',
];

export const MATHML_TAGS: readonly string[] = [
  'math', 'menclose', 'merror', 'mfenced', 'mfrac', 'mglyph', 'mi', 'mlabeledtr', 'mmultiscripts',
  'mn', 'mo', 'mover', 'mpadded', 'mphantom', 'mroot', 'mrow', 'ms', 'mspace', 'msqrt', 'mstyle',
  'msub', 'msup', 'msubsup', 'mtable', 'mtd', 'mtext', 'mtr', 'munder', 'munderover', 'mprescripts',
];

/** MathML elements that are never allowed by default but must be known for namespace checks. */
const MATHML_DISALLOWED_TAGS: readonly string[] = [
  'maction', 'maligngroup', 'malignmark', 'mlongdiv', 'mscarries', 'mscarry', 'msgroup', 'mstack',
  'msline', 'msrow', 'semantics', 'annotation', 'annotation-xml', 'mprescripts', 'none',
];

/** The node name DOMPurify uses to allow text nodes. */
export const TEXT_TAGS: readonly string[] = ['#text'];

// ─── Attributes ─────────────────────────────────────────────────────────

export const HTML_ATTRS: readonly string[] = [
  'accept', 'action', 'align', 'alt', 'autocapitalize', 'autocomplete', 'autopictureinpicture',
  'autoplay', 'background', 'bgcolor', 'border', 'capture', 'cellpadding', 'cellspacing', 'checked',
  'cite', 'class', 'clear', 'color', 'cols', 'colspan', 'command', 'commandfor', 'controls',
  'controlslist', 'coords', 'crossorigin', 'datetime', 'decoding', 'default', 'dir', 'disabled',
  'disablepictureinpicture', 'disableremoteplayback', 'download', 'draggable', 'enctype',
  'enterkeyhint', 'exportparts', 'face', 'for', 'headers', 'height', 'hidden', 'high', 'href',
  'hreflang', 'id', 'inert', 'inputmode', 'integrity', 'ismap', 'kind', 'label', 'lang', 'list',
  'loading', 'loop', 'low', 'max', 'maxlength', 'media', 'method', 'min', 'minlength', 'multiple',
  'muted', 'name', 'nonce', 'noshade', 'novalidate', 'nowrap', 'open', 'optimum', 'part', 'pattern',
  'placeholder', 'playsinline', 'popover', 'popovertarget', 'popovertargetaction', 'poster',
  'preload', 'pubdate', 'radiogroup', 'readonly', 'rel', 'required', 'rev', 'reversed', 'role',
  'rows', 'rowspan', 'spellcheck', 'scope', 'selected', 'shape', 'size', 'sizes', 'slot', 'span',
  'srclang', 'start', 'src', 'srcset', 'step', 'style', 'summary', 'tabindex', 'title', 'translate',
  'type', 'usemap', 'valign', 'value', 'width', 'wrap', 'xmlns',
];

export const SVG_ATTRS: readonly string[] = [
  'accent-height', 'accumulate', 'additive', 'alignment-baseline', 'amplitude', 'ascent',
  'attributename', 'attributetype', 'azimuth', 'basefrequency', 'baseline-shift', 'begin', 'bias',
  'by', 'class', 'clip', 'clippathunits', 'clip-path', 'clip-rule', 'color', 'color-interpolation',
  'color-interpolation-filters', 'color-profile', 'color-rendering', 'cx', 'cy', 'd', 'dx', 'dy',
  'diffuseconstant', 'direction', 'display', 'divisor', 'dominant-baseline', 'dur', 'edgemode',
  'elevation', 'end', 'exponent', 'fill', 'fill-opacity', 'fill-rule', 'filter', 'filterunits',
  'flood-color', 'flood-opacity', 'font-family', 'font-size', 'font-size-adjust', 'font-stretch',
  'font-style', 'font-variant', 'font-weight', 'fx', 'fy', 'g1', 'g2', 'glyph-name', 'glyphref',
  'gradientunits', 'gradienttransform', 'height', 'href', 'id', 'image-rendering', 'in', 'in2',
  'intercept', 'k', 'k1', 'k2', 'k3', 'k4', 'kerning', 'keypoints', 'keysplines', 'keytimes', 'lang',
  'lengthadjust', 'letter-spacing', 'kernelmatrix', 'kernelunitlength', 'lighting-color', 'local',
  'marker-end', 'marker-mid', 'marker-start', 'markerheight', 'markerunits', 'markerwidth',
  'maskcontentunits', 'maskunits', 'max', 'mask', 'mask-type', 'media', 'method', 'mode', 'min',
  'name', 'numoctaves', 'offset', 'operator', 'opacity', 'order', 'orient', 'orientation', 'origin',
  'overflow', 'paint-order', 'path', 'pathlength', 'patterncontentunits', 'patterntransform',
  'patternunits', 'pointer-events', 'points', 'preservealpha', 'preserveaspectratio',
  'primitiveunits', 'r', 'rx', 'ry', 'radius', 'refx', 'refy', 'repeatcount', 'repeatdur', 'restart',
  'result', 'rotate', 'scale', 'seed', 'shape-rendering', 'slope', 'specularconstant',
  'specularexponent', 'spreadmethod', 'startoffset', 'stddeviation', 'stitchtiles', 'stop-color',
  'stop-opacity', 'stroke-dasharray', 'stroke-dashoffset', 'stroke-linecap', 'stroke-linejoin',
  'stroke-miterlimit', 'stroke-opacity', 'stroke', 'stroke-width', 'style', 'surfacescale',
  'systemlanguage', 'tabindex', 'tablevalues', 'targetx', 'targety', 'transform',
  'transform-origin', 'text-anchor', 'text-decoration', 'text-orientation', 'text-rendering',
  'textlength', 'type', 'u1', 'u2', 'unicode', 'values', 'vector-effect', 'viewbox', 'visibility',
  'version', 'vert-adv-y', 'vert-origin-x', 'vert-origin-y', 'width', 'word-spacing', 'wrap',
  'writing-mode', 'xchannelselector', 'ychannelselector', 'x', 'x1', 'x2', 'xmlns', 'y', 'y1', 'y2',
  'z', 'zoomandpan',
];

export const MATHML_ATTRS: readonly string[] = [
  'accent', 'accentunder', 'align', 'bevelled', 'close', 'columnalign', 'columnlines',
  'columnspacing', 'columnspan', 'denomalign', 'depth', 'dir', 'display', 'displaystyle',
  'encoding', 'fence', 'frame', 'height', 'href', 'id', 'largeop', 'length', 'linethickness',
  'lquote', 'lspace', 'mathbackground', 'mathcolor', 'mathsize', 'mathvariant', 'maxsize',
  'minsize', 'movablelimits', 'notation', 'numalign', 'open', 'rowalign', 'rowlines', 'rowspacing',
  'rowspan', 'rspace', 'rquote', 'scriptlevel', 'scriptminsize', 'scriptsizemultiplier',
  'selection', 'separator', 'separators', 'stretchy', 'subscriptshift', 'supscriptshift',
  'symmetric', 'voffset', 'width', 'xmlns',
];

export const XML_ATTRS: readonly string[] = [
  'xlink:href', 'xml:id', 'xlink:title', 'xml:space', 'xmlns:xlink',
];

// ─── Defaults ───────────────────────────────────────────────────────────

export const DEFAULT_ALLOWED_TAGS: readonly string[] = [
  ...HTML_TAGS, ...SVG_TAGS, ...SVG_FILTER_TAGS, ...MATHML_TAGS, ...TEXT_TAGS,
];

export const DEFAULT_ALLOWED_ATTR: readonly string[] = [
  ...HTML_ATTRS, ...SVG_ATTRS, ...MATHML_ATTRS, ...XML_ATTRS,
];

/** Elements whose content is dropped, not kept, when the element is removed. */
export const DEFAULT_FORBID_CONTENTS: readonly string[] = [
  'annotation-xml', 'audio', 'colgroup', 'desc', 'foreignobject', 'head', 'iframe', 'math', 'mi',
  'mn', 'mo', 'ms', 'mtext', 'noembed', 'noframes', 'noscript', 'plaintext', 'script',
  'selectedcontent', 'style', 'svg', 'template', 'thead', 'title', 'video', 'xmp',
];

/** Elements whose URL attributes may hold `data:` URIs. */
export const DEFAULT_DATA_URI_TAGS: readonly string[] = [
  'audio', 'video', 'img', 'source', 'image', 'track',
];

/** Attributes whose values are never treated as URLs. */
export const DEFAULT_URI_SAFE_ATTRIBUTES: readonly string[] = [
  'alt', 'class', 'for', 'id', 'label', 'name', 'pattern', 'placeholder', 'role', 'summary',
  'title', 'value', 'style', 'xmlns',
];

export const ALL_SVG_TAGS: ReadonlySet<string> = new Set([
  ...SVG_TAGS, ...SVG_FILTER_TAGS, ...SVG_DISALLOWED_TAGS,
]);

export const ALL_MATHML_TAGS: ReadonlySet<string> = new Set([
  ...MATHML_TAGS, ...MATHML_DISALLOWED_TAGS,
]);

export const MATHML_TEXT_INTEGRATION_POINTS: ReadonlySet<string> = new Set([
  'mi', 'mo', 'mn', 'ms', 'mtext',
]);

export const HTML_INTEGRATION_POINTS: ReadonlySet<string> = new Set(['annotation-xml']);

/** Elements that are valid in both the SVG and the HTML namespace. */
export const COMMON_SVG_AND_HTML_ELEMENTS: ReadonlySet<string> = new Set([
  'title', 'style', 'font', 'a', 'script',
]);

/** HTML elements whose text children are serialized unescaped. */
export const LITERAL_TEXT_ELEMENTS: ReadonlySet<string> = new Set([
  'style', 'script', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext', 'noscript',
]);

export const SANITIZE_NAMED_PROPS_PREFIX = 'user-content-';

// ─── Patterns ───────────────────────────────────────────────────────────
// DOMPurify resets lastIndex before every test, so the test-only patterns
// below drop its `g` flag without changing behavior.

export const MUSTACHE_EXPR = /{{[\w\W]*|^[\w\W]*}}/g;
export const ERB_EXPR = /<%[\w\W]*|^[\w\W]*%>/g;
export const TMPLIT_EXPR = /\${[\w\W]*/g;
/** A template marker pair as it appears in serialized output. */
export const TMPL_MARKER_SERIALIZED = /{{|}}|\${|<%|%>|&lt;%|%&gt;/;
export const DATA_ATTR = /^data-[\-\w.\u00B7-\uFFFF]+$/;
export const ARIA_ATTR = /^aria-[\-\w]+$/;
export const IS_ALLOWED_URI =
  /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|sms|cid|xmpp|matrix):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;
export const IS_SCRIPT_OR_DATA = /^(?:\w+script|data):/i;
export const ATTR_WHITESPACE = /[\u0000-\u0020\u00A0\u1680\u180E\u2000-\u2029\u205F\u3000]/g;
export const DOCTYPE_NAME = /^html$/i;
export const ELEMENT_MARKUP_PROBE = /<[/\w!]/;
export const COMMENT_MARKUP_PROBE = /<[/\w]/;
export const FALLBACK_TAG_CLOSE = /<\/no(script|embed|frames)/i;
export const SELF_CLOSING_TAG = /\/>/i;
/** Comment closers and raw-text end tags inside an attribute value. */
export const ATTR_VALUE_BREAKOUT =
  /((--!?|])>)|<\/(style|script|title|xmp|textarea|noscript|iframe|noembed|noframes)/i;
export const LEADING_WHITESPACE = /^[\r\n\t ]+/;
