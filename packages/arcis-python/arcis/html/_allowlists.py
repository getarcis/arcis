"""Allowlists and name tables for the HTML sanitizer.

The tag and attribute lists are DOMPurify 3.4.18's ``src/tags.ts`` and
``src/attrs.ts`` (Apache-2.0, see THIRDPARTY-LICENSES.md, Source H), in the
same order. ``DOM_CLOBBER_NAMES_LIST`` is every property name that
DOMPurify's ``value in document || value in formElement`` check finds on
jsdom 31.0.1, the environment the shared fixtures are generated in (the
same 359 names as the Node SDK's ``src/html/dom-names.ts``).
"""

from __future__ import annotations

HTML_TAGS: tuple[str, ...] = (
    "a", "abbr", "acronym", "address", "area", "article", "aside", "audio", "b", "bdi", "bdo",
    "big", "blink", "blockquote", "body", "br", "button", "canvas", "caption", "center", "cite",
    "code", "col", "colgroup", "content", "data", "datalist", "dd", "decorator", "del",
    "details", "dfn", "dialog", "dir", "div", "dl", "dt", "element", "em", "fieldset",
    "figcaption", "figure", "font", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
    "head", "header", "hgroup", "hr", "html", "i", "img", "input", "ins", "kbd", "label",
    "legend", "li", "main", "map", "mark", "marquee", "menu", "menuitem", "meter", "nav",
    "nobr", "ol", "optgroup", "option", "output", "p", "picture", "pre", "progress", "q", "rp",
    "rt", "ruby", "s", "samp", "search", "section", "select", "shadow", "slot", "small",
    "source", "spacer", "span", "strike", "strong", "style", "sub", "summary", "sup", "table",
    "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time", "tr", "track", "tt",
    "u", "ul", "var", "video", "wbr",
)

SVG_TAGS: tuple[str, ...] = (
    "svg", "a", "altglyph", "altglyphdef", "altglyphitem", "animatecolor", "animatemotion",
    "animatetransform", "circle", "clippath", "defs", "desc", "ellipse", "filter", "font", "g",
    "glyph", "glyphref", "hkern", "image", "line", "lineargradient", "marker", "mask",
    "metadata", "mpath", "path", "pattern", "polygon", "polyline", "radialgradient", "rect",
    "stop", "style", "switch", "symbol", "text", "textpath", "title", "tref", "tspan", "view",
    "vkern",
)

SVG_FILTER_TAGS: tuple[str, ...] = (
    "feBlend", "feColorMatrix", "feComponentTransfer", "feComposite", "feConvolveMatrix",
    "feDiffuseLighting", "feDisplacementMap", "feDistantLight", "feDropShadow", "feFlood",
    "feFuncA", "feFuncB", "feFuncG", "feFuncR", "feGaussianBlur", "feImage", "feMerge",
    "feMergeNode", "feMorphology", "feOffset", "fePointLight", "feSpecularLighting",
    "feSpotLight", "feTile", "feTurbulence",
)

SVG_DISALLOWED_TAGS: tuple[str, ...] = (
    "animate", "color-profile", "cursor", "discard", "font-face", "font-face-format",
    "font-face-name", "font-face-src", "font-face-uri", "foreignobject", "hatch", "hatchpath",
    "mesh", "meshgradient", "meshpatch", "meshrow", "missing-glyph", "script", "set",
    "solidcolor", "unknown", "use",
)

MATHML_TAGS: tuple[str, ...] = (
    "math", "menclose", "merror", "mfenced", "mfrac", "mglyph", "mi", "mlabeledtr",
    "mmultiscripts", "mn", "mo", "mover", "mpadded", "mphantom", "mroot", "mrow", "ms",
    "mspace", "msqrt", "mstyle", "msub", "msup", "msubsup", "mtable", "mtd", "mtext", "mtr",
    "munder", "munderover", "mprescripts",
)

MATHML_DISALLOWED_TAGS: tuple[str, ...] = (
    "maction", "maligngroup", "malignmark", "mlongdiv", "mscarries", "mscarry", "msgroup",
    "mstack", "msline", "msrow", "semantics", "annotation", "annotation-xml", "mprescripts",
    "none",
)

TEXT_TAGS: tuple[str, ...] = (
    "#text",
)

HTML_ATTRS: tuple[str, ...] = (
    "accept", "action", "align", "alt", "autocapitalize", "autocomplete",
    "autopictureinpicture", "autoplay", "background", "bgcolor", "border", "capture",
    "cellpadding", "cellspacing", "checked", "cite", "class", "clear", "color", "cols",
    "colspan", "command", "commandfor", "controls", "controlslist", "coords", "crossorigin",
    "datetime", "decoding", "default", "dir", "disabled", "disablepictureinpicture",
    "disableremoteplayback", "download", "draggable", "enctype", "enterkeyhint", "exportparts",
    "face", "for", "headers", "height", "hidden", "high", "href", "hreflang", "id", "inert",
    "inputmode", "integrity", "ismap", "kind", "label", "lang", "list", "loading", "loop",
    "low", "max", "maxlength", "media", "method", "min", "minlength", "multiple", "muted",
    "name", "nonce", "noshade", "novalidate", "nowrap", "open", "optimum", "part", "pattern",
    "placeholder", "playsinline", "popover", "popovertarget", "popovertargetaction", "poster",
    "preload", "pubdate", "radiogroup", "readonly", "rel", "required", "rev", "reversed",
    "role", "rows", "rowspan", "spellcheck", "scope", "selected", "shape", "size", "sizes",
    "slot", "span", "srclang", "start", "src", "srcset", "step", "style", "summary", "tabindex",
    "title", "translate", "type", "usemap", "valign", "value", "width", "wrap", "xmlns",
)

SVG_ATTRS: tuple[str, ...] = (
    "accent-height", "accumulate", "additive", "alignment-baseline", "amplitude", "ascent",
    "attributename", "attributetype", "azimuth", "basefrequency", "baseline-shift", "begin",
    "bias", "by", "class", "clip", "clippathunits", "clip-path", "clip-rule", "color",
    "color-interpolation", "color-interpolation-filters", "color-profile", "color-rendering",
    "cx", "cy", "d", "dx", "dy", "diffuseconstant", "direction", "display", "divisor",
    "dominant-baseline", "dur", "edgemode", "elevation", "end", "exponent", "fill",
    "fill-opacity", "fill-rule", "filter", "filterunits", "flood-color", "flood-opacity",
    "font-family", "font-size", "font-size-adjust", "font-stretch", "font-style",
    "font-variant", "font-weight", "fx", "fy", "g1", "g2", "glyph-name", "glyphref",
    "gradientunits", "gradienttransform", "height", "href", "id", "image-rendering", "in",
    "in2", "intercept", "k", "k1", "k2", "k3", "k4", "kerning", "keypoints", "keysplines",
    "keytimes", "lang", "lengthadjust", "letter-spacing", "kernelmatrix", "kernelunitlength",
    "lighting-color", "local", "marker-end", "marker-mid", "marker-start", "markerheight",
    "markerunits", "markerwidth", "maskcontentunits", "maskunits", "max", "mask", "mask-type",
    "media", "method", "mode", "min", "name", "numoctaves", "offset", "operator", "opacity",
    "order", "orient", "orientation", "origin", "overflow", "paint-order", "path", "pathlength",
    "patterncontentunits", "patterntransform", "patternunits", "pointer-events", "points",
    "preservealpha", "preserveaspectratio", "primitiveunits", "r", "rx", "ry", "radius", "refx",
    "refy", "repeatcount", "repeatdur", "restart", "result", "rotate", "scale", "seed",
    "shape-rendering", "slope", "specularconstant", "specularexponent", "spreadmethod",
    "startoffset", "stddeviation", "stitchtiles", "stop-color", "stop-opacity",
    "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin",
    "stroke-miterlimit", "stroke-opacity", "stroke", "stroke-width", "style", "surfacescale",
    "systemlanguage", "tabindex", "tablevalues", "targetx", "targety", "transform",
    "transform-origin", "text-anchor", "text-decoration", "text-orientation", "text-rendering",
    "textlength", "type", "u1", "u2", "unicode", "values", "vector-effect", "viewbox",
    "visibility", "version", "vert-adv-y", "vert-origin-x", "vert-origin-y", "width",
    "word-spacing", "wrap", "writing-mode", "xchannelselector", "ychannelselector", "x", "x1",
    "x2", "xmlns", "y", "y1", "y2", "z", "zoomandpan",
)

MATHML_ATTRS: tuple[str, ...] = (
    "accent", "accentunder", "align", "bevelled", "close", "columnalign", "columnlines",
    "columnspacing", "columnspan", "denomalign", "depth", "dir", "display", "displaystyle",
    "encoding", "fence", "frame", "height", "href", "id", "largeop", "length", "linethickness",
    "lquote", "lspace", "mathbackground", "mathcolor", "mathsize", "mathvariant", "maxsize",
    "minsize", "movablelimits", "notation", "numalign", "open", "rowalign", "rowlines",
    "rowspacing", "rowspan", "rspace", "rquote", "scriptlevel", "scriptminsize",
    "scriptsizemultiplier", "selection", "separator", "separators", "stretchy",
    "subscriptshift", "supscriptshift", "symmetric", "voffset", "width", "xmlns",
)

XML_ATTRS: tuple[str, ...] = (
    "xlink:href", "xml:id", "xlink:title", "xml:space", "xmlns:xlink",
)

DOM_CLOBBER_NAMES_LIST: tuple[str, ...] = (
    "ATTRIBUTE_NODE", "CDATA_SECTION_NODE", "COMMENT_NODE", "DOCUMENT_FRAGMENT_NODE",
    "DOCUMENT_NODE", "DOCUMENT_POSITION_CONTAINED_BY", "DOCUMENT_POSITION_CONTAINS",
    "DOCUMENT_POSITION_DISCONNECTED", "DOCUMENT_POSITION_FOLLOWING",
    "DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC", "DOCUMENT_POSITION_PRECEDING",
    "DOCUMENT_TYPE_NODE", "ELEMENT_NODE", "ENTITY_NODE", "ENTITY_REFERENCE_NODE",
    "NOTATION_NODE", "PROCESSING_INSTRUCTION_NODE", "TEXT_NODE", "URL", "__defineGetter__",
    "__defineSetter__", "__lookupGetter__", "__lookupSetter__", "__proto__", "acceptCharset",
    "accessKey", "action", "activeElement", "addEventListener", "adoptNode",
    "adoptedStyleSheets", "after", "anchors", "append", "appendChild", "applets", "ariaAtomic",
    "ariaAutoComplete", "ariaBrailleLabel", "ariaBrailleRoleDescription", "ariaBusy",
    "ariaChecked", "ariaColCount", "ariaColIndex", "ariaColIndexText", "ariaColSpan",
    "ariaCurrent", "ariaDescription", "ariaDisabled", "ariaExpanded", "ariaHasPopup",
    "ariaHidden", "ariaInvalid", "ariaKeyShortcuts", "ariaLabel", "ariaLevel", "ariaLive",
    "ariaModal", "ariaMultiLine", "ariaMultiSelectable", "ariaOrientation", "ariaPlaceholder",
    "ariaPosInSet", "ariaPressed", "ariaReadOnly", "ariaRelevant", "ariaRequired",
    "ariaRoleDescription", "ariaRowCount", "ariaRowIndex", "ariaRowIndexText", "ariaRowSpan",
    "ariaSelected", "ariaSetSize", "ariaSort", "ariaValueMax", "ariaValueMin", "ariaValueNow",
    "ariaValueText", "assignedSlot", "attachInternals", "attachShadow", "attributes", "baseURI",
    "before", "blur", "body", "captureEvents", "characterSet", "charset", "checkValidity",
    "childElementCount", "childNodes", "children", "classList", "className", "clear", "click",
    "clientHeight", "clientLeft", "clientTop", "clientWidth", "cloneNode", "close", "closest",
    "compareDocumentPosition", "compatMode", "constructor", "contains", "contentType", "cookie",
    "createAttribute", "createAttributeNS", "createCDATASection", "createComment",
    "createDocumentFragment", "createElement", "createElementNS", "createEvent",
    "createExpression", "createNSResolver", "createNodeIterator", "createProcessingInstruction",
    "createRange", "createTextNode", "createTreeWalker", "currentScript", "dataset",
    "defaultView", "dir", "dispatchEvent", "doctype", "documentElement", "documentURI",
    "draggable", "elements", "embeds", "enctype", "evaluate", "firstChild", "firstElementChild",
    "focus", "forms", "getAttribute", "getAttributeNS", "getAttributeNames", "getAttributeNode",
    "getAttributeNodeNS", "getBoundingClientRect", "getClientRects", "getElementById",
    "getElementsByClassName", "getElementsByName", "getElementsByTagName",
    "getElementsByTagNameNS", "getRootNode", "getSelection", "hasAttribute", "hasAttributeNS",
    "hasAttributes", "hasChildNodes", "hasFocus", "hasOwnProperty", "head", "headingOffset",
    "headingReset", "hidden", "id", "images", "implementation", "importNode", "innerHTML",
    "inputEncoding", "insertAdjacentElement", "insertAdjacentHTML", "insertAdjacentText",
    "insertBefore", "isConnected", "isDefaultNamespace", "isEqualNode", "isPrototypeOf",
    "isSameNode", "lang", "lastChild", "lastElementChild", "lastModified", "length", "links",
    "localName", "location", "lookupNamespaceURI", "lookupPrefix", "matches", "method", "name",
    "namespaceURI", "nextElementSibling", "nextSibling", "noValidate", "nodeName", "nodeType",
    "nodeValue", "nonce", "normalize", "offsetHeight", "offsetLeft", "offsetParent",
    "offsetTop", "offsetWidth", "onabort", "onauxclick", "onbeforeinput", "onbeforematch",
    "onbeforetoggle", "onblur", "oncancel", "oncanplay", "oncanplaythrough", "onchange",
    "onclick", "onclose", "oncontextlost", "oncontextmenu", "oncontextrestored", "oncopy",
    "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragleave",
    "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended",
    "onerror", "onfocus", "onformdata", "ongotpointercapture", "oninput", "oninvalid",
    "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata",
    "onloadstart", "onlostpointercapture", "onmousedown", "onmouseenter", "onmouseleave",
    "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onpaste", "onpause", "onplay",
    "onplaying", "onpointercancel", "onpointerdown", "onpointerenter", "onpointerleave",
    "onpointermove", "onpointerout", "onpointerover", "onpointerrawupdate", "onpointerup",
    "onprogress", "onratechange", "onreadystatechange", "onreset", "onresize", "onscroll",
    "onscrollend", "onsecuritypolicyviolation", "onseeked", "onseeking", "onselect",
    "onslotchange", "onstalled", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle",
    "ontouchcancel", "ontouchend", "ontouchmove", "ontouchstart", "onvisibilitychange",
    "onvolumechange", "onwaiting", "onwebkitanimationend", "onwebkitanimationiteration",
    "onwebkitanimationstart", "onwebkittransitionend", "onwheel", "open", "outerHTML",
    "ownerDocument", "parentElement", "parentNode", "part", "plugins", "prefix", "prepend",
    "previousElementSibling", "previousSibling", "propertyIsEnumerable", "querySelector",
    "querySelectorAll", "readyState", "referrer", "releaseEvents", "remove", "removeAttribute",
    "removeAttributeNS", "removeAttributeNode", "removeChild", "removeEventListener",
    "replaceChild", "replaceChildren", "replaceWith", "reportValidity", "requestSubmit",
    "reset", "role", "scripts", "scrollHeight", "scrollLeft", "scrollTop", "scrollWidth",
    "setAttribute", "setAttributeNS", "setAttributeNode", "setAttributeNodeNS", "shadowRoot",
    "slot", "style", "styleSheets", "submit", "tabIndex", "tagName", "target", "textContent",
    "title", "toLocaleString", "toString", "toggleAttribute", "translate", "valueOf",
    "visibilityState", "webkitMatchesSelector", "write", "writeln",
)
