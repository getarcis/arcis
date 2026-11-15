/**
 * Property names of a DOM `Document` and an empty `HTMLFormElement` in the
 * reference environment (DOMPurify 3.4.18 on jsdom 31.0.1).
 *
 * With SANITIZE_DOM on, DOMPurify drops an `id` or `name` attribute whose
 * value is a property of `document` or of a form element (`value in document
 * || value in formElement`), since such an element could shadow ("clobber")
 * that property. There is no DOM here, so the names are listed: every string
 * key on the prototype chains of both objects, Object.prototype included.
 * The test suite recomputes this list from jsdom and fails if it drifts.
 */
const NAMES = `
  ATTRIBUTE_NODE CDATA_SECTION_NODE COMMENT_NODE DOCUMENT_FRAGMENT_NODE DOCUMENT_NODE
  DOCUMENT_POSITION_CONTAINED_BY DOCUMENT_POSITION_CONTAINS DOCUMENT_POSITION_DISCONNECTED
  DOCUMENT_POSITION_FOLLOWING DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC
  DOCUMENT_POSITION_PRECEDING DOCUMENT_TYPE_NODE ELEMENT_NODE ENTITY_NODE ENTITY_REFERENCE_NODE
  NOTATION_NODE PROCESSING_INSTRUCTION_NODE TEXT_NODE URL __defineGetter__ __defineSetter__
  __lookupGetter__ __lookupSetter__ __proto__ acceptCharset accessKey action activeElement
  addEventListener adoptNode adoptedStyleSheets after anchors append appendChild applets
  ariaAtomic ariaAutoComplete ariaBrailleLabel ariaBrailleRoleDescription ariaBusy ariaChecked
  ariaColCount ariaColIndex ariaColIndexText ariaColSpan ariaCurrent ariaDescription ariaDisabled
  ariaExpanded ariaHasPopup ariaHidden ariaInvalid ariaKeyShortcuts ariaLabel ariaLevel ariaLive
  ariaModal ariaMultiLine ariaMultiSelectable ariaOrientation ariaPlaceholder ariaPosInSet
  ariaPressed ariaReadOnly ariaRelevant ariaRequired ariaRoleDescription ariaRowCount ariaRowIndex
  ariaRowIndexText ariaRowSpan ariaSelected ariaSetSize ariaSort ariaValueMax ariaValueMin
  ariaValueNow ariaValueText assignedSlot attachInternals attachShadow attributes baseURI before
  blur body captureEvents characterSet charset checkValidity childElementCount childNodes children
  classList className clear click clientHeight clientLeft clientTop clientWidth cloneNode close
  closest compareDocumentPosition compatMode constructor contains contentType cookie
  createAttribute createAttributeNS createCDATASection createComment createDocumentFragment
  createElement createElementNS createEvent createExpression createNSResolver createNodeIterator
  createProcessingInstruction createRange createTextNode createTreeWalker currentScript dataset
  defaultView dir dispatchEvent doctype documentElement documentURI draggable elements embeds
  enctype evaluate firstChild firstElementChild focus forms getAttribute getAttributeNS
  getAttributeNames getAttributeNode getAttributeNodeNS getBoundingClientRect getClientRects
  getElementById getElementsByClassName getElementsByName getElementsByTagName
  getElementsByTagNameNS getRootNode getSelection hasAttribute hasAttributeNS hasAttributes
  hasChildNodes hasFocus hasOwnProperty head headingOffset headingReset hidden id images
  implementation importNode innerHTML inputEncoding insertAdjacentElement insertAdjacentHTML
  insertAdjacentText insertBefore isConnected isDefaultNamespace isEqualNode isPrototypeOf
  isSameNode lang lastChild lastElementChild lastModified length links localName location
  lookupNamespaceURI lookupPrefix matches method name namespaceURI nextElementSibling nextSibling
  noValidate nodeName nodeType nodeValue nonce normalize offsetHeight offsetLeft offsetParent
  offsetTop offsetWidth onabort onauxclick onbeforeinput onbeforematch onbeforetoggle onblur
  oncancel oncanplay oncanplaythrough onchange onclick onclose oncontextlost oncontextmenu
  oncontextrestored oncopy oncuechange oncut ondblclick ondrag ondragend ondragenter ondragleave
  ondragover ondragstart ondrop ondurationchange onemptied onended onerror onfocus onformdata
  ongotpointercapture oninput oninvalid onkeydown onkeypress onkeyup onload onloadeddata
  onloadedmetadata onloadstart onlostpointercapture onmousedown onmouseenter onmouseleave
  onmousemove onmouseout onmouseover onmouseup onpaste onpause onplay onplaying onpointercancel
  onpointerdown onpointerenter onpointerleave onpointermove onpointerout onpointerover
  onpointerrawupdate onpointerup onprogress onratechange onreadystatechange onreset onresize
  onscroll onscrollend onsecuritypolicyviolation onseeked onseeking onselect onslotchange
  onstalled onsubmit onsuspend ontimeupdate ontoggle ontouchcancel ontouchend ontouchmove
  ontouchstart onvisibilitychange onvolumechange onwaiting onwebkitanimationend
  onwebkitanimationiteration onwebkitanimationstart onwebkittransitionend onwheel open outerHTML
  ownerDocument parentElement parentNode part plugins prefix prepend previousElementSibling
  previousSibling propertyIsEnumerable querySelector querySelectorAll readyState referrer
  releaseEvents remove removeAttribute removeAttributeNS removeAttributeNode removeChild
  removeEventListener replaceChild replaceChildren replaceWith reportValidity requestSubmit reset
  role scripts scrollHeight scrollLeft scrollTop scrollWidth setAttribute setAttributeNS
  setAttributeNode setAttributeNodeNS shadowRoot slot style styleSheets submit tabIndex tagName
  target textContent title toLocaleString toString toggleAttribute translate valueOf
  visibilityState webkitMatchesSelector write writeln
`;

/** Values that make an `id` or `name` attribute a clobbering risk. */
export const CLOBBERABLE_NAMES: ReadonlySet<string> = new Set(NAMES.trim().split(/\s+/));
