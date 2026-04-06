package com.arcis.sanitizers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

class XssSanitizerTest {

    private XssSanitizer sanitizer;

    @BeforeEach
    void setUp() {
        sanitizer = new XssSanitizer();
    }

    // ─── Basic Script Tag Removal ───────────────────────────

    @Test
    @DisplayName("removes <script> tags with content")
    void removesScriptTags() {
        assertEquals("", sanitizer.sanitize("<script>alert(1)</script>"));
    }

    @Test
    @DisplayName("removes <SCRIPT> tags case-insensitive")
    void removesScriptTagsCaseInsensitive() {
        assertEquals("", sanitizer.sanitize("<SCRIPT>alert(1)</SCRIPT>"));
    }

    @Test
    @DisplayName("removes script tags with attributes")
    void removesScriptTagsWithAttributes() {
        assertEquals("", sanitizer.sanitize("<script src=\"evil.js\"></script>"));
    }

    // ─── Dangerous Tags ─────────────────────────────────────

    @Test
    @DisplayName("removes iframe tags")
    void removesIframeTags() {
        assertEquals("", sanitizer.sanitize("<iframe src=\"evil.com\"></iframe>"));
    }

    @Test
    @DisplayName("removes object/embed/applet tags")
    void removesDangerousTags() {
        assertEquals("", sanitizer.sanitize("<object data=\"evil.swf\">"));
        assertEquals("", sanitizer.sanitize("<embed src=\"evil.swf\">"));
        assertEquals("", sanitizer.sanitize("<applet code=\"Evil.class\">"));
    }

    // ─── Event Handlers ─────────────────────────────────────

    @Test
    @DisplayName("removes inline event handlers")
    void removesEventHandlers() {
        String input = "<img src=x onerror=alert(1)>";
        String result = sanitizer.sanitize(input);
        assertFalse(result.contains("onerror"));
    }

    @Test
    @DisplayName("removes onclick handler")
    void removesOnclick() {
        String input = "<div onclick=alert(1)>click</div>";
        String result = sanitizer.sanitize(input);
        assertFalse(result.contains("onclick"));
    }

    // ─── Dangerous Protocols ────────────────────────────────

    @Test
    @DisplayName("removes javascript: protocol")
    void removesJavascriptProtocol() {
        String result = sanitizer.sanitize("javascript:alert(1)");
        assertFalse(result.contains("javascript:"));
    }

    @Test
    @DisplayName("removes vbscript: protocol")
    void removesVbscriptProtocol() {
        String result = sanitizer.sanitize("vbscript:MsgBox");
        assertFalse(result.contains("vbscript:"));
    }

    // ─── CSS Expression ─────────────────────────────────────

    @Test
    @DisplayName("removes CSS expression()")
    void removesCssExpression() {
        String result = sanitizer.sanitize("background: expression(alert(1))");
        assertFalse(result.contains("expression("));
    }

    // ─── Safe Input Passthrough ─────────────────────────────

    @Test
    @DisplayName("safe text passes through unchanged")
    void safeTextUnchanged() {
        assertEquals("Hello World", sanitizer.sanitize("Hello World"));
    }

    @Test
    @DisplayName("safe HTML entities pass through")
    void safeEntitiesUnchanged() {
        assertEquals("Price: $5 &amp; tax", sanitizer.sanitize("Price: $5 &amp; tax"));
    }

    @Test
    @DisplayName("empty string returns empty")
    void emptyString() {
        assertEquals("", sanitizer.sanitize(""));
    }

    @Test
    @DisplayName("null returns empty")
    void nullInput() {
        assertEquals("", sanitizer.sanitize(null));
    }

    // ─── Idempotency (Pattern 8) ────────────────────────────

    @Test
    @DisplayName("idempotent: sanitize(sanitize(x)) == sanitize(x)")
    void idempotent() {
        String input = "<script>alert(1)</script>Hello";
        String once = sanitizer.sanitize(input);
        String twice = sanitizer.sanitize(once);
        assertEquals(once, twice);
    }

    @Test
    @DisplayName("idempotent on safe input")
    void idempotentSafeInput() {
        String safe = "Normal text with numbers 123";
        assertEquals(safe, sanitizer.sanitize(sanitizer.sanitize(safe)));
    }

    // ─── HTML Encode ────────────────────────────────────────

    @Test
    @DisplayName("htmlEncode encodes & < > \" '")
    void htmlEncodeBasic() {
        assertEquals("&amp;&lt;&gt;&quot;&#x27;", XssSanitizer.htmlEncode("&<>\"'"));
    }

    @Test
    @DisplayName("htmlEncode leaves safe text unchanged")
    void htmlEncodeSafeText() {
        assertEquals("Hello World", XssSanitizer.htmlEncode("Hello World"));
    }

    @Test
    @DisplayName("htmlEncode empty and null")
    void htmlEncodeEmpty() {
        assertEquals("", XssSanitizer.htmlEncode(""));
        assertEquals("", XssSanitizer.htmlEncode(null));
    }
}
