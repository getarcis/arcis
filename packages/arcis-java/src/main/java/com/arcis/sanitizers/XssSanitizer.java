package com.arcis.sanitizers;

import java.util.regex.Pattern;

/**
 * XSS (Cross-Site Scripting) sanitizer.
 * Strips script tags, event handlers, and dangerous URI schemes.
 * <p>
 * Case-insensitive matching — {@code <SCRIPT>} caught same as {@code <script>}.
 * Idempotent — sanitize(sanitize(x)) == sanitize(x).
 * </p>
 */
public final class XssSanitizer {

    // Script tags (with content between them)
    private static final Pattern SCRIPT_TAG = Pattern.compile(
            "<script\\b[^>]*>[\\s\\S]*?</script>", Pattern.CASE_INSENSITIVE);

    // Self-closing and opening script/iframe/object/embed/applet tags
    private static final Pattern DANGEROUS_TAGS = Pattern.compile(
            "</?\\s*(script|iframe|object|embed|applet|form|textarea|input|button|select)\\b[^>]*>",
            Pattern.CASE_INSENSITIVE);

    // Event handlers: onclick, onerror, onload, etc.
    private static final Pattern EVENT_HANDLERS = Pattern.compile(
            "\\bon\\w+\\s*=", Pattern.CASE_INSENSITIVE);

    // javascript: and vbscript: URI schemes
    private static final Pattern DANGEROUS_PROTOCOLS = Pattern.compile(
            "(javascript|vbscript|data)\\s*:", Pattern.CASE_INSENSITIVE);

    // Expression() in CSS
    private static final Pattern CSS_EXPRESSION = Pattern.compile(
            "expression\\s*\\(", Pattern.CASE_INSENSITIVE);

    /**
     * Strip XSS attack patterns from input.
     *
     * @param input the untrusted string
     * @return string with XSS patterns removed
     */
    public String sanitize(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }

        String result = input;
        result = SCRIPT_TAG.matcher(result).replaceAll("");
        result = DANGEROUS_TAGS.matcher(result).replaceAll("");
        result = EVENT_HANDLERS.matcher(result).replaceAll("");
        result = DANGEROUS_PROTOCOLS.matcher(result).replaceAll("");
        result = CSS_EXPRESSION.matcher(result).replaceAll("");

        return result;
    }

    /**
     * HTML entity encode the 5 dangerous characters in HTML body context.
     * Encodes {@code &} first to prevent double-encoding.
     *
     * @param input string to encode
     * @return HTML-encoded string
     */
    public static String htmlEncode(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }

        // SECURITY: & must be encoded first to prevent &lt; -> &amp;lt;
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#x27;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
