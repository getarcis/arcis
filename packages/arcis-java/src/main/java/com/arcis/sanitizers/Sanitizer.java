package com.arcis.sanitizers;

import com.arcis.core.ArcisConfig;

/**
 * Core sanitization engine. Applies all enabled sanitizers in sequence.
 * <p>
 * Follows Pattern 5 (Remove-Then-Encode): strip dangerous patterns first,
 * then HTML-encode remaining characters if enabled.
 * </p>
 */
public final class Sanitizer {

    private final ArcisConfig config;
    private final XssSanitizer xss;

    public Sanitizer(ArcisConfig config) {
        this.config = config;
        this.xss = new XssSanitizer();
    }

    /**
     * Sanitize a string against all enabled attack vectors.
     *
     * @param input the untrusted input
     * @return sanitized string
     */
    public String sanitizeString(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }

        if (input.length() > config.getMaxInputSize()) {
            input = input.substring(0, config.getMaxInputSize());
        }

        String result = input;

        // Step 1: Remove dangerous patterns (before encoding can hide them)
        if (config.isXss()) {
            result = xss.sanitize(result);
        }
        // TODO: SQL, NoSQL, path, command, SSTI, XXE, header injection sanitizers

        // Step 2: HTML-encode remaining special characters if enabled
        if (config.isHtmlEncode()) {
            result = XssSanitizer.htmlEncode(result);
        }

        return result;
    }
}
