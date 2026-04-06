package com.arcis;

import com.arcis.core.ArcisConfig;
import com.arcis.sanitizers.Sanitizer;

/**
 * Main entry point for the Arcis security middleware.
 * <p>
 * Install once. Protect everything.
 * </p>
 *
 * <pre>{@code
 * Arcis arcis = Arcis.create();
 * String safe = arcis.sanitize(userInput);
 * }</pre>
 */
public final class Arcis {

    public static final String VERSION = "0.1.0";

    private final ArcisConfig config;
    private final Sanitizer sanitizer;

    private Arcis(ArcisConfig config) {
        this.config = config;
        this.sanitizer = new Sanitizer(config);
    }

    /** Create Arcis with default secure configuration. */
    public static Arcis create() {
        return new Arcis(ArcisConfig.defaults());
    }

    /** Create Arcis with custom configuration. */
    public static Arcis create(ArcisConfig config) {
        return new Arcis(config);
    }

    /**
     * Sanitize a string against all enabled attack vectors.
     * Applies remove-then-encode strategy (Pattern 5).
     *
     * @param input the untrusted string to sanitize
     * @return the sanitized string, safe for rendering
     */
    public String sanitize(String input) {
        return sanitizer.sanitizeString(input);
    }

    /** Get the current configuration. */
    public ArcisConfig getConfig() {
        return config;
    }
}
