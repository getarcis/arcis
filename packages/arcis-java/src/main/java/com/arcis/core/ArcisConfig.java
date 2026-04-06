package com.arcis.core;

/**
 * Configuration for Arcis security middleware.
 * All security features are enabled by default (Pattern 6: Defensive Defaults).
 */
public final class ArcisConfig {

    private final boolean xss;
    private final boolean sql;
    private final boolean nosql;
    private final boolean path;
    private final boolean command;
    private final boolean proto;
    private final boolean ssti;
    private final boolean xxe;
    private final boolean headerInjection;
    private final boolean htmlEncode;
    private final int maxInputSize;
    private final SanitizeMode mode;

    private ArcisConfig(Builder builder) {
        this.xss = builder.xss;
        this.sql = builder.sql;
        this.nosql = builder.nosql;
        this.path = builder.path;
        this.command = builder.command;
        this.proto = builder.proto;
        this.ssti = builder.ssti;
        this.xxe = builder.xxe;
        this.headerInjection = builder.headerInjection;
        this.htmlEncode = builder.htmlEncode;
        this.maxInputSize = builder.maxInputSize;
        this.mode = builder.mode;
    }

    /** Create config with all defenses enabled. */
    public static ArcisConfig defaults() {
        return new Builder().build();
    }

    /** Create a new builder for custom configuration. */
    public static Builder builder() {
        return new Builder();
    }

    public boolean isXss() { return xss; }
    public boolean isSql() { return sql; }
    public boolean isNosql() { return nosql; }
    public boolean isPath() { return path; }
    public boolean isCommand() { return command; }
    public boolean isProto() { return proto; }
    public boolean isSsti() { return ssti; }
    public boolean isXxe() { return xxe; }
    public boolean isHeaderInjection() { return headerInjection; }
    public boolean isHtmlEncode() { return htmlEncode; }
    public int getMaxInputSize() { return maxInputSize; }
    public SanitizeMode getMode() { return mode; }

    public enum SanitizeMode {
        /** Throw SecurityThreatException on SQL/command injection. Recommended for APIs. */
        REJECT,
        /** Strip/replace threats in-place. Use when rejection is not feasible. */
        SANITIZE
    }

    public static final class Builder {
        private boolean xss = true;
        private boolean sql = true;
        private boolean nosql = true;
        private boolean path = true;
        private boolean command = true;
        private boolean proto = true;
        private boolean ssti = true;
        private boolean xxe = true;
        private boolean headerInjection = true;
        private boolean htmlEncode = false;
        private int maxInputSize = 1_000_000;
        private SanitizeMode mode = SanitizeMode.REJECT;

        public Builder xss(boolean enabled) { this.xss = enabled; return this; }
        public Builder sql(boolean enabled) { this.sql = enabled; return this; }
        public Builder nosql(boolean enabled) { this.nosql = enabled; return this; }
        public Builder path(boolean enabled) { this.path = enabled; return this; }
        public Builder command(boolean enabled) { this.command = enabled; return this; }
        public Builder proto(boolean enabled) { this.proto = enabled; return this; }
        public Builder ssti(boolean enabled) { this.ssti = enabled; return this; }
        public Builder xxe(boolean enabled) { this.xxe = enabled; return this; }
        public Builder headerInjection(boolean enabled) { this.headerInjection = enabled; return this; }
        public Builder htmlEncode(boolean enabled) { this.htmlEncode = enabled; return this; }
        public Builder maxInputSize(int size) { this.maxInputSize = size; return this; }
        public Builder mode(SanitizeMode mode) { this.mode = mode; return this; }

        public ArcisConfig build() {
            return new ArcisConfig(this);
        }
    }
}
