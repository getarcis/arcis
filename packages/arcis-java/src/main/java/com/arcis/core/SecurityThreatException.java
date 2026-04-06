package com.arcis.core;

/**
 * Thrown when a security threat is detected in REJECT mode.
 * Contains the threat type and the offending input for logging.
 */
public class SecurityThreatException extends RuntimeException {

    private final String threatType;
    private final String input;

    public SecurityThreatException(String threatType, String message, String input) {
        super(message);
        this.threatType = threatType;
        this.input = input;
    }

    /** The type of threat detected (e.g., "sql", "command"). */
    public String getThreatType() {
        return threatType;
    }

    /** The original input that triggered the detection. */
    public String getInput() {
        return input;
    }
}
