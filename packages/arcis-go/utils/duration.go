package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseDuration parses a human-readable duration string like "5m", "1h", "30s", "1d".
// Supports units: ms (milliseconds), s (seconds), m (minutes), h (hours), d (days).
// Also accepts plain numbers as milliseconds.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration string")
	}

	// Plain number → milliseconds
	if ms, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(ms * float64(time.Millisecond)), nil
	}

	// Find where the numeric part ends
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}

	if i == 0 {
		return 0, fmt.Errorf("invalid duration: %q", s)
	}

	numStr := s[:i]
	unit := strings.ToLower(strings.TrimSpace(s[i:]))

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid duration number: %q", numStr)
	}

	switch unit {
	case "ms":
		return time.Duration(num * float64(time.Millisecond)), nil
	case "s":
		return time.Duration(num * float64(time.Second)), nil
	case "m":
		return time.Duration(num * float64(time.Minute)), nil
	case "h":
		return time.Duration(num * float64(time.Hour)), nil
	case "d":
		return time.Duration(num * 24 * float64(time.Hour)), nil
	default:
		return 0, fmt.Errorf("unknown duration unit: %q", unit)
	}
}

// FormatDuration formats a time.Duration into a human-readable string.
// Uses the largest unit that results in a whole number, or seconds with decimals.
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "0ms"
	}

	ms := d.Milliseconds()

	// Days
	if ms >= 86400000 && ms%86400000 == 0 {
		return fmt.Sprintf("%dd", ms/86400000)
	}
	// Hours
	if ms >= 3600000 && ms%3600000 == 0 {
		return fmt.Sprintf("%dh", ms/3600000)
	}
	// Minutes
	if ms >= 60000 && ms%60000 == 0 {
		return fmt.Sprintf("%dm", ms/60000)
	}
	// Seconds
	if ms >= 1000 && ms%1000 == 0 {
		return fmt.Sprintf("%ds", ms/1000)
	}
	// Milliseconds
	return fmt.Sprintf("%dms", ms)
}
