package utils

import (
	"testing"
	"time"
)

func TestParseDuration_Milliseconds(t *testing.T) {
	d, err := ParseDuration("500ms")
	if err != nil {
		t.Fatal(err)
	}
	if d != 500*time.Millisecond {
		t.Errorf("Expected 500ms, got %v", d)
	}
}

func TestParseDuration_Seconds(t *testing.T) {
	d, err := ParseDuration("30s")
	if err != nil {
		t.Fatal(err)
	}
	if d != 30*time.Second {
		t.Errorf("Expected 30s, got %v", d)
	}
}

func TestParseDuration_Minutes(t *testing.T) {
	d, err := ParseDuration("5m")
	if err != nil {
		t.Fatal(err)
	}
	if d != 5*time.Minute {
		t.Errorf("Expected 5m, got %v", d)
	}
}

func TestParseDuration_Hours(t *testing.T) {
	d, err := ParseDuration("2h")
	if err != nil {
		t.Fatal(err)
	}
	if d != 2*time.Hour {
		t.Errorf("Expected 2h, got %v", d)
	}
}

func TestParseDuration_Days(t *testing.T) {
	d, err := ParseDuration("1d")
	if err != nil {
		t.Fatal(err)
	}
	if d != 24*time.Hour {
		t.Errorf("Expected 24h, got %v", d)
	}
}

func TestParseDuration_PlainNumber(t *testing.T) {
	d, err := ParseDuration("5000")
	if err != nil {
		t.Fatal(err)
	}
	if d != 5000*time.Millisecond {
		t.Errorf("Expected 5000ms, got %v", d)
	}
}

func TestParseDuration_Fractional(t *testing.T) {
	d, err := ParseDuration("1.5h")
	if err != nil {
		t.Fatal(err)
	}
	if d != 90*time.Minute {
		t.Errorf("Expected 90m, got %v", d)
	}
}

func TestParseDuration_Whitespace(t *testing.T) {
	d, err := ParseDuration("  10s  ")
	if err != nil {
		t.Fatal(err)
	}
	if d != 10*time.Second {
		t.Errorf("Expected 10s, got %v", d)
	}
}

func TestParseDuration_CaseInsensitive(t *testing.T) {
	d, err := ParseDuration("5M")
	if err != nil {
		t.Fatal(err)
	}
	if d != 5*time.Minute {
		t.Errorf("Expected 5m, got %v", d)
	}
}

func TestParseDuration_Empty(t *testing.T) {
	_, err := ParseDuration("")
	if err == nil {
		t.Error("Expected error for empty string")
	}
}

func TestParseDuration_InvalidUnit(t *testing.T) {
	_, err := ParseDuration("5x")
	if err == nil {
		t.Error("Expected error for invalid unit")
	}
}

func TestParseDuration_InvalidString(t *testing.T) {
	_, err := ParseDuration("abc")
	if err == nil {
		t.Error("Expected error for invalid string")
	}
}

func TestFormatDuration_Milliseconds(t *testing.T) {
	s := FormatDuration(500 * time.Millisecond)
	if s != "500ms" {
		t.Errorf("Expected '500ms', got %q", s)
	}
}

func TestFormatDuration_Seconds(t *testing.T) {
	s := FormatDuration(30 * time.Second)
	if s != "30s" {
		t.Errorf("Expected '30s', got %q", s)
	}
}

func TestFormatDuration_Minutes(t *testing.T) {
	s := FormatDuration(5 * time.Minute)
	if s != "5m" {
		t.Errorf("Expected '5m', got %q", s)
	}
}

func TestFormatDuration_Hours(t *testing.T) {
	s := FormatDuration(2 * time.Hour)
	if s != "2h" {
		t.Errorf("Expected '2h', got %q", s)
	}
}

func TestFormatDuration_Days(t *testing.T) {
	s := FormatDuration(48 * time.Hour)
	if s != "2d" {
		t.Errorf("Expected '2d', got %q", s)
	}
}

func TestFormatDuration_Zero(t *testing.T) {
	s := FormatDuration(0)
	if s != "0ms" {
		t.Errorf("Expected '0ms', got %q", s)
	}
}

func TestFormatDuration_NonEven(t *testing.T) {
	// 1500ms → "1500ms" (not evenly seconds)
	s := FormatDuration(1500 * time.Millisecond)
	if s != "1500ms" {
		t.Errorf("Expected '1500ms', got %q", s)
	}
}

func TestParseDuration_Roundtrip(t *testing.T) {
	cases := []string{"500ms", "30s", "5m", "2h", "1d"}
	for _, c := range cases {
		d, err := ParseDuration(c)
		if err != nil {
			t.Fatalf("ParseDuration(%q) failed: %v", c, err)
		}
		formatted := FormatDuration(d)
		if formatted != c {
			t.Errorf("Roundtrip failed: %q → %v → %q", c, d, formatted)
		}
	}
}
