package sanitizers

import (
	"testing"
)

// ─── ScanPii tests ──────────────────────────────────────────────────────────

func TestScanPii_Email(t *testing.T) {
	matches := ScanPii("Contact us at user@example.com for info", nil)
	found := false
	for _, m := range matches {
		if m.Type == PiiEmail && m.Value == "user@example.com" {
			found = true
		}
	}
	if !found {
		t.Error("Should detect email")
	}
}

func TestScanPii_Phone(t *testing.T) {
	tests := []string{
		"Call (555) 123-4567",
		"Phone: 555-123-4567",
		"Cell: 555.123.4567",
		"Tel: +1 555 123 4567",
	}
	for _, text := range tests {
		matches := ScanPii(text, nil)
		found := false
		for _, m := range matches {
			if m.Type == PiiPhone {
				found = true
			}
		}
		if !found {
			t.Errorf("Should detect phone in %q", text)
		}
	}
}

func TestScanPii_CreditCard(t *testing.T) {
	// Valid Luhn numbers
	tests := []string{
		"Card: 4111111111111111",     // Visa test
		"Payment: 5500000000000004",  // Mastercard test
	}
	for _, text := range tests {
		matches := ScanPii(text, nil)
		found := false
		for _, m := range matches {
			if m.Type == PiiCreditCard {
				found = true
			}
		}
		if !found {
			t.Errorf("Should detect credit card in %q", text)
		}
	}
}

func TestScanPii_CreditCard_InvalidLuhn(t *testing.T) {
	matches := ScanPii("Number: 1234567890123456", nil)
	for _, m := range matches {
		if m.Type == PiiCreditCard {
			t.Error("Should not detect invalid Luhn number as credit card")
		}
	}
}

func TestScanPii_SSN(t *testing.T) {
	matches := ScanPii("SSN: 123-45-6789", nil)
	found := false
	for _, m := range matches {
		if m.Type == PiiSSN {
			found = true
		}
	}
	if !found {
		t.Error("Should detect SSN")
	}
}

func TestScanPii_SSN_Invalid(t *testing.T) {
	invalid := []string{
		"SSN: 000-12-3456", // 000 area
		"SSN: 666-12-3456", // 666 area
		"SSN: 900-12-3456", // 900+ area
	}
	for _, text := range invalid {
		matches := ScanPii(text, nil)
		for _, m := range matches {
			if m.Type == PiiSSN {
				t.Errorf("Should reject invalid SSN in %q", text)
			}
		}
	}
}

func TestScanPii_IPv4(t *testing.T) {
	matches := ScanPii("Server at 192.168.1.1 is down", nil)
	found := false
	for _, m := range matches {
		if m.Type == PiiIPAddress && m.Value == "192.168.1.1" {
			found = true
		}
	}
	if !found {
		t.Error("Should detect IPv4 address")
	}
}

func TestScanPii_IPv6(t *testing.T) {
	matches := ScanPii("Host: 2001:0db8:85a3:0000:0000:8a2e:0370:7334", nil)
	found := false
	for _, m := range matches {
		if m.Type == PiiIPAddress {
			found = true
		}
	}
	if !found {
		t.Error("Should detect IPv6 address")
	}
}

func TestScanPii_Multiple(t *testing.T) {
	text := "Email user@test.com, call 555-123-4567, SSN 123-45-6789"
	matches := ScanPii(text, nil)

	types := make(map[PiiType]bool)
	for _, m := range matches {
		types[m.Type] = true
	}

	if !types[PiiEmail] {
		t.Error("Should detect email")
	}
	if !types[PiiPhone] {
		t.Error("Should detect phone")
	}
	if !types[PiiSSN] {
		t.Error("Should detect SSN")
	}
}

func TestScanPii_FilterByType(t *testing.T) {
	text := "Email user@test.com, call 555-123-4567"
	matches := ScanPii(text, &PiiScanOptions{Types: []PiiType{PiiEmail}})

	for _, m := range matches {
		if m.Type != PiiEmail {
			t.Errorf("Should only return email matches, got %s", m.Type)
		}
	}
	if len(matches) == 0 {
		t.Error("Should find at least one email")
	}
}

func TestScanPii_NoMatch(t *testing.T) {
	matches := ScanPii("Hello world, nothing sensitive here.", nil)
	if len(matches) != 0 {
		t.Errorf("Expected no matches, got %d", len(matches))
	}
}

func TestScanPii_Positions(t *testing.T) {
	text := "Hi user@test.com bye"
	matches := ScanPii(text, &PiiScanOptions{Types: []PiiType{PiiEmail}})
	if len(matches) != 1 {
		t.Fatalf("Expected 1 match, got %d", len(matches))
	}
	if matches[0].Start != 3 || matches[0].End != 16 {
		t.Errorf("Expected start=3 end=16, got start=%d end=%d", matches[0].Start, matches[0].End)
	}
}

// ─── DetectPii tests ────────────────────────────────────────────────────────

func TestDetectPii_True(t *testing.T) {
	if !DetectPii("Email: user@example.com", nil) {
		t.Error("Should detect PII")
	}
}

func TestDetectPii_False(t *testing.T) {
	if DetectPii("No PII here", nil) {
		t.Error("Should not detect PII")
	}
}

// ─── RedactPii tests ────────────────────────────────────────────────────────

func TestRedactPii_Default(t *testing.T) {
	result := RedactPii("Email: user@example.com", nil)
	if result != "Email: [REDACTED]" {
		t.Errorf("Expected 'Email: [REDACTED]', got %q", result)
	}
}

func TestRedactPii_CustomReplacement(t *testing.T) {
	result := RedactPii("Email: user@example.com", &PiiRedactOptions{Replacement: "***"})
	if result != "Email: ***" {
		t.Errorf("Expected 'Email: ***', got %q", result)
	}
}

func TestRedactPii_TypeLabels(t *testing.T) {
	result := RedactPii("Email: user@example.com", &PiiRedactOptions{TypeLabels: true})
	if result != "Email: [EMAIL]" {
		t.Errorf("Expected 'Email: [EMAIL]', got %q", result)
	}
}

func TestRedactPii_SSNLabel(t *testing.T) {
	result := RedactPii("SSN: 123-45-6789", &PiiRedactOptions{
		TypeLabels: true,
		Types:      []PiiType{PiiSSN},
	})
	if result != "SSN: [SSN]" {
		t.Errorf("Expected 'SSN: [SSN]', got %q", result)
	}
}

func TestRedactPii_Multiple(t *testing.T) {
	text := "Email user@test.com and SSN 123-45-6789"
	result := RedactPii(text, &PiiRedactOptions{TypeLabels: true, Types: []PiiType{PiiEmail, PiiSSN}})
	if result != "Email [EMAIL] and SSN [SSN]" {
		t.Errorf("Got %q", result)
	}
}

func TestRedactPii_NoMatch(t *testing.T) {
	text := "Nothing here"
	result := RedactPii(text, nil)
	if result != text {
		t.Errorf("Should return original text, got %q", result)
	}
}

// ─── Object scanning tests ─────────────────────────────────────────────────

func TestScanObjectPii_Simple(t *testing.T) {
	data := map[string]interface{}{
		"email": "user@example.com",
		"name":  "John",
	}

	matches := ScanObjectPii(data, nil)
	found := false
	for _, m := range matches {
		if m.Field == "email" && m.Type == PiiEmail {
			found = true
		}
	}
	if !found {
		t.Error("Should find email in object")
	}
}

func TestScanObjectPii_Nested(t *testing.T) {
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"profile": map[string]interface{}{
				"email": "user@example.com",
			},
		},
	}

	matches := ScanObjectPii(data, nil)
	found := false
	for _, m := range matches {
		if m.Field == "user.profile.email" && m.Type == PiiEmail {
			found = true
		}
	}
	if !found {
		t.Error("Should find nested email with dot path")
	}
}

func TestScanObjectPii_Array(t *testing.T) {
	data := map[string]interface{}{
		"users": []interface{}{
			map[string]interface{}{
				"phone": "555-123-4567",
			},
		},
	}

	matches := ScanObjectPii(data, nil)
	found := false
	for _, m := range matches {
		if m.Field == "users[0].phone" && m.Type == PiiPhone {
			found = true
		}
	}
	if !found {
		t.Error("Should find phone in array element with [0] notation")
	}
}

func TestScanObjectPii_StringArray(t *testing.T) {
	data := map[string]interface{}{
		"emails": []interface{}{
			"user@example.com",
			"admin@example.com",
		},
	}

	matches := ScanObjectPii(data, nil)
	if len(matches) < 2 {
		t.Errorf("Should find 2 emails, got %d", len(matches))
	}
}

func TestRedactObjectPii_Simple(t *testing.T) {
	data := map[string]interface{}{
		"email": "user@example.com",
		"name":  "John",
		"age":   30,
	}

	result := RedactObjectPii(data, nil)
	if result["email"] != "[REDACTED]" {
		t.Errorf("Expected email redacted, got %q", result["email"])
	}
	if result["name"] != "John" {
		t.Error("Name should not be changed")
	}
	if result["age"] != 30 {
		t.Error("Non-string values should be preserved")
	}
}

func TestRedactObjectPii_Nested(t *testing.T) {
	data := map[string]interface{}{
		"user": map[string]interface{}{
			"email": "user@example.com",
		},
	}

	result := RedactObjectPii(data, nil)
	user := result["user"].(map[string]interface{})
	if user["email"] != "[REDACTED]" {
		t.Errorf("Expected nested email redacted, got %q", user["email"])
	}
}

func TestRedactObjectPii_Immutable(t *testing.T) {
	data := map[string]interface{}{
		"email": "user@example.com",
	}

	RedactObjectPii(data, nil)
	if data["email"] != "user@example.com" {
		t.Error("Original data should not be modified")
	}
}

func TestRedactObjectPii_TypeLabels(t *testing.T) {
	data := map[string]interface{}{
		"email": "user@example.com",
		"ssn":   "123-45-6789",
	}

	result := RedactObjectPii(data, &PiiRedactOptions{TypeLabels: true})
	if result["email"] != "[EMAIL]" {
		t.Errorf("Expected [EMAIL], got %q", result["email"])
	}
	if result["ssn"] != "[SSN]" {
		t.Errorf("Expected [SSN], got %q", result["ssn"])
	}
}
