package validation

import (
	"testing"
)

// ─── Syntax tests ────────────────────────────────────────────────────────────

func TestIsValidEmailSyntax_ValidEmails(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.com",
		"user@sub.domain.com",
		"u@example.co",
		"firstname.lastname@company.org",
		"email@123.123.123.com",
		"1234567890@example.com",
		"user@example-domain.com",
	}
	for _, email := range valid {
		if !IsValidEmailSyntax(email) {
			t.Errorf("Expected %q to be valid", email)
		}
	}
}

func TestIsValidEmailSyntax_InvalidEmails(t *testing.T) {
	invalid := []string{
		"",
		"plainaddress",
		"@example.com",
		"user@",
		"user@.com",
		"user@com",
		"user..name@example.com",
		".user@example.com",
		"user.@example.com",
		"user@-example.com",
		"user@example",
		"user @example.com",
	}
	for _, email := range invalid {
		if IsValidEmailSyntax(email) {
			t.Errorf("Expected %q to be invalid", email)
		}
	}
}

func TestIsValidEmailSyntax_LengthLimits(t *testing.T) {
	// Local part > 64 chars
	longLocal := ""
	for i := 0; i < 65; i++ {
		longLocal += "a"
	}
	if IsValidEmailSyntax(longLocal + "@example.com") {
		t.Error("Local part > 64 should be invalid")
	}

	// Total > 254 chars
	longDomain := "a"
	for len(longDomain)+10 < 250 {
		longDomain += ".aaaa"
	}
	longEmail := "user@" + longDomain + ".com"
	if len(longEmail) <= 254 {
		// Make it longer if needed
		longEmail = "user@" + longDomain + "." + longDomain + ".com"
	}
	if len(longEmail) > 254 && IsValidEmailSyntax(longEmail) {
		t.Error("Email > 254 chars should be invalid")
	}
}

// ─── ValidateEmail tests ────────────────────────────────────────────────────

func TestValidateEmail_ValidEmail(t *testing.T) {
	result := ValidateEmail("user@example.com", nil)
	if !result.Valid {
		t.Error("Expected valid")
	}
	if result.Reason != "valid" {
		t.Errorf("Expected reason 'valid', got %q", result.Reason)
	}
	if result.Normalized != "user@example.com" {
		t.Errorf("Expected normalized 'user@example.com', got %q", result.Normalized)
	}
}

func TestValidateEmail_InvalidSyntax(t *testing.T) {
	result := ValidateEmail("notanemail", nil)
	if result.Valid {
		t.Error("Expected invalid")
	}
	if result.Reason != "invalid_syntax" {
		t.Errorf("Expected reason 'invalid_syntax', got %q", result.Reason)
	}
}

func TestValidateEmail_Normalizes(t *testing.T) {
	result := ValidateEmail("  User@Example.COM  ", nil)
	if result.Normalized != "user@example.com" {
		t.Errorf("Expected normalized 'user@example.com', got %q", result.Normalized)
	}
}

func TestValidateEmail_DisposableBlocked(t *testing.T) {
	disposables := []string{
		"user@mailinator.com",
		"user@guerrillamail.com",
		"user@tempmail.com",
		"user@yopmail.com",
		"user@throwaway.email",
		"user@10minutemail.com",
	}

	for _, email := range disposables {
		result := ValidateEmail(email, nil)
		if result.Valid {
			t.Errorf("Expected %q to be rejected as disposable", email)
		}
		if result.Reason != "disposable" {
			t.Errorf("Expected reason 'disposable' for %q, got %q", email, result.Reason)
		}
		if !result.IsDisposable {
			t.Errorf("Expected IsDisposable=true for %q", email)
		}
	}
}

func TestValidateEmail_DisposableAllowed(t *testing.T) {
	opts := &EmailValidationOptions{
		CheckDisposable: false,
		SuggestTypoFix:  true,
	}
	result := ValidateEmail("user@mailinator.com", opts)
	if !result.Valid {
		t.Error("Expected valid when disposable check disabled")
	}
	if !result.IsDisposable {
		t.Error("IsDisposable should still be true even when check disabled")
	}
}

func TestValidateEmail_FreeProvider(t *testing.T) {
	freeEmails := []string{
		"user@gmail.com",
		"user@yahoo.com",
		"user@hotmail.com",
		"user@outlook.com",
		"user@protonmail.com",
	}

	for _, email := range freeEmails {
		result := ValidateEmail(email, nil)
		if !result.IsFree {
			t.Errorf("Expected IsFree=true for %q", email)
		}
	}
}

func TestValidateEmail_NotFreeProvider(t *testing.T) {
	result := ValidateEmail("user@company.com", nil)
	if result.IsFree {
		t.Error("Expected IsFree=false for company email")
	}
}

func TestValidateEmail_TypoSuggestion(t *testing.T) {
	typos := []struct {
		input      string
		suggestion string
	}{
		{"user@gmial.com", "user@gmail.com"},
		{"user@gmaill.com", "user@gmail.com"},
		{"user@yahooo.com", "user@yahoo.com"},
		{"user@hotmial.com", "user@hotmail.com"},
		{"user@outlok.com", "user@outlook.com"},
		{"user@icloud.co", "user@icloud.com"},
		{"user@gmail.con", "user@gmail.com"},
	}

	for _, tt := range typos {
		result := ValidateEmail(tt.input, nil)
		if !result.Valid {
			t.Errorf("Typo %q should still be valid", tt.input)
		}
		if result.Reason != "typo" {
			t.Errorf("Expected reason 'typo' for %q, got %q", tt.input, result.Reason)
		}
		if result.Suggestion != tt.suggestion {
			t.Errorf("Expected suggestion %q for %q, got %q", tt.suggestion, tt.input, result.Suggestion)
		}
	}
}

func TestValidateEmail_TypoDisabled(t *testing.T) {
	opts := &EmailValidationOptions{
		CheckDisposable: true,
		SuggestTypoFix:  false,
	}
	result := ValidateEmail("user@gmial.com", opts)
	if result.Reason == "typo" {
		t.Error("Typo detection should be disabled")
	}
	if result.Suggestion != "" {
		t.Error("Should not have suggestion when typo disabled")
	}
}

func TestValidateEmail_BlockedDomain(t *testing.T) {
	opts := &EmailValidationOptions{
		CheckDisposable: true,
		SuggestTypoFix:  true,
		BlockedDomains:  []string{"evil.com"},
	}
	result := ValidateEmail("user@evil.com", opts)
	if result.Valid {
		t.Error("Expected blocked domain to be invalid")
	}
	if result.Reason != "blocked" {
		t.Errorf("Expected reason 'blocked', got %q", result.Reason)
	}
}

func TestValidateEmail_AllowedDomainBypassesDisposable(t *testing.T) {
	opts := &EmailValidationOptions{
		CheckDisposable: true,
		SuggestTypoFix:  true,
		AllowedDomains:  []string{"mailinator.com"},
	}
	result := ValidateEmail("user@mailinator.com", opts)
	if !result.Valid {
		t.Error("Allowed domain should bypass disposable check")
	}
	if result.Reason != "valid" {
		t.Errorf("Expected reason 'valid', got %q", result.Reason)
	}
}

func TestValidateEmail_AllowedDomainCaseInsensitive(t *testing.T) {
	opts := &EmailValidationOptions{
		CheckDisposable: true,
		AllowedDomains:  []string{"MAILINATOR.COM"},
	}
	result := ValidateEmail("user@mailinator.com", opts)
	if !result.Valid {
		t.Error("Allowed domain comparison should be case insensitive")
	}
}

// ─── MX Verification tests ─────────────────────────────────────────────────

func TestVerifyEmailMX_InvalidSyntax(t *testing.T) {
	if VerifyEmailMX("notanemail") {
		t.Error("Invalid syntax should return false")
	}
}

func TestVerifyEmailMX_ValidDomain(t *testing.T) {
	// gmail.com should have MX records
	result := VerifyEmailMX("test@gmail.com")
	if !result {
		t.Skip("DNS lookup may be unavailable in test environment")
	}
}

func TestVerifyEmailMX_InvalidDomain(t *testing.T) {
	result := VerifyEmailMX("test@thisdomain-definitely-does-not-exist-xyz123abc.com")
	if result {
		t.Error("Non-existent domain should return false")
	}
}
