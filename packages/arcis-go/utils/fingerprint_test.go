package utils

import (
	"net/http/httptest"
	"testing"
)

func TestFingerprint_Returns64CharHex(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	req.Header.Set("User-Agent", "Mozilla/5.0")

	hash := Fingerprint(req, nil)
	if len(hash) != 64 {
		t.Errorf("Expected 64-char hex, got %d chars: %s", len(hash), hash)
	}

	// Verify it's valid hex
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("Invalid hex character: %c", c)
			break
		}
	}
}

func TestFingerprint_Deterministic(t *testing.T) {
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		req.Header.Set("User-Agent", "TestAgent")
		req.Header.Set("Accept", "text/html")

		hash1 := Fingerprint(req, nil)

		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "1.2.3.4:1234"
		req2.Header.Set("User-Agent", "TestAgent")
		req2.Header.Set("Accept", "text/html")

		hash2 := Fingerprint(req2, nil)

		if hash1 != hash2 {
			t.Errorf("Same request produced different fingerprints: %s vs %s", hash1, hash2)
		}
	}
}

func TestFingerprint_DifferentUAProducesDifferentHash(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	req1.Header.Set("User-Agent", "Chrome")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	req2.Header.Set("User-Agent", "Firefox")

	h1 := Fingerprint(req1, nil)
	h2 := Fingerprint(req2, nil)

	if h1 == h2 {
		t.Error("Different User-Agents should produce different fingerprints")
	}
}

func TestFingerprint_DifferentIPProducesDifferentHash(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "5.6.7.8:1234"

	h1 := Fingerprint(req1, nil)
	h2 := Fingerprint(req2, nil)

	if h1 == h2 {
		t.Error("Different IPs should produce different fingerprints")
	}
}

func TestFingerprint_DisableIP(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	req1.Header.Set("User-Agent", "Same")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "5.6.7.8:1234"
	req2.Header.Set("User-Agent", "Same")

	opts := &FingerprintOptions{
		IP:             false,
		UserAgent:      true,
		Accept:         true,
		AcceptLanguage: true,
		AcceptEncoding: true,
	}

	h1 := Fingerprint(req1, opts)
	h2 := Fingerprint(req2, opts)

	if h1 != h2 {
		t.Error("With IP disabled, different IPs should produce same fingerprint")
	}
}

func TestFingerprint_DisableUserAgent(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	req1.Header.Set("User-Agent", "Chrome")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	req2.Header.Set("User-Agent", "Firefox")

	opts := &FingerprintOptions{
		IP:             true,
		UserAgent:      false,
		Accept:         true,
		AcceptLanguage: true,
		AcceptEncoding: true,
	}

	h1 := Fingerprint(req1, opts)
	h2 := Fingerprint(req2, opts)

	if h1 != h2 {
		t.Error("With UserAgent disabled, different UAs should produce same fingerprint")
	}
}

func TestFingerprint_CustomComponents(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"

	opts1 := &FingerprintOptions{
		IP:             true,
		UserAgent:      true,
		Accept:         true,
		AcceptLanguage: true,
		AcceptEncoding: true,
		Custom:         []string{"session-abc"},
	}

	opts2 := &FingerprintOptions{
		IP:             true,
		UserAgent:      true,
		Accept:         true,
		AcceptLanguage: true,
		AcceptEncoding: true,
		Custom:         []string{"session-xyz"},
	}

	h1 := Fingerprint(req, opts1)
	h2 := Fingerprint(req, opts2)

	if h1 == h2 {
		t.Error("Different custom components should produce different fingerprints")
	}
}

func TestFingerprint_AllDisabled(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	req1.Header.Set("User-Agent", "A")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "9.9.9.9:5678"
	req2.Header.Set("User-Agent", "B")

	opts := &FingerprintOptions{
		IP:             false,
		UserAgent:      false,
		Accept:         false,
		AcceptLanguage: false,
		AcceptEncoding: false,
	}

	h1 := Fingerprint(req1, opts)
	h2 := Fingerprint(req2, opts)

	if h1 != h2 {
		t.Error("With all disabled, fingerprints should be identical")
	}
}

func TestFingerprint_IncludesAcceptHeaders(t *testing.T) {
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "1.2.3.4:1234"
	req1.Header.Set("Accept", "text/html")
	req1.Header.Set("Accept-Language", "en-US")
	req1.Header.Set("Accept-Encoding", "gzip")

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.2.3.4:1234"
	req2.Header.Set("Accept", "application/json")
	req2.Header.Set("Accept-Language", "en-US")
	req2.Header.Set("Accept-Encoding", "gzip")

	h1 := Fingerprint(req1, nil)
	h2 := Fingerprint(req2, nil)

	if h1 == h2 {
		t.Error("Different Accept headers should produce different fingerprints")
	}
}

func TestFingerprint_WithIPOptions(t *testing.T) {
	ResetPlatformCache()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("Cf-Connecting-Ip", "203.0.113.50")

	optsGeneric := &FingerprintOptions{
		IP:             true,
		UserAgent:      false,
		Accept:         false,
		AcceptLanguage: false,
		AcceptEncoding: false,
		IPOptions:      &DetectIPOptions{Platform: PlatformGeneric},
	}

	optsCF := &FingerprintOptions{
		IP:             true,
		UserAgent:      false,
		Accept:         false,
		AcceptLanguage: false,
		AcceptEncoding: false,
		IPOptions:      &DetectIPOptions{Platform: PlatformCloudflare},
	}

	hGeneric := Fingerprint(req, optsGeneric)
	hCF := Fingerprint(req, optsCF)

	if hGeneric == hCF {
		t.Error("Different IP detection platforms should produce different fingerprints")
	}

	ResetPlatformCache()
}
