package validation

import (
	"net"
	"regexp"
	"strings"
)

const (
	maxEmailLength  = 254
	maxLocalLength  = 64
	maxDomainLength = 255
)

// EmailValidationResult holds the result of email validation.
type EmailValidationResult struct {
	Valid        bool   `json:"valid"`
	Reason       string `json:"reason"`
	Suggestion   string `json:"suggestion,omitempty"`
	IsFree       bool   `json:"isFree"`
	IsDisposable bool   `json:"isDisposable"`
	Normalized   string `json:"normalized"`
}

// EmailValidationOptions configures email validation behavior.
type EmailValidationOptions struct {
	CheckDisposable bool     // Reject disposable domains (default: true)
	SuggestTypoFix  bool     // Detect and suggest domain typos (default: true)
	BlockedDomains  []string // Custom blocked domains
	AllowedDomains  []string // Bypass disposable check for these domains
}

// DefaultEmailValidationOptions returns options with all checks enabled.
func DefaultEmailValidationOptions() EmailValidationOptions {
	return EmailValidationOptions{
		CheckDisposable: true,
		SuggestTypoFix:  true,
	}
}

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

var disposableDomains = map[string]bool{
	"guerrillamail.com": true, "guerrillamail.net": true, "guerrillamail.org": true,
	"tempmail.com": true, "temp-mail.org": true, "temp-mail.io": true,
	"throwaway.email": true, "throwaway.com": true, "mailinator.com": true,
	"mailinator.net": true, "yopmail.com": true, "yopmail.fr": true,
	"yopmail.net": true, "sharklasers.com": true, "grr.la": true,
	"guerrillamail.info": true, "guerrillamail.biz": true, "guerrillamail.de": true,
	"trashmail.com": true, "trashmail.me": true, "trashmail.net": true,
	"dispostable.com": true, "maildrop.cc": true, "mailnesia.com": true,
	"tempail.com": true, "mohmal.com": true, "getnada.com": true,
	"emailondeck.com": true, "discard.email": true, "fakeinbox.com": true,
	"mailcatch.com": true, "mintemail.com": true, "tempr.email": true,
	"tempinbox.com": true, "burnermail.io": true, "mailsac.com": true,
	"harakirimail.com": true, "tempmailo.com": true, "emailfake.com": true,
	"crazymailing.com": true, "armyspy.com": true, "dayrep.com": true,
	"einrot.com": true, "fleckens.hu": true, "gustr.com": true,
	"jourrapide.com": true, "rhyta.com": true, "superrito.com": true,
	"teleworm.us": true, "10minutemail.com": true, "10minutemail.net": true,
	"minutemail.com": true, "tempsky.com": true, "spamgourmet.com": true,
	"mytrashmail.com": true, "mailexpire.com": true, "safetymail.info": true,
	"filzmail.com": true, "trashymail.com": true, "sharkmail.com": true,
	"jetable.org": true, "nospam.ze.tc": true, "trash-me.com": true,
	"dodgit.com": true, "mailmoat.com": true, "spamfree24.org": true,
	"incognitomail.org": true, "tempomail.fr": true, "ephemail.net": true,
	"hidemail.de": true, "spaml.de": true, "uggsrock.com": true,
	"binkmail.com": true, "suremail.info": true, "bugmenot.com": true,
}

var freeProviders = map[string]bool{
	"gmail.com": true, "yahoo.com": true, "hotmail.com": true,
	"outlook.com": true, "aol.com": true, "protonmail.com": true,
	"proton.me": true, "icloud.com": true, "mail.com": true,
	"zoho.com": true, "yandex.com": true, "gmx.com": true,
	"gmx.net": true, "live.com": true, "msn.com": true,
	"me.com": true, "mac.com": true, "fastmail.com": true,
	"tutanota.com": true, "hey.com": true,
}

var typoSuggestions = map[string]string{
	// Gmail
	"gmial.com": "gmail.com", "gmaill.com": "gmail.com", "gmai.com": "gmail.com",
	"gamil.com": "gmail.com", "gnail.com": "gmail.com", "gmal.com": "gmail.com",
	"gmil.com": "gmail.com", "gmail.co": "gmail.com", "gmail.cm": "gmail.com",
	"gmail.om": "gmail.com", "gmail.con": "gmail.com", "gmail.cim": "gmail.com",
	"gmail.comm": "gmail.com",
	// Yahoo
	"yahooo.com": "yahoo.com", "yaho.com": "yahoo.com", "yahoo.co": "yahoo.com",
	"yahoo.cm": "yahoo.com", "yahoo.con": "yahoo.com", "yahho.com": "yahoo.com",
	// Hotmail
	"hotmial.com": "hotmail.com", "hotmal.com": "hotmail.com", "hotmai.com": "hotmail.com",
	"hotmil.com": "hotmail.com", "hotmail.co": "hotmail.com", "hotmail.cm": "hotmail.com",
	"hotmail.con": "hotmail.com",
	// Outlook
	"outlok.com": "outlook.com", "outloo.com": "outlook.com", "outlook.co": "outlook.com",
	"outlook.cm": "outlook.com",
	// Proton
	"protonmal.com": "protonmail.com", "protonmail.co": "protonmail.com",
	// iCloud
	"icloud.co": "icloud.com", "icloud.cm": "icloud.com", "icoud.com": "icloud.com",
}

// ValidateEmail validates an email address with disposable detection, typo suggestions, and more.
func ValidateEmail(email string, opts *EmailValidationOptions) EmailValidationResult {
	o := DefaultEmailValidationOptions()
	if opts != nil {
		o = *opts
	}

	normalized := strings.ToLower(strings.TrimSpace(email))

	result := EmailValidationResult{
		Normalized: normalized,
	}

	// Syntax check
	if !isValidEmailSyntax(normalized) {
		result.Reason = "invalid_syntax"
		return result
	}

	parts := strings.SplitN(normalized, "@", 2)
	domain := parts[1]

	// Set free/disposable flags
	result.IsFree = freeProviders[domain]
	result.IsDisposable = disposableDomains[domain]

	// Allowed domains bypass all checks (except syntax)
	if containsDomain(o.AllowedDomains, domain) {
		result.Valid = true
		result.Reason = "valid"
		return result
	}

	// Blocked domains
	if containsDomain(o.BlockedDomains, domain) {
		result.Reason = "blocked"
		return result
	}

	// Disposable check
	if o.CheckDisposable && result.IsDisposable {
		result.Reason = "disposable"
		return result
	}

	// Typo detection
	if o.SuggestTypoFix {
		if suggestion, ok := typoSuggestions[domain]; ok {
			result.Valid = true
			result.Reason = "typo"
			result.Suggestion = parts[0] + "@" + suggestion
			return result
		}
	}

	result.Valid = true
	result.Reason = "valid"
	return result
}

// VerifyEmailMX performs a DNS MX record lookup for the email's domain.
func VerifyEmailMX(email string) bool {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if !isValidEmailSyntax(normalized) {
		return false
	}

	parts := strings.SplitN(normalized, "@", 2)
	domain := parts[1]

	records, err := net.LookupMX(domain)
	if err == nil && len(records) > 0 {
		return true
	}

	// Fallback: try A record lookup
	addrs, err := net.LookupHost(domain)
	return err == nil && len(addrs) > 0
}

// IsValidEmailSyntax performs a syntax-only email validation.
func IsValidEmailSyntax(email string) bool {
	return isValidEmailSyntax(strings.ToLower(strings.TrimSpace(email)))
}

func isValidEmailSyntax(email string) bool {
	if len(email) == 0 || len(email) > maxEmailLength {
		return false
	}

	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}

	local, domain := parts[0], parts[1]

	if len(local) == 0 || len(local) > maxLocalLength {
		return false
	}
	if len(domain) == 0 || len(domain) > maxDomainLength {
		return false
	}

	// No consecutive dots in local part
	if strings.Contains(local, "..") {
		return false
	}
	// No leading/trailing dots in local part
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") {
		return false
	}

	return emailRegex.MatchString(email)
}

func containsDomain(domains []string, domain string) bool {
	for _, d := range domains {
		if strings.ToLower(d) == domain {
			return true
		}
	}
	return false
}
