/*
Package arcis provides security middleware for Go web applications.

The root package (`arcis.Protect`, `arcis.NewWithConfig`) ships:
  - Rate limiting with configurable windows and limits
  - Security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Fingerprint-header stripping (Server, X-Powered-By)

For request-body sanitization and block-mode (XSS / SQL / NoSQL / path /
command / SSTI / XXE / LDAP / XPath / email-header / prototype-pollution
patterns return 403 before the handler runs), use a framework adapter:

	import arcisgin "github.com/getarcis/arcis/v2/gin"

	r := gin.Default()
	cfg := arcisgin.DefaultConfig()
	cfg.Block = true
	r.Use(arcisgin.MiddlewareWithConfig(cfg))

The adapter packages (gin / echo / chi / fiber / nethttp) call
`arcis.ScanThreats` against body / query / URL path on every request.
The root `arcis.Protect(handler)` shorthand does NOT scan bodies; it
only applies headers + rate-limit. Use it when you want a stdlib-only
wrapper without body inspection.

Additional helpers (request validation, safe logging with PII redaction,
production-safe error handling, SSRF URL validation, open-redirect
validation) are available from the `arcis/validation`, `arcis/logging`,
`arcis/middleware`, and `arcis/utils` sub-packages.

v1.6.2 helpers (`CorrelationWindow`, `DetectDeserialization`, GraphQL
V34 inspectors, mutation tester) are accessible from
`arcis/middleware/correlation`, `arcis/sanitizers/deserialization`, and
`arcis/sanitizers/graphql`. Root-level re-exports land in v1.7.

Usage with net/http:

	import "github.com/getarcis/arcis/v2"

	// Headers + rate-limit only (no body sanitization)
	http.Handle("/", arcis.Protect(myHandler))

	// Custom config (still headers + rate-limit, no body scan)
	s := arcis.NewWithConfig(arcis.Config{
		RateLimitMax: 50,
		CSP: "default-src 'none'",
	})
	http.Handle("/", s.Handler(myHandler))

	// Full pipeline (body sanitization + block mode) — use chi adapter
	import archttp "github.com/getarcis/arcis/v2/nethttp"
	cfg := archttp.DefaultConfig()
	cfg.Block = true
	var h http.Handler = mux
	h = archttp.MiddlewareWithConfig(cfg)(h)

Usage with Gin:

	import "github.com/getarcis/arcis/v2/gin"

	r := gin.Default()
	r.Use(arcisgin.Middleware())

Usage with Echo:

	import "github.com/getarcis/arcis/v2/echo"

	e := echo.New()
	e.Use(arcisecho.Middleware())
*/
package arcis

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/getarcis/arcis/v2/core"
	"github.com/getarcis/arcis/v2/guards"
	"github.com/getarcis/arcis/v2/logging"
	"github.com/getarcis/arcis/v2/middleware"
	"github.com/getarcis/arcis/v2/sanitizers"
	"github.com/getarcis/arcis/v2/stores"
	"github.com/getarcis/arcis/v2/utils"
	"github.com/getarcis/arcis/v2/validation"
)

// ─── Type aliases (backward compatibility) ──────────────────────────────────

// Core types
type Config = core.Config
type RateLimitResult = core.RateLimitResult
type RateLimitEntry = core.RateLimitEntry
type RateLimitStore = core.RateLimitStore
type InputTooLargeError = core.InputTooLargeError

// Sanitizer types
type Sanitizer = sanitizers.Sanitizer

// Middleware types
type RateLimiter = middleware.RateLimiter
type SecurityHeaders = middleware.SecurityHeaders
type ErrorHandler = middleware.ErrorHandler
type SafeCors = middleware.SafeCors
type CorsOptions = middleware.CorsOptions
type CorsOrigin = middleware.CorsOrigin
type CorsHeaders = middleware.CorsHeaders
type SecureCookieDefaults = middleware.SecureCookieDefaults
type SecureCookieOptions = middleware.SecureCookieOptions
type CsrfProtection = middleware.CsrfProtection
type CsrfOptions = middleware.CsrfOptions
type CsrfCookieOptions = middleware.CsrfCookieOptions
type SlidingWindowLimiter = middleware.SlidingWindowLimiter
type TokenBucketLimiter = middleware.TokenBucketLimiter
type BotCategory = middleware.BotCategory
type BotDetectionResult = middleware.BotDetectionResult
type BotProtectionOptions = middleware.BotProtectionOptions

// Logging types
type SafeLogger = logging.SafeLogger

// Validation types
type FieldType = validation.FieldType
type FieldRule = validation.FieldRule
type ValidationSchema = validation.ValidationSchema
type ValidationError = validation.ValidationError
type Validator = validation.Validator

// URL/Redirect types
type ValidateURLOptions = utils.ValidateURLOptions
type ValidateURLResult = utils.ValidateURLResult
type ValidateRedirectOptions = utils.ValidateRedirectOptions
type ValidateRedirectResult = utils.ValidateRedirectResult
type Platform = utils.Platform
type DetectIPOptions = utils.DetectIPOptions
type FingerprintOptions = utils.FingerprintOptions

// Sanitizer PII types
type PiiType = sanitizers.PiiType
type PiiMatch = sanitizers.PiiMatch
type PiiScanOptions = sanitizers.PiiScanOptions
type PiiRedactOptions = sanitizers.PiiRedactOptions

// Prompt-injection types
type PromptInjectionMatch = sanitizers.PromptInjectionMatch
type PromptInjectionResult = sanitizers.PromptInjectionResult
type PromptInjectionSeverity = sanitizers.PromptInjectionSeverity

var (
	DetectPromptInjection   = sanitizers.DetectPromptInjection
	SanitizePromptInjection = sanitizers.SanitizePromptInjection
)

// Token-budget protection (LLM-cost guard) types
type TokenBudgetOptions = middleware.TokenBudgetOptions
type TokenBudget = middleware.TokenBudget

var NewTokenBudget = middleware.NewTokenBudget

// Guards API: extend Arcis decisions to non-HTTP contexts (jobs, queues,
// agent tool handlers, gRPC). See packages/arcis-go/guards.
//
//	g := arcis.NewGuards(arcis.GuardsConfig{...})
//	defer g.Close()
//	d := g.Run(arcis.GuardsInput{Key: jobUserID, Text: prompt, Tokens: cost})
//	if !d.OK { ... }
type GuardsConfig = guards.Config
type GuardsInput = guards.Input
type GuardsDecision = guards.Decision
type GuardsVector = guards.Vector
type GuardsSeverity = guards.Severity
type GuardsRateLimitOptions = guards.RateLimitOptions
type GuardsTokenBudgetOptions = guards.TokenBudgetOptions
type GuardsPromptInjectionOptions = guards.PromptInjectionOptions
type GuardsBotOptions = guards.BotOptions

var NewGuards = guards.New

// Email validation types
type EmailValidationResult = validation.EmailValidationResult
type EmailValidationOptions = validation.EmailValidationOptions

// File validation types
type ValidateFileOptions = validation.ValidateFileOptions
type FileInput = validation.FileInput
type ValidateFileResult = validation.ValidateFileResult

// Store types
type RedisClient = stores.RedisClient
type RedisStoreOptions = stores.RedisStoreOptions
type RedisRateLimitStore = stores.RedisRateLimitStore

// ─── Constants (re-exported) ────────────────────────────────────────────────

const Version = core.Version
const MaxRecursionDepth = core.MaxRecursionDepth
const DefaultMaxInputSize = core.DefaultMaxInputSize

// Platform constants
const (
	PlatformAuto       = utils.PlatformAuto
	PlatformGeneric    = utils.PlatformGeneric
	PlatformCloudflare = utils.PlatformCloudflare
	PlatformVercel     = utils.PlatformVercel
	PlatformFlyio      = utils.PlatformFlyio
	PlatformRender     = utils.PlatformRender
	PlatformFirebase   = utils.PlatformFirebase
	PlatformAWSALB     = utils.PlatformAWSALB
)

// Bot category constants
const (
	BotCategorySearchEngine = middleware.BotCategorySearchEngine
	BotCategorySocial       = middleware.BotCategorySocial
	BotCategoryMonitoring   = middleware.BotCategoryMonitoring
	BotCategoryAICrawler    = middleware.BotCategoryAICrawler
	BotCategoryScraper      = middleware.BotCategoryScraper
	BotCategoryAutomated    = middleware.BotCategoryAutomated
	BotCategoryUnknown      = middleware.BotCategoryUnknown
	BotCategoryHuman        = middleware.BotCategoryHuman
)

// PII type constants
const (
	PiiEmail      = sanitizers.PiiEmail
	PiiPhone      = sanitizers.PiiPhone
	PiiCreditCard = sanitizers.PiiCreditCard
	PiiSSN        = sanitizers.PiiSSN
	PiiIPAddress  = sanitizers.PiiIPAddress
)

// Validation field type constants
const (
	TypeString  = validation.TypeString
	TypeNumber  = validation.TypeNumber
	TypeBoolean = validation.TypeBoolean
	TypeEmail   = validation.TypeEmail
	TypeURL     = validation.TypeURL
	TypeUUID    = validation.TypeUUID
	TypeArray   = validation.TypeArray
	TypeObject  = validation.TypeObject
)

// ─── Constructor re-exports ─────────────────────────────────────────────────

// DefaultConfig returns the default Arcis configuration.
var DefaultConfig = core.DefaultConfig

// NewSanitizer creates a new Sanitizer with the given configuration.
var NewSanitizer = sanitizers.NewSanitizer

// NewSanitizerWithOptions creates a sanitizer with explicit options.
var NewSanitizerWithOptions = sanitizers.NewSanitizerWithOptions

// NewRateLimiter creates a new RateLimiter with the given limit and window.
var NewRateLimiter = middleware.NewRateLimiter

// NewRateLimiterWithStore creates a new RateLimiter backed by the provided store.
var NewRateLimiterWithStore = middleware.NewRateLimiterWithStore

// NewSecurityHeaders creates a new SecurityHeaders with the given configuration.
var NewSecurityHeaders = middleware.NewSecurityHeaders

// NewErrorHandler creates a new ErrorHandler.
var NewErrorHandler = middleware.NewErrorHandler

// NewErrorHandlerWithLogger creates an ErrorHandler with a custom logger.
var NewErrorHandlerWithLogger = middleware.NewErrorHandlerWithLogger

// ContainsSensitiveInfo checks if an error message contains sensitive info.
var ContainsSensitiveInfo = middleware.ContainsSensitiveInfo

// NewSafeCors creates a SafeCors instance with the given options.
var NewSafeCors = middleware.NewSafeCors

// SafeCorsMiddleware creates a CORS http.Handler middleware from options.
var SafeCorsMiddleware = middleware.SafeCorsMiddleware

// NewSecureCookieDefaults creates a SecureCookieDefaults with the given options.
var NewSecureCookieDefaults = middleware.NewSecureCookieDefaults

// EnforceSecureCookie enforces secure defaults on a Set-Cookie header value.
var EnforceSecureCookie = middleware.EnforceSecureCookie

// SecureCookieMiddleware creates a secure cookie middleware from options.
var SecureCookieMiddleware = middleware.SecureCookieMiddleware

// NewCsrfProtection creates a CsrfProtection with the given options.
var NewCsrfProtection = middleware.NewCsrfProtection

// GenerateCsrfToken generates a cryptographically random CSRF token.
var GenerateCsrfToken = middleware.GenerateCsrfToken

// ValidateCsrfToken compares two CSRF tokens using constant-time comparison.
var ValidateCsrfToken = middleware.ValidateCsrfToken

// CsrfMiddleware creates a CSRF protection middleware from options.
var CsrfMiddleware = middleware.CsrfMiddleware

// NewSafeLogger creates a new SafeLogger with default settings.
var NewSafeLogger = logging.NewSafeLogger

// NewSafeLoggerWithKeys creates a SafeLogger with custom sensitive keys.
var NewSafeLoggerWithKeys = logging.NewSafeLoggerWithKeys

// NewSafeLoggerOnlyKeys creates a SafeLogger with ONLY the specified keys.
var NewSafeLoggerOnlyKeys = logging.NewSafeLoggerOnlyKeys

// NewValidator creates a new Validator with the given schema.
var NewValidator = validation.NewValidator

// ValidateHandler creates middleware that validates request body.
var ValidateHandler = validation.ValidateHandler

// GetValidatedBody retrieves the validated body from request context.
var GetValidatedBody = validation.GetValidatedBody

// Float is a helper for creating FieldRule with Min/Max.
var Float = validation.Float

// SanitizeHeaderValue strips CRLF/null bytes from a header value.
var SanitizeHeaderValue = sanitizers.SanitizeHeaderValue

// SanitizeHeaders sanitizes a map of HTTP header key-value pairs.
var SanitizeHeaders = sanitizers.SanitizeHeaders

// DetectHeaderInjection checks if a string contains header injection patterns.
var DetectHeaderInjection = sanitizers.DetectHeaderInjection

// ValidateURL checks a URL for SSRF safety.
var ValidateURL = utils.ValidateURL

// IsURLSafe is a convenience wrapper that returns true/false.
var IsURLSafe = utils.IsURLSafe

// ValidateRedirect checks a redirect URL for open redirect attacks.
var ValidateRedirect = utils.ValidateRedirect

// IsRedirectSafe is a convenience wrapper that returns true/false.
var IsRedirectSafe = utils.IsRedirectSafe

// GetClientIP extracts the client IP address from the request.
var GetClientIP = utils.GetClientIP

// ─── Tier 2: Rate Limiter Variants ──────────────────────────────────────────

// NewSlidingWindowLimiter creates a weighted sliding window rate limiter.
var NewSlidingWindowLimiter = middleware.NewSlidingWindowLimiter

// NewTokenBucketLimiter creates a token bucket rate limiter.
var NewTokenBucketLimiter = middleware.NewTokenBucketLimiter

// NewTokenBucketLimiterWithCost creates a token bucket limiter with custom per-request cost.
var NewTokenBucketLimiterWithCost = middleware.NewTokenBucketLimiterWithCost

// ─── Tier 2: Platform-Aware IP Detection ────────────────────────────────────

// DetectClientIP extracts the client IP using platform-aware header detection.
var DetectClientIP = utils.DetectClientIP

// IsPrivateIP checks if an IP address is in a private/reserved range.
var IsPrivateIP = utils.IsPrivateIP

// ─── Tier 2: Request Fingerprinting ─────────────────────────────────────────

// Fingerprint generates a SHA-256 hash fingerprint of the request.
var Fingerprint = utils.Fingerprint

// ─── Tier 2: Duration Parsing ───────────────────────────────────────────────

// ParseDuration parses human-readable durations like "5m", "1h", "30s", "1d".
var ParseDuration = utils.ParseDuration

// FormatDuration formats a time.Duration into a human-readable string.
var FormatDuration = utils.FormatDuration

// ─── Tier 2: Email Validation ───────────────────────────────────────────────

// ValidateEmail validates an email address with disposable detection and typo suggestions.
var ValidateEmail = validation.ValidateEmail

// VerifyEmailMX performs a DNS MX record lookup for the email's domain.
var VerifyEmailMX = validation.VerifyEmailMX

// IsValidEmailSyntax performs a syntax-only email validation.
var IsValidEmailSyntax = validation.IsValidEmailSyntax

// ─── Tier 2: Bot Detection ─────────────────────────────────────────────────

// DetectBot analyzes a request to determine if it's from a bot.
var DetectBot = middleware.DetectBot

// BotProtection creates an http.Handler middleware for bot detection.
var BotProtection = middleware.BotProtection

// ─── Tier 2: Signup Protection ──────────────────────────────────────────────

// NewSignupProtection creates a composite signup-form protector combining
// email validation, bot detection, and a dedicated per-IP rate limit.
var NewSignupProtection = middleware.NewSignupProtection

// DefaultSignupProtectionOptions returns options with every check enabled.
var DefaultSignupProtectionOptions = middleware.DefaultSignupProtectionOptions

type (
	SignupProtection        = middleware.SignupProtection
	SignupProtectionOptions = middleware.SignupProtectionOptions
	SignupCheckResult       = middleware.SignupCheckResult
	SignupBlockReason       = middleware.SignupBlockReason
)

// ─── Tier 2: PII Scanning/Redaction ─────────────────────────────────────────

// ScanPii finds all PII occurrences in a string.
var ScanPii = sanitizers.ScanPii

// DetectPii checks if a string contains any PII.
var DetectPii = sanitizers.DetectPii

// RedactPii replaces all PII in a string with placeholders.
var RedactPii = sanitizers.RedactPii

// ScanObjectPii recursively scans a map for PII in string values.
var ScanObjectPii = sanitizers.ScanObjectPii

// RedactObjectPii recursively redacts PII in a map.
var RedactObjectPii = sanitizers.RedactObjectPii

// ─── Redis Store ─────────────────────────────────────────────────────────────

// NewRedisRateLimitStore creates a new Redis-backed rate limit store.
var NewRedisRateLimitStore = stores.NewRedisRateLimitStore

// ─── Standalone Sanitize Functions ───────────────────────────────────────────

// SanitizeXSS removes XSS patterns and HTML-encodes dangerous characters.
var SanitizeXSS = sanitizers.SanitizeXSS

// SanitizeSQL removes SQL injection patterns from input.
var SanitizeSQL = sanitizers.SanitizeSQL

// SanitizePath removes path traversal patterns from input.
var SanitizePath = sanitizers.SanitizePath

// SanitizeCommand removes command injection patterns from input.
var SanitizeCommand = sanitizers.SanitizeCommand

// ─── Detect Functions ────────────────────────────────────────────────────────

// DetectXSS checks if a string contains XSS patterns.
var DetectXSS = sanitizers.DetectXSS

// DetectSQL checks if a string contains SQL injection patterns.
var DetectSQL = sanitizers.DetectSQL

// DetectPathTraversal checks if a string contains path traversal patterns.
var DetectPathTraversal = sanitizers.DetectPathTraversal

// DetectCommandInjection checks if a string contains command injection patterns.
var DetectCommandInjection = sanitizers.DetectCommandInjection

// DetectSSTI checks if a string contains server-side template injection patterns.
var DetectSSTI = sanitizers.DetectSSTI

// DetectXXE checks if a string contains XML external entity injection patterns.
var DetectXXE = sanitizers.DetectXXE

// DetectNoSQLInjection checks if a map contains NoSQL injection operators.
var DetectNoSQLInjection = sanitizers.DetectNoSQLInjection

// DetectPrototypePollution checks if a map contains prototype pollution keys.
var DetectPrototypePollution = sanitizers.DetectPrototypePollution

// ThreatHit describes the first attack pattern found while scanning a request.
type ThreatHit = sanitizers.ThreatHit

// ScanThreats walks data and returns the first threat hit found, or nil.
var ScanThreats = sanitizers.ScanThreats

// ─── Helper Functions ────────────────────────────────────────────────────────

// IsDangerousNoSQLKey checks if a key is a dangerous NoSQL operator.
var IsDangerousNoSQLKey = sanitizers.IsDangerousNoSQLKey

// IsDangerousProtoKey checks if a key is a dangerous prototype pollution key.
var IsDangerousProtoKey = sanitizers.IsDangerousProtoKey

// GetDangerousOperators returns all blocked NoSQL operators.
var GetDangerousOperators = sanitizers.GetDangerousOperators

// GetDangerousProtoKeys returns all blocked prototype pollution keys.
var GetDangerousProtoKeys = sanitizers.GetDangerousProtoKeys

// EncodeHTMLEntities encodes HTML special characters in a string.
var EncodeHTMLEntities = sanitizers.EncodeHTMLEntities

// ─── Context-Aware Encoding ────────────────────────────────────────────────

// EncodeForHTML encodes for HTML body context (entity-encodes & < > " ').
var EncodeForHTML = sanitizers.EncodeForHTML

// EncodeForAttribute encodes for HTML attribute context (&#xHH; entities).
var EncodeForAttribute = sanitizers.EncodeForAttribute

// EncodeForJS encodes for JavaScript string context (\xHH / \uHHHH escaping).
var EncodeForJS = sanitizers.EncodeForJS

// EncodeForURL encodes for URL parameter context (percent encoding).
var EncodeForURL = sanitizers.EncodeForURL

// EncodeForCSS encodes for CSS value context (\HH hex escaping).
var EncodeForCSS = sanitizers.EncodeForCSS

// ─── LDAP Injection Prevention ───────────────────────────────────────────────

// SanitizeLdapFilter sanitizes a string for safe use in LDAP filter expressions (RFC 4515).
var SanitizeLdapFilter = sanitizers.SanitizeLdapFilter

// SanitizeLdapDn sanitizes a string for safe use in LDAP Distinguished Names (RFC 4514).
var SanitizeLdapDn = sanitizers.SanitizeLdapDn

// DetectLdapInjection checks if a string contains any LDAP injection
// patterns (including unescaped special chars). Use at sanitization
// context.
var DetectLdapInjection = sanitizers.DetectLdapInjection

// DetectLdapInjectionStrict checks only the attack-specific shapes ')(',
// '*)(', and the v1.6.2 ')(!', '&(!', '|(!' NOT-bypass shapes. Safe to
// use at request-boundary scanners where DetectLdapInjection would
// false-positive on legitimate parenthesised input.
var DetectLdapInjectionStrict = sanitizers.DetectLdapInjectionStrict

// ─── XPath Injection Prevention ──────────────────────────────────────────────

// DetectXPathInjection checks if a string contains XPath injection
// attack shapes.
var DetectXPathInjection = sanitizers.DetectXPathInjection

// SanitizeXPath sanitizes a string for safe use inside an XPath expression.
var SanitizeXPath = sanitizers.SanitizeXPath

// ─── Email-Header Injection Prevention ───────────────────────────────────────

// DetectEmailHeaderInjection checks if a string contains SMTP header
// injection patterns (CR / LF / NUL plus the Q10 v1.6.2 bare-newline
// bypass shapes).
var DetectEmailHeaderInjection = sanitizers.DetectEmailHeaderInjection

// ─── SSTI / XXE Standalone Sanitizers ────────────────────────────────────────

// SanitizeSSTI strips server-side template injection patterns from input.
var SanitizeSSTI = sanitizers.SanitizeSSTI

// SanitizeXXE strips XML external entity injection patterns from input.
var SanitizeXXE = sanitizers.SanitizeXXE

// ─── V33 (v1.6.2): Deserialization Marker Detection ──────────────────────────

// DeserializeRuntime is the tag returned by DetectDeserialization.
type DeserializeRuntime = sanitizers.DeserializeRuntime

// Runtime tags returned by DetectDeserialization.
const (
	DeserializePythonPickle          = sanitizers.DeserializePythonPickle
	DeserializeJavaFastJSON          = sanitizers.DeserializeJavaFastJSON
	DeserializePhpUnserialize        = sanitizers.DeserializePhpUnserialize
	DeserializeRubyMarshal           = sanitizers.DeserializeRubyMarshal
	DeserializeDotnetBinaryFormatter = sanitizers.DeserializeDotnetBinaryFormatter
	DeserializeNone                  = sanitizers.DeserializeNone
)

// DetectDeserialization detects modern serialized-object marker bytes
// (Python pickle, Java FastJSON, PHP unserialize, Ruby Marshal, .NET
// BinaryFormatter). Returns the runtime tag if a marker matches, or
// DeserializeNone if the input looks safe. Detection-only.
var DetectDeserialization = sanitizers.DetectDeserialization

// IsSerializedPayload is the boolean wrapper around DetectDeserialization.
var IsSerializedPayload = sanitizers.IsSerializedPayload

// ─── V34 (v1.6.2): GraphQL Alias Bomb + Fragment Cycle ───────────────────────

// GraphqlGuardOptions configures the GraphQL query inspector.
type GraphqlGuardOptions = sanitizers.GraphqlGuardOptions

// GraphqlGuardResult is the structured outcome of inspecting a GraphQL query.
type GraphqlGuardResult = sanitizers.GraphqlGuardResult

// NewGraphqlGuardOptions returns the documented defaults (MaxDepth: 10,
// MaxLength: 10000, BlockIntrospection: true, MaxAliases: 50,
// BlockFragmentCycles: true). Use this instead of GraphqlGuardOptions{}
// because Go's zero-value semantics on the bool fields would otherwise
// disable BlockIntrospection + BlockFragmentCycles.
var NewGraphqlGuardOptions = sanitizers.NewGraphqlGuardOptions

// InspectGraphqlQuery inspects a query against the configured limits.
// Pure function; middleware wraps it.
var InspectGraphqlQuery = sanitizers.InspectGraphqlQuery

// DetectGraphqlAbuse returns true if the query would be blocked at
// default settings. Boolean wrapper around InspectGraphqlQuery.
var DetectGraphqlAbuse = sanitizers.DetectGraphqlAbuse

// ─── v1.6.2: Stateful Per-IP Correlation Window ──────────────────────────────

// CorrelationWindow tracks a rolling per-IP event window with three
// detectors: scanner sweep, credential stuffing, race-window probe.
type CorrelationWindow = middleware.CorrelationWindow

// CorrelationWindowOptions configures the window thresholds.
type CorrelationWindowOptions = middleware.CorrelationWindowOptions

// CorrelationEvent is one recorded event in the window.
type CorrelationEvent = middleware.CorrelationEvent

// CorrelationDetections is the result returned from Record.
type CorrelationDetections = middleware.CorrelationDetections

// NewCorrelationWindow returns a configured CorrelationWindow.
var NewCorrelationWindow = middleware.NewCorrelationWindow

// NewCorrelationWindowOptions returns the documented defaults
// (WindowSeconds: 60, MaxIps: 10000, MaxEventsPerIp: 200,
// ScannerDistinctVectors: 3, ScannerMinRequests: 20,
// CredentialStuffingDistinctValues: 10, RaceWindowMs: 200).
var NewCorrelationWindowOptions = middleware.NewCorrelationWindowOptions

// ─── HPP (HTTP Parameter Pollution) Middleware ───────────────────────────────

// HppMiddleware deduplicates HTTP parameters to prevent pollution attacks.
var HppMiddleware = middleware.HppMiddleware

// ─── Tier 2: File Upload Validation ─────────────────────────────────────────

// ValidateFile validates a file upload for security.
var ValidateFile = validation.ValidateFile

// SanitizeFilename sanitizes a filename for safe storage.
var SanitizeFilename = validation.SanitizeFilename

// IsDangerousExtension checks if a file extension is dangerous/executable.
var IsDangerousExtension = validation.IsDangerousExtension

// ─── Arcis main struct ──────────────────────────────────────────────────────

// Arcis is the main security middleware.
type Arcis struct {
	config       Config
	sanitizer    *Sanitizer
	rateLimiter  *RateLimiter
	headers      *SecurityHeaders
	errorHandler *ErrorHandler
}

// New creates a new Arcis instance with default configuration.
func New() *Arcis {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new Arcis instance with custom configuration.
func NewWithConfig(config Config) *Arcis {
	s := &Arcis{config: config}

	if config.Sanitize {
		s.sanitizer = NewSanitizer(config)
	}

	if config.RateLimit {
		if config.RateLimitStore != nil {
			s.rateLimiter = NewRateLimiterWithStore(config.RateLimitMax, config.RateLimitWindow, config.RateLimitStore)
		} else {
			s.rateLimiter = NewRateLimiter(config.RateLimitMax, config.RateLimitWindow)
		}
		if config.RateLimitSkip != nil {
			s.rateLimiter.SetSkipFunc(config.RateLimitSkip)
		}
	}

	if config.Headers {
		s.headers = NewSecurityHeaders(config)
	}

	s.errorHandler = NewErrorHandler(config.IsDev)

	return s
}

// Protect wraps an http.Handler with Arcis protection using default config.
func Protect(handler http.Handler) http.Handler {
	return New().Handler(handler)
}

// Handler returns an http.Handler middleware.
func (s *Arcis) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Rate limiting
		if s.rateLimiter != nil {
			result := s.rateLimiter.Check(r)

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(result.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.Itoa(int(result.Reset.Seconds())))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(result.Reset.Seconds())))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":      "Too many requests, please try again later.",
					"retryAfter": int(result.Reset.Seconds()),
				})
				return
			}
		}

		// Security headers
		if s.headers != nil {
			for key, value := range s.headers.GetHeaders() {
				w.Header().Set(key, value)
			}
		}

		// Remove fingerprinting headers
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")

		next.ServeHTTP(w, r)
	})
}

// Close gracefully shuts down the Arcis instance, cleaning up resources.
func (s *Arcis) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// Sanitize sanitizes a string value.
func (s *Arcis) Sanitize(value string) string {
	if s.sanitizer == nil {
		return value
	}
	return s.sanitizer.SanitizeString(value)
}

// SanitizeMap sanitizes a map (like JSON body).
func (s *Arcis) SanitizeMap(data map[string]interface{}) map[string]interface{} {
	if s.sanitizer == nil {
		return data
	}
	return s.sanitizer.SanitizeMap(data)
}

// SanitizeBody reads, sanitizes, and returns JSON body from request.
func (s *Arcis) SanitizeBody(r *http.Request) (map[string]interface{}, error) {
	if s.sanitizer == nil {
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			return nil, err
		}
		return data, nil
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return s.sanitizer.SanitizeMap(data), nil
}
