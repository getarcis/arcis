package validation

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// DefaultMaxFileSize is the default maximum file size (5MB).
const DefaultMaxFileSize = 5 * 1024 * 1024

// ValidateFileOptions configures file upload validation.
type ValidateFileOptions struct {
	MaxSize              int      // Maximum file size in bytes (default: 5MB)
	AllowedTypes         []string // Allowed MIME types (e.g., ["image/jpeg", "image/png"])
	AllowedExtensions    []string // Allowed file extensions with dot (e.g., [".jpg", ".png"])
	BlockExecutables     bool     // Block dangerous/executable extensions (default: true)
	ValidateMagicBytes   bool     // Validate magic bytes match MIME type (default: true)
	BlockNoExtension     bool     // Block files with no extension (default: true)
	BlockDoubleExtensions bool    // Block double extensions like file.php.jpg (default: true)
}

// DefaultValidateFileOptions returns options with all protections enabled.
func DefaultValidateFileOptions() ValidateFileOptions {
	return ValidateFileOptions{
		MaxSize:              DefaultMaxFileSize,
		BlockExecutables:     true,
		ValidateMagicBytes:   true,
		BlockNoExtension:     true,
		BlockDoubleExtensions: true,
	}
}

// FileInput holds file metadata for validation.
type FileInput struct {
	Filename string // Original filename
	Mimetype string // MIME type (as claimed by client)
	Size     int    // File size in bytes
	Content  []byte // File content (for magic byte validation, optional)
}

// ValidateFileResult holds the result of file validation.
type ValidateFileResult struct {
	Valid             bool     `json:"valid"`
	Errors            []string `json:"errors"`
	SanitizedFilename string   `json:"sanitizedFilename"`
}

// Magic byte signatures for common file types.
var magicBytes = map[string][][]byte{
	// Images
	"image/jpeg": {{0xFF, 0xD8, 0xFF}},
	"image/png":  {{0x89, 0x50, 0x4E, 0x47}},
	"image/gif":  {[]byte("GIF87a"), []byte("GIF89a")},
	"image/webp": {[]byte("RIFF")},
	"image/bmp":  {{0x42, 0x4D}},
	// Documents
	"application/pdf": {[]byte("%PDF")},
	"application/zip": {{0x50, 0x4B, 0x03, 0x04}},
	// Audio
	"audio/mpeg": {{0xFF, 0xFB}, {0xFF, 0xF3}, {0x49, 0x44, 0x33}},
}

// Dangerous extensions that can execute code.
var dangerousExtensions = map[string]bool{
	// Scripts
	".exe": true, ".bat": true, ".cmd": true, ".com": true, ".msi": true, ".scr": true, ".pif": true,
	".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".ws": true, ".wsf": true, ".wsc": true, ".wsh": true,
	".ps1": true, ".ps1xml": true, ".ps2": true, ".ps2xml": true, ".psc1": true, ".psc2": true,
	".sh": true, ".bash": true, ".csh": true, ".ksh": true,
	// Server-side
	".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true, ".pht": true,
	".asp": true, ".aspx": true, ".ashx": true, ".asmx": true, ".cer": true,
	".jsp": true, ".jspx": true, ".jsw": true, ".jsv": true,
	".cgi": true, ".pl": true, ".py": true, ".rb": true,
	// Java
	".jar": true, ".war": true, ".ear": true, ".class": true,
	// Config that can execute
	".htaccess": true, ".htpasswd": true,
	// Template engines
	".ejs": true, ".pug": true, ".hbs": true, ".handlebars": true, ".njk": true, ".twig": true,
	// Shortcuts/links
	".lnk": true, ".inf": true, ".reg": true, ".url": true,
	// Office macros
	".docm": true, ".xlsm": true, ".pptm": true, ".dotm": true,
}

var (
	rePathComponents  = regexp.MustCompile(`^.*[/\\]`)
	reControlChars    = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	reUnsafeChars     = regexp.MustCompile(`[<>:"/\\|?*]`)
	reSpacesParens    = regexp.MustCompile(`[\s()]+`)
	reLeadingDots     = regexp.MustCompile(`^\.+`)
	reMultiUnderscores = regexp.MustCompile(`_{2,}`)
	reMultiDots       = regexp.MustCompile(`\.{2,}`)
	reUnderscoreDot   = regexp.MustCompile(`_+\.`)
	reEdgeUnderscores = regexp.MustCompile(`^_+|_+$`)
)

// SanitizeFilename sanitizes a filename for safe storage.
// Strips path traversal, null bytes, control characters, and unsafe characters.
func SanitizeFilename(filename string) string {
	name := filename

	// Strip null bytes
	name = strings.ReplaceAll(name, "\x00", "")

	// Strip path components (both Unix and Windows)
	name = rePathComponents.ReplaceAllString(name, "")

	// Strip control characters
	name = reControlChars.ReplaceAllString(name, "")

	// Strip characters unsafe for filesystems
	name = reUnsafeChars.ReplaceAllString(name, "")

	// Replace spaces and parens with underscores
	name = reSpacesParens.ReplaceAllString(name, "_")

	// Strip leading dots (hidden files / .htaccess)
	name = reLeadingDots.ReplaceAllString(name, "")

	// Collapse multiple underscores/dots
	name = reMultiUnderscores.ReplaceAllString(name, "_")
	name = reMultiDots.ReplaceAllString(name, ".")

	// Trim underscores before dots
	name = reUnderscoreDot.ReplaceAllString(name, ".")

	// Trim underscores from edges
	name = reEdgeUnderscores.ReplaceAllString(name, "")

	// Fallback for empty name
	if name == "" || name == "." {
		name = "unnamed"
	}

	return name
}

// ValidateFile validates a file upload for security.
func ValidateFile(file FileInput, opts *ValidateFileOptions) ValidateFileResult {
	o := DefaultValidateFileOptions()
	if opts != nil {
		if opts.MaxSize > 0 {
			o.MaxSize = opts.MaxSize
		}
		o.AllowedTypes = opts.AllowedTypes
		o.AllowedExtensions = opts.AllowedExtensions
		// Only override booleans if opts was provided — check by using the struct directly
		o.BlockExecutables = opts.BlockExecutables
		o.ValidateMagicBytes = opts.ValidateMagicBytes
		o.BlockNoExtension = opts.BlockNoExtension
		o.BlockDoubleExtensions = opts.BlockDoubleExtensions
	}

	var errors []string
	sanitized := SanitizeFilename(file.Filename)
	ext := getFileExtension(sanitized)

	// Size check
	if file.Size > o.MaxSize {
		errors = append(errors, fmt.Sprintf("File size %d exceeds maximum %d bytes", file.Size, o.MaxSize))
	}
	if file.Size == 0 {
		errors = append(errors, "File is empty")
	}

	// Extension checks
	if o.BlockNoExtension && ext == "" {
		errors = append(errors, "File has no extension")
	}

	if o.BlockExecutables && ext != "" && dangerousExtensions[ext] {
		errors = append(errors, fmt.Sprintf("Executable extension %q is not allowed", ext))
	}

	if o.BlockDoubleExtensions && hasDoubleExtension(sanitized) {
		errors = append(errors, "Double extensions with executable types are not allowed")
	}

	if len(o.AllowedExtensions) > 0 && ext != "" {
		allowed := false
		for _, ae := range o.AllowedExtensions {
			if strings.EqualFold(ae, ext) {
				allowed = true
				break
			}
		}
		if !allowed {
			normalized := make([]string, len(o.AllowedExtensions))
			for i, e := range o.AllowedExtensions {
				normalized[i] = strings.ToLower(e)
			}
			errors = append(errors, fmt.Sprintf("Extension %q is not allowed. Allowed: %s", ext, strings.Join(normalized, ", ")))
		}
	}

	// MIME type check
	if len(o.AllowedTypes) > 0 {
		allowed := false
		for _, at := range o.AllowedTypes {
			if at == file.Mimetype {
				allowed = true
				break
			}
		}
		if !allowed {
			errors = append(errors, fmt.Sprintf("MIME type %q is not allowed. Allowed: %s", file.Mimetype, strings.Join(o.AllowedTypes, ", ")))
		}
	}

	// Magic bytes validation
	if o.ValidateMagicBytes && len(file.Content) > 0 {
		if !matchesMagicBytes(file.Content, file.Mimetype) {
			errors = append(errors, fmt.Sprintf("File content does not match claimed MIME type %q", file.Mimetype))
		}
	}

	if errors == nil {
		errors = []string{}
	}

	return ValidateFileResult{
		Valid:             len(errors) == 0,
		Errors:            errors,
		SanitizedFilename: sanitized,
	}
}

// IsDangerousExtension checks if a file extension is considered dangerous/executable.
func IsDangerousExtension(filename string) bool {
	ext := getFileExtension(filename)
	return ext != "" && dangerousExtensions[ext]
}

func getFileExtension(filename string) string {
	lastDot := strings.LastIndex(filename, ".")
	if lastDot < 1 {
		return ""
	}
	return strings.ToLower(filename[lastDot:])
}

func hasDoubleExtension(filename string) bool {
	parts := strings.Split(filename, ".")
	if len(parts) < 3 {
		return false
	}
	// Check if any non-final extension is dangerous
	for i := 1; i < len(parts)-1; i++ {
		ext := "." + strings.ToLower(parts[i])
		if dangerousExtensions[ext] {
			return true
		}
	}
	return false
}

func matchesMagicBytes(content []byte, mimetype string) bool {
	signatures, exists := magicBytes[mimetype]
	if !exists || len(signatures) == 0 {
		return true // no signature to check
	}

	for _, sig := range signatures {
		if len(content) >= len(sig) && bytes.Equal(content[:len(sig)], sig) {
			return true
		}
	}
	return false
}
