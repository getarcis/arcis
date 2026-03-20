package validation

import (
	"testing"
)

// ─── SanitizeFilename tests ─────────────────────────────────────────────────

func TestSanitizeFilename_Normal(t *testing.T) {
	if r := SanitizeFilename("photo.jpg"); r != "photo.jpg" {
		t.Errorf("Expected 'photo.jpg', got %q", r)
	}
}

func TestSanitizeFilename_PathTraversal(t *testing.T) {
	if r := SanitizeFilename("../../etc/passwd"); r != "passwd" {
		t.Errorf("Expected 'passwd', got %q", r)
	}
}

func TestSanitizeFilename_WindowsPath(t *testing.T) {
	if r := SanitizeFilename(`C:\Users\file.txt`); r != "file.txt" {
		t.Errorf("Expected 'file.txt', got %q", r)
	}
}

func TestSanitizeFilename_UnsafeChars(t *testing.T) {
	if r := SanitizeFilename("file<name>.jpg"); r != "filename.jpg" {
		t.Errorf("Expected 'filename.jpg', got %q", r)
	}
}

func TestSanitizeFilename_Spaces(t *testing.T) {
	if r := SanitizeFilename("photo (1).jpg"); r != "photo_1.jpg" {
		t.Errorf("Expected 'photo_1.jpg', got %q", r)
	}
}

func TestSanitizeFilename_LeadingDots(t *testing.T) {
	if r := SanitizeFilename(".htaccess"); r != "htaccess" {
		t.Errorf("Expected 'htaccess', got %q", r)
	}
}

func TestSanitizeFilename_HiddenFile(t *testing.T) {
	if r := SanitizeFilename("...secret"); r != "secret" {
		t.Errorf("Expected 'secret', got %q", r)
	}
}

func TestSanitizeFilename_NullBytes(t *testing.T) {
	if r := SanitizeFilename("file\x00.jpg"); r != "file.jpg" {
		t.Errorf("Expected 'file.jpg', got %q", r)
	}
}

func TestSanitizeFilename_ControlChars(t *testing.T) {
	if r := SanitizeFilename("file\n\r\t.jpg"); r != "file.jpg" {
		t.Errorf("Expected 'file.jpg', got %q", r)
	}
}

func TestSanitizeFilename_MultipleUnderscores(t *testing.T) {
	if r := SanitizeFilename("file___name.jpg"); r != "file_name.jpg" {
		t.Errorf("Expected 'file_name.jpg', got %q", r)
	}
}

func TestSanitizeFilename_MultipleDots(t *testing.T) {
	if r := SanitizeFilename("file...jpg"); r != "file.jpg" {
		t.Errorf("Expected 'file.jpg', got %q", r)
	}
}

func TestSanitizeFilename_UnderscoreBeforeDot(t *testing.T) {
	if r := SanitizeFilename("photo_1_.jpg"); r != "photo_1.jpg" {
		t.Errorf("Expected 'photo_1.jpg', got %q", r)
	}
}

func TestSanitizeFilename_Empty(t *testing.T) {
	if r := SanitizeFilename(""); r != "unnamed" {
		t.Errorf("Expected 'unnamed', got %q", r)
	}
}

func TestSanitizeFilename_OnlyDots(t *testing.T) {
	if r := SanitizeFilename("..."); r != "unnamed" {
		t.Errorf("Expected 'unnamed', got %q", r)
	}
}

func TestSanitizeFilename_OnlySpecialChars(t *testing.T) {
	if r := SanitizeFilename("<>:\"/\\|?*"); r != "unnamed" {
		t.Errorf("Expected 'unnamed', got %q", r)
	}
}

// ─── IsDangerousExtension tests ─────────────────────────────────────────────

func TestIsDangerousExtension_Dangerous(t *testing.T) {
	dangerous := []string{
		"malware.exe", "script.bat", "hack.cmd", "setup.msi",
		"shell.php", "backdoor.jsp", "exploit.asp", "run.sh",
		"macro.docm", "link.lnk", "template.ejs",
		"payload.jar", "config.htaccess",
	}
	for _, f := range dangerous {
		if !IsDangerousExtension(f) {
			t.Errorf("Expected %q to be dangerous", f)
		}
	}
}

func TestIsDangerousExtension_Safe(t *testing.T) {
	safe := []string{
		"photo.jpg", "doc.pdf", "data.csv", "page.html",
		"image.png", "video.mp4", "archive.zip", "style.css",
	}
	for _, f := range safe {
		if IsDangerousExtension(f) {
			t.Errorf("Expected %q to be safe", f)
		}
	}
}

func TestIsDangerousExtension_NoExtension(t *testing.T) {
	if IsDangerousExtension("README") {
		t.Error("No extension should not be dangerous")
	}
}

// ─── ValidateFile tests ─────────────────────────────────────────────────────

func TestValidateFile_ValidImage(t *testing.T) {
	jpegContent := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00}
	result := ValidateFile(FileInput{
		Filename: "photo.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
		Content:  jpegContent,
	}, nil)

	if !result.Valid {
		t.Errorf("Expected valid, got errors: %v", result.Errors)
	}
	if result.SanitizedFilename != "photo.jpg" {
		t.Errorf("Expected 'photo.jpg', got %q", result.SanitizedFilename)
	}
}

func TestValidateFile_TooLarge(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "big.jpg",
		Mimetype: "image/jpeg",
		Size:     10 * 1024 * 1024, // 10MB
	}, nil)

	if result.Valid {
		t.Error("Expected invalid for oversized file")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "exceeds maximum") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected size error, got: %v", result.Errors)
	}
}

func TestValidateFile_CustomMaxSize(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "small.jpg",
		Mimetype: "image/jpeg",
		Size:     2000,
	}, &ValidateFileOptions{
		MaxSize:          1000,
		BlockExecutables: true,
		ValidateMagicBytes: true,
		BlockNoExtension: true,
		BlockDoubleExtensions: true,
	})

	if result.Valid {
		t.Error("Expected invalid for custom max size")
	}
}

func TestValidateFile_EmptyFile(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "empty.jpg",
		Mimetype: "image/jpeg",
		Size:     0,
	}, nil)

	if result.Valid {
		t.Error("Expected invalid for empty file")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "empty") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected empty error, got: %v", result.Errors)
	}
}

func TestValidateFile_ExecutableBlocked(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "malware.exe",
		Mimetype: "application/octet-stream",
		Size:     1024,
	}, nil)

	if result.Valid {
		t.Error("Expected executable to be blocked")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "Executable extension") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected executable error, got: %v", result.Errors)
	}
}

func TestValidateFile_ExecutableAllowed(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "script.sh",
		Mimetype: "text/plain",
		Size:     100,
	}, &ValidateFileOptions{
		BlockExecutables:     false,
		ValidateMagicBytes:   true,
		BlockNoExtension:     true,
		BlockDoubleExtensions: true,
	})

	if !result.Valid {
		t.Errorf("Expected valid when executables allowed, got errors: %v", result.Errors)
	}
}

func TestValidateFile_NoExtensionBlocked(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "README",
		Mimetype: "text/plain",
		Size:     100,
	}, nil)

	if result.Valid {
		t.Error("Expected no-extension to be blocked")
	}
}

func TestValidateFile_NoExtensionAllowed(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "README",
		Mimetype: "text/plain",
		Size:     100,
	}, &ValidateFileOptions{
		BlockNoExtension:     false,
		BlockExecutables:     true,
		ValidateMagicBytes:   true,
		BlockDoubleExtensions: true,
	})

	if !result.Valid {
		t.Errorf("Expected valid when no-extension allowed, got errors: %v", result.Errors)
	}
}

func TestValidateFile_DoubleExtensionBlocked(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "image.php.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
	}, nil)

	if result.Valid {
		t.Error("Expected double extension to be blocked")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "Double extensions") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected double extension error, got: %v", result.Errors)
	}
}

func TestValidateFile_DoubleExtensionSafe(t *testing.T) {
	// file.backup.jpg — "backup" is not dangerous
	result := ValidateFile(FileInput{
		Filename: "file.backup.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
	}, nil)

	// Should not trigger double extension error
	for _, e := range result.Errors {
		if contains(e, "Double extensions") {
			t.Error("Safe double extension should not be blocked")
		}
	}
}

func TestValidateFile_AllowedMimeType(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "photo.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
	}, &ValidateFileOptions{
		AllowedTypes:       []string{"image/jpeg", "image/png"},
		BlockExecutables:   true,
		ValidateMagicBytes: true,
		BlockNoExtension:   true,
		BlockDoubleExtensions: true,
	})

	if !result.Valid {
		t.Errorf("Expected valid for allowed MIME type, got errors: %v", result.Errors)
	}
}

func TestValidateFile_DisallowedMimeType(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "doc.pdf",
		Mimetype: "application/pdf",
		Size:     1024,
	}, &ValidateFileOptions{
		AllowedTypes:       []string{"image/jpeg", "image/png"},
		BlockExecutables:   true,
		ValidateMagicBytes: true,
		BlockNoExtension:   true,
		BlockDoubleExtensions: true,
	})

	if result.Valid {
		t.Error("Expected invalid for disallowed MIME type")
	}
}

func TestValidateFile_AllowedExtension(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "photo.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
	}, &ValidateFileOptions{
		AllowedExtensions:  []string{".jpg", ".png"},
		BlockExecutables:   true,
		ValidateMagicBytes: true,
		BlockNoExtension:   true,
		BlockDoubleExtensions: true,
	})

	if !result.Valid {
		t.Errorf("Expected valid for allowed extension, got errors: %v", result.Errors)
	}
}

func TestValidateFile_DisallowedExtension(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "doc.pdf",
		Mimetype: "application/pdf",
		Size:     1024,
	}, &ValidateFileOptions{
		AllowedExtensions:  []string{".jpg", ".png"},
		BlockExecutables:   true,
		ValidateMagicBytes: true,
		BlockNoExtension:   true,
		BlockDoubleExtensions: true,
	})

	if result.Valid {
		t.Error("Expected invalid for disallowed extension")
	}
}

func TestValidateFile_MagicBytesMatch(t *testing.T) {
	pngContent := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A}
	result := ValidateFile(FileInput{
		Filename: "image.png",
		Mimetype: "image/png",
		Size:     1024,
		Content:  pngContent,
	}, nil)

	if !result.Valid {
		t.Errorf("Expected valid for matching magic bytes, got errors: %v", result.Errors)
	}
}

func TestValidateFile_MagicBytesMismatch(t *testing.T) {
	fakeContent := []byte("not a real jpeg")
	result := ValidateFile(FileInput{
		Filename: "fake.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
		Content:  fakeContent,
	}, nil)

	if result.Valid {
		t.Error("Expected invalid for mismatched magic bytes")
	}
	found := false
	for _, e := range result.Errors {
		if contains(e, "does not match") {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected magic bytes error, got: %v", result.Errors)
	}
}

func TestValidateFile_MagicBytesSkipped(t *testing.T) {
	fakeContent := []byte("not a real jpeg")
	result := ValidateFile(FileInput{
		Filename: "fake.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
		Content:  fakeContent,
	}, &ValidateFileOptions{
		ValidateMagicBytes:   false,
		BlockExecutables:     true,
		BlockNoExtension:     true,
		BlockDoubleExtensions: true,
	})

	if !result.Valid {
		t.Errorf("Expected valid when magic bytes disabled, got errors: %v", result.Errors)
	}
}

func TestValidateFile_UnknownMimePassesMagicBytes(t *testing.T) {
	// Unknown MIME type with no registered magic bytes should pass
	result := ValidateFile(FileInput{
		Filename: "data.csv",
		Mimetype: "text/csv",
		Size:     100,
		Content:  []byte("col1,col2\n"),
	}, nil)

	for _, e := range result.Errors {
		if contains(e, "does not match") {
			t.Error("Unknown MIME types should pass magic byte validation")
		}
	}
}

func TestValidateFile_SanitizesFilename(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "../../evil<script>.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
	}, nil)

	if result.SanitizedFilename != "evilscript.jpg" {
		t.Errorf("Expected sanitized name 'evilscript.jpg', got %q", result.SanitizedFilename)
	}
}

func TestValidateFile_GIF87a(t *testing.T) {
	gifContent := []byte("GIF87a" + "\x00\x00\x00\x00")
	result := ValidateFile(FileInput{
		Filename: "anim.gif",
		Mimetype: "image/gif",
		Size:     1024,
		Content:  gifContent,
	}, nil)

	if !result.Valid {
		t.Errorf("Expected valid for GIF87a, got errors: %v", result.Errors)
	}
}

func TestValidateFile_GIF89a(t *testing.T) {
	gifContent := []byte("GIF89a" + "\x00\x00\x00\x00")
	result := ValidateFile(FileInput{
		Filename: "anim.gif",
		Mimetype: "image/gif",
		Size:     1024,
		Content:  gifContent,
	}, nil)

	if !result.Valid {
		t.Errorf("Expected valid for GIF89a, got errors: %v", result.Errors)
	}
}

func TestValidateFile_PDF(t *testing.T) {
	pdfContent := []byte("%PDF-1.7 fake")
	result := ValidateFile(FileInput{
		Filename: "doc.pdf",
		Mimetype: "application/pdf",
		Size:     1024,
		Content:  pdfContent,
	}, nil)

	if !result.Valid {
		t.Errorf("Expected valid for PDF, got errors: %v", result.Errors)
	}
}

func TestValidateFile_MultipleErrors(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "malware.exe",
		Mimetype: "application/octet-stream",
		Size:     0,
	}, nil)

	if result.Valid {
		t.Error("Expected invalid")
	}
	if len(result.Errors) < 2 {
		t.Errorf("Expected multiple errors, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestValidateFile_ErrorsIsEmptySlice(t *testing.T) {
	result := ValidateFile(FileInput{
		Filename: "photo.jpg",
		Mimetype: "image/jpeg",
		Size:     1024,
	}, nil)

	if result.Errors == nil {
		t.Error("Errors should be empty slice, not nil")
	}
	if len(result.Errors) != 0 {
		t.Errorf("Expected 0 errors, got %d", len(result.Errors))
	}
}

// helper
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
