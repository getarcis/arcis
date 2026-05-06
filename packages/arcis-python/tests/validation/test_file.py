"""
File upload validation tests.
"""

from arcis.validation.file import (
    sanitize_filename,
    validate_file,
    is_dangerous_extension,
)


class TestSanitizeFilename:

    def test_strips_path_traversal(self):
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("..\\..\\windows\\system32") == "system32"

    def test_strips_null_bytes(self):
        assert sanitize_filename("file\0name.jpg") == "filename.jpg"

    def test_strips_control_characters(self):
        assert sanitize_filename("file\x01\x02name.jpg") == "filename.jpg"

    def test_strips_unsafe_characters(self):
        assert sanitize_filename("file<name>.jpg") == "filename.jpg"
        assert sanitize_filename('file"name".jpg') == "filename.jpg"
        assert sanitize_filename("file|name.jpg") == "filename.jpg"

    def test_replaces_spaces_and_parens(self):
        assert sanitize_filename("photo (1).jpg") == "photo_1.jpg"
        assert sanitize_filename("my file name.jpg") == "my_file_name.jpg"

    def test_strips_leading_dots(self):
        assert sanitize_filename(".htaccess") == "htaccess"
        assert sanitize_filename("..hidden") == "hidden"
        assert sanitize_filename(".env") == "env"

    def test_collapses_underscores_and_dots(self):
        assert sanitize_filename("file___name.jpg") == "file_name.jpg"
        assert sanitize_filename("file...jpg") == "file.jpg"

    def test_unnamed_fallback(self):
        assert sanitize_filename("") == "unnamed"
        assert sanitize_filename("...") == "unnamed"
        assert sanitize_filename("\0") == "unnamed"

    def test_preserves_valid_filenames(self):
        assert sanitize_filename("photo.jpg") == "photo.jpg"
        assert sanitize_filename("document-v2.pdf") == "document-v2.pdf"

    def test_handles_paths(self):
        assert sanitize_filename("C:\\Users\\admin\\photo.jpg") == "photo.jpg"
        assert sanitize_filename("/home/user/photo.jpg") == "photo.jpg"


class TestIsDangerousExtension:

    def test_flags_executables(self):
        assert is_dangerous_extension("file.exe")
        assert is_dangerous_extension("file.bat")
        assert is_dangerous_extension("file.sh")
        assert is_dangerous_extension("file.php")
        assert is_dangerous_extension("file.jsp")

    def test_flags_server_side(self):
        assert is_dangerous_extension("file.asp")
        assert is_dangerous_extension("file.aspx")
        assert is_dangerous_extension("file.phtml")

    def test_flags_template_engines(self):
        assert is_dangerous_extension("file.ejs")
        assert is_dangerous_extension("file.pug")
        assert is_dangerous_extension("file.hbs")

    def test_flags_office_macros(self):
        assert is_dangerous_extension("file.docm")
        assert is_dangerous_extension("file.xlsm")

    def test_allows_safe_extensions(self):
        assert not is_dangerous_extension("file.jpg")
        assert not is_dangerous_extension("file.png")
        assert not is_dangerous_extension("file.pdf")
        assert not is_dangerous_extension("file.txt")
        assert not is_dangerous_extension("file.csv")

    def test_case_insensitive(self):
        assert is_dangerous_extension("file.EXE")
        assert is_dangerous_extension("file.Php")


class TestValidateFile:

    def test_accepts_valid_file(self):
        result = validate_file(
            "photo.jpg", "image/jpeg", 1024,
            content=b"\xFF\xD8\xFF\xE0",
        )
        assert result.valid
        assert result.errors == []

    def test_rejects_oversized_file(self):
        result = validate_file("photo.jpg", "image/jpeg", 10_000_000, max_size=5_000_000)
        assert not result.valid
        assert "exceeds maximum" in result.errors[0]

    def test_rejects_empty_file(self):
        result = validate_file("photo.jpg", "image/jpeg", 0)
        assert not result.valid
        assert "File is empty" in result.errors

    def test_blocks_executable_extension(self):
        result = validate_file("shell.php", "text/plain", 100)
        assert not result.valid
        assert ".php" in result.errors[0]

    def test_allows_safe_extension(self):
        result = validate_file("photo.jpg", "image/jpeg", 1024)
        assert result.valid

    def test_enforces_allowed_extensions(self):
        result = validate_file(
            "doc.pdf", "application/pdf", 1024,
            allowed_extensions=[".jpg", ".png"],
        )
        assert not result.valid
        assert ".pdf" in result.errors[0]

    def test_blocks_no_extension(self):
        result = validate_file("noext", "application/octet-stream", 100)
        assert not result.valid
        assert "no extension" in result.errors[0]

    def test_allows_no_extension_when_configured(self):
        result = validate_file("noext", "application/octet-stream", 100, block_no_extension=False)
        assert result.valid

    def test_blocks_double_extensions(self):
        result = validate_file("shell.php.jpg", "image/jpeg", 100)
        assert not result.valid
        assert "Double extensions" in result.errors[0]

    def test_allows_safe_double_extensions(self):
        result = validate_file("archive.tar.gz", "application/gzip", 100)
        assert result.valid

    def test_enforces_allowed_mime_types(self):
        result = validate_file(
            "doc.pdf", "application/pdf", 1024,
            allowed_types=["image/jpeg", "image/png"],
        )
        assert not result.valid
        assert "application/pdf" in result.errors[0]

    def test_validates_magic_bytes(self):
        result = validate_file(
            "photo.jpg", "image/jpeg", 1024,
            content=b"\x89PNG",  # PNG magic bytes, not JPEG
        )
        assert not result.valid
        assert "does not match" in result.errors[0]

    def test_accepts_matching_magic_bytes(self):
        result = validate_file(
            "photo.jpg", "image/jpeg", 1024,
            content=b"\xFF\xD8\xFF\xE0",
        )
        assert result.valid

    def test_skips_magic_bytes_without_content(self):
        result = validate_file("photo.jpg", "image/jpeg", 1024)
        assert result.valid

    def test_skips_magic_bytes_when_disabled(self):
        result = validate_file(
            "photo.jpg", "image/jpeg", 1024,
            content=b"\x00\x00",
            validate_magic_bytes=False,
        )
        assert result.valid

    def test_returns_sanitized_filename(self):
        result = validate_file("../../evil.jpg", "image/jpeg", 1024)
        assert result.sanitized_filename == "evil.jpg"
