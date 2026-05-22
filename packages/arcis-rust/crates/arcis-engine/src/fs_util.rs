//! File-reading helpers.
//!
//! All user-provided text inputs read by the engine go through
//! [`read_to_string_stripped`] so a UTF-8 or UTF-16 byte-order mark left by
//! editors does not poison downstream parsers. PowerShell 5.1's
//! `Out-File -Encoding utf8` writes a UTF-8 BOM by default, which without
//! this helper caused two distinct silent-failure modes:
//!
//! * `requirements.txt` with a BOM made `arcis sca` skip every package on
//!   that file (the requirements regex `^\s*[A-Za-z0-9_.-]+` does not match
//!   the BOM character `\u{FEFF}`, because U+FEFF is not in Unicode's
//!   `White_Space` property).
//! * `arcis audit --baseline file.json` rejected the file with
//!   "expected value at line 1 column 1" because `serde_json` saw the BOM
//!   as the first character of the document.
//!
//! See `documents/cli-test.md` round-1 bugs 4 and 13 for the original
//! reproducers.

use std::fs;
use std::io;
use std::path::Path;

/// Read a UTF-8 text file, transparently stripping a leading byte-order
/// mark if present. Drop-in replacement for [`std::fs::read_to_string`]
/// for any path that may have been touched by Windows tooling.
pub fn read_to_string_stripped(path: impl AsRef<Path>) -> io::Result<String> {
    let bytes = fs::read(path)?;
    decode_bytes_stripping_bom(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Decode a byte slice as text, handling UTF-8 / UTF-16 LE / UTF-16 BE
/// BOMs. Bytes without a BOM are decoded as plain UTF-8.
pub fn decode_bytes_stripping_bom(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(bytes[3..].to_vec())
            .map_err(|e| format!("invalid UTF-8 after UTF-8 BOM: {e}"))
    } else if bytes.starts_with(&[0xFF, 0xFE]) {
        decode_utf16(&bytes[2..], true)
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        decode_utf16(&bytes[2..], false)
    } else {
        String::from_utf8(bytes.to_vec()).map_err(|e| format!("invalid UTF-8: {e}"))
    }
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> Result<String, String> {
    if bytes.len() % 2 != 0 {
        return Err(format!(
            "UTF-16 input must have even length, got {} bytes",
            bytes.len()
        ));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16(&units).map_err(|e| format!("invalid UTF-16: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_utf8_bom() {
        let bytes = b"\xEF\xBB\xBFcolourama==0.1.6";
        let s = decode_bytes_stripping_bom(bytes).unwrap();
        assert_eq!(s, "colourama==0.1.6");
    }

    #[test]
    fn passes_through_plain_utf8() {
        let bytes = b"colourama==0.1.6\nrequests==2.25.0\n";
        let s = decode_bytes_stripping_bom(bytes).unwrap();
        assert_eq!(s, "colourama==0.1.6\nrequests==2.25.0\n");
    }

    #[test]
    fn empty_input_is_empty_string() {
        let s = decode_bytes_stripping_bom(b"").unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn bare_bom_decodes_to_empty_string() {
        let bytes = b"\xEF\xBB\xBF";
        let s = decode_bytes_stripping_bom(bytes).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn decodes_utf16_le_bom() {
        // "ab" in UTF-16 LE with BOM: FF FE 61 00 62 00
        let bytes = [0xFF_u8, 0xFE, 0x61, 0x00, 0x62, 0x00];
        let s = decode_bytes_stripping_bom(&bytes).unwrap();
        assert_eq!(s, "ab");
    }

    #[test]
    fn decodes_utf16_be_bom() {
        // "ab" in UTF-16 BE with BOM: FE FF 00 61 00 62
        let bytes = [0xFE_u8, 0xFF, 0x00, 0x61, 0x00, 0x62];
        let s = decode_bytes_stripping_bom(&bytes).unwrap();
        assert_eq!(s, "ab");
    }

    #[test]
    fn utf16_with_odd_byte_count_is_rejected() {
        let bytes = [0xFF_u8, 0xFE, 0x61];
        assert!(decode_bytes_stripping_bom(&bytes).is_err());
    }

    #[test]
    fn rejects_invalid_utf8_without_bom() {
        let bytes = b"\xFFnotvalid";
        assert!(decode_bytes_stripping_bom(bytes).is_err());
    }

    #[test]
    fn read_to_string_stripped_handles_bom_file() {
        let dir = std::env::temp_dir().join("arcis-fs-util-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bom-requirements.txt");
        std::fs::write(&path, b"\xEF\xBB\xBFcolourama==0.1.6").unwrap();
        let s = read_to_string_stripped(&path).unwrap();
        assert_eq!(s, "colourama==0.1.6");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_to_string_stripped_handles_plain_file() {
        let dir = std::env::temp_dir().join("arcis-fs-util-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("plain-requirements.txt");
        std::fs::write(&path, b"colourama==0.1.6").unwrap();
        let s = read_to_string_stripped(&path).unwrap();
        assert_eq!(s, "colourama==0.1.6");
        let _ = std::fs::remove_file(&path);
    }
}
