//! Text helpers shared by the shell and `exports` output.

use std::fmt::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Renders a raw server name for display: valid UTF-8 is shown as-is, invalid
/// bytes and control characters are shown as `\xNN`. Invisible format
/// characters that reorder or hide text (bidi overrides and isolates, zero-width
/// marks) are shown as `\u{NNNN}`, so a name cannot disguise its own extension.
pub fn display_name(name: &[u8]) -> String {
    let mut out = String::with_capacity(name.len());
    for chunk in name.utf8_chunks() {
        for ch in chunk.valid().chars() {
            if ch.is_control() {
                let _ = write!(out, "\\x{:02x}", ch as u32);
            } else if is_spoofing_format_char(ch) {
                let _ = write!(out, "\\u{{{:x}}}", ch as u32);
            } else {
                out.push(ch);
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    out
}

/// [`display_name`] for a string that came from the server or from a path.
pub fn display_str(s: &str) -> String {
    display_name(s.as_bytes())
}

/// [`display_name`] for a local path, shown the way the OS spells it.
pub fn display_path(p: &Path) -> String {
    display_name(p.as_os_str().as_bytes())
}

/// Format characters that change how surrounding text reads: bidi embedding,
/// override and isolate controls, zero-width spaces and joiners, and the byte
/// order mark. These are not `is_control`, so they need their own list.
pub(crate) fn is_spoofing_format_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_only_what_cannot_be_shown() {
        assert_eq!(display_name(b"plain.txt"), "plain.txt");
        assert_eq!(display_name("caf\u{e9}".as_bytes()), "caf\u{e9}");
        assert_eq!(display_name(b"bad\xffname"), "bad\\xffname");
        assert_eq!(display_name(b"tab\there"), "tab\\x09here");
    }
}

#[cfg(test)]
mod spoofing_tests {
    use super::*;

    #[test]
    fn bidi_and_zero_width_format_characters_are_escaped() {
        assert_eq!(display_name("invoice\u{202e}gpj.exe".as_bytes()), "invoice\\u{202e}gpj.exe");
        assert_eq!(display_name("a\u{200b}b\u{feff}".as_bytes()), "a\\u{200b}b\\u{feff}");
        assert_eq!(display_name("a\u{2066}b".as_bytes()), "a\\u{2066}b");
        assert_eq!(display_name("caf\u{e9}".as_bytes()), "caf\u{e9}");
    }
}
