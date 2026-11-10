//! Text helpers shared by the shell and `exports` output.

use std::fmt::Write;

/// Renders a raw server name for display: valid UTF-8 is shown as-is, invalid
/// bytes and control characters are shown as `\xNN`.
pub fn display_name(name: &[u8]) -> String {
    let mut out = String::with_capacity(name.len());
    for chunk in name.utf8_chunks() {
        for ch in chunk.valid().chars() {
            if ch.is_control() {
                let _ = write!(out, "\\x{:02x}", ch as u32);
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
