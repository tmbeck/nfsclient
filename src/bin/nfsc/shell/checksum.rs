//! Checksums for `sum` and `get --verify` (SHA-2 from the RustCrypto `sha2` crate).

use sha2::{Digest, Sha256, Sha512};

/// A checksum algorithm `sum -a` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algo {
    #[default]
    Sha256,
    Sha512,
}

impl Algo {
    /// The names `sum -a` accepts.
    pub const NAMES: &'static str = "sha256, sha512";

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => Some(Algo::Sha256),
            "sha512" | "sha-512" => Some(Algo::Sha512),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Algo::Sha256 => "sha256",
            Algo::Sha512 => "sha512",
        }
    }

    pub fn hasher(self) -> Hasher {
        match self {
            Algo::Sha256 => Hasher::Sha256(Sha256::new()),
            Algo::Sha512 => Hasher::Sha512(Box::new(Sha512::new())),
        }
    }
}

/// A running checksum.
pub enum Hasher {
    Sha256(Sha256),
    Sha512(Box<Sha512>),
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    /// The digest as lowercase hex, as sha256sum prints it.
    pub fn hex(self) -> String {
        match self {
            Hasher::Sha256(h) => to_hex(&h.finalize()),
            Hasher::Sha512(h) => to_hex(&h.finalize()),
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        let mut h = Algo::Sha256.hasher();
        h.update(b"hel");
        h.update(b"lo");
        assert_eq!(
            h.hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        let h = Algo::Sha512.hasher();
        assert!(h.hex().starts_with("cf83e1357eefb8bd"), "sha512 of nothing");
        assert_eq!(Algo::parse("SHA-256"), Some(Algo::Sha256));
        assert_eq!(Algo::parse("md5"), None);
    }
}
