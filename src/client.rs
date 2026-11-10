//! Version negotiation behind [`crate::fs::connect`].

use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::fs::{ConnectOptions, Connected, NfsVersion, VersionPref};

enum Attempt {
    V4(Option<u32>),
    V3,
    V2,
}

pub fn connect(host: IpAddr, path: &[u8], opts: &ConnectOptions) -> Result<Connected> {
    let attempts: Vec<Attempt> = match opts.version {
        VersionPref::Auto => vec![Attempt::V4(None), Attempt::V3, Attempt::V2],
        VersionPref::AnyV4 => vec![Attempt::V4(None)],
        VersionPref::Exact(NfsVersion::V4(m)) => vec![Attempt::V4(Some(m))],
        VersionPref::Exact(NfsVersion::V3) => vec![Attempt::V3],
        VersionPref::Exact(NfsVersion::V2) => vec![Attempt::V2],
    };
    let mut best: Option<Error> = None;
    for a in attempts {
        let r = match a {
            Attempt::V4(minor) => crate::nfs4::connect(host, path, minor, opts),
            Attempt::V3 => crate::nfs3::connect(host, path, opts),
            Attempt::V2 => crate::nfs2::connect(host, path, opts),
        };
        match r {
            Ok(c) => return Ok(c),
            Err(e) => {
                if best.as_ref().is_none_or(|b| progress(&e) > progress(b)) {
                    best = Some(e);
                }
            }
        }
    }
    Err(best.unwrap_or_else(|| Error::Invalid("no NFS version to try".into())))
}

/// How far a failed attempt got: a server-level answer (MNT3ERR_ACCES, auth
/// rejection, ...) beats a transport failure, which beats "version not offered".
/// The first error of the highest rank wins.
fn progress(e: &Error) -> u8 {
    if e.is_version_unsupported() {
        0
    } else if matches!(e, Error::Io(_) | Error::Timeout) {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Status;

    fn pick(errs: Vec<Error>) -> Error {
        let mut best: Option<Error> = None;
        for e in errs {
            if best.as_ref().is_none_or(|b| progress(&e) > progress(b)) {
                best = Some(e);
            }
        }
        best.unwrap()
    }

    #[test]
    fn real_mount_error_beats_connect_refusal() {
        let refused = Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
        let e = pick(vec![
            refused,
            Error::Nfs(Status::Access),
            Error::NotRegistered {
                prog: 100003,
                vers: 2,
            },
        ]);
        assert!(matches!(e, Error::Nfs(Status::Access)), "{e}");
    }

    #[test]
    fn transport_error_beats_unsupported() {
        let e = pick(vec![
            Error::VersionUnsupported("v4".into()),
            Error::Timeout,
            Error::NotRegistered {
                prog: 100003,
                vers: 2,
            },
        ]);
        assert!(matches!(e, Error::Timeout), "{e}");
    }

    #[test]
    fn ties_keep_the_first() {
        let e = pick(vec![
            Error::VersionUnsupported("a".into()),
            Error::NotRegistered { prog: 1, vers: 2 },
        ]);
        assert!(matches!(e, Error::VersionUnsupported(_)));
    }
}
