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
    let mut first_err: Option<Error> = None;
    let mut specific_err: Option<Error> = None;
    for a in attempts {
        let r = match a {
            Attempt::V4(minor) => crate::nfs4::connect(host, path, minor, opts),
            Attempt::V3 => crate::nfs3::connect(host, path, opts),
            Attempt::V2 => crate::nfs2::connect(host, path, opts),
        };
        match r {
            Ok(c) => return Ok(c),
            Err(e) => {
                if !e.is_version_unsupported() && specific_err.is_none() {
                    specific_err = Some(e);
                } else if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    Err(specific_err
        .or(first_err)
        .unwrap_or_else(|| Error::Invalid("no NFS version to try".into())))
}
