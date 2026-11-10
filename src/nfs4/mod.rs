//! NFSv4.x protocol codec (COMPOUND) and [`crate::fs::Filesystem`] backend.
//!
//! - [`types`]: bitmaps, fattr4 attribute sets, stateids, shared constants.
//! - [`ops`]: per-operation argument encoding and result decoding.
//! - [`compound`]: COMPOUND4args / COMPOUND4res.
//! - `session`: NFSv4.1+ client ID and session establishment.
//! - `state40`: NFSv4.0 client ID, open stateid cache, OPEN / CLOSE helpers.
//! - `backend`: connection, retry / recovery, and the Filesystem implementation.

pub mod compound;
pub mod ops;
pub mod types;

mod backend;
mod session;
mod state40;

use std::net::IpAddr;

use crate::error::Result;
use crate::fs::{ConnectOptions, Connected};

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 4;

/// Connect with the given minor version, or negotiate the highest supported
/// (2, then 1, then 0) when `minor` is None. Walks `path` from PUTROOTFH.
pub fn connect(
    host: IpAddr,
    path: &[u8],
    minor: Option<u32>,
    opts: &ConnectOptions,
) -> Result<Connected> {
    if opts.rpc.proto == crate::rpc::Proto::Udp {
        // RFC 7530 section 3.1: NFSv4 requires a congestion-controlled transport.
        return Err(crate::error::Error::VersionUnsupported(
            "NFSv4 requires TCP".into(),
        ));
    }
    backend::connect(host, path, minor, opts).map_err(|e| match e {
        crate::error::Error::Nfs(st @ (crate::fs::Status::Perm | crate::fs::Status::Access))
            if crate::rpc::fell_back_to_unprivileged() =>
        {
            crate::error::Error::Invalid(format!("{st}: {}", crate::rpc::PRIVILEGED_PORT_HINT))
        }
        e => e,
    })
}
