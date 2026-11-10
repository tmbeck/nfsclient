//! NFSv4.x protocol codec (COMPOUND) and [`crate::fs::Filesystem`] backend.
//! (nfs4 agent owns src/nfs4/.)

use std::net::IpAddr;

use crate::error::Result;
use crate::fs::{ConnectOptions, Connected};

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 4;

/// Connect with the given minor version, or negotiate the highest supported
/// (2, then 1, then 0) when `minor` is None. Walks `path` from PUTROOTFH.
pub fn connect(_host: IpAddr, _path: &[u8], _minor: Option<u32>, _opts: &ConnectOptions) -> Result<Connected> {
    todo!("nfs4 agent")
}
