//! NFSv2 protocol codec and [`crate::fs::Filesystem`] backend. (nfs2 agent owns src/nfs2/.)

use std::net::IpAddr;

use crate::error::Result;
use crate::fs::{ConnectOptions, Connected};

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 2;

/// Resolve `path` to an export via MOUNT (longest matching export prefix when the
/// full path isn't itself mountable), mount it, and return the backend.
pub fn connect(_host: IpAddr, _path: &[u8], _opts: &ConnectOptions) -> Result<Connected> {
    todo!("nfs2 agent")
}
