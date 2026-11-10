//! MOUNT protocol v1 (for NFSv2) and v3 (for NFSv3), program 100005.
//! (nfs3 agent owns this file.)
//!
//! PUBLIC API CONTRACT (fixed signatures):

use std::net::IpAddr;

use crate::error::Result;
use crate::fs::FileHandle;
use crate::rpc::RpcOptions;

pub const PROGRAM: u32 = 100005;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub dir: Vec<u8>,
    /// Allowed clients/groups as reported by the server.
    pub groups: Vec<String>,
}

/// MOUNTPROC_EXPORT (works with MOUNT v1 or v3; uses v3, falls back to v1).
/// `mount_port` overrides the portmap lookup.
pub fn exports(_host: IpAddr, _mount_port: Option<u16>, _opts: &RpcOptions) -> Result<Vec<Export>> {
    todo!("nfs3 agent")
}

/// Pick the export that `path` lives in: exact match, else the longest export
/// that is a whole-component prefix of `path`. Returns (export, remainder components).
pub fn resolve_export<'a>(exports: &'a [Export], path: &[u8]) -> Option<(&'a Export, Vec<Vec<u8>>)> {
    let _ = (exports, path);
    todo!("nfs3 agent")
}

/// MOUNTPROC_MNT. `version` is 1 (returns a 32-byte v2 handle) or 3. For v3 also
/// returns the server's accepted auth flavors.
pub fn mnt(
    _host: IpAddr,
    _mount_port: Option<u16>,
    _version: u32,
    _dir: &[u8],
    _opts: &RpcOptions,
) -> Result<(FileHandle, Vec<u32>)> {
    todo!("nfs3 agent")
}

/// MOUNTPROC_UMNT. Best effort.
pub fn umnt(_host: IpAddr, _mount_port: Option<u16>, _version: u32, _dir: &[u8], _opts: &RpcOptions) -> Result<()> {
    todo!("nfs3 agent")
}
