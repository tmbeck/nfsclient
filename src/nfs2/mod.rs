//! NFSv2 protocol (RFC 1094): wire types in [`proto`], the [`Filesystem`]
//! backend in `backend`.
//!
//! Known limits of the protocol that the backend works around:
//! - Offsets and sizes are u32, so nothing past 4 GiB is addressable.
//! - READ and WRITE carry at most [`proto::MAXDATA`] (8192) bytes per call.
//! - There is no atomic exclusive create, no server-side time for SETATTR,
//!   and no SYMLINK/LINK reply carrying the new file's attributes.

pub mod proto;

mod backend;

use std::net::{IpAddr, SocketAddr};

use crate::error::Result;
use crate::fs::{ConnectOptions, Connected, FileHandle, Filesystem};
use crate::mount;
use crate::portmap;
use crate::rpc::RpcOptions;

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 2;

/// Resolve `path` to an export via MOUNT (longest matching export prefix when the
/// full path isn't itself mountable), mount it, and return the backend.
///
/// Order: NFS port first (so an unregistered v2 fails before any MOUNT traffic),
/// then EXPORT plus export resolution, then MNT (v1). If EXPORT fails or nothing
/// matches, MNT is tried on the full path with no remainder.
pub fn connect(host: IpAddr, path: &[u8], opts: &ConnectOptions) -> Result<Connected> {
    let nfs_port = match opts.nfs_port {
        Some(p) => p,
        None => portmap::getport(host, PROGRAM, VERSION, opts.rpc.proto, &opts.rpc)?,
    };
    let (export, remainder, root) = mount_root(host, path, opts)?;
    let umount = backend::Umount {
        host,
        mount_port: opts.mount_port,
        export: export.clone(),
    };
    let fs = backend::Nfs2::new(
        SocketAddr::new(host, nfs_port),
        &opts.rpc,
        root,
        Some(umount),
    )?;
    Ok(Connected {
        fs: Box::new(fs),
        export,
        remainder,
    })
}

/// Export directory, remaining path components, and the root handle.
fn mount_root(
    host: IpAddr,
    path: &[u8],
    opts: &ConnectOptions,
) -> Result<(Vec<u8>, Vec<Vec<u8>>, FileHandle)> {
    // EXPORT failing (e.g. the server hides its export list) is not fatal:
    // MNT on the full path is the fallback.
    let exports = mount::exports(host, opts.mount_port, &opts.rpc).unwrap_or_default();
    let (export, remainder) = match mount::resolve_export(&exports, path) {
        Some((e, rest)) => (e.dir.clone(), rest),
        None => (path.to_vec(), Vec::new()),
    };
    let (root, _auth_flavors) = mount::mnt(host, opts.mount_port, 1, &export, &opts.rpc)?;
    Ok((export, remainder, root))
}

/// Backend over an already-known root handle, skipping portmap and MOUNT.
///
/// Test hook for talking to a server (such as an in-process fake) that serves
/// NFSv2 on `nfs_port` and already knows `root`. The backend does not UMNT on
/// disconnect in this mode, since it never mounted.
#[doc(hidden)]
pub fn connect_with_root(
    host: IpAddr,
    nfs_port: u16,
    root: FileHandle,
    opts: &RpcOptions,
) -> Result<Box<dyn Filesystem>> {
    let fs = backend::Nfs2::new(SocketAddr::new(host, nfs_port), opts, root, None)?;
    Ok(Box::new(fs))
}
