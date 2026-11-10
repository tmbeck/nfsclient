//! NFSv3 protocol codec and [`crate::fs::Filesystem`] backend. (nfs3 agent owns src/nfs3/.)
//!
//! - [`types`]: wire types shared by the procedures (fattr3, sattr3, wcc_data, ...).
//! - [`proto`]: procedure numbers, argument encoders and result decoders.
//! - [`backend`]: the `Filesystem` implementation on one RPC connection.

pub mod backend;
pub mod proto;
pub mod types;

use std::net::{IpAddr, SocketAddr};

use crate::error::{Error, Result};
use crate::fs::{ConnectOptions, Connected, Status};
use crate::mount;
use crate::portmap;
use crate::rpc::RpcClient;

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 3;

const AUTH_NONE: u32 = 0;
const AUTH_SYS: u32 = 1;

/// Resolve `path` to an export via MOUNT (longest matching export prefix when the
/// full path isn't itself mountable), mount it, and return the backend.
///
/// If EXPORT fails or no export contains `path`, the full path is mounted directly.
pub fn connect(host: IpAddr, path: &[u8], opts: &ConnectOptions) -> Result<Connected> {
    let (export, remainder) = choose_export(host, path, opts);

    // Contact the NFS service first so a missing v3 service leaves no mount behind.
    let port = match opts.nfs_port {
        Some(p) => p,
        None => portmap::getport(host, PROGRAM, VERSION, opts.rpc.proto, &opts.rpc)?,
    };
    let client = RpcClient::connect(SocketAddr::new(host, port), PROGRAM, VERSION, &opts.rpc)?;

    let (root, flavors) = match mount::mnt(host, opts.mount_port, 3, &export, &opts.rpc) {
        Ok(v) => v,
        Err(Error::Nfs(Status::Access)) => {
            let hint = if client.is_privileged() {
                "the export does not list this client address, or the path is not exported"
            } else {
                "this client used an unprivileged source port; exports marked 'secure' require \
                 a reserved port (run as root / with CAP_NET_BIND_SERVICE, or use --port-mode priv)"
            };
            return Err(Error::Invalid(format!(
                "MOUNT of {} was refused (permission denied): {hint}",
                String::from_utf8_lossy(&export)
            )));
        }
        Err(e) => return Err(e),
    };
    if let Err(e) = check_flavors(&flavors, &export) {
        let _ = mount::umnt(host, opts.mount_port, 3, &export, &opts.rpc);
        return Err(e);
    }

    let fs = match backend::open(
        client,
        host,
        opts.mount_port,
        opts.rpc.clone(),
        export.clone(),
        root,
    ) {
        Ok(fs) => fs,
        Err(e) => {
            let _ = mount::umnt(host, opts.mount_port, 3, &export, &opts.rpc);
            return Err(e);
        }
    };
    Ok(Connected {
        fs: Box::new(fs),
        export,
        remainder,
    })
}

/// Pick the export containing `path` (via EXPORT), or fall back to `path` itself.
fn choose_export(host: IpAddr, path: &[u8], opts: &ConnectOptions) -> (Vec<u8>, Vec<Vec<u8>>) {
    if let Ok(list) = mount::exports(host, opts.mount_port, &opts.rpc)
        && let Some((e, remainder)) = mount::resolve_export(&list, path)
    {
        return (e.dir.clone(), remainder);
    }
    (normalize(path), Vec::new())
}

/// Canonical absolute form: single slashes, no trailing slash (except root).
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut out = vec![b'/'];
    for (i, comp) in path.split(|&b| b == b'/').filter(|c| !c.is_empty()).enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(comp);
    }
    out
}

/// The server must accept AUTH_NONE or AUTH_SYS, the only flavors nfsc sends.
fn check_flavors(flavors: &[u32], export: &[u8]) -> Result<()> {
    if flavors.contains(&AUTH_SYS) || flavors.contains(&AUTH_NONE) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "export {} requires security flavor(s) {flavors:?}; nfsc supports AUTH_SYS (1) and AUTH_NONE (0)",
            String::from_utf8_lossy(export)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_paths() {
        assert_eq!(normalize(b"/"), b"/");
        assert_eq!(normalize(b""), b"/");
        assert_eq!(normalize(b"//srv//data/"), b"/srv/data");
        assert_eq!(normalize(b"srv/data"), b"/srv/data");
    }

    #[test]
    fn flavor_check() {
        let ex = b"/x";
        assert!(check_flavors(&[1], ex).is_ok());
        assert!(check_flavors(&[0, 390003], ex).is_ok());
        let err = check_flavors(&[390003, 390004], ex).unwrap_err();
        assert!(err.to_string().contains("390003"), "message should list the flavors: {err}");
        assert!(check_flavors(&[], ex).is_err());
    }
}
