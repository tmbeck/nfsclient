//! MOUNT protocol v1 (for NFSv2) and v3 (for NFSv3), program 100005.
//! (nfs3 agent owns this file.)
//!
//! PUBLIC API CONTRACT (fixed signatures):

use std::net::{IpAddr, SocketAddr};

use crate::error::{Error, Result};
use crate::fs::{FileHandle, Status};
use crate::portmap;
use crate::rpc::{Proto, RpcClient, RpcOptions};
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

pub const PROGRAM: u32 = 100005;

const MOUNTPROC_MNT: u32 = 1;
const MOUNTPROC_UMNT: u32 = 3;
const MOUNTPROC_EXPORT: u32 = 5;

/// Size of a MOUNT v1 (NFSv2) file handle.
const FHSIZE_V1: usize = 32;
/// Maximum size of a MOUNT v3 (NFSv3) file handle.
const FHSIZE_V3: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub dir: Vec<u8>,
    /// Allowed clients/groups as reported by the server.
    pub groups: Vec<String>,
}

/// One `exportnode`, without its trailing `next` pointer (the list idiom reads that).
impl Unpack for Export {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let dir = d.get_string()?;
        let groups = d.get_list::<String>()?;
        Ok(Export { dir, groups })
    }
}

/// MOUNTPROC_EXPORT reply: `*exportnode` linked list.
struct ExportList(Vec<Export>);

impl Unpack for ExportList {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(ExportList(d.get_list::<Export>()?))
    }
}

/// Directory path argument (MNT, UMNT): an XDR string.
struct DirPath<'a>(&'a [u8]);

impl Pack for DirPath<'_> {
    fn pack(&self, e: &mut Encoder) {
        e.put_string(self.0);
    }
}

/// `mountstat3` status word shared by v1 (`fhstatus`) and v3 (`mountres3`).
fn check_status(d: &mut Decoder<'_>) -> Result<()> {
    match d.get_u32()? {
        0 => Ok(()),
        code => Err(Error::Nfs(Status::from_v3(code))),
    }
}

/// MNT v1 reply: `fhstatus` with a fixed 32-byte handle.
struct MntV1 {
    fh: FileHandle,
}

impl Unpack for MntV1 {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        check_status(d)?;
        let fh = FileHandle(d.get_opaque_fixed(FHSIZE_V1)?.to_vec());
        Ok(MntV1 { fh })
    }
}

/// MNT v3 reply: `mountres3_ok` with the handle and the accepted auth flavors.
struct MntV3 {
    fh: FileHandle,
    flavors: Vec<u32>,
}

impl Unpack for MntV3 {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        check_status(d)?;
        let fh = FileHandle(d.get_opaque_max(FHSIZE_V3)?.to_vec());
        let flavors = d.get_array::<u32>()?;
        Ok(MntV3 { fh, flavors })
    }
}

/// Client for MOUNT `vers` on `host`: the given port, or a portmap lookup.
fn mount_client(
    host: IpAddr,
    mount_port: Option<u16>,
    vers: u32,
    opts: &RpcOptions,
) -> Result<RpcClient> {
    if let Some(p) = mount_port {
        return RpcClient::connect(SocketAddr::new(host, p), PROGRAM, vers, opts);
    }
    let (port, opts) = match portmap::getport(host, PROGRAM, vers, opts.proto, opts) {
        Ok(p) => (p, opts.clone()),
        Err(Error::NotRegistered { .. }) => {
            // mountd is often registered on one transport only: try the other.
            let mut other = opts.clone();
            other.proto = match opts.proto {
                Proto::Tcp => Proto::Udp,
                Proto::Udp => Proto::Tcp,
            };
            let p = portmap::getport(host, PROGRAM, vers, other.proto, &other)?;
            (p, other)
        }
        Err(e) if portmap::is_unreachable(&e) => return Err(portmap_unreachable(&e)),
        Err(e) => return Err(e),
    };
    RpcClient::connect(SocketAddr::new(host, port), PROGRAM, vers, &opts)
}

/// The mountd port is only discoverable through portmap, so say what to do.
/// A transient failure (refused, timed out: the server may be booting) stays
/// an I/O error of the same kind, so connection setup can retry it.
fn portmap_unreachable(e: &Error) -> Error {
    let msg = format!(
        "portmap (port 111) is unreachable ({e}); mountd's port can only be found through \
         portmap, so pass --mount-port (and --nfs-port) to skip portmap lookups"
    );
    let kind = match e {
        Error::Timeout => Some(std::io::ErrorKind::TimedOut),
        Error::Io(io) if e.is_retryable() => Some(io.kind()),
        _ => None,
    };
    match kind {
        Some(k) => Error::Io(std::io::Error::new(k, msg)),
        None => Error::Invalid(msg),
    }
}

/// Canonical absolute form: single slashes, no trailing slash (except root).
pub fn normalize_path(path: &[u8]) -> Vec<u8> {
    let mut out = vec![b'/'];
    for (i, comp) in components(path).into_iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(comp);
    }
    out
}

fn export_version(
    host: IpAddr,
    mount_port: Option<u16>,
    vers: u32,
    opts: &RpcOptions,
) -> Result<Vec<Export>> {
    let mut client = mount_client(host, mount_port, vers, opts)?;
    let ExportList(list) = client.call(MOUNTPROC_EXPORT, &())?;
    Ok(list)
}

/// MOUNTPROC_EXPORT (works with MOUNT v1 or v3; uses v3, falls back to v1).
/// `mount_port` overrides the portmap lookup.
pub fn exports(host: IpAddr, mount_port: Option<u16>, opts: &RpcOptions) -> Result<Vec<Export>> {
    match export_version(host, mount_port, 3, opts) {
        Err(e) if e.is_version_unsupported() => export_version(host, mount_port, 1, opts),
        r => r,
    }
}

/// Split a path on '/', ignoring empty components (duplicate and trailing slashes).
fn components(path: &[u8]) -> Vec<&[u8]> {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect()
}

/// Pick the export that `path` lives in: exact match, else the longest export
/// that is a whole-component prefix of `path`. Returns (export, remainder components).
pub fn resolve_export<'a>(
    exports: &'a [Export],
    path: &[u8],
) -> Option<(&'a Export, Vec<Vec<u8>>)> {
    let want = components(path);
    let mut best: Option<(&'a Export, usize)> = None;
    for e in exports {
        let dir = components(&e.dir);
        if dir.len() > want.len() || want[..dir.len()] != dir[..] {
            continue;
        }
        if best.is_none_or(|(_, n)| dir.len() > n) {
            best = Some((e, dir.len()));
        }
    }
    best.map(|(e, n)| (e, want[n..].iter().map(|c| c.to_vec()).collect()))
}

/// MOUNTPROC_MNT. `version` is 1 (returns a 32-byte v2 handle) or 3. For v3 also
/// returns the server's accepted auth flavors (v1 has no flavor list: returns empty).
pub fn mnt(
    host: IpAddr,
    mount_port: Option<u16>,
    version: u32,
    dir: &[u8],
    opts: &RpcOptions,
) -> Result<(FileHandle, Vec<u32>)> {
    let mut client = mount_client(host, mount_port, version, opts)?;
    match version {
        1 => {
            let r: MntV1 = client.call(MOUNTPROC_MNT, &DirPath(dir))?;
            Ok((r.fh, Vec::new()))
        }
        3 => {
            let r: MntV3 = client.call(MOUNTPROC_MNT, &DirPath(dir))?;
            Ok((r.fh, r.flavors))
        }
        v => Err(Error::Invalid(format!("unsupported MOUNT version {v}"))),
    }
}

/// MOUNTPROC_UMNT. Best effort.
pub fn umnt(
    host: IpAddr,
    mount_port: Option<u16>,
    version: u32,
    dir: &[u8],
    opts: &RpcOptions,
) -> Result<()> {
    let mut client = mount_client(host, mount_port, version, opts)?;
    client.call::<_, ()>(MOUNTPROC_UMNT, &DirPath(dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::{from_bytes, to_bytes};

    #[test]
    fn normalize_path_forms() {
        assert_eq!(normalize_path(b""), b"/");
        assert_eq!(normalize_path(b"/"), b"/");
        assert_eq!(normalize_path(b"srv//data/"), b"/srv/data");
    }

    fn ex(dir: &str) -> Export {
        Export {
            dir: dir.as_bytes().to_vec(),
            groups: vec![],
        }
    }

    #[test]
    fn dirpath_encoding_is_byte_exact() {
        assert_eq!(
            to_bytes(&DirPath(b"/srv")),
            [0, 0, 0, 4, b'/', b's', b'r', b'v']
        );
        // "/a" pads to 4 bytes.
        assert_eq!(to_bytes(&DirPath(b"/a")), [0, 0, 0, 2, b'/', b'a', 0, 0]);
    }

    #[test]
    fn export_list_decodes_linked_list_with_groups() {
        let mut b = Vec::new();
        // entry 1: "/srv/data" (9 bytes + 3 pad), groups: "10.0.0.0/8", "*"
        b.extend_from_slice(&[0, 0, 0, 1]);
        b.extend_from_slice(&[0, 0, 0, 9]);
        b.extend_from_slice(b"/srv/data\0\0\0");
        b.extend_from_slice(&[0, 0, 0, 1]); // group present
        b.extend_from_slice(&[0, 0, 0, 10]);
        b.extend_from_slice(b"10.0.0.0/8\0\0");
        b.extend_from_slice(&[0, 0, 0, 1]); // group present
        b.extend_from_slice(&[0, 0, 0, 1]);
        b.extend_from_slice(b"*\0\0\0");
        b.extend_from_slice(&[0, 0, 0, 0]); // no more groups
        // entry 2: "/tank", no groups
        b.extend_from_slice(&[0, 0, 0, 1]);
        b.extend_from_slice(&[0, 0, 0, 5]);
        b.extend_from_slice(b"/tank\0\0\0");
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&[0, 0, 0, 0]); // no more exports
        let ExportList(list) = from_bytes(&b).unwrap();
        assert_eq!(
            list,
            vec![
                Export {
                    dir: b"/srv/data".to_vec(),
                    groups: vec!["10.0.0.0/8".into(), "*".into()],
                },
                Export {
                    dir: b"/tank".to_vec(),
                    groups: vec![]
                },
            ]
        );
    }

    #[test]
    fn export_list_empty() {
        let ExportList(list) = from_bytes(&[0, 0, 0, 0]).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn export_list_truncated_is_error() {
        // present flag, dir length 9 but only 4 bytes follow
        let b = [0, 0, 0, 1, 0, 0, 0, 9, b'/', b's', b'r', b'v'];
        assert!(from_bytes::<ExportList>(&b).is_err());
        // missing terminating "no more exports" flag
        let b = [0, 0, 0, 1, 0, 0, 0, 1, b'/', 0, 0, 0, 0, 0, 0, 0];
        assert!(from_bytes::<ExportList>(&b).is_err());
    }

    #[test]
    fn mnt_v3_reply_decodes_handle_and_flavors() {
        let mut b = vec![0, 0, 0, 0]; // MNT3_OK
        b.extend_from_slice(&[0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef]);
        b.extend_from_slice(&[0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0]); // flavors [AUTH_SYS, AUTH_NONE]
        let r: MntV3 = from_bytes(&b).unwrap();
        assert_eq!(r.fh, FileHandle(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(r.flavors, vec![1, 0]);
    }

    #[test]
    fn mnt_v3_error_maps_to_status() {
        let r: Result<MntV3> = from_bytes(&[0, 0, 0, 13]);
        assert!(matches!(r, Err(Error::Nfs(Status::Access))));
        let r: Result<MntV3> = from_bytes(&[0, 0, 0, 2]);
        assert!(matches!(r, Err(Error::Nfs(Status::NoEnt))));
        let r: Result<MntV3> = from_bytes(&[0, 0, 0x27, 0x14]);
        assert!(
            matches!(r, Err(Error::Nfs(Status::NotSupp))),
            "10004 is NFS3ERR_NOTSUPP"
        );
        // Unknown mountstat3 code is preserved.
        let r: Result<MntV3> = from_bytes(&[0, 0, 0, 99]);
        assert!(matches!(r, Err(Error::Nfs(Status::Other(_, 99)))));
    }

    #[test]
    fn mnt_v1_reply_has_32_byte_handle() {
        let mut b = vec![0, 0, 0, 0];
        b.extend_from_slice(&[0x5a; 32]);
        let r: MntV1 = from_bytes(&b).unwrap();
        assert_eq!(r.fh.0, vec![0x5a; 32]);
        // A 4-byte handle is not a v1 handle.
        let mut short = vec![0, 0, 0, 0];
        short.extend_from_slice(&[1, 2, 3, 4]);
        assert!(from_bytes::<MntV1>(&short).is_err());
    }

    #[test]
    fn resolve_exact_match() {
        let exports = [ex("/srv"), ex("/srv/data")];
        let (e, rem) = resolve_export(&exports, b"/srv/data").unwrap();
        assert_eq!(e.dir, b"/srv/data");
        assert!(rem.is_empty());
    }

    #[test]
    fn resolve_longest_prefix_with_remainder() {
        let exports = [ex("/"), ex("/srv"), ex("/srv/data")];
        let (e, rem) = resolve_export(&exports, b"/srv/data/a/b").unwrap();
        assert_eq!(e.dir, b"/srv/data");
        assert_eq!(rem, vec![b"a".to_vec(), b"b".to_vec()]);
    }

    #[test]
    fn resolve_is_whole_component_only() {
        let exports = [ex("/srv")];
        assert!(resolve_export(&exports, b"/srvx").is_none());
        let (e, rem) = resolve_export(&exports, b"/srv/x").unwrap();
        assert_eq!(e.dir, b"/srv");
        assert_eq!(rem, vec![b"x".to_vec()]);
    }

    #[test]
    fn resolve_normalizes_slashes() {
        let exports = [ex("/srv/data/")];
        let (_, rem) = resolve_export(&exports, b"//srv//data///x/").unwrap();
        assert_eq!(rem, vec![b"x".to_vec()]);
        let exports = [ex("//srv")];
        assert!(resolve_export(&exports, b"/srv").is_some());
    }

    #[test]
    fn resolve_no_match() {
        let exports = [ex("/tank/backup")];
        assert!(resolve_export(&exports, b"/data/iso").is_none());
        assert!(resolve_export(&[], b"/").is_none());
    }

    #[test]
    fn resolve_root_export_matches_everything() {
        let exports = [ex("/")];
        let (e, rem) = resolve_export(&exports, b"/").unwrap();
        assert_eq!(e.dir, b"/");
        assert!(rem.is_empty());
        let (_, rem) = resolve_export(&exports, b"/a/b").unwrap();
        assert_eq!(rem.len(), 2);
    }
}

#[cfg(test)]
mod export_list_fuzz {
    use super::*;

    /// Random and truncated export lists must decode to Ok or Err, never panic.
    #[test]
    fn export_list_decoder_never_panics() {
        let mut state: u64 = 0x1234_5678_9abc_def1;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        // A valid list: one export with two groups, then the end marker.
        let mut seed = Vec::new();
        for word in [
            1u32,
            4,
            u32::from_be_bytes(*b"/srv"),
            1,
            3,
            u32::from_be_bytes(*b"a\0\0\0"),
            0,
        ] {
            seed.extend_from_slice(&word.to_be_bytes());
        }
        let mut inputs: Vec<Vec<u8>> = (0..=seed.len()).map(|n| seed[..n].to_vec()).collect();
        for _ in 0..3000 {
            let len = (next() % 200) as usize;
            inputs.push((0..len).map(|_| next() as u8).collect());
        }
        for _ in 0..3000 {
            let mut m = seed.clone();
            let i = (next() as usize) % m.len();
            m[i] = next() as u8;
            inputs.push(m);
        }
        for buf in inputs {
            let result = std::panic::catch_unwind(|| {
                let _ = crate::xdr::from_bytes::<ExportList>(&buf);
            });
            assert!(result.is_ok(), "export list decoder panicked on {buf:02x?}");
        }
    }
}
