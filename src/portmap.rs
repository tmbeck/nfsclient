//! Portmapper v2 (program 100000, RFC 1833). (portmap/CLI agent owns this file.)
//!
//! PUBLIC API CONTRACT (fixed signatures):

use std::net::{IpAddr, SocketAddr};

use crate::error::{Error, Result};
use crate::rpc::{Auth, Proto, RpcClient, RpcOptions};
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

pub const PROGRAM: u32 = 100000;
pub const VERSION: u32 = 2;
pub const PORT: u16 = 111;

const PMAPPROC_NULL: u32 = 0;
const PMAPPROC_GETPORT: u32 = 3;
const PMAPPROC_DUMP: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub prog: u32,
    pub vers: u32,
    /// Raw IPPROTO value (6 = tcp, 17 = udp); see [`Proto::from_ipproto`].
    pub prot: u32,
    pub port: u32,
}

impl Pack for Mapping {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.prog)
            .put_u32(self.vers)
            .put_u32(self.prot)
            .put_u32(self.port);
    }
}

impl Unpack for Mapping {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Mapping {
            prog: d.get_u32()?,
            vers: d.get_u32()?,
            prot: d.get_u32()?,
            port: d.get_u32()?,
        })
    }
}

/// PMAPPROC_DUMP reply body: `pmaplist` is an XDR linked list of `mapping`.
struct PmapList(Vec<Mapping>);

impl Unpack for PmapList {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(PmapList(d.get_list::<Mapping>()?))
    }
}

/// Portmap calls are always made with AUTH_NONE, whatever credentials the
/// caller wants for the program it is looking up.
fn portmap_opts(opts: &RpcOptions) -> RpcOptions {
    RpcOptions {
        auth: Auth::None,
        ..opts.clone()
    }
}

fn connect(host: IpAddr, opts: &RpcOptions) -> Result<RpcClient> {
    let opts = portmap_opts(opts);
    RpcClient::connect(SocketAddr::new(host, PORT), PROGRAM, VERSION, &opts)
}

/// PMAPPROC_GETPORT. Returns the port, or `Error::NotRegistered` if the server returns 0.
pub fn getport(host: IpAddr, prog: u32, vers: u32, proto: Proto, opts: &RpcOptions) -> Result<u16> {
    let mut client = connect(host, opts)?;
    let args = Mapping {
        prog,
        vers,
        prot: proto.ipproto(),
        port: 0,
    };
    let port: u32 = client.call(PMAPPROC_GETPORT, &args)?;
    match port {
        0 => Err(Error::NotRegistered { prog, vers }),
        p => u16::try_from(p).map_err(|_| Error::Protocol(format!("portmap returned port {p}"))),
    }
}

/// True when `e` means the portmapper itself could not be reached (refused,
/// unreachable, or silent), as opposed to answering "not registered".
pub fn is_unreachable(e: &Error) -> bool {
    matches!(e, Error::Io(_) | Error::Timeout)
}

/// Standard NFS port, used when the portmapper cannot be reached.
pub const NFS_DEFAULT_PORT: u16 = 2049;

/// Port of the NFS service: GETPORT, falling back to 2049 when portmap (111)
/// is unreachable. A portmap that answers "not registered" is not a fallback case.
pub fn nfs_port(host: IpAddr, vers: u32, proto: Proto, opts: &RpcOptions) -> Result<u16> {
    match getport(host, 100003, vers, proto, opts) {
        Err(e) if is_unreachable(&e) => Ok(NFS_DEFAULT_PORT),
        r => r,
    }
}

/// PMAPPROC_DUMP. Talks to the portmapper using `opts.proto`.
pub fn dump(host: IpAddr, opts: &RpcOptions) -> Result<Vec<Mapping>> {
    let mut client = connect(host, opts)?;
    let PmapList(list) = client.call(PMAPPROC_DUMP, &())?;
    Ok(list)
}

/// PMAPPROC_NULL: check that the portmapper answers.
pub fn ping(host: IpAddr, opts: &RpcOptions) -> Result<()> {
    let mut client = connect(host, opts)?;
    client.call::<(), ()>(PMAPPROC_NULL, &())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::{from_bytes, to_bytes};

    #[test]
    fn getport_args_are_byte_exact() {
        // prog 100003, vers 3, prot tcp (6), port 0
        let m = Mapping {
            prog: 100003,
            vers: 3,
            prot: 6,
            port: 0,
        };
        assert_eq!(
            to_bytes(&m),
            [0, 1, 0x86, 0xa3, 0, 0, 0, 3, 0, 0, 0, 6, 0, 0, 0, 0]
        );
    }

    #[test]
    fn mapping_roundtrip() {
        let m = Mapping {
            prog: 100005,
            vers: 3,
            prot: 17,
            port: 59936,
        };
        assert_eq!(from_bytes::<Mapping>(&to_bytes(&m)).unwrap(), m);
    }

    fn put_entry(e: &mut Encoder, prog: u32, vers: u32, prot: u32, port: u32) {
        e.put_bool(true)
            .put_u32(prog)
            .put_u32(vers)
            .put_u32(prot)
            .put_u32(port);
    }

    #[test]
    fn dump_reply_decodes_linked_list() {
        let mut e = Encoder::new();
        put_entry(&mut e, 100000, 2, 6, 111);
        put_entry(&mut e, 100003, 3, 6, 2049);
        put_entry(&mut e, 100021, 4, 17, 60623);
        e.put_bool(false);
        let PmapList(list) = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(
            list,
            vec![
                Mapping {
                    prog: 100000,
                    vers: 2,
                    prot: 6,
                    port: 111
                },
                Mapping {
                    prog: 100003,
                    vers: 3,
                    prot: 6,
                    port: 2049
                },
                Mapping {
                    prog: 100021,
                    vers: 4,
                    prot: 17,
                    port: 60623
                },
            ]
        );
    }

    #[test]
    fn dump_reply_empty_list() {
        let PmapList(list) = from_bytes(&[0, 0, 0, 0]).unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn dump_reply_truncated_is_error() {
        let mut e = Encoder::new();
        e.put_bool(true).put_u32(100000).put_u32(2);
        assert!(from_bytes::<PmapList>(e.as_bytes()).is_err());
        // Missing terminating FALSE after the last entry.
        let mut e = Encoder::new();
        put_entry(&mut e, 100000, 2, 6, 111);
        assert!(from_bytes::<PmapList>(e.as_bytes()).is_err());
    }

    #[test]
    fn portmap_calls_force_auth_none() {
        let opts = RpcOptions {
            auth: Auth::Sys {
                stamp: 1,
                machine_name: "x".into(),
                uid: 1000,
                gid: 1000,
                gids: vec![],
            },
            ..RpcOptions::default()
        };
        assert_eq!(portmap_opts(&opts).auth, Auth::None);
        assert_eq!(portmap_opts(&opts).proto, opts.proto);
    }
}
