//! nfsc: a userspace NFS client library.
//!
//! Layers, bottom up:
//! - [`xdr`]: External Data Representation codec (RFC 4506).
//! - [`rpc`]: ONC-RPC v2 client over TCP/UDP with AUTH_NONE / AUTH_SYS (RFC 5531).
//! - [`portmap`]: portmapper v2 GETPORT / DUMP (RFC 1833).
//! - [`mount`]: MOUNT v1/v3 (RFC 1094 appendix A, RFC 1813 section 5).
//! - [`nfs2`], [`nfs3`], [`nfs4`]: protocol codecs and [`fs::Filesystem`] backends.
//! - [`fs`]: the version-agnostic facade consumers use; [`fs::connect`] negotiates.

pub mod client;
pub mod error;
pub mod fs;
pub mod mount;
pub mod nfs2;
pub mod nfs3;
pub mod nfs4;
pub mod portmap;
pub mod rpc;
pub mod xdr;

pub use error::{Error, Result};
