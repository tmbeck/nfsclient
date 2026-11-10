//! nfsc: a userspace NFS client library.
//!
//! Layers, bottom up:
//! - [`xdr`]: External Data Representation codec (RFC 4506).
//! - [`rpc`]: ONC-RPC v2 client over TCP/UDP with AUTH_NONE / AUTH_SYS (RFC 5531).
//! - [`portmap`]: portmapper v2 GETPORT / DUMP (RFC 1833).

pub mod error;
pub mod portmap;
pub mod rpc;
pub mod xdr;

pub use error::{Error, Result};
