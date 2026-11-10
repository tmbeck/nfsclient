//! NFSv4.x protocol codec (COMPOUND) and [`crate::fs::Filesystem`] backend.
//!
//! - [`types`]: bitmaps, fattr4 attribute sets, stateids, shared constants.
//! - [`ops`]: per-operation argument encoding and result decoding.
//! - [`compound`]: COMPOUND4args / COMPOUND4res.
//! - [`session`]: NFSv4.1+ client ID and session establishment.
//! - [`state40`]: NFSv4.0 client ID, open stateid cache, OPEN / CLOSE helpers.
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
pub fn connect(host: IpAddr, path: &[u8], minor: Option<u32>, opts: &ConnectOptions) -> Result<Connected> {
    backend::connect(host, path, minor, opts)
}
