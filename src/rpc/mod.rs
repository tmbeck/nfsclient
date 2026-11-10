//! ONC-RPC v2 client (RFC 5531).
//!
//! PUBLIC API CONTRACT: other modules (portmap, mount, nfs) and the CLI code
//! against the items in this file. Signatures here are fixed; bodies are
//! implemented in this module and its submodules.

use std::net::SocketAddr;
use std::time::Duration;

use crate::error::Result;
use crate::xdr::{Pack, Unpack};

/// Transport protocol. Values match IPPROTO_* as used by portmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    /// IPPROTO number used in portmap mappings (TCP = 6, UDP = 17).
    pub fn ipproto(self) -> u32 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
        }
    }

    pub fn from_ipproto(p: u32) -> Option<Self> {
        match p {
            6 => Some(Proto::Tcp),
            17 => Some(Proto::Udp),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// How to pick the local source port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortMode {
    /// Try a reserved port (<1024); fall back to an ephemeral port if binding
    /// fails with EACCES/EPERM (and only then).
    #[default]
    Auto,
    /// Require a reserved port; fail if none can be bound.
    Privileged,
    /// Always use an ephemeral port.
    Unprivileged,
}

/// RPC credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// AUTH_NONE (flavor 0).
    None,
    /// AUTH_SYS / AUTH_UNIX (flavor 1).
    Sys {
        stamp: u32,
        /// At most 255 bytes on the wire.
        machine_name: String,
        uid: u32,
        gid: u32,
        /// At most 16 entries on the wire.
        gids: Vec<u32>,
    },
}

impl Auth {
    /// AUTH_SYS for the current process's uid/gid/supplementary groups and hostname.
    pub fn sys_from_process() -> Self {
        auth::sys_from_process()
    }
}

/// Connection options shared by all RPC clients.
#[derive(Debug, Clone)]
pub struct RpcOptions {
    pub proto: Proto,
    pub port_mode: PortMode,
    /// Total time to wait for a reply to one call (UDP: across all retransmits).
    pub timeout: Duration,
    pub auth: Auth,
}

impl Default for RpcOptions {
    fn default() -> Self {
        Self {
            proto: Proto::Tcp,
            port_mode: PortMode::Auto,
            timeout: Duration::from_secs(10),
            auth: Auth::None,
        }
    }
}

/// A connected RPC client bound to one (program, version) on one server address.
/// Not thread-safe; one outstanding call at a time.
pub struct RpcClient {
    inner: transport::Transport,
    prog: u32,
    vers: u32,
    auth: Auth,
    next_xid: u32,
    privileged: bool,
}

impl RpcClient {
    /// Connect (TCP) or bind+connect (UDP) to `addr` for program `prog` version `vers`.
    /// Honors `opts.port_mode`; when `Auto` falls back, a warning is printed to stderr
    /// once per process.
    pub fn connect(addr: SocketAddr, prog: u32, vers: u32, opts: &RpcOptions) -> Result<Self> {
        let (inner, privileged) = transport::Transport::connect(addr, opts)?;
        Ok(Self {
            inner,
            prog,
            vers,
            auth: opts.auth.clone(),
            next_xid: transport::initial_xid(),
            privileged,
        })
    }

    /// Perform one call: encode `args`, send, wait for the matching xid, check
    /// reply/accept status, decode the result body as `R` (must consume it fully).
    pub fn call<A: Pack + ?Sized, R: Unpack>(&mut self, procedure: u32, args: &A) -> Result<R> {
        let xid = self.next_xid;
        self.next_xid = self.next_xid.wrapping_add(1);
        let msg = message::encode_call(xid, self.prog, self.vers, procedure, &self.auth, args);
        let reply = self.inner.round_trip(xid, &msg)?;
        let body = message::decode_reply(xid, &reply)?;
        crate::xdr::from_bytes(body)
    }

    /// NULL procedure (proc 0): a ping.
    pub fn null(&mut self) -> Result<()> {
        self.call(0, &())
    }

    /// Whether the local source port is reserved (<1024).
    pub fn is_privileged(&self) -> bool {
        self.privileged
    }

    pub fn program(&self) -> (u32, u32) {
        (self.prog, self.vers)
    }

    pub fn proto(&self) -> Proto {
        self.inner.proto()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.inner.peer_addr()
    }

    /// Replace the credentials used for subsequent calls.
    pub fn set_auth(&mut self, auth: Auth) {
        self.auth = auth;
    }
}

pub mod auth;
pub mod message;
pub mod transport;
