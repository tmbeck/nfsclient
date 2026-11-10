//! Crate-wide error type.

use std::fmt;
use std::io;

/// Why an RPC call was rejected (reply_stat = MSG_DENIED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// RPC_MISMATCH: server supports RPC versions low..=high.
    RpcMismatch { low: u32, high: u32 },
    /// AUTH_ERROR with the auth_stat value (e.g. 1 = AUTH_BADCRED, 2 = AUTH_REJECTEDCRED,
    /// 5 = AUTH_TOOWEAK, which is what "secure" exports return for unprivileged ports).
    AuthError(u32),
}

/// Non-success accept_stat values (reply_stat = MSG_ACCEPTED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptError {
    ProgUnavail,
    ProgMismatch { low: u32, high: u32 },
    ProcUnavail,
    GarbageArgs,
    SystemErr,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// Malformed or truncated XDR data.
    Xdr(String),
    /// No reply within the configured timeout (after all UDP retransmits).
    Timeout,
    /// The call was rejected (MSG_DENIED).
    Rejected(RejectReason),
    /// The call was accepted but not executed successfully.
    Accept(AcceptError),
    /// Protocol violation by the peer (bad xid, bad msg type, oversized record, ...).
    Protocol(String),
    /// Program/version/protocol is not registered with the portmapper.
    NotRegistered { prog: u32, vers: u32 },
    /// Bad user input (address parse, etc.).
    Invalid(String),
    /// The server returned a non-OK NFS or MOUNT status.
    Nfs(crate::fs::Status),
    /// The server does not support the requested NFS version / minor version.
    VersionUnsupported(String),
}

impl Error {
    /// True when the error means "this protocol version isn't offered", so a
    /// caller negotiating versions should try the next one.
    pub fn is_version_unsupported(&self) -> bool {
        matches!(
            self,
            Error::VersionUnsupported(_)
                | Error::NotRegistered { .. }
                | Error::Accept(AcceptError::ProgUnavail)
                | Error::Accept(AcceptError::ProgMismatch { .. })
        )
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::Xdr(m) => write!(f, "XDR decode error: {m}"),
            Error::Timeout => write!(f, "RPC timed out"),
            Error::Rejected(RejectReason::RpcMismatch { low, high }) => {
                write!(f, "RPC version mismatch (server supports {low}..{high})")
            }
            Error::Rejected(RejectReason::AuthError(s)) => {
                let name = match s {
                    1 => "AUTH_BADCRED",
                    2 => "AUTH_REJECTEDCRED",
                    3 => "AUTH_BADVERF",
                    4 => "AUTH_REJECTEDVERF",
                    5 => "AUTH_TOOWEAK (server may require a privileged source port)",
                    6 => "AUTH_INVALIDRESP",
                    7 => "AUTH_FAILED",
                    _ => "unknown auth error",
                };
                write!(f, "RPC authentication error {s}: {name}")
            }
            Error::Accept(a) => match a {
                AcceptError::ProgUnavail => write!(f, "RPC program unavailable"),
                AcceptError::ProgMismatch { low, high } => {
                    write!(f, "RPC program version mismatch (server supports {low}..{high})")
                }
                AcceptError::ProcUnavail => write!(f, "RPC procedure unavailable"),
                AcceptError::GarbageArgs => write!(f, "server could not decode arguments"),
                AcceptError::SystemErr => write!(f, "server system error"),
            },
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::NotRegistered { prog, vers } => {
                write!(f, "program {prog} version {vers} is not registered with portmapper")
            }
            Error::Invalid(m) => write!(f, "{m}"),
            Error::Nfs(st) => write!(f, "{st}"),
            Error::VersionUnsupported(m) => write!(f, "version not supported: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
