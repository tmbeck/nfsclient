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
    NotRegistered {
        prog: u32,
        vers: u32,
    },
    /// Bad user input (address parse, etc.).
    Invalid(String),
    /// The server returned a non-OK NFS or MOUNT status.
    Nfs(crate::fs::Status),
    /// The server does not support the requested NFS version / minor version.
    VersionUnsupported(String),
    /// A retryable failure persisted until the retry budget
    /// ([`RetryPolicy::budget`](crate::rpc::RetryPolicy::budget)) ran out.
    /// `last` is the error of the final attempt. Not itself retryable.
    GaveUp {
        /// The operation that was retried (an NFS procedure name such as `READ`).
        op: &'static str,
        /// Attempts made, including the first.
        attempts: u32,
        /// Time from the first failure until giving up.
        elapsed: std::time::Duration,
        last: Box<Error>,
    },
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

/// NFS4ERR_GRACE: the server is in its grace period after a restart.
const NFS4ERR_GRACE: u32 = 10013;

impl Error {
    /// True when the same request may succeed if it is sent again later,
    /// unchanged: the failure is about the connection or the server's
    /// momentary state, not about the request.
    ///
    /// Retryable:
    /// - [`Error::Timeout`] (no reply in time);
    /// - [`Error::Io`] for a lost or refused connection: `ConnectionReset`,
    ///   `ConnectionRefused`, `ConnectionAborted`, `BrokenPipe`,
    ///   `NotConnected`, `UnexpectedEof` (peer closed mid-record), `TimedOut`,
    ///   `HostUnreachable` / `NetworkUnreachable` / `NetworkDown` (a
    ///   rebooting NAS or a flapping link), `WouldBlock` and `Interrupted`;
    /// - [`Error::Nfs`] with [`Status::Jukebox`](crate::fs::Status::Jukebox)
    ///   (NFS3ERR_JUKEBOX, NFS4ERR_DELAY) or NFS4ERR_GRACE.
    ///
    /// Everything else (NFS statuses such as `NoEnt` or `Stale`, RPC rejects,
    /// decode and protocol errors, bad input) is permanent for that request.
    /// Note that a retried non-idempotent call (CREATE, REMOVE, RENAME, ...)
    /// can report an error caused by its own first attempt; callers decide
    /// whether a retry is safe.
    pub fn is_retryable(&self) -> bool {
        use crate::fs::{NfsVersion, Status};
        match self {
            Error::Timeout => true,
            Error::Io(e) => {
                // On macOS / BSD, a failed connect to a closed port or a socket
                // teardown can report EINVAL (code 22) instead of ECONNREFUSED.
                #[cfg(target_os = "macos")]
                if e.raw_os_error() == Some(22) {
                    return true;
                }
                matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::NotConnected
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::HostUnreachable
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::NetworkDown
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                )
            }
            Error::Nfs(Status::Jukebox) => true,
            Error::Nfs(Status::Other(NfsVersion::V4(_), NFS4ERR_GRACE)) => true,
            _ => false,
        }
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
                    write!(
                        f,
                        "RPC program version mismatch (server supports {low}..{high})"
                    )
                }
                AcceptError::ProcUnavail => write!(f, "RPC procedure unavailable"),
                AcceptError::GarbageArgs => write!(f, "server could not decode arguments"),
                AcceptError::SystemErr => write!(f, "server system error"),
            },
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::NotRegistered { prog, vers } => {
                write!(
                    f,
                    "program {prog} version {vers} is not registered with portmapper"
                )
            }
            Error::Invalid(m) => write!(f, "{m}"),
            Error::Nfs(st) => write!(f, "{st}"),
            Error::VersionUnsupported(m) => write!(f, "version not supported: {m}"),
            Error::GaveUp {
                op,
                attempts,
                elapsed,
                last,
            } => write!(
                f,
                "gave up on {op} after retrying for {:.1}s ({attempts} attempts): {last}",
                elapsed.as_secs_f64()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::GaveUp { last, .. } => Some(last.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{NfsVersion, Status};

    #[test]
    fn retryable_classification() {
        let io = |k| Error::Io(io::Error::from(k));
        for e in [
            Error::Timeout,
            io(io::ErrorKind::ConnectionReset),
            io(io::ErrorKind::ConnectionRefused),
            io(io::ErrorKind::ConnectionAborted),
            io(io::ErrorKind::BrokenPipe),
            io(io::ErrorKind::UnexpectedEof),
            Error::Nfs(Status::Jukebox),
            Error::Nfs(Status::Other(NfsVersion::V4(1), 10013)),
        ] {
            assert!(e.is_retryable(), "{e:?}");
        }
        for e in [
            io(io::ErrorKind::PermissionDenied),
            io(io::ErrorKind::NotFound),
            Error::Nfs(Status::Stale),
            Error::Nfs(Status::NoEnt),
            Error::Nfs(Status::Other(NfsVersion::V3, 10013)),
            Error::Protocol("x".into()),
            Error::Xdr("x".into()),
            Error::Rejected(RejectReason::AuthError(5)),
            Error::Accept(AcceptError::GarbageArgs),
            Error::Invalid("x".into()),
        ] {
            assert!(!e.is_retryable(), "{e:?}");
        }
    }
}
