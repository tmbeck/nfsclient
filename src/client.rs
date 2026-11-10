//! Version negotiation behind [`crate::fs::connect`], retried as a whole
//! while the server is unreachable.

use std::io::ErrorKind;
use std::net::IpAddr;

use crate::error::{Error, Result};
use crate::fs::{ConnectOptions, Connected, NfsVersion, VersionPref};
use crate::rpc::retry::Retrier;

/// Operation name in retry events and [`Error::GaveUp`] for connection setup.
pub const CONNECT_OP: &str = "connect";

#[derive(Clone, Copy)]
enum Attempt {
    V4(Option<u32>),
    V3,
    V2,
}

/// How a round of attempts (every version in the preference list) failed.
enum Round {
    /// The server answered for real: a permanent error, or every version
    /// is not offered. Retrying cannot help.
    Final(Error),
    /// Only transport-level failures (or "server busy"), possibly mixed with
    /// "not offered": the server may be down or booting. Try again later.
    Transient(Error),
}

/// Connect, negotiating the version per `opts.version`, and retry the whole
/// negotiation under `opts.rpc.retry` while the server is unreachable.
///
/// One round tries every version in the preference list, without retries
/// inside. "Version not offered" answers (PROG_MISMATCH,
/// NFS4ERR_MINOR_VERS_MISMATCH, not registered with portmap) fall through
/// to the next version at once. When no version connects:
/// - a permanent answer from the server (permission denied, no such export,
///   ...) or "not offered" for every version is returned at once;
/// - otherwise the failures were transient (refused, reset, timeout,
///   unreachable, NFS4ERR_DELAY / GRACE): the round is repeated after a
///   backoff until something answers or the budget runs out, then
///   [`Error::GaveUp`] (op `"connect"`) wraps the most informative error of
///   the last round. Retry events report op `"connect"`.
///
/// A host or network that is unreachable ends a round at once: no other
/// version on that host can answer either.
pub fn connect(host: IpAddr, path: &[u8], opts: &ConnectOptions) -> Result<Connected> {
    let attempts: Vec<Attempt> = match opts.version {
        VersionPref::Auto => vec![Attempt::V4(None), Attempt::V3, Attempt::V2],
        VersionPref::AnyV4 => vec![Attempt::V4(None)],
        VersionPref::Exact(NfsVersion::V4(m)) => vec![Attempt::V4(Some(m))],
        VersionPref::Exact(NfsVersion::V3) => vec![Attempt::V3],
        VersionPref::Exact(NfsVersion::V2) => vec![Attempt::V2],
    };
    let policy = &opts.rpc.retry;
    let mut retry = Retrier::new(policy, CONNECT_OP);
    loop {
        match round(host, path, opts, &attempts) {
            Ok(c) => {
                retry.succeeded();
                return Ok(c);
            }
            Err(Round::Final(e)) => return Err(e),
            Err(Round::Transient(e)) if !policy.enabled() => return Err(final_form(e)),
            Err(Round::Transient(e)) => retry.backoff(e)?,
        }
    }
}

/// Try every version once.
fn round(
    host: IpAddr,
    path: &[u8],
    opts: &ConnectOptions,
    attempts: &[Attempt],
) -> std::result::Result<Connected, Round> {
    let mut errors = Vec::new();
    for &a in attempts {
        let r = match a {
            Attempt::V4(minor) => crate::nfs4::connect_for_negotiation(host, path, minor, opts)
                .map_err(mark_v4_refusal),
            Attempt::V3 => crate::nfs3::connect(host, path, opts),
            Attempt::V2 => crate::nfs2::connect(host, path, opts),
        };
        match r {
            Ok(c) => return Ok(c),
            Err(e) => {
                let host_down = host_unreachable(&e);
                errors.push(e);
                if host_down {
                    break;
                }
            }
        }
    }
    Err(classify(errors))
}

/// Decide what a failed round means, and pick the error to report.
fn classify(errors: Vec<Error>) -> Round {
    let transient = errors.iter().any(Error::is_retryable);
    let permanent = errors
        .iter()
        .any(|e| !e.is_retryable() && !e.is_version_unsupported() && !is_v4_refusal(e));
    let best = pick(errors).unwrap_or_else(|| Error::Invalid("no NFS version to try".into()));
    if transient && !permanent {
        Round::Transient(best)
    } else {
        Round::Final(final_form(best))
    }
}

/// The first error of the highest [`progress`].
fn pick(errors: Vec<Error>) -> Option<Error> {
    let mut best: Option<Error> = None;
    for e in errors {
        if best.as_ref().is_none_or(|b| progress(&e) > progress(b)) {
            best = Some(e);
        }
    }
    best
}

/// Message on the I/O error for "nothing listening on the NFSv4 port".
const V4_REFUSED: &str = "connection refused on the NFSv4 port";

/// A refused NFSv4 connection may just mean the server has no NFSv4 on that
/// port (v3 servers can listen elsewhere), so it ranks with "not offered"
/// when picking the error to report, but it is still transient (a booting
/// server refuses too). Tag it so the two can be told apart.
fn mark_v4_refusal(e: Error) -> Error {
    match e {
        Error::Io(io) if io.kind() == ErrorKind::ConnectionRefused => Error::Io(
            std::io::Error::new(ErrorKind::ConnectionRefused, V4_REFUSED),
        ),
        e => e,
    }
}

fn is_v4_refusal(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == ErrorKind::ConnectionRefused
        && io.get_ref().is_some_and(|m| m.to_string() == V4_REFUSED))
}

/// The error to report when no retry follows: a refused NFSv4 connection
/// reads as "NFSv4 is not offered here".
fn final_form(e: Error) -> Error {
    if is_v4_refusal(&e) {
        Error::VersionUnsupported("nothing listening for NFS on the NFSv4 port".into())
    } else {
        e
    }
}

/// The host itself cannot be reached (no route, network down): trying
/// another NFS version on it is pointless until it is back.
fn host_unreachable(e: &Error) -> bool {
    matches!(e, Error::Io(io) if matches!(
        io.kind(),
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown
    ))
}

/// How far a failed attempt got: a server-level answer (MNT3ERR_ACCES, auth
/// rejection, ...) beats a transport failure, which beats "version not offered".
/// The first error of the highest rank wins.
fn progress(e: &Error) -> u8 {
    if e.is_version_unsupported() || is_v4_refusal(e) {
        0
    } else if matches!(e, Error::Io(_) | Error::Timeout) {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AcceptError;
    use crate::fs::Status;

    fn refused() -> Error {
        Error::Io(std::io::Error::from(ErrorKind::ConnectionRefused))
    }

    #[test]
    fn real_mount_error_beats_connect_refusal() {
        let e = pick(vec![
            refused(),
            Error::Nfs(Status::Access),
            Error::NotRegistered {
                prog: 100003,
                vers: 2,
            },
        ])
        .unwrap();
        assert!(matches!(e, Error::Nfs(Status::Access)), "{e}");
    }

    #[test]
    fn transport_error_beats_unsupported() {
        let e = pick(vec![
            Error::VersionUnsupported("v4".into()),
            Error::Timeout,
            Error::NotRegistered {
                prog: 100003,
                vers: 2,
            },
        ])
        .unwrap();
        assert!(matches!(e, Error::Timeout), "{e}");
    }

    #[test]
    fn ties_keep_the_first() {
        let e = pick(vec![
            Error::VersionUnsupported("a".into()),
            Error::NotRegistered { prog: 1, vers: 2 },
        ])
        .unwrap();
        assert!(matches!(e, Error::VersionUnsupported(_)));
    }

    #[test]
    fn unsupported_everywhere_is_final() {
        let r = classify(vec![
            Error::Accept(AcceptError::ProgMismatch { low: 3, high: 3 }),
            Error::NotRegistered { prog: 1, vers: 2 },
        ]);
        assert!(matches!(r, Round::Final(Error::Accept(_))));
    }

    #[test]
    fn refusals_are_transient_and_v4_refusal_ranks_lowest() {
        let r = classify(vec![
            mark_v4_refusal(refused()),
            refused(),
            Error::NotRegistered { prog: 1, vers: 2 },
        ]);
        match r {
            Round::Transient(e) => assert!(!is_v4_refusal(&e) && e.is_retryable(), "{e}"),
            Round::Final(e) => panic!("expected transient, got {e}"),
        }
        // v4 refused, v3/v2 not registered (rpcbind up, nfsd not yet): wait.
        let r = classify(vec![
            mark_v4_refusal(refused()),
            Error::NotRegistered { prog: 1, vers: 3 },
        ]);
        assert!(matches!(r, Round::Transient(_)));
    }

    #[test]
    fn permanent_answer_beats_transient_failures() {
        let r = classify(vec![mark_v4_refusal(refused()), Error::Nfs(Status::Access)]);
        assert!(matches!(r, Round::Final(Error::Nfs(Status::Access))));
    }

    #[test]
    fn a_lone_v4_refusal_reads_as_unsupported_when_final() {
        let e = final_form(mark_v4_refusal(refused()));
        assert!(matches!(e, Error::VersionUnsupported(_)), "{e}");
        assert!(matches!(final_form(refused()), Error::Io(_)));
    }
}
