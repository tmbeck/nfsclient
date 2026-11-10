//! NFSv4.x client: connection setup, COMPOUND execution with retry/recovery,
//! and the [`Filesystem`] implementation.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::fs::{
    Attr, ConnectOptions, Connected, CreateMode, DirEntry, FileHandle, FileType, Filesystem,
    FsStat, NfsVersion, SetAttr,
};
use crate::rpc::retry::Retrier;
use crate::rpc::{RpcClient, RpcOptions};

use super::compound::{CompoundArgs, CompoundRes, PROC_COMPOUND};
use super::ops::{
    ChannelAttrs, Claim, CreateKind, FILE_SYNC4, OP_CLOSE, OP_OPEN, OP_OPEN_CONFIRM, Op, OpenHow,
    Res, ResOp, UNSTABLE4,
};
use super::types::{
    ANON_STATEID, BASIC_ATTRS, FSSTAT_ATTRS, Fattr, OPEN4_SHARE_ACCESS_BOTH, READDIR_ATTRS,
    StateId, attr, code, encode_setattr,
};
use crate::rpc::pipeline::{self, DEFAULT_WINDOW, ReadIo, WriteAck, WriteIo};

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 4;
const DEFAULT_PORT: u16 = 2049;

/// Largest READ/WRITE payload we ever send (1 MiB).
pub(crate) const MAX_IO: u32 = 1024 * 1024;
/// Allowance for COMPOUND, SEQUENCE and reply headers when sizing transfers.
const CHAN_OVERHEAD: u32 = 1024;
/// Largest channel size we request in CREATE_SESSION.
pub(super) const CHAN_REQUEST: u32 = MAX_IO + 8192;
/// Session slots requested in CREATE_SESSION (the server may grant fewer).
pub(super) const MAX_SLOTS: u32 = 16;
/// Callback program number we advertise; no callbacks are ever served.
pub(super) const CB_PROGRAM: u32 = 0x4000_0000;
/// Bounds on how long to keep retrying NFS4ERR_GRACE / NFS4ERR_DELAY; see [`grace_wait`].
const GRACE_WAIT_MIN: Duration = Duration::from_secs(30);
const GRACE_WAIT_MAX: Duration = Duration::from_secs(300);
/// Longest wait between two client / session setup attempts that got
/// NFS4ERR_DELAY or NFS4ERR_GRACE.
const SETUP_MAX_BACKOFF: Duration = Duration::from_secs(2);
/// Lease used until the server reports lease_time.
const DEFAULT_LEASE: Duration = Duration::from_secs(90);
/// Cap on remembered (parent, name) pairs used to open files by name in NFSv4.0.
const NAME_CACHE_CAP: usize = 65_536;

/// Session state (NFSv4.1+). Each slot carries one request at a time; blocking
/// calls use a free slot, and pipelined transfers use several.
pub(crate) struct Session {
    pub id: [u8; 16],
    /// Sequence id to use for the next SEQUENCE on each slot (index = slot id).
    pub slot_seq: Vec<u32>,
    /// Slots with a pipelined request whose reply has not been read yet.
    pub busy: Vec<bool>,
    pub max_req: u32,
    pub max_resp: u32,
    /// Slots whose last request may or may not have been executed: its reply
    /// was lost (connection failure, timeout, undecodable reply) or the
    /// server reported a seqid mix-up, so the server's seqid for the slot is
    /// `slot_seq` or one past it. Not used for new requests until
    /// [`Nfs4Backend::resume`] has probed them: reusing the seqid blindly
    /// could get the cached reply of the lost request (data for another
    /// offset) or NFS4ERR_RETRY_UNCACHED_REP.
    pub uncertain: Vec<bool>,
}

impl Session {
    /// A session with `slots` slots, each expecting seqid 1.
    pub(crate) fn new(id: [u8; 16], slots: usize, max_req: u32, max_resp: u32) -> Self {
        Session {
            id,
            slot_seq: vec![1; slots],
            busy: vec![false; slots],
            max_req,
            max_resp,
            uncertain: vec![false; slots],
        }
    }

    /// First slot free for a new request.
    fn usable_slot(&self) -> Option<usize> {
        (0..self.busy.len()).find(|&i| !self.busy[i] && !self.uncertain[i])
    }

    /// Slots that may carry requests: all but the uncertain ones.
    fn usable_count(&self) -> usize {
        self.uncertain.iter().filter(|u| !**u).count()
    }

    fn mark_uncertain(&mut self, slot: usize) {
        if let Some(u) = self.uncertain.get_mut(slot) {
            *u = true;
        }
    }
}

/// SEQUENCE statuses that leave the slot's server-side seqid unknown.
fn slot_confused(status: u32) -> bool {
    matches!(
        status,
        code::SEQ_MISORDERED | code::RETRY_UNCACHED_REP | code::SEQ_FALSE_RETRY
    )
}

/// A COMPOUND sent by [`Nfs4Backend::issue_compound`] whose reply is still due.
#[derive(Debug, Clone, Copy)]
pub(super) struct Pending {
    xid: u32,
    /// Session slot the request was sequenced on (NFSv4.1+).
    slot: Option<usize>,
    /// NFSv4.0: whether a successful reply renews the lease.
    renews: bool,
}

pub(crate) struct Nfs4Backend {
    addr: SocketAddr,
    opts: RpcOptions,
    rpc: RpcClient,
    pub(super) minor: u32,
    root: FileHandle,
    pub(super) clientid: u64,
    pub(super) session: Option<Session>,
    /// Next open-owner seqid (NFSv4.0 OPEN / OPEN_CONFIRM / CLOSE).
    pub(super) open_seqid: u32,
    /// Open-owner string sent with every OPEN. Replaced after NFS4ERR_BAD_SEQID.
    pub(super) open_owner: Vec<u8>,
    /// csa_sequence for the next CREATE_SESSION on `clientid` (NFSv4.1+).
    pub(super) create_seq: u32,
    pub(super) opens: super::state40::OpenCache,
    /// Last known (parent directory, name) for each handle, for NFSv4.0 CLAIM_NULL opens.
    pub(super) names: HashMap<FileHandle, (FileHandle, Vec<u8>)>,
    pub(super) lease: Duration,
    last_activity: Instant,
    max_read: u32,
    max_write: u32,
    readdir_max: u32,
    /// Client owner string, fixed for this connection.
    pub(super) owner_id: Vec<u8>,
    /// Client verifier for EXCHANGE_ID / SETCLIENTID, fixed for the life of
    /// the backend. Re-establishing with the same verifier tells the server
    /// this is the same client instance (not a reboot), so it hands back the
    /// same client ID with its open state when it still has it.
    pub(super) verifier: [u8; 8],
    /// NFSv4.0: an open-owner was abandoned after NFS4ERR_BAD_SEQID while it
    /// still had opens, which can no longer be CLOSEd (their seqid is
    /// unknown). See [`Nfs4Backend::new_open_owner`].
    pub(super) leaked_opens: bool,
    disconnected: bool,
}

/// Random 64-bit value (std only; RandomState is seeded from the OS).
pub(super) fn rand64() -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.write_u128(nanos);
    h.finish()
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

/// Map a failure to open the TCP connection into "NFSv4 is not offered here".
pub(super) fn map_connect_err(e: Error) -> Error {
    match e {
        Error::Io(ref io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            Error::VersionUnsupported("nothing listening for NFS on the NFSv4 port".into())
        }
        other => other,
    }
}

/// Connect with the given minor version, or negotiate the highest supported
/// (2, then 1, then 0) when `minor` is None. Walks `path` from PUTROOTFH.
///
/// With `quick_setup`, the setup calls run without retries and the backend
/// gets `opts.rpc.retry` only once it is connected (the caller retries the
/// whole setup).
pub(crate) fn connect(
    host: IpAddr,
    path: &[u8],
    minor: Option<u32>,
    opts: &ConnectOptions,
    quick_setup: bool,
) -> Result<Connected> {
    let addr = SocketAddr::new(host, opts.nfs_port.unwrap_or(DEFAULT_PORT));
    let mut setup = opts.rpc.clone();
    if quick_setup {
        setup.retry = crate::rpc::RetryPolicy::none();
    }
    let rpc = RpcClient::connect(addr, PROGRAM, VERSION, &setup)?;
    let mut be = Nfs4Backend::new(addr, setup, rpc);
    let minors: Vec<u32> = match minor {
        Some(m) => vec![m],
        None => vec![2, 1, 0],
    };
    let mut negotiated = false;
    for m in minors {
        be.minor = m;
        match be.establish() {
            Ok(()) => {
                negotiated = true;
                break;
            }
            Err(Error::Nfs(crate::fs::Status::Other(_, c))) if c == code::MINOR_VERS_MISMATCH => {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    if !negotiated {
        return Err(Error::VersionUnsupported(
            "server offers no NFSv4 minor version".into(),
        ));
    }
    be.walk(path)?;
    if quick_setup {
        be.opts.retry = opts.rpc.retry.clone();
        be.rpc.set_retry_policy(opts.rpc.retry.clone());
    }
    Ok(Connected {
        fs: Box::new(be),
        export: path.to_vec(),
        remainder: Vec::new(),
    })
}

/// How long to keep retrying NFS4ERR_GRACE (and NFS4ERR_DELAY during client
/// setup). Linux sets the grace period to the lease time, so wait about two
/// leases, within fixed bounds.
pub(super) fn grace_wait(lease: Duration) -> Duration {
    (lease * 2).clamp(GRACE_WAIT_MIN, GRACE_WAIT_MAX)
}

/// Whether an open-owner seqid-mutating operation (OPEN, OPEN_CONFIRM, CLOSE)
/// that returned `status` advanced the owner's seqid. RFC 7530 §9.1.7: the
/// seqid is not incremented for these errors.
pub(super) fn seqid_advances(status: u32) -> bool {
    !matches!(
        status,
        code::STALE_CLIENTID
            | code::STALE_STATEID
            | code::BAD_STATEID
            | code::BAD_SEQID
            | code::BADXDR
            | code::RESOURCE
            | code::NOFILEHANDLE
            | code::MOVED
    )
}

/// Recovery step [`Nfs4Backend::exec`] must take before its next attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fix {
    None,
    /// Open a new TCP connection and resume client state on it
    /// ([`Nfs4Backend::resume`]).
    Reconnect,
    /// Resume client state on the current connection: probe session slots
    /// whose last request was lost ([`Nfs4Backend::resume`]).
    Resume,
    /// Re-establish the client ID and session on the current connection.
    Recover,
    /// New session on the existing client ID, else a full recovery.
    RecoverSession,
}

/// Failures that mean the connection (not the request) is broken: the next
/// attempt needs a new connection.
fn broken_connection(e: &Error) -> bool {
    matches!(e, Error::Io(_) | Error::Timeout | Error::Protocol(_))
}

/// Whether resending `ops` has the same effect as sending them once: only
/// lookups, attribute reads, READ, READDIR, READLINK, and WRITE / COMMIT
/// (the same bytes at the same offset; COMMIT verifiers catch lost unstable
/// data). OPEN, CLOSE, SETATTR and the namespace operations are not.
pub(super) fn idempotent(ops: &[Op]) -> bool {
    ops.iter().all(|op| {
        matches!(
            op,
            Op::Sequence { .. }
                | Op::Putrootfh
                | Op::Putfh(_)
                | Op::Getfh
                | Op::Savefh
                | Op::Lookup(_)
                | Op::Lookupp
                | Op::Getattr(_)
                | Op::Readlink
                | Op::Read { .. }
                | Op::Write { .. }
                | Op::Commit { .. }
                | Op::Readdir { .. }
                | Op::Renew(_)
        )
    })
}

/// A name for the compound in retry events and errors: its first operation
/// other than the file handle plumbing (PUTFH, GETFH, ...).
pub(super) fn compound_name(ops: &[Op]) -> &'static str {
    ops.iter()
        .find_map(|op| {
            Some(match op {
                Op::Putrootfh | Op::Putfh(_) | Op::Getfh | Op::Savefh => return None,
                Op::Sequence { .. } => "SEQUENCE",
                Op::ExchangeId { .. } => "EXCHANGE_ID",
                Op::CreateSession { .. } => "CREATE_SESSION",
                Op::DestroySession(_) => "DESTROY_SESSION",
                Op::BindConnToSession(_) => "BIND_CONN_TO_SESSION",
                Op::DestroyClientid(_) => "DESTROY_CLIENTID",
                Op::ReclaimComplete => "RECLAIM_COMPLETE",
                Op::Setclientid { .. } => "SETCLIENTID",
                Op::SetclientidConfirm { .. } => "SETCLIENTID_CONFIRM",
                Op::Renew(_) => "RENEW",
                Op::Lookup(_) => "LOOKUP",
                Op::Lookupp => "LOOKUPP",
                Op::Getattr(_) => "GETATTR",
                Op::Setattr { .. } => "SETATTR",
                Op::Readlink => "READLINK",
                Op::Read { .. } => "READ",
                Op::Write { .. } => "WRITE",
                Op::Commit { .. } => "COMMIT",
                Op::Open(_) => "OPEN",
                Op::OpenConfirm { .. } => "OPEN_CONFIRM",
                Op::Close { .. } => "CLOSE",
                Op::DelegReturn(_) => "DELEGRETURN",
                Op::Create { .. } => "CREATE",
                Op::Remove(_) => "REMOVE",
                Op::Rename { .. } => "RENAME",
                Op::Link(_) => "LINK",
                Op::Readdir { .. } => "READDIR",
            })
        })
        .unwrap_or("COMPOUND")
}

/// Whether an NFSv4.0 COMPOUND renews the client's lease when it succeeds:
/// RENEW and SETCLIENTID_CONFIRM, or an operation carrying the clientid or a
/// non-special stateid. Plain GETATTR / LOOKUP / READDIR do not.
pub(super) fn renews_lease_40(ops: &[Op]) -> bool {
    ops.iter().any(|op| match op {
        Op::Renew(_) | Op::SetclientidConfirm { .. } | Op::Open(_) => true,
        Op::OpenConfirm { stateid, .. }
        | Op::Close { stateid, .. }
        | Op::Read { stateid, .. }
        | Op::Write { stateid, .. }
        | Op::Setattr { stateid, .. }
        | Op::DelegReturn(stateid) => !stateid.is_special(),
        _ => false,
    })
}

impl Nfs4Backend {
    /// A backend on an open RPC connection, with no client state yet.
    pub(super) fn new(addr: SocketAddr, opts: RpcOptions, rpc: RpcClient) -> Self {
        Nfs4Backend {
            addr,
            opts,
            rpc,
            minor: 0,
            root: FileHandle::default(),
            clientid: 0,
            session: None,
            open_seqid: 0,
            open_owner: super::state40::OPEN_OWNER.to_vec(),
            create_seq: 0,
            opens: super::state40::OpenCache::default(),
            names: HashMap::new(),
            lease: DEFAULT_LEASE,
            last_activity: Instant::now(),
            max_read: MAX_IO,
            max_write: MAX_IO,
            readdir_max: 32 * 1024,
            owner_id: format!("nfsc {} {} {:x}", hostname(), std::process::id(), rand64())
                .into_bytes(),
            verifier: rand64().to_be_bytes(),
            leaked_opens: false,
            disconnected: false,
        }
    }

    pub(super) fn status_err(&self, st: u32) -> Error {
        Error::Nfs(crate::fs::Status::from_v4(st, self.minor))
    }

    /// Turn a compound reply into its results, or the first failing status.
    pub(super) fn check(&self, res: CompoundRes) -> Result<Vec<ResOp>> {
        if res.status == code::OK {
            Ok(res.results)
        } else {
            Err(self.status_err(res.status))
        }
    }

    pub(super) fn new_verifier(&self) -> [u8; 8] {
        rand64().to_be_bytes()
    }

    /// Send one COMPOUND. When `sequenced` and the minor version is 4.1+, a
    /// SEQUENCE is prepended and its result stripped from the returned results.
    /// Bumps the session slot seqid after a successful SEQUENCE and the open
    /// owner seqid for each OPEN / OPEN_CONFIRM / CLOSE that was executed and
    /// did not fail with a non-advancing error ([`seqid_advances`]). Records
    /// lease renewal: a successful SEQUENCE (4.1+), or a successful compound
    /// that renews the lease (4.0, [`renews_lease_40`]).
    pub(super) fn send(&mut self, ops: Vec<Op>, sequenced: bool) -> Result<CompoundRes> {
        let use_seq = sequenced && self.minor >= 1;
        let renews = self.minor == 0 && renews_lease_40(&ops);
        let mut all = Vec::with_capacity(ops.len() + 1);
        let mut slot = None;
        if use_seq {
            let s = self
                .session
                .as_ref()
                .ok_or_else(|| Error::Protocol("NFSv4.1 operation without a session".into()))?;
            let free = s
                .usable_slot()
                .ok_or_else(|| Error::Protocol("no free session slot".into()))?;
            all.push(Op::Sequence {
                session: s.id,
                seqid: s.slot_seq[free],
                slot: free as u32,
                highest: (s.busy.len() - 1) as u32,
            });
            slot = Some(free);
        }
        all.extend(ops);
        let args = CompoundArgs {
            minor: self.minor,
            ops: all,
        };
        let res: CompoundRes = match self.rpc.call(PROC_COMPOUND, &args) {
            Ok(r) => r,
            Err(e) => {
                if let (Some(i), Some(s)) = (slot, self.session.as_mut()) {
                    s.mark_uncertain(i);
                }
                return Err(e);
            }
        };
        if renews && res.status == code::OK {
            self.last_activity = Instant::now();
        }
        let mut results = res.results;
        if let Some(free) = slot {
            let seq_ok = matches!(results.first(), Some(r) if r.status == code::OK);
            let confused = results.first().is_some_and(|r| slot_confused(r.status));
            if !results.is_empty() {
                results.remove(0);
            }
            if let Some(s) = self.session.as_mut() {
                if seq_ok {
                    s.slot_seq[free] = next_seqid(s.slot_seq[free]);
                    self.last_activity = Instant::now();
                } else if confused {
                    s.mark_uncertain(free);
                }
            }
        }
        for r in &results {
            if matches!(r.opcode, OP_OPEN | OP_CLOSE | OP_OPEN_CONFIRM) && seqid_advances(r.status)
            {
                self.open_seqid = self.open_seqid.wrapping_add(1);
            }
        }
        Ok(CompoundRes {
            status: res.status,
            results,
        })
    }

    /// Send one COMPOUND without waiting for its reply (pipelining). On NFSv4.1+
    /// the SEQUENCE is sent on a free session slot, which stays busy until
    /// [`Nfs4Backend::complete_compound`] reads the reply.
    pub(super) fn issue_compound(&mut self, ops: Vec<Op>) -> Result<Pending> {
        let renews = self.minor == 0 && renews_lease_40(&ops);
        let mut all = Vec::with_capacity(ops.len() + 1);
        let mut slot = None;
        if self.minor >= 1 {
            let s = self
                .session
                .as_ref()
                .ok_or_else(|| Error::Protocol("NFSv4.1 operation without a session".into()))?;
            let free = s
                .usable_slot()
                .ok_or_else(|| Error::Protocol("no free session slot".into()))?;
            all.push(Op::Sequence {
                session: s.id,
                seqid: s.slot_seq[free],
                slot: free as u32,
                highest: (s.busy.len() - 1) as u32,
            });
            slot = Some(free);
        }
        all.extend(ops);
        let args = CompoundArgs {
            minor: self.minor,
            ops: all,
        };
        let xid = match self.rpc.send_call(PROC_COMPOUND, &args) {
            Ok(x) => x,
            Err(e) => {
                if let (Some(i), Some(s)) = (slot, self.session.as_mut()) {
                    s.mark_uncertain(i);
                }
                return Err(e);
            }
        };
        if let (Some(i), Some(s)) = (slot, self.session.as_mut()) {
            s.busy[i] = true;
        }
        Ok(Pending { xid, slot, renews })
    }

    /// Read the reply to a pipelined COMPOUND, free its slot, advance the slot's
    /// seqid on success, and return the results (SEQUENCE stripped) or the
    /// failing status.
    pub(super) fn complete_compound(&mut self, p: Pending) -> Result<Vec<ResOp>> {
        let reply = self.rpc.recv_reply::<CompoundRes>(p.xid);
        if let (Some(i), Some(s)) = (p.slot, self.session.as_mut()) {
            s.busy[i] = false;
            let confused = match &reply {
                Err(_) => true,
                Ok(r) => r.results.first().is_some_and(|r| slot_confused(r.status)),
            };
            if confused {
                s.mark_uncertain(i);
            }
        }
        let res = reply?;
        if p.renews && res.status == code::OK {
            self.last_activity = Instant::now();
        }
        let mut results = res.results;
        if let Some(i) = p.slot {
            let seq_ok = matches!(results.first(), Some(r) if r.status == code::OK);
            if !results.is_empty() {
                results.remove(0);
            }
            if let Some(s) = self.session.as_mut().filter(|_| seq_ok) {
                s.slot_seq[i] = next_seqid(s.slot_seq[i]);
                self.last_activity = Instant::now();
            }
        }
        if res.status == code::OK {
            Ok(results)
        } else {
            Err(self.status_err(res.status))
        }
    }

    /// Pipelined requests in flight at once: the session's slot count (capped),
    /// or the default window for NFSv4.0. One over UDP.
    fn window(&self) -> usize {
        if !self.rpc.pipelined() {
            return 1;
        }
        match &self.session {
            Some(s) if self.minor >= 1 => s.usable_count().clamp(1, DEFAULT_WINDOW),
            _ => DEFAULT_WINDOW,
        }
    }

    /// Run a sequenced compound with retry and recovery, under the
    /// connection's [`RetryPolicy`](crate::rpc::RetryPolicy) (one time budget
    /// and backoff for the whole operation, recovery included):
    /// - NFS4ERR_DELAY and NFS4ERR_GRACE: back off and retry (the server did
    ///   not execute the failing operation, so this is safe for any compound).
    /// - NFS4ERR_BADSESSION / DEADSESSION: create a new session on the existing
    ///   client ID (so the server keeps our opens), or fully re-establish if
    ///   that fails; then retry.
    /// - Other session / client / lease errors: re-establish the client and
    ///   session, then retry.
    /// - A broken connection (I/O error, timeout, garbled reply): reconnect
    ///   and re-establish, then resend. Compounds that only read (see
    ///   [`idempotent`]) are resent until the budget runs out; others (OPEN,
    ///   CREATE, REMOVE, RENAME, SETATTR, ...) are resent at most once,
    ///   since a repeat of an executed one can fail misleadingly.
    /// - NFS4ERR_BAD_SEQID (4.0): switch to a fresh open-owner and retry once.
    ///
    /// The first session / client recovery happens at once, even with
    /// retries disabled (it is protocol recovery, not a retry); later ones
    /// back off. Reconnecting and recovery may fail repeatedly while a server
    /// reboots; those failures are retried under the same budget. When the
    /// budget runs out the error is [`Error::GaveUp`].
    ///
    /// Local conditions (no free session slot) fail without touching the connection.
    ///
    /// `build` is called on every attempt so it can read the current clientid
    /// and seqids.
    pub(super) fn exec<F>(&mut self, build: F) -> Result<Vec<ResOp>>
    where
        F: Fn(&Nfs4Backend) -> Vec<Op>,
    {
        self.maybe_renew();
        let policy = self.opts.retry.clone();
        let mut retry = Retrier::new(&policy, "COMPOUND");
        let mut fix = Fix::None;
        if self
            .session
            .as_ref()
            .is_some_and(|s| s.uncertain.iter().any(|u| *u) && !s.busy.iter().any(|b| *b))
        {
            // A slot lost its reply earlier: learn its seqid before using
            // the session again, so the pipeline gets its full window back.
            fix = Fix::Resume;
        }
        // Session / client recoveries so far; the first one does not back off.
        let mut recoveries = 0u32;
        // A non-idempotent compound was already resent after a transport failure.
        let mut resent = false;
        let mut new_owner = false;
        loop {
            if fix != Fix::None {
                let r = match fix {
                    Fix::Reconnect => self.reconnect(),
                    Fix::Resume => self.resume(),
                    Fix::Recover => self.recover(),
                    Fix::RecoverSession => self.recover_session(),
                    Fix::None => Ok(()),
                };
                match r {
                    Ok(()) => fix = Fix::None,
                    Err(e) if broken_connection(&e) => {
                        retry.backoff(e)?;
                        fix = Fix::Reconnect;
                        continue;
                    }
                    Err(e) if e.is_retryable() => {
                        retry.backoff(e)?;
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            if self.minor >= 1 {
                match &self.session {
                    None if recoveries == 0 => {
                        recoveries += 1;
                        fix = Fix::Recover;
                        continue;
                    }
                    None => {
                        return Err(Error::Protocol(
                            "NFSv4.1 operation without a session".into(),
                        ));
                    }
                    Some(s) if s.usable_slot().is_none() => {
                        if s.uncertain.iter().any(|u| *u) && !s.busy.iter().any(|b| *b) {
                            // Only slots with a lost request are left: probe them.
                            fix = Fix::Resume;
                            continue;
                        }
                        return Err(Error::Protocol("no free session slot".into()));
                    }
                    Some(_) => {}
                }
            }
            let ops = build(&*self);
            let idem = idempotent(&ops);
            // CLOSE / OPEN_CONFIRM carry a stateid of the current open-owner;
            // after BAD_SEQID that owner is gone, so a rebuilt one would mix
            // the new owner's seqid with the old owner's stateid.
            let owner_bound = ops
                .iter()
                .any(|op| matches!(op, Op::Close { .. } | Op::OpenConfirm { .. }));
            retry.set_op(compound_name(&ops));
            let res = match self.send(ops, true) {
                Ok(r) => r,
                Err(e) if broken_connection(&e) => {
                    if !idem {
                        if resent {
                            return Err(e);
                        }
                        resent = true;
                    }
                    retry.backoff(e)?;
                    fix = Fix::Reconnect;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if res.status == code::OK {
                retry.succeeded();
                return Ok(res.results);
            }
            match res.status {
                code::DELAY | code::GRACE => retry.backoff(self.status_err(res.status))?,
                code::BAD_SEQID if self.minor == 0 && owner_bound => {
                    self.new_open_owner();
                    return Err(self.status_err(res.status));
                }
                code::BAD_SEQID if self.minor == 0 && !new_owner => {
                    new_owner = true;
                    self.new_open_owner();
                }
                code::BADSESSION | code::DEADSESSION => {
                    if recoveries > 0 {
                        retry.backoff(self.status_err(res.status))?;
                    }
                    recoveries += 1;
                    fix = Fix::RecoverSession;
                }
                code::SEQ_MISORDERED | code::RETRY_UNCACHED_REP | code::SEQ_FALSE_RETRY
                    if self.minor >= 1 =>
                {
                    // `send` marked the slot uncertain; probing it (or, if
                    // that fails, a new session on the same client ID)
                    // brings it back without losing open state.
                    if recoveries > 0 {
                        retry.backoff(self.status_err(res.status))?;
                    }
                    recoveries += 1;
                    fix = Fix::Resume;
                }
                code::EXPIRED if recoveries > 0 => {
                    // The client state was already re-established in this
                    // call, so EXPIRED now refers to a stateid in the request
                    // that belonged to the old client (NFSv4.0 servers such as
                    // knfsd answer EXPIRED for those). Recovering again would
                    // loop until the budget runs out; let the caller replace
                    // the stateid instead (see `exec_stateid`).
                    return Err(self.status_err(res.status));
                }
                code::STALE_CLIENTID | code::EXPIRED | code::BADSLOT | code::BAD_HIGH_SLOT => {
                    if recoveries > 0 {
                        retry.backoff(self.status_err(res.status))?;
                    }
                    recoveries += 1;
                    fix = Fix::Recover;
                }
                other => return Err(self.status_err(other)),
            }
        }
    }

    /// [`Nfs4Backend::send`] for client / session setup, which cannot go through
    /// [`Nfs4Backend::exec`]: NFS4ERR_DELAY and NFS4ERR_GRACE are retried with
    /// backoff for up to [`grace_wait`]; any other status is returned as is.
    pub(super) fn send_setup<F>(&mut self, sequenced: bool, build: F) -> Result<CompoundRes>
    where
        F: Fn(&Nfs4Backend) -> Vec<Op>,
    {
        // The connection's retry policy, but never longer than a grace period.
        let mut policy = self.opts.retry.clone();
        policy.budget = policy.budget.min(grace_wait(self.lease));
        policy.max_backoff = policy.max_backoff.min(SETUP_MAX_BACKOFF);
        let mut retry = Retrier::new(&policy, "COMPOUND");
        loop {
            let ops = build(&*self);
            retry.set_op(compound_name(&ops));
            let res = self.send(ops, sequenced)?;
            if !matches!(res.status, code::DELAY | code::GRACE) || !policy.enabled() {
                retry.succeeded();
                return Ok(res);
            }
            retry.backoff(self.status_err(res.status))?;
        }
    }

    /// Reopen the TCP connection and resume client state on it.
    fn reconnect(&mut self) -> Result<()> {
        self.rpc = RpcClient::connect(self.addr, PROGRAM, VERSION, &self.opts)?;
        self.resume()
    }

    /// Keep as much client state as the server still has after the
    /// connection was lost (and re-established), cheapest step first:
    ///
    /// - NFSv4.1+: keep using the session. With SP4_NONE a SEQUENCE on the
    ///   new connection binds it to the session (RFC 8881 §2.10.11.1);
    ///   BIND_CONN_TO_SESSION is sent if the server asks for it. Slots whose
    ///   request was lost with the old connection are probed first, so their
    ///   seqids are known again. Then CREATE_SESSION on the existing client
    ///   ID, and only then a new EXCHANGE_ID ([`Nfs4Backend::recover`]).
    /// - NFSv4.0: RENEW the client ID on the new connection; only if the
    ///   server no longer knows it, SETCLIENTID again.
    ///
    /// Open stateids stay valid in every case where the server kept the
    /// client ID. Errors that mean "try again later" (a broken connection,
    /// NFS4ERR_DELAY) are returned for the caller to back off and retry.
    pub(super) fn resume(&mut self) -> Result<()> {
        if self.clientid == 0 {
            return self.recover();
        }
        if self.minor == 0 {
            let res = self.send(vec![Op::Renew(self.clientid)], false)?;
            return match res.status {
                // CB_PATH_DOWN still renews the lease (RFC 7530 §16.29.4); no
                // callbacks are ever served, so Linux reports it routinely.
                code::OK | code::CB_PATH_DOWN => Ok(()),
                code::DELAY => Err(self.status_err(res.status)),
                _ => self.recover(),
            };
        }
        if self.session.is_some() {
            match self.resume_session() {
                Ok(()) => return Ok(()),
                Err(e) if e.is_retryable() || broken_connection(&e) => return Err(e),
                Err(_) => {}
            }
        }
        self.recover_session()
    }

    /// NFSv4.1+: make the current session usable on the current connection.
    /// Probes every uncertain slot (see [`Session::uncertain`]), or sends one
    /// empty SEQUENCE when there is none.
    fn resume_session(&mut self) -> Result<()> {
        let uncertain: Vec<usize> = match &self.session {
            Some(s) => (0..s.uncertain.len()).filter(|&i| s.uncertain[i]).collect(),
            None => return Err(Error::Protocol("no session to resume".into())),
        };
        if uncertain.is_empty() {
            let slot = self
                .session
                .as_ref()
                .and_then(Session::usable_slot)
                .ok_or_else(|| Error::Protocol("no free session slot".into()))?;
            let seqid = self.session.as_ref().map_or(1, |s| s.slot_seq[slot]);
            let st = self.probe_slot(slot, seqid)?;
            if st != code::OK {
                return Err(self.status_err(st));
            }
            if let Some(s) = self.session.as_mut() {
                s.slot_seq[slot] = next_seqid(seqid);
            }
            return Ok(());
        }
        for slot in uncertain {
            self.resolve_slot(slot)?;
        }
        Ok(())
    }

    /// Learn the server's seqid for a slot whose last request (seqid N) was
    /// lost. A SEQUENCE with N+1 succeeds if the server executed N; if it
    /// answers NFS4ERR_SEQ_MISORDERED, N never ran, and N is sent again as a
    /// new (empty) request. Either way the slot is usable afterwards.
    fn resolve_slot(&mut self, slot: usize) -> Result<()> {
        let n = match &self.session {
            Some(s) => s.slot_seq[slot],
            None => return Err(Error::Protocol("no session to resume".into())),
        };
        let mut used = next_seqid(n);
        let mut st = self.probe_slot(slot, used)?;
        if st == code::SEQ_MISORDERED {
            used = n;
            st = self.probe_slot(slot, used)?;
        }
        if st != code::OK {
            return Err(self.status_err(st));
        }
        if let Some(s) = self.session.as_mut() {
            s.slot_seq[slot] = next_seqid(used);
            s.uncertain[slot] = false;
        }
        Ok(())
    }

    /// One COMPOUND holding only SEQUENCE(`slot`, `seqid`) on the current
    /// session; returns its status. When the server wants the connection
    /// bound first (NFS4ERR_CONN_NOT_BOUND_TO_SESSION), sends
    /// BIND_CONN_TO_SESSION and tries once more.
    fn probe_slot(&mut self, slot: usize, seqid: u32) -> Result<u32> {
        let Some((id, highest)) = self.session.as_ref().map(|s| (s.id, s.busy.len() - 1)) else {
            return Err(Error::Protocol("no session to resume".into()));
        };
        let mut bound = false;
        loop {
            let args = CompoundArgs {
                minor: self.minor,
                ops: vec![Op::Sequence {
                    session: id,
                    seqid,
                    slot: slot as u32,
                    highest: highest as u32,
                }],
            };
            let res: CompoundRes = self.rpc.call(PROC_COMPOUND, &args)?;
            if res.status == code::CONN_NOT_BOUND_TO_SESSION && !bound {
                bound = true;
                let r = self.send(vec![Op::BindConnToSession(id)], false)?;
                if r.status != code::OK {
                    return Ok(r.status);
                }
                continue;
            }
            if res.status == code::OK {
                self.last_activity = Instant::now();
            }
            return Ok(res.status);
        }
    }

    /// Re-establish client ID / session after the server dropped our state
    /// (or a resume failed). Uses the backend's fixed verifier, so a server
    /// that still has the client ID returns it unchanged; open stateids are
    /// kept in that case and discarded when the client ID changed.
    pub(super) fn recover(&mut self) -> Result<()> {
        let old = self.clientid;
        let opens = std::mem::take(&mut self.opens);
        let seqid = self.open_seqid;
        self.session = None;
        match self.establish() {
            Ok(()) if old != 0 && self.clientid == old => {
                self.opens = opens;
                self.open_seqid = seqid;
                Ok(())
            }
            Ok(()) => Ok(()),
            Err(e) => {
                // Nothing is known yet; the next attempt decides.
                self.opens = opens;
                self.open_seqid = seqid;
                Err(e)
            }
        }
    }

    /// The session is gone but the client ID may not be: try CREATE_SESSION on
    /// the existing client ID first, so the server keeps our opens; fall back
    /// to a full [`Nfs4Backend::recover`].
    fn recover_session(&mut self) -> Result<()> {
        self.session = None;
        if self.minor >= 1 && self.clientid != 0 && self.create_session(self.clientid).is_ok() {
            return Ok(());
        }
        self.recover()
    }

    /// Abandon the open-owner after NFS4ERR_BAD_SEQID: its seqid is unknown,
    /// so its opens can no longer be closed and are forgotten. The next OPEN
    /// uses a new owner, whose first seqid the server accepts as given.
    ///
    /// The abandoned owner's opens cannot be released one by one: CLOSE needs
    /// the owner's seqid, and RELEASE_LOCKOWNER only covers lock owners. If
    /// there were any, disconnecting releases them all at once with a
    /// SETCLIENTID / SETCLIENTID_CONFIRM under a new verifier (the server
    /// then drops the old client's state, as after a client reboot);
    /// otherwise they would only expire with the lease.
    pub(super) fn new_open_owner(&mut self) {
        if self.minor == 0 && !self.opens.drain().is_empty() {
            self.leaked_opens = true;
        }
        let mut owner = super::state40::OPEN_OWNER.to_vec();
        owner.extend_from_slice(format!(" {:x}", rand64()).as_bytes());
        self.open_owner = owner;
        self.open_seqid = 0;
    }

    /// Establish a client ID (and a session for 4.1+) on the current connection.
    fn establish(&mut self) -> Result<()> {
        if self.minor == 0 {
            self.establish_40()
        } else {
            self.establish_41()
        }
    }

    /// Lease upkeep before an operation: RENEW (4.0) or an empty SEQUENCE
    /// compound (4.1+) once half the lease has passed without traffic.
    /// Failures are ignored; the operation itself will hit the error and recover.
    fn maybe_renew(&mut self) {
        if self.last_activity.elapsed() < self.lease / 2 {
            return;
        }
        if self.minor == 0 {
            let _ = self.send(vec![Op::Renew(self.clientid)], false);
        } else if self.session.is_some() {
            let _ = self.send(Vec::new(), true);
        }
    }

    /// Walk `path` from the pseudo-root, one LOOKUP (or LOOKUPP for "..") per component.
    fn walk(&mut self, path: &[u8]) -> Result<()> {
        let res = self.exec(|_| vec![Op::Putrootfh, Op::Getfh])?;
        let mut cur = fh_at(&res, 1)?;
        for comp in path
            .split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
        {
            let dir = cur.clone();
            let is_parent = comp == b"..";
            let name = comp.to_vec();
            let res = self.exec(|_| {
                if is_parent {
                    vec![Op::Putfh(dir.0.clone()), Op::Lookupp, Op::Getfh]
                } else {
                    vec![
                        Op::Putfh(dir.0.clone()),
                        Op::Lookup(name.clone()),
                        Op::Getfh,
                    ]
                }
            })?;
            let next = fh_at(&res, 2)?;
            if !is_parent {
                self.remember(&next, &dir, comp);
            }
            cur = next;
        }
        let res = self.exec(|_| {
            vec![
                Op::Putfh(cur.0.clone()),
                Op::Getattr(vec![
                    attr::SUPPORTED_ATTRS,
                    attr::LEASE_TIME,
                    attr::MAXREAD,
                    attr::MAXWRITE,
                ]),
            ]
        })?;
        let a = attr_at(&res, 1)?;
        if let Some(l) = a.lease_time.filter(|l| *l > 0) {
            self.lease = Duration::from_secs(u64::from(l));
        }
        let (chan_req, chan_resp) = match &self.session {
            Some(s) => (s.max_req, s.max_resp),
            None => (u32::MAX, u32::MAX),
        };
        let srv_read = a
            .maxread
            .map(|v| v.min(u64::from(u32::MAX)) as u32)
            .unwrap_or(MAX_IO);
        let srv_write = a
            .maxwrite
            .map(|v| v.min(u64::from(u32::MAX)) as u32)
            .unwrap_or(MAX_IO);
        self.max_read = srv_read
            .min(chan_resp.saturating_sub(CHAN_OVERHEAD))
            .clamp(512, MAX_IO);
        self.max_write = srv_write
            .min(chan_req.saturating_sub(CHAN_OVERHEAD))
            .clamp(512, MAX_IO);
        self.readdir_max = chan_resp.saturating_sub(4096).clamp(1024, 32 * 1024);
        self.root = cur;
        Ok(())
    }

    /// Remember that `child` is `name` inside `dir` (for NFSv4.0 open-by-name).
    pub(super) fn remember(&mut self, child: &FileHandle, dir: &FileHandle, name: &[u8]) {
        if self.names.len() >= NAME_CACHE_CAP {
            self.names.clear();
        }
        self.names
            .insert(child.clone(), (dir.clone(), name.to_vec()));
    }

    /// Run `build` with the stateid for I/O on `fh`. If the stateid is rejected,
    /// forget it, open the file again and retry with the new stateid; if that
    /// fails too, retry once with the anonymous stateid.
    pub(super) fn exec_stateid<F>(
        &mut self,
        fh: &FileHandle,
        write: bool,
        build: F,
    ) -> Result<Vec<ResOp>>
    where
        F: Fn(StateId) -> Vec<Op>,
    {
        let sid = self.stateid_for_io(fh, write);
        match self.exec(|_| build(sid)) {
            Err(Error::Nfs(crate::fs::Status::Other(_, c)))
                if sid != ANON_STATEID && Self::is_stateid_error(c) =>
            {
                self.opens.forget(fh);
                let fresh = self.stateid_for_io(fh, write);
                if fresh != ANON_STATEID {
                    match self.exec(|_| build(fresh)) {
                        Err(Error::Nfs(crate::fs::Status::Other(_, c)))
                            if Self::is_stateid_error(c) =>
                        {
                            self.opens.forget(fh);
                        }
                        other => return other,
                    }
                }
                self.exec(|_| build(ANON_STATEID))
            }
            other => other,
        }
    }

    fn release_object(&mut self, fh: &FileHandle) {
        self.opens.forget(fh);
        self.names.remove(fh);
    }

    fn disconnect_inner(&mut self) {
        if self.disconnected {
            return;
        }
        self.disconnected = true;
        if self.clientid == 0 {
            // Never got as far as establishing client state.
            return;
        }
        for (fh, sid) in self.opens.drain() {
            let seqid = self.open_seqid;
            let _ = self.send(
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Close {
                        seqid,
                        stateid: sid,
                    },
                ],
                true,
            );
        }
        if self.minor == 0 && self.leaked_opens {
            let _ = self.release_client_40();
        }
        if self.minor >= 1 {
            if let Some(id) = self.session.as_ref().map(|s| s.id) {
                let _ = self.send(vec![Op::DestroySession(id)], true);
                self.session = None;
            }
            let _ = self.send(vec![Op::DestroyClientid(self.clientid)], false);
        }
    }
}

impl Drop for Nfs4Backend {
    fn drop(&mut self) {
        self.disconnect_inner();
    }
}

/// Slot sequence id after `s`; wraps through 0 (RFC 8881 §2.10.6.1).
fn next_seqid(s: u32) -> u32 {
    s.wrapping_add(1)
}

/// READ pipeline: one COMPOUND per request, sequenced on a free slot (4.1+).
struct V4Reads<'a, 'b> {
    be: &'a mut Nfs4Backend,
    fh: &'b FileHandle,
    stateid: StateId,
}

impl ReadIo for V4Reads<'_, '_> {
    type Tag = Pending;

    fn issue(&mut self, offset: u64, count: u32) -> Result<Pending> {
        let (fh, stateid) = (self.fh.0.clone(), self.stateid);
        self.be.issue_compound(vec![
            Op::Putfh(fh),
            Op::Read {
                stateid,
                offset,
                count,
            },
        ])
    }

    fn complete(&mut self, p: Pending) -> Result<(Vec<u8>, bool)> {
        let res = self.be.complete_compound(p)?;
        match body(&res, 1)? {
            Res::Read { eof, data } => Ok((data.clone(), *eof)),
            _ => Err(xdr_err("READ")),
        }
    }

    fn read_sync(&mut self, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        let policy = self.be.opts.retry.clone();
        let r = pipeline::read_with_progress(&policy, offset, count, || {
            self.be.read(self.fh, offset, count)
        });
        // Recovery (after a server restart) may have replaced the open state;
        // later pipelined READs must not use a stale stateid.
        self.stateid = self.be.stateid_for_io(self.fh, false);
        r
    }
}

/// UNSTABLE WRITE pipeline; COMMIT goes through the normal blocking path.
struct V4Writes<'a, 'b> {
    be: &'a mut Nfs4Backend,
    fh: &'b FileHandle,
    stateid: StateId,
}

impl WriteIo for V4Writes<'_, '_> {
    type Tag = Pending;

    fn issue(&mut self, offset: u64, data: &[u8]) -> Result<Pending> {
        let (fh, stateid) = (self.fh.0.clone(), self.stateid);
        self.be.issue_compound(vec![
            Op::Putfh(fh),
            Op::Write {
                stateid,
                offset,
                data: data.to_vec(),
                stable: UNSTABLE4,
            },
        ])
    }

    fn complete(&mut self, p: Pending) -> Result<WriteAck> {
        let res = self.be.complete_compound(p)?;
        match body(&res, 1)? {
            Res::Write {
                count,
                committed,
                verf,
            } => Ok(WriteAck {
                count: *count,
                durable: *committed == FILE_SYNC4,
                verf: *verf,
            }),
            _ => Err(xdr_err("WRITE")),
        }
    }

    fn write_sync(&mut self, offset: u64, data: &[u8]) -> Result<WriteAck> {
        let fh = self.fh;
        let res = self.be.exec_stateid(fh, true, |sid| {
            vec![
                Op::Putfh(fh.0.clone()),
                Op::Write {
                    stateid: sid,
                    offset,
                    data: data.to_vec(),
                    stable: UNSTABLE4,
                },
            ]
        });
        // As for reads: pick up open state re-established by recovery.
        self.stateid = self.be.stateid_for_io(fh, true);
        match body(&res?, 1)? {
            Res::Write {
                count,
                committed,
                verf,
            } => Ok(WriteAck {
                count: *count,
                durable: *committed == FILE_SYNC4,
                verf: *verf,
            }),
            _ => Err(xdr_err("WRITE")),
        }
    }

    fn commit(&mut self, offset: u64, count: u32) -> Result<[u8; 8]> {
        let fh = self.fh.0.clone();
        let res = self
            .be
            .exec(|_| vec![Op::Putfh(fh.clone()), Op::Commit { offset, count }])?;
        match body(&res, 1)? {
            Res::Verf(v) => Ok(*v),
            _ => Err(xdr_err("COMMIT")),
        }
    }
}

/// Result body of op `i`, or an error if it is missing.
pub(super) fn body(res: &[ResOp], i: usize) -> Result<&Res> {
    res.get(i)
        .map(|r| &r.body)
        .ok_or_else(|| Error::Xdr(format!("missing result for operation {i}")))
}

pub(super) fn fh_at(res: &[ResOp], i: usize) -> Result<FileHandle> {
    match body(res, i)? {
        Res::Fh(v) => Ok(FileHandle(v.clone())),
        _ => Err(Error::Xdr("expected GETFH result".into())),
    }
}

pub(super) fn attr_at(res: &[ResOp], i: usize) -> Result<&super::types::AttrSet> {
    match body(res, i)? {
        Res::Attr(a) => Ok(a),
        _ => Err(Error::Xdr("expected GETATTR result".into())),
    }
}

fn to_fs_attr(a: &super::types::AttrSet) -> Attr {
    a.to_attr()
}

fn check_ftype_dir(a: &Attr, want_dir: bool) -> Result<()> {
    match (a.ftype, want_dir) {
        (FileType::Directory, false) => Err(Error::Nfs(crate::fs::Status::IsDir)),
        (t, true) if t != FileType::Directory => Err(Error::Nfs(crate::fs::Status::NotDir)),
        _ => Ok(()),
    }
}

fn xdr_err(what: &str) -> Error {
    Error::Xdr(format!("unexpected result body for {what}"))
}

impl Filesystem for Nfs4Backend {
    fn version(&self) -> NfsVersion {
        NfsVersion::V4(self.minor)
    }

    fn root(&self) -> FileHandle {
        self.root.clone()
    }

    fn max_read(&self) -> u32 {
        self.max_read
    }

    fn max_write(&self) -> u32 {
        self.max_write
    }

    fn getattr(&mut self, fh: &FileHandle) -> Result<Attr> {
        let res =
            self.exec(|_| vec![Op::Putfh(fh.0.clone()), Op::Getattr(BASIC_ATTRS.to_vec())])?;
        Ok(to_fs_attr(attr_at(&res, 1)?))
    }

    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr> {
        let fat: Fattr = encode_setattr(attrs, None);
        let res = if attrs.size.is_some() {
            self.exec_stateid(fh, true, |sid| {
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Setattr {
                        stateid: sid,
                        attrs: fat.clone(),
                    },
                    Op::Getattr(BASIC_ATTRS.to_vec()),
                ]
            })?
        } else {
            self.exec(|_| {
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Setattr {
                        stateid: ANON_STATEID,
                        attrs: fat.clone(),
                    },
                    Op::Getattr(BASIC_ATTRS.to_vec()),
                ]
            })?
        };
        Ok(to_fs_attr(attr_at(&res, 2)?))
    }

    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> Result<(FileHandle, Attr)> {
        if name == b"." {
            let a = self.getattr(dir)?;
            return Ok((dir.clone(), a));
        }
        let parent = name == b"..";
        let res = self.exec(|_| {
            if parent {
                vec![
                    Op::Putfh(dir.0.clone()),
                    Op::Lookupp,
                    Op::Getfh,
                    Op::Getattr(BASIC_ATTRS.to_vec()),
                ]
            } else {
                vec![
                    Op::Putfh(dir.0.clone()),
                    Op::Lookup(name.to_vec()),
                    Op::Getfh,
                    Op::Getattr(BASIC_ATTRS.to_vec()),
                ]
            }
        })?;
        let fh = fh_at(&res, 2)?;
        let a = to_fs_attr(attr_at(&res, 3)?);
        if !parent {
            self.remember(&fh, dir, name);
        }
        Ok((fh, a))
    }

    fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<DirEntry>> {
        let mut out: Vec<DirEntry> = Vec::new();
        let mut cookie = 0u64;
        let mut verf = [0u8; 8];
        let mut restarted = false;
        loop {
            let (cookie_now, verf_now) = (cookie, verf);
            let res = self.exec(|s| {
                vec![
                    Op::Putfh(dir.0.clone()),
                    Op::Readdir {
                        cookie: cookie_now,
                        verifier: verf_now,
                        dircount: s.readdir_max,
                        maxcount: s.readdir_max,
                        attrs: READDIR_ATTRS.to_vec(),
                    },
                ]
            });
            let res = match res {
                Err(Error::Nfs(crate::fs::Status::BadCookie)) if !restarted => {
                    restarted = true;
                    out.clear();
                    cookie = 0;
                    verf = [0u8; 8];
                    continue;
                }
                other => other?,
            };
            let (new_verf, entries, eof) = match body(&res, 1)? {
                Res::Readdir {
                    verifier,
                    entries,
                    eof,
                } => (*verifier, entries.clone(), *eof),
                _ => return Err(xdr_err("READDIR")),
            };
            // Without this, a server that returns empty pages without EOF would
            // keep the loop spinning on the same cookie forever.
            if entries.is_empty() && !eof {
                return Err(Error::Protocol(
                    "READDIR returned no entries before eof".into(),
                ));
            }
            for e in entries {
                cookie = e.cookie;
                if e.name == b"." || e.name == b".." {
                    continue;
                }
                let handle = e.attrs.filehandle.clone().map(FileHandle);
                let attr = if e.attrs.rdattr_error.unwrap_or(0) == 0 {
                    Some(to_fs_attr(&e.attrs))
                } else {
                    None
                };
                let fileid = e.attrs.fileid.unwrap_or(0);
                if let Some(h) = &handle {
                    self.remember(h, dir, &e.name);
                }
                out.push(DirEntry {
                    name: e.name,
                    fileid,
                    attr,
                    handle,
                });
            }
            if out.len() > crate::fs::MAX_DIR_ENTRIES {
                return Err(Error::Protocol(format!(
                    "directory listing exceeds {} entries",
                    crate::fs::MAX_DIR_ENTRIES
                )));
            }
            verf = new_verf;
            if eof {
                break;
            }
        }
        Ok(out)
    }

    fn readlink(&mut self, fh: &FileHandle) -> Result<Vec<u8>> {
        let res = self.exec(|_| vec![Op::Putfh(fh.0.clone()), Op::Readlink])?;
        match body(&res, 1)? {
            Res::Readlink(t) => Ok(t.clone()),
            _ => Err(xdr_err("READLINK")),
        }
    }

    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        let count = count.min(self.max_read);
        if count == 0 {
            return Ok((Vec::new(), false));
        }
        let res = self.exec_stateid(fh, false, |sid| {
            vec![
                Op::Putfh(fh.0.clone()),
                Op::Read {
                    stateid: sid,
                    offset,
                    count,
                },
            ]
        })?;
        match body(&res, 1)? {
            Res::Read { eof, data } => Ok((data.clone(), *eof)),
            _ => Err(xdr_err("READ")),
        }
    }

    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> Result<u32> {
        let mut done = 0usize;
        let chunk_max = self.max_write as usize;
        while done < data.len() {
            let n = (data.len() - done).min(chunk_max);
            let chunk = &data[done..done + n];
            let off = offset + done as u64;
            let res = self.exec_stateid(fh, true, |sid| {
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Write {
                        stateid: sid,
                        offset: off,
                        data: chunk.to_vec(),
                        stable: FILE_SYNC4,
                    },
                ]
            })?;
            let (count, committed) = match body(&res, 1)? {
                Res::Write {
                    count, committed, ..
                } => (*count as usize, *committed),
                _ => return Err(xdr_err("WRITE")),
            };
            let count = count.min(n);
            if committed != FILE_SYNC4 && count > 0 {
                // Server buffered the data; make it durable.
                self.exec(|_| {
                    vec![
                        Op::Putfh(fh.0.clone()),
                        Op::Commit {
                            offset: off,
                            count: count as u32,
                        },
                    ]
                })?;
            }
            if count == 0 {
                break;
            }
            done += count;
        }
        Ok(done as u32)
    }

    fn read_stream(
        &mut self,
        fh: &FileHandle,
        offset: u64,
        len: Option<u64>,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        self.maybe_renew();
        let stateid = self.stateid_for_io(fh, false);
        let (chunk, window) = (self.max_read, self.window());
        let mut io = V4Reads {
            be: self,
            fh,
            stateid,
        };
        pipeline::read_pipelined(&mut io, offset, len, chunk, window, sink)
    }

    fn write_stream(
        &mut self,
        fh: &FileHandle,
        offset: u64,
        source: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<u64> {
        self.maybe_renew();
        let stateid = self.stateid_for_io(fh, true);
        let (chunk, window) = (self.max_write as usize, self.window());
        let mut io = V4Writes {
            be: self,
            fh,
            stateid,
        };
        pipeline::write_pipelined(&mut io, offset, chunk, window, source)
    }

    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_FILE_MODE);
        let exclusive = mode == CreateMode::Exclusive;
        let verf = self.new_verifier();
        let fat = if exclusive {
            Fattr::default()
        } else {
            encode_setattr(attrs, Some(0o644))
        };
        let createmode = match mode {
            CreateMode::Unchecked => 0,
            CreateMode::Guarded => 1,
            CreateMode::Exclusive => {
                if self.minor >= 1 {
                    3
                } else {
                    2
                }
            }
        };
        let res = self.exec(|s| {
            vec![
                Op::Putfh(dir.0.clone()),
                Op::Open(super::state40::open_args(
                    s,
                    OPEN4_SHARE_ACCESS_BOTH,
                    OpenHow::Create {
                        mode: createmode,
                        verf,
                        attrs: fat.clone(),
                    },
                    Claim::Null(name.to_vec()),
                )),
                Op::Getfh,
                Op::Getattr(BASIC_ATTRS.to_vec()),
            ]
        })?;
        let (stateid, rflags, deleg) = match body(&res, 1)? {
            Res::Open {
                stateid,
                rflags,
                deleg,
            } => (*stateid, *rflags, *deleg),
            _ => return Err(xdr_err("OPEN")),
        };
        let fh = fh_at(&res, 2)?;
        let mut attr = to_fs_attr(attr_at(&res, 3)?);
        self.finish_open(&fh, stateid, rflags, deleg, OPEN4_SHARE_ACCESS_BOTH)?;
        self.remember(&fh, dir, name);
        if exclusive && !attrs_empty(attrs) {
            attr = self.setattr(&fh, attrs)?;
        }
        Ok((fh, attr))
    }

    fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_DIR_MODE);
        let fat = encode_setattr(attrs, Some(0o755));
        let res = self.exec(|_| {
            vec![
                Op::Putfh(dir.0.clone()),
                Op::Create {
                    kind: CreateKind::Dir,
                    name: name.to_vec(),
                    attrs: fat.clone(),
                },
                Op::Getfh,
                Op::Getattr(BASIC_ATTRS.to_vec()),
            ]
        })?;
        let fh = fh_at(&res, 2)?;
        let a = to_fs_attr(attr_at(&res, 3)?);
        self.remember(&fh, dir, name);
        Ok((fh, a))
    }

    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_SYMLINK_MODE);
        let fat = encode_setattr(attrs, Some(0o777));
        let res = self.exec(|_| {
            vec![
                Op::Putfh(dir.0.clone()),
                Op::Create {
                    kind: CreateKind::Symlink(target.to_vec()),
                    name: name.to_vec(),
                    attrs: fat.clone(),
                },
                Op::Getfh,
                Op::Getattr(BASIC_ATTRS.to_vec()),
            ]
        })?;
        let fh = fh_at(&res, 2)?;
        let a = to_fs_attr(attr_at(&res, 3)?);
        self.remember(&fh, dir, name);
        Ok((fh, a))
    }

    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> Result<()> {
        self.exec(|_| {
            vec![
                Op::Putfh(target.0.clone()),
                Op::Savefh,
                Op::Putfh(dir.0.clone()),
                Op::Link(name.to_vec()),
            ]
        })?;
        Ok(())
    }

    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let (fh, a) = self.lookup(dir, name)?;
        check_ftype_dir(&a, false)?;
        self.close_entry(&fh);
        self.exec(|_| vec![Op::Putfh(dir.0.clone()), Op::Remove(name.to_vec())])?;
        self.release_object(&fh);
        Ok(())
    }

    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let (fh, a) = self.lookup(dir, name)?;
        check_ftype_dir(&a, true)?;
        self.exec(|_| vec![Op::Putfh(dir.0.clone()), Op::Remove(name.to_vec())])?;
        self.release_object(&fh);
        Ok(())
    }

    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> Result<()> {
        self.exec(|_| {
            vec![
                Op::Putfh(from_dir.0.clone()),
                Op::Savefh,
                Op::Putfh(to_dir.0.clone()),
                Op::Rename {
                    from: from_name.to_vec(),
                    to: to_name.to_vec(),
                },
            ]
        })?;
        Ok(())
    }

    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat> {
        let res =
            self.exec(|_| vec![Op::Putfh(fh.0.clone()), Op::Getattr(FSSTAT_ATTRS.to_vec())])?;
        Ok(attr_at(&res, 1)?.to_fsstat())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.disconnect_inner();
        Ok(())
    }
}

/// True when no attribute would be set.
fn attrs_empty(a: &SetAttr) -> bool {
    a.mode.is_none()
        && a.uid.is_none()
        && a.gid.is_none()
        && a.owner.is_none()
        && a.group.is_none()
        && a.size.is_none()
        && a.atime.is_none()
        && a.mtime.is_none()
}

/// Channel attributes we request for the fore channel of a session.
pub(super) fn fore_channel_request() -> ChannelAttrs {
    ChannelAttrs {
        headerpadsize: 0,
        maxrequestsize: CHAN_REQUEST,
        maxresponsesize: CHAN_REQUEST,
        maxresponsesize_cached: 8192,
        maxoperations: 32,
        maxrequests: MAX_SLOTS,
    }
}

pub(super) fn back_channel_request() -> ChannelAttrs {
    ChannelAttrs {
        headerpadsize: 0,
        maxrequestsize: 4096,
        maxresponsesize: 4096,
        maxresponsesize_cached: 0,
        maxoperations: 2,
        maxrequests: 1,
    }
}

/// Compile-time check: the backend can move between threads (see
/// [`crate::fs::Connected::fs`]).
const _: fn() = || {
    fn is_send<T: Send>() {}
    is_send::<Nfs4Backend>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs4::ops::{
        OP_BIND_CONN_TO_SESSION, OP_CREATE_SESSION, OP_EXCHANGE_ID, OP_PUTFH, OP_PUTROOTFH,
        OP_READ, OP_RENEW,
    };
    use crate::rpc::PortMode;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    const OP_SEQUENCE: u32 = 53;
    const OP_RECLAIM_COMPLETE: u32 = 58;
    const OP_SETCLIENTID: u32 = 35;
    const OP_SETCLIENTID_CONFIRM: u32 = 36;

    fn w(ws: &[u32]) -> Vec<u8> {
        ws.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    /// COMPOUND4res body: status, empty tag, then (opcode, status, result body) per op.
    fn compound(status: u32, ops: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut v = w(&[status, 0, ops.len() as u32]);
        for (op, st, body) in ops {
            v.extend(w(&[*op, *st]));
            v.extend_from_slice(body);
        }
        v
    }

    fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).ok()?;
            let n = u32::from_be_bytes(hdr);
            let mut frag = vec![0u8; (n & 0x7fff_ffff) as usize];
            s.read_exact(&mut frag).ok()?;
            out.extend_from_slice(&frag);
            if n & 0x8000_0000 != 0 {
                return Some(out);
            }
        }
    }

    /// Fake NFSv4 server: answers each call with the next scripted COMPOUND
    /// reply body, then closes the connection. Returns the address and the
    /// number of calls received so far.
    fn fake_server(replies: Vec<Vec<u8>>) -> (SocketAddr, Arc<Mutex<usize>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(0usize));
        let seen = calls.clone();
        std::thread::spawn(move || {
            let Ok((mut s, _)) = l.accept() else { return };
            for body in replies {
                let Some(call) = read_record(&mut s) else {
                    return;
                };
                *seen.lock().unwrap() += 1;
                let mut msg = call[0..4].to_vec(); // xid
                msg.extend(w(&[1, 0, 0, 0, 0])); // REPLY, ACCEPTED, AUTH_NONE verf, SUCCESS
                msg.extend(body);
                let mut rec = (0x8000_0000u32 | msg.len() as u32).to_be_bytes().to_vec();
                rec.extend(msg);
                if s.write_all(&rec).is_err() {
                    return;
                }
            }
            // Count (but do not answer) any further call.
            if read_record(&mut s).is_some() {
                *seen.lock().unwrap() += 1;
            }
        });
        (addr, calls)
    }

    fn backend(addr: SocketAddr, minor: u32) -> Nfs4Backend {
        let opts = RpcOptions {
            port_mode: PortMode::Unprivileged,
            timeout: Duration::from_secs(5),
            ..RpcOptions::default()
        };
        let rpc = RpcClient::connect(addr, PROGRAM, VERSION, &opts).unwrap();
        let mut be = Nfs4Backend::new(addr, opts, rpc);
        be.minor = minor;
        // No teardown traffic on drop.
        be.disconnected = true;
        be
    }

    fn sid(n: u8) -> StateId {
        StateId {
            seqid: 1,
            other: [n; 12],
        }
    }

    fn stateid_bytes(s: StateId) -> Vec<u8> {
        let mut v = w(&[s.seqid]);
        v.extend_from_slice(&s.other);
        v
    }

    fn chan_bytes() -> Vec<u8> {
        w(&[0, 65536, 65536, 0, 8, 4, 0])
    }

    fn create_session_ok(id: [u8; 16], seq: u32) -> Vec<u8> {
        let mut body = id.to_vec();
        body.extend(w(&[seq, 0]));
        body.extend(chan_bytes());
        body.extend(chan_bytes());
        compound(code::OK, &[(OP_CREATE_SESSION, code::OK, body)])
    }

    fn sequence_ok(id: [u8; 16]) -> (u32, u32, Vec<u8>) {
        let mut body = id.to_vec();
        body.extend(w(&[1, 0, 3, 3, 0]));
        (OP_SEQUENCE, code::OK, body)
    }

    #[test]
    fn slot_seqids_advance_and_wrap_through_zero() {
        assert_eq!(next_seqid(1), 2);
        assert_eq!(next_seqid(u32::MAX), 0);
        assert_eq!(next_seqid(0), 1);
    }

    #[test]
    fn seqid_not_advanced_for_rfc7530_errors() {
        for c in [
            code::STALE_CLIENTID,
            code::STALE_STATEID,
            code::BAD_STATEID,
            code::BAD_SEQID,
            code::BADXDR,
            code::RESOURCE,
            code::NOFILEHANDLE,
            code::MOVED,
        ] {
            assert!(!seqid_advances(c), "{c}");
        }
        for c in [code::OK, code::OLD_STATEID, code::EXPIRED, 2, 13] {
            assert!(seqid_advances(c), "{c}");
        }
    }

    #[test]
    fn grace_wait_follows_lease() {
        assert_eq!(
            grace_wait(Duration::from_secs(90)),
            Duration::from_secs(180)
        );
        assert_eq!(grace_wait(Duration::from_secs(5)), GRACE_WAIT_MIN);
        assert_eq!(grace_wait(Duration::from_secs(3600)), GRACE_WAIT_MAX);
    }

    #[test]
    fn only_stateful_ops_renew_a_40_lease() {
        assert!(!renews_lease_40(&[Op::Putrootfh, Op::Getattr(vec![1])]));
        assert!(!renews_lease_40(&[
            Op::Putfh(vec![1]),
            Op::Lookup(b"a".to_vec())
        ]));
        let read = |stateid| Op::Read {
            stateid,
            offset: 0,
            count: 1,
        };
        assert!(!renews_lease_40(&[read(ANON_STATEID)]));
        assert!(!renews_lease_40(&[read(
            super::super::types::BYPASS_STATEID
        )]));
        assert!(renews_lease_40(&[read(sid(7))]));
        assert!(renews_lease_40(&[Op::Renew(1)]));
    }

    #[test]
    fn send_bumps_open_seqid_only_when_server_did() {
        let close = |st: u32| {
            let body = if st == code::OK {
                stateid_bytes(sid(2))
            } else {
                Vec::new()
            };
            compound(st, &[(OP_CLOSE, st, body)])
        };
        let (addr, _) = fake_server(vec![
            close(code::BAD_SEQID),
            close(code::STALE_STATEID),
            close(code::OLD_STATEID),
            close(code::OK),
        ]);
        let mut be = backend(addr, 0);
        be.open_seqid = 5;
        let mut seen = Vec::new();
        for _ in 0..4 {
            let op = Op::Close {
                seqid: be.open_seqid,
                stateid: sid(1),
            };
            be.send(vec![op], false).unwrap();
            seen.push(be.open_seqid);
        }
        assert_eq!(seen, [5, 5, 6, 7]);
    }

    #[test]
    fn bad_seqid_switches_to_a_new_open_owner_and_retries() {
        let mut open_ok = stateid_bytes(sid(3));
        open_ok.extend(w(&[0, 0, 0, 0, 0])); // change_info4
        open_ok.extend(w(&[0, 0, 0])); // rflags, empty attrset, no delegation
        let (addr, calls) = fake_server(vec![
            compound(
                code::BAD_SEQID,
                &[
                    (OP_PUTFH, code::OK, Vec::new()),
                    (OP_OPEN, code::BAD_SEQID, Vec::new()),
                ],
            ),
            compound(
                code::OK,
                &[
                    (OP_PUTFH, code::OK, Vec::new()),
                    (OP_OPEN, code::OK, open_ok),
                ],
            ),
        ]);
        let mut be = backend(addr, 0);
        be.clientid = 9;
        be.open_seqid = 7;
        be.opens
            .insert(FileHandle(vec![1]), sid(1), OPEN4_SHARE_ACCESS_BOTH);
        let res = be.exec(|s| {
            vec![
                Op::Putfh(vec![2]),
                Op::Open(super::super::state40::open_args(
                    s,
                    OPEN4_SHARE_ACCESS_BOTH,
                    OpenHow::NoCreate,
                    Claim::Fh,
                )),
            ]
        });
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(*calls.lock().unwrap(), 2);
        assert_ne!(be.open_owner, super::super::state40::OPEN_OWNER);
        assert_eq!(be.open_seqid, 1);
        assert!(be.opens.get(&FileHandle(vec![1]), false).is_none());
        assert!(
            be.leaked_opens,
            "the old owner's open is remembered as leaked"
        );
    }

    #[test]
    fn close_after_bad_seqid_is_not_rebuilt_for_the_new_owner() {
        let (addr, calls) = fake_server(vec![compound(
            code::BAD_SEQID,
            &[
                (OP_PUTFH, code::OK, Vec::new()),
                (OP_CLOSE, code::BAD_SEQID, Vec::new()),
            ],
        )]);
        let mut be = backend(addr, 0);
        be.clientid = 9;
        be.open_seqid = 7;
        let res = be.exec(|s| {
            vec![
                Op::Putfh(vec![1]),
                Op::Close {
                    seqid: s.open_seqid,
                    stateid: sid(1),
                },
            ]
        });
        assert!(res.is_err(), "{res:?}");
        assert_eq!(*calls.lock().unwrap(), 1, "CLOSE was not resent");
        assert_ne!(be.open_owner, super::super::state40::OPEN_OWNER);
    }

    #[test]
    fn establish_40_retries_delay() {
        let mut sc = w(&[0, 0x42]);
        sc.extend_from_slice(&[7; 8]);
        let (addr, calls) = fake_server(vec![
            compound(code::DELAY, &[(OP_SETCLIENTID, code::DELAY, Vec::new())]),
            compound(code::OK, &[(OP_SETCLIENTID, code::OK, sc)]),
            compound(
                code::GRACE,
                &[(OP_SETCLIENTID_CONFIRM, code::GRACE, Vec::new())],
            ),
            compound(code::OK, &[(OP_SETCLIENTID_CONFIRM, code::OK, Vec::new())]),
        ]);
        let mut be = backend(addr, 0);
        be.establish_40().unwrap();
        assert_eq!(be.clientid, 0x42);
        assert_eq!(*calls.lock().unwrap(), 4);
    }

    #[test]
    fn establish_41_retries_delay() {
        // clientid, sequence 5, flags, SP4_NONE, minor id, empty major id / scope / impl list.
        let xid = w(&[0, 0x77, 5, 0, 0, 0, 0, 0, 0, 0]);
        let sess = [0xab; 16];
        let (addr, calls) = fake_server(vec![
            compound(code::DELAY, &[(OP_EXCHANGE_ID, code::DELAY, Vec::new())]),
            compound(code::OK, &[(OP_EXCHANGE_ID, code::OK, xid)]),
            compound(code::DELAY, &[(OP_CREATE_SESSION, code::DELAY, Vec::new())]),
            create_session_ok(sess, 5),
            compound(
                code::OK,
                &[
                    sequence_ok(sess),
                    (OP_RECLAIM_COMPLETE, code::OK, Vec::new()),
                ],
            ),
        ]);
        let mut be = backend(addr, 1);
        be.establish_41().unwrap();
        assert_eq!(be.clientid, 0x77);
        assert_eq!(be.create_seq, 6);
        let s = be.session.as_ref().unwrap();
        assert_eq!(s.id, sess);
        assert_eq!(s.slot_seq, vec![2, 1, 1, 1]);
        assert_eq!(*calls.lock().unwrap(), 5);
    }

    #[test]
    fn bad_session_recreates_session_on_same_clientid() {
        let old = [1; 16];
        let new = [2; 16];
        let (addr, calls) = fake_server(vec![
            compound(
                code::BADSESSION,
                &[(OP_SEQUENCE, code::BADSESSION, Vec::new())],
            ),
            create_session_ok(new, 3),
            compound(
                code::OK,
                &[sequence_ok(new), (OP_PUTROOTFH, code::OK, Vec::new())],
            ),
        ]);
        let mut be = backend(addr, 1);
        be.clientid = 0x55;
        be.create_seq = 3;
        be.session = Some(Session {
            slot_seq: vec![9],
            ..Session::new(old, 1, 4096, 4096)
        });
        be.opens
            .insert(FileHandle(vec![1]), sid(1), OPEN4_SHARE_ACCESS_BOTH);
        be.exec(|_| vec![Op::Putrootfh]).unwrap();
        assert_eq!(*calls.lock().unwrap(), 3);
        assert_eq!(be.clientid, 0x55);
        assert_eq!(be.create_seq, 4);
        assert_eq!(be.session.as_ref().unwrap().id, new);
        // The open survived: no full EXCHANGE_ID recovery happened.
        assert!(be.opens.get(&FileHandle(vec![1]), true).is_some());
    }

    #[test]
    fn failed_open_confirm_closes_the_open() {
        let (addr, calls) = fake_server(vec![
            compound(
                code::BAD_STATEID,
                &[
                    (OP_PUTFH, code::OK, Vec::new()),
                    (OP_OPEN_CONFIRM, code::BAD_STATEID, Vec::new()),
                ],
            ),
            compound(
                code::OK,
                &[
                    (OP_PUTFH, code::OK, Vec::new()),
                    (OP_CLOSE, code::OK, stateid_bytes(sid(1))),
                ],
            ),
        ]);
        let mut be = backend(addr, 0);
        be.clientid = 9;
        let fh = FileHandle(vec![4]);
        let r = be.finish_open(
            &fh,
            sid(1),
            super::super::types::OPEN4_RESULT_CONFIRM,
            None,
            OPEN4_SHARE_ACCESS_BOTH,
        );
        assert!(r.is_err());
        assert_eq!(
            *calls.lock().unwrap(),
            2,
            "CLOSE sent after failed OPEN_CONFIRM"
        );
        assert!(be.opens.get(&fh, false).is_none());
    }

    fn fast_retry(budget: Duration) -> crate::rpc::RetryPolicy {
        crate::rpc::RetryPolicy {
            budget,
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(100),
            ..crate::rpc::RetryPolicy::default()
        }
    }

    fn with_retry(mut be: Nfs4Backend, policy: crate::rpc::RetryPolicy) -> Nfs4Backend {
        be.opts.retry = policy.clone();
        be.rpc.set_retry_policy(policy);
        be
    }

    #[test]
    fn delay_is_retried_until_the_server_answers() {
        let delay = || compound(code::DELAY, &[(OP_PUTROOTFH, code::DELAY, Vec::new())]);
        let (addr, calls) = fake_server(vec![
            delay(),
            delay(),
            delay(),
            compound(code::OK, &[(OP_PUTROOTFH, code::OK, Vec::new())]),
        ]);
        let retries = Arc::new(Mutex::new(0u32));
        let seen = retries.clone();
        let mut policy = fast_retry(Duration::from_secs(10));
        policy.on_retry = Some(Arc::new(move |e: &crate::rpc::RetryEvent<'_>| {
            if let crate::rpc::RetryEvent::Retrying { error, .. } = e {
                assert!(matches!(error, Error::Nfs(crate::fs::Status::Jukebox)));
                *seen.lock().unwrap() += 1;
            }
        }));
        let mut be = with_retry(backend(addr, 0), policy);
        be.exec(|_| vec![Op::Putrootfh]).unwrap();
        assert_eq!(*calls.lock().unwrap(), 4);
        assert_eq!(*retries.lock().unwrap(), 3);
    }

    #[test]
    fn endless_delay_gives_up_when_the_budget_runs_out() {
        let replies = (0..200)
            .map(|_| compound(code::DELAY, &[(OP_PUTROOTFH, code::DELAY, Vec::new())]))
            .collect();
        let (addr, _) = fake_server(replies);
        let mut be = with_retry(backend(addr, 0), fast_retry(Duration::from_millis(300)));
        let started = Instant::now();
        match be.exec(|_| vec![Op::Putrootfh]) {
            Err(Error::GaveUp { last, attempts, .. }) => {
                assert!(matches!(*last, Error::Nfs(crate::fs::Status::Jukebox)));
                assert!(attempts >= 2);
            }
            other => panic!("expected GaveUp, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn zero_budget_returns_delay_at_once() {
        let (addr, calls) = fake_server(vec![compound(
            code::DELAY,
            &[(OP_PUTROOTFH, code::DELAY, Vec::new())],
        )]);
        let mut be = with_retry(backend(addr, 0), crate::rpc::RetryPolicy::none());
        let r = be.exec(|_| vec![Op::Putrootfh]);
        assert!(
            matches!(r, Err(Error::Nfs(crate::fs::Status::Jukebox))),
            "{r:?}"
        );
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    /// Opcode of the first operation in a COMPOUND call message.
    fn first_opcode(call: &[u8]) -> u32 {
        let at = |o: usize| u32::from_be_bytes(call[o..o + 4].try_into().unwrap());
        let mut off = 24;
        for _ in 0..2 {
            off += 8 + (at(off + 4) as usize).div_ceil(4) * 4; // cred, verf
        }
        off += 4 + (at(off) as usize).div_ceil(4) * 4; // tag
        at(off + 8) // after minorversion and the op count
    }

    /// Fake server driven by `handle(first opcode)`: `Some(body)` answers,
    /// `None` drops the connection and refuses connections for `outage`.
    /// Returns the address and the first opcode of every call received.
    fn outage_server(
        outage: Duration,
        mut handle: impl FnMut(u32) -> Option<Vec<u8>> + Send + 'static,
    ) -> (SocketAddr, Arc<Mutex<Vec<u32>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        std::thread::spawn(move || {
            let mut listener = Some(l);
            loop {
                let l = match &listener {
                    Some(l) => l,
                    None => match TcpListener::bind(addr) {
                        Ok(l) => listener.insert(l),
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(20));
                            continue;
                        }
                    },
                };
                let Ok((mut s, _)) = l.accept() else { return };
                let mut dropped = false;
                while let Some(call) = read_record(&mut s) {
                    let op = first_opcode(&call);
                    seen.lock().unwrap().push(op);
                    let Some(body) = handle(op) else {
                        dropped = true;
                        break;
                    };
                    let mut msg = call[0..4].to_vec();
                    msg.extend(w(&[1, 0, 0, 0, 0]));
                    msg.extend(body);
                    let mut rec = (0x8000_0000u32 | msg.len() as u32).to_be_bytes().to_vec();
                    rec.extend(msg);
                    if s.write_all(&rec).is_err() {
                        break;
                    }
                }
                drop(s);
                if dropped {
                    listener = None;
                    std::thread::sleep(outage);
                }
            }
        });
        (addr, log)
    }

    /// Replies for a v4.0 recovery after a server reboot: RENEW of the old
    /// client ID fails with STALE_CLIENTID, then SETCLIENTID / _CONFIRM.
    fn setclientid_reply(op: u32) -> Option<Vec<u8>> {
        match op {
            OP_RENEW => Some(compound(
                code::STALE_CLIENTID,
                &[(OP_RENEW, code::STALE_CLIENTID, Vec::new())],
            )),
            OP_SETCLIENTID => {
                let mut sc = w(&[0, 0x42]);
                sc.extend_from_slice(&[7; 8]);
                Some(compound(code::OK, &[(OP_SETCLIENTID, code::OK, sc)]))
            }
            OP_SETCLIENTID_CONFIRM => Some(compound(
                code::OK,
                &[(OP_SETCLIENTID_CONFIRM, code::OK, Vec::new())],
            )),
            _ => None,
        }
    }

    #[test]
    fn reconnect_is_retried_while_the_server_is_down() {
        let mut first = true;
        let (addr, log) = outage_server(Duration::from_millis(700), move |op| {
            if op == OP_PUTROOTFH {
                if std::mem::take(&mut first) {
                    return None;
                }
                return Some(compound(code::OK, &[(OP_PUTROOTFH, code::OK, Vec::new())]));
            }
            setclientid_reply(op)
        });
        let mut be = with_retry(backend(addr, 0), fast_retry(Duration::from_secs(10)));
        be.clientid = 9;
        let started = Instant::now();
        be.exec(|_| vec![Op::Putrootfh])
            .expect("recovers once the server is back");
        assert!(started.elapsed() >= Duration::from_millis(500));
        assert_eq!(be.clientid, 0x42, "client state re-established");
        assert_eq!(
            *log.lock().unwrap(),
            [
                OP_PUTROOTFH,
                OP_RENEW,
                OP_SETCLIENTID,
                OP_SETCLIENTID_CONFIRM,
                OP_PUTROOTFH
            ]
        );
    }

    #[test]
    fn non_idempotent_compound_is_resent_at_most_once() {
        const OP_REMOVE: u32 = 28;
        let (addr, log) = outage_server(Duration::from_millis(100), setclientid_reply);
        let mut be = with_retry(backend(addr, 0), fast_retry(Duration::from_secs(10)));
        be.clientid = 9;
        let started = Instant::now();
        let r = be.exec(|_| vec![Op::Remove(b"x".to_vec())]);
        assert!(r.is_err(), "{r:?}");
        assert!(!matches!(r, Err(Error::GaveUp { .. })), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        let removes = log
            .lock()
            .unwrap()
            .iter()
            .filter(|&&o| o == OP_REMOVE)
            .count();
        assert_eq!(removes, 2, "original plus one resend");
    }

    #[test]
    fn compound_classification() {
        assert!(idempotent(&[
            Op::Putfh(vec![1]),
            Op::Lookup(b"a".to_vec()),
            Op::Getfh
        ]));
        assert!(idempotent(&[
            Op::Putfh(vec![1]),
            Op::Read {
                stateid: ANON_STATEID,
                offset: 0,
                count: 1
            }
        ]));
        assert!(!idempotent(&[
            Op::Putfh(vec![1]),
            Op::Remove(b"a".to_vec())
        ]));
        assert!(!idempotent(&[
            Op::Putfh(vec![1]),
            Op::Lookup(b"a".to_vec()),
            Op::Close {
                seqid: 1,
                stateid: ANON_STATEID
            }
        ]));
        assert_eq!(
            compound_name(&[Op::Putfh(vec![1]), Op::Getattr(vec![1])]),
            "GETATTR"
        );
        assert_eq!(compound_name(&[Op::Putrootfh]), "COMPOUND");
    }

    #[test]
    fn no_free_slot_fails_without_reconnecting() {
        let (addr, calls) = fake_server(Vec::new());
        let mut be = backend(addr, 1);
        be.session = Some(Session {
            busy: vec![true],
            ..Session::new([1; 16], 1, 4096, 4096)
        });
        match be.exec(|_| vec![Op::Putrootfh]) {
            Err(Error::Protocol(m)) => assert!(m.contains("slot"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    /// Byte `i` of the fake file served by [`SessionServer`].
    fn file_byte(i: u64) -> u8 {
        (i % 251) as u8
    }

    /// What the [`SessionServer`] saw in one call.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Seen {
        /// SEQUENCE (slot, seqid) followed by the opcode of the next
        /// operation (0 when SEQUENCE was alone).
        Seq { slot: u32, seqid: u32, next: u32 },
        /// A COMPOUND not starting with SEQUENCE: its first opcode.
        Other(u32),
        /// A SEQUENCE that reused the last seqid of its slot (a replay).
        Replay { slot: u32, seqid: u32 },
    }

    /// Knobs for [`session_server`].
    #[derive(Default)]
    struct SessionScript {
        /// Drop the connection, after executing it, on the READ of this
        /// offset (the first time only).
        drop_after_read_at: Option<u64>,
        /// Answer SEQUENCE on a new connection with
        /// NFS4ERR_CONN_NOT_BOUND_TO_SESSION until BIND_CONN_TO_SESSION.
        require_bind: bool,
        /// The session is gone once the first connection drops: SEQUENCE
        /// gets NFS4ERR_BADSESSION until CREATE_SESSION.
        forget_session_on_drop: bool,
    }

    /// Fake NFSv4.1 server with a real slot table (seqid checks like
    /// knfsd: next seqid executes, the same seqid is an uncached replay,
    /// anything else is misordered). Serves PUTFH + READ of a 1 MiB file,
    /// SEQUENCE-only probes, BIND_CONN_TO_SESSION and CREATE_SESSION; any
    /// other COMPOUND drops the connection. Returns the address and a log.
    fn session_server(
        session: [u8; 16],
        slot_seq: Vec<u32>,
        script: SessionScript,
    ) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        std::thread::spawn(move || {
            let mut session = session;
            // Last executed seqid per slot.
            let mut last: Vec<u32> = slot_seq.iter().map(|s| s.wrapping_sub(1)).collect();
            let mut dropped_once = false;
            let mut session_ok = true;
            let mut first_conn = true;
            loop {
                let Ok((mut s, _)) = l.accept() else { return };
                let mut bound = first_conn || !script.require_bind;
                first_conn = false;
                while let Some(call) = read_record(&mut s) {
                    let at = |o: usize| u32::from_be_bytes(call[o..o + 4].try_into().unwrap());
                    let mut off = 24;
                    for _ in 0..2 {
                        off += 8 + (at(off + 4) as usize).div_ceil(4) * 4;
                    }
                    off += 4 + (at(off) as usize).div_ceil(4) * 4; // tag; now at minorversion
                    let nops = at(off + 4);
                    let op = at(off + 8);
                    let reply = if op == OP_SEQUENCE {
                        let id: [u8; 16] = call[off + 12..off + 28].try_into().unwrap();
                        let seqid = at(off + 28);
                        let slot = at(off + 32);
                        let next_off = off + 44;
                        let next = if nops > 1 { at(next_off) } else { 0 };
                        let seq_err = |st: u32| compound(st, &[(OP_SEQUENCE, st, Vec::new())]);
                        if !bound {
                            seen.lock().unwrap().push(Seen::Seq { slot, seqid, next });
                            Some(seq_err(code::CONN_NOT_BOUND_TO_SESSION))
                        } else if !session_ok || id != session {
                            seen.lock().unwrap().push(Seen::Seq { slot, seqid, next });
                            Some(seq_err(code::BADSESSION))
                        } else if seqid == last[slot as usize] {
                            seen.lock().unwrap().push(Seen::Replay { slot, seqid });
                            Some(seq_err(code::RETRY_UNCACHED_REP))
                        } else if seqid != last[slot as usize].wrapping_add(1) {
                            seen.lock().unwrap().push(Seen::Seq { slot, seqid, next });
                            Some(seq_err(code::SEQ_MISORDERED))
                        } else {
                            seen.lock().unwrap().push(Seen::Seq { slot, seqid, next });
                            last[slot as usize] = seqid;
                            if nops == 1 {
                                Some(compound(code::OK, &[sequence_ok(session)]))
                            } else if next == OP_PUTFH && nops == 3 {
                                let fhlen = at(next_off + 4) as usize;
                                let r = next_off + 8 + fhlen.div_ceil(4) * 4;
                                assert_eq!(at(r), OP_READ);
                                let offset = u64::from(at(r + 20)) << 32 | u64::from(at(r + 24));
                                let count = at(r + 28);
                                if script.drop_after_read_at == Some(offset) && !dropped_once {
                                    dropped_once = true;
                                    if script.forget_session_on_drop {
                                        session_ok = false;
                                    }
                                    None
                                } else {
                                    let end = (offset + u64::from(count)).min(1 << 20);
                                    let data: Vec<u8> = (offset..end).map(file_byte).collect();
                                    let mut body =
                                        w(&[u32::from(end == 1 << 20), data.len() as u32]);
                                    body.extend_from_slice(&data);
                                    body.resize(body.len().div_ceil(4) * 4, 0);
                                    Some(compound(
                                        code::OK,
                                        &[
                                            sequence_ok(session),
                                            (OP_PUTFH, code::OK, Vec::new()),
                                            (OP_READ, code::OK, body),
                                        ],
                                    ))
                                }
                            } else {
                                None
                            }
                        }
                    } else {
                        seen.lock().unwrap().push(Seen::Other(op));
                        match op {
                            OP_BIND_CONN_TO_SESSION => {
                                bound = true;
                                let mut body = session.to_vec();
                                body.extend(w(&[1, 0]));
                                Some(compound(
                                    code::OK,
                                    &[(OP_BIND_CONN_TO_SESSION, code::OK, body)],
                                ))
                            }
                            OP_CREATE_SESSION => {
                                session = [0x5e; 16];
                                session_ok = true;
                                last = vec![0; 16];
                                Some(create_session_ok(session, 0))
                            }
                            _ => None,
                        }
                    };
                    let Some(body) = reply else { break };
                    let mut msg = call[0..4].to_vec();
                    msg.extend(w(&[1, 0, 0, 0, 0]));
                    msg.extend(body);
                    let mut rec = (0x8000_0000u32 | msg.len() as u32).to_be_bytes().to_vec();
                    rec.extend(msg);
                    if s.write_all(&rec).is_err() {
                        break;
                    }
                }
            }
        });
        (addr, log)
    }

    /// A 4.1 backend with an established session of `slots` slots and an
    /// open of file handle [1] cached.
    fn session_backend(addr: SocketAddr, id: [u8; 16], slot_seq: Vec<u32>) -> Nfs4Backend {
        let mut be = with_retry(backend(addr, 1), fast_retry(Duration::from_secs(10)));
        be.clientid = 0x55;
        be.create_seq = 3;
        let n = slot_seq.len();
        be.session = Some(Session {
            slot_seq,
            ..Session::new(id, n, CHAN_REQUEST, CHAN_REQUEST)
        });
        be.max_read = 4096;
        be.opens
            .insert(FileHandle(vec![1]), sid(1), OPEN4_SHARE_ACCESS_BOTH);
        be
    }

    fn no_client_setup(log: &[Seen]) {
        for s in log {
            assert!(
                !matches!(
                    s,
                    Seen::Other(OP_EXCHANGE_ID) | Seen::Other(OP_CREATE_SESSION)
                ),
                "client state was re-established: {log:?}"
            );
            assert!(
                !matches!(s, Seen::Replay { .. }),
                "a lost slot's seqid was reused: {log:?}"
            );
        }
    }

    #[test]
    fn session_survives_a_dropped_connection_and_keeps_the_open() {
        let id = [0x51; 16];
        let (addr, log) = session_server(
            id,
            vec![5, 1],
            SessionScript {
                drop_after_read_at: Some(0),
                ..SessionScript::default()
            },
        );
        let mut be = session_backend(addr, id, vec![5, 1]);
        let (data, _) = be.read(&FileHandle(vec![1]), 0, 100).unwrap();
        assert_eq!(data, (0..100).map(file_byte).collect::<Vec<_>>());
        let log = log.lock().unwrap().clone();
        no_client_setup(&log);
        assert_eq!(
            log,
            [
                Seen::Seq {
                    slot: 0,
                    seqid: 5,
                    next: OP_PUTFH
                },
                // Slot 0's READ was executed but its reply lost: probing
                // with the next seqid succeeds, so the slot moves on.
                Seen::Seq {
                    slot: 0,
                    seqid: 6,
                    next: 0
                },
                Seen::Seq {
                    slot: 0,
                    seqid: 7,
                    next: OP_PUTFH
                },
            ]
        );
        let s = be.session.as_ref().unwrap();
        assert_eq!(s.id, id, "same session");
        assert_eq!(s.slot_seq, [8, 1]);
        assert_eq!(be.clientid, 0x55);
        assert_eq!(be.opens.get(&FileHandle(vec![1]), false), Some(sid(1)));
    }

    #[test]
    fn lost_unexecuted_request_is_resent_on_the_same_seqid() {
        // An earlier request on slot 0 (seqid 9) was lost before the server
        // saw it, so the slot is uncertain and the server is still at 8.
        let id = [0x52; 16];
        let (addr, log) = session_server(id, vec![9], SessionScript::default());
        let mut be = session_backend(addr, id, vec![9]);
        be.session.as_mut().unwrap().mark_uncertain(0);
        let (data, _) = be.read(&FileHandle(vec![1]), 4096, 10).unwrap();
        assert_eq!(data, (4096..4106).map(file_byte).collect::<Vec<_>>());
        let log = log.lock().unwrap().clone();
        no_client_setup(&log);
        assert_eq!(
            log,
            [
                Seen::Seq {
                    slot: 0,
                    seqid: 10,
                    next: 0
                }, // misordered: 9 never ran
                Seen::Seq {
                    slot: 0,
                    seqid: 9,
                    next: 0
                },
                Seen::Seq {
                    slot: 0,
                    seqid: 10,
                    next: OP_PUTFH
                },
            ]
        );
    }

    #[test]
    fn new_connection_is_bound_to_the_session_when_the_server_asks() {
        let id = [0x53; 16];
        let (addr, log) = session_server(
            id,
            vec![1],
            SessionScript {
                drop_after_read_at: Some(0),
                require_bind: true,
                ..SessionScript::default()
            },
        );
        let mut be = session_backend(addr, id, vec![1]);
        be.read(&FileHandle(vec![1]), 0, 10).unwrap();
        let log = log.lock().unwrap().clone();
        no_client_setup(&log);
        assert!(
            log.contains(&Seen::Other(OP_BIND_CONN_TO_SESSION)),
            "{log:?}"
        );
        assert_eq!(be.session.as_ref().unwrap().id, id);
        assert_eq!(be.opens.get(&FileHandle(vec![1]), false), Some(sid(1)));
    }

    #[test]
    fn lost_session_is_recreated_on_the_same_client_id() {
        let id = [0x54; 16];
        let (addr, log) = session_server(
            id,
            vec![1, 1],
            SessionScript {
                drop_after_read_at: Some(0),
                forget_session_on_drop: true,
                ..SessionScript::default()
            },
        );
        let mut be = session_backend(addr, id, vec![1, 1]);
        let (data, _) = be.read(&FileHandle(vec![1]), 0, 10).unwrap();
        assert_eq!(data, (0..10).map(file_byte).collect::<Vec<_>>());
        let log = log.lock().unwrap().clone();
        assert!(log.contains(&Seen::Other(OP_CREATE_SESSION)), "{log:?}");
        assert!(!log.contains(&Seen::Other(OP_EXCHANGE_ID)), "{log:?}");
        assert_eq!(be.session.as_ref().unwrap().id, [0x5e; 16]);
        assert_eq!(be.clientid, 0x55);
        assert_eq!(be.opens.get(&FileHandle(vec![1]), false), Some(sid(1)));
    }

    #[test]
    fn pipelined_read_survives_a_lost_reply_mid_window() {
        let id = [0x55; 16];
        let (addr, log) = session_server(
            id,
            vec![1; 4],
            SessionScript {
                drop_after_read_at: Some(3 * 4096),
                ..SessionScript::default()
            },
        );
        let mut be = session_backend(addr, id, vec![1; 4]);
        let len = 64 * 1024u64;
        let mut got = Vec::new();
        let n = be
            .read_stream(&FileHandle(vec![1]), 0, Some(len), &mut |c: &[u8]| {
                got.extend_from_slice(c);
                Ok(())
            })
            .unwrap();
        assert_eq!(n, len);
        assert!(
            got == (0..len).map(file_byte).collect::<Vec<_>>(),
            "wrong data after recovery"
        );
        let log = log.lock().unwrap().clone();
        no_client_setup(&log);
        assert!(
            log.iter().any(|s| matches!(s, Seen::Seq { next: 0, .. })),
            "the lost slots were probed: {log:?}"
        );
        assert_eq!(be.session.as_ref().unwrap().id, id);
        assert!(
            be.session.as_ref().unwrap().uncertain.iter().all(|u| !u),
            "every slot was resolved"
        );
    }

    #[test]
    fn v40_reconnect_renews_and_keeps_the_client_id() {
        let mut first = true;
        let (addr, log) = outage_server(Duration::from_millis(50), move |op| match op {
            OP_PUTROOTFH if std::mem::take(&mut first) => None,
            OP_PUTROOTFH => Some(compound(code::OK, &[(OP_PUTROOTFH, code::OK, Vec::new())])),
            OP_RENEW => Some(compound(code::OK, &[(OP_RENEW, code::OK, Vec::new())])),
            _ => None,
        });
        let mut be = with_retry(backend(addr, 0), fast_retry(Duration::from_secs(10)));
        be.clientid = 9;
        be.open_seqid = 4;
        be.opens
            .insert(FileHandle(vec![1]), sid(1), OPEN4_SHARE_ACCESS_BOTH);
        be.exec(|_| vec![Op::Putrootfh]).unwrap();
        assert_eq!(*log.lock().unwrap(), [OP_PUTROOTFH, OP_RENEW, OP_PUTROOTFH]);
        assert_eq!(be.clientid, 9);
        assert_eq!(be.open_seqid, 4);
        assert_eq!(be.opens.get(&FileHandle(vec![1]), false), Some(sid(1)));
    }

    #[test]
    fn recovery_that_gets_the_same_client_id_back_keeps_opens() {
        // EXCHANGE_ID with the backend's fixed verifier: the server still
        // knows the client and returns the same client ID.
        let xid = w(&[0, 0x55, 4, 0, 0, 0, 0, 0, 0, 0]);
        let sess = [0xcd; 16];
        let (addr, _) = fake_server(vec![
            compound(code::OK, &[(OP_EXCHANGE_ID, code::OK, xid)]),
            create_session_ok(sess, 4),
            compound(
                code::COMPLETE_ALREADY,
                &[
                    sequence_ok(sess),
                    (OP_RECLAIM_COMPLETE, code::COMPLETE_ALREADY, Vec::new()),
                ],
            ),
        ]);
        let mut be = backend(addr, 1);
        be.clientid = 0x55;
        let verifier = be.verifier;
        be.opens
            .insert(FileHandle(vec![1]), sid(1), OPEN4_SHARE_ACCESS_BOTH);
        be.recover().unwrap();
        assert_eq!(be.verifier, verifier);
        assert_eq!(be.opens.get(&FileHandle(vec![1]), false), Some(sid(1)));
    }

    #[test]
    fn recovery_with_a_new_client_id_drops_opens() {
        let xid = w(&[0, 0x66, 4, 0, 0, 0, 0, 0, 0, 0]);
        let sess = [0xce; 16];
        let (addr, _) = fake_server(vec![
            compound(code::OK, &[(OP_EXCHANGE_ID, code::OK, xid)]),
            create_session_ok(sess, 4),
            compound(
                code::OK,
                &[
                    sequence_ok(sess),
                    (OP_RECLAIM_COMPLETE, code::OK, Vec::new()),
                ],
            ),
        ]);
        let mut be = backend(addr, 1);
        be.clientid = 0x55;
        be.opens
            .insert(FileHandle(vec![1]), sid(1), OPEN4_SHARE_ACCESS_BOTH);
        be.recover().unwrap();
        assert_eq!(be.clientid, 0x66);
        assert!(be.opens.get(&FileHandle(vec![1]), false).is_none());
    }

    #[test]
    fn setup_delay_wait_honors_a_zero_budget() {
        let (addr, calls) = fake_server(vec![
            compound(code::DELAY, &[(OP_EXCHANGE_ID, code::DELAY, Vec::new())]),
            compound(code::DELAY, &[(OP_EXCHANGE_ID, code::DELAY, Vec::new())]),
        ]);
        let mut be = with_retry(backend(addr, 1), crate::rpc::RetryPolicy::none());
        let r = be.establish_41();
        assert!(
            matches!(r, Err(Error::Nfs(crate::fs::Status::Jukebox))),
            "{r:?}"
        );
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}
