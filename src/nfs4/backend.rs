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
fn map_connect_err(e: Error) -> Error {
    match e {
        Error::Io(ref io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            Error::VersionUnsupported("nothing listening for NFS on the NFSv4 port".into())
        }
        other => other,
    }
}

/// Connect with the given minor version, or negotiate the highest supported
/// (2, then 1, then 0) when `minor` is None. Walks `path` from PUTROOTFH.
pub(crate) fn connect(
    host: IpAddr,
    path: &[u8],
    minor: Option<u32>,
    opts: &ConnectOptions,
) -> Result<Connected> {
    let addr = SocketAddr::new(host, opts.nfs_port.unwrap_or(DEFAULT_PORT));
    let rpc = RpcClient::connect(addr, PROGRAM, VERSION, &opts.rpc).map_err(map_connect_err)?;
    let mut be = Nfs4Backend::new(addr, opts.rpc.clone(), rpc);
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

/// Exponential backoff for the `n`th (1-based) NFS4ERR_DELAY retry:
/// 100 ms, doubling up to 1.6 s.
pub(super) fn backoff(n: u32) -> Duration {
    Duration::from_millis(50u64 << n.clamp(1, 5))
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
    /// Open a new TCP connection and re-establish client state.
    Reconnect,
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
                .busy
                .iter()
                .position(|b| !b)
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
        let res: CompoundRes = self.rpc.call(PROC_COMPOUND, &args)?;
        if renews && res.status == code::OK {
            self.last_activity = Instant::now();
        }
        let mut results = res.results;
        if let Some(free) = slot {
            let seq_ok = matches!(results.first(), Some(r) if r.status == code::OK);
            if !results.is_empty() {
                results.remove(0);
            }
            if let Some(s) = self.session.as_mut().filter(|_| seq_ok) {
                s.slot_seq[free] = next_seqid(s.slot_seq[free]);
                self.last_activity = Instant::now();
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
                .busy
                .iter()
                .position(|b| !b)
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
        let xid = self.rpc.send_call(PROC_COMPOUND, &args)?;
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
            Some(s) if self.minor >= 1 => s.busy.len().min(DEFAULT_WINDOW),
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
        // Session / client recoveries so far; the first one does not back off.
        let mut recoveries = 0u32;
        // A non-idempotent compound was already resent after a transport failure.
        let mut resent = false;
        let mut new_owner = false;
        loop {
            if fix != Fix::None {
                let r = match fix {
                    Fix::Reconnect => self.reconnect(),
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
                    Some(s) if s.busy.iter().all(|b| *b) => {
                        return Err(Error::Protocol("no free session slot".into()));
                    }
                    Some(_) => {}
                }
            }
            let ops = build(&*self);
            let idem = idempotent(&ops);
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
                code::STALE_CLIENTID
                | code::EXPIRED
                | code::BADSLOT
                | code::SEQ_MISORDERED
                | code::BAD_HIGH_SLOT => {
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
        let started = Instant::now();
        let mut tries = 0u32;
        loop {
            let res = self.send(build(&*self), sequenced)?;
            if !matches!(res.status, code::DELAY | code::GRACE)
                || started.elapsed() > grace_wait(self.lease)
            {
                return Ok(res);
            }
            tries += 1;
            std::thread::sleep(backoff(tries));
        }
    }

    /// Reopen the TCP connection and re-establish client state.
    fn reconnect(&mut self) -> Result<()> {
        self.rpc = RpcClient::connect(self.addr, PROGRAM, VERSION, &self.opts)?;
        self.recover()
    }

    /// Re-establish client ID / session after the server dropped our state.
    /// Open stateids from the old client are discarded.
    pub(super) fn recover(&mut self) -> Result<()> {
        self.session = None;
        self.opens.clear();
        self.open_seqid = 0;
        self.establish()
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
    pub(super) fn new_open_owner(&mut self) {
        self.opens.clear();
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
    /// forget it and retry once with the anonymous stateid.
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

/// Sequence id after `s` (never 0, which is reserved for "no request yet").
fn next_seqid(s: u32) -> u32 {
    match s.wrapping_add(1) {
        0 => 1,
        n => n,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs4::ops::{OP_CREATE_SESSION, OP_EXCHANGE_ID, OP_PUTFH, OP_PUTROOTFH};
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
    fn seqids_advance_and_skip_zero() {
        assert_eq!(next_seqid(1), 2);
        assert_eq!(next_seqid(u32::MAX), 1);
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
        let (addr, calls) = fake_server(vec![
            compound(
                code::BAD_SEQID,
                &[
                    (OP_PUTFH, code::OK, Vec::new()),
                    (OP_CLOSE, code::BAD_SEQID, Vec::new()),
                ],
            ),
            compound(
                code::OK,
                &[
                    (OP_PUTFH, code::OK, Vec::new()),
                    (OP_CLOSE, code::OK, stateid_bytes(sid(3))),
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
                Op::Putfh(vec![1]),
                Op::Close {
                    seqid: s.open_seqid,
                    stateid: sid(1),
                },
            ]
        });
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(*calls.lock().unwrap(), 2);
        assert_ne!(be.open_owner, super::super::state40::OPEN_OWNER);
        assert_eq!(be.open_seqid, 1);
        assert!(be.opens.get(&FileHandle(vec![1]), false).is_none());
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
            id: old,
            slot_seq: vec![9],
            busy: vec![false],
            max_req: 4096,
            max_resp: 4096,
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

    /// SETCLIENTID / SETCLIENTID_CONFIRM replies for a v4.0 recovery.
    fn setclientid_reply(op: u32) -> Option<Vec<u8>> {
        match op {
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
            id: [1; 16],
            slot_seq: vec![1],
            busy: vec![true],
            max_req: 4096,
            max_resp: 4096,
        });
        match be.exec(|_| vec![Op::Putrootfh]) {
            Err(Error::Protocol(m)) => assert!(m.contains("slot"), "{m}"),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(*calls.lock().unwrap(), 0);
    }
}
