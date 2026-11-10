//! NFSv4.x client: connection setup, COMPOUND execution with retry/recovery,
//! and the [`Filesystem`] implementation.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::fs::{
    Attr, ConnectOptions, Connected, CreateMode, DirEntry, FileHandle, FileType, Filesystem, FsStat,
    NfsVersion, SetAttr,
};
use crate::rpc::{RpcClient, RpcOptions};

use super::compound::{CompoundArgs, CompoundRes, PROC_COMPOUND};
use super::ops::{ChannelAttrs, Claim, CreateKind, Op, OpenHow, Res, ResOp, FILE_SYNC4, OP_CLOSE, OP_OPEN, OP_OPEN_CONFIRM};
use super::types::{
    attr, code, encode_setattr, Fattr, StateId, ANON_STATEID, BASIC_ATTRS, FSSTAT_ATTRS, OPEN4_SHARE_ACCESS_BOTH,
    READDIR_ATTRS,
};

pub const PROGRAM: u32 = 100003;
pub const VERSION: u32 = 4;
const DEFAULT_PORT: u16 = 2049;

/// Largest READ/WRITE payload we ever send (1 MiB).
pub(crate) const MAX_IO: u32 = 1024 * 1024;
/// Allowance for COMPOUND, SEQUENCE and reply headers when sizing transfers.
const CHAN_OVERHEAD: u32 = 1024;
/// Largest channel size we request in CREATE_SESSION.
pub(super) const CHAN_REQUEST: u32 = MAX_IO + 8192;
/// Callback program number we advertise; no callbacks are ever served.
pub(super) const CB_PROGRAM: u32 = 0x4000_0000;
/// How long to keep retrying NFS4ERR_GRACE.
const GRACE_WAIT: Duration = Duration::from_secs(30);
/// Lease used until the server reports lease_time.
const DEFAULT_LEASE: Duration = Duration::from_secs(90);
/// Cap on remembered (parent, name) pairs used to open files by name in NFSv4.0.
const NAME_CACHE_CAP: usize = 65_536;

/// Session state (NFSv4.1+). Only slot 0 is used; requests are sequential.
pub(crate) struct Session {
    pub id: [u8; 16],
    /// Sequence id to use for the next SEQUENCE on slot 0.
    pub seq: u32,
    pub max_req: u32,
    pub max_resp: u32,
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
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
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
pub(crate) fn connect(host: IpAddr, path: &[u8], minor: Option<u32>, opts: &ConnectOptions) -> Result<Connected> {
    let addr = SocketAddr::new(host, opts.nfs_port.unwrap_or(DEFAULT_PORT));
    let rpc = RpcClient::connect(addr, PROGRAM, VERSION, &opts.rpc).map_err(map_connect_err)?;
    let mut be = Nfs4Backend {
        addr,
        opts: opts.rpc.clone(),
        rpc,
        minor: 0,
        root: FileHandle::default(),
        clientid: 0,
        session: None,
        open_seqid: 0,
        opens: super::state40::OpenCache::default(),
        names: HashMap::new(),
        lease: DEFAULT_LEASE,
        last_activity: Instant::now(),
        max_read: MAX_IO,
        max_write: MAX_IO,
        readdir_max: 32 * 1024,
        owner_id: format!("nfsc {} {} {:x}", hostname(), std::process::id(), rand64()).into_bytes(),
        disconnected: false,
    };
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
            Err(Error::Nfs(crate::fs::Status::Other(_, c))) if c == code::MINOR_VERS_MISMATCH => continue,
            Err(e) => return Err(e),
        }
    }
    if !negotiated {
        return Err(Error::VersionUnsupported("server offers no NFSv4 minor version".into()));
    }
    be.walk(path)?;
    Ok(Connected { fs: Box::new(be), export: path.to_vec(), remainder: Vec::new() })
}

impl Nfs4Backend {
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
    /// owner seqid for each OPEN / OPEN_CONFIRM / CLOSE that was executed.
    pub(super) fn send(&mut self, ops: Vec<Op>, sequenced: bool) -> Result<CompoundRes> {
        let use_seq = sequenced && self.minor >= 1;
        let mut all = Vec::with_capacity(ops.len() + 1);
        if use_seq {
            let s = self
                .session
                .as_ref()
                .ok_or_else(|| Error::Protocol("NFSv4.1 operation without a session".into()))?;
            all.push(Op::Sequence { session: s.id, seqid: s.seq, slot: 0, highest: 0 });
        }
        all.extend(ops);
        let args = CompoundArgs { minor: self.minor, ops: all };
        let res: CompoundRes = self.rpc.call(PROC_COMPOUND, &args)?;
        self.last_activity = Instant::now();
        let mut results = res.results;
        if use_seq {
            let seq_ok = matches!(results.first(), Some(r) if r.status == code::OK);
            if !results.is_empty() {
                results.remove(0);
            }
            if seq_ok {
                if let Some(s) = self.session.as_mut() {
                    s.seq = s.seq.wrapping_add(1);
                }
            }
        }
        for r in &results {
            if matches!(r.opcode, OP_OPEN | OP_CLOSE | OP_OPEN_CONFIRM) {
                self.open_seqid = self.open_seqid.wrapping_add(1);
            }
        }
        Ok(CompoundRes { status: res.status, results })
    }

    /// Run a sequenced compound with retry and recovery:
    /// - NFS4ERR_DELAY and NFS4ERR_GRACE: back off and retry (GRACE for a bounded time).
    /// - Session / client / lease errors, or a broken connection: reconnect and
    ///   re-establish the client and session, then retry once.
    ///
    /// `build` is called on every attempt so it can read the current clientid
    /// and seqids.
    pub(super) fn exec<F>(&mut self, build: F) -> Result<Vec<ResOp>>
    where
        F: Fn(&Nfs4Backend) -> Vec<Op>,
    {
        self.maybe_renew();
        let started = Instant::now();
        let mut delays = 0u32;
        let mut recovered = false;
        loop {
            let ops = build(&*self);
            let res = match self.send(ops, true) {
                Ok(r) => r,
                Err(Error::Io(_) | Error::Timeout | Error::Protocol(_)) if !recovered => {
                    recovered = true;
                    self.reconnect()?;
                    continue;
                }
                Err(e) => return Err(e),
            };
            if res.status == code::OK {
                return Ok(res.results);
            }
            match res.status {
                code::DELAY => {
                    delays += 1;
                    if delays > 40 {
                        return Err(self.status_err(res.status));
                    }
                    std::thread::sleep(Duration::from_millis(50u64 << delays.min(5)));
                }
                code::GRACE => {
                    if started.elapsed() > GRACE_WAIT {
                        return Err(self.status_err(res.status));
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
                code::BADSESSION
                | code::DEADSESSION
                | code::STALE_CLIENTID
                | code::EXPIRED
                | code::BADSLOT
                | code::SEQ_MISORDERED
                | code::BAD_HIGH_SLOT
                    if !recovered =>
                {
                    recovered = true;
                    self.recover()?;
                }
                other => return Err(self.status_err(other)),
            }
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
        for comp in path.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".") {
            let dir = cur.clone();
            let is_parent = comp == b"..";
            let name = comp.to_vec();
            let res = self.exec(|_| {
                if is_parent {
                    vec![Op::Putfh(dir.0.clone()), Op::Lookupp, Op::Getfh]
                } else {
                    vec![Op::Putfh(dir.0.clone()), Op::Lookup(name.clone()), Op::Getfh]
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
                Op::Getattr(vec![attr::SUPPORTED_ATTRS, attr::LEASE_TIME, attr::MAXREAD, attr::MAXWRITE]),
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
        let srv_read = a.maxread.map(|v| v.min(u64::from(u32::MAX)) as u32).unwrap_or(MAX_IO);
        let srv_write = a.maxwrite.map(|v| v.min(u64::from(u32::MAX)) as u32).unwrap_or(MAX_IO);
        self.max_read = srv_read.min(MAX_IO).min(chan_resp.saturating_sub(CHAN_OVERHEAD)).max(512);
        self.max_write = srv_write.min(MAX_IO).min(chan_req.saturating_sub(CHAN_OVERHEAD)).max(512);
        self.readdir_max = chan_resp.saturating_sub(4096).min(32 * 1024).max(1024);
        self.root = cur;
        Ok(())
    }

    /// Remember that `child` is `name` inside `dir` (for NFSv4.0 open-by-name).
    pub(super) fn remember(&mut self, child: &FileHandle, dir: &FileHandle, name: &[u8]) {
        if self.names.len() >= NAME_CACHE_CAP {
            self.names.clear();
        }
        self.names.insert(child.clone(), (dir.clone(), name.to_vec()));
    }

    /// Run `build` with the stateid for I/O on `fh`. If the stateid is rejected,
    /// forget it and retry once with the anonymous stateid.
    pub(super) fn exec_stateid<F>(&mut self, fh: &FileHandle, write: bool, build: F) -> Result<Vec<ResOp>>
    where
        F: Fn(StateId) -> Vec<Op>,
    {
        let sid = self.stateid_for_io(fh, write);
        match self.exec(|_| build(sid)) {
            Err(Error::Nfs(crate::fs::Status::Other(_, c))) if sid != ANON_STATEID && Self::is_stateid_error(c) =>
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
        for sid in self.opens.drain() {
            let _ = self.send(vec![Op::Close { seqid: self.open_seqid, stateid: sid }], true);
        }
        if self.minor >= 1 {
            if let Some(s) = self.session.take() {
                let _ = self.send(vec![Op::DestroySession(s.id)], true);
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
        let res = self.exec(|_| vec![Op::Putfh(fh.0.clone()), Op::Getattr(BASIC_ATTRS.to_vec())])?;
        Ok(to_fs_attr(attr_at(&res, 1)?))
    }

    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr> {
        let fat: Fattr = encode_setattr(attrs, None);
        let res = if attrs.size.is_some() {
            self.exec_stateid(fh, true, |sid| {
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Setattr { stateid: sid, attrs: fat.clone() },
                    Op::Getattr(BASIC_ATTRS.to_vec()),
                ]
            })?
        } else {
            self.exec(|_| {
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Setattr { stateid: ANON_STATEID, attrs: fat.clone() },
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
                vec![Op::Putfh(dir.0.clone()), Op::Lookupp, Op::Getfh, Op::Getattr(BASIC_ATTRS.to_vec())]
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
                vec![Op::Putfh(dir.0.clone()), Op::Readdir {
                    cookie: cookie_now,
                    verifier: verf_now,
                    dircount: s.readdir_max,
                    maxcount: s.readdir_max,
                    attrs: READDIR_ATTRS.to_vec(),
                }]
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
                Res::Readdir { verifier, entries, eof } => (*verifier, entries.clone(), *eof),
                _ => return Err(xdr_err("READDIR")),
            };
            for e in entries {
                cookie = e.cookie;
                if e.name == b"." || e.name == b".." {
                    continue;
                }
                let handle = e.attrs.filehandle.clone().map(FileHandle);
                let attr = if e.attrs.rdattr_error.is_none() { Some(to_fs_attr(&e.attrs)) } else { None };
                let fileid = e.attrs.fileid.unwrap_or(0);
                if let Some(h) = &handle {
                    self.remember(h, dir, &e.name);
                }
                out.push(DirEntry { name: e.name, fileid, attr, handle });
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
            vec![Op::Putfh(fh.0.clone()), Op::Read { stateid: sid, offset, count }]
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
                vec![Op::Putfh(fh.0.clone()), Op::Write { stateid: sid, offset: off, data: chunk.to_vec() }]
            })?;
            let (count, committed) = match body(&res, 1)? {
                Res::Write { count, committed } => (*count as usize, *committed),
                _ => return Err(xdr_err("WRITE")),
            };
            let count = count.min(n);
            if committed != FILE_SYNC4 && count > 0 {
                // Server buffered the data; make it durable.
                self.exec(|_| vec![Op::Commit { offset: off, count: count as u32 }])?;
            }
            if count == 0 {
                break;
            }
            done += count;
        }
        Ok(done as u32)
    }

    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let exclusive = mode == CreateMode::Exclusive;
        let verf = self.new_verifier();
        let fat = if exclusive { Fattr::default() } else { encode_setattr(attrs, Some(0o644)) };
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
                    OpenHow::Create { mode: createmode, verf, attrs: fat.clone() },
                    Claim::Null(name.to_vec()),
                )),
                Op::Getfh,
                Op::Getattr(BASIC_ATTRS.to_vec()),
            ]
        })?;
        let (stateid, rflags, deleg) = match body(&res, 1)? {
            Res::Open { stateid, rflags, deleg } => (*stateid, *rflags, *deleg),
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

    fn mkdir(&mut self, dir: &FileHandle, name: &[u8], attrs: &SetAttr) -> Result<(FileHandle, Attr)> {
        let fat = encode_setattr(attrs, Some(0o755));
        let res = self.exec(|_| {
            vec![
                Op::Putfh(dir.0.clone()),
                Op::Create { kind: CreateKind::Dir, name: name.to_vec(), attrs: fat.clone() },
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
        let fat = encode_setattr(attrs, Some(0o777));
        let res = self.exec(|_| {
            vec![
                Op::Putfh(dir.0.clone()),
                Op::Create { kind: CreateKind::Symlink(target.to_vec()), name: name.to_vec(), attrs: fat.clone() },
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
                Op::Rename { from: from_name.to_vec(), to: to_name.to_vec() },
            ]
        })?;
        Ok(())
    }

    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat> {
        let res = self.exec(|_| vec![Op::Putfh(fh.0.clone()), Op::Getattr(FSSTAT_ATTRS.to_vec())])?;
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
        maxrequests: 4,
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

