//! In-process NFSv4.0 / 4.1 / 4.2 server for backend tests.
//!
//! One TCP listener on an ephemeral 127.0.0.1 port answers NFS program 100003
//! version 4 (NULL and COMPOUND). The tree is a [`nfsc::memfs::MemFs`]:
//! handles are its 8-byte ids and PUTROOTFH yields its root (no pseudo-fs).
//!
//! On top of the tree the server keeps real-ish protocol state:
//!
//! - client IDs: SETCLIENTID / SETCLIENTID_CONFIRM (4.0) and EXCHANGE_ID /
//!   CREATE_SESSION (4.1+), with leases that expire (checked lazily when a
//!   request uses the client) and are renewed the way RFC 7530 section 9.5
//!   and RFC 8881 section 8.3 say;
//! - sessions with a slot table: every SEQUENCE is checked against the slot's
//!   last seqid. A retransmission (same slot and seqid) is answered like
//!   knfsd: with the cached reply when the original asked `cachethis`, else
//!   NFS4ERR_RETRY_UNCACHED_REP. With [`Config::cache_all_replies`] the
//!   cached reply is always returned, like a fully caching server, even when
//!   the new request differs from the cached one;
//! - open stateids with seqids, and NFSv4.0 open-owner seqid checking per
//!   RFC 7530 section 9.1.7 (replays answered from the owner's cache, the
//!   seqid not advanced for the errors listed there), OPEN_CONFIRM for new
//!   open-owners;
//! - READDIR cookies (entry index + 3) and a cookie verifier, paging by
//!   `maxcount`;
//! - pattern files ([`pattern_byte`]) of any size, computed on the fly, and
//!   UNSTABLE write tracking with a write verifier that changes on reboot.
//!
//! Client misbehavior the server can see (a wrong slot or open-owner seqid,
//! a slot reused for a different request, a bad csa_sequence, an operation
//! outside a session, a READ larger than `maxread`, ...) is recorded as a
//! *violation*. Dropping a [`FakeNfs4`] with violations fails the test, so
//! every test checks seqid use for free.
//!
//! Faults come from a script of [`Rule`]s or a closure hook (see [`Fault`]).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nfsc::error::Error;
use nfsc::fs::{
    Attr, CreateMode, FileHandle, FileType, Filesystem, SetAttr, SetTime, Status, Time,
};
use nfsc::memfs::MemFs;
use nfsc::xdr::{Decoder, Encoder};

pub const NFS_PROG: u32 = 100003;

// Operation numbers.
pub const OP_ACCESS: u32 = 3;
pub const OP_CLOSE: u32 = 4;
pub const OP_COMMIT: u32 = 5;
pub const OP_CREATE: u32 = 6;
pub const OP_DELEGRETURN: u32 = 8;
pub const OP_GETATTR: u32 = 9;
pub const OP_GETFH: u32 = 10;
pub const OP_LINK: u32 = 11;
pub const OP_LOOKUP: u32 = 15;
pub const OP_LOOKUPP: u32 = 16;
pub const OP_OPEN: u32 = 18;
pub const OP_OPEN_CONFIRM: u32 = 20;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_REMOVE: u32 = 28;
pub const OP_RENAME: u32 = 29;
pub const OP_RENEW: u32 = 30;
pub const OP_RESTOREFH: u32 = 31;
pub const OP_SAVEFH: u32 = 32;
pub const OP_SETATTR: u32 = 34;
pub const OP_SETCLIENTID: u32 = 35;
pub const OP_SETCLIENTID_CONFIRM: u32 = 36;
pub const OP_WRITE: u32 = 38;
pub const OP_BIND_CONN_TO_SESSION: u32 = 41;
pub const OP_EXCHANGE_ID: u32 = 42;
pub const OP_CREATE_SESSION: u32 = 43;
pub const OP_DESTROY_SESSION: u32 = 44;
pub const OP_SEQUENCE: u32 = 53;
pub const OP_DESTROY_CLIENTID: u32 = 57;
pub const OP_RECLAIM_COMPLETE: u32 = 58;
pub const OP_ILLEGAL: u32 = 10044;
/// Rule wildcard: matches every COMPOUND; a status fault hits its first op.
pub const OP_ANY: u32 = u32::MAX;

// nfsstat4 values.
pub const NFS4_OK: u32 = 0;
pub const NFS4ERR_NOENT: u32 = 2;
pub const NFS4ERR_IO: u32 = 5;
pub const NFS4ERR_ACCESS: u32 = 13;
pub const NFS4ERR_EXIST: u32 = 17;
pub const NFS4ERR_NOTDIR: u32 = 20;
pub const NFS4ERR_ISDIR: u32 = 21;
pub const NFS4ERR_INVAL: u32 = 22;
pub const NFS4ERR_ROFS: u32 = 30;
pub const NFS4ERR_STALE: u32 = 70;
pub const NFS4ERR_BADHANDLE: u32 = 10001;
pub const NFS4ERR_BAD_COOKIE: u32 = 10003;
pub const NFS4ERR_NOTSUPP: u32 = 10004;
pub const NFS4ERR_TOOSMALL: u32 = 10005;
pub const NFS4ERR_SERVERFAULT: u32 = 10006;
pub const NFS4ERR_BADTYPE: u32 = 10007;
pub const NFS4ERR_DELAY: u32 = 10008;
pub const NFS4ERR_EXPIRED: u32 = 10011;
pub const NFS4ERR_GRACE: u32 = 10013;
pub const NFS4ERR_RESOURCE: u32 = 10018;
pub const NFS4ERR_MOVED: u32 = 10019;
pub const NFS4ERR_NOFILEHANDLE: u32 = 10020;
pub const NFS4ERR_MINOR_VERS_MISMATCH: u32 = 10021;
pub const NFS4ERR_STALE_CLIENTID: u32 = 10022;
pub const NFS4ERR_STALE_STATEID: u32 = 10023;
pub const NFS4ERR_OLD_STATEID: u32 = 10024;
pub const NFS4ERR_BAD_STATEID: u32 = 10025;
pub const NFS4ERR_BAD_SEQID: u32 = 10026;
pub const NFS4ERR_SYMLINK: u32 = 10029;
pub const NFS4ERR_RESTOREFH: u32 = 10030;
pub const NFS4ERR_ATTRNOTSUPP: u32 = 10032;
pub const NFS4ERR_BADXDR: u32 = 10036;
pub const NFS4ERR_OPENMODE: u32 = 10038;
pub const NFS4ERR_OP_ILLEGAL: u32 = 10044;
pub const NFS4ERR_ADMIN_REVOKED: u32 = 10047;
pub const NFS4ERR_BADSESSION: u32 = 10052;
pub const NFS4ERR_BADSLOT: u32 = 10053;
pub const NFS4ERR_COMPLETE_ALREADY: u32 = 10054;
pub const NFS4ERR_SEQ_MISORDERED: u32 = 10063;
pub const NFS4ERR_SEQUENCE_POS: u32 = 10064;
pub const NFS4ERR_RETRY_UNCACHED_REP: u32 = 10068;
pub const NFS4ERR_OP_NOT_IN_SESSION: u32 = 10071;
pub const NFS4ERR_CLIENTID_BUSY: u32 = 10074;
pub const NFS4ERR_BAD_HIGH_SLOT: u32 = 10077;
pub const NFS4ERR_DEADSESSION: u32 = 10078;
pub const NFS4ERR_NOT_ONLY_OP: u32 = 10081;

// accept_stat values.
const ACCEPT_SUCCESS: u32 = 0;
const ACCEPT_PROG_UNAVAIL: u32 = 1;
const ACCEPT_PROG_MISMATCH: u32 = 2;
const ACCEPT_PROC_UNAVAIL: u32 = 3;
const ACCEPT_GARBAGE_ARGS: u32 = 4;

const UNSTABLE4: u32 = 0;
const FILE_SYNC4: u32 = 2;

const OPEN4_SHARE_ACCESS_WRITE: u32 = 2;
const OPEN4_RESULT_CONFIRM: u32 = 0x2;
const OPEN4_RESULT_LOCKTYPE_POSIX: u32 = 0x4;
const EXCHGID4_FLAG_USE_NON_PNFS: u32 = 0x0001_0000;
const EXCHGID4_FLAG_CONFIRMED_R: u32 = 0x8000_0000;

/// First READDIR cookie handed out (0, 1 and 2 are reserved, RFC 8881 18.23.4).
const FIRST_COOKIE: u64 = 3;
/// Largest channel sizes granted in CREATE_SESSION.
const CHAN_MAX: u32 = 2 << 20;

/// Byte `offset` of a pattern file with `seed`. Every bit of the offset
/// affects the result, so a misplaced chunk anywhere is detected.
pub fn pattern_byte(seed: u64, offset: u64) -> u8 {
    let x = (offset ^ seed).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (x >> 56) as u8 ^ (offset as u8)
}

/// `len` bytes of a pattern file from `offset`.
pub fn pattern(seed: u64, offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| pattern_byte(seed, offset + i))
        .collect()
}

/// RFC 7530 section 9.1.7: open-owner seqid-mutating operations that fail
/// with one of these do not advance the owner's seqid.
pub fn seqid_advances(status: u32) -> bool {
    !matches!(
        status,
        NFS4ERR_STALE_CLIENTID
            | NFS4ERR_STALE_STATEID
            | NFS4ERR_BAD_STATEID
            | NFS4ERR_BAD_SEQID
            | NFS4ERR_BADXDR
            | NFS4ERR_RESOURCE
            | NFS4ERR_NOFILEHANDLE
            | NFS4ERR_MOVED
    )
}

/// Server set-up.
#[derive(Debug, Clone)]
pub struct Config {
    /// Minor versions accepted; others get NFS4ERR_MINOR_VERS_MISMATCH.
    pub minors: Vec<u32>,
    /// lease_time in seconds.
    pub lease_secs: u32,
    /// Fore channel slots granted (at most what the client asks for).
    pub slots: u32,
    /// maxread / maxwrite attributes. Larger requests are violations.
    pub maxread: u32,
    pub maxwrite: u32,
    /// NFSv4.0: the first OPEN of a new open-owner must be confirmed.
    pub open_confirm: bool,
    /// During the grace period, READ / WRITE with a special stateid get
    /// NFS4ERR_GRACE (as from a server that cannot rule out conflicts).
    pub grace_blocks_anon_io: bool,
    /// Answer every slot replay with the cached reply, even when the replayed
    /// request differs from the original and `cachethis` was false.
    /// Default: knfsd behavior (NFS4ERR_RETRY_UNCACHED_REP unless cachethis).
    pub cache_all_replies: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            minors: vec![0, 1, 2],
            lease_secs: 30,
            slots: 8,
            maxread: 256 << 10,
            maxwrite: 256 << 10,
            open_confirm: true,
            grace_blocks_anon_io: true,
            cache_all_replies: false,
        }
    }
}

/// One COMPOUND as faults see it.
#[derive(Debug, Clone)]
pub struct Call {
    pub minor: u32,
    /// Opcodes in order.
    pub ops: Vec<u32>,
    /// 1-based count of COMPOUNDs received, this one included.
    pub nth: usize,
    /// READ / WRITE / COMMIT offset, READ / COMMIT count or WRITE length,
    /// READDIR cookie (of the first such op).
    pub offset: u64,
    pub count: u32,
    pub cookie: u64,
}

impl Call {
    pub fn has(&self, op: u32) -> bool {
        self.ops.contains(&op)
    }
}

/// What to do to one COMPOUND instead of (or before) answering it normally.
#[derive(Debug, Clone)]
pub enum Fault {
    /// The matched op fails with this status; ops before it run normally.
    /// For NFSv4.0 open-owner ops the owner seqid is checked and advanced
    /// as for a real failure with that status.
    Status(u32),
    /// Sleep, then answer normally.
    Delay(Duration),
    /// Close the connection; the request is not executed.
    Drop,
    /// Execute the request, then close the connection without replying.
    DropReply,
    /// Execute, send the first `n` bytes of the reply record, close.
    Truncate(usize),
    /// Never answer (not executed); keep the connection open.
    Silent,
    /// Cut every connection and refuse new ones for the duration. State is
    /// kept. The request is not executed.
    Restart(Duration),
    /// Server reboot: cut connections, refuse new ones for `down`, forget all
    /// clients, sessions and opens, change the boot and write verifiers, and
    /// return NFS4ERR_GRACE to non-reclaim OPENs for `grace` after that.
    Reboot { down: Duration, grace: Duration },
    /// Destroy the session the COMPOUND uses (all sessions for a 4.0 or
    /// session-less request), then process it (so it gets BADSESSION).
    KillSession,
    /// Expire every client's lease, then process the request.
    ExpireLease,
    /// READ: return at most `n` bytes and eof = false.
    ShortRead(u32),
}

type Filter = Arc<dyn Fn(&Call) -> bool + Send + Sync>;

/// One entry of a fault script. Matches COMPOUNDs containing `op` (and the
/// optional filter); skips the first `after` matches, then fires `times` times.
#[derive(Clone)]
pub struct Rule {
    op: u32,
    after: usize,
    times: usize,
    fault: Fault,
    filter: Option<Filter>,
}

impl Rule {
    /// A rule for COMPOUNDs containing operation `op` ([`OP_ANY`] for all).
    pub fn op(op: u32, fault: Fault) -> Rule {
        Rule {
            op,
            after: 0,
            times: usize::MAX,
            fault,
            filter: None,
        }
    }

    /// Let the first `n` matching calls through untouched.
    pub fn after(mut self, n: usize) -> Rule {
        self.after = n;
        self
    }

    /// Fire this many times, then stop matching.
    pub fn times(mut self, n: usize) -> Rule {
        self.times = n;
        self
    }

    /// Only consider calls for which `f` is true.
    pub fn when(mut self, f: impl Fn(&Call) -> bool + Send + Sync + 'static) -> Rule {
        self.filter = Some(Arc::new(f));
        self
    }
}

type Hook = Box<dyn FnMut(&Call) -> Option<Fault> + Send>;

/// Counters shared with the test.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub compounds: usize,
    /// COMPOUNDs per minor version (rejected ones included).
    pub by_minor: HashMap<u32, usize>,
    /// Operations received, per opcode.
    pub ops: HashMap<u32, usize>,
    /// Failed operations, per (opcode, status).
    pub errors: HashMap<(u32, u32), usize>,
    pub tcp_connections: usize,
    pub faults_fired: usize,
    /// Client misbehavior; must stay empty (checked on drop).
    pub violations: Vec<String>,
    /// READ / WRITE with the anonymous or READ-bypass stateid.
    pub anon_io: usize,
    /// READ / WRITE with an open stateid that was accepted.
    pub stateid_io: usize,
    /// SEQUENCE retransmissions (same slot and seqid).
    pub slot_replays: usize,
    /// NFSv4.0 open-owner seqid replays.
    pub owner_replays: usize,
    /// Highest slot id used.
    pub max_slot: u32,
    pub max_read_count: u32,
    pub max_write_len: u32,
    pub unstable_writes: usize,
    /// READDIR replies and the most entries in one.
    pub readdir_pages: usize,
    pub readdir_max_entries: usize,
}

impl Stats {
    pub fn op(&self, op: u32) -> usize {
        self.ops.get(&op).copied().unwrap_or(0)
    }

    /// Times `op` failed with `status`.
    pub fn error(&self, op: u32, status: u32) -> usize {
        self.errors.get(&(op, status)).copied().unwrap_or(0)
    }

    /// Times any op failed with `status`.
    pub fn status(&self, status: u32) -> usize {
        self.errors
            .iter()
            .filter(|((_, s), _)| *s == status)
            .map(|(_, n)| n)
            .sum()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
struct Sid {
    seqid: u32,
    other: [u8; 12],
}

impl Sid {
    fn special(&self) -> bool {
        (self.seqid == 0 && self.other == [0; 12])
            || (self.seqid == u32::MAX && self.other == [0xff; 12])
    }

    fn put(&self, e: &mut Encoder) {
        e.put_u32(self.seqid).put_opaque_fixed(&self.other);
    }
}

struct Client {
    owner: Vec<u8>,
    verifier: [u8; 8],
    /// SETCLIENTID_CONFIRM verifier (4.0).
    confirm: [u8; 8],
    confirmed: bool,
    v41: bool,
    last_renew: Instant,
    /// Lease forcibly expired by [`Fault::ExpireLease`].
    expired: bool,
    /// Next csa_sequence expected by CREATE_SESSION.
    create_seq: u32,
    /// Result body of the last CREATE_SESSION, for its replay.
    create_cache: Option<Vec<u8>>,
    reclaim_complete: bool,
}

impl Client {
    fn lease_ok(&self, lease: Duration) -> bool {
        !self.expired && self.last_renew.elapsed() <= lease
    }
}

struct Slot {
    /// Seqid of the last request executed on the slot (0: none yet).
    seqid: u32,
    /// That request's COMPOUND args, its cachethis flag and full reply.
    request: Vec<u8>,
    cachethis: bool,
    reply: Option<Vec<u8>>,
}

struct Session {
    clientid: u64,
    slots: Vec<Slot>,
}

struct OpenOwner {
    /// Seqid of the last seqid-mutating op that advanced the owner.
    last: u32,
    confirmed: bool,
    /// Result of that op, for replays.
    cache: (u32, Vec<u8>),
}

struct Open {
    clientid: u64,
    owner: Vec<u8>,
    fh: Vec<u8>,
    seqid: u32,
    access: u32,
    confirmed: bool,
}

struct Listed {
    name: Vec<u8>,
    fh: FileHandle,
    attr: Attr,
}

struct State {
    fs: MemFs,
    patterns: HashMap<Vec<u8>, u64>,
    uncommitted: Vec<(Vec<u8>, u64, usize)>,
    write_verf: u64,
    boot: u32,
    grace_until: Option<Instant>,
    clients: HashMap<u64, Client>,
    sessions: HashMap<[u8; 16], Session>,
    owners: HashMap<(u64, Vec<u8>), OpenOwner>,
    opens: HashMap<[u8; 12], Open>,
    counter: u32,
    /// Namespace generation; the READDIR cookie verifier.
    dir_gen: u64,
    listings: HashMap<Vec<u8>, Arc<Vec<Listed>>>,
}

impl State {
    fn next(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }

    fn in_grace(&mut self) -> bool {
        match self.grace_until {
            Some(t) if Instant::now() < t => true,
            Some(_) => {
                self.grace_until = None;
                false
            }
            None => false,
        }
    }

    fn namespace_changed(&mut self) {
        self.listings.clear();
        self.dir_gen += 1;
    }

    fn purge_client(&mut self, id: u64) {
        self.clients.remove(&id);
        self.sessions.retain(|_, s| s.clientid != id);
        self.opens.retain(|_, o| o.clientid != id);
        self.owners.retain(|(c, _), _| *c != id);
    }

    fn reboot(&mut self, grace: Duration) {
        self.boot += 1;
        self.clients.clear();
        self.sessions.clear();
        self.owners.clear();
        self.opens.clear();
        self.grace_until = Some(Instant::now() + grace);
        self.write_verf = self.write_verf.wrapping_add(0x0101_0101);
        for (fh, off, len) in std::mem::take(&mut self.uncommitted) {
            let _ = self.fs.write(&FileHandle(fh), off, &vec![0xEE; len]);
        }
    }

    fn new_clientid(&mut self) -> u64 {
        (u64::from(self.boot) << 32) | u64::from(self.next())
    }
}

struct Shared {
    cfg: Config,
    state: Mutex<State>,
    stats: Mutex<Stats>,
    script: Mutex<Vec<Rule>>,
    hook: Mutex<Option<Hook>>,
    down_until: Mutex<Option<Instant>>,
    conns: Mutex<Vec<TcpStream>>,
    stop: AtomicBool,
}

impl Shared {
    fn violation(&self, msg: String) {
        eprintln!("nfs4 fake: client violation: {msg}");
        self.stats.lock().unwrap().violations.push(msg);
    }

    fn lease(&self) -> Duration {
        Duration::from_secs(u64::from(self.cfg.lease_secs))
    }
}

pub struct FakeNfs4 {
    pub port: u16,
    shared: Arc<Shared>,
}

impl Drop for FakeNfs4 {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for c in self.shared.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
        let v = std::mem::take(&mut self.shared.stats.lock().unwrap().violations);
        if !v.is_empty() && !thread::panicking() {
            panic!(
                "client protocol violations seen by the fake server:\n{}",
                v.join("\n")
            );
        }
    }
}

impl FakeNfs4 {
    pub fn root(&self) -> FileHandle {
        self.shared.state.lock().unwrap().fs.root()
    }

    /// Mutate the backing tree directly (set-up and inspection).
    pub fn with_fs<R>(&self, f: impl FnOnce(&mut MemFs) -> R) -> R {
        let mut st = self.shared.state.lock().unwrap();
        st.namespace_changed();
        f(&mut st.fs)
    }

    /// Add a read-only file of `size` bytes whose content is [`pattern`]`(seed, ..)`.
    pub fn add_pattern_file(&self, path: &str, size: u64, seed: u64) -> FileHandle {
        let mut st = self.shared.state.lock().unwrap();
        st.namespace_changed();
        st.fs
            .add_sparse_file(path, size, 0)
            .expect("add_sparse_file");
        let fh = walk(&mut st.fs, path);
        st.patterns.insert(fh.0.clone(), seed);
        fh
    }

    /// Whole content of a regular (non-pattern) file in the backing tree.
    pub fn file(&self, path: &str) -> Vec<u8> {
        let st = self.shared.state.lock().unwrap();
        st.fs.read_file(path).expect("no such file")
    }

    pub fn read_at(&self, path: &str, offset: u64, len: u32) -> Vec<u8> {
        let st = self.shared.state.lock().unwrap();
        st.fs.read_at(path, offset, len).expect("no such file")
    }

    /// Uncommitted UNSTABLE writes still outstanding.
    pub fn uncommitted(&self) -> usize {
        self.shared.state.lock().unwrap().uncommitted.len()
    }

    /// Opens the server holds.
    pub fn opens(&self) -> usize {
        self.shared.state.lock().unwrap().opens.len()
    }

    pub fn stats(&self) -> Stats {
        self.shared.stats.lock().unwrap().clone()
    }

    /// Violations so far (also checked when the server is dropped).
    pub fn violations(&self) -> Vec<String> {
        self.shared.stats.lock().unwrap().violations.clone()
    }

    pub fn reset_stats(&self) {
        let mut s = self.shared.stats.lock().unwrap();
        let v = std::mem::take(&mut s.violations);
        *s = Stats::default();
        s.violations = v;
    }

    /// Replace the fault script.
    pub fn script(&self, rules: Vec<Rule>) {
        *self.shared.script.lock().unwrap() = rules;
    }

    /// Install a closure consulted (after the script) for every COMPOUND.
    pub fn set_hook(&self, f: impl FnMut(&Call) -> Option<Fault> + Send + 'static) {
        *self.shared.hook.lock().unwrap() = Some(Box::new(f));
    }

    pub fn clear_faults(&self) {
        self.script(Vec::new());
        *self.shared.hook.lock().unwrap() = None;
    }

    /// Cut all connections and refuse new ones for `d` (state kept).
    pub fn restart(&self, d: Duration) {
        restart(&self.shared, d);
    }

    /// Reboot now (see [`Fault::Reboot`]).
    pub fn reboot(&self, down: Duration, grace: Duration) {
        self.shared.state.lock().unwrap().reboot(down + grace);
        restart(&self.shared, down);
    }
}

fn walk(fs: &mut MemFs, path: &str) -> FileHandle {
    let mut fh = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        fh = fs.lookup(&fh, c.as_bytes()).expect("walk").0;
    }
    fh
}

fn restart(shared: &Shared, d: Duration) {
    *shared.down_until.lock().unwrap() = Some(Instant::now() + d);
    for c in shared.conns.lock().unwrap().drain(..) {
        let _ = c.shutdown(Shutdown::Both);
    }
}

fn is_down(shared: &Shared) -> bool {
    let mut g = shared.down_until.lock().unwrap();
    match *g {
        Some(t) if Instant::now() < t => true,
        Some(_) => {
            *g = None;
            false
        }
        None => false,
    }
}

// ------------------------------------------------------------------ start

pub fn start() -> FakeNfs4 {
    start_with(Config::default())
}

pub fn start_with(cfg: Config) -> FakeNfs4 {
    let tcp = TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let port = tcp.local_addr().unwrap().port();
    let mut fs = MemFs::new();
    fs.max_read = u32::MAX;
    fs.max_write = u32::MAX;
    let shared = Arc::new(Shared {
        cfg,
        state: Mutex::new(State {
            fs,
            patterns: HashMap::new(),
            uncommitted: Vec::new(),
            write_verf: 0x1122_3344_5566_7788,
            boot: 1,
            grace_until: None,
            clients: HashMap::new(),
            sessions: HashMap::new(),
            owners: HashMap::new(),
            opens: HashMap::new(),
            counter: 0,
            dir_gen: 1,
            listings: HashMap::new(),
        }),
        stats: Mutex::new(Stats::default()),
        script: Mutex::new(Vec::new()),
        hook: Mutex::new(None),
        down_until: Mutex::new(None),
        conns: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
    });
    serve_tcp(&shared, tcp, port);
    FakeNfs4 { port, shared }
}

/// Accept loop that honors restarts: while down, the listener is closed (so
/// connects are refused), then bound again on the same port.
fn serve_tcp(shared: &Arc<Shared>, listener: TcpListener, port: u16) {
    let shared = Arc::clone(shared);
    thread::spawn(move || {
        let mut listener = Some(listener);
        while !shared.stop.load(Ordering::SeqCst) {
            if is_down(&shared) {
                listener = None;
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            let l = match &listener {
                Some(l) => l,
                None => match TcpListener::bind(("127.0.0.1", port)) {
                    Ok(l) => listener.insert(l),
                    Err(_) => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                },
            };
            l.set_nonblocking(true).unwrap();
            match l.accept() {
                Ok((conn, _)) => {
                    conn.set_nonblocking(false).unwrap();
                    let _ = conn.set_nodelay(true);
                    shared.stats.lock().unwrap().tcp_connections += 1;
                    if let Ok(c) = conn.try_clone() {
                        shared.conns.lock().unwrap().push(c);
                    }
                    let shared = Arc::clone(&shared);
                    thread::spawn(move || serve_conn(&shared, conn));
                }
                Err(_) => thread::sleep(Duration::from_millis(2)),
            }
        }
    });
}

fn serve_conn(shared: &Shared, mut conn: TcpStream) {
    while let Some(msg) = read_record(&mut conn) {
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        match handle_message(shared, &msg) {
            Outcome::Reply(r) => {
                if write_record(&mut conn, &r).is_err() {
                    break;
                }
            }
            Outcome::None => {}
            Outcome::Close => break,
            Outcome::Truncate(r, n) => {
                let mut rec = (0x8000_0000u32 | r.len() as u32).to_be_bytes().to_vec();
                rec.extend_from_slice(&r);
                let _ = conn.write_all(&rec[..n.min(rec.len())]);
                break;
            }
        }
    }
    let _ = conn.shutdown(Shutdown::Both);
}

fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).ok()?;
        let w = u32::from_be_bytes(hdr);
        let mut frag = vec![0u8; (w & 0x7fff_ffff) as usize];
        s.read_exact(&mut frag).ok()?;
        out.extend_from_slice(&frag);
        if w & 0x8000_0000 != 0 {
            return Some(out);
        }
    }
}

fn write_record(s: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    let mut rec = Vec::with_capacity(4 + data.len());
    rec.extend_from_slice(&(0x8000_0000u32 | data.len() as u32).to_be_bytes());
    rec.extend_from_slice(data);
    s.write_all(&rec)
}

// --------------------------------------------------------------- dispatch

enum Outcome {
    Reply(Vec<u8>),
    None,
    Close,
    Truncate(Vec<u8>, usize),
}

fn accepted(xid: u32, accept: u32, body: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.put_u32(xid).put_u32(1).put_u32(0);
    e.put_u32(0).put_opaque(&[]);
    e.put_u32(accept);
    let mut v = e.into_inner();
    v.extend_from_slice(body);
    v
}

fn handle_message(shared: &Shared, msg: &[u8]) -> Outcome {
    let mut d = Decoder::new(msg);
    let parse = |d: &mut Decoder| -> Option<(u32, u32, u32, u32)> {
        let xid = d.get_u32().ok()?;
        if d.get_u32().ok()? != 0 || d.get_u32().ok()? != 2 {
            return None;
        }
        let prog = d.get_u32().ok()?;
        let vers = d.get_u32().ok()?;
        let proc_ = d.get_u32().ok()?;
        for _ in 0..2 {
            d.get_u32().ok()?;
            d.get_opaque().ok()?;
        }
        Some((xid, prog, vers, proc_))
    };
    let Some((xid, prog, vers, proc_)) = parse(&mut d) else {
        return Outcome::Close;
    };
    if prog != NFS_PROG {
        return Outcome::Reply(accepted(xid, ACCEPT_PROG_UNAVAIL, &[]));
    }
    if vers != 4 {
        let mut b = Encoder::new();
        b.put_u32(4).put_u32(4);
        return Outcome::Reply(accepted(xid, ACCEPT_PROG_MISMATCH, b.as_bytes()));
    }
    match proc_ {
        0 => Outcome::Reply(accepted(xid, ACCEPT_SUCCESS, &[])),
        1 => compound(shared, xid, d.rest()),
        _ => Outcome::Reply(accepted(xid, ACCEPT_PROC_UNAVAIL, &[])),
    }
}

/// One encoded operation result: opcode, status, body (only when OK, except
/// SETATTR, whose attrsset is always present).
type OpRes = (u32, u32, Vec<u8>);

fn compound_body(status: u32, tag: &[u8], results: &[OpRes]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.put_u32(status)
        .put_string(tag)
        .put_u32(results.len() as u32);
    for (op, st, body) in results {
        e.put_u32(*op).put_u32(*st).put_opaque_fixed(body);
    }
    e.into_inner()
}

fn pick_fault(shared: &Shared, call: &Call) -> Option<(Fault, u32)> {
    {
        let mut script = shared.script.lock().unwrap();
        for r in script.iter_mut() {
            if r.times == 0 || (r.op != OP_ANY && !call.has(r.op)) {
                continue;
            }
            if let Some(f) = &r.filter
                && !f(call)
            {
                continue;
            }
            if r.after > 0 {
                r.after -= 1;
                continue;
            }
            r.times -= 1;
            return Some((r.fault.clone(), r.op));
        }
    }
    let mut hook = shared.hook.lock().unwrap();
    hook.as_mut().and_then(|h| h(call)).map(|f| (f, OP_ANY))
}

fn compound(shared: &Shared, xid: u32, args: &[u8]) -> Outcome {
    let mut d = Decoder::new(args);
    let (tag, minor) = match (d.get_string(), d.get_u32()) {
        (Ok(t), Ok(m)) => (t, m),
        _ => return Outcome::Reply(accepted(xid, ACCEPT_GARBAGE_ARGS, &[])),
    };
    let nth = {
        let mut s = shared.stats.lock().unwrap();
        s.compounds += 1;
        *s.by_minor.entry(minor).or_insert(0) += 1;
        s.compounds
    };
    if !shared.cfg.minors.contains(&minor) {
        let body = compound_body(NFS4ERR_MINOR_VERS_MISMATCH, &tag, &[]);
        return Outcome::Reply(accepted(xid, ACCEPT_SUCCESS, &body));
    }
    let ops = match decode_ops(&mut d) {
        Ok(ops) => ops,
        Err(e) => {
            shared.violation(format!("undecodable COMPOUND (minor {minor}): {e}"));
            let body = compound_body(NFS4ERR_BADXDR, &tag, &[]);
            return Outcome::Reply(accepted(xid, ACCEPT_SUCCESS, &body));
        }
    };
    let codes: Vec<u32> = ops.iter().map(|o| o.code()).collect();
    {
        let mut s = shared.stats.lock().unwrap();
        for c in &codes {
            *s.ops.entry(*c).or_insert(0) += 1;
        }
    }
    if let Some((status, at)) = structure_error(shared, minor, &ops) {
        // Only the offending op is reported; nothing in the COMPOUND ran.
        let op = if status == NFS4ERR_OP_ILLEGAL {
            OP_ILLEGAL
        } else {
            codes[at]
        };
        let body = compound_body(status, &tag, &[(op, status, vec![])]);
        return Outcome::Reply(accepted(xid, ACCEPT_SUCCESS, &body));
    }

    let mut call = Call {
        minor,
        ops: codes.clone(),
        nth,
        offset: 0,
        count: 0,
        cookie: 0,
    };
    for op in &ops {
        match op {
            ArgOp::Read { offset, count, .. } | ArgOp::Commit { offset, count } => {
                (call.offset, call.count) = (*offset, *count);
                break;
            }
            ArgOp::Write { offset, data, .. } => {
                (call.offset, call.count) = (*offset, data.len() as u32);
                break;
            }
            ArgOp::Readdir { cookie, .. } => {
                call.cookie = *cookie;
                break;
            }
            _ => {}
        }
    }

    let fault = pick_fault(shared, &call);
    if fault.is_some() {
        shared.stats.lock().unwrap().faults_fired += 1;
    }
    let mut status_at = None;
    let mut read_fault = None;
    let mut after = None;
    if let Some((f, op)) = fault {
        match f {
            Fault::Status(s) => {
                let i = if op == OP_ANY {
                    0
                } else {
                    codes.iter().position(|c| *c == op).unwrap_or(0)
                };
                status_at = Some((i, s));
            }
            Fault::Delay(t) => thread::sleep(t),
            Fault::Drop => return Outcome::Close,
            Fault::Silent => return Outcome::None,
            Fault::Restart(t) => {
                restart(shared, t);
                return Outcome::Close;
            }
            Fault::Reboot { down, grace } => {
                shared.state.lock().unwrap().reboot(down + grace);
                restart(shared, down);
                return Outcome::Close;
            }
            Fault::KillSession => {
                let mut st = shared.state.lock().unwrap();
                match ops.first() {
                    Some(ArgOp::Sequence { session, .. }) => {
                        st.sessions.remove(session);
                    }
                    _ => st.sessions.clear(),
                }
            }
            Fault::ExpireLease => {
                let mut st = shared.state.lock().unwrap();
                for c in st.clients.values_mut() {
                    c.expired = true;
                }
            }
            Fault::ShortRead(n) => read_fault = Some(n),
            f @ (Fault::DropReply | Fault::Truncate(_)) => after = Some(f),
        }
    }

    let mut st = shared.state.lock().unwrap();
    let mut ctx = Ctx {
        minor,
        cur: None,
        saved: None,
        clientid: None,
        session: None,
        slot: None,
        cachethis: false,
    };
    let mut results: Vec<OpRes> = Vec::with_capacity(ops.len());
    let mut status = NFS4_OK;
    for (i, op) in ops.iter().enumerate() {
        let (s, mut body) = match status_at {
            Some((at, code)) if at == i => injected(shared, &mut st, &ctx, op, code),
            _ => {
                if let (0, ArgOp::Sequence { .. }) = (i, op) {
                    match sequence(shared, &mut st, &mut ctx, op, args, ops.len() == 1) {
                        Seq::Replay(reply) => {
                            drop(st);
                            return finish(xid, reply, after);
                        }
                        Seq::Done(s, b) => (s, b),
                    }
                } else {
                    exec_op(shared, &mut st, &mut ctx, op, read_fault)
                }
            }
        };
        if s != NFS4_OK {
            *shared
                .stats
                .lock()
                .unwrap()
                .errors
                .entry((op.code(), s))
                .or_insert(0) += 1;
            if op.code() == OP_SETATTR && body.is_empty() {
                body = vec![0, 0, 0, 0];
            } else if op.code() != OP_SETATTR {
                body.clear();
            }
        }
        results.push((op.code(), s, body));
        status = s;
        if s != NFS4_OK {
            break;
        }
    }
    let reply = compound_body(status, &tag, &results);
    if let (Some(id), Some(slot)) = (ctx.session, ctx.slot)
        && let Some(sess) = st.sessions.get_mut(&id)
    {
        let sl = &mut sess.slots[slot];
        sl.reply = Some(reply.clone());
        sl.request = args.to_vec();
        sl.cachethis = ctx.cachethis;
    }
    drop(st);
    finish(xid, reply, after)
}

fn finish(xid: u32, body: Vec<u8>, after: Option<Fault>) -> Outcome {
    let reply = accepted(xid, ACCEPT_SUCCESS, &body);
    match after {
        Some(Fault::DropReply) => Outcome::Close,
        Some(Fault::Truncate(n)) => Outcome::Truncate(reply, n),
        _ => Outcome::Reply(reply),
    }
}

/// Session placement rules (RFC 8881 section 2.10.6 / 18.46) and minor
/// version op sets. Returns the status and the index of the offending op.
fn structure_error(shared: &Shared, minor: u32, ops: &[ArgOp]) -> Option<(u32, usize)> {
    if minor == 0 {
        if let Some(i) = ops.iter().position(|o| o.code() > 39) {
            shared.violation(format!("NFSv4.0 COMPOUND with op {}", ops[i].code()));
            return Some((NFS4ERR_OP_ILLEGAL, i));
        }
        return None;
    }
    if let Some(i) = ops.iter().position(|o| {
        matches!(
            o.code(),
            OP_SETCLIENTID | OP_SETCLIENTID_CONFIRM | OP_RENEW | OP_OPEN_CONFIRM
        )
    }) {
        shared.violation(format!(
            "NFSv4.{minor} COMPOUND with 4.0-only op {}",
            ops[i].code()
        ));
        return Some((NFS4ERR_NOTSUPP, i));
    }
    if let Some(i) = ops.iter().skip(1).position(|o| o.code() == OP_SEQUENCE) {
        shared.violation("SEQUENCE not first in COMPOUND".into());
        return Some((NFS4ERR_SEQUENCE_POS, i + 1));
    }
    match ops.first() {
        None | Some(ArgOp::Sequence { .. }) => None,
        Some(op) => {
            let sessionless = matches!(
                op.code(),
                OP_EXCHANGE_ID
                    | OP_CREATE_SESSION
                    | OP_DESTROY_SESSION
                    | OP_DESTROY_CLIENTID
                    | OP_BIND_CONN_TO_SESSION
            );
            if !sessionless {
                shared.violation(format!("op {} outside a session", op.code()));
                Some((NFS4ERR_OP_NOT_IN_SESSION, 0))
            } else if ops.len() > 1 {
                shared.violation(format!("op {} not alone in its COMPOUND", op.code()));
                Some((NFS4ERR_NOT_ONLY_OP, 0))
            } else {
                None
            }
        }
    }
}

struct Ctx {
    minor: u32,
    cur: Option<FileHandle>,
    saved: Option<FileHandle>,
    /// The session's client (4.1+, after SEQUENCE).
    clientid: Option<u64>,
    session: Option<[u8; 16]>,
    slot: Option<usize>,
    cachethis: bool,
}

enum Seq {
    Done(u32, Vec<u8>),
    /// A retransmission answered with this COMPOUND4res.
    Replay(Vec<u8>),
}

fn next_seqid(s: u32) -> u32 {
    match s.wrapping_add(1) {
        0 => 1,
        n => n,
    }
}

fn sequence(
    shared: &Shared,
    st: &mut State,
    ctx: &mut Ctx,
    op: &ArgOp,
    args: &[u8],
    probe: bool,
) -> Seq {
    let ArgOp::Sequence {
        session,
        seqid,
        slot,
        highest,
        cachethis,
    } = op
    else {
        unreachable!()
    };
    let (seqid, slot, highest) = (*seqid, *slot, *highest);
    let Some(clientid) = st.sessions.get(session).map(|s| s.clientid) else {
        return Seq::Done(NFS4ERR_BADSESSION, vec![]);
    };
    let lease = shared.lease();
    if !st.clients.get(&clientid).is_some_and(|c| c.lease_ok(lease)) {
        st.purge_client(clientid);
        return Seq::Done(NFS4ERR_BADSESSION, vec![]);
    }
    let sess = st.sessions.get_mut(session).unwrap();
    let n = sess.slots.len() as u32;
    if slot >= n {
        shared.violation(format!("SEQUENCE on slot {slot}, session has {n} slots"));
        return Seq::Done(NFS4ERR_BADSLOT, vec![]);
    }
    if highest >= n {
        shared.violation(format!(
            "SEQUENCE highest_slotid {highest}, session has {n} slots"
        ));
        return Seq::Done(NFS4ERR_BAD_HIGH_SLOT, vec![]);
    }
    let sl = &mut sess.slots[slot as usize];
    if seqid == sl.seqid && sl.seqid != 0 {
        let same = sl.request == args;
        if !same {
            shared.violation(format!(
                "slot {slot} seqid {seqid} reused for a different request"
            ));
        }
        shared.stats.lock().unwrap().slot_replays += 1;
        if let Some(r) = &sl.reply
            && (shared.cfg.cache_all_replies || (same && sl.cachethis))
        {
            return Seq::Replay(r.clone());
        }
        return Seq::Done(NFS4ERR_RETRY_UNCACHED_REP, vec![]);
    }
    let want = next_seqid(sl.seqid);
    if seqid != want {
        // RFC 8881 2.10.6.1: after a lost reply the client may probe with an
        // empty SEQUENCE at N+1 to learn whether request N ran; when it did
        // not, the server answers SEQ_MISORDERED. That probe is not misuse.
        if !(probe && seqid == next_seqid(want)) {
            shared.violation(format!(
                "SEQUENCE slot {slot}: seqid {seqid}, expected {want}"
            ));
        }
        return Seq::Done(NFS4ERR_SEQ_MISORDERED, vec![]);
    }
    sl.seqid = seqid;
    sl.reply = None;
    if let Some(c) = st.clients.get_mut(&clientid) {
        c.last_renew = Instant::now();
    }
    ctx.clientid = Some(clientid);
    ctx.session = Some(*session);
    ctx.slot = Some(slot as usize);
    ctx.cachethis = *cachethis;
    {
        let mut s = shared.stats.lock().unwrap();
        s.max_slot = s.max_slot.max(slot);
    }
    let mut e = Encoder::new();
    e.put_opaque_fixed(session)
        .put_u32(seqid)
        .put_u32(slot)
        .put_u32(n - 1)
        .put_u32(n - 1)
        .put_u32(0);
    Seq::Done(NFS4_OK, e.into_inner())
}

/// Status fault on `op`. NFSv4.0 open-owner ops still check and advance the
/// owner seqid as a real failure with `code` would.
fn injected(shared: &Shared, st: &mut State, ctx: &Ctx, op: &ArgOp, code: u32) -> (u32, Vec<u8>) {
    if ctx.minor != 0 {
        return (code, vec![]);
    }
    let key = match op {
        ArgOp::Open(a) => Some(((a.clientid, a.owner.clone()), a.seqid, true)),
        ArgOp::OpenConfirm { sid, seqid } | ArgOp::Close { sid, seqid } => st
            .opens
            .get(&sid.other)
            .map(|o| ((o.clientid, o.owner.clone()), *seqid, false)),
        _ => None,
    };
    let Some((key, seqid, is_open)) = key else {
        return (code, vec![]);
    };
    if let Some(o) = st.owners.get(&key) {
        if seqid == o.last {
            shared.stats.lock().unwrap().owner_replays += 1;
            return o.cache.clone();
        }
        if seqid != o.last.wrapping_add(1) {
            shared.violation(format!(
                "open-owner seqid {seqid} (op {}), expected {}",
                op.code(),
                o.last.wrapping_add(1)
            ));
            return (NFS4ERR_BAD_SEQID, vec![]);
        }
    }
    if seqid_advances(code) {
        if let Some(o) = st.owners.get_mut(&key) {
            o.last = seqid;
            o.cache = (code, vec![]);
        } else if is_open {
            st.owners.insert(
                key,
                OpenOwner {
                    last: seqid,
                    confirmed: false,
                    cache: (code, vec![]),
                },
            );
        }
    }
    (code, vec![])
}

// --------------------------------------------------------------- op codec

#[derive(Debug, Clone)]
struct Chan {
    headerpad: u32,
    maxreq: u32,
    maxresp: u32,
    maxresp_cached: u32,
    maxops: u32,
    maxreqs: u32,
}

#[derive(Debug, Clone)]
enum How {
    NoCreate,
    /// createmode4 and the attributes (mode only is honored).
    Create {
        mode: u32,
        attrs: SetAttrs,
    },
}

#[derive(Debug, Clone)]
enum OpenClaim {
    Null(Vec<u8>),
    Previous,
    Fh,
    Other(u32),
}

#[derive(Debug, Clone)]
struct OpenArgs {
    seqid: u32,
    share_access: u32,
    clientid: u64,
    owner: Vec<u8>,
    how: How,
    claim: OpenClaim,
}

#[derive(Debug, Clone, Default)]
struct SetAttrs {
    bitmap: Vec<u32>,
    size: Option<u64>,
    mode: Option<u32>,
    atime: Option<SetTime>,
    mtime: Option<SetTime>,
    unsupported: Option<u32>,
}

#[derive(Debug, Clone)]
enum ArgOp {
    Access,
    Close {
        seqid: u32,
        sid: Sid,
    },
    Commit {
        offset: u64,
        count: u32,
    },
    Create {
        ftype: u32,
        link: Vec<u8>,
        name: Vec<u8>,
        attrs: SetAttrs,
    },
    DelegReturn,
    Getattr(Vec<u32>),
    Getfh,
    Link(Vec<u8>),
    Lookup(Vec<u8>),
    Lookupp,
    Open(OpenArgs),
    OpenConfirm {
        sid: Sid,
        seqid: u32,
    },
    Putfh(Vec<u8>),
    Putrootfh,
    Read {
        sid: Sid,
        offset: u64,
        count: u32,
    },
    Readdir {
        cookie: u64,
        verf: [u8; 8],
        maxcount: u32,
        attrs: Vec<u32>,
    },
    Readlink,
    Remove(Vec<u8>),
    Rename {
        from: Vec<u8>,
        to: Vec<u8>,
    },
    Renew(u64),
    Restorefh,
    Savefh,
    Setattr {
        sid: Sid,
        attrs: SetAttrs,
    },
    Setclientid {
        verf: [u8; 8],
        id: Vec<u8>,
    },
    SetclientidConfirm {
        clientid: u64,
        verf: [u8; 8],
    },
    Write {
        sid: Sid,
        offset: u64,
        stable: u32,
        data: Vec<u8>,
    },
    ExchangeId {
        verf: [u8; 8],
        owner: Vec<u8>,
    },
    CreateSession {
        clientid: u64,
        seq: u32,
        fore: Chan,
        back: Chan,
    },
    DestroySession([u8; 16]),
    BindConn([u8; 16]),
    Sequence {
        session: [u8; 16],
        seqid: u32,
        slot: u32,
        highest: u32,
        cachethis: bool,
    },
    DestroyClientid(u64),
    ReclaimComplete,
}

impl ArgOp {
    fn code(&self) -> u32 {
        match self {
            ArgOp::Access => OP_ACCESS,
            ArgOp::Close { .. } => OP_CLOSE,
            ArgOp::Commit { .. } => OP_COMMIT,
            ArgOp::Create { .. } => OP_CREATE,
            ArgOp::DelegReturn => OP_DELEGRETURN,
            ArgOp::Getattr(_) => OP_GETATTR,
            ArgOp::Getfh => OP_GETFH,
            ArgOp::Link(_) => OP_LINK,
            ArgOp::Lookup(_) => OP_LOOKUP,
            ArgOp::Lookupp => OP_LOOKUPP,
            ArgOp::Open(_) => OP_OPEN,
            ArgOp::OpenConfirm { .. } => OP_OPEN_CONFIRM,
            ArgOp::Putfh(_) => OP_PUTFH,
            ArgOp::Putrootfh => OP_PUTROOTFH,
            ArgOp::Read { .. } => OP_READ,
            ArgOp::Readdir { .. } => OP_READDIR,
            ArgOp::Readlink => OP_READLINK,
            ArgOp::Remove(_) => OP_REMOVE,
            ArgOp::Rename { .. } => OP_RENAME,
            ArgOp::Renew(_) => OP_RENEW,
            ArgOp::Restorefh => OP_RESTOREFH,
            ArgOp::Savefh => OP_SAVEFH,
            ArgOp::Setattr { .. } => OP_SETATTR,
            ArgOp::Setclientid { .. } => OP_SETCLIENTID,
            ArgOp::SetclientidConfirm { .. } => OP_SETCLIENTID_CONFIRM,
            ArgOp::Write { .. } => OP_WRITE,
            ArgOp::ExchangeId { .. } => OP_EXCHANGE_ID,
            ArgOp::CreateSession { .. } => OP_CREATE_SESSION,
            ArgOp::DestroySession(_) => OP_DESTROY_SESSION,
            ArgOp::BindConn(_) => OP_BIND_CONN_TO_SESSION,
            ArgOp::Sequence { .. } => OP_SEQUENCE,
            ArgOp::DestroyClientid(_) => OP_DESTROY_CLIENTID,
            ArgOp::ReclaimComplete => OP_RECLAIM_COMPLETE,
        }
    }
}

type R<T> = nfsc::Result<T>;

fn get_sid(d: &mut Decoder) -> R<Sid> {
    let seqid = d.get_u32()?;
    let mut other = [0u8; 12];
    other.copy_from_slice(d.get_opaque_fixed(12)?);
    Ok(Sid { seqid, other })
}

fn get_fixed<const N: usize>(d: &mut Decoder) -> R<[u8; N]> {
    let mut v = [0u8; N];
    v.copy_from_slice(d.get_opaque_fixed(N)?);
    Ok(v)
}

fn get_chan(d: &mut Decoder) -> R<Chan> {
    let c = Chan {
        headerpad: d.get_u32()?,
        maxreq: d.get_u32()?,
        maxresp: d.get_u32()?,
        maxresp_cached: d.get_u32()?,
        maxops: d.get_u32()?,
        maxreqs: d.get_u32()?,
    };
    let _rdma: Vec<u32> = d.get_array()?;
    Ok(c)
}

fn get_settime(d: &mut Decoder) -> R<SetTime> {
    Ok(match d.get_u32()? {
        0 => SetTime::ServerNow,
        _ => SetTime::Client(Time {
            seconds: d.get_i64()?,
            nseconds: d.get_u32()?,
        }),
    })
}

/// fattr4 for SETATTR / CREATE / OPEN: size, mode and times are applied;
/// owner strings are accepted and ignored; other attributes are unsupported.
fn get_setattrs(d: &mut Decoder) -> R<SetAttrs> {
    let bitmap: Vec<u32> = d.get_array()?;
    let vals = d.get_opaque()?;
    let mut v = Decoder::new(vals);
    let mut s = SetAttrs {
        bitmap: bitmap.clone(),
        ..SetAttrs::default()
    };
    for n in bits(&bitmap) {
        match n {
            4 => s.size = Some(v.get_u64()?),
            33 => s.mode = Some(v.get_u32()?),
            36 | 37 => {
                v.get_string()?;
            }
            48 => s.atime = Some(get_settime(&mut v)?),
            54 => s.mtime = Some(get_settime(&mut v)?),
            other => {
                s.unsupported = Some(other);
                return Ok(s);
            }
        }
    }
    v.finish()?;
    Ok(s)
}

fn decode_ops(d: &mut Decoder) -> R<Vec<ArgOp>> {
    let n = d.get_u32()?;
    let mut ops = Vec::new();
    for _ in 0..n {
        ops.push(decode_op(d)?);
    }
    d.finish()?;
    Ok(ops)
}

fn decode_op(d: &mut Decoder) -> R<ArgOp> {
    let code = d.get_u32()?;
    Ok(match code {
        OP_ACCESS => {
            d.get_u32()?;
            ArgOp::Access
        }
        OP_CLOSE => ArgOp::Close {
            seqid: d.get_u32()?,
            sid: get_sid(d)?,
        },
        OP_COMMIT => ArgOp::Commit {
            offset: d.get_u64()?,
            count: d.get_u32()?,
        },
        OP_CREATE => {
            let ftype = d.get_u32()?;
            let mut link = Vec::new();
            match ftype {
                5 => link = d.get_string()?,
                3 | 4 => {
                    d.get_u32()?;
                    d.get_u32()?;
                }
                _ => {}
            }
            ArgOp::Create {
                ftype,
                link,
                name: d.get_string()?,
                attrs: get_setattrs(d)?,
            }
        }
        OP_DELEGRETURN => {
            get_sid(d)?;
            ArgOp::DelegReturn
        }
        OP_GETATTR => ArgOp::Getattr(d.get_array()?),
        OP_GETFH => ArgOp::Getfh,
        OP_LINK => ArgOp::Link(d.get_string()?),
        OP_LOOKUP => ArgOp::Lookup(d.get_string()?),
        OP_LOOKUPP => ArgOp::Lookupp,
        OP_OPEN => {
            let seqid = d.get_u32()?;
            let share_access = d.get_u32()?;
            let _deny = d.get_u32()?;
            let clientid = d.get_u64()?;
            let owner = d.get_opaque_vec()?;
            let how = match d.get_u32()? {
                0 => How::NoCreate,
                _ => {
                    let mode = d.get_u32()?;
                    let attrs = match mode {
                        0 | 1 => get_setattrs(d)?,
                        2 => {
                            d.get_opaque_fixed(8)?;
                            SetAttrs::default()
                        }
                        _ => {
                            d.get_opaque_fixed(8)?;
                            get_setattrs(d)?
                        }
                    };
                    How::Create { mode, attrs }
                }
            };
            let claim = match d.get_u32()? {
                0 => OpenClaim::Null(d.get_string()?),
                1 => {
                    d.get_u32()?;
                    OpenClaim::Previous
                }
                2 => {
                    get_sid(d)?;
                    d.get_string()?;
                    OpenClaim::Other(2)
                }
                3 => {
                    d.get_string()?;
                    OpenClaim::Other(3)
                }
                4 => OpenClaim::Fh,
                5 => {
                    get_sid(d)?;
                    OpenClaim::Other(5)
                }
                c => OpenClaim::Other(c),
            };
            ArgOp::Open(OpenArgs {
                seqid,
                share_access,
                clientid,
                owner,
                how,
                claim,
            })
        }
        OP_OPEN_CONFIRM => ArgOp::OpenConfirm {
            sid: get_sid(d)?,
            seqid: d.get_u32()?,
        },
        OP_PUTFH => ArgOp::Putfh(d.get_opaque_vec()?),
        OP_PUTROOTFH => ArgOp::Putrootfh,
        OP_READ => ArgOp::Read {
            sid: get_sid(d)?,
            offset: d.get_u64()?,
            count: d.get_u32()?,
        },
        OP_READDIR => {
            let cookie = d.get_u64()?;
            let verf = get_fixed::<8>(d)?;
            let _dircount = d.get_u32()?;
            let maxcount = d.get_u32()?;
            ArgOp::Readdir {
                cookie,
                verf,
                maxcount,
                attrs: d.get_array()?,
            }
        }
        OP_READLINK => ArgOp::Readlink,
        OP_REMOVE => ArgOp::Remove(d.get_string()?),
        OP_RENAME => ArgOp::Rename {
            from: d.get_string()?,
            to: d.get_string()?,
        },
        OP_RENEW => ArgOp::Renew(d.get_u64()?),
        OP_RESTOREFH => ArgOp::Restorefh,
        OP_SAVEFH => ArgOp::Savefh,
        OP_SETATTR => ArgOp::Setattr {
            sid: get_sid(d)?,
            attrs: get_setattrs(d)?,
        },
        OP_SETCLIENTID => {
            let verf = get_fixed::<8>(d)?;
            let id = d.get_opaque_vec()?;
            let _cb_program = d.get_u32()?;
            let _netid = d.get_string()?;
            let _addr = d.get_string()?;
            let _ident = d.get_u32()?;
            ArgOp::Setclientid { verf, id }
        }
        OP_SETCLIENTID_CONFIRM => ArgOp::SetclientidConfirm {
            clientid: d.get_u64()?,
            verf: get_fixed::<8>(d)?,
        },
        OP_WRITE => ArgOp::Write {
            sid: get_sid(d)?,
            offset: d.get_u64()?,
            stable: d.get_u32()?,
            data: d.get_opaque_vec()?,
        },
        OP_EXCHANGE_ID => {
            let verf = get_fixed::<8>(d)?;
            let owner = d.get_opaque_vec()?;
            let _flags = d.get_u32()?;
            let sp = d.get_u32()?;
            if sp != 0 {
                return Err(Error::Xdr(format!("state_protect {sp} not supported")));
            }
            let n_impl = d.get_u32()?;
            for _ in 0..n_impl {
                d.get_string()?;
                d.get_string()?;
                d.get_i64()?;
                d.get_u32()?;
            }
            ArgOp::ExchangeId { verf, owner }
        }
        OP_CREATE_SESSION => {
            let clientid = d.get_u64()?;
            let seq = d.get_u32()?;
            let _flags = d.get_u32()?;
            let fore = get_chan(d)?;
            let back = get_chan(d)?;
            let _cb_program = d.get_u32()?;
            let n_sec = d.get_u32()?;
            for _ in 0..n_sec {
                match d.get_u32()? {
                    0 => {}
                    1 => {
                        d.get_u32()?;
                        d.get_string()?;
                        d.get_u32()?;
                        d.get_u32()?;
                        let _gids: Vec<u32> = d.get_array()?;
                    }
                    f => return Err(Error::Xdr(format!("callback flavor {f}"))),
                }
            }
            ArgOp::CreateSession {
                clientid,
                seq,
                fore,
                back,
            }
        }
        OP_DESTROY_SESSION => ArgOp::DestroySession(get_fixed::<16>(d)?),
        OP_BIND_CONN_TO_SESSION => {
            let id = get_fixed::<16>(d)?;
            d.get_u32()?;
            d.get_bool()?;
            ArgOp::BindConn(id)
        }
        OP_SEQUENCE => ArgOp::Sequence {
            session: get_fixed::<16>(d)?,
            seqid: d.get_u32()?,
            slot: d.get_u32()?,
            highest: d.get_u32()?,
            cachethis: d.get_bool()?,
        },
        OP_DESTROY_CLIENTID => ArgOp::DestroyClientid(d.get_u64()?),
        OP_RECLAIM_COMPLETE => {
            d.get_bool()?;
            ArgOp::ReclaimComplete
        }
        other => return Err(Error::Xdr(format!("unsupported op {other}"))),
    })
}

// ------------------------------------------------------------ attributes

const SUPPORTED: &[u32] = &[
    0, 1, 4, 8, 10, 11, 19, 20, 21, 22, 23, 30, 31, 33, 35, 36, 37, 41, 42, 43, 44, 45, 47, 52, 53,
];

/// Attribute numbers set in a bitmap4, in increasing order.
fn bits(words: &[u32]) -> Vec<u32> {
    let mut out = Vec::new();
    for (wi, w) in words.iter().enumerate() {
        for b in 0..32u32 {
            if w & (1 << b) != 0 {
                out.push(wi as u32 * 32 + b);
            }
        }
    }
    out
}

fn bitmap_of(attrs: &[u32]) -> Vec<u32> {
    let mut words: Vec<u32> = Vec::new();
    for &a in attrs {
        let w = (a / 32) as usize;
        if words.len() <= w {
            words.resize(w + 1, 0);
        }
        words[w] |= 1 << (a % 32);
    }
    words
}

fn ftype4(t: FileType) -> u32 {
    match t {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::BlockDevice => 3,
        FileType::CharDevice => 4,
        FileType::Symlink => 5,
        FileType::Socket => 6,
        FileType::Fifo => 7,
        FileType::Other(t) => t,
    }
}

fn put_time(e: &mut Encoder, t: Time) {
    e.put_i64(t.seconds).put_u32(t.nseconds);
}

/// fattr4 with the requested attributes this server supports.
fn put_fattr(e: &mut Encoder, requested: &[u32], a: &Attr, fh: &[u8], cfg: &Config) {
    let mut v = Encoder::new();
    let mut got = Vec::new();
    for n in bits(requested) {
        if !SUPPORTED.contains(&n) {
            continue;
        }
        got.push(n);
        match n {
            0 => {
                v.put_array(bitmap_of(SUPPORTED).as_slice());
            }
            1 => {
                v.put_u32(ftype4(a.ftype));
            }
            4 => {
                v.put_u64(a.size);
            }
            8 => {
                v.put_u64(a.fsid).put_u64(0);
            }
            10 => {
                v.put_u32(cfg.lease_secs);
            }
            11 => {
                v.put_u32(0);
            }
            19 => {
                v.put_opaque(fh);
            }
            20 => {
                v.put_u64(a.fileid);
            }
            21..=23 => {
                v.put_u64(1_000_000);
            }
            30 => {
                v.put_u64(u64::from(cfg.maxread));
            }
            31 => {
                v.put_u64(u64::from(cfg.maxwrite));
            }
            33 => {
                v.put_u32(a.mode);
            }
            35 => {
                v.put_u32(a.nlink);
            }
            36 => {
                v.put_string(a.uid.to_string().as_bytes());
            }
            37 => {
                v.put_string(a.gid.to_string().as_bytes());
            }
            41 => {
                v.put_u32(a.rdev.0).put_u32(a.rdev.1);
            }
            42..=44 => {
                v.put_u64(1 << 40);
            }
            45 => {
                v.put_u64(a.used);
            }
            47 => put_time(&mut v, a.atime),
            52 => put_time(&mut v, a.ctime),
            53 => put_time(&mut v, a.mtime),
            _ => unreachable!(),
        }
    }
    e.put_array(bitmap_of(&got).as_slice());
    e.put_opaque(v.as_bytes());
}

fn put_cinfo(e: &mut Encoder, generation: u64) {
    e.put_bool(true)
        .put_u64(generation.wrapping_sub(1))
        .put_u64(generation);
}

fn status_code(s: Status) -> u32 {
    match s {
        Status::Perm => 1,
        Status::NoEnt => 2,
        Status::Io => 5,
        Status::Nxio => 6,
        Status::Access => 13,
        Status::Exist => 17,
        Status::XDev => 18,
        Status::NoDev => 19,
        Status::NotDir => 20,
        Status::IsDir => 21,
        Status::Inval => 22,
        Status::FBig => 27,
        Status::NoSpc => 28,
        Status::Rofs => 30,
        Status::MLink => 31,
        Status::NameTooLong => 63,
        Status::NotEmpty => 66,
        Status::DQuot => 69,
        Status::Stale => 70,
        Status::Remote => 71,
        Status::BadHandle => NFS4ERR_BADHANDLE,
        Status::NotSync => NFS4ERR_INVAL,
        Status::BadCookie => NFS4ERR_BAD_COOKIE,
        Status::NotSupp => NFS4ERR_NOTSUPP,
        Status::TooSmall => NFS4ERR_TOOSMALL,
        Status::ServerFault => NFS4ERR_SERVERFAULT,
        Status::BadType => NFS4ERR_BADTYPE,
        Status::Jukebox => NFS4ERR_DELAY,
        Status::Other(_, c) => c,
    }
}

fn err_code(e: Error) -> u32 {
    match e {
        Error::Nfs(s) => status_code(s),
        _ => NFS4ERR_IO,
    }
}

fn to_setattr(a: &SetAttrs) -> SetAttr {
    SetAttr {
        mode: a.mode,
        size: a.size,
        atime: a.atime,
        mtime: a.mtime,
        ..SetAttr::default()
    }
}

// ------------------------------------------------------------ state ops

/// Check an NFSv4.0 client ID: renews its lease when it is valid.
fn client_live(shared: &Shared, st: &mut State, clientid: u64) -> Result<(), u32> {
    if (clientid >> 32) as u32 != st.boot {
        return Err(NFS4ERR_STALE_CLIENTID);
    }
    let lease = shared.lease();
    match st.clients.get_mut(&clientid) {
        // Like knfsd: an unknown client ID of this boot instance has expired.
        None => Err(NFS4ERR_EXPIRED),
        Some(c) if !c.confirmed => Err(NFS4ERR_STALE_CLIENTID),
        Some(c) if !c.lease_ok(lease) => {
            st.purge_client(clientid);
            Err(NFS4ERR_EXPIRED)
        }
        Some(c) => {
            c.last_renew = Instant::now();
            Ok(())
        }
    }
}

/// Validate a stateid for READ / WRITE / SETATTR on `fh`.
fn check_stateid(
    shared: &Shared,
    st: &mut State,
    ctx: &Ctx,
    sid: &Sid,
    fh: &FileHandle,
    write: bool,
) -> Result<(), u32> {
    if sid.special() {
        if shared.cfg.grace_blocks_anon_io && st.in_grace() {
            return Err(NFS4ERR_GRACE);
        }
        shared.stats.lock().unwrap().anon_io += 1;
        return Ok(());
    }
    let boot = u32::from_be_bytes(sid.other[0..4].try_into().unwrap());
    if boot != st.boot {
        return Err(if ctx.minor == 0 {
            NFS4ERR_STALE_STATEID
        } else {
            NFS4ERR_BAD_STATEID
        });
    }
    let Some(o) = st.opens.get(&sid.other) else {
        if ctx.minor == 0 {
            let low = u32::from_be_bytes(sid.other[4..8].try_into().unwrap());
            let clientid = (u64::from(boot) << 32) | u64::from(low);
            if !st.clients.contains_key(&clientid) {
                // knfsd: the stateid's client is gone (lease expired).
                return Err(NFS4ERR_EXPIRED);
            }
        }
        return Err(NFS4ERR_BAD_STATEID);
    };
    let (clientid, same_fh, oseq, confirmed, access) =
        (o.clientid, o.fh == fh.0, o.seqid, o.confirmed, o.access);
    if ctx.minor == 0 {
        client_live(shared, st, clientid)?;
    } else if ctx.clientid != Some(clientid) {
        return Err(NFS4ERR_BAD_STATEID);
    }
    if !same_fh || !confirmed {
        return Err(NFS4ERR_BAD_STATEID);
    }
    if !(ctx.minor >= 1 && sid.seqid == 0) {
        if sid.seqid > oseq {
            return Err(NFS4ERR_BAD_STATEID);
        }
        if sid.seqid < oseq {
            return Err(NFS4ERR_OLD_STATEID);
        }
    }
    if write && access & OPEN4_SHARE_ACCESS_WRITE == 0 {
        return Err(NFS4ERR_OPENMODE);
    }
    shared.stats.lock().unwrap().stateid_io += 1;
    Ok(())
}

/// Run an NFSv4.0 open-owner seqid-mutating op: replay detection, seqid
/// check, and advancing the seqid unless the result is a non-advancing error.
/// `create` makes a missing owner (OPEN only).
fn owner_op(
    shared: &Shared,
    st: &mut State,
    key: (u64, Vec<u8>),
    seqid: u32,
    opname: &str,
    create: bool,
    f: impl FnOnce(&mut State, bool) -> (u32, Vec<u8>),
) -> (u32, Vec<u8>) {
    let confirmed = match st.owners.get(&key) {
        Some(o) if seqid == o.last => {
            shared.stats.lock().unwrap().owner_replays += 1;
            return o.cache.clone();
        }
        Some(o) if seqid != o.last.wrapping_add(1) => {
            shared.violation(format!(
                "{opname}: open-owner seqid {seqid}, expected {}",
                o.last.wrapping_add(1)
            ));
            return (NFS4ERR_BAD_SEQID, vec![]);
        }
        Some(o) => o.confirmed,
        None => false,
    };
    let r = f(st, confirmed);
    if seqid_advances(r.0) {
        match st.owners.get_mut(&key) {
            Some(o) => {
                o.last = seqid;
                o.cache = r.clone();
            }
            None if create => {
                st.owners.insert(
                    key,
                    OpenOwner {
                        last: seqid,
                        confirmed: false,
                        cache: r.clone(),
                    },
                );
            }
            None => {}
        }
    }
    r
}

fn open_op(shared: &Shared, st: &mut State, ctx: &mut Ctx, a: &OpenArgs) -> (u32, Vec<u8>) {
    let Some(cur) = ctx.cur.clone() else {
        return (NFS4ERR_NOFILEHANDLE, vec![]);
    };
    let clientid = if ctx.minor == 0 {
        if let Err(s) = client_live(shared, st, a.clientid) {
            return (s, vec![]);
        }
        a.clientid
    } else {
        let c = ctx.clientid.expect("sequenced");
        if a.clientid != c && a.clientid != 0 {
            shared.violation(format!(
                "OPEN clientid {:#x} differs from the session's {c:#x}",
                a.clientid
            ));
        }
        c
    };
    if ctx.minor >= 1 {
        let r = open_inner(shared, st, ctx, clientid, a, &cur, true);
        return r;
    }
    let key = (clientid, a.owner.clone());
    let mut new_cur = None;
    let r = owner_op(shared, st, key, a.seqid, "OPEN", true, |st, confirmed| {
        let mut c = Ctx {
            minor: 0,
            cur: Some(cur.clone()),
            saved: None,
            clientid: None,
            session: None,
            slot: None,
            cachethis: false,
        };
        let r = open_inner(shared, st, &mut c, clientid, a, &cur, confirmed);
        new_cur = c.cur;
        r
    });
    if r.0 == NFS4_OK {
        ctx.cur = new_cur;
    }
    r
}

fn open_inner(
    shared: &Shared,
    st: &mut State,
    ctx: &mut Ctx,
    clientid: u64,
    a: &OpenArgs,
    cur: &FileHandle,
    owner_confirmed: bool,
) -> (u32, Vec<u8>) {
    macro_rules! tryfs {
        ($x:expr) => {
            match $x {
                Ok(v) => v,
                Err(e) => return (err_code(e), vec![]),
            }
        };
    }
    if !matches!(a.claim, OpenClaim::Previous) && st.in_grace() {
        return (NFS4ERR_GRACE, vec![]);
    }
    let mut created = false;
    let fh = match &a.claim {
        OpenClaim::Null(name) => match &a.how {
            How::NoCreate => tryfs!(st.fs.lookup(cur, name)).0,
            How::Create { mode, attrs } => match st.fs.lookup(cur, name) {
                Ok((fh, _)) if *mode == 0 => fh,
                Ok(_) => return (NFS4ERR_EXIST, vec![]),
                Err(Error::Nfs(Status::NoEnt)) => {
                    let cm = match mode {
                        0 => CreateMode::Unchecked,
                        1 => CreateMode::Guarded,
                        _ => CreateMode::Exclusive,
                    };
                    created = true;
                    tryfs!(st.fs.create(cur, name, cm, &to_setattr(attrs))).0
                }
                Err(e) => return (err_code(e), vec![]),
            },
        },
        OpenClaim::Fh if ctx.minor >= 1 => cur.clone(),
        OpenClaim::Previous => return (NFS4ERR_NOTSUPP, vec![]),
        _ => {
            shared.violation("OPEN claim not valid for this minor version".into());
            return (NFS4ERR_NOTSUPP, vec![]);
        }
    };
    if created {
        st.namespace_changed();
    }
    let attr = tryfs!(st.fs.getattr(&fh));
    match attr.ftype {
        FileType::Regular => {}
        FileType::Directory => return (NFS4ERR_ISDIR, vec![]),
        FileType::Symlink => return (NFS4ERR_SYMLINK, vec![]),
        _ => return (NFS4ERR_INVAL, vec![]),
    }
    let existing = st
        .opens
        .iter_mut()
        .find(|(_, o)| o.clientid == clientid && o.owner == a.owner && o.fh == fh.0);
    let (sid, confirmed) = match existing {
        Some((other, o)) => {
            o.access |= a.share_access;
            o.seqid += 1;
            (
                Sid {
                    seqid: o.seqid,
                    other: *other,
                },
                o.confirmed,
            )
        }
        None => {
            let mut other = [0u8; 12];
            other[0..4].copy_from_slice(&st.boot.to_be_bytes());
            other[4..8].copy_from_slice(&(clientid as u32).to_be_bytes());
            other[8..12].copy_from_slice(&st.next().to_be_bytes());
            let confirmed = ctx.minor >= 1 || !shared.cfg.open_confirm || owner_confirmed;
            st.opens.insert(
                other,
                Open {
                    clientid,
                    owner: a.owner.clone(),
                    fh: fh.0.clone(),
                    seqid: 1,
                    access: a.share_access,
                    confirmed,
                },
            );
            (Sid { seqid: 1, other }, confirmed)
        }
    };
    let mut rflags = OPEN4_RESULT_LOCKTYPE_POSIX;
    if !confirmed {
        rflags |= OPEN4_RESULT_CONFIRM;
    }
    ctx.cur = Some(fh);
    let mut e = Encoder::new();
    sid.put(&mut e);
    put_cinfo(&mut e, st.dir_gen);
    e.put_u32(rflags);
    e.put_u32(0); // attrset: empty bitmap
    e.put_u32(0); // OPEN_DELEGATE_NONE
    (NFS4_OK, e.into_inner())
}

/// Look up an open by stateid for OPEN_CONFIRM / CLOSE (no seqid checks).
fn find_open(st: &State, ctx: &Ctx, sid: &Sid) -> Result<(u64, Vec<u8>), u32> {
    let boot = u32::from_be_bytes(sid.other[0..4].try_into().unwrap());
    if boot != st.boot {
        return Err(if ctx.minor == 0 {
            NFS4ERR_STALE_STATEID
        } else {
            NFS4ERR_BAD_STATEID
        });
    }
    match st.opens.get(&sid.other) {
        Some(o) => Ok((o.clientid, o.owner.clone())),
        None => Err(NFS4ERR_BAD_STATEID),
    }
}

/// Check a stateid's seqid against its open (`fh` must match too).
fn sid_current(st: &State, ctx: &Ctx, sid: &Sid, fh: &FileHandle) -> Result<(), u32> {
    let o = st.opens.get(&sid.other).ok_or(NFS4ERR_BAD_STATEID)?;
    if o.fh != fh.0 {
        return Err(NFS4ERR_BAD_STATEID);
    }
    if ctx.minor >= 1 && sid.seqid == 0 {
        return Ok(());
    }
    if sid.seqid > o.seqid {
        Err(NFS4ERR_BAD_STATEID)
    } else if sid.seqid < o.seqid {
        Err(NFS4ERR_OLD_STATEID)
    } else {
        Ok(())
    }
}

fn open_confirm(
    shared: &Shared,
    st: &mut State,
    ctx: &Ctx,
    sid: Sid,
    seqid: u32,
) -> (u32, Vec<u8>) {
    let Some(fh) = ctx.cur.clone() else {
        return (NFS4ERR_NOFILEHANDLE, vec![]);
    };
    let key = match find_open(st, ctx, &sid) {
        Ok(k) => k,
        Err(s) => return (s, vec![]),
    };
    if let Err(s) = client_live(shared, st, key.0) {
        return (s, vec![]);
    }
    let owner_key = key.clone();
    owner_op(shared, st, key, seqid, "OPEN_CONFIRM", false, |st, _| {
        if let Err(s) = sid_current(st, ctx, &sid, &fh) {
            return (s, vec![]);
        }
        let o = st.opens.get_mut(&sid.other).unwrap();
        if o.confirmed {
            return (NFS4ERR_BAD_STATEID, vec![]);
        }
        o.confirmed = true;
        o.seqid += 1;
        let new = Sid {
            seqid: o.seqid,
            other: sid.other,
        };
        if let Some(ow) = st.owners.get_mut(&owner_key) {
            ow.confirmed = true;
        }
        let mut e = Encoder::new();
        new.put(&mut e);
        (NFS4_OK, e.into_inner())
    })
}

fn close(shared: &Shared, st: &mut State, ctx: &Ctx, sid: Sid, seqid: u32) -> (u32, Vec<u8>) {
    let Some(fh) = ctx.cur.clone() else {
        return (NFS4ERR_NOFILEHANDLE, vec![]);
    };
    let key = match find_open(st, ctx, &sid) {
        Ok(k) => k,
        Err(s) => return (s, vec![]),
    };
    if ctx.minor >= 1 && ctx.clientid != Some(key.0) {
        return (NFS4ERR_BAD_STATEID, vec![]);
    }
    let body = |st: &mut State, _: bool| -> (u32, Vec<u8>) {
        if let Err(s) = sid_current(st, ctx, &sid, &fh) {
            return (s, vec![]);
        }
        let o = st.opens.remove(&sid.other).unwrap();
        let mut e = Encoder::new();
        Sid {
            seqid: o.seqid.wrapping_add(1),
            other: sid.other,
        }
        .put(&mut e);
        (NFS4_OK, e.into_inner())
    };
    if ctx.minor >= 1 {
        return body(st, true);
    }
    if let Err(s) = client_live(shared, st, key.0) {
        return (s, vec![]);
    }
    owner_op(shared, st, key, seqid, "CLOSE", false, body)
}

// ------------------------------------------------------------- exec ops

fn exec_op(
    shared: &Shared,
    st: &mut State,
    ctx: &mut Ctx,
    op: &ArgOp,
    read_fault: Option<u32>,
) -> (u32, Vec<u8>) {
    macro_rules! need_fh {
        () => {
            match &ctx.cur {
                Some(f) => f.clone(),
                None => return (NFS4ERR_NOFILEHANDLE, vec![]),
            }
        };
    }
    macro_rules! tryfs {
        ($x:expr) => {
            match $x {
                Ok(v) => v,
                Err(e) => return (err_code(e), vec![]),
            }
        };
    }
    macro_rules! tryst {
        ($x:expr) => {
            if let Err(s) = $x {
                return (s, vec![]);
            }
        };
    }
    let cfg = &shared.cfg;
    let mut e = Encoder::new();
    match op {
        ArgOp::Access => {
            let fh = need_fh!();
            tryfs!(st.fs.getattr(&fh));
            e.put_u32(0x3f).put_u32(0x3f);
        }
        ArgOp::Putrootfh => ctx.cur = Some(st.fs.root()),
        ArgOp::Putfh(fh) => {
            let fh = FileHandle(fh.clone());
            match st.fs.getattr(&fh) {
                Ok(_) => ctx.cur = Some(fh),
                Err(Error::Nfs(Status::BadHandle)) => return (NFS4ERR_BADHANDLE, vec![]),
                Err(_) => return (NFS4ERR_STALE, vec![]),
            }
        }
        ArgOp::Getfh => {
            let fh = need_fh!();
            e.put_opaque(&fh.0);
        }
        ArgOp::Savefh => ctx.saved = Some(need_fh!()),
        ArgOp::Restorefh => match &ctx.saved {
            Some(f) => ctx.cur = Some(f.clone()),
            None => return (NFS4ERR_RESTOREFH, vec![]),
        },
        ArgOp::Lookup(name) => {
            let dir = need_fh!();
            let a = tryfs!(st.fs.getattr(&dir));
            if a.ftype != FileType::Directory {
                return (NFS4ERR_NOTDIR, vec![]);
            }
            if name.is_empty() || name == b"." || name == b".." {
                return (NFS4ERR_INVAL, vec![]);
            }
            ctx.cur = Some(tryfs!(st.fs.lookup(&dir, name)).0);
        }
        ArgOp::Lookupp => {
            let dir = need_fh!();
            if dir == st.fs.root() {
                return (NFS4ERR_NOENT, vec![]);
            }
            ctx.cur = Some(tryfs!(st.fs.lookup(&dir, b"..")).0);
        }
        ArgOp::Getattr(req) => {
            let fh = need_fh!();
            let a = tryfs!(st.fs.getattr(&fh));
            put_fattr(&mut e, req, &a, &fh.0, cfg);
        }
        ArgOp::Setattr { sid, attrs } => {
            let fh = need_fh!();
            if let Some(n) = attrs.unsupported {
                let _ = n;
                return (NFS4ERR_ATTRNOTSUPP, vec![0, 0, 0, 0]);
            }
            if attrs.size.is_some() {
                if let Err(s) = check_stateid(shared, st, ctx, sid, &fh, true) {
                    return (s, vec![0, 0, 0, 0]);
                }
                if st.patterns.contains_key(&fh.0) {
                    return (NFS4ERR_ROFS, vec![0, 0, 0, 0]);
                }
            }
            if let Err(err) = st.fs.setattr(&fh, &to_setattr(attrs)) {
                return (err_code(err), vec![0, 0, 0, 0]);
            }
            e.put_array(attrs.bitmap.as_slice());
        }
        ArgOp::Readlink => {
            let fh = need_fh!();
            let t = tryfs!(st.fs.readlink(&fh));
            e.put_string(&t);
        }
        ArgOp::Read { sid, offset, count } => {
            let fh = need_fh!();
            tryst!(check_stateid(shared, st, ctx, sid, &fh, false));
            if *count > cfg.maxread {
                shared.violation(format!("READ count {count} > maxread {}", cfg.maxread));
            }
            {
                let mut s = shared.stats.lock().unwrap();
                s.max_read_count = s.max_read_count.max(*count);
            }
            let count = (*count).min(cfg.maxread);
            let a = tryfs!(st.fs.getattr(&fh));
            if a.ftype == FileType::Directory {
                return (NFS4ERR_ISDIR, vec![]);
            }
            let (mut data, mut eof) = match st.patterns.get(&fh.0) {
                Some(&seed) => {
                    let end = offset.saturating_add(u64::from(count)).min(a.size);
                    let start = (*offset).min(end);
                    (pattern(seed, start, (end - start) as usize), end >= a.size)
                }
                None => tryfs!(st.fs.read(&fh, *offset, count)),
            };
            if let Some(n) = read_fault {
                data.truncate(n as usize);
                eof = false;
            }
            e.put_bool(eof).put_opaque(&data);
        }
        ArgOp::Write {
            sid,
            offset,
            stable,
            data,
        } => {
            let fh = need_fh!();
            tryst!(check_stateid(shared, st, ctx, sid, &fh, true));
            if data.len() as u32 > cfg.maxwrite {
                shared.violation(format!(
                    "WRITE of {} bytes > maxwrite {}",
                    data.len(),
                    cfg.maxwrite
                ));
            }
            {
                let mut s = shared.stats.lock().unwrap();
                s.max_write_len = s.max_write_len.max(data.len() as u32);
                if *stable == UNSTABLE4 {
                    s.unstable_writes += 1;
                }
            }
            if st.patterns.contains_key(&fh.0) {
                return (NFS4ERR_ROFS, vec![]);
            }
            let n = tryfs!(st.fs.write(&fh, *offset, data));
            let committed = if *stable == UNSTABLE4 {
                st.uncommitted.push((fh.0.clone(), *offset, n as usize));
                UNSTABLE4
            } else {
                FILE_SYNC4
            };
            e.put_u32(n).put_u32(committed).put_u64(st.write_verf);
        }
        ArgOp::Commit { .. } => {
            let fh = need_fh!();
            tryfs!(st.fs.getattr(&fh));
            st.uncommitted.retain(|(h, _, _)| *h != fh.0);
            e.put_u64(st.write_verf);
        }
        ArgOp::Create {
            ftype,
            link,
            name,
            attrs,
        } => {
            let dir = need_fh!();
            let sa = to_setattr(attrs);
            let (fh, _) = match ftype {
                2 => tryfs!(st.fs.mkdir(&dir, name, &sa)),
                5 => tryfs!(st.fs.symlink(&dir, name, link, &sa)),
                _ => return (NFS4ERR_BADTYPE, vec![]),
            };
            st.namespace_changed();
            put_cinfo(&mut e, st.dir_gen);
            e.put_array(attrs.bitmap.as_slice());
            ctx.cur = Some(fh);
        }
        ArgOp::Remove(name) => {
            let dir = need_fh!();
            let (_, a) = tryfs!(st.fs.lookup(&dir, name));
            if a.ftype == FileType::Directory {
                tryfs!(st.fs.rmdir(&dir, name));
            } else {
                tryfs!(st.fs.remove(&dir, name));
            }
            st.namespace_changed();
            put_cinfo(&mut e, st.dir_gen);
        }
        ArgOp::Rename { from, to } => {
            let to_dir = need_fh!();
            let Some(from_dir) = ctx.saved.clone() else {
                return (NFS4ERR_NOFILEHANDLE, vec![]);
            };
            tryfs!(st.fs.rename(&from_dir, from, &to_dir, to));
            st.namespace_changed();
            put_cinfo(&mut e, st.dir_gen);
            put_cinfo(&mut e, st.dir_gen);
        }
        ArgOp::Link(name) => {
            let dir = need_fh!();
            let Some(target) = ctx.saved.clone() else {
                return (NFS4ERR_NOFILEHANDLE, vec![]);
            };
            tryfs!(st.fs.link(&target, &dir, name));
            st.namespace_changed();
            put_cinfo(&mut e, st.dir_gen);
        }
        ArgOp::Readdir {
            cookie,
            verf,
            maxcount,
            attrs,
        } => return readdir(shared, st, ctx, *cookie, *verf, *maxcount, attrs),
        ArgOp::Open(a) => return open_op(shared, st, ctx, a),
        ArgOp::OpenConfirm { sid, seqid } => return open_confirm(shared, st, ctx, *sid, *seqid),
        ArgOp::Close { seqid, sid } => return close(shared, st, ctx, *sid, *seqid),
        ArgOp::DelegReturn => return (NFS4ERR_BAD_STATEID, vec![]),
        ArgOp::Renew(clientid) => tryst!(client_live(shared, st, *clientid)),
        ArgOp::Setclientid { verf, id } => {
            // A new unconfirmed record; older unconfirmed ones for the id go.
            let stale: Vec<u64> = st
                .clients
                .iter()
                .filter(|(_, c)| !c.v41 && c.owner == *id && !c.confirmed)
                .map(|(k, _)| *k)
                .collect();
            for k in stale {
                st.purge_client(k);
            }
            let clientid = st.new_clientid();
            let confirm = (u64::from(st.next()) ^ 0x5a5a_0000_0000_5a5a).to_be_bytes();
            st.clients.insert(
                clientid,
                Client {
                    owner: id.clone(),
                    verifier: *verf,
                    confirm,
                    confirmed: false,
                    v41: false,
                    last_renew: Instant::now(),
                    expired: false,
                    create_seq: 0,
                    create_cache: None,
                    reclaim_complete: false,
                },
            );
            e.put_u64(clientid).put_opaque_fixed(&confirm);
        }
        ArgOp::SetclientidConfirm { clientid, verf } => {
            let Some(c) = st.clients.get_mut(clientid) else {
                return (NFS4ERR_STALE_CLIENTID, vec![]);
            };
            if c.confirm != *verf {
                return (NFS4ERR_STALE_CLIENTID, vec![]);
            }
            c.confirmed = true;
            c.expired = false;
            c.last_renew = Instant::now();
            let owner = c.owner.clone();
            // The client rebooted: its earlier records and their state go.
            let old: Vec<u64> = st
                .clients
                .iter()
                .filter(|(k, c)| **k != *clientid && !c.v41 && c.owner == owner)
                .map(|(k, _)| *k)
                .collect();
            for k in old {
                st.purge_client(k);
            }
        }
        ArgOp::ExchangeId { verf, owner } => {
            let existing = st
                .clients
                .iter()
                .find(|(_, c)| c.v41 && c.owner == *owner)
                .map(|(k, c)| (*k, c.verifier == *verf));
            let clientid = match existing {
                Some((k, true)) => k,
                other => {
                    if let Some((k, false)) = other {
                        // Same owner, new verifier: the client rebooted.
                        st.purge_client(k);
                    }
                    let k = st.new_clientid();
                    st.clients.insert(
                        k,
                        Client {
                            owner: owner.clone(),
                            verifier: *verf,
                            confirm: [0; 8],
                            confirmed: false,
                            v41: true,
                            last_renew: Instant::now(),
                            expired: false,
                            create_seq: 1,
                            create_cache: None,
                            reclaim_complete: false,
                        },
                    );
                    k
                }
            };
            let c = &st.clients[&clientid];
            let mut flags = EXCHGID4_FLAG_USE_NON_PNFS;
            if c.confirmed {
                flags |= EXCHGID4_FLAG_CONFIRMED_R;
            }
            e.put_u64(clientid).put_u32(c.create_seq).put_u32(flags);
            e.put_u32(0); // SP4_NONE
            e.put_u64(0).put_opaque(b"nfs4fake");
            e.put_opaque(b"nfs4fake");
            e.put_u32(0); // no server_impl_id
        }
        ArgOp::CreateSession {
            clientid,
            seq,
            fore,
            back,
        } => {
            if (*clientid >> 32) as u32 != st.boot {
                return (NFS4ERR_STALE_CLIENTID, vec![]);
            }
            let boot = st.boot;
            let counter = st.next();
            let Some(c) = st.clients.get_mut(clientid).filter(|c| c.v41) else {
                return (NFS4ERR_STALE_CLIENTID, vec![]);
            };
            if *seq == c.create_seq.wrapping_sub(1)
                && let Some(cached) = &c.create_cache
            {
                return (NFS4_OK, cached.clone());
            }
            if *seq != c.create_seq {
                let want = c.create_seq;
                shared.violation(format!(
                    "CREATE_SESSION csa_sequence {seq}, expected {want}"
                ));
                return (NFS4ERR_SEQ_MISORDERED, vec![]);
            }
            let mut id = [0u8; 16];
            id[0..4].copy_from_slice(&boot.to_be_bytes());
            id[4..12].copy_from_slice(&clientid.to_be_bytes());
            id[12..16].copy_from_slice(&counter.to_be_bytes());
            let nslots = fore.maxreqs.min(cfg.slots).max(1);
            e.put_opaque_fixed(&id).put_u32(*seq).put_u32(0);
            e.put_u32(0)
                .put_u32(fore.maxreq.min(CHAN_MAX))
                .put_u32(fore.maxresp.min(CHAN_MAX))
                .put_u32(fore.maxresp_cached.min(64 << 10))
                .put_u32(fore.maxops.min(64))
                .put_u32(nslots)
                .put_u32(0);
            e.put_u32(back.headerpad)
                .put_u32(back.maxreq)
                .put_u32(back.maxresp)
                .put_u32(back.maxresp_cached)
                .put_u32(back.maxops)
                .put_u32(back.maxreqs)
                .put_u32(0);
            c.create_seq = c.create_seq.wrapping_add(1);
            c.confirmed = true;
            c.expired = false;
            c.last_renew = Instant::now();
            c.create_cache = Some(e.as_bytes().to_vec());
            let slots = (0..nslots)
                .map(|_| Slot {
                    seqid: 0,
                    request: Vec::new(),
                    cachethis: false,
                    reply: None,
                })
                .collect();
            st.sessions.insert(
                id,
                Session {
                    clientid: *clientid,
                    slots,
                },
            );
        }
        ArgOp::BindConn(id) => {
            if !st.sessions.contains_key(id) {
                return (NFS4ERR_BADSESSION, vec![]);
            }
            // Connections are never required to be bound; accept as is.
            e.put_opaque_fixed(id).put_u32(1).put_bool(false);
        }
        ArgOp::DestroySession(id) => {
            if st.sessions.remove(id).is_none() {
                return (NFS4ERR_BADSESSION, vec![]);
            }
        }
        ArgOp::DestroyClientid(id) => {
            if !st.clients.contains_key(id) {
                return (NFS4ERR_STALE_CLIENTID, vec![]);
            }
            if st.sessions.values().any(|s| s.clientid == *id) {
                return (NFS4ERR_CLIENTID_BUSY, vec![]);
            }
            st.purge_client(*id);
        }
        ArgOp::ReclaimComplete => {
            let Some(c) = ctx.clientid.and_then(|id| st.clients.get_mut(&id)) else {
                return (NFS4ERR_STALE_CLIENTID, vec![]);
            };
            if c.reclaim_complete {
                return (NFS4ERR_COMPLETE_ALREADY, vec![]);
            }
            c.reclaim_complete = true;
        }
        ArgOp::Sequence { .. } => unreachable!("SEQUENCE is handled by compound()"),
    }
    (NFS4_OK, e.into_inner())
}

/// Entries of a directory in name order (no "." / ".."), cached.
fn listing(st: &mut State, dir: &FileHandle) -> nfsc::Result<Arc<Vec<Listed>>> {
    if let Some(l) = st.listings.get(&dir.0) {
        return Ok(Arc::clone(l));
    }
    let entries = st.fs.readdir(dir)?;
    let out: Vec<Listed> = entries
        .into_iter()
        .map(|ent| Listed {
            name: ent.name,
            fh: ent.handle.expect("memfs readdir gives handles"),
            attr: ent.attr.expect("memfs readdir gives attrs"),
        })
        .collect();
    let l = Arc::new(out);
    st.listings.insert(dir.0.clone(), Arc::clone(&l));
    Ok(l)
}

fn readdir(
    shared: &Shared,
    st: &mut State,
    ctx: &Ctx,
    cookie: u64,
    verf: [u8; 8],
    maxcount: u32,
    attrs: &[u32],
) -> (u32, Vec<u8>) {
    let Some(dir) = ctx.cur.clone() else {
        return (NFS4ERR_NOFILEHANDLE, vec![]);
    };
    match st.fs.getattr(&dir) {
        Ok(a) if a.ftype == FileType::Directory => {}
        Ok(_) => return (NFS4ERR_NOTDIR, vec![]),
        Err(e) => return (err_code(e), vec![]),
    }
    let cur_verf = st.dir_gen.to_be_bytes();
    if cookie == 0 && verf != [0; 8] {
        shared.violation("READDIR cookie 0 with a non-zero verifier".into());
    }
    if cookie != 0 && verf != cur_verf {
        return (NFS4ERR_BAD_COOKIE, vec![]);
    }
    let list = match listing(st, &dir) {
        Ok(l) => l,
        Err(e) => return (err_code(e), vec![]),
    };
    let start = match cookie {
        0 => 0,
        c if c < FIRST_COOKIE => return (NFS4ERR_BAD_COOKIE, vec![]),
        c => (c - FIRST_COOKIE + 1) as usize,
    };
    if start > list.len() {
        return (NFS4ERR_BAD_COOKIE, vec![]);
    }
    // verifier + list terminator + eof
    let mut used = 8 + 4 + 4;
    let mut entries = Encoder::new();
    let mut i = start;
    while i < list.len() {
        let l = &list[i];
        let mut one = Encoder::new();
        one.put_bool(true)
            .put_u64(i as u64 + FIRST_COOKIE)
            .put_string(&l.name);
        put_fattr(&mut one, attrs, &l.attr, &l.fh.0, &shared.cfg);
        if used + one.len() > maxcount as usize {
            break;
        }
        used += one.len();
        entries.put_opaque_fixed(one.as_bytes());
        i += 1;
    }
    if i == start && start < list.len() {
        return (NFS4ERR_TOOSMALL, vec![]);
    }
    {
        let mut s = shared.stats.lock().unwrap();
        s.readdir_pages += 1;
        s.readdir_max_entries = s.readdir_max_entries.max(i - start);
    }
    let mut e = Encoder::new();
    e.put_opaque_fixed(&cur_verf);
    e.put_opaque_fixed(entries.as_bytes());
    e.put_bool(false).put_bool(i >= list.len());
    (NFS4_OK, e.into_inner())
}
