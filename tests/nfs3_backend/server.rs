//! In-process NFSv3 + MOUNTv3 + portmap v2 server for backend tests.
//!
//! One server answers all three programs on one 127.0.0.1 port number, over
//! TCP (record marking) and UDP. With [`Config::portmap_on_111`] or
//! [`Config::nfs_on_2049`] it also listens on those well-known ports; that
//! needs a private network namespace (see the test file's `in_netns`).
//!
//! The tree is a [`nfsc::memfs::MemFs`]: handles are its 8-byte ids and the
//! export `/export` is its root. On top of it the server adds:
//!
//! - pattern files: content is [`pattern_byte`]`(seed, offset)`, computed on
//!   the fly, so a file of any size (well past 4 GiB) costs no memory;
//! - UNSTABLE write tracking: data written UNSTABLE is stored at once but
//!   remembered until a COMMIT. [`Fault::BumpVerifier`] changes the write
//!   verifier and overwrites every uncommitted range with `0xEE`, as a server
//!   reboot would lose it, so a client that does not resend is caught;
//! - per-request fault injection through a script of [`Rule`]s or a closure
//!   hook (see [`Fault`]);
//! - counters and limit checks in [`Stats`] (for example READs larger than
//!   the advertised `rtmax`).

#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nfsc::error::Error;
use nfsc::fs::{
    Attr, CreateMode, FileHandle, FileType, Filesystem, SetAttr, SetTime, Status, Time,
};
use nfsc::memfs::MemFs;
use nfsc::rpc::Proto;
use nfsc::xdr::{Decoder, Encoder};

pub const PMAP_PROG: u32 = 100000;
pub const NFS_PROG: u32 = 100003;
pub const MOUNT_PROG: u32 = 100005;

pub const EXPORT: &str = "/export";

// NFSv3 procedures.
pub const NULL: u32 = 0;
pub const GETATTR: u32 = 1;
pub const SETATTR: u32 = 2;
pub const LOOKUP: u32 = 3;
pub const ACCESS: u32 = 4;
pub const READLINK: u32 = 5;
pub const READ: u32 = 6;
pub const WRITE: u32 = 7;
pub const CREATE: u32 = 8;
pub const MKDIR: u32 = 9;
pub const SYMLINK: u32 = 10;
pub const REMOVE: u32 = 12;
pub const RMDIR: u32 = 13;
pub const RENAME: u32 = 14;
pub const LINK: u32 = 15;
pub const READDIR: u32 = 16;
pub const READDIRPLUS: u32 = 17;
pub const FSSTAT: u32 = 18;
pub const FSINFO: u32 = 19;
pub const COMMIT: u32 = 21;

// MOUNT procedures.
pub const MNT: u32 = 1;
pub const UMNT: u32 = 3;
pub const MOUNT_EXPORT: u32 = 5;

// Portmap procedures.
pub const GETPORT: u32 = 3;

// nfsstat3 values used by tests.
pub const NFS3ERR_IO: u32 = 5;
pub const NFS3ERR_ROFS: u32 = 30;
pub const NFS3ERR_BAD_COOKIE: u32 = 10003;
pub const NFS3ERR_NOTSUPP: u32 = 10004;
pub const NFS3ERR_TOOSMALL: u32 = 10005;
pub const NFS3ERR_SERVERFAULT: u32 = 10006;
pub const NFS3ERR_JUKEBOX: u32 = 10008;

// accept_stat values.
pub const ACCEPT_SUCCESS: u32 = 0;
pub const ACCEPT_PROG_UNAVAIL: u32 = 1;
pub const ACCEPT_PROG_MISMATCH: u32 = 2;
pub const ACCEPT_PROC_UNAVAIL: u32 = 3;
pub const ACCEPT_GARBAGE_ARGS: u32 = 4;

const UNSTABLE: u32 = 0;
const FILE_SYNC: u32 = 2;

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

/// What FSINFO advertises.
#[derive(Debug, Clone, Copy)]
pub struct Fsinfo {
    pub rtmax: u32,
    pub rtpref: u32,
    pub wtmax: u32,
    pub wtpref: u32,
    pub dtpref: u32,
}

impl Default for Fsinfo {
    fn default() -> Self {
        Fsinfo {
            rtmax: 1 << 20,
            rtpref: 64 << 10,
            wtmax: 1 << 20,
            wtpref: 64 << 10,
            dtpref: 8 << 10,
        }
    }
}

/// Server set-up. `Default` serves everything on one ephemeral port only.
#[derive(Debug, Clone)]
pub struct Config {
    pub fsinfo: Fsinfo,
    /// Which (program, transport) pairs the portmapper reports as registered.
    pub register_nfs_tcp: bool,
    pub register_nfs_udp: bool,
    pub register_mount_tcp: bool,
    pub register_mount_udp: bool,
    /// Also listen on 127.0.0.1:111 (TCP and UDP). Needs a private netns.
    pub portmap_on_111: bool,
    /// Also listen on 127.0.0.1:2049 (TCP and UDP). Needs a private netns.
    pub nfs_on_2049: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            fsinfo: Fsinfo::default(),
            register_nfs_tcp: true,
            register_nfs_udp: true,
            register_mount_tcp: true,
            register_mount_udp: true,
            portmap_on_111: false,
            nfs_on_2049: false,
        }
    }
}

/// One request as the fault hook sees it.
#[derive(Debug, Clone)]
pub struct Call {
    pub prog: u32,
    pub vers: u32,
    pub proc_: u32,
    pub proto: Proto,
    /// 1-based count of calls to this (prog, proc), this one included.
    pub seq: usize,
    /// First argument when it is a file handle (NFS procedures).
    pub fh: Vec<u8>,
    /// READ / WRITE / COMMIT offset.
    pub offset: u64,
    /// READ / COMMIT count, WRITE data length.
    pub count: u32,
    /// READDIR / READDIRPLUS cookie.
    pub cookie: u64,
}

/// What to do to one request instead of (or before) answering it normally.
#[derive(Debug, Clone)]
pub enum Fault {
    /// Answer with this nfsstat3 (or mountstat3) and an empty failure arm.
    Status(u32),
    /// Answer with this accept_stat (PROC_UNAVAIL, GARBAGE_ARGS, ...).
    Accept(u32),
    /// Sleep, then answer normally.
    Delay(Duration),
    /// Close the connection without answering (UDP: no reply).
    Drop,
    /// Never answer; keep the connection open.
    Silent,
    /// Send only the first `n` bytes of the reply record (header included),
    /// then close the connection. UDP: no reply.
    Truncate(usize),
    /// READ: return at most `n` bytes and eof = false.
    ShortRead(u32),
    /// READ: report `count` as the data length plus `n`.
    CountOverData(u32),
    /// Change the write verifier (losing uncommitted data), then answer normally.
    BumpVerifier,
    /// Drop every connection and refuse new ones for the duration (the UDP
    /// socket ignores requests meanwhile), then listen on the same ports again.
    Restart(Duration),
}

type Filter = Arc<dyn Fn(&Call) -> bool + Send + Sync>;

/// One entry of a fault script. Matches calls to `prog`/`proc_` (and the
/// optional filter); skips the first `after` matches, then fires `times` times.
#[derive(Clone)]
pub struct Rule {
    prog: u32,
    proc_: u32,
    after: usize,
    times: usize,
    fault: Fault,
    filter: Option<Filter>,
}

impl Rule {
    /// A rule for NFS procedure `proc_` that fires on every match.
    pub fn nfs(proc_: u32, fault: Fault) -> Rule {
        Rule::prog(NFS_PROG, proc_, fault)
    }

    pub fn prog(prog: u32, proc_: u32, fault: Fault) -> Rule {
        Rule {
            prog,
            proc_,
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
    /// Calls per (prog, proc).
    pub calls: HashMap<(u32, u32), usize>,
    /// Calls per (prog, transport).
    pub by_proto: HashMap<(u32, Proto), usize>,
    /// Largest READ `count` and WRITE data length requested.
    pub max_read_count: u32,
    pub max_write_len: u32,
    /// Requests that exceeded FSINFO's rtmax / wtmax.
    pub rtmax_violations: usize,
    pub wtmax_violations: usize,
    /// Portmap GETPORT questions: (prog, vers, prot, answer).
    pub getport: Vec<(u32, u32, u32, u32)>,
    pub tcp_connections: usize,
    /// UNSTABLE writes received, and data bytes in them.
    pub unstable_writes: usize,
    pub unstable_bytes: u64,
    pub faults_fired: usize,
}

impl Stats {
    pub fn nfs(&self, proc_: u32) -> usize {
        self.calls.get(&(NFS_PROG, proc_)).copied().unwrap_or(0)
    }

    pub fn mount(&self, proc_: u32) -> usize {
        self.calls.get(&(MOUNT_PROG, proc_)).copied().unwrap_or(0)
    }

    pub fn prog_over(&self, prog: u32, proto: Proto) -> usize {
        self.by_proto.get(&(prog, proto)).copied().unwrap_or(0)
    }
}

struct Listed {
    name: Vec<u8>,
    fileid: u64,
    fh: FileHandle,
    attr: Attr,
}

struct State {
    fs: MemFs,
    /// Pattern files: handle -> seed.
    patterns: HashMap<Vec<u8>, u64>,
    /// UNSTABLE writes not yet covered by a COMMIT: (handle, offset, len).
    uncommitted: Vec<(Vec<u8>, u64, usize)>,
    verf: u64,
    /// Directory listings, rebuilt after any change.
    listings: HashMap<Vec<u8>, Arc<Vec<Listed>>>,
}

struct Shared {
    cfg: Config,
    state: Mutex<State>,
    stats: Mutex<Stats>,
    script: Mutex<Vec<Rule>>,
    hook: Mutex<Option<Hook>>,
    /// While set and in the future, listeners are closed.
    down_until: Mutex<Option<Instant>>,
    /// Open TCP connections, so a restart can cut them.
    conns: Mutex<Vec<TcpStream>>,
    stop: AtomicBool,
    port: u16,
}

pub struct FakeNfs3 {
    pub port: u16,
    shared: Arc<Shared>,
}

impl Drop for FakeNfs3 {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for c in self.shared.conns.lock().unwrap().drain(..) {
            let _ = c.shutdown(Shutdown::Both);
        }
    }
}

impl FakeNfs3 {
    /// Root handle of the export.
    pub fn root(&self) -> FileHandle {
        self.shared.state.lock().unwrap().fs.root()
    }

    /// Mutate the backing tree directly (set-up and inspection).
    pub fn with_fs<R>(&self, f: impl FnOnce(&mut MemFs) -> R) -> R {
        let mut st = self.shared.state.lock().unwrap();
        st.listings.clear();
        f(&mut st.fs)
    }

    /// Add a read-only file of `size` bytes whose content is [`pattern`]`(seed, ..)`.
    pub fn add_pattern_file(&self, path: &str, size: u64, seed: u64) -> FileHandle {
        let mut st = self.shared.state.lock().unwrap();
        st.listings.clear();
        st.fs
            .add_sparse_file(path, size, 0)
            .expect("add_sparse_file");
        let fh = walk(&mut st.fs, path);
        st.patterns.insert(fh.0.clone(), seed);
        fh
    }

    /// Whole content of a regular (non-pattern) file in the backing tree.
    pub fn file(&self, path: &str) -> Vec<u8> {
        self.shared
            .state
            .lock()
            .unwrap()
            .fs
            .read_file(path)
            .expect("no such file")
    }

    /// Uncommitted UNSTABLE writes still outstanding.
    pub fn uncommitted(&self) -> usize {
        self.shared.state.lock().unwrap().uncommitted.len()
    }

    pub fn stats(&self) -> Stats {
        self.shared.stats.lock().unwrap().clone()
    }

    pub fn reset_stats(&self) {
        *self.shared.stats.lock().unwrap() = Stats::default();
    }

    /// Replace the fault script.
    pub fn script(&self, rules: Vec<Rule>) {
        *self.shared.script.lock().unwrap() = rules;
    }

    /// Install a closure consulted (after the script) for every request.
    pub fn set_hook(&self, f: impl FnMut(&Call) -> Option<Fault> + Send + 'static) {
        *self.shared.hook.lock().unwrap() = Some(Box::new(f));
    }

    pub fn clear_faults(&self) {
        self.script(Vec::new());
        *self.shared.hook.lock().unwrap() = None;
    }

    /// Cut all connections and refuse new ones for `d`.
    pub fn restart(&self, d: Duration) {
        restart(&self.shared, d);
    }

    /// Change the write verifier, losing uncommitted data.
    pub fn bump_verifier(&self) {
        bump_verifier(&mut self.shared.state.lock().unwrap());
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

fn bump_verifier(st: &mut State) {
    st.verf = st.verf.wrapping_add(0x0101_0101);
    let lost = std::mem::take(&mut st.uncommitted);
    for (fh, off, len) in lost {
        let _ = st.fs.write(&FileHandle(fh), off, &vec![0xEE; len]);
    }
    st.listings.clear();
}

// ------------------------------------------------------------------ start

pub fn start() -> FakeNfs3 {
    start_with(Config::default())
}

pub fn start_with(cfg: Config) -> FakeNfs3 {
    let (udp, tcp, port) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let port = udp.local_addr().unwrap().port();
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
            break (udp, tcp, port);
        }
    };
    let mut fs = MemFs::new();
    fs.max_read = u32::MAX;
    fs.max_write = u32::MAX;
    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        state: Mutex::new(State {
            fs,
            patterns: HashMap::new(),
            uncommitted: Vec::new(),
            verf: 0x1122_3344_5566_7788,
            listings: HashMap::new(),
        }),
        stats: Mutex::new(Stats::default()),
        script: Mutex::new(Vec::new()),
        hook: Mutex::new(None),
        down_until: Mutex::new(None),
        conns: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        port,
    });
    serve_udp(&shared, udp);
    serve_tcp(&shared, tcp, port);
    let mut extra = Vec::new();
    if cfg.portmap_on_111 {
        extra.push(111);
    }
    if cfg.nfs_on_2049 {
        extra.push(2049);
    }
    for p in extra {
        let udp = UdpSocket::bind(("127.0.0.1", p)).expect("bind well-known udp port");
        let tcp = TcpListener::bind(("127.0.0.1", p)).expect("bind well-known tcp port");
        serve_udp(&shared, udp);
        serve_tcp(&shared, tcp, p);
    }
    FakeNfs3 { port, shared }
}

fn serve_udp(shared: &Arc<Shared>, udp: UdpSocket) {
    let shared = Arc::clone(shared);
    udp.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        while !shared.stop.load(Ordering::SeqCst) {
            let Ok((n, peer)) = udp.recv_from(&mut buf) else {
                continue;
            };
            if is_down(&shared) {
                continue;
            }
            if let Outcome::Reply(r) = handle_message(&shared, &buf[..n], Proto::Udp) {
                let _ = udp.send_to(&r, peer);
            }
        }
    });
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
                    Ok(l) => {
                        l.set_nonblocking(true).unwrap();
                        listener.insert(l)
                    }
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
        match handle_message(shared, &msg, Proto::Tcp) {
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

fn mismatch(xid: u32, vers: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&vers.to_be_bytes());
    b.extend_from_slice(&vers.to_be_bytes());
    accepted(xid, ACCEPT_PROG_MISMATCH, &b)
}

/// Peek at the arguments the hook may want to match on.
fn call_info(prog: u32, vers: u32, proc_: u32, proto: Proto, args: &[u8]) -> Call {
    let mut c = Call {
        prog,
        vers,
        proc_,
        proto,
        seq: 0,
        fh: Vec::new(),
        offset: 0,
        count: 0,
        cookie: 0,
    };
    if prog != NFS_PROG || proc_ == NULL {
        return c;
    }
    let mut d = Decoder::new(args);
    let Ok(fh) = d.get_opaque() else { return c };
    c.fh = fh.to_vec();
    match proc_ {
        READ | COMMIT => {
            c.offset = d.get_u64().unwrap_or(0);
            c.count = d.get_u32().unwrap_or(0);
        }
        WRITE => {
            c.offset = d.get_u64().unwrap_or(0);
            c.count = d.get_u32().unwrap_or(0);
        }
        READDIR | READDIRPLUS => c.cookie = d.get_u64().unwrap_or(0),
        _ => {}
    }
    c
}

fn pick_fault(shared: &Shared, call: &Call) -> Option<Fault> {
    {
        let mut script = shared.script.lock().unwrap();
        for r in script.iter_mut() {
            if r.prog != call.prog || r.proc_ != call.proc_ || r.times == 0 {
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
            return Some(r.fault.clone());
        }
    }
    let mut hook = shared.hook.lock().unwrap();
    hook.as_mut().and_then(|h| h(call))
}

/// Zero words of the failure arm for an NFS procedure (attrs/wcc all absent).
fn fail_arm(proc_: u32) -> usize {
    match proc_ {
        GETATTR => 0,
        LOOKUP | ACCESS | READLINK | READ | READDIR | READDIRPLUS | FSSTAT | FSINFO => 1,
        RENAME => 4,
        LINK => 3,
        _ => 2,
    }
}

fn status_body(prog: u32, proc_: u32, status: u32) -> Vec<u8> {
    let mut e = Encoder::new();
    e.put_u32(status);
    if prog == NFS_PROG {
        for _ in 0..fail_arm(proc_) {
            e.put_u32(0);
        }
    }
    e.into_inner()
}

fn handle_message(shared: &Shared, msg: &[u8], proto: Proto) -> Outcome {
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
    let args = d.rest();

    let want_vers = match prog {
        PMAP_PROG => 2,
        NFS_PROG | MOUNT_PROG => 3,
        _ => return Outcome::Reply(accepted(xid, ACCEPT_PROG_UNAVAIL, &[])),
    };
    if vers != want_vers {
        return Outcome::Reply(mismatch(xid, want_vers));
    }

    let mut call = call_info(prog, vers, proc_, proto, args);
    {
        let mut st = shared.stats.lock().unwrap();
        let n = st.calls.entry((prog, proc_)).or_insert(0);
        *n += 1;
        call.seq = *n;
        *st.by_proto.entry((prog, proto)).or_insert(0) += 1;
    }

    let fault = pick_fault(shared, &call);
    if fault.is_some() {
        shared.stats.lock().unwrap().faults_fired += 1;
    }
    let mut read_fault = None;
    let mut truncate = None;
    match fault {
        None => {}
        Some(Fault::Status(s)) => {
            return Outcome::Reply(accepted(xid, ACCEPT_SUCCESS, &status_body(prog, proc_, s)));
        }
        Some(Fault::Accept(a)) => return Outcome::Reply(accepted(xid, a, &[])),
        Some(Fault::Delay(t)) => thread::sleep(t),
        Some(Fault::Drop) => return Outcome::Close,
        Some(Fault::Silent) => return Outcome::None,
        Some(Fault::Truncate(n)) => truncate = Some(n),
        Some(f @ (Fault::ShortRead(_) | Fault::CountOverData(_))) => read_fault = Some(f),
        Some(Fault::BumpVerifier) => bump_verifier(&mut shared.state.lock().unwrap()),
        Some(Fault::Restart(t)) => {
            restart(shared, t);
            return Outcome::Close;
        }
    }

    let result = match prog {
        PMAP_PROG => portmap(shared, proc_, args),
        MOUNT_PROG => mount(shared, proc_, args),
        _ => nfs(shared, proc_, args, read_fault),
    };
    let reply = match result {
        Ok(body) => accepted(xid, ACCEPT_SUCCESS, &body),
        Err(accept) => accepted(xid, accept, &[]),
    };
    match (truncate, proto) {
        (Some(n), Proto::Tcp) => Outcome::Truncate(reply, n),
        (Some(_), Proto::Udp) => Outcome::None,
        (None, _) => Outcome::Reply(reply),
    }
}

type Rpc = Result<Vec<u8>, u32>;

fn garbage(_: Error) -> u32 {
    ACCEPT_GARBAGE_ARGS
}

fn portmap(shared: &Shared, proc_: u32, args: &[u8]) -> Rpc {
    let cfg = &shared.cfg;
    let port = u32::from(shared.port);
    let mut e = Encoder::new();
    match proc_ {
        0 => {}
        GETPORT => {
            let mut d = Decoder::new(args);
            let prog = d.get_u32().map_err(garbage)?;
            let vers = d.get_u32().map_err(garbage)?;
            let prot = d.get_u32().map_err(garbage)?;
            let tcp = prot == 6;
            let registered = match (prog, vers) {
                (NFS_PROG, 3) => {
                    if tcp {
                        cfg.register_nfs_tcp
                    } else {
                        cfg.register_nfs_udp
                    }
                }
                (MOUNT_PROG, 3) => {
                    if tcp {
                        cfg.register_mount_tcp
                    } else {
                        cfg.register_mount_udp
                    }
                }
                (PMAP_PROG, 2) => true,
                _ => false,
            };
            let answer = match (registered, prog) {
                (false, _) => 0,
                (true, PMAP_PROG) => 111,
                (true, _) => port,
            };
            shared
                .stats
                .lock()
                .unwrap()
                .getport
                .push((prog, vers, prot, answer));
            e.put_u32(answer);
        }
        _ => return Err(ACCEPT_PROC_UNAVAIL),
    }
    Ok(e.into_inner())
}

fn mount(shared: &Shared, proc_: u32, args: &[u8]) -> Rpc {
    let mut e = Encoder::new();
    match proc_ {
        0 => {}
        MNT => {
            let mut d = Decoder::new(args);
            let dir = d.get_opaque().map_err(garbage)?;
            if dir == EXPORT.as_bytes() {
                let root = shared.state.lock().unwrap().fs.root();
                e.put_u32(0).put_opaque(&root.0);
                e.put_u32(2).put_u32(1).put_u32(0); // flavors: AUTH_SYS, AUTH_NONE
            } else {
                e.put_u32(2); // MNT3ERR_NOENT
            }
        }
        UMNT => {}
        MOUNT_EXPORT => {
            e.put_bool(true).put_string(EXPORT.as_bytes());
            e.put_bool(true).put_string(b"*").put_bool(false);
            e.put_bool(false);
        }
        _ => return Err(ACCEPT_PROC_UNAVAIL),
    }
    Ok(e.into_inner())
}

// --------------------------------------------------------------- NFS codec

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
        Status::BadHandle => 10001,
        Status::NotSync => 10002,
        Status::BadCookie => 10003,
        Status::NotSupp => 10004,
        Status::TooSmall => 10005,
        Status::ServerFault => 10006,
        Status::BadType => 10007,
        Status::Jukebox => 10008,
        Status::Other(_, c) => c,
    }
}

fn err_code(e: Error) -> u32 {
    match e {
        Error::Nfs(s) => status_code(s),
        _ => NFS3ERR_IO,
    }
}

const FATTR3_LEN: usize = 84;

fn put_time(e: &mut Encoder, t: Time) {
    e.put_u32(t.seconds as u32).put_u32(t.nseconds);
}

fn put_fattr(e: &mut Encoder, a: &Attr) {
    let ftype = match a.ftype {
        FileType::Regular => 1,
        FileType::Directory => 2,
        FileType::BlockDevice => 3,
        FileType::CharDevice => 4,
        FileType::Symlink => 5,
        FileType::Socket => 6,
        FileType::Fifo => 7,
        FileType::Other(t) => t,
    };
    e.put_u32(ftype)
        .put_u32(a.mode)
        .put_u32(a.nlink)
        .put_u32(a.uid)
        .put_u32(a.gid)
        .put_u64(a.size)
        .put_u64(a.used)
        .put_u32(a.rdev.0)
        .put_u32(a.rdev.1)
        .put_u64(a.fsid)
        .put_u64(a.fileid);
    put_time(e, a.atime);
    put_time(e, a.mtime);
    put_time(e, a.ctime);
}

fn put_post_attr(e: &mut Encoder, a: Option<&Attr>) {
    match a {
        Some(a) => {
            e.put_bool(true);
            put_fattr(e, a);
        }
        None => {
            e.put_bool(false);
        }
    }
}

/// wcc_data with no pre-op attributes and the given post-op attributes.
fn put_wcc(e: &mut Encoder, after: Option<&Attr>) {
    e.put_bool(false);
    put_post_attr(e, after);
}

fn get_sattr(d: &mut Decoder) -> nfsc::Result<SetAttr> {
    let mut s = SetAttr::default();
    if d.get_bool()? {
        s.mode = Some(d.get_u32()?);
    }
    if d.get_bool()? {
        s.uid = Some(d.get_u32()?);
    }
    if d.get_bool()? {
        s.gid = Some(d.get_u32()?);
    }
    if d.get_bool()? {
        s.size = Some(d.get_u64()?);
    }
    let mut times = [None, None];
    for t in &mut times {
        *t = match d.get_u32()? {
            0 => None,
            1 => Some(SetTime::ServerNow),
            _ => Some(SetTime::Client(Time {
                seconds: i64::from(d.get_u32()?),
                nseconds: d.get_u32()?,
            })),
        };
    }
    s.atime = times[0];
    s.mtime = times[1];
    Ok(s)
}

fn fh_of(d: &mut Decoder) -> nfsc::Result<FileHandle> {
    Ok(FileHandle(d.get_opaque()?.to_vec()))
}

/// Run one NFS procedure. `Ok` is the full result body (status first).
fn nfs(shared: &Shared, proc_: u32, args: &[u8], read_fault: Option<Fault>) -> Rpc {
    let mut st = shared.state.lock().unwrap();
    let mut d = Decoder::new(args);
    let mut e = Encoder::new();
    let r = nfs_proc(shared, &mut st, proc_, &mut d, &mut e, read_fault);
    match r {
        Ok(Ok(())) => Ok(e.into_inner()),
        Ok(Err(status)) => Ok(status_body(NFS_PROG, proc_, status)),
        Err(accept) => Err(accept),
    }
}

/// Inner result: Err(accept_stat) for RPC-level failures, Ok(Err(nfsstat3)) for NFS errors.
fn nfs_proc(
    shared: &Shared,
    st: &mut State,
    proc_: u32,
    d: &mut Decoder,
    e: &mut Encoder,
    read_fault: Option<Fault>,
) -> Result<Result<(), u32>, u32> {
    macro_rules! arg {
        ($x:expr) => {
            $x.map_err(|_| ACCEPT_GARBAGE_ARGS)?
        };
    }
    macro_rules! nfs_try {
        ($x:expr) => {
            match $x {
                Ok(v) => v,
                Err(err) => return Ok(Err(err_code(err))),
            }
        };
    }
    let mutating = !matches!(
        proc_,
        NULL | GETATTR
            | LOOKUP
            | ACCESS
            | READLINK
            | READ
            | READDIR
            | READDIRPLUS
            | FSSTAT
            | FSINFO
            | COMMIT
    );
    if mutating {
        st.listings.clear();
    }
    let fsinfo = shared.cfg.fsinfo;
    match proc_ {
        NULL => {}
        GETATTR => {
            let fh = arg!(fh_of(d));
            let a = nfs_try!(st.fs.getattr(&fh));
            e.put_u32(0);
            put_fattr(e, &a);
        }
        SETATTR => {
            let fh = arg!(fh_of(d));
            let sa = arg!(get_sattr(d));
            if st.patterns.contains_key(&fh.0) {
                return Ok(Err(NFS3ERR_ROFS));
            }
            let a = nfs_try!(st.fs.setattr(&fh, &sa));
            e.put_u32(0);
            put_wcc(e, Some(&a));
        }
        LOOKUP => {
            let dir = arg!(fh_of(d));
            let name = arg!(d.get_opaque()).to_vec();
            let (fh, a) = nfs_try!(st.fs.lookup(&dir, &name));
            let da = st.fs.getattr(&dir).ok();
            e.put_u32(0).put_opaque(&fh.0);
            put_post_attr(e, Some(&a));
            put_post_attr(e, da.as_ref());
        }
        ACCESS => {
            let fh = arg!(fh_of(d));
            let bits = arg!(d.get_u32());
            let a = nfs_try!(st.fs.getattr(&fh));
            e.put_u32(0);
            put_post_attr(e, Some(&a));
            e.put_u32(bits);
        }
        READLINK => {
            let fh = arg!(fh_of(d));
            let t = nfs_try!(st.fs.readlink(&fh));
            e.put_u32(0).put_bool(false).put_opaque(&t);
        }
        READ => {
            let fh = arg!(fh_of(d));
            let offset = arg!(d.get_u64());
            let count = arg!(d.get_u32());
            {
                let mut s = shared.stats.lock().unwrap();
                s.max_read_count = s.max_read_count.max(count);
                if count > fsinfo.rtmax {
                    s.rtmax_violations += 1;
                }
            }
            let count = count.min(fsinfo.rtmax);
            let a = nfs_try!(st.fs.getattr(&fh));
            let (mut data, mut eof) = match st.patterns.get(&fh.0) {
                Some(&seed) => {
                    let end = offset.saturating_add(u64::from(count)).min(a.size);
                    let start = offset.min(end);
                    (pattern(seed, start, (end - start) as usize), end >= a.size)
                }
                None => nfs_try!(st.fs.read(&fh, offset, count)),
            };
            let mut reported = data.len() as u32;
            match read_fault {
                Some(Fault::ShortRead(n)) => {
                    data.truncate(n as usize);
                    reported = data.len() as u32;
                    eof = false;
                }
                Some(Fault::CountOverData(n)) => reported += n,
                _ => {}
            }
            e.put_u32(0);
            put_post_attr(e, Some(&a));
            e.put_u32(reported).put_bool(eof).put_opaque(&data);
        }
        WRITE => {
            let fh = arg!(fh_of(d));
            let offset = arg!(d.get_u64());
            let _count = arg!(d.get_u32());
            let stable = arg!(d.get_u32());
            let data = arg!(d.get_opaque()).to_vec();
            {
                let mut s = shared.stats.lock().unwrap();
                s.max_write_len = s.max_write_len.max(data.len() as u32);
                if data.len() as u32 > fsinfo.wtmax {
                    s.wtmax_violations += 1;
                }
                if stable == UNSTABLE {
                    s.unstable_writes += 1;
                    s.unstable_bytes += data.len() as u64;
                }
            }
            if st.patterns.contains_key(&fh.0) {
                return Ok(Err(NFS3ERR_ROFS));
            }
            let data = &data[..data.len().min(fsinfo.wtmax as usize)];
            let n = nfs_try!(st.fs.write(&fh, offset, data));
            let committed = if stable == UNSTABLE {
                st.uncommitted.push((fh.0.clone(), offset, n as usize));
                UNSTABLE
            } else {
                FILE_SYNC
            };
            let a = st.fs.getattr(&fh).ok();
            e.put_u32(0);
            put_wcc(e, a.as_ref());
            e.put_u32(n).put_u32(committed).put_u64(st.verf);
        }
        CREATE => {
            let dir = arg!(fh_of(d));
            let name = arg!(d.get_opaque()).to_vec();
            let how = arg!(d.get_u32());
            let (mode, sa) = match how {
                0 => (CreateMode::Unchecked, arg!(get_sattr(d))),
                1 => (CreateMode::Guarded, arg!(get_sattr(d))),
                _ => {
                    arg!(d.get_opaque_fixed(8));
                    (CreateMode::Exclusive, SetAttr::default())
                }
            };
            let (fh, a) = nfs_try!(st.fs.create(&dir, &name, mode, &sa));
            put_created(st, e, &dir, &fh, &a);
        }
        MKDIR => {
            let dir = arg!(fh_of(d));
            let name = arg!(d.get_opaque()).to_vec();
            let sa = arg!(get_sattr(d));
            let (fh, a) = nfs_try!(st.fs.mkdir(&dir, &name, &sa));
            put_created(st, e, &dir, &fh, &a);
        }
        SYMLINK => {
            let dir = arg!(fh_of(d));
            let name = arg!(d.get_opaque()).to_vec();
            let sa = arg!(get_sattr(d));
            let target = arg!(d.get_opaque()).to_vec();
            let (fh, a) = nfs_try!(st.fs.symlink(&dir, &name, &target, &sa));
            put_created(st, e, &dir, &fh, &a);
        }
        REMOVE | RMDIR => {
            let dir = arg!(fh_of(d));
            let name = arg!(d.get_opaque()).to_vec();
            if proc_ == REMOVE {
                nfs_try!(st.fs.remove(&dir, &name));
            } else {
                nfs_try!(st.fs.rmdir(&dir, &name));
            }
            let da = st.fs.getattr(&dir).ok();
            e.put_u32(0);
            put_wcc(e, da.as_ref());
        }
        RENAME => {
            let fd = arg!(fh_of(d));
            let fname = arg!(d.get_opaque()).to_vec();
            let td = arg!(fh_of(d));
            let tname = arg!(d.get_opaque()).to_vec();
            nfs_try!(st.fs.rename(&fd, &fname, &td, &tname));
            e.put_u32(0);
            put_wcc(e, None);
            put_wcc(e, None);
        }
        LINK => {
            let fh = arg!(fh_of(d));
            let dir = arg!(fh_of(d));
            let name = arg!(d.get_opaque()).to_vec();
            nfs_try!(st.fs.link(&fh, &dir, &name));
            let a = st.fs.getattr(&fh).ok();
            e.put_u32(0);
            put_post_attr(e, a.as_ref());
            put_wcc(e, None);
        }
        READDIR | READDIRPLUS => {
            let plus = proc_ == READDIRPLUS;
            let dir = arg!(fh_of(d));
            let cookie = arg!(d.get_u64());
            arg!(d.get_opaque_fixed(8));
            let (dircount, maxcount) = if plus {
                (arg!(d.get_u32()), arg!(d.get_u32()))
            } else {
                let c = arg!(d.get_u32());
                (u32::MAX, c)
            };
            let listing = nfs_try!(listing(st, &dir));
            let dattr = nfs_try!(st.fs.getattr(&dir));
            let start = cookie as usize;
            if start > listing.len() {
                return Ok(Err(NFS3ERR_BAD_COOKIE));
            }
            // status + post_op_attr + verf + list end + eof
            let mut used = 4 + 4 + FATTR3_LEN + 8 + 4 + 4;
            let mut dir_used = 0usize;
            let mut body = Encoder::new();
            let mut i = start;
            while i < listing.len() {
                let l = &listing[i];
                let name_len = 4 + l.name.len().div_ceil(4) * 4;
                let dir_part = 8 + name_len + 8;
                let size = 4
                    + dir_part
                    + if plus {
                        4 + FATTR3_LEN + 4 + 4 + l.fh.0.len().div_ceil(4) * 4
                    } else {
                        0
                    };
                if used + size > maxcount as usize || dir_used + dir_part > dircount as usize {
                    break;
                }
                used += size;
                dir_used += dir_part;
                body.put_bool(true)
                    .put_u64(l.fileid)
                    .put_opaque(&l.name)
                    .put_u64(i as u64 + 1);
                if plus {
                    put_post_attr(&mut body, Some(&l.attr));
                    body.put_bool(true).put_opaque(&l.fh.0);
                }
                i += 1;
            }
            if i == start && start < listing.len() {
                return Ok(Err(NFS3ERR_TOOSMALL));
            }
            e.put_u32(0);
            put_post_attr(e, Some(&dattr));
            e.put_opaque_fixed(&[0xC0, 0x0C, 0x1E, 0, 0, 0, 0, 1]);
            // The entries are already XDR (4-byte aligned): append them as is.
            e.put_opaque_fixed(body.as_bytes());
            e.put_bool(false).put_bool(i >= listing.len());
        }
        FSSTAT => {
            let fh = arg!(fh_of(d));
            let a = nfs_try!(st.fs.getattr(&fh));
            e.put_u32(0);
            put_post_attr(e, Some(&a));
            e.put_u64(1 << 40)
                .put_u64(1 << 39)
                .put_u64(1 << 38)
                .put_u64(1000)
                .put_u64(500)
                .put_u64(400)
                .put_u32(0);
        }
        FSINFO => {
            let fh = arg!(fh_of(d));
            let a = nfs_try!(st.fs.getattr(&fh));
            e.put_u32(0);
            put_post_attr(e, Some(&a));
            e.put_u32(fsinfo.rtmax)
                .put_u32(fsinfo.rtpref)
                .put_u32(4096)
                .put_u32(fsinfo.wtmax)
                .put_u32(fsinfo.wtpref)
                .put_u32(4096)
                .put_u32(fsinfo.dtpref)
                .put_u64(u64::MAX)
                .put_u32(0)
                .put_u32(1)
                .put_u32(0x1b);
        }
        COMMIT => {
            let fh = arg!(fh_of(d));
            let _off = arg!(d.get_u64());
            let _count = arg!(d.get_u32());
            st.uncommitted.retain(|(h, _, _)| *h != fh.0);
            let a = st.fs.getattr(&fh).ok();
            e.put_u32(0);
            put_wcc(e, a.as_ref());
            e.put_u64(st.verf);
        }
        _ => return Err(ACCEPT_PROC_UNAVAIL),
    }
    Ok(Ok(()))
}

fn put_created(st: &mut State, e: &mut Encoder, dir: &FileHandle, fh: &FileHandle, a: &Attr) {
    let da = st.fs.getattr(dir).ok();
    e.put_u32(0).put_bool(true).put_opaque(&fh.0);
    put_post_attr(e, Some(a));
    put_wcc(e, da.as_ref());
}

/// "." and "..", then the entries in name order. Cookie of entry i is i + 1.
fn listing(st: &mut State, dir: &FileHandle) -> nfsc::Result<Arc<Vec<Listed>>> {
    if let Some(l) = st.listings.get(&dir.0) {
        return Ok(Arc::clone(l));
    }
    let entries = st.fs.readdir(dir)?;
    let dattr = st.fs.getattr(dir)?;
    let (pfh, pattr) = st.fs.lookup(dir, b"..")?;
    let mut out = Vec::with_capacity(entries.len() + 2);
    out.push(Listed {
        name: b".".to_vec(),
        fileid: dattr.fileid,
        fh: dir.clone(),
        attr: dattr,
    });
    out.push(Listed {
        name: b"..".to_vec(),
        fileid: pattr.fileid,
        fh: pfh,
        attr: pattr,
    });
    for ent in entries {
        let fh = ent.handle.expect("memfs readdir gives handles");
        let attr = ent.attr.expect("memfs readdir gives attrs");
        out.push(Listed {
            name: ent.name,
            fileid: ent.fileid,
            fh,
            attr,
        });
    }
    let l = Arc::new(out);
    st.listings.insert(dir.0.clone(), Arc::clone(&l));
    Ok(l)
}
