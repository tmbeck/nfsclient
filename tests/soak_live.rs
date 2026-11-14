//! Chaos and soak tests: long transfers against real NFS servers survive
//! network faults and server restarts, and never return short or wrong data.
//!
//! Every live test is skipped unless `NFSC_TEST_SOAK=1` and at least one
//! read-write target is set (target names never appear in this file):
//!
//!   NFSC_TEST_RW_GANESHA=host:/export   nfs-ganesha (testenv/up.sh)
//!   NFSC_TEST_RW_KNFSD=host:/export     kernel nfsd
//!
//! Each test makes a `nfsc-soak-<random>` directory under the export, writes a
//! large file with deterministic content (directly, no proxy) and removes the
//! directory afterwards. Reads and writes then go through a fault-injecting
//! TCP proxy on 127.0.0.1 (tests/support/chaos_proxy.rs) that resets,
//! half-closes, stalls, slows down and "takes down" the server on a seeded
//! random schedule. Every byte is checked against the expected pattern.
//!
//! Knobs:
//!   NFSC_TEST_SOAK_MIB=1024         file size
//!   NFSC_TEST_SOAK_VERS=3,4.0,4.1,4.2   versions for the read test (a version
//!                                   the server does not offer is skipped)
//!   NFSC_TEST_SOAK_WRITE_VERS=3,4.1 versions for the write test
//!   NFSC_TEST_SOAK_CLI_VERS=3,4.1   versions for the CLI tests
//!   NFSC_TEST_SOAK_FAULTS=8         faults per transfer
//!   NFSC_TEST_SOAK_SEED=N           fault schedule seed (default: random; printed)
//!   NFSC_TEST_SOAK_BUDGET_SECS=900  time limit per transfer
//!   NFSC_TEST_SOAK_TMPDIR=dir       local files of the CLI tests (default: temp dir)
//!   NFSC_TEST_SOAK_KEEP=1           keep the remote scratch directory
//!   NFSC_TEST_CHAOS_VERBOSE=1       log every injected fault on stderr
//!
//! Server restart (`soak_server_restart`, needs `sudo -n podman`):
//!   NFSC_TEST_SOAK_RESTART=1        enable
//!   NFSC_TEST_SOAK_RESTART_VERS=3,4.0,4.1,4.2  readers run in parallel
//!                                   during one `podman restart`
//!   NFSC_TEST_SOAK_RESTART_SECS=30  throttled duration of each read
//!   NFSC_TEST_SOAK_CONTAINER_<SRV>  container name (default nfsc-<srv>)
//! Only ganesha is restarted: the kernel nfsd container exports tmpfs, so a
//! restart loses the file.
//!
//! The tests in this binary run one at a time (they share a lock). The proxy
//! self-tests at the end need no server and always run.
//!
//! Run them all with `just soak [MiB]`.

#[path = "support/chaos_proxy.rs"]
mod chaos_proxy;

use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use chaos_proxy::{ChaosProxy, Fault, RandomChaos, Rng, Schedule, Stats, Trigger};
use nfsc::error::{Error, Result};
use nfsc::fs::{
    ConnectOptions, Connected, CreateMode, FileHandle, Filesystem, NfsVersion, SetAttr, VersionPref,
};
use nfsc::rpc::{Auth, PortMode, Proto, RetryEvent, RetryPolicy, RpcOptions};

const MIB: u64 = 1 << 20;
const MOUNT_PROG: u32 = 100005;
const NFS_PROG: u32 = 100003;

/// RPC timeout for transfers through the proxy: stalls are longer.
const RPC_TIMEOUT: Duration = Duration::from_secs(4);
/// Retry budget per operation under chaos (the longest outage is ~10 s).
const CHAOS_RETRY_BUDGET: Duration = Duration::from_secs(120);
/// Retry budget per operation across a server restart (stop, start, grace).
const RESTART_RETRY_BUDGET: Duration = Duration::from_secs(300);

// ---- configuration --------------------------------------------------------------

static SERIAL: Mutex<()> = Mutex::new(());

/// The live tests run one at a time: they share servers and the restart test
/// takes a server away.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_u64(key: &str, default: u64) -> u64 {
    env(key)
        .map(|v| {
            v.parse()
                .unwrap_or_else(|_| panic!("{key}={v}: not a number"))
        })
        .unwrap_or(default)
}

fn soak_enabled(test: &str) -> bool {
    if env("NFSC_TEST_SOAK").as_deref() != Some("1") {
        eprintln!("{test}: skipped (set NFSC_TEST_SOAK=1 and NFSC_TEST_RW_<SRV>)");
        return false;
    }
    true
}

fn size() -> u64 {
    env_u64("NFSC_TEST_SOAK_MIB", 1024) * MIB
}

fn faults_per_transfer() -> usize {
    env_u64("NFSC_TEST_SOAK_FAULTS", 8) as usize
}

fn budget() -> Duration {
    Duration::from_secs(env_u64("NFSC_TEST_SOAK_BUDGET_SECS", 900))
}

fn random_u64() -> u64 {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    );
    h.finish()
}

/// The fault schedule seed: NFSC_TEST_SOAK_SEED or random. Printed so a
/// failing schedule can be replayed.
fn fault_seed(test: &str) -> u64 {
    let seed = env("NFSC_TEST_SOAK_SEED")
        .map(|v| v.parse().expect("NFSC_TEST_SOAK_SEED"))
        .unwrap_or_else(random_u64);
    eprintln!("{test}: fault seed {seed} (replay with NFSC_TEST_SOAK_SEED={seed})");
    seed
}

fn parse_versions(key: &str, default: &str) -> Vec<NfsVersion> {
    env(key)
        .unwrap_or_else(|| default.to_string())
        .split(',')
        .map(|v| match v.trim() {
            "3" => NfsVersion::V3,
            "4.0" | "4" => NfsVersion::V4(0),
            "4.1" => NfsVersion::V4(1),
            "4.2" => NfsVersion::V4(2),
            o => panic!("{key}: unknown version {o}"),
        })
        .collect()
}

fn vers_arg(v: NfsVersion) -> &'static str {
    match v {
        NfsVersion::V2 => "2",
        NfsVersion::V3 => "3",
        NfsVersion::V4(0) => "4.0",
        NfsVersion::V4(1) => "4.1",
        NfsVersion::V4(_) => "4.2",
    }
}

#[derive(Clone)]
struct Target {
    name: &'static str,
    ip: IpAddr,
    export: Vec<u8>,
    container: String,
}

fn targets() -> Vec<Target> {
    let mut out = Vec::new();
    for (name, key) in [
        ("ganesha", "NFSC_TEST_RW_GANESHA"),
        ("knfsd", "NFSC_TEST_RW_KNFSD"),
    ] {
        let Some(v) = env(key) else { continue };
        let (host, path) = v
            .split_once(':')
            .unwrap_or_else(|| panic!("{key}: expected host:/path"));
        let ip = (host, 2049)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .unwrap_or_else(|| panic!("{key}: cannot resolve host"))
            .ip();
        let container = env(&format!("NFSC_TEST_SOAK_CONTAINER_{}", name.to_uppercase()))
            .unwrap_or_else(|| format!("nfsc-{name}"));
        out.push(Target {
            name,
            ip,
            export: path.as_bytes().to_vec(),
            container,
        });
    }
    if out.is_empty() {
        eprintln!("no NFSC_TEST_RW_<SRV> target set; nothing to soak");
    }
    out
}

// ---- deterministic content ------------------------------------------------------

fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Fill `buf` with the content of a file with this `seed` at offset `off`.
/// Byte `o` of the file is byte `o % 8` of `mix(seed + o / 8)`, so any range
/// can be produced (and checked) on its own.
fn fill(seed: u64, off: u64, buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let o = off + i as u64;
        let k = (o % 8) as usize;
        let n = (8 - k).min(buf.len() - i);
        let w = mix(seed.wrapping_add(o / 8)).to_le_bytes();
        buf[i..i + n].copy_from_slice(&w[k..k + n]);
        i += n;
    }
}

/// Checks a byte stream against the pattern, in order.
struct Verifier {
    seed: u64,
    pos: u64,
    scratch: Vec<u8>,
}

impl Verifier {
    fn new(seed: u64, pos: u64) -> Self {
        Self {
            seed,
            pos,
            scratch: Vec::new(),
        }
    }

    fn check(&mut self, data: &[u8]) -> Result<()> {
        self.scratch.resize(data.len(), 0);
        fill(self.seed, self.pos, &mut self.scratch);
        if self.scratch != data {
            let i = self
                .scratch
                .iter()
                .zip(data)
                .position(|(a, b)| a != b)
                .unwrap_or(0);
            return Err(Error::Protocol(format!(
                "data mismatch at offset {} (chunk of {} at {})",
                self.pos + i as u64,
                data.len(),
                self.pos
            )));
        }
        self.pos += data.len() as u64;
        Ok(())
    }
}

/// Check a local file against the pattern; returns its length.
fn verify_local(path: &std::path::Path, seed: u64) -> std::io::Result<u64> {
    let mut f = std::fs::File::open(path)?;
    let mut v = Verifier::new(seed, 0);
    let mut buf = vec![0u8; 4 * MIB as usize];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(v.pos);
        }
        v.check(&buf[..n]).map_err(std::io::Error::other)?;
    }
}

// ---- retry accounting -------------------------------------------------------------

/// Counts the retry events of one transfer (through [`RetryPolicy::on_retry`]).
#[derive(Default)]
struct RetryLog {
    retrying: AtomicU64,
    recovered: AtomicU64,
    gave_up: AtomicU64,
    /// "OP: error" -> count, for the summary.
    kinds: Mutex<BTreeMap<String, u64>>,
}

impl RetryLog {
    fn policy(self: &Arc<Self>, budget: Duration) -> RetryPolicy {
        let log = self.clone();
        RetryPolicy {
            budget,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(5),
            jitter: true,
            on_retry: Some(Arc::new(move |ev: &RetryEvent<'_>| log.record(ev))),
            cancel: None,
        }
    }

    fn record(&self, ev: &RetryEvent<'_>) {
        match ev {
            RetryEvent::Retrying { op, error, .. } => {
                self.retrying.fetch_add(1, Ordering::Relaxed);
                let mut msg = error.to_string();
                msg.truncate(60);
                *self
                    .kinds
                    .lock()
                    .unwrap()
                    .entry(format!("{op}: {msg}"))
                    .or_default() += 1;
            }
            RetryEvent::Recovered { .. } => {
                self.recovered.fetch_add(1, Ordering::Relaxed);
            }
            RetryEvent::GaveUp { op, error, .. } => {
                self.gave_up.fetch_add(1, Ordering::Relaxed);
                eprintln!("  gave up: {op}: {error}");
            }
        }
    }

    fn retries(&self) -> u64 {
        self.retrying.load(Ordering::Relaxed)
    }

    fn summary(&self) -> String {
        let kinds = self.kinds.lock().unwrap();
        let top: Vec<String> = kinds.iter().map(|(k, n)| format!("{n}x {k}")).collect();
        format!(
            "retries {} recovered {} gave-up {} [{}]",
            self.retrying.load(Ordering::Relaxed),
            self.recovered.load(Ordering::Relaxed),
            self.gave_up.load(Ordering::Relaxed),
            top.join("; ")
        )
    }
}

// ---- connections ------------------------------------------------------------------

fn rpc_opts(retry: RetryPolicy, timeout: Duration) -> RpcOptions {
    RpcOptions {
        proto: Proto::Tcp,
        port_mode: PortMode::Unprivileged,
        timeout,
        auth: Auth::sys_from_process(),
        retry,
    }
}

/// The NFS (and, for v3, MOUNT) proxies in front of one server.
struct Proxies {
    nfs: ChaosProxy,
    /// v3 only: MOUNT goes through a fault-free proxy, so the client can be
    /// pointed at 127.0.0.1 for both services.
    mount: Option<ChaosProxy>,
}

impl Proxies {
    fn start(t: &Target, vers: NfsVersion, schedule: Schedule) -> Self {
        let probe = rpc_opts(RetryPolicy::none(), Duration::from_secs(5));
        let (nfs_port, mount) = match vers {
            NfsVersion::V4(_) => (2049, None),
            v => {
                let n = if v == NfsVersion::V3 { 3 } else { 2 };
                let nfs = nfsc::portmap::getport(t.ip, NFS_PROG, n, Proto::Tcp, &probe)
                    .expect("portmap: NFS port");
                let mnt = nfsc::portmap::getport(t.ip, MOUNT_PROG, n, Proto::Tcp, &probe)
                    .expect("portmap: MOUNT port");
                let mp = ChaosProxy::start(SocketAddr::new(t.ip, mnt), Schedule::None)
                    .expect("start MOUNT proxy");
                (nfs, Some(mp))
            }
        };
        let nfs =
            ChaosProxy::start(SocketAddr::new(t.ip, nfs_port), schedule).expect("start NFS proxy");
        Self { nfs, mount }
    }

    fn connect(&self, t: &Target, vers: NfsVersion, rpc: RpcOptions) -> Result<Connected> {
        let opts = ConnectOptions {
            rpc,
            nfs_port: Some(self.nfs.port()),
            mount_port: self.mount.as_ref().map(|m| m.port()),
            version: VersionPref::Exact(vers),
        };
        nfsc::fs::connect(IpAddr::V4(Ipv4Addr::LOCALHOST), &t.export, &opts)
    }
}

impl Proxies {
    /// Point both proxies at `ip` (same NFS port; MOUNT port looked up again).
    fn retarget(&self, ip: IpAddr) {
        let nfs_port = self.nfs.target().port();
        self.nfs.set_target(SocketAddr::new(ip, nfs_port));
        if let Some(m) = &self.mount {
            let probe = rpc_opts(RetryPolicy::none(), Duration::from_secs(5));
            let port = nfsc::portmap::getport(ip, MOUNT_PROG, 3, Proto::Tcp, &probe)
                .unwrap_or(m.target().port());
            m.set_target(SocketAddr::new(ip, port));
        }
    }
}

fn connect_direct(t: &Target, vers: NfsVersion, rpc: RpcOptions) -> Result<Connected> {
    let opts = ConnectOptions {
        rpc,
        nfs_port: None,
        mount_port: None,
        version: VersionPref::Exact(vers),
    };
    nfsc::fs::connect(t.ip, &t.export, &opts)
}

fn default_rpc() -> RpcOptions {
    rpc_opts(RetryPolicy::default(), Duration::from_secs(10))
}

/// Look up `dir/name` below the root of `c`.
fn lookup_path(c: &mut Connected, dir: &str, name: &str) -> Result<FileHandle> {
    let root = c.fs.root();
    let (d, _) = c.fs.lookup(&root, dir.as_bytes())?;
    let (f, _) = c.fs.lookup(&d, name.as_bytes())?;
    Ok(f)
}

/// `want`, or less when the export has too little free space for it (the
/// knfsd test export is a 512 MiB tmpfs). Rounded down to a whole MiB.
fn fit_size(t: &Target, want: u64) -> u64 {
    let avail = connect_direct(t, NfsVersion::V3, default_rpc())
        .and_then(|mut c| {
            let root = c.fs.root();
            let st = c.fs.fsstat(&root);
            let _ = c.fs.disconnect();
            st
        })
        .map(|s| s.avail_bytes)
        .unwrap_or(u64::MAX);
    let room = avail.saturating_sub(64 * MIB) / 10 * 8 / MIB * MIB;
    if want <= room {
        return want;
    }
    let size = room.max(16 * MIB);
    eprintln!(
        "[{}] only {} MiB free on the export: using {} MiB instead of {} MiB",
        t.name,
        avail / MIB,
        size / MIB,
        want / MIB
    );
    size
}

/// A remote scratch directory; removed (with its files) when dropped.
struct Scratch {
    target: Target,
    dir: String,
}

impl Scratch {
    fn create(t: &Target) -> Self {
        let dir = format!("nfsc-soak-{:016x}", random_u64());
        let mut c = connect_direct(t, NfsVersion::V3, default_rpc()).expect("connect (setup)");
        let root = c.fs.root();
        c.fs.mkdir(&root, dir.as_bytes(), &SetAttr::default())
            .expect("mkdir scratch dir");
        let _ = c.fs.disconnect();
        Self {
            target: t.clone(),
            dir,
        }
    }

    /// Write a `size`-byte pattern file with `seed` directly to the server.
    fn write_file(&self, name: &str, size: u64, seed: u64) {
        let start = Instant::now();
        let mut c = connect_direct(&self.target, NfsVersion::V3, default_rpc())
            .expect("connect (setup write)");
        let root = c.fs.root();
        let (d, _) = c.fs.lookup(&root, self.dir.as_bytes()).expect("lookup dir");
        let (fh, _) =
            c.fs.create(
                &d,
                name.as_bytes(),
                CreateMode::Guarded,
                &SetAttr::default(),
            )
            .expect("create");
        let n = write_pattern(c.fs.as_mut(), &fh, size, seed).expect("setup write_stream");
        assert_eq!(n, size);
        let attr = c.fs.getattr(&fh).expect("getattr");
        assert_eq!(attr.size, size, "size after setup write");
        let _ = c.fs.disconnect();
        let secs = start.elapsed().as_secs_f64();
        eprintln!(
            "[{}] wrote {name}: {} MiB in {secs:.1}s ({:.0} MiB/s, direct)",
            self.target.name,
            size / MIB,
            size as f64 / MIB as f64 / secs
        );
    }

    fn remove(&self, name: &str) {
        if let Ok(mut c) = connect_direct(&self.target, NfsVersion::V3, default_rpc()) {
            let root = c.fs.root();
            if let Ok((d, _)) = c.fs.lookup(&root, self.dir.as_bytes()) {
                let _ = c.fs.remove(&d, name.as_bytes());
            }
            let _ = c.fs.disconnect();
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if env("NFSC_TEST_SOAK_KEEP").as_deref() == Some("1") {
            eprintln!("[{}] keeping {}", self.target.name, self.dir);
            return;
        }
        let r = (|| -> Result<()> {
            let mut c = connect_direct(&self.target, NfsVersion::V3, default_rpc())?;
            let root = c.fs.root();
            let (d, _) = c.fs.lookup(&root, self.dir.as_bytes())?;
            for e in c.fs.readdir(&d)? {
                c.fs.remove(&d, &e.name)?;
            }
            c.fs.rmdir(&root, self.dir.as_bytes())?;
            let _ = c.fs.disconnect();
            Ok(())
        })();
        if let Err(e) = r {
            eprintln!(
                "[{}] WARNING: could not remove {}: {e}",
                self.target.name, self.dir
            );
        }
    }
}

fn write_pattern(fs: &mut dyn Filesystem, fh: &FileHandle, size: u64, seed: u64) -> Result<u64> {
    let mut pos = 0u64;
    fs.write_stream(fh, 0, &mut |buf: &mut [u8]| {
        let n = (size - pos).min(buf.len() as u64) as usize;
        fill(seed, pos, &mut buf[..n]);
        pos += n as u64;
        Ok(n)
    })
}

/// Read `fh` to EOF (no length: a short result must be an error or EOF),
/// checking every byte. Returns bytes read.
fn read_verify(fs: &mut dyn Filesystem, fh: &FileHandle, seed: u64) -> Result<u64> {
    let mut v = Verifier::new(seed, 0);
    let n = fs.read_stream(fh, 0, None, &mut |d| v.check(d))?;
    if n != v.pos {
        return Err(Error::Protocol(format!(
            "read_stream returned {n} but delivered {}",
            v.pos
        )));
    }
    Ok(n)
}

/// Outcome of one transfer, for the summary table.
struct Report {
    line: String,
}

fn mib_s(bytes: u64, d: Duration) -> f64 {
    bytes as f64 / MIB as f64 / d.as_secs_f64()
}

/// Check the usual invariants of a chaos transfer; Err describes the failure.
fn judge(
    what: &str,
    got: Result<u64>,
    size: u64,
    elapsed: Duration,
    stats: &Stats,
    log: &RetryLog,
) -> std::result::Result<Report, String> {
    let line = format!(
        "{what}: {:.1}s ({:.0} MiB/s), {} faults ({} disruptive), {} connections, {}",
        elapsed.as_secs_f64(),
        mib_s(size, elapsed),
        stats.faults.len(),
        stats.disruptive(RPC_TIMEOUT),
        stats.accepted,
        log.summary()
    );
    let faults = stats.fault_summary();
    let fail = |why: String| Err(format!("{line}\n    FAILED: {why}\n    faults: {faults}"));
    match got {
        Err(e) => return fail(format!("transfer error: {e}")),
        Ok(n) if n != size => return fail(format!("short transfer: {n} of {size} bytes")),
        Ok(_) => {}
    }
    if elapsed > budget() {
        return fail(format!("took longer than the {:?} budget", budget()));
    }
    if stats.disruptive(RPC_TIMEOUT) == 0 {
        return fail("no disruptive fault was injected (file too small?)".into());
    }
    if log.retries() == 0 && stats.accepted < 2 {
        return fail(
            "disruptive faults were injected but neither a retry nor a reconnect was observed"
                .into(),
        );
    }
    if log.gave_up.load(Ordering::Relaxed) > 0 {
        return fail("an operation gave up (but the transfer succeeded?)".into());
    }
    Ok(Report {
        line: format!("{line}\n    faults: {faults}"),
    })
}

fn finish(test: &str, results: Vec<std::result::Result<Report, String>>) {
    eprintln!("\n== {test} summary");
    let mut failed = 0;
    for r in &results {
        match r {
            Ok(r) => eprintln!("  PASS {}", r.line),
            Err(e) => {
                failed += 1;
                eprintln!("  FAIL {e}");
            }
        }
    }
    assert_eq!(failed, 0, "{test}: {failed} transfer(s) failed (see above)");
}

// ---- read under chaos ----------------------------------------------------------

#[test]
fn soak_read_through_chaos() {
    const T: &str = "soak_read_through_chaos";
    if !soak_enabled(T) {
        return;
    }
    let _g = serial();
    let size = size();
    let seed = fault_seed(T);
    let mut results = Vec::new();
    for t in targets() {
        let size = fit_size(&t, size);
        let scratch = Scratch::create(&t);
        let content = random_u64();
        scratch.write_file("soak.bin", size, content);
        for (i, vers) in parse_versions("NFSC_TEST_SOAK_VERS", "3,4.0,4.1,4.2")
            .into_iter()
            .enumerate()
        {
            let what = format!("[{}] read {vers}", t.name);
            let log = Arc::new(RetryLog::default());
            let chaos = RandomChaos::mixed(
                seed.wrapping_add(i as u64),
                size,
                faults_per_transfer(),
                RPC_TIMEOUT,
            );
            let px = Proxies::start(&t, vers, Schedule::Random(chaos));
            let mut c = match px.connect(
                &t,
                vers,
                rpc_opts(log.policy(CHAOS_RETRY_BUDGET), RPC_TIMEOUT),
            ) {
                Ok(c) => c,
                Err(e) if e.is_version_unsupported() => {
                    eprintln!("{what}: skipped, server does not offer it ({e})");
                    continue;
                }
                Err(e) => {
                    results.push(Err(format!("{what}: connect through proxy: {e}")));
                    continue;
                }
            };
            eprintln!("{what}: start");
            let start = Instant::now();
            let got = lookup_path(&mut c, &scratch.dir, "soak.bin")
                .and_then(|fh| read_verify(c.fs.as_mut(), &fh, content));
            let elapsed = start.elapsed();
            let _ = c.fs.disconnect();
            let r = judge(&what, got, size, elapsed, &px.nfs.stats(), &log);
            eprintln!("{}", r.as_ref().map(|r| &r.line).unwrap_or_else(|e| e));
            results.push(r);
        }
    }
    finish(T, results);
}

// ---- write under chaos ---------------------------------------------------------

#[test]
fn soak_write_through_chaos() {
    const T: &str = "soak_write_through_chaos";
    if !soak_enabled(T) {
        return;
    }
    let _g = serial();
    let size = size();
    let seed = fault_seed(T);
    let mut results = Vec::new();
    for t in targets() {
        let size = fit_size(&t, size);
        let scratch = Scratch::create(&t);
        for (i, vers) in parse_versions("NFSC_TEST_SOAK_WRITE_VERS", "3,4.1")
            .into_iter()
            .enumerate()
        {
            let what = format!("[{}] write {vers}", t.name);
            let name = format!("w-{}.bin", vers_arg(vers));
            let content = random_u64();
            let log = Arc::new(RetryLog::default());
            let chaos = RandomChaos::mixed(
                seed.wrapping_add(i as u64),
                size,
                faults_per_transfer(),
                RPC_TIMEOUT,
            );
            let px = Proxies::start(&t, vers, Schedule::Random(chaos));
            let mut c = match px.connect(
                &t,
                vers,
                rpc_opts(log.policy(CHAOS_RETRY_BUDGET), RPC_TIMEOUT),
            ) {
                Ok(c) => c,
                Err(e) if e.is_version_unsupported() => {
                    eprintln!("{what}: skipped, server does not offer it ({e})");
                    continue;
                }
                Err(e) => {
                    results.push(Err(format!("{what}: connect through proxy: {e}")));
                    continue;
                }
            };
            eprintln!("{what}: start");
            let start = Instant::now();
            let got = (|| {
                let root = c.fs.root();
                let (d, _) = c.fs.lookup(&root, scratch.dir.as_bytes())?;
                let (fh, _) = c.fs.create(
                    &d,
                    name.as_bytes(),
                    CreateMode::Guarded,
                    &SetAttr::default(),
                )?;
                write_pattern(c.fs.as_mut(), &fh, size, content)
            })();
            let elapsed = start.elapsed();
            let _ = c.fs.disconnect();
            let stats = px.nfs.stats();
            drop(px);
            let mut r = judge(&what, got, size, elapsed, &stats, &log);
            if r.is_ok() {
                // A clean, direct read must return exactly what was written.
                let check = connect_direct(&t, NfsVersion::V3, default_rpc()).and_then(|mut c| {
                    let fh = lookup_path(&mut c, &scratch.dir, &name)?;
                    let size_attr = c.fs.getattr(&fh)?.size;
                    let n = read_verify(c.fs.as_mut(), &fh, content)?;
                    let _ = c.fs.disconnect();
                    Ok((size_attr, n))
                });
                match check {
                    Ok((a, n)) if a == size && n == size => {}
                    Ok((a, n)) => {
                        r = Err(format!(
                            "{what}: written file has size {a}, read {n}, want {size}"
                        ))
                    }
                    Err(e) => r = Err(format!("{what}: verifying read failed: {e}")),
                }
            }
            eprintln!("{}", r.as_ref().map(|r| &r.line).unwrap_or_else(|e| e));
            results.push(r);
            scratch.remove(&name);
        }
    }
    finish(T, results);
}

// ---- server restart --------------------------------------------------------------

fn podman(args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new("sudo")
        .args(["-n", "podman"])
        .args(args)
        .output()
}

fn container_ip(name: &str) -> Option<String> {
    let out = podman(&[
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        name,
    ])
    .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Wait until a fresh v3 connection to `t` works.
fn wait_ready(t: &Target, limit: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if let Ok(mut c) = connect_direct(
            t,
            NfsVersion::V3,
            rpc_opts(RetryPolicy::none(), Duration::from_secs(3)),
        ) {
            let _ = c.fs.disconnect();
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

#[test]
fn soak_server_restart() {
    const T: &str = "soak_server_restart";
    if !soak_enabled(T) {
        return;
    }
    if env("NFSC_TEST_SOAK_RESTART").as_deref() != Some("1") {
        eprintln!("{T}: skipped (set NFSC_TEST_SOAK_RESTART=1; restarts the server container)");
        return;
    }
    let _g = serial();
    let size = size();
    let secs = env_u64("NFSC_TEST_SOAK_RESTART_SECS", 30).max(5);
    let mut results = Vec::new();
    for t in targets() {
        let size = fit_size(&t, size);
        if t.name == "knfsd" {
            eprintln!("[knfsd] restart: skipped, its export is tmpfs and a restart loses the file");
            continue;
        }
        let ip_before = container_ip(&t.container);
        if ip_before.as_deref() != Some(&t.ip.to_string()) {
            eprintln!(
                "[{}] restart: skipped, container {} does not have the target address",
                t.name, t.container
            );
            continue;
        }
        let mut scratch = Scratch::create(&t);
        let content = random_u64();
        scratch.write_file("soak.bin", size, content);

        // One reader per version, all in parallel, throttled so each read takes
        // about `secs`; one restart a quarter of the way in. The readers go
        // through fault-free proxies: podman may give the restarted container
        // a new address, and the proxies are pointed at it, as a stable server
        // name would be.
        let versions = parse_versions("NFSC_TEST_SOAK_RESTART_VERS", "3,4.0,4.1,4.2");
        let rate = size as f64 / secs as f64;
        let progress = Arc::new(AtomicU64::new(0));
        let mut proxies = Vec::new();
        let mut readers = Vec::new();
        for vers in versions {
            let px = Arc::new(Proxies::start(&t, vers, Schedule::None));
            proxies.push(px.clone());
            let t = t.clone();
            let dir = scratch.dir.clone();
            let progress = progress.clone();
            readers.push(thread::spawn(move || {
                let what = format!("[{}] read {vers} across restart", t.name);
                let log = Arc::new(RetryLog::default());
                let rpc = rpc_opts(log.policy(RESTART_RETRY_BUDGET), Duration::from_secs(5));
                let mut c = match px.connect(&t, vers, rpc) {
                    Ok(c) => c,
                    Err(e) if e.is_version_unsupported() => return None,
                    Err(e) => return Some(Err(format!("{what}: connect: {e}"))),
                };
                let start = Instant::now();
                let mut v = Verifier::new(content, 0);
                let got = lookup_path(&mut c, &dir, "soak.bin").and_then(|fh| {
                    c.fs.read_stream(&fh, 0, None, &mut |d| {
                        v.check(d)?;
                        progress.fetch_add(d.len() as u64, Ordering::Relaxed);
                        // Throttle: a slow consumer keeps the read going
                        // while the server restarts.
                        let due = Duration::from_secs_f64(v.pos as f64 / rate);
                        if let Some(w) = due.checked_sub(start.elapsed()) {
                            thread::sleep(w);
                        }
                        Ok(())
                    })
                });
                let elapsed = start.elapsed();
                let _ = c.fs.disconnect();
                let line = format!(
                    "{what}: {:.1}s, {} connections, {}",
                    elapsed.as_secs_f64(),
                    px.nfs.stats().accepted,
                    log.summary()
                );
                Some(match got {
                    Err(e) => Err(format!("{line}\n    FAILED: {e}")),
                    Ok(n) if n != size || v.pos != size => {
                        Err(format!("{line}\n    FAILED: short read {n} of {size}"))
                    }
                    Ok(_) if log.retries() == 0 && px.nfs.stats().accepted < 2 => Err(format!(
                        "{line}\n    FAILED: neither a retry nor a reconnect across the restart"
                    )),
                    Ok(_) => Ok(Report { line }),
                })
            }));
        }
        let n_readers = readers.len() as u64;

        // Restart once the readers are about a quarter of the way through.
        let threshold = n_readers * size / 4;
        let wait_start = Instant::now();
        while progress.load(Ordering::Relaxed) < threshold
            && wait_start.elapsed() < Duration::from_secs(secs * 4)
            && !readers.iter().all(|r| r.is_finished())
        {
            thread::sleep(Duration::from_millis(50));
        }
        let at = Instant::now();
        eprintln!(
            "[{}] restarting container {} at {:.1}s ({} MiB read in total)",
            t.name,
            t.container,
            wait_start.elapsed().as_secs_f64(),
            progress.load(Ordering::Relaxed) / MIB
        );
        let restart = podman(&["restart", &t.container]);
        let restart_secs = at.elapsed().as_secs_f64();
        match &restart {
            Ok(o) if o.status.success() => {
                eprintln!("[{}] podman restart done in {restart_secs:.1}s", t.name)
            }
            Ok(o) => results.push(Err(format!(
                "[{}] podman restart failed: {}",
                t.name,
                String::from_utf8_lossy(&o.stderr).trim()
            ))),
            Err(e) => results.push(Err(format!("[{}] podman restart: {e}", t.name))),
        }
        match container_ip(&t.container).and_then(|ip| ip.parse::<IpAddr>().ok()) {
            Some(ip) if ip != t.ip => {
                eprintln!(
                    "[{}] the container came back at a new address; retargeting the proxies \
                     (update the env file with `just testenv-up`)",
                    t.name
                );
                // Wait for MOUNT to be registered at the new address before
                // the v3 proxy looks up its port.
                let mut moved = t.clone();
                moved.ip = ip;
                wait_ready(&moved, Duration::from_secs(120));
                for px in &proxies {
                    px.retarget(ip);
                }
                scratch.target.ip = ip;
            }
            Some(_) => {}
            None => results.push(Err(format!(
                "[{}] cannot read the container address after the restart",
                t.name
            ))),
        }
        for r in readers {
            if let Some(r) = r.join().expect("reader panicked") {
                eprintln!("{}", r.as_ref().map(|r| &r.line).unwrap_or_else(|e| e));
                results.push(r);
            }
        }
        if !wait_ready(&scratch.target, Duration::from_secs(120)) {
            results.push(Err(format!(
                "[{}] server not ready after the restart",
                t.name
            )));
        }
        drop(scratch);
    }
    finish(T, results);
}

// ---- CLI -------------------------------------------------------------------------

#[cfg(feature = "cli")]
mod cli {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Stdio};

    /// A local scratch directory for downloads; removed when dropped.
    struct LocalDir(PathBuf);

    impl LocalDir {
        fn new() -> Self {
            let base = env("NFSC_TEST_SOAK_TMPDIR")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let p = base.join(format!("nfsc-soak-{:016x}", random_u64()));
            std::fs::create_dir_all(&p).expect("create local scratch dir");
            Self(p)
        }
    }

    impl Drop for LocalDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `nfsc shell 127.0.0.1:EXPORT -v VERS -c CMD` through the proxies, with
    /// stdout and stderr going to files in `dir`.
    fn spawn_nfsc(
        t: &Target,
        px: &Proxies,
        vers: NfsVersion,
        cmd: &str,
        dir: &Path,
        tag: &str,
    ) -> Child {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nfsc"));
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("NFSC_") {
                c.env_remove(k);
            }
        }
        c.arg("shell")
            .arg(format!("127.0.0.1:{}", String::from_utf8_lossy(&t.export)))
            .args(["-v", vers_arg(vers), "-c", cmd])
            .env("NFSC_NFS_PORT", px.nfs.port().to_string())
            .env("NFSC_TIMEOUT", RPC_TIMEOUT.as_secs().to_string())
            .env("NFSC_RETRY_TIME", CHAOS_RETRY_BUDGET.as_secs().to_string())
            .env("NFSC_PORT_MODE", "unpriv")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(dir.join(format!("{tag}.out"))).unwrap())
            .stderr(std::fs::File::create(dir.join(format!("{tag}.err"))).unwrap());
        if let Some(m) = &px.mount {
            c.env("NFSC_MOUNT_PORT", m.port().to_string());
        }
        c.spawn().expect("spawn nfsc")
    }

    fn wait_limit(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(s) = child.try_wait().expect("wait") {
                return Some(s);
            }
            if start.elapsed() > limit {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn read_log(dir: &Path, tag: &str) -> (String, String) {
        let r = |ext: &str| {
            std::fs::read_to_string(dir.join(format!("{tag}.{ext}"))).unwrap_or_default()
        };
        (r("out"), r("err"))
    }

    fn tail(s: &str) -> String {
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(8)..].join("\n      ")
    }

    /// Check the downloaded file; Err describes the problem.
    fn check_download(local: &Path, seed: u64, size: u64) -> std::result::Result<(), String> {
        match verify_local(local, seed) {
            Ok(n) if n == size => {}
            Ok(n) => return Err(format!("local file has {n} bytes, want {size}")),
            Err(e) => return Err(format!("local file: {e}")),
        }
        let part = local.with_file_name(format!(
            "{}.nfsc-part",
            local.file_name().unwrap().to_string_lossy()
        ));
        if part.exists() {
            return Err(format!("{} left behind", part.display()));
        }
        Ok(())
    }

    /// `get -cV` of the big file through a chaos proxy: exit 0, exact content.
    #[test]
    fn soak_cli_get_through_chaos() {
        const T: &str = "soak_cli_get_through_chaos";
        if !soak_enabled(T) {
            return;
        }
        let _g = serial();
        let size = size();
        let seed = fault_seed(T);
        let mut results = Vec::new();
        for t in targets() {
            let size = fit_size(&t, size);
            let scratch = Scratch::create(&t);
            let content = random_u64();
            scratch.write_file("soak.bin", size, content);
            for (i, vers) in parse_versions("NFSC_TEST_SOAK_CLI_VERS", "3,4.1")
                .into_iter()
                .enumerate()
            {
                let what = format!("[{}] nfsc get -cV {vers}", t.name);
                let local = LocalDir::new();
                let dest = local.0.join("soak.bin");
                // -V reads the file twice: spread the faults over both reads.
                let chaos = RandomChaos::mixed(
                    seed.wrapping_add(i as u64),
                    2 * size,
                    faults_per_transfer(),
                    RPC_TIMEOUT,
                );
                let px = Proxies::start(&t, vers, Schedule::Random(chaos));
                let cmd = format!("get -cV {}/soak.bin {}", scratch.dir, dest.display());
                let start = Instant::now();
                let mut child = spawn_nfsc(&t, &px, vers, &cmd, &local.0, "get");
                let status = wait_limit(&mut child, budget() * 2);
                let elapsed = start.elapsed();
                let stats = px.nfs.stats();
                let (out, err) = read_log(&local.0, "get");
                let recovered = err.matches("recovered after").count();
                let retries = err.matches("retrying").count();
                let line = format!(
                    "{what}: {:.1}s ({:.0} MiB/s incl. verify read), {} faults ({} disruptive), \
                     {} connections, stderr: {retries} retry / {recovered} recovered lines",
                    elapsed.as_secs_f64(),
                    mib_s(2 * size, elapsed),
                    stats.faults.len(),
                    stats.disruptive(RPC_TIMEOUT),
                    stats.accepted
                );
                let fail = |why: String| {
                    Err(format!(
                        "{line}\n    FAILED: {why}\n    faults: {}\n    stdout: {}\n    stderr: {}",
                        stats.fault_summary(),
                        tail(&out),
                        tail(&err)
                    ))
                };
                let r = match status {
                    None => fail("did not finish in time".into()),
                    Some(s) if !s.success() => fail(format!("exit status {s}")),
                    Some(_) => match check_download(&dest, content, size) {
                        Err(e) => fail(e),
                        Ok(()) if stats.disruptive(RPC_TIMEOUT) > 0 && stats.accepted < 2 => {
                            fail("faults were injected but nfsc never reconnected".into())
                        }
                        Ok(()) => Ok(Report {
                            line: format!("{line}\n    faults: {}", stats.fault_summary()),
                        }),
                    },
                };
                eprintln!("{}", r.as_ref().map(|r| &r.line).unwrap_or_else(|e| e));
                results.push(r);
            }
        }
        finish(T, results);
    }

    /// SIGINT a slow `get -cV` part-way, check the kept part file, then
    /// `get -cV` again (under chaos) resumes and verifies.
    #[test]
    fn soak_cli_interrupt_resume() {
        const T: &str = "soak_cli_interrupt_resume";
        if !soak_enabled(T) {
            return;
        }
        let _g = serial();
        let size = size();
        let seed = fault_seed(T);
        let mut results = Vec::new();
        for t in targets() {
            let size = fit_size(&t, size);
            let scratch = Scratch::create(&t);
            let content = random_u64();
            scratch.write_file("soak.bin", size, content);
            for (i, vers) in parse_versions("NFSC_TEST_SOAK_CLI_VERS", "3,4.1")
                .into_iter()
                .enumerate()
            {
                let what = format!("[{}] nfsc get -cV {vers}, SIGINT, get -cV", t.name);
                results.push(interrupt_resume(
                    &t,
                    &scratch,
                    vers,
                    size,
                    content,
                    seed + i as u64,
                    &what,
                ));
            }
        }
        finish(T, results);
    }

    fn interrupt_resume(
        t: &Target,
        scratch: &Scratch,
        vers: NfsVersion,
        size: u64,
        content: u64,
        seed: u64,
        what: &str,
    ) -> std::result::Result<Report, String> {
        let local = LocalDir::new();
        let dest = local.0.join("soak.bin");
        let part = local.0.join("soak.bin.nfsc-part");
        let cmd = format!("get -cV {}/soak.bin {}", scratch.dir, dest.display());

        // 1. A slow download (about 20 s), interrupted at about 30%.
        let px = Proxies::start(t, vers, Schedule::None);
        px.nfs.set_bandwidth(Some((size / 20).max(MIB)));
        let mut child = spawn_nfsc(t, &px, vers, &cmd, &local.0, "first");
        let start = Instant::now();
        let mut at = 0;
        while start.elapsed() < Duration::from_secs(120) {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            at = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
            if at >= size * 3 / 10 {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let pid = child.id().to_string();
        let _ = Command::new("kill").args(["-INT", &pid]).status();
        let status = wait_limit(&mut child, Duration::from_secs(60));
        let (out1, err1) = read_log(&local.0, "first");
        let fail = |why: String| {
            Err(format!(
                "{what}\n    FAILED: {why}\n    stdout: {}\n    stderr: {}",
                tail(&out1),
                tail(&err1)
            ))
        };
        match status {
            Some(s) if s.code() == Some(130) => {}
            Some(s) => return fail(format!("interrupted nfsc: exit status {s}, want 130")),
            None => return fail("interrupted nfsc did not exit".into()),
        }
        drop(px);
        if dest.exists() {
            return fail("interrupted download created the final file".into());
        }
        let kept = match verify_local(&part, content) {
            Ok(n) if n > 0 && n < size => n,
            Ok(n) => return fail(format!("part file has {n} bytes after SIGINT at ~{at}")),
            Err(e) => return fail(format!("part file after SIGINT: {e}")),
        };

        // 2. Resume under chaos, with verify.
        let chaos = RandomChaos::mixed(
            seed,
            2 * size - kept,
            (faults_per_transfer() / 2).max(2),
            RPC_TIMEOUT,
        );
        let px = Proxies::start(t, vers, Schedule::Random(chaos));
        let start = Instant::now();
        let mut child = spawn_nfsc(t, &px, vers, &cmd, &local.0, "resume");
        let status = wait_limit(&mut child, budget() * 2);
        let elapsed = start.elapsed();
        let stats = px.nfs.stats();
        let (out2, err2) = read_log(&local.0, "resume");
        let line = format!(
            "{what}: interrupted at {} MiB (part verified), resume {:.1}s, {} faults ({} disruptive)",
            kept / MIB,
            elapsed.as_secs_f64(),
            stats.faults.len(),
            stats.disruptive(RPC_TIMEOUT)
        );
        let fail = |why: String| {
            Err(format!(
                "{line}\n    FAILED: {why}\n    faults: {}\n    stdout: {}\n    stderr: {}",
                stats.fault_summary(),
                tail(&out2),
                tail(&err2)
            ))
        };
        match status {
            None => return fail("resume did not finish in time".into()),
            Some(s) if !s.success() => return fail(format!("resume: exit status {s}")),
            Some(_) => {}
        }
        if !out2.contains("resumed at") && !err2.contains("resumed at") {
            return fail("resume output does not say 'resumed at'".into());
        }
        if let Err(e) = check_download(&dest, content, size) {
            return fail(e);
        }
        Ok(Report {
            line: format!("{line}\n    faults: {}", stats.fault_summary()),
        })
    }
}

// ---- regression tests for bugs found by the soak --------------------------------
//
// Short (64 MiB) reads with one scripted fault. They need only
// NFSC_TEST_RW_<SRV> (not NFSC_TEST_SOAK). The v4 ones are ignored until the
// bugs are fixed; run them with `cargo test --test soak_live bug_ -- --ignored`.

/// Read a 64 MiB file over `vers` through a proxy that injects `fault`
/// once 8 MiB have passed; the read must complete and verify.
fn read_across_one_fault(vers: NfsVersion, fault: Fault) {
    let _g = serial();
    let size = 64 * MIB;
    let mut failures = Vec::new();
    for t in targets() {
        let scratch = Scratch::create(&t);
        let content = random_u64();
        scratch.write_file("reset.bin", size, content);
        let log = Arc::new(RetryLog::default());
        let script = vec![(Trigger::AfterBytes(8 * MIB), fault.clone())];
        let px = Proxies::start(&t, vers, Schedule::Script(script));
        let rpc = rpc_opts(log.policy(Duration::from_secs(30)), RPC_TIMEOUT);
        let mut c = match px.connect(&t, vers, rpc) {
            Ok(c) => c,
            Err(e) if e.is_version_unsupported() => continue,
            Err(e) => panic!("[{}] connect: {e}", t.name),
        };
        let start = Instant::now();
        let got = lookup_path(&mut c, &scratch.dir, "reset.bin")
            .and_then(|fh| read_verify(c.fs.as_mut(), &fh, content));
        let line = format!(
            "[{}] {vers} read across {fault}: {:.1}s, {:?}, {}",
            t.name,
            start.elapsed().as_secs_f64(),
            got.as_ref().map_err(|e| e.to_string()),
            log.summary()
        );
        eprintln!("{line}");
        let _ = c.fs.disconnect();
        if !matches!(got, Ok(n) if n == size) {
            failures.push(line);
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn have_rw_target() -> bool {
    let ok = env("NFSC_TEST_RW_GANESHA").is_some() || env("NFSC_TEST_RW_KNFSD").is_some();
    if !ok {
        eprintln!("skipped (set NFSC_TEST_RW_<SRV>)");
    }
    ok
}

/// NFSv3 control for the bug tests below: passes today.
#[test]
fn v3_read_survives_reset_and_down() {
    if have_rw_target() {
        read_across_one_fault(NfsVersion::V3, Fault::Reset);
        read_across_one_fault(NfsVersion::V3, Fault::Down(Duration::from_secs(3)));
    }
}

/// NFSv4.0: an outage (connects refused for 3 s) makes `exec` reconnect, and
/// `reconnect` runs a full `recover`
/// (src/nfs4/backend.rs:636), whose SETCLIENTID uses a new verifier
/// (src/nfs4/state40.rs:141), so the server drops every open of the old client.
/// `exec_stateid` (src/nfs4/backend.rs:772) built the compound with the old
/// stateid before calling `exec`, so every retry after recovery resends the
/// stale stateid, gets NFS4ERR_EXPIRED, recovers again, and the READ gives up
/// when the retry budget runs out.
#[test]
#[ignore = "BUG: NFSv4.0 READ never recovers after a 3 s server outage (NFS4ERR_EXPIRED loop until GaveUp); src/nfs4/backend.rs:636,772"]
fn bug_v40_read_survives_server_down() {
    if have_rw_target() {
        read_across_one_fault(NfsVersion::V4(0), Fault::Down(Duration::from_secs(3)));
    }
}

/// NFSv4.1/4.2: when a reply is lost with the connection, `complete_compound`
/// (src/nfs4/backend.rs:444) and `send` (src/nfs4/backend.rs:383) leave the
/// slot's seqid unchanged although the server executed the request. The resend
/// reuses that slot and seqid, the server answers
/// NFS4ERR_RETRY_UNCACHED_REP (10068), and `exec` (src/nfs4/backend.rs:591)
/// returns it as a hard error, with no retry. (A server that cached the reply
/// would instead return the reply of the lost request, which may be for a
/// different offset.)
#[test]
#[ignore = "BUG: NFSv4.1 READ fails with NFS4ERR_RETRY_UNCACHED_REP after a connection reset; src/nfs4/backend.rs:383,444,591"]
fn bug_v41_read_survives_connection_reset() {
    if have_rw_target() {
        read_across_one_fault(NfsVersion::V4(1), Fault::Reset);
    }
}

#[test]
#[ignore = "BUG: as bug_v41_read_survives_connection_reset, for NFSv4.2"]
fn bug_v42_read_survives_connection_reset() {
    if have_rw_target() {
        read_across_one_fault(NfsVersion::V4(2), Fault::Reset);
    }
}

/// NFSv4.1: the outage path of bug_v40_read_survives_server_down. `reconnect`
/// runs `recover`, which clears the open state; `exec_stateid` keeps resending
/// the old stateid, so every attempt gets NFS4ERR_EXPIRED until the budget
/// runs out (seen in the 1 GiB soak for 4.1 reads and writes and 4.2 reads).
#[test]
#[ignore = "BUG: NFSv4.1 READ never recovers after a 3 s server outage (NFS4ERR_EXPIRED loop until GaveUp); src/nfs4/backend.rs:636,772"]
fn bug_v41_read_survives_server_down() {
    if have_rw_target() {
        read_across_one_fault(NfsVersion::V4(1), Fault::Down(Duration::from_secs(3)));
    }
}

// ---- proxy self-tests (no server needed) ------------------------------------------

/// An echo server on 127.0.0.1; returns its address.
fn echo_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { break };
            thread::spawn(move || {
                let mut r = s.try_clone().unwrap();
                let _ = std::io::copy(&mut r, &mut s);
            });
        }
    });
    addr
}

fn echo_roundtrip(s: &mut TcpStream, len: usize) -> std::io::Result<Vec<u8>> {
    let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
    let mut w = s.try_clone()?;
    let d2 = data.clone();
    let writer = thread::spawn(move || w.write_all(&d2));
    let mut got = vec![0u8; len];
    s.read_exact(&mut got)?;
    writer.join().unwrap()?;
    assert_eq!(got, data, "echo data differs");
    Ok(got)
}

/// Whether the connection is broken: a read returns EOF or an error within `limit`.
fn is_broken(s: &mut TcpStream, limit: Duration) -> bool {
    if s.set_read_timeout(Some(limit)).is_err() {
        return true;
    }
    let mut b = [0u8; 1];
    match s.read(&mut b) {
        Ok(0) => true,
        Ok(_) => false,
        Err(e) => !matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
    }
}

#[test]
fn proxy_forwards_and_counts() {
    let px = ChaosProxy::start(echo_server(), Schedule::None).unwrap();
    let mut s = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut s, 3 * MIB as usize).unwrap();
    let st = px.stats();
    assert_eq!(st.accepted, 1);
    assert_eq!(st.bytes_to_server, 3 * MIB);
    assert_eq!(st.bytes_to_client, 3 * MIB);
    assert!(st.faults.is_empty());
}

#[test]
fn proxy_reset_and_half_close_break_connections() {
    let px = ChaosProxy::start(echo_server(), Schedule::None).unwrap();
    let mut a = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut a, 1000).unwrap();
    px.inject(Fault::Reset);
    assert!(
        is_broken(&mut a, Duration::from_secs(2)),
        "reset did not break"
    );

    let mut b = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut b, 1000).unwrap();
    px.inject(Fault::HalfClose);
    let mut buf = [0u8; 1];
    b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(b.read(&mut buf).unwrap(), 0, "half-close: want EOF");
    // The other direction still accepts data.
    b.write_all(b"still open").unwrap();

    let mut c = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut c, 1000).unwrap();
}

#[test]
fn proxy_set_target_moves_new_connections() {
    let (a, b) = (echo_server(), echo_server());
    let px = ChaosProxy::start(a, Schedule::None).unwrap();
    let mut s1 = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut s1, 1000).unwrap();
    px.set_target(b);
    assert_eq!(px.target(), b);
    // The open connection keeps its server; a new one goes to the new target.
    echo_roundtrip(&mut s1, 1000).unwrap();
    let mut s2 = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut s2, 1000).unwrap();
    // Retarget to a closed port: new connections are aborted.
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    px.set_target(closed);
    let mut s3 = TcpStream::connect(px.addr()).unwrap();
    assert!(is_broken(&mut s3, Duration::from_secs(6)));
}

#[test]
fn proxy_down_refuses_then_recovers() {
    let px = ChaosProxy::start(echo_server(), Schedule::None).unwrap();
    let mut a = TcpStream::connect(px.addr()).unwrap();
    px.inject(Fault::Down(Duration::from_millis(2000)));
    assert!(is_broken(&mut a, Duration::from_secs(2)));
    let e = TcpStream::connect(px.addr()).expect_err("connect while down");
    assert!(
        matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::InvalidInput
        ),
        "{e}"
    );
    thread::sleep(Duration::from_millis(2200));
    let mut b = TcpStream::connect(px.addr()).expect("connect after down");
    echo_roundtrip(&mut b, 1000).unwrap();
}

#[test]
fn proxy_stall_latency_and_bandwidth_delay_data() {
    let px = ChaosProxy::start(echo_server(), Schedule::None).unwrap();
    let mut s = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut s, 10).unwrap();

    px.inject(Fault::Stall(Duration::from_millis(500)));
    let t = Instant::now();
    echo_roundtrip(&mut s, 10).unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(450),
        "{:?}",
        t.elapsed()
    );

    px.inject(Fault::Latency {
        delay: Duration::from_millis(100),
        period: Duration::from_secs(5),
    });
    let t = Instant::now();
    echo_roundtrip(&mut s, 10).unwrap();
    // Both directions are delayed.
    assert!(
        t.elapsed() >= Duration::from_millis(190),
        "{:?}",
        t.elapsed()
    );
    px.set_latency(None);

    px.set_bandwidth(Some(1_000_000));
    let t = Instant::now();
    echo_roundtrip(&mut s, 500_000).unwrap();
    assert!(
        t.elapsed() >= Duration::from_millis(400),
        "{:?}",
        t.elapsed()
    );
    px.set_bandwidth(None);
    let t = Instant::now();
    echo_roundtrip(&mut s, 500_000).unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(400),
        "{:?}",
        t.elapsed()
    );
}

#[test]
fn proxy_script_fires_after_bytes() {
    let script = vec![(Trigger::AfterBytes(200_000), Fault::Reset)];
    let px = ChaosProxy::start(echo_server(), Schedule::Script(script)).unwrap();
    let mut s = TcpStream::connect(px.addr()).unwrap();
    echo_roundtrip(&mut s, 50_000).unwrap();
    assert!(px.stats().faults.is_empty(), "fired too early");
    // Keep sending until the reset arrives.
    let start = Instant::now();
    let broke = loop {
        if echo_roundtrip(&mut s, 50_000).is_err() {
            break true;
        }
        if start.elapsed() > Duration::from_secs(5) {
            break false;
        }
    };
    assert!(broke, "scripted reset did not break the connection");
    let st = px.stats();
    assert_eq!(st.faults.len(), 1);
    assert_eq!(st.faults[0].1, Fault::Reset);
}

#[test]
fn random_schedule_is_reproducible() {
    let c = RandomChaos::mixed(42, 1 << 30, 50, RPC_TIMEOUT);
    let draw = |seed| {
        let mut rng = Rng::new(seed);
        (0..50)
            .map(|_| chaos_proxy::random_fault(&mut rng, &c))
            .collect::<Vec<_>>()
    };
    assert_eq!(draw(7), draw(7));
    assert_ne!(draw(7), draw(8));
    let kinds = draw(7);
    assert!(kinds.iter().any(|f| matches!(f, Fault::Reset)));
    assert!(kinds.iter().any(|f| matches!(f, Fault::Down(_))));
    assert!(
        kinds
            .iter()
            .any(|f| matches!(f, Fault::Stall(d) if *d > RPC_TIMEOUT))
    );
}

#[test]
fn pattern_ranges_agree() {
    let mut whole = vec![0u8; 1000];
    fill(9, 0, &mut whole);
    for (off, len) in [(0, 1), (3, 17), (8, 8), (999, 1), (123, 456)] {
        let mut part = vec![0u8; len];
        fill(9, off as u64, &mut part);
        assert_eq!(part, whole[off..off + len]);
    }
    let mut v = Verifier::new(9, 0);
    v.check(&whole[..500]).unwrap();
    let mut bad = whole[500..].to_vec();
    bad[10] ^= 1;
    let e = v.check(&bad).unwrap_err().to_string();
    assert!(e.contains("offset 510"), "{e}");
}
