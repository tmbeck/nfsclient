//! A TCP proxy that injects network faults, for chaos and soak tests.
//!
//! [`ChaosProxy::start`] listens on `127.0.0.1:<ephemeral>` and forwards every
//! accepted connection to one target address. Faults ([`Fault`]) are injected
//! by hand ([`ChaosProxy::inject`]), from a fixed script, or from a seeded
//! random schedule ([`Schedule`]). Scheduled faults can fire at a time since
//! the proxy started or after a number of bytes has passed through it, so a
//! fast transfer still sees its faults and an idle proxy sees none.
//!
//! Each connection uses four threads: a reader and a writer per direction,
//! joined by a bounded channel. Writers apply stalls, added latency and the
//! bandwidth cap; readers only read, so latency does not reduce throughput.
//!
//! Include it from a test crate with
//! `#[path = "support/chaos_proxy.rs"] mod chaos_proxy;`. It uses only std and
//! `socket2` (already a dependency of the crate).

#![allow(dead_code)]

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// One injected fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Abort every open connection (both sides; the client gets a reset or EOF).
    Reset,
    /// Close the proxy-to-client direction of every open connection (the
    /// client reads EOF); requests from the client still reach the server.
    HalfClose,
    /// Stop forwarding in both directions on all connections, including ones
    /// accepted during the stall, for this long. Nothing is dropped.
    Stall(Duration),
    /// Delay every forwarded chunk by `delay` for `period`.
    Latency { delay: Duration, period: Duration },
    /// Cap the throughput of each direction of each connection for `period`.
    Bandwidth {
        bytes_per_sec: u64,
        period: Duration,
    },
    /// "Server down": abort every connection and close the listening socket
    /// for this long, so new connections are refused (ECONNREFUSED).
    Down(Duration),
}

impl Fault {
    /// Whether the fault breaks connections (the client must reconnect).
    pub fn breaks_connections(&self) -> bool {
        matches!(self, Fault::Reset | Fault::HalfClose | Fault::Down(_))
    }

    /// Whether a client with this RPC timeout must notice the fault: it
    /// breaks connections, or it stalls for longer than the timeout.
    pub fn disrupts(&self, rpc_timeout: Duration) -> bool {
        match self {
            Fault::Stall(d) => *d > rpc_timeout,
            f => f.breaks_connections(),
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Reset => write!(f, "reset"),
            Fault::HalfClose => write!(f, "half-close"),
            Fault::Stall(d) => write!(f, "stall {:.1}s", d.as_secs_f64()),
            Fault::Latency { delay, period } => write!(
                f,
                "latency {}ms for {:.1}s",
                delay.as_millis(),
                period.as_secs_f64()
            ),
            Fault::Bandwidth {
                bytes_per_sec,
                period,
            } => write!(
                f,
                "bandwidth {:.1} MB/s for {:.1}s",
                *bytes_per_sec as f64 / 1e6,
                period.as_secs_f64()
            ),
            Fault::Down(d) => write!(f, "down {:.1}s", d.as_secs_f64()),
        }
    }
}

/// When a scripted fault fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// This long after the proxy started.
    At(Duration),
    /// Once this many bytes (both directions together) have been forwarded.
    AfterBytes(u64),
}

/// Seeded random fault generator. Every `gap_bytes` (uniform in the range)
/// of forwarded traffic one fault is picked by `weights` and its duration
/// drawn from the matching range.
#[derive(Debug, Clone)]
pub struct RandomChaos {
    pub seed: u64,
    /// Bytes between two faults, uniform in `[lo, hi]`.
    pub gap_bytes: (u64, u64),
    /// Stop after this many faults.
    pub max_faults: usize,
    /// Weights of reset, half-close, stall, latency, bandwidth, down.
    pub weights: [u32; 6],
    pub stall: (Duration, Duration),
    pub down: (Duration, Duration),
    pub latency: (Duration, Duration),
    pub bandwidth: (u64, u64),
    /// How long latency and bandwidth faults last.
    pub period: (Duration, Duration),
}

impl RandomChaos {
    /// A mix of every fault kind, about `faults` of them over `total_bytes`.
    /// Stalls last 1-5 s longer than `rpc_timeout`, so they are noticed.
    pub fn mixed(seed: u64, total_bytes: u64, faults: usize, rpc_timeout: Duration) -> Self {
        let mean = (total_bytes / (faults.max(1) as u64 + 1)).max(1);
        Self {
            seed,
            gap_bytes: (mean / 2, mean + mean / 2),
            max_faults: faults,
            weights: [3, 2, 2, 1, 1, 2],
            stall: (
                rpc_timeout + Duration::from_secs(1),
                rpc_timeout + Duration::from_secs(5),
            ),
            down: (Duration::from_secs(1), Duration::from_secs(6)),
            latency: (Duration::from_millis(5), Duration::from_millis(60)),
            bandwidth: (2_000_000, 40_000_000),
            period: (Duration::from_secs(1), Duration::from_secs(4)),
        }
    }
}

/// What the proxy does on its own.
#[derive(Debug, Clone)]
pub enum Schedule {
    /// Nothing; faults only via [`ChaosProxy::inject`].
    None,
    /// These faults, each once, when its trigger is reached.
    Script(Vec<(Trigger, Fault)>),
    Random(RandomChaos),
}

/// Counters and the fault log of a proxy.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub accepted: u64,
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    /// Every injected fault with its time since the proxy started.
    pub faults: Vec<(Duration, Fault)>,
}

impl Stats {
    pub fn disruptive(&self, rpc_timeout: Duration) -> usize {
        self.faults
            .iter()
            .filter(|(_, f)| f.disrupts(rpc_timeout))
            .count()
    }

    pub fn fault_summary(&self) -> String {
        self.faults
            .iter()
            .map(|(t, f)| format!("{:.1}s {f}", t.as_secs_f64()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// A shaping setting that may expire: `(value, until)`; `until` None is forever.
type Timed<T> = Option<(T, Option<Instant>)>;

fn timed_value<T: Copy>(t: &Timed<T>, now: Instant) -> Option<T> {
    match t {
        Some((v, None)) => Some(*v),
        Some((v, Some(until))) if *until > now => Some(*v),
        _ => None,
    }
}

#[derive(Default)]
struct Ctl {
    stall_until: Option<Instant>,
    down_until: Option<Instant>,
    latency: Timed<Duration>,
    bandwidth: Timed<u64>,
}

struct Conn {
    client: TcpStream,
    server: TcpStream,
    dead: AtomicBool,
    /// The proxy-to-client direction was closed (half-close).
    to_client_closed: AtomicBool,
}

impl Conn {
    fn kill(&self) {
        if self.dead.swap(true, Ordering::SeqCst) {
            return;
        }
        // Linger 0: the final close sends a RST instead of a FIN.
        let _ = socket2::SockRef::from(&self.client).set_linger(Some(Duration::ZERO));
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.server.shutdown(Shutdown::Both);
    }
}

struct Shared {
    target: Mutex<SocketAddr>,
    start: Instant,
    stop: AtomicBool,
    accepted: AtomicU64,
    to_server: AtomicU64,
    to_client: AtomicU64,
    ctl: Mutex<Ctl>,
    conns: Mutex<Vec<Arc<Conn>>>,
    faults: Mutex<Vec<(Duration, Fault)>>,
    verbose: bool,
}

impl Shared {
    fn total_bytes(&self) -> u64 {
        self.to_server.load(Ordering::Relaxed) + self.to_client.load(Ordering::Relaxed)
    }

    fn kill_all(&self) {
        let conns = std::mem::take(&mut *self.conns.lock().unwrap());
        for c in conns {
            c.kill();
        }
    }

    fn inject(&self, fault: Fault) {
        let now = Instant::now();
        if self.verbose {
            eprintln!(
                "[chaos {}] {:.2}s: {fault}",
                self.target.lock().unwrap(),
                self.start.elapsed().as_secs_f64()
            );
        }
        self.faults
            .lock()
            .unwrap()
            .push((now.duration_since(self.start), fault.clone()));
        match fault {
            Fault::Reset => self.kill_all(),
            Fault::HalfClose => {
                for c in self.conns.lock().unwrap().iter() {
                    c.to_client_closed.store(true, Ordering::SeqCst);
                    let _ = c.client.shutdown(Shutdown::Write);
                }
            }
            Fault::Stall(d) => self.ctl.lock().unwrap().stall_until = Some(now + d),
            Fault::Latency { delay, period } => {
                self.ctl.lock().unwrap().latency = Some((delay, Some(now + period)))
            }
            Fault::Bandwidth {
                bytes_per_sec,
                period,
            } => self.ctl.lock().unwrap().bandwidth = Some((bytes_per_sec, Some(now + period))),
            Fault::Down(d) => {
                self.ctl.lock().unwrap().down_until = Some(now + d);
                self.kill_all();
            }
        }
    }

    fn stalled(&self) -> bool {
        let now = Instant::now();
        self.ctl
            .lock()
            .unwrap()
            .stall_until
            .is_some_and(|u| u > now)
    }

    fn down(&self) -> bool {
        let now = Instant::now();
        self.ctl.lock().unwrap().down_until.is_some_and(|u| u > now)
    }

    fn shaping(&self) -> (Option<Duration>, Option<u64>) {
        let now = Instant::now();
        let ctl = self.ctl.lock().unwrap();
        (
            timed_value(&ctl.latency, now),
            timed_value(&ctl.bandwidth, now),
        )
    }
}

/// The proxy. Dropping it stops it and aborts every connection.
pub struct ChaosProxy {
    addr: SocketAddr,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl ChaosProxy {
    /// Listen on 127.0.0.1 (ephemeral port) and forward to `target`.
    pub fn start(target: SocketAddr, schedule: Schedule) -> io::Result<Self> {
        Self::start_opts(
            target,
            schedule,
            std::env::var_os("NFSC_TEST_CHAOS_VERBOSE").is_some(),
        )
    }

    /// As [`ChaosProxy::start`]; `verbose` logs every fault on stderr.
    pub fn start_opts(target: SocketAddr, schedule: Schedule, verbose: bool) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            target: Mutex::new(target),
            start: Instant::now(),
            stop: AtomicBool::new(false),
            accepted: AtomicU64::new(0),
            to_server: AtomicU64::new(0),
            to_client: AtomicU64::new(0),
            ctl: Mutex::new(Ctl::default()),
            conns: Mutex::new(Vec::new()),
            faults: Mutex::new(Vec::new()),
            verbose,
        });
        let mut threads = Vec::new();
        {
            let shared = shared.clone();
            threads.push(thread::spawn(move || accept_loop(listener, addr, shared)));
        }
        if !matches!(schedule, Schedule::None) {
            let shared = shared.clone();
            threads.push(thread::spawn(move || scheduler(schedule, shared)));
        }
        Ok(Self {
            addr,
            shared,
            threads,
        })
    }

    /// Where clients connect.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Forward new connections to `target` from now on (open ones keep their
    /// server). For a server that comes back at another address, like a NAS
    /// whose name stays stable.
    pub fn set_target(&self, target: SocketAddr) {
        *self.shared.target.lock().unwrap() = target;
    }

    pub fn target(&self) -> SocketAddr {
        *self.shared.target.lock().unwrap()
    }

    pub fn inject(&self, fault: Fault) {
        self.shared.inject(fault);
    }

    /// A permanent bandwidth cap per direction per connection (None: off).
    /// A [`Fault::Bandwidth`] replaces it until the fault's period ends.
    pub fn set_bandwidth(&self, bytes_per_sec: Option<u64>) {
        self.shared.ctl.lock().unwrap().bandwidth = bytes_per_sec.map(|b| (b, None));
    }

    /// A permanent added latency per forwarded chunk (None: off).
    pub fn set_latency(&self, delay: Option<Duration>) {
        self.shared.ctl.lock().unwrap().latency = delay.map(|d| (d, None));
    }

    /// Connections currently open.
    pub fn open_connections(&self) -> usize {
        let mut conns = self.shared.conns.lock().unwrap();
        conns.retain(|c| !c.dead.load(Ordering::SeqCst));
        conns.len()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            accepted: self.shared.accepted.load(Ordering::Relaxed),
            bytes_to_server: self.shared.to_server.load(Ordering::Relaxed),
            bytes_to_client: self.shared.to_client.load(Ordering::Relaxed),
            faults: self.shared.faults.lock().unwrap().clone(),
        }
    }
}

impl Drop for ChaosProxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.kill_all();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        self.shared.kill_all();
    }
}

fn accept_loop(listener: TcpListener, addr: SocketAddr, shared: Arc<Shared>) {
    let mut listener = Some(listener);
    while !shared.stop.load(Ordering::SeqCst) {
        if shared.down() {
            // Closing the socket makes connects fail with ECONNREFUSED.
            listener = None;
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let Some(l) = listener.as_ref() else {
            // std sets SO_REUSEADDR on Unix, so the port can be bound again.
            match TcpListener::bind(addr).and_then(|l| l.set_nonblocking(true).map(|_| l)) {
                Ok(l) => listener = Some(l),
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
            continue;
        };
        match l.accept() {
            Ok((client, _)) => {
                shared.accepted.fetch_add(1, Ordering::Relaxed);
                let shared = shared.clone();
                thread::spawn(move || serve(client, shared));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2))
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn serve(client: TcpStream, shared: Arc<Shared>) {
    let _ = client.set_nonblocking(false);
    let target = *shared.target.lock().unwrap();
    let server = match TcpStream::connect_timeout(&target, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => {
            // Target unreachable: abort the client connection.
            let _ = socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO));
            return;
        }
    };
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let (Ok(c2), Ok(s2)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let conn = Arc::new(Conn {
        client,
        server,
        dead: AtomicBool::new(false),
        to_client_closed: AtomicBool::new(false),
    });
    if shared.stop.load(Ordering::SeqCst) || shared.down() {
        conn.kill();
        return;
    }
    shared.conns.lock().unwrap().push(conn.clone());
    let (Ok(c3), Ok(s3)) = (c2.try_clone(), s2.try_clone()) else {
        conn.kill();
        return;
    };
    // client -> server
    pipe(c2, s2, conn.clone(), shared.clone(), Dir::ToServer);
    // server -> client
    pipe(s3, c3, conn, shared, Dir::ToClient);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToServer,
    ToClient,
}

type Chunk = (Instant, Vec<u8>);

fn pipe(mut src: TcpStream, dst: TcpStream, conn: Arc<Conn>, shared: Arc<Shared>, dir: Dir) {
    let (tx, rx) = mpsc::sync_channel::<Chunk>(64);
    {
        let conn = conn.clone();
        thread::spawn(move || read_side(&mut src, tx, &conn));
    }
    thread::spawn(move || write_side(dst, rx, conn, shared, dir));
}

fn read_side(src: &mut TcpStream, tx: SyncSender<Chunk>, conn: &Conn) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if conn.dead.load(Ordering::SeqCst)
                    || tx.send((Instant::now(), buf[..n].to_vec())).is_err()
                {
                    break;
                }
            }
        }
    }
}

fn write_side(
    mut dst: TcpStream,
    rx: Receiver<Chunk>,
    conn: Arc<Conn>,
    shared: Arc<Shared>,
    dir: Dir,
) {
    let closed = |conn: &Conn| {
        conn.dead.load(Ordering::SeqCst)
            || (dir == Dir::ToClient && conn.to_client_closed.load(Ordering::SeqCst))
    };
    let mut clean_eof = false;
    'outer: loop {
        let (t, data) = match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(c) => c,
            Err(RecvTimeoutError::Timeout) => {
                if closed(&conn) || shared.stop.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                clean_eof = true;
                break;
            }
        };
        while shared.stalled() {
            if closed(&conn) || shared.stop.load(Ordering::SeqCst) {
                break 'outer;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let (latency, bandwidth) = shared.shaping();
        if let Some(d) = latency {
            let due = t + d;
            while Instant::now() < due {
                if closed(&conn) {
                    break 'outer;
                }
                thread::sleep((due - Instant::now()).min(Duration::from_millis(10)));
            }
        }
        if closed(&conn) {
            break;
        }
        let started = Instant::now();
        if dst.write_all(&data).is_err() {
            break;
        }
        let counter = match dir {
            Dir::ToServer => &shared.to_server,
            Dir::ToClient => &shared.to_client,
        };
        counter.fetch_add(data.len() as u64, Ordering::Relaxed);
        if let Some(rate) = bandwidth.filter(|r| *r > 0) {
            let want = Duration::from_secs_f64(data.len() as f64 / rate as f64);
            if let Some(rest) = want.checked_sub(started.elapsed()) {
                thread::sleep(rest);
            }
        }
    }
    if clean_eof && !conn.dead.load(Ordering::SeqCst) {
        // The source closed: pass the FIN on, keep the other direction.
        let _ = dst.shutdown(Shutdown::Write);
    } else if !(dir == Dir::ToClient && conn.to_client_closed.load(Ordering::SeqCst)) {
        conn.kill();
    }
}

/// splitmix64: small, seedable, good enough for fault schedules.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `[lo, hi]`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }

    pub fn duration(&mut self, (lo, hi): (Duration, Duration)) -> Duration {
        Duration::from_millis(self.range(lo.as_millis() as u64, hi.as_millis() as u64))
    }
}

pub fn random_fault(rng: &mut Rng, c: &RandomChaos) -> Fault {
    let total: u32 = c.weights.iter().sum();
    let mut pick = rng.range(0, total.max(1) as u64 - 1) as u32;
    let mut kind = 0;
    for (i, w) in c.weights.iter().enumerate() {
        if pick < *w {
            kind = i;
            break;
        }
        pick -= w;
    }
    match kind {
        0 => Fault::Reset,
        1 => Fault::HalfClose,
        2 => Fault::Stall(rng.duration(c.stall)),
        3 => Fault::Latency {
            delay: rng.duration(c.latency),
            period: rng.duration(c.period),
        },
        4 => Fault::Bandwidth {
            bytes_per_sec: rng.range(c.bandwidth.0, c.bandwidth.1),
            period: rng.duration(c.period),
        },
        _ => Fault::Down(rng.duration(c.down)),
    }
}

fn scheduler(schedule: Schedule, shared: Arc<Shared>) {
    let tick = Duration::from_millis(2);
    match schedule {
        Schedule::None => {}
        Schedule::Script(mut items) => {
            while !items.is_empty() && !shared.stop.load(Ordering::SeqCst) {
                let (elapsed, bytes) = (shared.start.elapsed(), shared.total_bytes());
                let mut i = 0;
                while i < items.len() {
                    let due = match items[i].0 {
                        Trigger::At(t) => elapsed >= t,
                        Trigger::AfterBytes(b) => bytes >= b,
                    };
                    if due {
                        let (_, f) = items.remove(i);
                        shared.inject(f);
                    } else {
                        i += 1;
                    }
                }
                thread::sleep(tick);
            }
        }
        Schedule::Random(c) => {
            let mut rng = Rng::new(c.seed);
            let mut fired = 0;
            let mut next = rng.range(c.gap_bytes.0, c.gap_bytes.1);
            while fired < c.max_faults && !shared.stop.load(Ordering::SeqCst) {
                if shared.total_bytes() >= next {
                    shared.inject(random_fault(&mut rng, &c));
                    fired += 1;
                    next = shared.total_bytes() + rng.range(c.gap_bytes.0, c.gap_bytes.1);
                }
                thread::sleep(tick);
            }
        }
    }
}
