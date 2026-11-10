//! Retry policy tests for the NFSv3 backend against a scripted loopback
//! server: outages (connection dropped, then refused), JUKEBOX, silence.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::fs::{CreateMode, FileHandle, Filesystem, SetAttr, Status};
use crate::nfs3::backend::{self, Nfs3};
use crate::nfs3::proto;
use crate::rpc::{Auth, PortMode, Proto, RetryEvent, RetryPolicy, RpcClient, RpcOptions};

const NFS3ERR_JUKEBOX: u32 = 10008;
const NFS3ERR_NOTSUPP: u32 = 10004;

/// What the server does with one call.
enum Action {
    Reply(Vec<u32>),
    /// Read the call but never answer it.
    Ignore,
    /// Drop the connection without answering and refuse connections for a while.
    Outage(Duration),
}

#[derive(Default)]
struct Script {
    file: Vec<u8>,
    /// READs still to be answered with NFS3ERR_JUKEBOX.
    jukebox_reads: u32,
    /// The next READ starts an outage of this length.
    outage_on_read: Option<Duration>,
    silent_reads: bool,
    silent_creates: bool,
    /// Requested by the test: drop the current connection, refuse for this long.
    outage_now: Option<Duration>,
}

struct Fake {
    addr: SocketAddr,
    script: Arc<Mutex<Script>>,
    /// The connection being served, so the test can cut it.
    current: Arc<Mutex<Option<TcpStream>>>,
    reads: Arc<AtomicU32>,
    creates: Arc<AtomicU32>,
    connections: Arc<AtomicU32>,
}

fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_be_bytes()).collect()
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
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

/// Offset of the procedure arguments in a call message (after cred and verf).
fn args_offset(call: &[u8]) -> usize {
    let mut off = 24; // xid, mtype, rpcvers, prog, vers, proc
    for _ in 0..2 {
        let len = u32_at(call, off + 4) as usize;
        off += 8 + len.div_ceil(4) * 4;
    }
    off
}

fn fattr() -> Vec<u32> {
    // NF3REG, mode, nlink, uid, gid, size, used, rdev, fsid, fileid, 3 times.
    vec![
        1, 0o644, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0,
    ]
}

fn read_ok(file: &[u8], offset: u64, count: u32) -> Vec<u32> {
    let start = (offset as usize).min(file.len());
    let end = (start + count as usize).min(file.len());
    let data = &file[start..end];
    let mut v = vec![0, 0, data.len() as u32, u32::from(end == file.len())];
    v.push(data.len() as u32);
    let mut padded = data.to_vec();
    padded.resize(data.len().div_ceil(4) * 4, 0);
    v.extend(
        padded
            .chunks(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap())),
    );
    v
}

impl Fake {
    fn start(script: Script) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let fake = Fake {
            addr,
            script: Arc::new(Mutex::new(script)),
            current: Arc::default(),
            reads: Arc::default(),
            creates: Arc::default(),
            connections: Arc::default(),
        };
        let (script, current) = (fake.script.clone(), fake.current.clone());
        let (reads, creates, conns) = (
            fake.reads.clone(),
            fake.creates.clone(),
            fake.connections.clone(),
        );
        std::thread::spawn(move || {
            let mut listener = Some(listener);
            loop {
                let l = match &listener {
                    Some(l) => l,
                    None => {
                        // Rebind the same port after an outage.
                        match TcpListener::bind(addr) {
                            Ok(l) => listener.insert(l),
                            Err(_) => {
                                std::thread::sleep(Duration::from_millis(20));
                                continue;
                            }
                        }
                    }
                };
                let Ok((mut s, _)) = l.accept() else { return };
                conns.fetch_add(1, Ordering::SeqCst);
                *current.lock().unwrap() = s.try_clone().ok();
                let mut outage = None;
                while let Some(call) = read_record(&mut s) {
                    let procedure = u32_at(&call, 20);
                    let args = &call[args_offset(&call)..];
                    let action = {
                        let mut sc = script.lock().unwrap();
                        match procedure {
                            proto::FSINFO => Action::Reply(vec![NFS3ERR_NOTSUPP, 0]),
                            proto::GETATTR => {
                                let mut v = vec![0];
                                v.extend(fattr());
                                Action::Reply(v)
                            }
                            proto::READ => {
                                reads.fetch_add(1, Ordering::SeqCst);
                                let fhlen = u32_at(args, 0) as usize;
                                let o = 4 + fhlen.div_ceil(4) * 4;
                                let offset = (u64::from(u32_at(args, o)) << 32)
                                    | u64::from(u32_at(args, o + 4));
                                let count = u32_at(args, o + 8);
                                if let Some(d) = sc.outage_on_read.take() {
                                    Action::Outage(d)
                                } else if sc.silent_reads {
                                    Action::Ignore
                                } else if sc.jukebox_reads > 0 {
                                    sc.jukebox_reads -= 1;
                                    Action::Reply(vec![NFS3ERR_JUKEBOX, 0])
                                } else {
                                    Action::Reply(read_ok(&sc.file, offset, count))
                                }
                            }
                            proto::CREATE => {
                                creates.fetch_add(1, Ordering::SeqCst);
                                if sc.silent_creates {
                                    Action::Ignore
                                } else {
                                    let mut v = vec![0, 1, 4, 0x0909_0909, 1];
                                    v.extend(fattr());
                                    v.extend([0, 0]);
                                    Action::Reply(v)
                                }
                            }
                            _ => Action::Reply(vec![NFS3ERR_NOTSUPP, 0]),
                        }
                    };
                    match action {
                        Action::Reply(body) => {
                            let mut msg = call[0..4].to_vec();
                            msg.extend(words(&[1, 0, 0, 0, 0]));
                            msg.extend(words(&body));
                            let mut rec =
                                (0x8000_0000u32 | msg.len() as u32).to_be_bytes().to_vec();
                            rec.extend(msg);
                            if s.write_all(&rec).is_err() {
                                break;
                            }
                        }
                        Action::Ignore => {}
                        Action::Outage(d) => {
                            outage = Some(d);
                            break;
                        }
                    }
                }
                *current.lock().unwrap() = None;
                drop(s);
                let requested = script.lock().unwrap().outage_now.take();
                if let Some(d) = outage.or(requested) {
                    // Nothing listens on the port: connects are refused.
                    listener = None;
                    std::thread::sleep(d);
                }
            }
        });
        fake
    }

    /// Cut the current connection and refuse new ones for `d`.
    fn outage_now(&self, d: Duration) {
        self.script.lock().unwrap().outage_now = Some(d);
        if let Some(s) = self.current.lock().unwrap().as_ref() {
            let _ = s.shutdown(Shutdown::Both);
        }
        // Let the server thread notice and close its listener.
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn fast_policy(budget: Duration) -> RetryPolicy {
    RetryPolicy {
        budget,
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(200),
        ..RetryPolicy::default()
    }
}

fn connect(fake: &Fake, timeout: Duration, retry: RetryPolicy) -> Nfs3 {
    let opts = RpcOptions {
        proto: Proto::Tcp,
        port_mode: PortMode::Unprivileged,
        timeout,
        auth: Auth::None,
        retry,
    };
    let client =
        RpcClient::connect(fake.addr, crate::nfs3::PROGRAM, crate::nfs3::VERSION, &opts).unwrap();
    backend::open(
        client,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        None,
        opts,
        b"/".to_vec(),
        FileHandle(vec![1, 2, 3, 4]),
    )
    .unwrap()
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
}

fn read_all(fs: &mut Nfs3, len: u64) -> crate::error::Result<Vec<u8>> {
    let mut out = Vec::new();
    let fh = FileHandle(vec![5; 8]);
    fs.read_stream(&fh, 0, Some(len), &mut |b: &[u8]| {
        out.extend_from_slice(b);
        Ok(())
    })?;
    Ok(out)
}

#[test]
fn read_survives_a_server_that_refuses_connections_for_a_while() {
    let file = pattern(600_000);
    let fake = Fake::start(Script {
        file: file.clone(),
        outage_on_read: Some(Duration::from_millis(1200)),
        ..Script::default()
    });
    let events = Arc::new(Mutex::new(Vec::new()));
    let ev = events.clone();
    let mut policy = fast_policy(Duration::from_secs(20));
    policy.on_retry = Some(Arc::new(move |e: &RetryEvent<'_>| {
        let s = match e {
            RetryEvent::Retrying { op, error, .. } => format!("retry {op}: {error}"),
            RetryEvent::Recovered { op, .. } => format!("recovered {op}"),
            RetryEvent::GaveUp { op, .. } => format!("gave up {op}"),
        };
        ev.lock().unwrap().push(s);
    }));
    let mut fs = connect(&fake, Duration::from_secs(2), policy);
    let started = Instant::now();
    let out = read_all(&mut fs, file.len() as u64).expect("read completes after the outage");
    assert_eq!(out, file);
    assert!(
        started.elapsed() >= Duration::from_millis(1000),
        "the outage was waited out"
    );
    let events = events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.starts_with("retry READ") && e.contains("refused")),
        "connection refusals were retried: {events:?}"
    );
    assert!(events.iter().any(|e| e == "recovered READ"), "{events:?}");
    assert!(fake.connections.load(Ordering::SeqCst) >= 2);
}

#[test]
fn jukebox_twice_then_the_read_completes() {
    let file = pattern(10_000);
    let fake = Fake::start(Script {
        file: file.clone(),
        jukebox_reads: 2,
        ..Script::default()
    });
    let mut fs = connect(
        &fake,
        Duration::from_secs(2),
        fast_policy(Duration::from_secs(10)),
    );
    let (data, eof) = fs.read(&FileHandle(vec![5; 8]), 0, 65536).unwrap();
    assert_eq!(data, file);
    assert!(eof);
    assert_eq!(fake.reads.load(Ordering::SeqCst), 3);
}

#[test]
fn jukebox_in_a_pipelined_stream_completes() {
    let file = pattern(300_000);
    let fake = Fake::start(Script {
        file: file.clone(),
        jukebox_reads: 2,
        ..Script::default()
    });
    let mut fs = connect(
        &fake,
        Duration::from_secs(2),
        fast_policy(Duration::from_secs(10)),
    );
    assert_eq!(read_all(&mut fs, file.len() as u64).unwrap(), file);
}

#[test]
fn exhausted_budget_is_a_clear_error() {
    let fake = Fake::start(Script {
        file: pattern(1000),
        silent_reads: true,
        ..Script::default()
    });
    let mut fs = connect(
        &fake,
        Duration::from_millis(200),
        fast_policy(Duration::from_millis(800)),
    );
    let started = Instant::now();
    let e = read_all(&mut fs, 1000).expect_err("the server never answers");
    assert!(started.elapsed() < Duration::from_secs(5));
    match &e {
        Error::GaveUp {
            op, attempts, last, ..
        } => {
            assert_eq!(*op, "READ");
            assert!(*attempts >= 2, "{attempts}");
            assert!(matches!(**last, Error::Timeout), "{last:?}");
        }
        other => panic!("expected GaveUp, got {other:?}"),
    }
    let msg = e.to_string();
    assert!(
        msg.contains("gave up on READ after retrying for"),
        "message says what gave up and after how long: {msg}"
    );
}

#[test]
fn jukebox_until_the_budget_runs_out() {
    let fake = Fake::start(Script {
        file: pattern(1000),
        jukebox_reads: u32::MAX,
        ..Script::default()
    });
    let mut fs = connect(
        &fake,
        Duration::from_secs(2),
        fast_policy(Duration::from_millis(500)),
    );
    match fs.read(&FileHandle(vec![5; 8]), 0, 100) {
        Err(Error::GaveUp { last, .. }) => {
            assert!(matches!(*last, Error::Nfs(Status::Jukebox)), "{last:?}")
        }
        other => panic!("expected GaveUp, got {other:?}"),
    }
}

#[test]
fn zero_budget_disables_retries() {
    let fake = Fake::start(Script {
        file: pattern(1000),
        jukebox_reads: 1,
        ..Script::default()
    });
    let mut fs = connect(&fake, Duration::from_secs(2), RetryPolicy::none());
    match fs.read(&FileHandle(vec![5; 8]), 0, 100) {
        Err(Error::Nfs(Status::Jukebox)) => {}
        other => panic!("expected JUKEBOX, got {other:?}"),
    }
    assert_eq!(fake.reads.load(Ordering::SeqCst), 1);
}

#[test]
fn timed_out_create_is_not_resent() {
    let fake = Fake::start(Script {
        silent_creates: true,
        ..Script::default()
    });
    let mut fs = connect(
        &fake,
        Duration::from_millis(300),
        fast_policy(Duration::from_secs(10)),
    );
    let started = Instant::now();
    let r = fs.create(
        &FileHandle(vec![1, 2, 3, 4]),
        b"new",
        CreateMode::Guarded,
        &SetAttr::default(),
    );
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "no retry loop");
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fake.creates.load(Ordering::SeqCst), 1, "sent exactly once");
}

#[test]
fn create_waits_for_a_refusing_server_when_nothing_was_sent() {
    let fake = Fake::start(Script::default());
    let mut fs = connect(&fake, Duration::from_secs(2), RetryPolicy::none());
    let root = FileHandle(vec![1, 2, 3, 4]);
    fake.outage_now(Duration::from_millis(800));
    // Without retries the GETATTR fails and the connection is dropped.
    assert!(fs.getattr(&root).is_err());
    fs.client
        .set_retry_policy(fast_policy(Duration::from_secs(10)));
    // Reconnecting is refused for a while; CREATE was never sent, so it is
    // safe to wait for the server.
    let (fh, _) = fs
        .create(&root, b"new", CreateMode::Guarded, &SetAttr::default())
        .expect("create after the outage");
    assert_eq!(fh, FileHandle(vec![9; 4]));
    assert_eq!(fake.creates.load(Ordering::SeqCst), 1);
}

#[test]
fn idempotency_classification() {
    for p in [
        proto::NULL,
        proto::GETATTR,
        proto::LOOKUP,
        proto::ACCESS,
        proto::READLINK,
        proto::READ,
        proto::WRITE,
        proto::READDIR,
        proto::READDIRPLUS,
        proto::FSSTAT,
        proto::FSINFO,
        proto::PATHCONF,
        proto::COMMIT,
    ] {
        assert!(backend::idempotent(p), "{}", backend::proc_name(p));
    }
    for p in [
        proto::SETATTR,
        proto::CREATE,
        proto::MKDIR,
        proto::SYMLINK,
        proto::REMOVE,
        proto::RMDIR,
        proto::RENAME,
        proto::LINK,
    ] {
        assert!(!backend::idempotent(p), "{}", backend::proc_name(p));
    }
}
