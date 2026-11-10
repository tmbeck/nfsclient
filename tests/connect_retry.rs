//! `fs::connect` against a server that is down or restarting: connection
//! setup is retried under the retry policy, while "version not offered"
//! answers still fall through to the next version at once.
//!
//! Uses the in-process NFSv3 + MOUNT + portmap fake from
//! tests/nfs3_backend/server.rs. The portmap test re-runs itself inside a
//! private user + network namespace (`unshare -rn`) so it may bind port 111;
//! where namespaces are not available it prints a note and passes.

#[path = "nfs3_backend/server.rs"]
mod server;

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nfsc::error::{AcceptError, Error};
use nfsc::fs::{ConnectOptions, NfsVersion, VersionPref, connect};
use nfsc::rpc::{Auth, PortMode, Proto, RetryEvent, RetryPolicy, RpcOptions};

use server::{Config, FakeNfs3, MOUNT_PROG, NFS_PROG, start, start_with};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Retry events as (kind, op).
type Log = Arc<Mutex<Vec<(&'static str, &'static str)>>>;

fn policy(budget: Duration) -> (RetryPolicy, Log) {
    let log: Log = Arc::default();
    let l = log.clone();
    let p = RetryPolicy {
        budget,
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(300),
        on_retry: Some(Arc::new(move |e: &RetryEvent<'_>| {
            l.lock().unwrap().push(match e {
                RetryEvent::Retrying { op, .. } => ("retry", *op),
                RetryEvent::Recovered { op, .. } => ("recovered", *op),
                RetryEvent::GaveUp { op, .. } => ("gave up", *op),
            })
        })),
        ..RetryPolicy::default()
    };
    (p, log)
}

fn opts(port: u16, version: VersionPref, retry: RetryPolicy) -> ConnectOptions {
    ConnectOptions {
        rpc: RpcOptions {
            proto: Proto::Tcp,
            port_mode: PortMode::Unprivileged,
            timeout: Duration::from_secs(2),
            auth: Auth::None,
            retry,
        },
        nfs_port: Some(port),
        mount_port: Some(port),
        version,
    }
}

/// A loopback port nothing listens on (connections are refused).
fn dead_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn count(log: &Log, kind: &str) -> usize {
    log.lock().unwrap().iter().filter(|e| e.0 == kind).count()
}

/// Take the fake down for `d` and wait until its listener is closed.
fn take_down(srv: &FakeNfs3, d: Duration) {
    srv.restart(d);
    std::thread::sleep(Duration::from_millis(50));
}

fn waits_for_restart(version: VersionPref) {
    let srv = start();
    take_down(&srv, Duration::from_millis(1500));
    let (p, log) = policy(Duration::from_secs(20));
    let started = Instant::now();
    let mut c = connect(LOCALHOST, b"/export", &opts(srv.port, version, p))
        .unwrap_or_else(|e| panic!("connect: {e}"));
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1200), "{took:?}");
    assert!(took < Duration::from_secs(10), "{took:?}");
    assert_eq!(c.fs.version(), NfsVersion::V3);
    c.fs.getattr(&c.fs.root()).unwrap();
    let log = log.lock().unwrap().clone();
    assert!(log.iter().all(|e| e.1 == "connect"), "{log:?}");
    assert!(log.iter().any(|e| e.0 == "retry"), "{log:?}");
    assert_eq!(log.last(), Some(&("recovered", "connect")), "{log:?}");
    c.fs.disconnect().unwrap();
}

#[test]
fn exact_v3_connect_waits_for_a_restarting_server() {
    waits_for_restart(VersionPref::Exact(NfsVersion::V3));
}

#[test]
fn auto_connect_waits_for_a_restarting_server_then_negotiates() {
    // While down, every version is refused (transient); once up, NFSv4
    // gets PROG_MISMATCH from the v3-only fake and falls through to v3.
    waits_for_restart(VersionPref::Auto);
}

#[test]
fn auto_against_a_down_host_gives_up_once_within_the_budget() {
    let (p, log) = policy(Duration::from_millis(800));
    let started = Instant::now();
    let r = connect(
        LOCALHOST,
        b"/export",
        &opts(dead_port(), VersionPref::Auto, p),
    );
    let took = started.elapsed();
    match &r {
        Err(Error::GaveUp { op, last, .. }) => {
            assert_eq!(*op, "connect");
            assert!(last.is_retryable(), "{last}");
        }
        other => panic!("expected GaveUp, got {:?}", other.as_ref().err()),
    }
    // One budget for the whole negotiation, not one per version.
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert_eq!(count(&log, "gave up"), 1);
    assert!(count(&log, "retry") >= 1);
    assert!(log.lock().unwrap().iter().all(|e| e.1 == "connect"));
}

#[test]
fn zero_budget_reports_a_down_host_at_once() {
    let started = Instant::now();
    let r = connect(
        LOCALHOST,
        b"/export",
        &opts(
            dead_port(),
            VersionPref::Exact(NfsVersion::V3),
            RetryPolicy::none(),
        ),
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    match r {
        Err(e @ Error::Io(_)) => assert!(e.is_retryable(), "{e}"),
        Err(e) => panic!("expected the refusal itself, got {e}"),
        Ok(_) => panic!("connected to nothing"),
    }
}

#[test]
fn prog_mismatch_falls_through_without_waiting() {
    let srv = start();
    let (p, log) = policy(Duration::from_secs(20));
    let started = Instant::now();
    let c = connect(LOCALHOST, b"/export", &opts(srv.port, VersionPref::Auto, p)).unwrap();
    assert_eq!(c.fs.version(), NfsVersion::V3);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());
}

#[test]
fn version_not_offered_is_final_not_retried() {
    let srv = start();
    for version in [
        VersionPref::Exact(NfsVersion::V4(1)),
        VersionPref::AnyV4,
        VersionPref::Exact(NfsVersion::V2),
    ] {
        let (p, log) = policy(Duration::from_secs(20));
        let started = Instant::now();
        let r = connect(LOCALHOST, b"/export", &opts(srv.port, version, p));
        assert!(started.elapsed() < Duration::from_secs(2), "{version:?}");
        match r {
            Err(e) => assert!(
                e.is_version_unsupported()
                    || matches!(e, Error::Accept(AcceptError::ProgMismatch { .. })),
                "{version:?}: {e}"
            ),
            Ok(_) => panic!("{version:?} connected to a v3-only server"),
        }
        assert!(log.lock().unwrap().is_empty(), "{version:?} was retried");
    }
}

#[test]
fn permanent_mount_error_is_not_retried() {
    let srv = start();
    let (p, log) = policy(Duration::from_secs(20));
    let started = Instant::now();
    let r = connect(
        LOCALHOST,
        b"/no/such/export",
        &opts(srv.port, VersionPref::Exact(NfsVersion::V3), p),
    );
    assert!(r.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(log.lock().unwrap().is_empty());
}

// --------------------------------------------- portmap (private netns)

const NETNS_ENV: &str = "CONN_RETRY_IN_NETNS";

/// Run test `name` again inside a private user + network namespace, where it
/// may bind port 111. Returns true for that inner run.
fn in_netns(name: &str) -> bool {
    if std::env::var_os(NETNS_ENV).is_some() {
        return true;
    }
    let probe = Command::new("unshare")
        .args(["-rn", "sh", "-c", "ip link set lo up"])
        .output();
    if !matches!(&probe, Ok(o) if o.status.success()) {
        eprintln!("skipping {name}: unprivileged user/network namespaces are not available");
        return false;
    }
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("unshare")
        .args(["-rn", "sh", "-c", "ip link set lo up && exec \"$0\" \"$@\""])
        .arg(&exe)
        .args([name, "--exact", "--nocapture", "--test-threads=1"])
        .env(NETNS_ENV, "1")
        .output()
        .expect("run test in netns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{name} failed in its network namespace:\n{stdout}\n{stderr}"
    );
    false
}

#[test]
fn v3_via_portmap_waits_for_a_restarting_server() {
    if !in_netns("v3_via_portmap_waits_for_a_restarting_server") {
        return;
    }
    let srv = start_with(Config {
        portmap_on_111: true,
        ..Config::default()
    });
    take_down(&srv, Duration::from_millis(1500));
    let (p, log) = policy(Duration::from_secs(20));
    let mut o = opts(0, VersionPref::Exact(NfsVersion::V3), p);
    o.nfs_port = None;
    o.mount_port = None;
    let started = Instant::now();
    let mut c = connect(LOCALHOST, b"/export", &o).unwrap_or_else(|e| panic!("connect: {e}"));
    assert!(started.elapsed() >= Duration::from_millis(1200));
    assert_eq!(c.fs.version(), NfsVersion::V3);
    c.fs.getattr(&c.fs.root()).unwrap();
    assert!(count(&log, "retry") >= 1);
    assert_eq!(count(&log, "recovered"), 1);
    let st = srv.stats();
    let asked = |prog| st.getport.iter().filter(|q| q.0 == prog).count();
    assert!(asked(NFS_PROG) >= 1, "{:?}", st.getport);
    assert!(asked(MOUNT_PROG) >= 1, "{:?}", st.getport);
    c.fs.disconnect().unwrap();
}
