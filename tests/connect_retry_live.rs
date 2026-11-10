//! Live check that an NFSv4 transfer survives its TCP connection being cut
//! mid-stream: the backend reconnects and keeps its client state (session,
//! client ID, open stateid) instead of starting over as a new client.
//!
//! Opt-in: needs `NFSC_TEST_RO=host:/export` (the testenv fixture tree, with
//! `big.bin`) and `NFSC_TEST_KILL_CONN=1`, and runs `sudo -n ss -K` to reset
//! this process's own connection (only sockets owned by this process are
//! touched). Nothing is written. Target names never appear in this file.

use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use nfsc::fs::{ConnectOptions, FileHandle, Filesystem, NfsVersion, VersionPref, connect};
use nfsc::rpc::{Auth, RetryEvent, RetryPolicy, RpcOptions};

fn target() -> Option<(IpAddr, Vec<u8>)> {
    std::env::var_os("NFSC_TEST_KILL_CONN")?;
    let v = std::env::var("NFSC_TEST_RO").ok()?;
    let (host, path) = v.split_once(':')?;
    let ip = (host, 2049).to_socket_addrs().ok()?.next()?.ip();
    Some((ip, path.as_bytes().to_vec()))
}

/// Reset every TCP connection of this process to `ip`:2049.
fn kill_own_connections(ip: IpAddr) -> usize {
    let me = format!("pid={},", std::process::id());
    let out = Command::new("sudo")
        .args(["-n", "ss", "-Htnp", "state", "established"])
        .output()
        .expect("ss");
    let mut killed = 0;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if !line.contains(&me) || cols.len() < 4 {
            continue;
        }
        let (local, peer) = (cols[2], cols[3]);
        if peer != format!("{ip}:2049") {
            continue;
        }
        let Some((_, sport)) = local.rsplit_once(':') else {
            continue;
        };
        let st = Command::new("sudo")
            .args([
                "-n",
                "ss",
                "-K",
                "dst",
                &ip.to_string(),
                "dport",
                "=",
                "2049",
            ])
            .args(["sport", "=", sport])
            .output()
            .expect("ss -K");
        if st.status.success() {
            killed += 1;
        }
    }
    killed
}

fn lookup(fs: &mut dyn Filesystem, name: &[u8]) -> FileHandle {
    let root = fs.root();
    fs.lookup(&root, name).expect("lookup big.bin").0
}

#[test]
fn v4_stream_survives_a_reset_connection() {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RO / NFSC_TEST_KILL_CONN not set; skipping");
        return;
    };
    for minor in [0, 1, 2] {
        let retries = Arc::new(AtomicU32::new(0));
        let r = retries.clone();
        let opts = ConnectOptions {
            rpc: RpcOptions {
                auth: Auth::sys_from_process(),
                retry: RetryPolicy {
                    budget: Duration::from_secs(60),
                    on_retry: Some(Arc::new(move |e: &RetryEvent<'_>| {
                        if let RetryEvent::Retrying { op, error, .. } = e {
                            eprintln!("  retry {op}: {error}");
                            r.fetch_add(1, Ordering::SeqCst);
                        }
                    })),
                    ..RetryPolicy::default()
                },
                ..RpcOptions::default()
            },
            nfs_port: None,
            mount_port: None,
            version: VersionPref::Exact(NfsVersion::V4(minor)),
        };
        let mut c = match connect(ip, &path, &opts) {
            Ok(c) => c,
            Err(e) if e.is_version_unsupported() => {
                eprintln!("NFSv4.{minor} not offered; skipping it");
                continue;
            }
            Err(e) => panic!("connect 4.{minor}: {e}"),
        };
        let fh = lookup(c.fs.as_mut(), b"big.bin");
        let mut clean = Vec::new();
        c.fs.read_stream(&fh, 0, None, &mut |b: &[u8]| {
            clean.extend_from_slice(b);
            Ok(())
        })
        .expect("clean read");
        let mut got = Vec::new();
        let mut cut = false;
        c.fs.read_stream(&fh, 0, None, &mut |b: &[u8]| {
            got.extend_from_slice(b);
            if !cut && got.len() >= 1 << 20 {
                cut = true;
                assert!(kill_own_connections(ip) > 0, "no connection to cut");
            }
            Ok(())
        })
        .unwrap_or_else(|e| panic!("4.{minor} read across a reset: {e}"));
        assert!(cut);
        assert_eq!(got.len(), clean.len(), "4.{minor}");
        assert!(got == clean, "4.{minor}: data differs after the reset");
        eprintln!(
            "NFSv4.{minor}: {} bytes intact across a reset ({} retries)",
            got.len(),
            retries.load(Ordering::SeqCst)
        );
        c.fs.disconnect().expect("disconnect");
    }
}
