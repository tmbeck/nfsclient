//! Live read-only NFSv4 tests. Skipped unless `NFSC_TEST_RO=host:/export/path`
//! is set. Only session management and read operations are issued; nothing is
//! written. Target names never appear in this file.

use std::net::{IpAddr, ToSocketAddrs};

use nfsc::fs::{ConnectOptions, Connected, FileType, NfsVersion, VersionPref};
use nfsc::rpc::{Auth, RpcOptions};

fn target() -> Option<(IpAddr, Vec<u8>)> {
    let v = std::env::var("NFSC_TEST_RO").ok()?;
    let (host, path) = v.split_once(':')?;
    let ip = (host, 2049).to_socket_addrs().ok()?.next()?.ip();
    Some((ip, path.as_bytes().to_vec()))
}

fn opts(minor: Option<u32>) -> ConnectOptions {
    ConnectOptions {
        rpc: RpcOptions { auth: Auth::sys_from_process(), ..RpcOptions::default() },
        nfs_port: None,
        mount_port: None,
        version: match minor {
            Some(m) => VersionPref::Exact(NfsVersion::V4(m)),
            None => VersionPref::AnyV4,
        },
    }
}

/// Connect, then exercise read paths against the export root.
fn exercise(minor: Option<u32>) {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let Connected { mut fs, .. } = nfsc::nfs4::connect(ip, &path, minor, &opts(minor)).expect("connect");
    let root = fs.root();
    let attr = fs.getattr(&root).expect("getattr root");
    assert_eq!(attr.ftype, FileType::Directory);
    let st = fs.fsstat(&root).expect("fsstat");
    eprintln!("minor {minor:?}: root {:?} fsstat {:?} maxread {} maxwrite {}", fs.version(), st, fs.max_read(), fs.max_write());
    let entries = fs.readdir(&root).expect("readdir");
    eprintln!("minor {minor:?}: {} entries", entries.len());
    for e in entries.iter().take(20) {
        let name = String::from_utf8_lossy(&e.name).into_owned();
        let (fh, a) = fs.lookup(&root, &e.name).expect("lookup entry");
        eprintln!("  {name}: {:?} size {}", a.ftype, a.size);
        if a.ftype == FileType::Regular && a.size > 0 {
            let n = a.size.min(u64::from(fs.max_read())) as u32;
            let (data, _eof) = fs.read(&fh, 0, n).expect("read");
            assert_eq!(data.len() as u32, n.min(data.len() as u32));
            assert!(!data.is_empty());
        }
    }
    let (up, _) = fs.lookup(&root, b"..").expect("lookup ..");
    eprintln!("minor {minor:?}: '..' handle {} bytes", up.0.len());
    fs.disconnect().expect("disconnect");
}

#[test]
fn negotiate_minor_none() {
    exercise(None);
}

#[test]
fn explicit_minor_0() {
    exercise(Some(0));
}

#[test]
fn explicit_minor_1() {
    exercise(Some(1));
}

#[test]
fn explicit_minor_2() {
    exercise(Some(2));
}
