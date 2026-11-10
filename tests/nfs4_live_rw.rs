//! Live read-write NFSv4 tests against local test servers. Each target is
//! gated by an environment variable (skipped when unset):
//!   NFSC_TEST_RW_KNFSD=host:/export    kernel nfsd
//!   NFSC_TEST_RW_GANESHA=host:/export  nfs-ganesha
//! Every test runs for minor versions 0, 1 and 2 inside a fresh directory named
//! `nfsc-v4-<random>` under the export, removed afterwards. Target names never
//! appear in this file.

use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, ToSocketAddrs};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use nfsc::error::{Error, Result};
use nfsc::fs::{
    ConnectOptions, Connected, CreateMode, FileHandle, FileType, Filesystem, NfsVersion, SetAttr, SetTime,
    Status, Time, VersionPref,
};
use nfsc::rpc::{Auth, RpcOptions};

struct Target {
    name: &'static str,
    ip: IpAddr,
    path: Vec<u8>,
}

fn targets() -> Vec<Target> {
    let mut out = Vec::new();
    for (name, key) in [("knfsd", "NFSC_TEST_RW_KNFSD"), ("ganesha", "NFSC_TEST_RW_GANESHA")] {
        let Ok(v) = std::env::var(key) else { continue };
        let Some((host, path)) = v.split_once(':') else { continue };
        let Some(ip) = (host, 2049).to_socket_addrs().ok().and_then(|mut it| it.next()).map(|a| a.ip()) else {
            continue;
        };
        out.push(Target { name, ip, path: path.as_bytes().to_vec() });
    }
    out
}

fn connect(t: &Target, minor: u32) -> Connected {
    let opts = ConnectOptions {
        rpc: RpcOptions { auth: Auth::sys_from_process(), ..RpcOptions::default() },
        nfs_port: None,
        mount_port: None,
        version: VersionPref::Exact(NfsVersion::V4(minor)),
    };
    nfsc::nfs4::connect(t.ip, &t.path, Some(minor), &opts).expect("connect")
}

fn uid() -> u32 {
    match Auth::sys_from_process() {
        Auth::Sys { uid, .. } => uid,
        Auth::None => 0,
    }
}

fn unique_name() -> String {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    format!("nfsc-v4-{:012x}", h.finish() & 0xffff_ffff_ffff)
}

fn is_status<T: std::fmt::Debug>(r: Result<T>, want: Status) -> bool {
    matches!(r, Err(Error::Nfs(s)) if s == want)
}

/// Recursively remove `name` under `parent`. Best effort; errors are returned.
fn rm_rf(fs: &mut dyn Filesystem, parent: &FileHandle, name: &[u8]) -> Result<()> {
    let (fh, a) = fs.lookup(parent, name)?;
    if a.ftype == FileType::Directory {
        for e in fs.readdir(&fh)? {
            rm_rf(fs, &fh, &e.name)?;
        }
        fs.rmdir(parent, name)
    } else {
        fs.remove(parent, name)
    }
}

fn suite(fs: &mut dyn Filesystem, dir: &FileHandle) {
    let ds = SetAttr::default();

    // CREATE: all modes, guarded conflict.
    let (g, _) = fs
        .create(dir, b"guarded", CreateMode::Guarded, &SetAttr { mode: Some(0o644), ..Default::default() })
        .expect("guarded create");
    assert!(is_status(fs.create(dir, b"guarded", CreateMode::Guarded, &ds), Status::Exist));
    fs.create(dir, b"guarded", CreateMode::Unchecked, &ds).expect("unchecked on existing");
    let (_ex, _) = fs.create(dir, b"excl", CreateMode::Exclusive, &ds).expect("exclusive");
    assert!(is_status(fs.create(dir, b"excl", CreateMode::Exclusive, &ds), Status::Exist));
    let (ex2, ea) = fs
        .create(dir, b"excl2", CreateMode::Exclusive, &SetAttr { mode: Some(0o700), ..Default::default() })
        .expect("exclusive with attrs");
    assert_eq!(ea.mode, 0o700, "attributes applied after exclusive create");
    fs.remove(dir, b"excl2").expect("remove excl2");
    let _ = ex2;

    // WRITE / READ across max_write and max_read boundaries.
    let len = 3 * 1024 * 1024 + 4567;
    let data: Vec<u8> = (0..len).map(|i: usize| (i.wrapping_mul(7) % 251) as u8).collect();
    assert_eq!(fs.write(&g, 0, &data).expect("write") as usize, len);
    assert_eq!(fs.getattr(&g).expect("getattr").size, len as u64);
    let mut back = Vec::with_capacity(len);
    let mut off = 0u64;
    loop {
        let (chunk, eof) = fs.read(&g, off, 1 << 20).expect("read");
        off += chunk.len() as u64;
        back.extend_from_slice(&chunk);
        if chunk.is_empty() || eof {
            break;
        }
    }
    assert!(back == data, "read-back mismatch");
    fs.write(&g, 1000, b"HELLO").expect("offset write");
    assert_eq!(fs.read(&g, 1000, 5).expect("read back").0, b"HELLO");

    // MKDIR / RMDIR / type checks.
    let _ = fs.mkdir(dir, b"sub", &ds).expect("mkdir");
    assert!(is_status(fs.rmdir(dir, b"guarded"), Status::NotDir));
    assert!(is_status(fs.remove(dir, b"sub"), Status::IsDir));

    // RENAME.
    fs.rename(dir, b"guarded", dir, b"renamed").expect("rename");
    assert!(is_status(fs.lookup(dir, b"guarded"), Status::NoEnt));
    assert_eq!(fs.lookup(dir, b"renamed").expect("renamed").0, g);

    // SYMLINK / READLINK.
    let (ln, la) = fs.symlink(dir, b"lnk", b"renamed/target", &ds).expect("symlink");
    assert_eq!(la.ftype, FileType::Symlink);
    assert_eq!(fs.readlink(&ln).expect("readlink"), b"renamed/target");

    // LINK.
    fs.link(&g, dir, b"hard").expect("link");
    assert_eq!(fs.getattr(&g).expect("getattr").nlink, 2);

    // SETATTR: mode, size, numeric owner, client mtime.
    let a = fs
        .setattr(
            &g,
            &SetAttr {
                mode: Some(0o600),
                size: Some(100),
                uid: Some(uid()),
                mtime: Some(SetTime::Client(Time { seconds: 1_000_000_000, nseconds: 0 })),
                ..Default::default()
            },
        )
        .expect("setattr");
    assert_eq!(a.mode, 0o600);
    assert_eq!(a.size, 100);
    assert_eq!(a.uid, uid());
    assert_eq!(a.mtime.seconds, 1_000_000_000);
    assert_eq!(fs.read(&g, 0, 1000).expect("read truncated").0.len(), 100);

    // REMOVE / RMDIR.
    fs.remove(dir, b"hard").expect("remove");
    assert!(is_status(fs.lookup(dir, b"hard"), Status::NoEnt));
    fs.rmdir(dir, b"sub").expect("rmdir");
    fs.remove(dir, b"lnk").expect("remove symlink");

    // READDIR with pagination.
    let (big, _) = fs.mkdir(dir, b"big", &ds).expect("mkdir big");
    for i in 0..1200 {
        fs.create(&big, format!("f{i:04}").as_bytes(), CreateMode::Guarded, &ds).expect("create many");
    }
    let entries = fs.readdir(&big).expect("readdir");
    assert_eq!(entries.len(), 1200);
    assert!(entries.iter().all(|e| e.attr.is_some() && e.handle.is_some()));

    // FSSTAT and lookup("..").
    let st = fs.fsstat(dir).expect("fsstat");
    assert!(st.total_bytes > 0);
    let parent = fs.lookup(&big, b"..").expect("lookup ..").1;
    assert_eq!(parent.fileid, fs.getattr(dir).expect("getattr dir").fileid);
    assert_eq!(fs.lookup(dir, b".").expect("lookup .").0, *dir);
}

fn run_target(t: &Target, minor: u32) {
    let Connected { mut fs, .. } = connect(t, minor);
    let root = fs.root();
    let name = unique_name();
    let (dir, _) = fs.mkdir(&root, name.as_bytes(), &SetAttr::default()).expect("mkdir test dir");
    let result = catch_unwind(AssertUnwindSafe(|| suite(&mut *fs, &dir)));
    let cleanup = rm_rf(&mut *fs, &root, name.as_bytes());
    let _ = fs.disconnect();
    if let Err(e) = cleanup {
        eprintln!("{} minor {minor}: cleanup of {name} failed: {e}", t.name);
    }
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

#[test]
fn rw_all_targets_all_minors() {
    let ts = targets();
    if ts.is_empty() {
        eprintln!("no NFSC_TEST_RW_* target set; skipping");
        return;
    }
    for t in &ts {
        for minor in [0, 1, 2] {
            eprintln!("== {} NFSv4.{minor}", t.name);
            run_target(t, minor);
        }
    }
}

/// Idle past half the lease, then operate: RENEW (4.0) must keep the client alive.
#[test]
fn lease_renewal_after_idle() {
    if std::env::var("NFSC_TEST_LEASE").is_err() {
        eprintln!("NFSC_TEST_LEASE not set; skipping lease idle test");
        return;
    }
    let ts = targets();
    let Some(t) = ts.first() else { return };
    let Connected { mut fs, .. } = connect(t, 0);
    let root = fs.root();
    fs.getattr(&root).expect("getattr");
    std::thread::sleep(Duration::from_secs(50));
    fs.getattr(&root).expect("getattr after idle");
    fs.disconnect().expect("disconnect");
}
