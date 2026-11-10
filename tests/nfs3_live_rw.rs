//! Read-write live tests for NFSv3 against a writable export.
//!
//! Gated on `NFSC_TEST_RW=host:/export` (skipped when unset). Every test works
//! inside a fresh `nfsc-v3-<random>` directory under the export and removes it
//! again, even when the test fails. `NFSC_TEST_RW_UDP=1` also runs the transfer
//! test over UDP when the server offers NFSv3 on UDP.

use std::net::{IpAddr, ToSocketAddrs};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nfsc::error::Error;
use nfsc::fs::{
    self, Attr, ConnectOptions, Connected, CreateMode, FileHandle, FileType, Filesystem, NfsVersion, SetAttr,
    SetTime, Status, Time, VersionPref,
};
use nfsc::rpc::{Auth, PortMode, Proto, RpcOptions};

fn resolve(host: &str) -> IpAddr {
    if let Ok(ip) = host.parse() {
        return ip;
    }
    (host, 0)
        .to_socket_addrs()
        .expect("resolve host")
        .next()
        .expect("host has no address")
        .ip()
}

fn target() -> Option<(IpAddr, Vec<u8>)> {
    let spec = std::env::var("NFSC_TEST_RW").ok()?;
    let (host, path) = spec.split_once(':').expect("NFSC_TEST_RW must be host:/export");
    Some((resolve(host), path.as_bytes().to_vec()))
}

fn opts(proto: Proto) -> ConnectOptions {
    ConnectOptions {
        rpc: RpcOptions {
            proto,
            port_mode: PortMode::Auto,
            timeout: Duration::from_secs(20),
            auth: Auth::sys_from_process(),
        },
        nfs_port: None,
        mount_port: None,
        version: VersionPref::Exact(NfsVersion::V3),
    }
}

fn connect(ip: IpAddr, path: &[u8], proto: Proto) -> Connected {
    fs::connect(ip, path, &opts(proto)).unwrap_or_else(|e| panic!("connect over {}: {e}", proto.name()))
}

fn random_suffix() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos() as u64;
    format!("{:016x}", nanos ^ (u64::from(std::process::id()) << 40))
}

/// Remove `name` under `parent`, recursively for directories. A missing name is fine.
fn purge(fs: &mut dyn Filesystem, parent: &FileHandle, name: &[u8]) -> nfsc::Result<()> {
    let (fh, attr) = match fs.lookup(parent, name) {
        Ok(v) => v,
        Err(Error::Nfs(Status::NoEnt)) => return Ok(()),
        Err(e) => return Err(e),
    };
    if attr.ftype == FileType::Directory {
        for e in fs.readdir(&fh)? {
            purge(fs, &fh, &e.name)?;
        }
        fs.rmdir(parent, name)
    } else {
        fs.remove(parent, name)
    }
}

/// Run `body` inside a fresh work directory under the export, then remove it.
fn in_workdir(test: &str, body: impl FnOnce(&mut dyn Filesystem, &FileHandle)) {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RW not set; skipping {test}");
        return;
    };
    let Connected { mut fs, remainder, .. } = connect(ip, &path, Proto::Tcp);
    let mut base = fs.root();
    for c in &remainder {
        base = fs.lookup(&base, c).expect("lookup remainder").0;
    }
    let dirname = format!("nfsc-v3-{}", random_suffix());
    let (work, _) = fs
        .mkdir(&base, dirname.as_bytes(), &SetAttr::default())
        .expect("create work directory");

    let outcome = catch_unwind(AssertUnwindSafe(|| body(fs.as_mut(), &work)));

    let cleanup = purge(fs.as_mut(), &base, dirname.as_bytes());
    let _ = fs.disconnect();
    if let Err(p) = outcome {
        if let Err(e) = &cleanup {
            eprintln!("cleanup of {dirname} also failed: {e}");
        }
        resume_unwind(p);
    }
    cleanup.unwrap_or_else(|e| panic!("cleanup of {dirname} failed: {e}"));
}

/// Deterministic test pattern that does not repeat on power-of-two boundaries.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x & 0xff) as u8
        })
        .collect()
}

fn write_all(fs: &mut dyn Filesystem, fh: &FileHandle, offset: u64, data: &[u8]) {
    let mut done = 0usize;
    while done < data.len() {
        let n = fs.write(fh, offset + done as u64, &data[done..]).expect("write") as usize;
        assert!(n > 0, "server accepted zero bytes");
        done += n;
    }
}

fn read_all(fs: &mut dyn Filesystem, fh: &FileHandle) -> Vec<u8> {
    let mut out = Vec::new();
    let chunk = fs.max_read();
    loop {
        let (data, eof) = fs.read(fh, out.len() as u64, chunk).expect("read");
        out.extend_from_slice(&data);
        if eof || data.is_empty() {
            return out;
        }
    }
}

fn create_file(fs: &mut dyn Filesystem, dir: &FileHandle, name: &str) -> (FileHandle, Attr) {
    fs.create(dir, name.as_bytes(), CreateMode::Guarded, &SetAttr::default())
        .expect("create file")
}

#[test]
fn rw_small_write_read_back() {
    in_workdir("rw_small_write_read_back", |fs, work| {
        let (fh, _) = create_file(fs, work, "small");
        write_all(fs, &fh, 0, b"hello, world");
        assert_eq!(fs.getattr(&fh).unwrap().size, 12);
        assert_eq!(read_all(fs, &fh), b"hello, world");

        // Overwrite in the middle without changing the length.
        write_all(fs, &fh, 7, b"NFS!");
        assert_eq!(read_all(fs, &fh), b"hello, NFS!");
        assert_eq!(fs.getattr(&fh).unwrap().size, 12);

        // Write past the end leaves a hole that reads back as zeros.
        write_all(fs, &fh, 20, b"x");
        let back = read_all(fs, &fh);
        assert_eq!(back.len(), 21);
        assert!(back[12..20].iter().all(|&b| b == 0));
        assert_eq!(back[20], b'x');

        // Zero-length write is a no-op.
        assert_eq!(fs.write(&fh, 0, &[]).unwrap(), 0);
    });
}

#[test]
fn rw_multi_mib_roundtrip_crossing_transfer_boundaries() {
    in_workdir("rw_multi_mib_roundtrip", |fs, work| {
        let (fh, _) = create_file(fs, work, "big");
        let max = fs.max_write() as usize;
        let len = 5 * 1024 * 1024 + 12_345;
        let data = pattern(len, 1);
        // Feed the writes in sizes that do not line up with max_write.
        let step = max + max / 2 + 7;
        let mut off = 0usize;
        while off < len {
            let end = (off + step).min(len);
            write_all(fs, &fh, off as u64, &data[off..end]);
            off = end;
        }
        let attr = fs.getattr(&fh).unwrap();
        assert_eq!(attr.size, len as u64);
        let back = read_all(fs, &fh);
        assert!(back == data, "read-back differs from written data");

        // An unaligned read that spans a transfer boundary.
        let start = max - 3;
        let (part, _) = fs.read(&fh, start as u64, (max + 100) as u32).unwrap();
        assert_eq!(&part[..], &data[start..start + part.len()]);
        assert!(!part.is_empty());
    });
}

#[test]
fn rw_create_modes() {
    in_workdir("rw_create_modes", |fs, work| {
        let (g, _) = create_file(fs, work, "g");
        match fs.create(work, b"g", CreateMode::Guarded, &SetAttr::default()) {
            Err(Error::Nfs(Status::Exist)) => {}
            other => panic!("GUARDED create of existing name returned {other:?}"),
        }
        let (u, _) = fs
            .create(work, b"g", CreateMode::Unchecked, &SetAttr::default())
            .expect("UNCHECKED create of existing name succeeds");
        assert_eq!(fs.getattr(&u).unwrap().fileid, fs.getattr(&g).unwrap().fileid);

        let attrs = SetAttr {
            mode: Some(0o640),
            ..SetAttr::default()
        };
        let (e, a) = fs
            .create(work, b"e", CreateMode::Exclusive, &attrs)
            .expect("EXCLUSIVE create");
        assert_eq!(a.mode, 0o640, "attributes must be applied after EXCLUSIVE create");
        assert_eq!(a.ftype, FileType::Regular);
        match fs.create(work, b"e", CreateMode::Exclusive, &attrs) {
            Err(Error::Nfs(Status::Exist)) => {}
            other => panic!("second EXCLUSIVE create returned {other:?}"),
        }
        assert_eq!(fs.getattr(&e).unwrap().mode, 0o640);

        let (m, a) = fs
            .create(
                work,
                b"m",
                CreateMode::Unchecked,
                &SetAttr {
                    mode: Some(0o600),
                    ..SetAttr::default()
                },
            )
            .expect("create with mode");
        assert_eq!(a.mode, 0o600);
        assert_eq!(fs.getattr(&m).unwrap().mode, 0o600);
    });
}

#[test]
fn rw_mkdir_rmdir() {
    in_workdir("rw_mkdir_rmdir", |fs, work| {
        let (d, a) = fs.mkdir(work, b"d", &SetAttr::default()).expect("mkdir");
        assert_eq!(a.ftype, FileType::Directory);
        assert!(matches!(fs.mkdir(work, b"d", &SetAttr::default()), Err(Error::Nfs(Status::Exist))));

        create_file(fs, &d, "inside");
        assert!(matches!(fs.rmdir(work, b"d"), Err(Error::Nfs(Status::NotEmpty))));
        fs.remove(&d, b"inside").expect("remove inside");
        fs.rmdir(work, b"d").expect("rmdir");
        assert!(matches!(fs.lookup(work, b"d"), Err(Error::Nfs(Status::NoEnt))));
    });
}

#[test]
fn rw_rename_same_and_cross_directory() {
    in_workdir("rw_rename", |fs, work| {
        let (fh, _) = create_file(fs, work, "a");
        write_all(fs, &fh, 0, b"payload");
        fs.rename(work, b"a", work, b"b").expect("rename in directory");
        assert!(matches!(fs.lookup(work, b"a"), Err(Error::Nfs(Status::NoEnt))));
        let (b, _) = fs.lookup(work, b"b").unwrap();
        assert_eq!(b, fh, "renamed file keeps its handle");

        let (sub, _) = fs.mkdir(work, b"sub", &SetAttr::default()).unwrap();
        fs.rename(work, b"b", &sub, b"c").expect("rename across directories");
        assert_eq!(read_all(fs, &fh), b"payload");
        assert!(matches!(
            fs.rename(work, b"missing", work, b"x"),
            Err(Error::Nfs(Status::NoEnt))
        ));
    });
}

#[test]
fn rw_symlink_readlink() {
    in_workdir("rw_symlink", |fs, work| {
        let (l, a) = fs
            .symlink(work, b"l", b"some/where/../target", &SetAttr::default())
            .expect("symlink");
        assert_eq!(a.ftype, FileType::Symlink);
        assert_eq!(fs.readlink(&l).unwrap(), b"some/where/../target");

        let long = vec![b'a'; 1000];
        let (l2, _) = fs.symlink(work, b"long", &long, &SetAttr::default()).unwrap();
        assert_eq!(fs.readlink(&l2).unwrap(), long);
        let (found, attr) = fs.lookup(work, b"l").unwrap();
        assert_eq!(found, l);
        assert_eq!(attr.ftype, FileType::Symlink, "LOOKUP must not follow the link");
    });
}

#[test]
fn rw_hard_link() {
    in_workdir("rw_hard_link", |fs, work| {
        let (f, _) = create_file(fs, work, "f");
        write_all(fs, &f, 0, b"shared");
        fs.link(&f, work, b"f2").expect("link");
        assert_eq!(fs.getattr(&f).unwrap().nlink, 2);
        let (f2, a2) = fs.lookup(work, b"f2").unwrap();
        assert_eq!(a2.fileid, fs.getattr(&f).unwrap().fileid);
        fs.remove(work, b"f").unwrap();
        assert_eq!(fs.getattr(&f2).unwrap().nlink, 1);
        assert_eq!(read_all(fs, &f2), b"shared");
    });
}

#[test]
fn rw_setattr_mode_size_times() {
    in_workdir("rw_setattr", |fs, work| {
        let (f, _) = create_file(fs, work, "s");
        write_all(fs, &f, 0, &pattern(100, 3));

        let a = fs
            .setattr(
                &f,
                &SetAttr {
                    mode: Some(0o4750),
                    ..SetAttr::default()
                },
            )
            .unwrap();
        assert_eq!(a.mode, 0o4750, "setuid/setgid/sticky-compatible mode bits survive");
        assert_eq!(a.ftype, FileType::Regular);

        let a = fs
            .setattr(
                &f,
                &SetAttr {
                    size: Some(10),
                    ..SetAttr::default()
                },
            )
            .unwrap();
        assert_eq!(a.size, 10);
        assert_eq!(read_all(fs, &f), pattern(100, 3)[..10]);

        let a = fs
            .setattr(
                &f,
                &SetAttr {
                    size: Some(4096),
                    ..SetAttr::default()
                },
            )
            .unwrap();
        assert_eq!(a.size, 4096);
        assert!(read_all(fs, &f)[10..].iter().all(|&b| b == 0));

        let t = Time {
            seconds: 1_000_000_000,
            nseconds: 0,
        };
        let a = fs
            .setattr(
                &f,
                &SetAttr {
                    mtime: Some(SetTime::Client(t)),
                    ..SetAttr::default()
                },
            )
            .unwrap();
        assert_eq!(a.mtime.seconds, t.seconds);

        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let a = fs
            .setattr(
                &f,
                &SetAttr {
                    atime: Some(SetTime::ServerNow),
                    ..SetAttr::default()
                },
            )
            .unwrap();
        assert!((a.atime.seconds - before).abs() < 600, "server-set atime is near the server clock");
    });
}

#[test]
fn rw_remove_then_missing() {
    in_workdir("rw_remove", |fs, work| {
        let (f, _) = create_file(fs, work, "gone");
        fs.remove(work, b"gone").unwrap();
        assert!(matches!(fs.lookup(work, b"gone"), Err(Error::Nfs(Status::NoEnt))));
        assert!(matches!(fs.remove(work, b"gone"), Err(Error::Nfs(Status::NoEnt))));
        // The removed object's handle no longer resolves.
        assert!(fs.getattr(&f).is_err());
    });
}

#[test]
fn rw_readdir_paginates_over_a_thousand_entries() {
    in_workdir("rw_readdir_many", |fs, work| {
        let (big, _) = fs.mkdir(work, b"big", &SetAttr::default()).unwrap();
        assert!(fs.readdir(&big).unwrap().is_empty());
        let total = 1100;
        for i in 0..total {
            create_file(fs, &big, &format!("file-{i:05}"));
        }
        let entries = fs.readdir(&big).expect("readdir");
        assert_eq!(entries.len(), total, "every entry listed once across pages");
        let mut names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total);
        assert!(entries.iter().all(|e| e.attr.is_some()), "READDIRPLUS supplies attributes");
        assert!(entries.iter().all(|e| e.handle.is_some()), "READDIRPLUS supplies handles");
    });
}

#[test]
fn rw_fsstat_and_fsinfo_sizes() {
    in_workdir("rw_fsstat", |fs, work| {
        let s = fs.fsstat(work).expect("fsstat");
        assert!(s.total_bytes > 0);
        assert!(s.free_bytes <= s.total_bytes);
        assert!(s.avail_bytes <= s.total_bytes);
        assert!(fs.max_read() > 0 && fs.max_write() > 0);
    });
}

#[test]
fn rw_data_is_visible_on_a_fresh_connection() {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RW not set; skipping");
        return;
    };
    in_workdir("rw_durability", |fs, work| {
        let (f, _) = create_file(fs, work, "durable");
        let data = pattern(200_000, 9);
        write_all(fs, &f, 0, &data);
        // A second mount of the same export must see the bytes. File handles are
        // server-side names, so the work directory handle is valid there too.
        let Connected { fs: mut other, .. } = connect(ip, &path, Proto::Tcp);
        let (seen, _) = other.lookup(work, b"durable").expect("file visible on second connection");
        assert!(read_all(other.as_mut(), &seen) == data);
        other.disconnect().expect("disconnect second connection");
    });
}

#[test]
fn rw_udp_transfer_when_offered() {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RW not set; skipping");
        return;
    };
    if std::env::var("NFSC_TEST_RW_UDP").is_err() {
        eprintln!("NFSC_TEST_RW_UDP not set; skipping UDP");
        return;
    }
    let udp = RpcOptions {
        proto: Proto::Udp,
        ..RpcOptions::default()
    };
    match nfsc::portmap::getport(ip, nfsc::nfs3::PROGRAM, nfsc::nfs3::VERSION, Proto::Udp, &udp) {
        Err(Error::NotRegistered { .. }) => {
            eprintln!("NFSv3 is not registered over UDP on this server; skipping");
            return;
        }
        Err(e) => panic!("portmap over UDP: {e}"),
        Ok(_) => {}
    }
    let Connected { mut fs, remainder, .. } = fs::connect(ip, &path, &opts(Proto::Udp)).expect("connect over UDP");
    let root = fs.root();
    let mut base = root;
    for c in &remainder {
        base = fs.lookup(&base, c).unwrap().0;
    }
    let dirname = format!("nfsc-v3-{}", random_suffix());
    let (work, _) = fs.mkdir(&base, dirname.as_bytes(), &SetAttr::default()).unwrap();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let (f, _) = create_file(fs.as_mut(), &work, "u");
        let data = pattern(300_000, 4);
        write_all(fs.as_mut(), &f, 0, &data);
        assert!(fs.max_write() <= 32 << 10, "UDP transfers are capped");
        assert!(read_all(fs.as_mut(), &f) == data);
    }));
    let cleanup = purge(fs.as_mut(), &base, dirname.as_bytes());
    let _ = fs.disconnect();
    if let Err(p) = outcome {
        resume_unwind(p);
    }
    cleanup.expect("cleanup");
}
