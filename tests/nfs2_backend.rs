//! NFSv2 backend against the in-process fake server, over TCP and UDP.

#[path = "nfs2_backend/server.rs"]
mod server;

use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use nfsc::error::{Error, Result};
use nfsc::fs::{
    Attr, CreateMode, FileHandle, FileType, Filesystem, SetAttr, SetTime, Status, Time,
};
use nfsc::nfs2::connect_with_root;
use nfsc::rpc::{Auth, PortMode, Proto, RpcOptions};

use server::{FakeNfs2, start};

fn rpc_opts(proto: Proto) -> RpcOptions {
    RpcOptions {
        proto,
        port_mode: PortMode::Unprivileged,
        timeout: Duration::from_secs(5),
        auth: Auth::None,
    }
}

fn mount(srv: &FakeNfs2, proto: Proto) -> Box<dyn Filesystem> {
    connect_with_root(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        srv.port,
        srv.root(),
        &rpc_opts(proto),
    )
    .expect("connect_with_root")
}

fn ok<T: Debug>(r: Result<T>) -> T {
    r.unwrap_or_else(|e| panic!("unexpected error: {e}"))
}

fn expect_status<T: Debug>(r: Result<T>, want: Status) {
    match r {
        Err(Error::Nfs(s)) => assert_eq!(s, want),
        other => panic!("expected {want:?}, got {other:?}"),
    }
}

/// Write all of `data`, honoring short writes.
fn write_all(fs: &mut dyn Filesystem, fh: &FileHandle, mut offset: u64, mut data: &[u8]) {
    while !data.is_empty() {
        let n = ok(fs.write(fh, offset, data)) as usize;
        assert!(n > 0 && n <= data.len());
        offset += n as u64;
        data = &data[n..];
    }
}

/// Read to EOF in max_read-sized requests.
fn read_all(fs: &mut dyn Filesystem, fh: &FileHandle) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let (chunk, eof) = ok(fs.read(fh, out.len() as u64, fs.max_read()));
        out.extend_from_slice(&chunk);
        if eof {
            return out;
        }
        assert!(!chunk.is_empty(), "non-eof empty read");
    }
}

fn names(entries: &[nfsc::fs::DirEntry]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
    v.sort();
    v
}

fn create_file(fs: &mut dyn Filesystem, dir: &FileHandle, name: &str) -> (FileHandle, Attr) {
    ok(fs.create(
        dir,
        name.as_bytes(),
        CreateMode::Unchecked,
        &SetAttr::default(),
    ))
}

fn mkdir(fs: &mut dyn Filesystem, dir: &FileHandle, name: &str) -> FileHandle {
    ok(fs.mkdir(dir, name.as_bytes(), &SetAttr::default())).0
}

/// Every method, exercised end to end.
fn full_suite(proto: Proto) {
    let srv = start();
    let mut fs = mount(&srv, proto);
    let root = fs.root();

    assert_eq!(fs.version(), nfsc::fs::NfsVersion::V2);
    assert_eq!(fs.max_read(), 8192);
    assert_eq!(fs.max_write(), 8192);
    assert_eq!(root, srv.root());

    // getattr on the root: type bits stripped from mode.
    let a = ok(fs.getattr(&root));
    assert_eq!(a.ftype, FileType::Directory);
    assert_eq!(a.mode, 0o755);
    assert_eq!(a.fileid, 1);
    assert_eq!(a.fsid, 0x1234);
    assert_eq!(a.used, 1024);

    // create: Guarded succeeds for a new name, then Exist.
    let (hello, attr) = ok(fs.create(
        &root,
        b"hello.txt",
        CreateMode::Guarded,
        &SetAttr::default(),
    ));
    assert_eq!(attr.ftype, FileType::Regular);
    assert_eq!(attr.size, 0);
    expect_status(
        fs.create(
            &root,
            b"hello.txt",
            CreateMode::Guarded,
            &SetAttr::default(),
        ),
        Status::Exist,
    );
    expect_status(
        fs.create(
            &root,
            b"hello.txt",
            CreateMode::Exclusive,
            &SetAttr::default(),
        ),
        Status::Exist,
    );
    // Unchecked returns the existing file.
    let (again, _) = create_file(fs.as_mut(), &root, "hello.txt");
    assert_eq!(again, hello);

    // write and read, with eof and short reads.
    assert_eq!(ok(fs.write(&hello, 0, b"hello world")), 11);
    assert_eq!(ok(fs.read(&hello, 0, 100)), (b"hello world".to_vec(), true));
    assert_eq!(ok(fs.read(&hello, 0, 5)), (b"hello".to_vec(), false));
    assert_eq!(ok(fs.read(&hello, 6, 5)), (b"world".to_vec(), true));
    assert_eq!(ok(fs.read(&hello, 11, 10)), (Vec::new(), true));
    assert_eq!(ok(fs.read(&hello, 0, 0)), (Vec::new(), false));

    // A write past EOF leaves a zero-filled hole.
    assert_eq!(ok(fs.write(&hello, 20, b"!")), 1);
    let body = read_all(fs.as_mut(), &hello);
    assert_eq!(body.len(), 21);
    assert_eq!(&body[..11], b"hello world");
    assert!(body[11..20].iter().all(|&b| b == 0));
    assert_eq!(body[20], b'!');
    assert_eq!(ok(fs.getattr(&hello)).size, 21);

    // Large write goes through in chunks; read back equals what was written.
    let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let (bigfh, _) = create_file(fs.as_mut(), &root, "big.bin");
    // One call is capped at MAXDATA and may be short.
    assert_eq!(ok(fs.write(&bigfh, 0, &big)), 8192);
    write_all(fs.as_mut(), &bigfh, 0, &big);
    assert_eq!(read_all(fs.as_mut(), &bigfh), big);

    // lookup, including a miss.
    let (lh, la) = ok(fs.lookup(&root, b"hello.txt"));
    assert_eq!(lh, hello);
    assert_eq!(la.size, 21);
    expect_status(fs.lookup(&root, b"missing"), Status::NoEnt);

    // setattr: mode, size, and a client mtime (usec -> nsec).
    let attrs = SetAttr {
        mode: Some(0o600),
        size: Some(5),
        mtime: Some(SetTime::Client(Time {
            seconds: 1_600_000_000,
            nseconds: 5_000_000,
        })),
        ..SetAttr::default()
    };
    let after = ok(fs.setattr(&hello, &attrs));
    assert_eq!(after.mode, 0o600);
    assert_eq!(after.size, 5);
    assert_eq!(
        after.mtime,
        Time {
            seconds: 1_600_000_000,
            nseconds: 5_000_000
        }
    );
    assert_eq!(read_all(fs.as_mut(), &hello), b"hello");

    // mkdir, nested lookup, ".." via lookup.
    let dir = mkdir(fs.as_mut(), &root, "d");
    expect_status(fs.mkdir(&root, b"d", &SetAttr::default()), Status::Exist);
    let (inner, _) = create_file(fs.as_mut(), &dir, "inner");
    let (inner2, _) = ok(fs.lookup(&dir, b"inner"));
    assert_eq!(inner2, inner);
    let (up, upattr) = ok(fs.lookup(&dir, b".."));
    assert_eq!(up, root);
    assert_eq!(upattr.ftype, FileType::Directory);
    let (dot, _) = ok(fs.lookup(&dir, b"."));
    assert_eq!(dot, dir);
    expect_status(fs.lookup(&hello, b"x"), Status::NotDir);

    // readdir: no "." or "..".
    let entries = ok(fs.readdir(&root));
    assert_eq!(
        names(&entries),
        vec![b"big.bin".to_vec(), b"d".to_vec(), b"hello.txt".to_vec()]
    );
    assert!(
        entries
            .iter()
            .all(|e| e.attr.is_none() && e.handle.is_none())
    );
    assert_eq!(names(&ok(fs.readdir(&dir))), vec![b"inner".to_vec()]);

    // symlink, then readlink; the new entry is looked up.
    let (ln, lnattr) = ok(fs.symlink(&root, b"ln", b"hello.txt", &SetAttr::default()));
    assert_eq!(lnattr.ftype, FileType::Symlink);
    assert_eq!(ok(fs.readlink(&ln)), b"hello.txt");
    expect_status(
        fs.symlink(&root, b"ln", b"x", &SetAttr::default()),
        Status::Exist,
    );

    // hard link: same fileid, nlink goes to 2.
    ok(fs.link(&hello, &root, b"hard"));
    let (hh, _) = ok(fs.lookup(&root, b"hard"));
    let ha = ok(fs.getattr(&hh));
    assert_eq!(ha.fileid, la.fileid);
    assert_eq!(ha.nlink, 2);

    // rename a file, then a directory, then check the old names are gone.
    ok(fs.rename(&root, b"hello.txt", &root, b"renamed.txt"));
    expect_status(fs.lookup(&root, b"hello.txt"), Status::NoEnt);
    assert_eq!(ok(fs.lookup(&root, b"renamed.txt")).0, hello);
    ok(fs.rename(&root, b"d", &root, b"d2"));
    assert_eq!(ok(fs.lookup(&root, b"d2")).0, dir);
    let (_, d2attr) = ok(fs.lookup(&root, b"d2"));
    assert_eq!(d2attr.ftype, FileType::Directory);

    // remove: file ok, missing -> NoEnt, directory -> IsDir.
    ok(fs.remove(&root, b"hard"));
    expect_status(fs.remove(&root, b"hard"), Status::NoEnt);
    expect_status(fs.remove(&root, b"d2"), Status::IsDir);

    // rmdir: non-empty -> NotEmpty, file -> NotDir, then empty dir works.
    expect_status(fs.rmdir(&root, b"d2"), Status::NotEmpty);
    expect_status(fs.rmdir(&root, b"renamed.txt"), Status::NotDir);
    ok(fs.remove(&dir, b"inner"));
    ok(fs.rmdir(&root, b"d2"));
    expect_status(fs.lookup(&root, b"d2"), Status::NoEnt);

    // fsstat: bytes = blocks * bsize.
    let st = ok(fs.fsstat(&root));
    assert_eq!(st.total_bytes, 1000 * 1024);
    assert_eq!(st.free_bytes, 500 * 1024);
    assert_eq!(st.avail_bytes, 400 * 1024);
    assert_eq!((st.total_files, st.free_files, st.avail_files), (0, 0, 0));

    // Stale handle.
    let mut bogus = [0u8; 32];
    bogus[..4].copy_from_slice(&0xdead_beefu32.to_be_bytes());
    expect_status(fs.getattr(&FileHandle(bogus.to_vec())), Status::Stale);

    // A non-32-byte handle is rejected locally.
    expect_status(fs.getattr(&FileHandle(vec![0; 16])), Status::BadHandle);

    // Names over 255 bytes are rejected locally.
    expect_status(fs.lookup(&root, &[b'n'; 256]), Status::NameTooLong);

    // Exclusive create on a fresh name works (best effort, not atomic).
    ok(fs.create(&root, b"excl", CreateMode::Exclusive, &SetAttr::default()));

    ok(fs.disconnect());
}

#[test]
fn full_suite_tcp() {
    full_suite(Proto::Tcp);
}

#[test]
fn full_suite_udp() {
    full_suite(Proto::Udp);
}

fn pagination(proto: Proto) {
    let srv = start();
    let mut fs = mount(&srv, proto);
    let root = fs.root();
    let mut want = Vec::new();
    for i in 0..200 {
        let name = format!("file-with-a-rather-long-name-{i:04}-{}", "x".repeat(40));
        create_file(fs.as_mut(), &root, &name);
        want.push(name.into_bytes());
    }
    let before = srv.stats.readdir_calls.load(Ordering::SeqCst);
    let entries = ok(fs.readdir(&root));
    let calls = srv.stats.readdir_calls.load(Ordering::SeqCst) - before;
    assert!(calls >= 2, "expected multiple READDIR pages, got {calls}");
    want.sort();
    assert_eq!(names(&entries), want);
    // Each file name is unique: no duplicates across pages.
    let mut dedup = names(&entries);
    dedup.dedup();
    assert_eq!(dedup.len(), 200);
}

#[test]
fn readdir_paginates_tcp() {
    pagination(Proto::Tcp);
}

#[test]
fn readdir_paginates_udp() {
    pagination(Proto::Udp);
}

#[test]
fn empty_directory_lists_nothing() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    assert!(ok(fs.readdir(&root)).is_empty());
}

#[test]
fn offsets_beyond_u32_are_fbig() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (fh, _) = create_file(fs.as_mut(), &root, "f");
    let beyond = u64::from(u32::MAX) + 1;
    expect_status(fs.read(&fh, beyond, 10), Status::FBig);
    expect_status(fs.write(&fh, beyond, b"x"), Status::FBig);
    expect_status(
        fs.setattr(
            &fh,
            &SetAttr {
                size: Some(beyond),
                ..SetAttr::default()
            },
        ),
        Status::FBig,
    );
}

#[test]
fn read_at_4gib_boundary_is_clamped_not_sent() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (fh, _) = create_file(fs.as_mut(), &root, "f");
    // The last addressable offset with a request that runs past 4 GiB.
    let (data, eof) = ok(fs.read(&fh, u64::from(u32::MAX), 100));
    assert!(data.is_empty());
    assert!(eof);
}

#[test]
fn read_count_is_capped_at_maxdata() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Udp);
    let root = fs.root();
    let (fh, _) = create_file(fs.as_mut(), &root, "f");
    let data = vec![7u8; 9000];
    write_all(fs.as_mut(), &fh, 0, &data);
    let (chunk, eof) = ok(fs.read(&fh, 0, 100_000));
    assert_eq!(chunk.len(), 8192);
    assert!(!eof);
}

#[test]
fn udp_retransmits_after_dropped_request() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Udp);
    srv.stats.udp_drop.store(1, Ordering::SeqCst);
    let a = ok(fs.getattr(&fs.root()));
    assert_eq!(a.fileid, 1);
    assert_eq!(srv.stats.udp_drop.load(Ordering::SeqCst), 0);
}

#[test]
fn timeout_when_server_never_answers() {
    let srv = start();
    let mut opts = rpc_opts(Proto::Udp);
    opts.timeout = Duration::from_millis(1500);
    let mut fs =
        connect_with_root(IpAddr::V4(Ipv4Addr::LOCALHOST), srv.port, srv.root(), &opts).unwrap();
    // Drop more requests than the client will send in its window.
    srv.stats.udp_drop.store(100, Ordering::SeqCst);
    match fs.getattr(&fs.root()) {
        Err(Error::Timeout) => {}
        other => panic!("expected timeout, got {other:?}"),
    }
}

#[test]
fn rename_over_existing_file_replaces_it() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (a, _) = create_file(fs.as_mut(), &root, "a");
    ok(fs.write(&a, 0, b"AAA"));
    let (b, _) = create_file(fs.as_mut(), &root, "b");
    ok(fs.write(&b, 0, b"BBBB"));
    ok(fs.rename(&root, b"a", &root, b"b"));
    let (nb, attr) = ok(fs.lookup(&root, b"b"));
    assert_eq!(nb, a);
    assert_eq!(attr.size, 3);
    expect_status(fs.lookup(&root, b"a"), Status::NoEnt);
}

#[test]
fn rename_directory_into_another_directory_fixes_dotdot() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let src = mkdir(fs.as_mut(), &root, "src");
    let dst = mkdir(fs.as_mut(), &root, "dst");
    let moved = mkdir(fs.as_mut(), &src, "moved");
    ok(fs.rename(&src, b"moved", &dst, b"moved"));
    let (fh, _) = ok(fs.lookup(&dst, b"moved"));
    assert_eq!(fh, moved);
    let (up, _) = ok(fs.lookup(&moved, b".."));
    assert_eq!(up, dst);
}

#[test]
fn symlink_and_readlink_on_non_link_is_error() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (f, _) = create_file(fs.as_mut(), &root, "plain");
    expect_status(fs.readlink(&f), Status::Inval);
}

#[test]
fn setattr_mode_only_keeps_size() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (f, _) = create_file(fs.as_mut(), &root, "f");
    ok(fs.write(&f, 0, b"abc"));
    let a = ok(fs.setattr(
        &f,
        &SetAttr {
            mode: Some(0o4755),
            ..SetAttr::default()
        },
    ));
    assert_eq!(a.mode, 0o4755);
    assert_eq!(a.size, 3);
}

#[test]
fn connect_with_root_disconnect_is_quiet() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    // No MOUNT state to undo, so disconnect must not touch MOUNT at all.
    ok(fs.disconnect());
}
