//! NFSv3 backend against the in-process fake NFSv3 + MOUNTv3 + portmap server
//! (tests/nfs3_backend/server.rs), with fault injection.
//!
//! Most tests pass the NFS and MOUNT ports in `ConnectOptions`, so portmap is
//! not involved. Tests that need portmap on 111 (or NFS on 2049) re-run
//! themselves inside a private user + network namespace (`unshare -rn`), where
//! an unprivileged process may bind those ports; where namespaces are not
//! available they print a note and pass.
//!
//! Connections use a short retry budget ([`fast_retry`]) so fault tests that
//! exhaust it finish quickly.

#[path = "nfs3_backend/server.rs"]
mod server;

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::{Duration, Instant};

use nfsc::error::Error;
use nfsc::fs::{
    ConnectOptions, Connected, CreateMode, FileHandle, FileType, Filesystem, NfsVersion, SetAttr,
    Status, VersionPref, connect,
};
use nfsc::rpc::{Auth, PortMode, Proto, RetryPolicy, RpcOptions};

use server::{
    COMMIT, Config, FSINFO, FakeNfs3, Fault, Fsinfo, GETATTR, MOUNT_PROG, NFS_PROG,
    NFS3ERR_BAD_COOKIE, NFS3ERR_JUKEBOX, NFS3ERR_SERVERFAULT, NFS3ERR_TOOSMALL, READ, READDIR,
    READDIRPLUS, Rule, WRITE, pattern, pattern_byte, start, start_with,
};

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

fn rpc(proto: Proto) -> RpcOptions {
    RpcOptions {
        proto,
        port_mode: PortMode::Unprivileged,
        timeout: Duration::from_secs(5),
        auth: Auth::None,
        retry: fast_retry(),
    }
}

/// Retries with a short budget and backoff, so fault tests run fast.
fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        budget: Duration::from_secs(8),
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(500),
        ..RetryPolicy::default()
    }
}

/// Options that reach the fake directly, without portmap.
fn opts(srv: &FakeNfs3, proto: Proto) -> ConnectOptions {
    ConnectOptions {
        rpc: rpc(proto),
        nfs_port: Some(srv.port),
        mount_port: Some(srv.port),
        version: VersionPref::Exact(NfsVersion::V3),
    }
}

fn mount(srv: &FakeNfs3, proto: Proto) -> Box<dyn Filesystem> {
    connect(LOCALHOST, b"/export", &opts(srv, proto))
        .unwrap_or_else(|e| panic!("connect: {e}"))
        .fs
}

/// [`mount`] with a retry budget of half a second, for faults that never
/// clear (the client retries, then gives up).
fn mount_short_budget(srv: &FakeNfs3) -> Box<dyn Filesystem> {
    let mut o = opts(srv, Proto::Tcp);
    o.rpc.retry.budget = Duration::from_millis(500);
    connect(LOCALHOST, b"/export", &o)
        .unwrap_or_else(|e| panic!("connect: {e}"))
        .fs
}

fn lookup(fs: &mut dyn Filesystem, path: &str) -> FileHandle {
    let mut fh = fs.root();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        fh = fs
            .lookup(&fh, c.as_bytes())
            .unwrap_or_else(|e| panic!("lookup {c}: {e}"))
            .0;
    }
    fh
}

/// FNV-1a, enough to compare multi-MB transfers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 = (self.0 ^ u64::from(b)).wrapping_mul(0x100_0000_01b3);
        }
    }
    fn of(data: &[u8]) -> Self {
        let mut h = Fnv::new();
        h.update(data);
        h
    }
}

/// What a read_stream delivered, checked byte for byte against a pattern file.
struct Checked {
    result: nfsc::Result<u64>,
    /// Bytes delivered that matched the pattern at their offset (all of them,
    /// or the check panicked).
    delivered: u64,
    hash: Fnv,
}

fn stream_pattern(
    fs: &mut dyn Filesystem,
    fh: &FileHandle,
    seed: u64,
    offset: u64,
    len: Option<u64>,
) -> Checked {
    let mut pos = offset;
    let mut hash = Fnv::new();
    let result = fs.read_stream(fh, offset, len, &mut |chunk| {
        for (i, &b) in chunk.iter().enumerate() {
            let at = pos + i as u64;
            assert_eq!(b, pattern_byte(seed, at), "wrong byte at offset {at}");
        }
        hash.update(chunk);
        pos += chunk.len() as u64;
        Ok(())
    });
    Checked {
        result,
        delivered: pos - offset,
        hash,
    }
}

/// Bytes from `data` to `write_stream`, in odd-sized pieces.
fn write_from(fs: &mut dyn Filesystem, fh: &FileHandle, data: &[u8]) -> nfsc::Result<u64> {
    let mut at = 0usize;
    fs.write_stream(fh, 0, &mut |buf| {
        let n = buf.len().min(data.len() - at).min(50_000);
        buf[..n].copy_from_slice(&data[at..at + n]);
        at += n;
        Ok(n)
    })
}

fn read_all(fs: &mut dyn Filesystem, fh: &FileHandle) -> Vec<u8> {
    let mut out = Vec::new();
    fs.read_stream(fh, 0, None, &mut |c| {
        out.extend_from_slice(c);
        Ok(())
    })
    .expect("read_stream");
    out
}

fn sorted_names(entries: &[nfsc::fs::DirEntry]) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = entries.iter().map(|e| e.name.clone()).collect();
    v.sort();
    v
}

// ------------------------------------------------------------ basic paths

fn basic(proto: Proto) {
    let srv = start();
    let size = 6 * MIB + 12345;
    srv.add_pattern_file("data/big.bin", size, 7);
    srv.with_fs(|fs| {
        fs.add_file("hello.txt", b"hello world").unwrap();
        fs.add_dir("empty").unwrap();
    });

    let Connected {
        mut fs,
        export,
        remainder,
    } = connect(LOCALHOST, b"/export/data", &opts(&srv, proto)).expect("connect");
    assert_eq!(export, b"/export");
    assert_eq!(remainder, vec![b"data".to_vec()]);
    assert_eq!(fs.version(), NfsVersion::V3);
    let st = srv.stats();
    assert_eq!(st.mount(server::MNT), 1);
    assert_eq!(st.mount(server::MOUNT_EXPORT), 1);
    assert_eq!(st.nfs(FSINFO), 1);
    match proto {
        Proto::Tcp => assert_eq!((fs.max_read(), fs.max_write()), (64 << 10, 64 << 10)),
        Proto::Udp => assert_eq!((fs.max_read(), fs.max_write()), (32 << 10, 32 << 10)),
    }

    // ls of the root, with READDIRPLUS attributes.
    let root = fs.root();
    let entries = fs.readdir(&root).expect("readdir");
    assert_eq!(
        sorted_names(&entries),
        vec![b"data".to_vec(), b"empty".to_vec(), b"hello.txt".to_vec()]
    );
    let hello = entries.iter().find(|e| e.name == b"hello.txt").unwrap();
    assert_eq!(hello.attr.as_ref().unwrap().size, 11);
    assert!(hello.handle.is_some());
    let empty = lookup(fs.as_mut(), "empty");
    assert!(fs.readdir(&empty).unwrap().is_empty());

    // getattr and lookup.
    let a = fs.getattr(&root).unwrap();
    assert_eq!(a.ftype, FileType::Directory);
    let big = lookup(fs.as_mut(), "data/big.bin");
    let a = fs.getattr(&big).unwrap();
    assert_eq!((a.ftype, a.size), (FileType::Regular, size));
    match fs.lookup(&root, b"missing") {
        Err(Error::Nfs(Status::NoEnt)) => {}
        other => panic!("expected NoEnt, got {other:?}"),
    }

    // read_stream of the multi-MB file, to EOF and with a length.
    let c = stream_pattern(fs.as_mut(), &big, 7, 0, None);
    assert_eq!(c.result.unwrap(), size);
    assert_eq!(c.hash, Fnv::of(&pattern(7, 0, size as usize)));
    let c = stream_pattern(fs.as_mut(), &big, 7, 1000, Some(MIB));
    assert_eq!(c.result.unwrap(), MIB);
    // A length past EOF stops at EOF.
    let c = stream_pattern(fs.as_mut(), &big, 7, size - 10, Some(100));
    assert_eq!(c.result.unwrap(), 10);

    // write_stream (UNSTABLE + COMMIT), then read back through both sides.
    let data = pattern(99, 0, (3 * MIB + 777) as usize);
    let (fh, _) = fs
        .create(&root, b"out.bin", CreateMode::Guarded, &SetAttr::default())
        .unwrap();
    srv.reset_stats();
    assert_eq!(
        write_from(fs.as_mut(), &fh, &data).unwrap(),
        data.len() as u64
    );
    let st = srv.stats();
    assert!(st.unstable_writes > 0, "write_stream used FILE_SYNC");
    assert!(st.nfs(COMMIT) >= 1, "no COMMIT after unstable writes");
    assert_eq!(srv.uncommitted(), 0, "unstable data left uncommitted");
    assert_eq!(Fnv::of(&srv.file("out.bin")), Fnv::of(&data));
    assert_eq!(Fnv::of(&read_all(fs.as_mut(), &fh)), Fnv::of(&data));

    // Small FILE_SYNC write and read.
    assert_eq!(fs.write(&fh, 0, b"HEAD").unwrap(), 4);
    let mut want = b"HEAD".to_vec();
    want.extend_from_slice(&data[4..6]);
    assert_eq!(fs.read(&fh, 0, 6).unwrap(), (want, false));
    assert_eq!(srv.uncommitted(), 0);

    fs.disconnect().unwrap();
    assert_eq!(srv.stats().mount(server::UMNT), 1);
}

#[test]
fn basic_tcp() {
    basic(Proto::Tcp);
}

#[test]
fn basic_udp() {
    basic(Proto::Udp);
}

#[test]
fn auto_version_settles_on_v3() {
    let srv = start();
    let mut o = opts(&srv, Proto::Tcp);
    o.version = VersionPref::Auto;
    let mut c = connect(LOCALHOST, b"/export", &o).expect("connect");
    assert_eq!(c.fs.version(), NfsVersion::V3);
    c.fs.getattr(&c.fs.root()).unwrap();
}

#[test]
fn mount_of_unexported_path_fails() {
    let srv = start();
    // EXPORT lists only /export, so "/other" is mounted directly and refused.
    match connect(LOCALHOST, b"/other", &opts(&srv, Proto::Tcp)) {
        Err(Error::Nfs(Status::NoEnt)) => {}
        Err(e) => panic!("expected NoEnt, got {e}"),
        Ok(_) => panic!("mount of /other succeeded"),
    }
}

#[test]
fn reads_beyond_4gib_on_sparse_file() {
    let srv = start();
    let size = 6 * GIB + 4321;
    let fh = srv.add_pattern_file("huge.bin", size, 0xfeed);
    let mut fs = mount(&srv, Proto::Tcp);
    assert_eq!(fs.getattr(&fh).unwrap().size, size);

    for off in [
        (4 * GIB) - 3,
        4 * GIB,
        4 * GIB + 1,
        5 * GIB + 123_456_789,
        size - 70_000,
    ] {
        let (data, eof) = fs.read(&fh, off, 4096).unwrap();
        assert_eq!(data, pattern(0xfeed, off, 4096), "read at {off}");
        assert!(!eof);
        let c = stream_pattern(fs.as_mut(), &fh, 0xfeed, off, Some(300_000));
        let want = (size - off).min(300_000);
        assert_eq!(c.result.unwrap(), want, "stream at {off}");
    }
    // The tail: short final read with EOF.
    let (data, eof) = fs.read(&fh, size - 100, 4096).unwrap();
    assert_eq!(data, pattern(0xfeed, size - 100, 100));
    assert!(eof);
    let (data, eof) = fs.read(&fh, size + GIB, 10).unwrap();
    assert!(data.is_empty() && eof);
}

#[test]
fn writes_beyond_4gib_land_at_the_right_offset() {
    let srv = start();
    srv.with_fs(|fs| fs.add_sparse_file("sparse.bin", 5 * GIB, 0).unwrap());
    let mut fs = mount(&srv, Proto::Tcp);
    let fh = lookup(fs.as_mut(), "sparse.bin");
    let off = 4 * GIB + 17;
    assert_eq!(fs.write(&fh, off, b"far away").unwrap(), 8);
    assert_eq!(fs.read(&fh, off - 2, 12).unwrap().0, b"\0\0far away\0\0");
    // Nothing leaked to the low 32 bits of the offset.
    assert_eq!(fs.read(&fh, 17, 8).unwrap().0, vec![0; 8]);
}

// ------------------------------------------------------------- READ faults

#[test]
fn short_read_replies_are_refetched() {
    let srv = start();
    let size = 4 * MIB + 99;
    let fh = srv.add_pattern_file("f", size, 3);
    let mut fs = mount(&srv, Proto::Tcp);
    srv.script(vec![
        Rule::nfs(READ, Fault::ShortRead(1000)).when(|c| c.seq % 3 == 0),
        Rule::nfs(READ, Fault::ShortRead(1)).when(|c| c.seq % 7 == 0),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 3, 0, None);
    assert_eq!(c.result.unwrap(), size);
    assert!(srv.stats().faults_fired > 3);

    // With a length too.
    let c = stream_pattern(fs.as_mut(), &fh, 3, 12345, Some(2 * MIB));
    assert_eq!(c.result.unwrap(), 2 * MIB);

    // A single short read() is returned as is.
    srv.script(vec![Rule::nfs(READ, Fault::ShortRead(10)).times(1)]);
    let (d, eof) = fs.read(&fh, 0, 4096).unwrap();
    assert_eq!((d.len(), eof), (10, false));
}

#[test]
fn short_read_replies_over_udp() {
    let srv = start();
    let size = MIB + 5;
    let fh = srv.add_pattern_file("f", size, 4);
    let mut fs = mount(&srv, Proto::Udp);
    srv.script(vec![
        Rule::nfs(READ, Fault::ShortRead(777)).when(|c| c.seq % 2 == 0),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 4, 0, Some(size));
    assert_eq!(c.result.unwrap(), size);
}

#[test]
fn read_count_beyond_data_is_rejected() {
    let srv = start();
    let fh = srv.add_pattern_file("f", 2 * MIB, 5);
    let mut fs = mount(&srv, Proto::Tcp);

    // Plain read(): a protocol error, not short or padded data.
    srv.script(vec![Rule::nfs(READ, Fault::CountOverData(10)).times(1)]);
    match fs.read(&fh, 0, 4096) {
        Err(Error::Protocol(m)) => assert!(m.contains("count"), "{m}"),
        other => panic!("expected protocol error, got {other:?}"),
    }

    // Once in a stream: that reply is dropped and the range is fetched again.
    srv.script(vec![
        Rule::nfs(READ, Fault::CountOverData(1)).after(3).times(1),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 5, 0, None);
    assert_eq!(c.result.unwrap(), 2 * MIB);

    // Every time for one offset: the stream fails at that offset, and what
    // reached the sink before is correct (checked by stream_pattern).
    let bad = 5 * 65536;
    srv.script(vec![
        Rule::nfs(READ, Fault::CountOverData(1)).when(move |c| c.offset == bad),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 5, 0, None);
    match c.result {
        Err(Error::Protocol(_)) => {}
        other => panic!("expected protocol error, got {other:?}"),
    }
    assert!(
        c.delivered <= bad,
        "delivered {} past the bad reply",
        c.delivered
    );
}

/// read_stream to EOF (`len: None`, as `cat` and `get x -` use it) must not
/// stop at a READ reply with no data and eof = false and return Ok with
/// however much it had: that would be a silently truncated file.
#[test]
fn read_reply_with_no_data_and_no_eof_is_an_error_to_eof() {
    let size = MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 6);
    let mut fs = mount_short_budget(&srv);
    let bad = 3 * 65536;
    srv.script(vec![
        Rule::nfs(READ, Fault::ShortRead(0)).when(move |c| c.offset == bad),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 6, 0, None);
    assert_complete_or_error(&c, size);
}

#[test]
fn read_reply_with_no_data_and_no_eof_is_an_error_with_length() {
    let srv = start();
    let fh = srv.add_pattern_file("f", MIB, 6);
    let mut fs = mount_short_budget(&srv);
    let bad = 3 * 65536;
    srv.script(vec![
        Rule::nfs(READ, Fault::ShortRead(0)).when(move |c| c.offset == bad),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 6, 0, Some(MIB));
    assert!(c.result.is_err(), "silently short: {:?}", c.result);
    assert_eq!(c.delivered, bad);
}

// ------------------------------------------------------------ WRITE faults

fn verifier_change(rule: Rule) {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (fh, _) = fs
        .create(&root, b"w.bin", CreateMode::Unchecked, &SetAttr::default())
        .unwrap();
    let data = pattern(0xabc, 0, (2 * MIB + 3) as usize);
    let chunks = data.len().div_ceil(fs.max_write() as usize);
    srv.script(vec![rule]);
    assert_eq!(
        write_from(fs.as_mut(), &fh, &data).unwrap(),
        data.len() as u64
    );
    let st = srv.stats();
    assert_eq!(st.faults_fired, 1);
    assert!(
        st.nfs(WRITE) > chunks,
        "no WRITE was resent ({} for {chunks} chunks)",
        st.nfs(WRITE)
    );
    assert!(st.nfs(COMMIT) >= 2, "only {} COMMIT", st.nfs(COMMIT));
    assert_eq!(srv.uncommitted(), 0);
    let got = srv.file("w.bin");
    assert_eq!(got.len(), data.len());
    assert!(got == data, "file content differs after verifier change");
}

#[test]
fn write_verifier_change_mid_stream_forces_resend() {
    verifier_change(Rule::nfs(WRITE, Fault::BumpVerifier).after(10).times(1));
}

#[test]
fn write_verifier_change_at_commit_forces_resend() {
    verifier_change(Rule::nfs(COMMIT, Fault::BumpVerifier).times(1));
}

#[test]
fn write_verifier_that_never_settles_is_an_error() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (fh, _) = fs
        .create(&root, b"w.bin", CreateMode::Unchecked, &SetAttr::default())
        .unwrap();
    srv.script(vec![Rule::nfs(COMMIT, Fault::BumpVerifier)]);
    let data = vec![1u8; 300_000];
    let r = write_from(fs.as_mut(), &fh, &data);
    assert!(r.is_err(), "write_stream reported success: {r:?}");
}

#[test]
fn write_error_mid_stream_is_reported() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (fh, _) = fs
        .create(&root, b"w.bin", CreateMode::Unchecked, &SetAttr::default())
        .unwrap();
    srv.script(vec![Rule::nfs(WRITE, Fault::Status(28)).after(5).times(1)]);
    match write_from(fs.as_mut(), &fh, &vec![2u8; MIB as usize]) {
        Err(Error::Nfs(Status::NoSpc)) => {}
        other => panic!("expected NoSpc, got {other:?}"),
    }
}

// ------------------------------------------------------------------ FSINFO

#[test]
fn fsinfo_failure_falls_back_to_defaults() {
    for fault in [
        Fault::Status(NFS3ERR_SERVERFAULT),
        Fault::Accept(server::ACCEPT_PROC_UNAVAIL),
    ] {
        let srv = start();
        srv.script(vec![Rule::nfs(FSINFO, fault)]);
        let fh = srv.add_pattern_file("f", MIB, 8);
        let mut fs = mount(&srv, Proto::Tcp);
        assert_eq!((fs.max_read(), fs.max_write()), (64 << 10, 64 << 10));
        let c = stream_pattern(fs.as_mut(), &fh, 8, 0, None);
        assert_eq!(c.result.unwrap(), MIB);
    }
}

#[test]
fn transfers_respect_rtmax_and_wtmax() {
    let srv = start_with(Config {
        fsinfo: Fsinfo {
            rtmax: 16 << 10,
            rtpref: 64 << 10,
            wtmax: 8 << 10,
            wtpref: 32 << 10,
            dtpref: 4096,
        },
        ..Config::default()
    });
    let fh = srv.add_pattern_file("f", MIB + 1, 9);
    let mut fs = mount(&srv, Proto::Tcp);
    assert_eq!((fs.max_read(), fs.max_write()), (16 << 10, 8 << 10));

    let c = stream_pattern(fs.as_mut(), &fh, 9, 0, None);
    assert_eq!(c.result.unwrap(), MIB + 1);
    let (d, _) = fs.read(&fh, 0, 1 << 20).unwrap();
    assert_eq!(d.len(), 16 << 10);

    let root = fs.root();
    let (w, _) = fs
        .create(&root, b"w", CreateMode::Unchecked, &SetAttr::default())
        .unwrap();
    let data = pattern(1, 0, 200_000);
    write_from(fs.as_mut(), &w, &data).unwrap();
    assert_eq!(fs.write(&w, 0, &data).unwrap(), 8 << 10);
    assert_eq!(srv.file("w"), data);

    let st = srv.stats();
    assert_eq!(
        st.rtmax_violations, 0,
        "READ over rtmax: {}",
        st.max_read_count
    );
    assert_eq!(
        st.wtmax_violations, 0,
        "WRITE over wtmax: {}",
        st.max_write_len
    );
    assert_eq!(st.max_read_count, 16 << 10);
}

#[test]
fn huge_fsinfo_sizes_are_capped() {
    let srv = start_with(Config {
        fsinfo: Fsinfo {
            rtmax: 64 << 20,
            rtpref: 16 << 20,
            wtmax: 64 << 20,
            wtpref: 16 << 20,
            dtpref: 4096,
        },
        ..Config::default()
    });
    let fs = mount(&srv, Proto::Tcp);
    assert_eq!((fs.max_read(), fs.max_write()), (1 << 20, 1 << 20));
    let fs = mount(&srv, Proto::Udp);
    assert_eq!((fs.max_read(), fs.max_write()), (32 << 10, 32 << 10));
}

// ---------------------------------------------------------------- READDIR

fn populate(srv: &FakeNfs3, dir: &str, n: usize) -> Vec<Vec<u8>> {
    srv.with_fs(|fs| {
        fs.add_dir(dir).unwrap();
        (0..n)
            .map(|i| {
                let name = format!("entry-{i:06}-{}", "n".repeat(i % 40));
                fs.add_file(&format!("{dir}/{name}"), &[]).unwrap();
                name.into_bytes()
            })
            .collect()
    })
}

#[test]
fn readdirplus_toosmall_falls_back_to_readdir() {
    let srv = start();
    let mut want = populate(&srv, "d", 3000);
    want.sort();
    let mut fs = mount(&srv, Proto::Tcp);
    let d = lookup(fs.as_mut(), "d");
    srv.script(vec![Rule::nfs(
        READDIRPLUS,
        Fault::Status(NFS3ERR_TOOSMALL),
    )]);
    let entries = fs.readdir(&d).expect("readdir");
    assert_eq!(sorted_names(&entries), want);
    assert!(entries.iter().all(|e| e.attr.is_none()));
    let st = srv.stats();
    assert_eq!(st.nfs(READDIRPLUS), 1);
    assert!(st.nfs(READDIR) >= 2, "READDIR pages: {}", st.nfs(READDIR));
    // The fallback sticks for later listings.
    fs.readdir(&d).unwrap();
    assert_eq!(srv.stats().nfs(READDIRPLUS), 1);
}

#[test]
fn readdirplus_notsupp_falls_back_to_readdir() {
    let srv = start();
    populate(&srv, "d", 10);
    let mut fs = mount(&srv, Proto::Tcp);
    let d = lookup(fs.as_mut(), "d");
    srv.script(vec![Rule::nfs(
        READDIRPLUS,
        Fault::Accept(server::ACCEPT_PROC_UNAVAIL),
    )]);
    assert_eq!(fs.readdir(&d).unwrap().len(), 10);
}

#[test]
fn bad_cookie_restarts_the_listing() {
    let srv = start();
    let mut want = populate(&srv, "d", 2000);
    want.sort();
    let mut fs = mount(&srv, Proto::Tcp);
    let d = lookup(fs.as_mut(), "d");
    srv.script(vec![
        Rule::nfs(READDIRPLUS, Fault::Status(NFS3ERR_BAD_COOKIE))
            .when(|c| c.cookie != 0)
            .after(2)
            .times(1),
    ]);
    let entries = fs.readdir(&d).expect("readdir");
    assert_eq!(entries.len(), 2000, "duplicates or losses after restart");
    assert_eq!(sorted_names(&entries), want);
    assert_eq!(srv.stats().faults_fired, 1);

    // A second BAD_COOKIE within one listing is reported.
    srv.script(vec![
        Rule::nfs(READDIRPLUS, Fault::Status(NFS3ERR_BAD_COOKIE)).when(|c| c.cookie != 0),
    ]);
    match fs.readdir(&d) {
        Err(Error::Nfs(Status::BadCookie)) => {}
        other => panic!("expected BadCookie, got {:?}", other.map(|v| v.len())),
    }
}

#[test]
fn huge_directory_lists_completely() {
    let srv = start();
    let mut want = populate(&srv, "big", 20_000);
    want.sort();
    let mut fs = mount(&srv, Proto::Tcp);
    let d = lookup(fs.as_mut(), "big");
    let t = Instant::now();
    let entries = fs.readdir(&d).expect("readdir");
    assert_eq!(entries.len(), 20_000);
    assert_eq!(sorted_names(&entries), want);
    assert!(
        entries
            .iter()
            .all(|e| e.attr.is_some() && e.handle.is_some())
    );
    let pages = srv.stats().nfs(READDIRPLUS);
    assert!(pages > 10, "only {pages} READDIRPLUS pages");
    eprintln!("20k entries in {pages} pages, {:?}", t.elapsed());

    // Plain READDIR over UDP too.
    let mut fs = mount(&srv, Proto::Udp);
    srv.script(vec![Rule::nfs(
        READDIRPLUS,
        Fault::Status(NFS3ERR_TOOSMALL),
    )]);
    let entries = fs.readdir(&d).expect("readdir over udp");
    assert_eq!(sorted_names(&entries), want);
}

// -------------------------------------------------------- connection loss

/// The transfer either delivers exactly the file, or fails; never a short Ok.
fn assert_complete_or_error(c: &Checked, size: u64) {
    match &c.result {
        Ok(n) => {
            assert_eq!(*n, size, "silently short read_stream");
            assert_eq!(c.delivered, size);
        }
        Err(e) => {
            assert!(c.delivered < size);
            eprintln!("transfer failed after {} bytes: {e}", c.delivered);
        }
    }
}

#[test]
fn connection_drop_mid_read_stream() {
    let size = 3 * MIB + 1;
    for fault in [Fault::Drop, Fault::Truncate(4 + 40), Fault::Truncate(3)] {
        let srv = start();
        let fh = srv.add_pattern_file("f", size, 11);
        let mut fs = mount(&srv, Proto::Tcp);
        srv.script(vec![Rule::nfs(READ, fault.clone()).after(5).times(1)]);
        let c = stream_pattern(fs.as_mut(), &fh, 11, 0, None);
        assert_complete_or_error(&c, size);
        // The client reconnects on its next call, so today it recovers.
        assert_eq!(c.result.as_ref().ok(), Some(&size), "{fault:?}");
        assert!(
            srv.stats().tcp_connections >= 3,
            "no reconnect for {fault:?}"
        );

        // Same with a requested length.
        srv.script(vec![Rule::nfs(READ, fault.clone()).after(2).times(1)]);
        let c = stream_pattern(fs.as_mut(), &fh, 11, 0, Some(size));
        assert_complete_or_error(&c, size);
    }
}

#[test]
fn repeated_connection_drops_never_give_short_data() {
    let size = 2 * MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 12);
    let mut fs = mount(&srv, Proto::Tcp);
    srv.script(vec![Rule::nfs(READ, Fault::Drop).when(|c| c.seq % 4 == 0)]);
    let c = stream_pattern(fs.as_mut(), &fh, 12, 0, None);
    assert_complete_or_error(&c, size);
    let c = stream_pattern(fs.as_mut(), &fh, 12, 0, Some(size));
    assert_complete_or_error(&c, size);
}

#[test]
fn delayed_replies_still_complete() {
    let size = MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 13);
    let mut fs = mount(&srv, Proto::Tcp);
    srv.script(vec![
        Rule::nfs(READ, Fault::Delay(Duration::from_millis(30))).when(|c| c.seq % 3 == 0),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 13, 0, None);
    assert_eq!(c.result.unwrap(), size);
}

#[test]
fn reply_slower_than_the_timeout_mid_stream() {
    let size = 2 * MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 19);
    let mut o = opts(&srv, Proto::Tcp);
    o.rpc.timeout = Duration::from_millis(400);
    let mut fs = connect(LOCALHOST, b"/export", &o).unwrap().fs;
    // One reply arrives after the client gave up on it; the late reply (and
    // the ones queued behind it on the connection) must not be mistaken for
    // the answers to later requests.
    srv.script(vec![
        Rule::nfs(READ, Fault::Delay(Duration::from_millis(700)))
            .after(4)
            .times(1),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 19, 0, Some(size));
    assert_complete_or_error(&c, size);
    let c = stream_pattern(fs.as_mut(), &fh, 19, 0, None);
    assert_eq!(c.result.unwrap(), size);
}

#[test]
fn connection_drop_mid_write_stream_is_never_silent() {
    for fault in [Fault::Drop, Fault::Truncate(10)] {
        let srv = start();
        let mut fs = mount(&srv, Proto::Tcp);
        let root = fs.root();
        let (fh, _) = fs
            .create(&root, b"w", CreateMode::Unchecked, &SetAttr::default())
            .unwrap();
        srv.script(vec![Rule::nfs(WRITE, fault.clone()).after(6).times(1)]);
        let data = pattern(20, 0, (2 * MIB) as usize);
        match write_from(fs.as_mut(), &fh, &data) {
            Ok(n) => {
                assert_eq!(n, data.len() as u64);
                assert!(
                    srv.file("w") == data,
                    "Ok but wrong content after {fault:?}"
                );
            }
            Err(e) => eprintln!("write_stream failed after {fault:?}: {e}"),
        }
        // The backend is usable afterwards.
        fs.getattr(&fh).expect("getattr after the drop");
    }
}

#[test]
fn single_jukebox_in_stream_is_absorbed_by_fallback() {
    let size = MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 21);
    let mut fs = mount(&srv, Proto::Tcp);
    let busy = 2 * 65536;
    srv.script(vec![
        Rule::nfs(READ, Fault::Status(NFS3ERR_JUKEBOX))
            .when(move |c| c.offset == busy)
            .times(1),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 21, 0, None);
    assert_eq!(c.result.unwrap(), size);
}

#[test]
fn silent_server_times_out() {
    let srv = start();
    let mut o = opts(&srv, Proto::Tcp);
    o.rpc.timeout = Duration::from_millis(500);
    o.rpc.retry = RetryPolicy::none();
    let mut fs = connect(LOCALHOST, b"/export", &o).unwrap().fs;
    srv.script(vec![Rule::nfs(GETATTR, Fault::Silent)]);
    let t = Instant::now();
    match fs.getattr(&fs.root()) {
        Err(Error::Timeout) => {}
        other => panic!("expected timeout, got {other:?}"),
    }
    assert!(t.elapsed() < Duration::from_secs(4));
}

// --------------------------------------------------------- retry policy

#[test]
fn jukebox_twice_then_ok_read_completes() {
    let size = 2 * MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 14);
    let mut fs = mount(&srv, Proto::Tcp);
    // Both JUKEBOX replies hit the same range: the pipelined READ and the
    // blocking READ the pipeline falls back to.
    let busy = 3 * 65536;
    srv.script(vec![
        Rule::nfs(READ, Fault::Status(NFS3ERR_JUKEBOX))
            .when(move |c| c.offset == busy)
            .times(2),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 14, 0, None);
    assert_eq!(c.result.unwrap(), size);
}

#[test]
fn jukebox_twice_then_ok_getattr() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    srv.script(vec![
        Rule::nfs(GETATTR, Fault::Status(NFS3ERR_JUKEBOX)).times(2),
    ]);
    fs.getattr(&fs.root()).expect("getattr after JUKEBOX x2");
}

#[test]
fn jukebox_during_write_stream_completes() {
    let srv = start();
    let mut fs = mount(&srv, Proto::Tcp);
    let root = fs.root();
    let (fh, _) = fs
        .create(&root, b"w", CreateMode::Unchecked, &SetAttr::default())
        .unwrap();
    srv.script(vec![
        Rule::nfs(WRITE, Fault::Status(NFS3ERR_JUKEBOX))
            .after(4)
            .times(2),
    ]);
    let data = pattern(15, 0, MIB as usize);
    write_from(fs.as_mut(), &fh, &data).expect("write_stream after JUKEBOX");
    assert_eq!(srv.file("w"), data);
}

#[test]
fn server_restart_mid_transfer_completes() {
    let size = 4 * MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 16);
    let mut fs = mount(&srv, Proto::Tcp);
    srv.script(vec![
        Rule::nfs(READ, Fault::Restart(Duration::from_secs(2)))
            .after(6)
            .times(1),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 16, 0, None);
    assert_eq!(c.result.unwrap(), size);
}

/// What the client does today when the server is down for a while: a clear
/// error, never short data.
#[test]
fn server_restart_mid_transfer_is_never_silently_short() {
    let size = 2 * MIB;
    let srv = start();
    let fh = srv.add_pattern_file("f", size, 17);
    let mut fs = mount(&srv, Proto::Tcp);
    srv.script(vec![
        Rule::nfs(READ, Fault::Restart(Duration::from_millis(300)))
            .after(6)
            .times(1),
    ]);
    let c = stream_pattern(fs.as_mut(), &fh, 17, 0, Some(size));
    assert_complete_or_error(&c, size);
    // After the outage the same backend works again.
    std::thread::sleep(Duration::from_millis(400));
    let c = stream_pattern(fs.as_mut(), &fh, 17, 0, None);
    assert_eq!(c.result.unwrap(), size);
}

// --------------------------------------------- portmap (private netns)

const NETNS_ENV: &str = "NFS3FAKE_IN_NETNS";

/// Run test `name` again inside a private user + network namespace, where it
/// may bind 111 and 2049. Returns true when the caller is that inner run and
/// should do the work; false for the outer run (which checks the inner one).
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

fn portmap_opts(proto: Proto) -> ConnectOptions {
    ConnectOptions {
        rpc: rpc(proto),
        nfs_port: None,
        mount_port: None,
        version: VersionPref::Exact(NfsVersion::V3),
    }
}

#[test]
fn connect_via_portmap() {
    if !in_netns("connect_via_portmap") {
        return;
    }
    let srv = start_with(Config {
        portmap_on_111: true,
        ..Config::default()
    });
    srv.add_pattern_file("f", MIB, 18);
    for (proto, version) in [
        (Proto::Tcp, VersionPref::Exact(NfsVersion::V3)),
        (Proto::Udp, VersionPref::Exact(NfsVersion::V3)),
        (Proto::Tcp, VersionPref::Auto),
    ] {
        let mut o = portmap_opts(proto);
        o.version = version;
        let mut fs = connect(LOCALHOST, b"/export", &o)
            .unwrap_or_else(|e| panic!("connect over {proto:?}: {e}"))
            .fs;
        assert_eq!(fs.version(), NfsVersion::V3);
        let fh = lookup(fs.as_mut(), "f");
        assert_eq!(
            stream_pattern(fs.as_mut(), &fh, 18, 0, None)
                .result
                .unwrap(),
            MIB
        );
        fs.disconnect().unwrap();
    }
    let st = srv.stats();
    let asked = |prog| st.getport.iter().filter(|q| q.0 == prog).count();
    assert!(asked(NFS_PROG) >= 3, "{:?}", st.getport);
    assert!(asked(MOUNT_PROG) >= 3, "{:?}", st.getport);
}

#[test]
fn mountd_on_udp_only_with_nfs_on_tcp() {
    if !in_netns("mountd_on_udp_only_with_nfs_on_tcp") {
        return;
    }
    let srv = start_with(Config {
        portmap_on_111: true,
        register_mount_tcp: false,
        register_nfs_udp: false,
        ..Config::default()
    });
    let mut fs = connect(LOCALHOST, b"/export", &portmap_opts(Proto::Tcp))
        .expect("connect with mountd on UDP only")
        .fs;
    fs.getattr(&fs.root()).unwrap();
    fs.disconnect().unwrap();
    let st = srv.stats();
    assert_eq!(
        st.prog_over(MOUNT_PROG, Proto::Tcp),
        0,
        "MOUNT went over TCP"
    );
    assert!(st.prog_over(MOUNT_PROG, Proto::Udp) >= 2);
    assert!(st.prog_over(NFS_PROG, Proto::Tcp) >= 2);
    assert_eq!(st.prog_over(NFS_PROG, Proto::Udp), 0);
    // The client asked for TCP first and was told "not registered".
    assert!(
        st.getport
            .iter()
            .any(|&(prog, _, prot, port)| prog == MOUNT_PROG && prot == 6 && port == 0),
        "{:?}",
        st.getport
    );
}

#[test]
fn nfs_port_falls_back_to_2049_without_portmap() {
    if !in_netns("nfs_port_falls_back_to_2049_without_portmap") {
        return;
    }
    let srv = start_with(Config {
        nfs_on_2049: true,
        ..Config::default()
    });
    let mut o = portmap_opts(Proto::Tcp);
    o.mount_port = Some(srv.port);
    let mut fs = connect(LOCALHOST, b"/export", &o)
        .expect("connect with NFS on 2049 and no portmap")
        .fs;
    fs.getattr(&fs.root()).unwrap();
    assert!(srv.stats().getport.is_empty());
}
