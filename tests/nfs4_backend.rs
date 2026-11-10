//! NFSv4.0 / 4.1 / 4.2 backend against the in-process fake NFSv4 server
//! (tests/nfs4_backend/server.rs), with fault injection.
//!
//! Every test connects with the fake's port in `ConnectOptions::nfs_port`.
//! The fake checks the client's use of session slot seqids, CREATE_SESSION
//! sequence numbers and NFSv4.0 open-owner seqids; any misuse is a
//! *violation*, and dropping the server with violations fails the test.
//!
//! Connections use a short retry budget ([`fast_retry`]) and the server short
//! leases and grace periods, so the suite stays fast.

#[path = "nfs4_backend/server.rs"]
mod server;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use nfsc::error::Error;
use nfsc::fs::{
    ConnectOptions, CreateMode, FileHandle, FileType, Filesystem, NfsVersion, SetAttr, Status,
    VersionPref, connect,
};
use nfsc::rpc::{Auth, PortMode, Proto, RetryPolicy, RpcOptions};

use server::*;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// Retries with a short budget and backoff, so fault tests run fast.
fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        budget: Duration::from_secs(8),
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(400),
        ..RetryPolicy::default()
    }
}

fn opts(srv: &FakeNfs4, minor: Option<u32>) -> ConnectOptions {
    ConnectOptions {
        rpc: RpcOptions {
            proto: Proto::Tcp,
            port_mode: PortMode::Unprivileged,
            timeout: Duration::from_secs(3),
            auth: Auth::None,
            retry: fast_retry(),
        },
        nfs_port: Some(srv.port),
        mount_port: None,
        version: match minor {
            Some(m) => VersionPref::Exact(NfsVersion::V4(m)),
            None => VersionPref::AnyV4,
        },
    }
}

/// A fake with an `export` directory, which tests mount.
fn server(cfg: Config) -> FakeNfs4 {
    let srv = start_with(cfg);
    srv.with_fs(|fs| fs.add_dir("export").unwrap());
    srv
}

fn mount_opts(o: &ConnectOptions) -> Box<dyn Filesystem> {
    connect(LOCALHOST, b"/export", o)
        .unwrap_or_else(|e| panic!("connect: {e}"))
        .fs
}

fn mount(srv: &FakeNfs4, minor: u32) -> Box<dyn Filesystem> {
    mount_opts(&opts(srv, Some(minor)))
}

fn mount_budget(srv: &FakeNfs4, minor: u32, budget: Duration) -> Box<dyn Filesystem> {
    let mut o = opts(srv, Some(minor));
    o.rpc.retry.budget = budget;
    mount_opts(&o)
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

/// What a read_stream delivered, checked byte for byte against a pattern file.
struct Checked {
    result: nfsc::Result<u64>,
    /// Bytes delivered (all matched the pattern unless `bad` is set).
    delivered: u64,
    /// First offset whose byte did not match.
    bad: Option<u64>,
}

/// read_stream from a pattern file. A wrong byte stops the stream (the sink
/// fails) and is reported in [`Checked::bad`].
fn stream_pattern(
    fs: &mut dyn Filesystem,
    fh: &FileHandle,
    seed: u64,
    offset: u64,
    len: Option<u64>,
) -> Checked {
    let mut pos = offset;
    let mut bad = None;
    let result = fs.read_stream(fh, offset, len, &mut |chunk| {
        for (i, &b) in chunk.iter().enumerate() {
            let at = pos + i as u64;
            if b != pattern_byte(seed, at) {
                bad = Some(at);
                return Err(Error::Invalid(format!("wrong byte at offset {at}")));
            }
        }
        pos += chunk.len() as u64;
        Ok(())
    });
    Checked {
        result,
        delivered: pos - offset,
        bad,
    }
}

/// The stream delivered exactly `want` correct bytes and succeeded.
fn assert_complete(c: &Checked, want: u64) {
    assert_eq!(c.bad, None, "wrong data delivered (result {:?})", c.result);
    match &c.result {
        Ok(n) => assert_eq!(*n, want, "read_stream returned a short count"),
        Err(e) => panic!("read_stream failed after {} bytes: {e}", c.delivered),
    }
    assert_eq!(c.delivered, want);
}

/// Bytes from `data` to `write_stream` at `offset`, in odd-sized pieces.
fn write_from(
    fs: &mut dyn Filesystem,
    fh: &FileHandle,
    offset: u64,
    data: &[u8],
) -> nfsc::Result<u64> {
    let mut at = 0usize;
    fs.write_stream(fh, offset, &mut |buf| {
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

fn assert_clean(srv: &FakeNfs4) {
    let v = srv.violations();
    assert!(
        v.is_empty(),
        "client protocol violations:\n{}",
        v.join("\n")
    );
}

/// A server with a pattern file `export/big.bin` of `size` bytes (seed 7),
/// mounted with `minor`; returns the server, the backend and the handle.
fn with_big(cfg: Config, minor: u32, size: u64) -> (FakeNfs4, Box<dyn Filesystem>, FileHandle) {
    let srv = server(cfg);
    srv.add_pattern_file("export/big.bin", size, 7);
    let mut fs = mount(&srv, minor);
    let fh = lookup(fs.as_mut(), "big.bin");
    (srv, fs, fh)
}

/// Read all of `export/big.bin` under the given fault script and check it.
fn read_under(minor: u32, rules: Vec<Rule>) -> FakeNfs4 {
    let size = 4 * MIB + 4321;
    let (srv, mut fs, fh) = with_big(Config::default(), minor, size);
    srv.script(rules);
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_complete(&c, size);
    assert_clean(&srv);
    drop(fs);
    srv
}

// ------------------------------------------------------------ negotiation

#[test]
fn negotiates_highest_offered_minor_version() {
    for (minors, want) in [(vec![0, 1, 2], 2), (vec![0, 1], 1), (vec![0], 0)] {
        let srv = server(Config {
            minors: minors.clone(),
            ..Config::default()
        });
        let c = connect(LOCALHOST, b"/export", &opts(&srv, None)).expect("connect");
        assert_eq!(
            c.fs.version(),
            NfsVersion::V4(want),
            "server offers {minors:?}"
        );
        assert_eq!(c.export, b"/export");
        let st = srv.stats();
        for m in want + 1..=2 {
            assert_eq!(
                st.by_minor.get(&m),
                Some(&1),
                "minor {m} should be tried exactly once"
            );
        }
        if want >= 1 {
            assert_eq!(st.op(OP_EXCHANGE_ID), 1);
            assert_eq!(st.op(OP_SETCLIENTID), 0);
        } else {
            assert_eq!(st.op(OP_SETCLIENTID), 1);
            assert_eq!(st.op(OP_SETCLIENTID_CONFIRM), 1);
        }
    }
}

#[test]
fn exact_minor_that_is_not_offered_is_version_unsupported() {
    let srv = server(Config {
        minors: vec![0, 1],
        ..Config::default()
    });
    match connect(LOCALHOST, b"/export", &opts(&srv, Some(2))) {
        Err(e) => assert!(e.is_version_unsupported(), "{e}"),
        Ok(_) => panic!("connected with a minor version the server refuses"),
    }
}

// ------------------------------------------------------------ basic paths

fn basic(minor: u32) {
    let srv = server(Config::default());
    let size = 6 * MIB + 12345;
    srv.add_pattern_file("export/data/big.bin", size, 7);
    srv.with_fs(|fs| {
        fs.add_file("export/hello.txt", b"hello world").unwrap();
        fs.add_dir("export/empty").unwrap();
        fs.add_symlink("export/link", "hello.txt").unwrap();
    });
    let mut fs = mount(&srv, minor);
    assert_eq!(fs.version(), NfsVersion::V4(minor));
    assert_eq!((fs.max_read(), fs.max_write()), (256 << 10, 256 << 10));

    let root = fs.root();
    let ents = fs.readdir(&root).expect("readdir");
    assert_eq!(
        sorted_names(&ents),
        vec![
            b"data".to_vec(),
            b"empty".to_vec(),
            b"hello.txt".to_vec(),
            b"link".to_vec()
        ]
    );
    for e in &ents {
        assert!(
            e.handle.is_some() && e.attr.is_some(),
            "entry without attrs"
        );
    }
    let (hello, a) = fs.lookup(&root, b"hello.txt").expect("lookup");
    assert_eq!((a.ftype, a.size), (FileType::Regular, 11));
    assert_eq!(fs.getattr(&hello).unwrap().size, 11);
    let link = lookup(fs.as_mut(), "link");
    assert_eq!(fs.readlink(&link).unwrap(), b"hello.txt");
    match fs.lookup(&root, b"missing") {
        Err(Error::Nfs(Status::NoEnt)) => {}
        other => panic!("lookup of a missing name: {other:?}"),
    }
    let empty = lookup(fs.as_mut(), "empty");
    assert!(fs.readdir(&empty).unwrap().is_empty());
    assert_eq!(read_all(fs.as_mut(), &hello), b"hello world");

    srv.reset_stats();
    let big = lookup(fs.as_mut(), "data/big.bin");
    assert_eq!(fs.getattr(&big).unwrap().size, size);
    let c = stream_pattern(fs.as_mut(), &big, 7, 0, None);
    assert_complete(&c, size);
    let st = srv.stats();
    assert!(st.op(OP_READ) >= size.div_ceil(256 << 10) as usize);
    assert_eq!(st.max_read_count, 256 << 10);
    assert_eq!(st.op(OP_OPEN), 1, "one OPEN for the stream");
    assert_eq!(st.anon_io, 0, "reads used the open stateid");
    if minor == 0 {
        // The open-owner was confirmed by the OPEN for hello.txt.
        assert_eq!(st.op(OP_OPEN_CONFIRM), 0);
    }
    // A ranged read in the middle, then the tail.
    let c = stream_pattern(fs.as_mut(), &big, 7, 3 * MIB + 17, Some(MIB + 3));
    assert_complete(&c, MIB + 3);
    let c = stream_pattern(fs.as_mut(), &big, 7, size - 1000, Some(5000));
    assert_complete(&c, 1000);
    drop(fs);
    assert_eq!(srv.opens(), 0, "disconnect closes the opens");
}

#[test]
fn basic_v40() {
    basic(0);
}

#[test]
fn basic_v41() {
    basic(1);
}

#[test]
fn basic_v42() {
    basic(2);
}

fn data_bytes(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn write_commit(minor: u32) {
    let srv = server(Config::default());
    let mut fs = mount(&srv, minor);
    let root = fs.root();
    let (fh, _) = fs
        .create(
            &root,
            b"out.bin",
            CreateMode::Unchecked,
            &SetAttr::default(),
        )
        .expect("create");
    srv.reset_stats();
    let data = data_bytes((5 * MIB + 777) as usize, 3);
    let n = write_from(fs.as_mut(), &fh, 0, &data).expect("write_stream");
    assert_eq!(n, data.len() as u64);
    assert!(srv.file("export/out.bin") == data, "file content differs");
    assert_eq!(srv.uncommitted(), 0, "everything committed");
    let st = srv.stats();
    assert!(st.op(OP_COMMIT) >= 1);
    assert!(st.unstable_writes >= data.len().div_ceil(256 << 10));
    assert_eq!(st.max_write_len, 256 << 10);
    assert_eq!(st.anon_io, 0, "writes used the open stateid");
    assert_eq!(st.op(OP_OPEN), 0, "create's open was reused");
    assert_eq!(fs.getattr(&fh).unwrap().size, data.len() as u64);
    // Plain write, read back through the backend.
    assert_eq!(fs.write(&fh, 10, b"0123456789").unwrap(), 10);
    let back = read_all(fs.as_mut(), &fh);
    assert_eq!(&back[10..20], b"0123456789");
    assert_eq!(back.len(), data.len());
}

#[test]
fn write_stream_commit_v40() {
    write_commit(0);
}

#[test]
fn write_stream_commit_v41() {
    write_commit(1);
}

#[test]
fn write_stream_commit_v42() {
    write_commit(2);
}

fn beyond_4gib(minor: u32) {
    let size = 5 * GIB + 3;
    let (srv, mut fs, fh) = with_big(Config::default(), minor, size);
    assert_eq!(fs.getattr(&fh).unwrap().size, size);
    let c = stream_pattern(fs.as_mut(), &fh, 7, 4 * GIB - 100_000, Some(3 * MIB));
    assert_complete(&c, 3 * MIB);
    let (data, eof) = fs.read(&fh, 4 * GIB - 10, 100).expect("read");
    assert_eq!(data, pattern(7, 4 * GIB - 10, 100));
    assert!(!eof);
    let c = stream_pattern(fs.as_mut(), &fh, 7, size - 1000, None);
    assert_complete(&c, 1000);

    srv.with_fs(|f| f.add_sparse_file("export/sparse.bin", 6 * GIB, 0).unwrap());
    let sp = lookup(fs.as_mut(), "sparse.bin");
    let data = data_bytes(MIB as usize + 5, 9);
    let at = 4 * GIB + 512 * MIB + 5;
    assert_eq!(
        write_from(fs.as_mut(), &sp, at, &data).unwrap(),
        data.len() as u64
    );
    assert!(srv.read_at("export/sparse.bin", at, data.len() as u32) == data);
    assert_eq!(srv.uncommitted(), 0);
}

#[test]
fn offsets_beyond_4gib_v40() {
    beyond_4gib(0);
}

#[test]
fn offsets_beyond_4gib_v41() {
    beyond_4gib(1);
}

// --------------------------------------------------------- DELAY / GRACE

fn delay_on_read(minor: u32) {
    let srv = read_under(
        minor,
        vec![
            Rule::op(OP_READ, Fault::Status(NFS4ERR_DELAY))
                .after(3)
                .times(4),
        ],
    );
    assert_eq!(srv.stats().error(OP_READ, NFS4ERR_DELAY), 4);
}

#[test]
fn delay_on_read_completes_v40() {
    delay_on_read(0);
}

#[test]
fn delay_on_read_completes_v41() {
    delay_on_read(1);
}

fn delay_on_open(minor: u32) {
    let srv = read_under(
        minor,
        vec![Rule::op(OP_OPEN, Fault::Status(NFS4ERR_DELAY)).times(3)],
    );
    let st = srv.stats();
    assert_eq!(st.error(OP_OPEN, NFS4ERR_DELAY), 3);
    assert_eq!(st.anon_io, 0, "the OPEN was retried, not abandoned");
}

#[test]
fn delay_on_open_completes_v40() {
    delay_on_open(0);
}

#[test]
fn delay_on_open_completes_v41() {
    delay_on_open(1);
}

#[test]
fn grace_on_open_outside_a_reboot_is_retried() {
    for minor in [0, 1] {
        let srv = read_under(
            minor,
            vec![Rule::op(OP_OPEN, Fault::Status(NFS4ERR_GRACE)).times(2)],
        );
        assert_eq!(srv.stats().anon_io, 0, "minor {minor}");
    }
}

fn reboot_mid_read(minor: u32) {
    let size = 4 * MIB + 99;
    let (srv, mut fs, fh) = with_big(Config::default(), minor, size);
    let grace = Duration::from_millis(1200);
    srv.script(vec![
        Rule::op(
            OP_READ,
            Fault::Reboot {
                down: Duration::from_millis(200),
                grace,
            },
        )
        .after(5)
        .times(1),
    ]);
    let t = Instant::now();
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_complete(&c, size);
    assert!(
        t.elapsed() >= grace,
        "read finished inside the grace period"
    );
    let st = srv.stats();
    assert!(st.status(NFS4ERR_GRACE) > 0, "grace period not exercised");
    if minor == 0 {
        assert_eq!(st.op(OP_SETCLIENTID_CONFIRM), 2, "client ID re-established");
    } else {
        assert_eq!(st.op(OP_EXCHANGE_ID), 2, "client ID re-established");
    }
    assert_clean(&srv);
}

#[test]
fn reboot_mid_read_waits_out_grace_v40() {
    reboot_mid_read(0);
}

#[test]
fn reboot_mid_read_waits_out_grace_v41() {
    reboot_mid_read(1);
}

#[test]
fn reboot_mid_read_waits_out_grace_v42() {
    reboot_mid_read(2);
}

#[test]
fn reboot_mid_write_resends_lost_unstable_data() {
    for minor in [0, 1] {
        let srv = server(Config::default());
        let mut fs = mount(&srv, minor);
        let root = fs.root();
        let (fh, _) = fs
            .create(
                &root,
                b"out.bin",
                CreateMode::Unchecked,
                &SetAttr::default(),
            )
            .expect("create");
        srv.script(vec![
            Rule::op(
                OP_WRITE,
                Fault::Reboot {
                    down: Duration::from_millis(100),
                    grace: Duration::from_millis(500),
                },
            )
            .after(6)
            .times(1),
        ]);
        let data = data_bytes((3 * MIB + 5) as usize, minor + 1);
        assert_eq!(
            write_from(fs.as_mut(), &fh, 0, &data).expect("write_stream"),
            data.len() as u64
        );
        assert!(
            srv.file("export/out.bin") == data,
            "minor {minor}: data lost"
        );
        assert_clean(&srv);
    }
}

// ------------------------------------------------- session / client faults

fn badsession_mid_transfer(minor: u32) {
    let srv = read_under(
        minor,
        vec![Rule::op(OP_READ, Fault::KillSession).after(5).times(1)],
    );
    let st = srv.stats();
    assert!(st.error(OP_SEQUENCE, NFS4ERR_BADSESSION) >= 1);
    assert_eq!(st.op(OP_EXCHANGE_ID), 1, "client ID kept");
    assert_eq!(st.op(OP_CREATE_SESSION), 2, "one new session");
    assert_eq!(st.op(OP_OPEN), 1, "open state kept");
    assert_eq!(st.anon_io, 0);
}

#[test]
fn badsession_mid_transfer_keeps_client_and_opens_v41() {
    badsession_mid_transfer(1);
}

#[test]
fn badsession_mid_transfer_keeps_client_and_opens_v42() {
    badsession_mid_transfer(2);
}

/// From the sixth READ COMPOUND on, fail the SEQUENCE of every READ with
/// `code` until the client sends a COMPOUND for which `until` holds: the
/// server really lost the state, so a blocking retry on the same session
/// fails too.
fn sequence_fault_until(srv: &FakeNfs4, code: u32, until: impl Fn(&Call) -> bool + Send + 'static) {
    let reads = AtomicUsize::new(0);
    let done = std::sync::atomic::AtomicBool::new(false);
    srv.set_hook(move |c| {
        if until(c) {
            done.store(true, Ordering::SeqCst);
        }
        if done.load(Ordering::SeqCst) || !c.has(OP_READ) {
            return None;
        }
        if reads.fetch_add(1, Ordering::SeqCst) < 5 {
            return None;
        }
        Some(Fault::Status(code))
    });
}

/// [`read_under`] with [`sequence_fault_until`].
fn read_under_sequence_fault(
    code: u32,
    until: impl Fn(&Call) -> bool + Send + 'static,
) -> FakeNfs4 {
    let size = 4 * MIB + 4321;
    let (srv, mut fs, fh) = with_big(Config::default(), 1, size);
    sequence_fault_until(&srv, code, until);
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_complete(&c, size);
    assert_clean(&srv);
    assert!(
        srv.stats().error(OP_SEQUENCE, code) >= 1,
        "status {code} never sent"
    );
    drop(fs);
    srv
}

#[test]
fn deadsession_mid_transfer_gets_a_new_session_v41() {
    let srv = read_under_sequence_fault(NFS4ERR_DEADSESSION, |c| c.has(OP_CREATE_SESSION));
    let st = srv.stats();
    assert_eq!(st.op(OP_EXCHANGE_ID), 1);
    assert_eq!(st.op(OP_CREATE_SESSION), 2);
    assert_eq!(st.op(OP_OPEN), 1);
}

#[test]
fn sequence_errors_mid_read_recover_fully_v41() {
    for code in [NFS4ERR_STALE_CLIENTID, NFS4ERR_BADSLOT] {
        let srv = read_under_sequence_fault(code, |c| c.has(OP_EXCHANGE_ID));
        assert_eq!(srv.stats().op(OP_EXCHANGE_ID), 2, "status {code}");
    }
}

/// SEQ_MISORDERED leaves the slot's seqid unknown: the client probes the slot
/// with SEQUENCE-only COMPOUNDs (RFC 8881 2.10.6.1) and keeps its client ID,
/// session and opens.
#[test]
fn seq_misordered_mid_read_resyncs_the_slot_v41() {
    let srv = read_under_sequence_fault(NFS4ERR_SEQ_MISORDERED, |c| c.ops == [OP_SEQUENCE]);
    let st = srv.stats();
    assert_eq!(st.op(OP_EXCHANGE_ID), 1, "client ID kept");
    assert_eq!(st.op(OP_OPEN), 1, "open state kept");
    assert_eq!(st.anon_io, 0);
}

fn expired_lease(minor: u32) {
    let srv = read_under(
        minor,
        vec![Rule::op(OP_READ, Fault::ExpireLease).after(5).times(1)],
    );
    let st = srv.stats();
    if minor == 0 {
        assert_eq!(st.op(OP_SETCLIENTID_CONFIRM), 2);
    } else {
        assert_eq!(st.op(OP_EXCHANGE_ID), 2);
    }
}

#[test]
fn expired_lease_mid_read_recovers_v40() {
    expired_lease(0);
}

#[test]
fn expired_lease_mid_read_recovers_v41() {
    expired_lease(1);
}

fn stateid_errors_on_read(minor: u32) {
    let mut codes = vec![
        NFS4ERR_BAD_STATEID,
        NFS4ERR_OLD_STATEID,
        NFS4ERR_ADMIN_REVOKED,
    ];
    if minor == 0 {
        codes.push(NFS4ERR_STALE_STATEID);
    }
    for code in codes {
        read_under(
            minor,
            vec![Rule::op(OP_READ, Fault::Status(code)).after(3).times(1)],
        );
    }
}

#[test]
fn stateid_errors_on_read_recover_v40() {
    stateid_errors_on_read(0);
}

#[test]
fn stateid_errors_on_read_recover_v41() {
    stateid_errors_on_read(1);
}

#[test]
fn transient_server_errors_on_read_recover() {
    for minor in [0, 1] {
        for code in [NFS4ERR_SERVERFAULT, NFS4ERR_RESOURCE] {
            read_under(
                minor,
                vec![Rule::op(OP_READ, Fault::Status(code)).after(4).times(1)],
            );
        }
    }
}

#[test]
fn persistent_serverfault_is_a_clear_error_not_short_data() {
    for minor in [0, 1] {
        let size = 2 * MIB + 1;
        let (srv, mut fs, fh) = with_big(Config::default(), minor, size);
        srv.script(vec![
            Rule::op(OP_READ, Fault::Status(NFS4ERR_SERVERFAULT)).after(3),
        ]);
        let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
        assert_eq!(c.bad, None);
        match c.result {
            Err(Error::Nfs(Status::ServerFault)) => {}
            other => panic!("minor {minor}: expected SERVERFAULT, got {other:?}"),
        }
        assert!(c.delivered < size);
        srv.clear_faults();
    }
}

#[test]
fn short_reads_are_refetched() {
    for minor in [0, 1] {
        read_under(
            minor,
            vec![Rule::op(OP_READ, Fault::ShortRead(1000)).after(2).times(5)],
        );
    }
}

// ---------------------------------------------------------- NFSv4.0 state

#[test]
fn open_confirm_once_per_open_owner_v40() {
    let srv = server(Config::default());
    srv.add_pattern_file("export/a.bin", 300 * KIB, 1);
    srv.add_pattern_file("export/b.bin", 300 * KIB, 2);
    let mut fs = mount(&srv, 0);
    let a = lookup(fs.as_mut(), "a.bin");
    let b = lookup(fs.as_mut(), "b.bin");
    assert_complete(&stream_pattern(fs.as_mut(), &a, 1, 0, None), 300 * KIB);
    let st = srv.stats();
    assert_eq!((st.op(OP_OPEN), st.op(OP_OPEN_CONFIRM)), (1, 1));
    assert_complete(&stream_pattern(fs.as_mut(), &b, 2, 0, None), 300 * KIB);
    let st = srv.stats();
    assert_eq!(
        (st.op(OP_OPEN), st.op(OP_OPEN_CONFIRM)),
        (2, 1),
        "a confirmed open-owner needs no second OPEN_CONFIRM"
    );
    assert_eq!(st.anon_io, 0, "reads used confirmed stateids");
    assert_eq!(srv.opens(), 2);
    drop(fs);
    assert_eq!(srv.opens(), 0);
}

#[test]
fn open_owner_seqid_not_advanced_on_excluded_errors_v40() {
    let srv = server(Config::default());
    for (i, name) in ["a", "b", "c", "d", "e", "f", "g"].iter().enumerate() {
        srv.add_pattern_file(&format!("export/{name}"), 100 * KIB, i as u64);
    }
    let mut fs = mount(&srv, 0);
    let read = |fs: &mut dyn Filesystem, name: &str, seed: u64| {
        let fh = lookup(fs, name);
        assert_complete(&stream_pattern(fs, &fh, seed, 0, None), 100 * KIB);
    };
    read(fs.as_mut(), "a", 0);
    // RESOURCE does not advance the seqid (RFC 7530 9.1.7): the client must
    // reuse it, or the server sees a gap.
    srv.script(vec![
        Rule::op(OP_OPEN, Fault::Status(NFS4ERR_RESOURCE)).times(1),
    ]);
    read(fs.as_mut(), "b", 1);
    read(fs.as_mut(), "c", 2);
    // ACCESS does advance it.
    srv.script(vec![
        Rule::op(OP_OPEN, Fault::Status(NFS4ERR_ACCESS)).times(1),
    ]);
    read(fs.as_mut(), "d", 3);
    read(fs.as_mut(), "e", 4);
    // CLOSE failing with RESOURCE (remove closes the open first).
    srv.script(vec![
        Rule::op(OP_CLOSE, Fault::Status(NFS4ERR_RESOURCE)).times(1),
    ]);
    let root = fs.root();
    fs.remove(&root, b"e").expect("remove");
    read(fs.as_mut(), "f", 5);
    // OPEN_CONFIRM is not involved again: the owner stays confirmed.
    srv.script(vec![
        Rule::op(OP_OPEN, Fault::Status(NFS4ERR_NOFILEHANDLE)).times(1),
    ]);
    read(fs.as_mut(), "g", 6);
    let st = srv.stats();
    assert_eq!(st.op(OP_OPEN_CONFIRM), 1);
    assert_eq!(st.owner_replays, 0);
    assert_clean(&srv);
}

#[test]
fn bad_seqid_switches_to_a_new_open_owner_v40() {
    let srv = server(Config::default());
    srv.add_pattern_file("export/a", 100 * KIB, 1);
    srv.add_pattern_file("export/b", 100 * KIB, 2);
    let mut fs = mount(&srv, 0);
    let a = lookup(fs.as_mut(), "a");
    assert_complete(&stream_pattern(fs.as_mut(), &a, 1, 0, None), 100 * KIB);
    srv.script(vec![
        Rule::op(OP_OPEN, Fault::Status(NFS4ERR_BAD_SEQID)).times(1),
    ]);
    let b = lookup(fs.as_mut(), "b");
    assert_complete(&stream_pattern(fs.as_mut(), &b, 2, 0, None), 100 * KIB);
    let st = srv.stats();
    assert_eq!(st.op(OP_OPEN), 3, "OPEN retried once with the new owner");
    assert_eq!(st.op(OP_OPEN_CONFIRM), 2, "the new owner is confirmed");
    assert_eq!(st.anon_io, 0);
}

#[test]
fn renew_keeps_the_lease_alive_while_idle_v40() {
    let size = 600 * KIB;
    let (srv, mut fs, fh) = with_big(
        Config {
            lease_secs: 2,
            ..Config::default()
        },
        0,
        size,
    );
    assert_complete(&stream_pattern(fs.as_mut(), &fh, 7, 0, None), size);
    // Idle for well over a lease, with only lease-neutral GETATTRs; the
    // client must RENEW in time.
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(4500) {
        std::thread::sleep(Duration::from_millis(600));
        fs.getattr(&fh).expect("getattr");
    }
    assert_complete(&stream_pattern(fs.as_mut(), &fh, 7, 0, None), size);
    let st = srv.stats();
    assert!(st.op(OP_RENEW) >= 2, "RENEW sent {} times", st.op(OP_RENEW));
    assert_eq!(st.status(NFS4ERR_EXPIRED), 0, "lease expired");
    assert_eq!(st.op(OP_SETCLIENTID), 1, "no recovery needed");
    assert_eq!(st.op(OP_OPEN), 1, "the open survived the idle time");
    assert_eq!(st.anon_io, 0);
}

#[test]
fn sequence_keeps_the_lease_alive_while_idle_v41() {
    let size = 600 * KIB;
    let (srv, mut fs, fh) = with_big(
        Config {
            lease_secs: 2,
            ..Config::default()
        },
        1,
        size,
    );
    assert_complete(&stream_pattern(fs.as_mut(), &fh, 7, 0, None), size);
    std::thread::sleep(Duration::from_millis(1500));
    fs.getattr(&fh).expect("getattr");
    std::thread::sleep(Duration::from_millis(1500));
    assert_complete(&stream_pattern(fs.as_mut(), &fh, 7, 0, None), size);
    let st = srv.stats();
    assert_eq!(st.op(OP_EXCHANGE_ID), 1, "no recovery needed");
    assert_eq!(st.op(OP_OPEN), 1);
}

// ----------------------------------------------------- connection failures

/// Every 7th READ loses its reply (the server executes it and closes the
/// connection), four times in one stream. With `truncate`, every other one
/// is cut off mid-record instead.
fn repeated_drops(minor: u32, truncate: bool) {
    let size = 6 * MIB + 7;
    let (srv, mut fs, fh) = with_big(Config::default(), minor, size);
    let reads = Arc::new(AtomicUsize::new(0));
    let fired = Arc::new(AtomicUsize::new(0));
    let (r, f) = (Arc::clone(&reads), Arc::clone(&fired));
    srv.set_hook(move |c| {
        if !c.has(OP_READ) {
            return None;
        }
        let n = r.fetch_add(1, Ordering::SeqCst) + 1;
        if n % 7 == 0 && f.load(Ordering::SeqCst) < 4 {
            f.fetch_add(1, Ordering::SeqCst);
            return Some(if truncate && n % 14 == 0 {
                Fault::Truncate(60)
            } else {
                Fault::DropReply
            });
        }
        None
    });
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_eq!(c.bad, None, "wrong data");
    match &c.result {
        Ok(n) => assert_eq!(*n, size, "silently short read"),
        Err(e) => panic!("read_stream failed after {} bytes: {e}", c.delivered),
    }
    assert_eq!(fired.load(Ordering::SeqCst), 4);
    assert_clean(&srv);
}

#[test]
fn connection_drops_during_read_stream_v40() {
    repeated_drops(0, false);
}

#[test]
fn truncated_replies_during_read_stream_v40() {
    repeated_drops(0, true);
}

#[test]
fn connection_drops_during_read_stream_v41() {
    repeated_drops(1, false);
}

#[test]
fn truncated_replies_during_read_stream_v41() {
    repeated_drops(1, true);
}

fn lost_read_reply(cfg: Config) {
    let size = 4 * MIB + 11;
    let (srv, mut fs, fh) = with_big(cfg, 1, size);
    srv.script(vec![Rule::op(OP_READ, Fault::DropReply).after(5).times(1)]);
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_complete(&c, size);
    assert_clean(&srv);
}

fn lost_write_reply(cfg: Config) {
    let srv = server(cfg);
    let mut fs = mount(&srv, 1);
    let root = fs.root();
    let (fh, _) = fs
        .create(
            &root,
            b"out.bin",
            CreateMode::Unchecked,
            &SetAttr::default(),
        )
        .expect("create");
    srv.script(vec![Rule::op(OP_WRITE, Fault::DropReply).after(5).times(1)]);
    let data = data_bytes((10 * MIB + 3) as usize, 11);
    let r = write_from(fs.as_mut(), &fh, 0, &data);
    assert_eq!(r.expect("write_stream"), data.len() as u64);
    assert!(srv.file("export/out.bin") == data, "file content differs");
    assert_clean(&srv);
}

/// knfsd: a replayed slot seqid without cachethis gets RETRY_UNCACHED_REP.
#[test]
fn lost_read_reply_mid_window_v41() {
    lost_read_reply(Config::default());
}

#[test]
fn lost_write_reply_mid_window_v41() {
    lost_write_reply(Config::default());
}

/// A fully caching server answers the reused slot seqid with the cached
/// reply of a different request: wrong data at another offset.
#[test]
fn lost_read_reply_mid_window_caching_server_v41() {
    lost_read_reply(Config {
        cache_all_replies: true,
        ..Config::default()
    });
}

#[test]
fn lost_write_reply_mid_window_caching_server_v41() {
    lost_write_reply(Config {
        cache_all_replies: true,
        ..Config::default()
    });
}

/// A lost reply, and then the reply to the client's own slot probe is lost
/// too (the server ran the probe): the client must learn the slot's seqid
/// again before reusing it, or a real request would get the probe's cached
/// SEQUENCE-only reply back.
fn lost_reply_then_lost_probe(cfg: Config, write: bool) {
    let probe_lost = Rule::op(OP_SEQUENCE, Fault::DropReply)
        .when(|c| c.ops == [OP_SEQUENCE])
        .times(1);
    if write {
        let srv = server(cfg);
        let mut fs = mount(&srv, 1);
        let root = fs.root();
        let (fh, _) = fs
            .create(
                &root,
                b"out.bin",
                CreateMode::Unchecked,
                &SetAttr::default(),
            )
            .expect("create");
        srv.script(vec![
            Rule::op(OP_WRITE, Fault::DropReply).after(5).times(1),
            probe_lost,
        ]);
        let data = data_bytes((10 * MIB + 3) as usize, 13);
        let r = write_from(fs.as_mut(), &fh, 0, &data);
        assert_eq!(r.expect("write_stream"), data.len() as u64);
        assert!(srv.file("export/out.bin") == data, "file content differs");
        assert_clean(&srv);
    } else {
        let size = 4 * MIB + 11;
        let (srv, mut fs, fh) = with_big(cfg, 1, size);
        srv.script(vec![
            Rule::op(OP_READ, Fault::DropReply).after(5).times(1),
            probe_lost,
        ]);
        let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
        assert_complete(&c, size);
        assert_clean(&srv);
    }
}

#[test]
fn lost_probe_reply_read_caching_server_v41() {
    lost_reply_then_lost_probe(
        Config {
            cache_all_replies: true,
            ..Config::default()
        },
        false,
    );
}

#[test]
fn lost_probe_reply_write_caching_server_v41() {
    lost_reply_then_lost_probe(
        Config {
            cache_all_replies: true,
            ..Config::default()
        },
        true,
    );
}

#[test]
fn lost_probe_reply_write_v41() {
    lost_reply_then_lost_probe(Config::default(), true);
}

fn server_down_mid_transfer(minor: u32) {
    let size = 4 * MIB + 5;
    let (srv, mut fs, fh) = with_big(Config::default(), minor, size);
    let down = Duration::from_secs(2);
    srv.script(vec![
        Rule::op(OP_READ, Fault::Restart(down)).after(6).times(1),
    ]);
    let t = Instant::now();
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_complete(&c, size);
    assert!(t.elapsed() >= down);
    assert_clean(&srv);
}

#[test]
fn server_down_2s_mid_transfer_completes_v40() {
    server_down_mid_transfer(0);
}

#[test]
fn server_down_2s_mid_transfer_completes_v41() {
    server_down_mid_transfer(1);
}

fn gives_up(minor: u32, fault: Fault) {
    let size = 2 * MIB;
    let srv = server(Config::default());
    srv.add_pattern_file("export/big.bin", size, 7);
    let budget = Duration::from_millis(800);
    let mut fs = mount_budget(&srv, minor, budget);
    let fh = lookup(fs.as_mut(), "big.bin");
    srv.script(vec![Rule::op(OP_READ, fault).after(3)]);
    let t = Instant::now();
    let c = stream_pattern(fs.as_mut(), &fh, 7, 0, None);
    assert_eq!(c.bad, None);
    match &c.result {
        Err(Error::GaveUp { .. }) => {}
        other => panic!("minor {minor}: expected GaveUp, got {other:?}"),
    }
    assert!(c.delivered < size);
    assert!(
        t.elapsed() < budget * 2 + Duration::from_secs(4),
        "gave up after {:?}",
        t.elapsed()
    );
    srv.clear_faults();
}

#[test]
fn retry_budget_exhausted_gives_up_server_down() {
    for minor in [0, 1] {
        gives_up(minor, Fault::Restart(Duration::from_secs(10)));
    }
}

#[test]
fn retry_budget_exhausted_gives_up_endless_delay() {
    for minor in [0, 1] {
        gives_up(minor, Fault::Status(NFS4ERR_DELAY));
    }
}

// -------------------------------------------------------------- directories

fn huge_directory(minor: u32) {
    let srv = server(Config::default());
    let n = 20_000;
    srv.with_fs(|fs| {
        fs.add_dir("export/many").unwrap();
        for i in 0..n {
            fs.add_file(&format!("export/many/file-{i:05}"), b"x")
                .unwrap();
        }
    });
    let mut fs = mount(&srv, minor);
    let dir = lookup(fs.as_mut(), "many");
    srv.reset_stats();
    let ents = fs.readdir(&dir).expect("readdir");
    let names = sorted_names(&ents);
    let want: Vec<Vec<u8>> = (0..n)
        .map(|i| format!("file-{i:05}").into_bytes())
        .collect();
    assert_eq!(names.len(), n, "entry count");
    assert!(names == want, "names differ");
    assert!(
        ents.iter()
            .all(|e| e.attr.as_ref().is_some_and(|a| a.size == 1))
    );
    let st = srv.stats();
    assert!(st.readdir_pages >= 20, "{} pages", st.readdir_pages);
    assert_eq!(st.op(OP_READDIR), st.readdir_pages);
    assert!(st.readdir_max_entries < n);
}

#[test]
fn huge_directory_pages_by_maxcount_v40() {
    huge_directory(0);
}

#[test]
fn huge_directory_pages_by_maxcount_v41() {
    huge_directory(1);
}

#[test]
fn bad_cookie_restarts_the_listing() {
    for minor in [0, 1] {
        let srv = server(Config::default());
        let n = 3000;
        srv.with_fs(|fs| {
            fs.add_dir("export/d").unwrap();
            for i in 0..n {
                fs.add_file(&format!("export/d/f{i}"), b"").unwrap();
            }
        });
        let mut fs = mount(&srv, minor);
        let dir = lookup(fs.as_mut(), "d");
        srv.reset_stats();
        srv.script(vec![
            Rule::op(OP_READDIR, Fault::Status(NFS4ERR_BAD_COOKIE))
                .when(|c| c.cookie != 0)
                .after(3)
                .times(1),
        ]);
        let ents = fs.readdir(&dir).expect("readdir");
        assert_eq!(ents.len(), n, "minor {minor}: duplicates or gaps");
        let mut names = sorted_names(&ents);
        names.dedup();
        assert_eq!(names.len(), n);
        let st = srv.stats();
        assert_eq!(st.error(OP_READDIR, NFS4ERR_BAD_COOKIE), 1);
        assert!(st.op(OP_READDIR) > st.readdir_pages, "listing restarted");
    }
}

// ------------------------------------------------------------------- slots

#[test]
fn pipelining_respects_the_granted_slot_count_v41() {
    for slots in [1, 2, 5] {
        let size = 3 * MIB;
        let (srv, mut fs, fh) = with_big(
            Config {
                slots,
                ..Config::default()
            },
            1,
            size,
        );
        assert_complete(&stream_pattern(fs.as_mut(), &fh, 7, 0, None), size);
        let st = srv.stats();
        assert!(st.max_slot < slots, "slot {} of {slots}", st.max_slot);
        assert_eq!(st.slot_replays, 0);
        assert_clean(&srv);
    }
}
