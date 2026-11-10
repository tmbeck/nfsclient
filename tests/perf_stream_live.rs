//! Live tests and timing benchmarks for pipelined bulk transfers
//! (`Filesystem::read_stream` / `write_stream`). Targets come only from
//! environment variables; without them every test is skipped.
//!
//!   NFSC_TEST_RW_GANESHA=host:/export/rw   read-write export; tests create and
//!   NFSC_TEST_RW_KNFSD=host:/export/rw    remove a `nfsc-perf-<random>` directory
//!   NFSC_TEST_RO_GANESHA=host:/export/ro   read-only export (read tests only)
//!
//! Read-only benchmark against any export (writes nothing; use for NAS targets):
//!   NFSC_PERF_RO_FILE=host:/export/path/to/file
//!   NFSC_PERF_RO_VERS=3,4.2                 versions to try (default 3,4.0,4.1,4.2)
//!   NFSC_PERF_RO_MIB=2048                   bytes read per run (default 2048)
//!
//! The benchmarks are `#[ignore]`d. Run with
//!   cargo test --release --test perf_stream_live -- --ignored --nocapture
//! and NFSC_PERF_MIB (default 512) sets the size of the read-write benchmark file.

use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, ToSocketAddrs};
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::time::Instant;

use nfsc::error::{Error, Result};
use nfsc::fs::{
    connect, ConnectOptions, CreateMode, FileHandle, Filesystem, NfsVersion, SetAttr, VersionPref,
};
use nfsc::rpc::{Auth, RpcOptions};

const RW_KEYS: [(&str, &str); 2] = [
    ("ganesha", "NFSC_TEST_RW_GANESHA"),
    ("knfsd", "NFSC_TEST_RW_KNFSD"),
];

/// A host and export path from `NFSC_*=host:/path`.
fn parse_target(v: &str) -> Option<(IpAddr, Vec<u8>, String)> {
    let (host, path) = v.split_once(':')?;
    let ip = (host, 2049).to_socket_addrs().ok()?.next()?.ip();
    Some((ip, path.as_bytes().to_vec(), host.to_string()))
}

fn rw_targets() -> Vec<(&'static str, IpAddr, Vec<u8>)> {
    RW_KEYS
        .iter()
        .filter_map(|(name, key)| {
            let v = std::env::var(key).ok()?;
            let (ip, path, _) = parse_target(&v)?;
            Some((*name, ip, path))
        })
        .collect()
}

fn versions() -> Vec<(String, VersionPref)> {
    vec![
        ("v3".to_string(), VersionPref::Exact(NfsVersion::V3)),
        ("v4.0".to_string(), VersionPref::Exact(NfsVersion::V4(0))),
        ("v4.1".to_string(), VersionPref::Exact(NfsVersion::V4(1))),
        ("v4.2".to_string(), VersionPref::Exact(NfsVersion::V4(2))),
    ]
}

fn open(ip: IpAddr, path: &[u8], version: VersionPref) -> (Box<dyn Filesystem>, Vec<u8>) {
    let opts = ConnectOptions {
        rpc: RpcOptions {
            auth: Auth::sys_from_process(),
            ..RpcOptions::default()
        },
        version,
        ..ConnectOptions::default()
    };
    let c = connect(ip, path, &opts).expect("connect");
    (c.fs, path.to_vec())
}

/// Deterministic content: the byte at absolute position `p` (so misplaced data is caught).
fn byte_at(p: u64) -> u8 {
    (p.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8
}

/// A write source producing `len` bytes of `byte_at` starting at absolute position `base`.
fn pattern_source(base: u64, len: u64) -> impl FnMut(&mut [u8]) -> Result<usize> {
    let mut pos = 0u64;
    move |buf: &mut [u8]| {
        let n = (len - pos).min(buf.len() as u64) as usize;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b = byte_at(base + pos + i as u64);
        }
        pos += n as u64;
        Ok(n)
    }
}

/// Sequential transfer exactly as the trait's default `read_stream` does it.
fn seq_read(fs: &mut dyn Filesystem, fh: &FileHandle, offset: u64, len: u64, sink: &mut dyn FnMut(&[u8])) -> Result<u64> {
    let chunk = fs.max_read();
    let mut pos = offset;
    let end = offset + len;
    while pos < end {
        let want = (end - pos).min(u64::from(chunk)) as u32;
        let (data, eof) = fs.read(fh, pos, want)?;
        if !data.is_empty() {
            sink(&data);
            pos += data.len() as u64;
        }
        if eof || data.is_empty() {
            break;
        }
    }
    Ok(pos - offset)
}

/// Sequential write exactly as the trait's default `write_stream` does it.
fn seq_write(fs: &mut dyn Filesystem, fh: &FileHandle, offset: u64, source: &mut dyn FnMut(&mut [u8]) -> Result<usize>) -> Result<u64> {
    let mut buf = vec![0u8; fs.max_write() as usize];
    let mut pos = offset;
    loop {
        let n = source(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut done = 0;
        while done < n {
            let w = fs.write(fh, pos, &buf[done..n])? as usize;
            if w == 0 {
                return Err(Error::Protocol("server accepted a 0-byte write".into()));
            }
            done += w;
            pos += w as u64;
        }
    }
    Ok(pos - offset)
}

fn unique_dir() -> String {
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    format!("nfsc-perf-{:012x}", h.finish() & 0xffff_ffff_ffff)
}

/// Run `body` in a fresh scratch directory on the export, then remove it even on panic.
fn in_scratch_dir(fs: &mut dyn Filesystem, body: &mut dyn FnMut(&mut dyn Filesystem, &FileHandle) -> Result<()>) {
    let root = fs.root();
    let name = unique_dir();
    let (dir, _) = fs.mkdir(&root, name.as_bytes(), &SetAttr::default()).expect("mkdir scratch");
    let r = catch_unwind(AssertUnwindSafe(|| body(fs, &dir)));
    // Best-effort removal: children first, then the directory.
    if let Ok(entries) = fs.readdir(&dir) {
        for e in entries {
            let _ = fs.remove(&dir, &e.name);
        }
    }
    let _ = fs.rmdir(&root, name.as_bytes());
    match r {
        Ok(res) => res.expect("scratch test body"),
        Err(p) => resume_unwind(p),
    }
}

fn create_file(fs: &mut dyn Filesystem, dir: &FileHandle, name: &str) -> FileHandle {
    fs.create(dir, name.as_bytes(), CreateMode::Guarded, &SetAttr::default())
        .expect("create")
        .0
}

/// Check that `fs.read_stream` returns exactly `byte_at` content for the range.
fn verify_read(fs: &mut dyn Filesystem, fh: &FileHandle, offset: u64, len: Option<u64>, expect_len: u64) -> Result<()> {
    let mut pos = offset;
    let mut bad: Option<String> = None;
    let n = fs.read_stream(fh, offset, len, &mut |b: &[u8]| {
        for (i, &x) in b.iter().enumerate() {
            if bad.is_none() && x != byte_at(pos + i as u64) {
                bad = Some(format!("byte mismatch at {}", pos + i as u64));
            }
        }
        pos += b.len() as u64;
        Ok(())
    })?;
    if let Some(m) = bad {
        return Err(Error::Protocol(m));
    }
    assert_eq!(n, expect_len, "bytes delivered (offset {offset}, len {len:?})");
    assert_eq!(pos - offset, expect_len);
    Ok(())
}

#[test]
fn stream_round_trip_at_boundaries() {
    for (target, ip, path) in rw_targets() {
        for (vname, version) in versions() {
            let (mut fs, _) = open(ip, &path, version);
            let max_r = u64::from(fs.max_read());
            let max_w = u64::from(fs.max_write());
            let max = max_r.min(max_w);
            eprintln!("{target} {vname}: max_read {max_r} max_write {max_w}");
            in_scratch_dir(fs.as_mut(), &mut |fs, dir| {
                let sizes = [0, 1, max - 1, max, max + 1, 3 * max + 17, 5 * 1024 * 1024 + 3];
                for (i, &size) in sizes.iter().enumerate() {
                    let name = format!("f{i}.bin");
                    let fh = create_file(fs, dir, &name);
                    let wrote = fs.write_stream(&fh, 0, &mut pattern_source(0, size))?;
                    assert_eq!(wrote, size, "{target} {vname} write {size}");
                    let attr = fs.getattr(&fh)?;
                    assert_eq!(attr.size, size, "{target} {vname} size after write {size}");
                    verify_read(fs, &fh, 0, None, size)?;
                    verify_read(fs, &fh, 0, Some(size), size)?;
                    // A read past EOF delivers nothing.
                    verify_read(fs, &fh, size, Some(10), 0)?;
                }
                // Unaligned offsets: write 2 MiB + 3 at offset 4097, leaving a hole before it.
                let fh = create_file(fs, dir, "unaligned.bin");
                let base = 4097u64;
                let len = 2 * 1024 * 1024 + 3;
                let wrote = fs.write_stream(&fh, base, &mut pattern_source(base, len))?;
                assert_eq!(wrote, len);
                // Reads at odd offsets and lengths.
                verify_read(fs, &fh, base + 1, Some(777_777), 777_777)?;
                verify_read(fs, &fh, base + 300_000, None, len - 300_000)?;
                Ok(())
            });
            let _ = fs.disconnect();
        }
    }
}

#[test]
fn sink_error_aborts_and_connection_still_works() {
    for (target, ip, path) in rw_targets() {
        for (vname, version) in versions() {
            let (mut fs, _) = open(ip, &path, version);
            let chunk = u64::from(fs.max_read());
            in_scratch_dir(fs.as_mut(), &mut |fs, dir| {
                let fh = create_file(fs, dir, "abort.bin");
                let size = 6 * chunk + 11;
                fs.write_stream(&fh, 0, &mut pattern_source(0, size))?;
                let mut calls = 0;
                let r = fs.read_stream(&fh, 0, None, &mut |_b: &[u8]| {
                    calls += 1;
                    if calls == 3 {
                        Err(Error::Invalid("sink full".into()))
                    } else {
                        Ok(())
                    }
                });
                assert!(matches!(r, Err(Error::Invalid(_))), "{target} {vname}: {r:?}");
                assert_eq!(calls, 3, "{target} {vname}: sink not called after its error");
                // The same connection serves a complete read afterwards.
                verify_read(fs, &fh, 0, None, size)?;
                Ok(())
            });
            let _ = fs.disconnect();
        }
    }
}

#[test]
fn write_stream_then_read_back_via_sequential_path() {
    for (target, ip, path) in rw_targets() {
        for (vname, version) in versions() {
            let (mut fs, _) = open(ip, &path, version);
            in_scratch_dir(fs.as_mut(), &mut |fs, dir| {
                let fh = create_file(fs, dir, "seq.bin");
                let size = 3 * 1024 * 1024 + 129;
                fs.write_stream(&fh, 0, &mut pattern_source(0, size))?;
                let mut got = Vec::new();
                let n = seq_read(fs, &fh, 0, size, &mut |b: &[u8]| got.extend_from_slice(b))?;
                assert_eq!(n, size, "{target} {vname}");
                assert!(got.iter().enumerate().all(|(i, &b)| b == byte_at(i as u64)), "{target} {vname}: content");
                Ok(())
            });
            let _ = fs.disconnect();
        }
    }
}

fn ro_targets() -> Option<(IpAddr, Vec<u8>)> {
    let (ip, path, _) = parse_target(&std::env::var("NFSC_TEST_RO_GANESHA").ok()?)?;
    Some((ip, path))
}

#[test]
fn read_stream_on_readonly_fixture_matches_sequential() {
    let Some((ip, export)) = ro_targets() else { return };
    for (vname, version) in versions() {
        let (mut fs, _) = open(ip, &export, version);
        let root = fs.root();
        let entries = fs.readdir(&root).expect("readdir");
        let Some(f) = entries.iter().find(|e| e.name == b"big.bin") else { continue };
        let fh = f.handle.clone().unwrap_or_else(|| fs.lookup(&root, b"big.bin").unwrap().0);
        let size = fs.getattr(&fh).unwrap().size;
        let mut seq = Vec::new();
        seq_read(fs.as_mut(), &fh, 0, size, &mut |b: &[u8]| seq.extend_from_slice(b)).unwrap();
        let mut piped = Vec::new();
        let n = fs.read_stream(&fh, 0, None, &mut |b: &[u8]| {
            piped.extend_from_slice(b);
            Ok(())
        })
        .unwrap();
        assert_eq!(n, size, "{vname}");
        assert_eq!(piped, seq, "{vname}: pipelined and sequential reads differ");
    }
}

/// Timed read of `len` bytes from `off` with a transfer function; returns MiB/s.
fn time_read(
    fs: &mut dyn Filesystem,
    fh: &FileHandle,
    len: u64,
    pipelined: bool,
) -> f64 {
    let mut total = 0u64;
    let started = Instant::now();
    let mut sink = |b: &[u8]| total += b.len() as u64;
    let n = if pipelined {
        fs.read_stream(fh, 0, Some(len), &mut |b: &[u8]| {
            sink(b);
            Ok(())
        })
    } else {
        seq_read(fs, fh, 0, len, &mut sink)
    }
    .expect("read");
    assert_eq!(n, total);
    let secs = started.elapsed().as_secs_f64();
    total as f64 / secs / (1024.0 * 1024.0)
}

/// Read-write benchmark: sequential vs pipelined READ and WRITE, per version.
#[test]
#[ignore = "benchmark: run with --ignored --nocapture"]
fn bench_rw_sequential_vs_pipelined() {
    let mib: u64 = std::env::var("NFSC_PERF_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(512);
    let size = mib * 1024 * 1024;
    for (target, ip, path) in rw_targets() {
        for (vname, version) in versions() {
            let (mut fs, _) = open(ip, &path, version);
            in_scratch_dir(fs.as_mut(), &mut |fs, dir| {
                let fh = create_file(fs, dir, "bench.bin");
                let t = Instant::now();
                seq_write(fs, &fh, 0, &mut pattern_source(0, size))?;
                let seq_w = size as f64 / t.elapsed().as_secs_f64() / 1048576.0;
                let t = Instant::now();
                fs.write_stream(&fh, 0, &mut pattern_source(0, size))?;
                let pipe_w = size as f64 / t.elapsed().as_secs_f64() / 1048576.0;
                let seq_r = time_read(fs, &fh, size, false);
                let pipe_r = time_read(fs, &fh, size, true);
                println!(
                    "BENCH {target} {vname} {mib} MiB: write seq {seq_w:.1} pipelined {pipe_w:.1} MiB/s; \
                     read seq {seq_r:.1} pipelined {pipe_r:.1} MiB/s"
                );
                Ok(())
            });
            let _ = fs.disconnect();
        }
    }
}

/// Read-only benchmark against a real server (e.g. a NAS). Never writes.
#[test]
#[ignore = "benchmark: NFSC_PERF_RO_FILE; run with --ignored --nocapture"]
fn bench_ro_read_sequential_vs_pipelined() {
    let Ok(spec) = std::env::var("NFSC_PERF_RO_FILE") else { return };
    let Some((ip, file_path, _)) = parse_target(&spec) else {
        panic!("NFSC_PERF_RO_FILE must be host:/export/path/to/file");
    };
    let mib: u64 = std::env::var("NFSC_PERF_RO_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(2048);
    let vers = std::env::var("NFSC_PERF_RO_VERS").unwrap_or_else(|_| "3,4.0,4.1,4.2".into());
    // Split the export from the file name at the last slash.
    let cut = file_path.iter().rposition(|&b| b == b'/').unwrap_or(0);
    let (export, name) = (&file_path[..cut.max(1)], &file_path[cut + 1..]);
    for v in vers.split(',') {
        let version = match v.trim() {
            "3" => VersionPref::Exact(NfsVersion::V3),
            "4.0" => VersionPref::Exact(NfsVersion::V4(0)),
            "4.1" => VersionPref::Exact(NfsVersion::V4(1)),
            "4.2" => VersionPref::Exact(NfsVersion::V4(2)),
            other => panic!("unknown version {other}"),
        };
        let opts = ConnectOptions {
            rpc: RpcOptions {
                auth: Auth::sys_from_process(),
                ..RpcOptions::default()
            },
            version,
            ..ConnectOptions::default()
        };
        let c = connect(ip, export, &opts).expect("connect");
        let mut fs = c.fs;
        // The directory may lie below the export (v2/v3): walk the remainder.
        let mut dir = fs.root();
        for comp in &c.remainder {
            dir = fs.lookup(&dir, comp).expect("lookup benchmark dir").0;
        }
        let (fh, attr) = fs.lookup(&dir, name).expect("lookup benchmark file");
        let len = mib.min(attr.size / (1024 * 1024)).max(1) * 1024 * 1024;
        let seq = time_read(fs.as_mut(), &fh, len, false);
        let pipe = time_read(fs.as_mut(), &fh, len, true);
        println!(
            "BENCH-RO {v} {} MiB: read seq {seq:.1} pipelined {pipe:.1} MiB/s",
            len / (1024 * 1024)
        );
        let _ = fs.disconnect();
    }
}
