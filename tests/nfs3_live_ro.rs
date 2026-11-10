//! Read-only live tests for NFSv3, through the `fs::connect` facade.
//!
//! Gated on environment variables; skipped when unset:
//! - `NFSC_TEST_RO=host:/export` browse, read, stat (read procedures only).
//! - `NFSC_TEST_RO_UDP=1` also run the browse test over UDP.
//! - `NFSC_TEST_RO_MANIFEST=/path/to/sha256sum-file` verify fixture contents
//!   (`<sha256>  <path relative to the export>` per line).
//! - `NFSC_TEST_RO_SECURE=host:/export` an export that requires reserved source
//!   ports; an unprivileged connect must fail and a privileged one must succeed.
//!
//! Only NULL/GETATTR/LOOKUP/READLINK/READ/READDIR(PLUS)/FSSTAT/FSINFO and MOUNT
//! EXPORT/MNT/UMNT are issued. Nothing here writes to the server.

use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::Duration;

use nfsc::error::Error;
use nfsc::fs::{
    self, Attr, ConnectOptions, Connected, FileHandle, FileType, Filesystem, NfsVersion, Status,
    VersionPref,
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

/// Parse `host:/export` from an environment variable.
fn target(var: &str) -> Option<(IpAddr, Vec<u8>)> {
    let spec = std::env::var(var).ok()?;
    let (host, path) = spec
        .split_once(':')
        .unwrap_or_else(|| panic!("{var} must be host:/export"));
    Some((resolve(host), path.as_bytes().to_vec()))
}

fn opts(proto: Proto, port_mode: PortMode) -> ConnectOptions {
    ConnectOptions {
        rpc: RpcOptions {
            proto,
            port_mode,
            timeout: Duration::from_secs(10),
            auth: Auth::sys_from_process(),
            ..RpcOptions::default()
        },
        nfs_port: None,
        mount_port: None,
        version: VersionPref::Exact(NfsVersion::V3),
    }
}

fn connect(ip: IpAddr, path: &[u8], proto: Proto) -> Connected {
    let spec = String::from_utf8_lossy(path).into_owned();
    fs::connect(ip, path, &opts(proto, PortMode::Auto))
        .unwrap_or_else(|e| panic!("connect {spec} over {}: {e}", proto.name()))
}

/// Resolve the remainder components below the export root.
fn walk(fs: &mut dyn Filesystem, mut fh: FileHandle, rem: &[Vec<u8>]) -> (FileHandle, Attr) {
    let mut attr = fs.getattr(&fh).expect("getattr root");
    for c in rem {
        let (next, a) = fs.lookup(&fh, c).expect("lookup remainder");
        fh = next;
        attr = a;
    }
    (fh, attr)
}

/// Read a whole file in `max_read` chunks.
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

fn sha256_hex(data: &[u8]) -> String {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run sha256sum");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(data)
        .expect("write to sha256sum");
    let out = child.wait_with_output().expect("sha256sum");
    String::from_utf8_lossy(&out.stdout)[..64].to_string()
}

fn browse(ip: IpAddr, path: &[u8], proto: Proto) {
    let Connected {
        mut fs,
        export,
        remainder,
    } = connect(ip, path, proto);
    assert_eq!(fs.version(), NfsVersion::V3);
    assert!(fs.max_read() > 0 && fs.max_write() > 0);
    eprintln!(
        "[{}] export {} remainder {:?} max_read {} max_write {}",
        proto.name(),
        String::from_utf8_lossy(&export),
        remainder
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>(),
        fs.max_read(),
        fs.max_write()
    );
    let root = fs.root();
    let (dir, dattr) = walk(fs.as_mut(), root.clone(), &remainder);
    assert_eq!(dattr.ftype, FileType::Directory);

    let entries = fs.readdir(&dir).expect("readdir");
    let mut names: Vec<&[u8]> = entries.iter().map(|e| e.name.as_slice()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names.len(),
        entries.len(),
        "readdir returned duplicate names"
    );
    assert!(!names.contains(&&b"."[..]) && !names.contains(&&b".."[..]));

    let mut checked_file = false;
    for e in &entries {
        let (fh, attr) = fs.lookup(&dir, &e.name).expect("lookup of a listed name");
        assert_eq!(
            attr.fileid, e.fileid,
            "readdir fileid must match lookup for {:?}",
            e.name
        );
        if let Some(a) = &e.attr {
            assert_eq!(a.size, attr.size, "READDIRPLUS attrs disagree with GETATTR");
        }
        match attr.ftype {
            FileType::Symlink => {
                let target = fs.readlink(&fh).expect("readlink");
                assert!(!target.is_empty());
            }
            FileType::Regular if !checked_file => {
                checked_file = true;
                let first = fs.read(&fh, 0, 4096).expect("read first block");
                assert!(first.0.len() <= 4096);
                if attr.size > 0 {
                    assert!(!first.0.is_empty(), "non-empty file returned no data");
                }
                let past = fs.read(&fh, attr.size, 4096).expect("read at EOF");
                assert!(
                    past.0.is_empty() && past.1,
                    "read at EOF must be empty with eof"
                );
            }
            _ => {}
        }
    }

    let fsstat = fs.fsstat(&dir).expect("fsstat");
    assert!(fsstat.total_bytes > 0);
    assert!(fsstat.free_bytes <= fsstat.total_bytes);

    match fs.lookup(&dir, b"nfsc-no-such-name-0f3a") {
        Err(Error::Nfs(Status::NoEnt)) => {}
        other => panic!("lookup of a missing name returned {other:?}"),
    }
    fs.lookup(&root, b"..")
        .expect("lookup .. from the export root");
    fs.disconnect().expect("disconnect");
}

#[test]
fn ro_browse_tcp() {
    let Some((ip, path)) = target("NFSC_TEST_RO") else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    browse(ip, &path, Proto::Tcp);
}

#[test]
fn ro_browse_udp() {
    let Some((ip, path)) = target("NFSC_TEST_RO") else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    if std::env::var("NFSC_TEST_RO_UDP").is_err() {
        eprintln!("NFSC_TEST_RO_UDP not set; skipping UDP");
        return;
    }
    let udp = RpcOptions {
        proto: Proto::Udp,
        ..RpcOptions::default()
    };
    match nfsc::portmap::getport(
        ip,
        nfsc::nfs3::PROGRAM,
        nfsc::nfs3::VERSION,
        Proto::Udp,
        &udp,
    ) {
        Err(Error::NotRegistered { .. }) => {
            eprintln!("NFSv3 is not registered over UDP on this server; skipping");
            return;
        }
        Err(e) => panic!("portmap lookup over UDP: {e}"),
        Ok(port) => eprintln!("NFSv3 over UDP is on port {port}"),
    }
    browse(ip, &path, Proto::Udp);
}

/// A path below the export resolves to the export with the rest as remainder.
#[test]
fn ro_resolve_deeper_path() {
    let Some((ip, path)) = target("NFSC_TEST_RO") else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let Connected { mut fs, .. } = connect(ip, &path, Proto::Tcp);
    let root = fs.root();
    let subdir = fs
        .readdir(&root)
        .expect("readdir root")
        .into_iter()
        .find(|e| {
            e.attr
                .as_ref()
                .is_some_and(|a| a.ftype == FileType::Directory)
        })
        .map(|e| e.name);
    fs.disconnect().expect("disconnect");
    let Some(subdir) = subdir else {
        eprintln!("export has no subdirectory; skipping deeper-path check");
        return;
    };
    let mut deeper = path.clone();
    deeper.push(b'/');
    deeper.extend_from_slice(&subdir);
    deeper.extend_from_slice(b"/nfsc-missing");
    let Connected {
        mut fs,
        export,
        remainder,
    } = connect(ip, &deeper, Proto::Tcp);
    assert_eq!(export, path, "the export containing the deeper path");
    assert_eq!(remainder.len(), 2);
    assert_eq!(remainder[0], subdir);
    assert_eq!(remainder[1], b"nfsc-missing");
    fs.disconnect().expect("disconnect");
}

/// A path that no export contains is mounted directly and the server's answer
/// (typically NOENT or permission denied) is surfaced.
#[test]
fn ro_unexported_path_is_refused() {
    let Some((ip, path)) = target("NFSC_TEST_RO") else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let _ = path;
    let bogus = b"/nfsc-no-such-export-0f3a";
    match fs::connect(ip, bogus, &opts(Proto::Tcp, PortMode::Auto)) {
        Ok(_) => panic!("mounting a non-existent path unexpectedly succeeded"),
        Err(e) => eprintln!("refused as expected: {e}"),
    }
}

/// Every file named in the manifest must hash to the recorded value.
#[test]
fn ro_fixtures_match_manifest() {
    let Some((ip, path)) = target("NFSC_TEST_RO") else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let Ok(manifest) = std::env::var("NFSC_TEST_RO_MANIFEST") else {
        eprintln!("NFSC_TEST_RO_MANIFEST not set; skipping fixture checks");
        return;
    };
    // Raw bytes: fixtures deliberately include a non-UTF-8 file name.
    let text = std::fs::read(&manifest).expect("read manifest");
    let Connected {
        mut fs, remainder, ..
    } = connect(ip, &path, Proto::Tcp);
    let root = fs.root();
    let (base, _) = walk(fs.as_mut(), root, &remainder);

    let mut checked = 0;
    for line in text.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
        let (want, rel) = line.split_at(64);
        let want = std::str::from_utf8(want).expect("hex digest");
        let rel = rel
            .strip_prefix(b"  ")
            .expect("manifest line: '<sha256>  <path>'");
        let mut fh = base.clone();
        for comp in rel.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            fh = fs.lookup(&fh, comp).expect("lookup fixture").0;
        }
        let data = read_all(fs.as_mut(), &fh);
        let rel = String::from_utf8_lossy(rel);
        assert_eq!(sha256_hex(&data), want, "sha256 mismatch for {rel}");
        checked += 1;
    }
    assert!(checked > 0, "manifest had no entries");
    eprintln!("verified {checked} fixture file(s)");
}

/// Unprivileged source ports must be refused by a `secure` export and a
/// reserved port must work. Run with sudo so the privileged connect can bind.
#[test]
fn ro_secure_export_port_policy() {
    let Some((ip, path)) = target("NFSC_TEST_RO_SECURE") else {
        eprintln!("NFSC_TEST_RO_SECURE not set; skipping");
        return;
    };
    match fs::connect(ip, &path, &opts(Proto::Tcp, PortMode::Unprivileged)) {
        Ok(_) => panic!("unprivileged connect to a secure export unexpectedly succeeded"),
        Err(e) => eprintln!("unprivileged connect refused as expected: {e}"),
    }
    let Connected { mut fs, .. } = fs::connect(ip, &path, &opts(Proto::Tcp, PortMode::Privileged))
        .expect("privileged connect to secure export");
    let root = fs.root();
    fs.getattr(&root).expect("getattr over a privileged port");
    fs.disconnect().expect("disconnect");
}
