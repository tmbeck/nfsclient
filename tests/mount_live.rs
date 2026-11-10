//! Live MOUNT protocol tests (EXPORT, MNT, UMNT only). Gated on `NFSC_TEST_RO=host:/export`;
//! skipped when unset. Mounting a read-only export and unmounting it is allowed on the
//! shared test servers; nothing here touches file contents or metadata.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use nfsc::error::Error;
use nfsc::fs::Status;
use nfsc::mount;
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
    let spec = std::env::var("NFSC_TEST_RO").ok()?;
    let (host, path) = spec.split_once(':').expect("NFSC_TEST_RO must be host:/export");
    Some((resolve(host), path.as_bytes().to_vec()))
}

fn opts(proto: Proto) -> RpcOptions {
    RpcOptions {
        proto,
        port_mode: PortMode::Auto,
        timeout: Duration::from_secs(10),
        auth: Auth::sys_from_process(),
    }
}

#[test]
fn mount_export_lists_the_target_over_tcp_and_udp() {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let exports = mount::exports(ip, None, &opts(Proto::Tcp)).expect("EXPORT over TCP");
    assert!(!exports.is_empty(), "server lists no exports");
    let (found, rem) = mount::resolve_export(&exports, &path).expect("target export is listed");
    assert!(rem.is_empty());
    assert_eq!(found.dir, path);
    eprintln!("exports: {}", exports.len());

    // EXPORT over UDP is tried whenever MOUNT is registered on UDP.
    match mount::exports(ip, None, &opts(Proto::Udp)) {
        Ok(udp) => assert_eq!(udp.len(), exports.len(), "same export list over UDP"),
        Err(e) if e.is_version_unsupported() => eprintln!("MOUNT not registered over UDP: {e}"),
        Err(e) => panic!("EXPORT over UDP: {e}"),
    }
}

#[test]
fn mount_v3_mnt_returns_handle_and_flavors_then_umnt() {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let o = opts(Proto::Tcp);
    let (fh, flavors) = mount::mnt(ip, None, 3, &path, &o).expect("MNT v3");
    assert!(!fh.0.is_empty() && fh.0.len() <= 64, "v3 handle is 1..=64 bytes");
    assert!(
        flavors.contains(&1) || flavors.contains(&0),
        "server accepts neither AUTH_SYS nor AUTH_NONE: {flavors:?}"
    );
    mount::umnt(ip, None, 3, &path, &o).expect("UMNT v3");
}

#[test]
fn mount_v1_mnt_returns_32_byte_handle() {
    let Some((ip, path)) = target() else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    let o = opts(Proto::Tcp);
    match mount::mnt(ip, None, 1, &path, &o) {
        Ok((fh, flavors)) => {
            assert_eq!(fh.0.len(), 32, "MOUNT v1 handles are 32 bytes");
            assert!(flavors.is_empty(), "v1 carries no flavor list");
            mount::umnt(ip, None, 1, &path, &o).expect("UMNT v1");
        }
        Err(e) if e.is_version_unsupported() => eprintln!("MOUNT v1 not registered: {e}"),
        Err(e) => panic!("MNT v1: {e}"),
    }
}

#[test]
fn mount_of_unexported_path_is_refused() {
    let Some((ip, _)) = target() else {
        eprintln!("NFSC_TEST_RO not set; skipping");
        return;
    };
    match mount::mnt(ip, None, 3, b"/nfsc-no-such-export-0f3a", &opts(Proto::Tcp)) {
        Err(Error::Nfs(Status::Access | Status::NoEnt)) => {}
        other => panic!("MNT of a non-existent path returned {other:?}"),
    }
}
