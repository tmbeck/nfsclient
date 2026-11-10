//! Live portmap checks against the server named by NFSC_TEST_HOST.
//! Only PMAPPROC_NULL, DUMP and GETPORT are sent. Skipped when the variable is unset.

use std::net::ToSocketAddrs;

use nfsc::Error;
use nfsc::portmap;
use nfsc::rpc::{Proto, RpcOptions};

fn host_ip() -> Option<std::net::IpAddr> {
    let host = match std::env::var("NFSC_TEST_HOST") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            eprintln!("skipping: NFSC_TEST_HOST is not set");
            return None;
        }
    };
    let ip = (host.as_str(), portmap::PORT)
        .to_socket_addrs()
        .expect("resolve NFSC_TEST_HOST")
        .next()
        .expect("NFSC_TEST_HOST has an address")
        .ip();
    Some(ip)
}

#[test]
fn null_dump_and_getport_agree() {
    let Some(ip) = host_ip() else { return };
    let opts = RpcOptions::default();

    portmap::ping(ip, &opts).expect("portmapper NULL");

    let list = portmap::dump(ip, &opts).expect("portmapper DUMP over tcp");
    assert!(!list.is_empty());
    let portmapper = list
        .iter()
        .find(|m| m.prog == portmap::PROGRAM && m.vers == portmap::VERSION)
        .expect("portmapper registers itself");
    assert_eq!(portmapper.port, portmap::PORT as u32);

    // Every TCP mapping must be returned by GETPORT with the same port.
    for m in list.iter().filter(|m| m.prot == 6) {
        let port = portmap::getport(ip, m.prog, m.vers, Proto::Tcp, &opts)
            .unwrap_or_else(|e| panic!("getport {} {} failed: {e}", m.prog, m.vers));
        assert_eq!(port as u32, m.port, "prog {} vers {}", m.prog, m.vers);
    }
}

#[test]
fn dump_over_udp_lists_the_same_programs() {
    let Some(ip) = host_ip() else { return };
    let tcp = portmap::dump(ip, &RpcOptions::default()).expect("DUMP over tcp");
    let udp_opts = RpcOptions {
        proto: Proto::Udp,
        ..RpcOptions::default()
    };
    let udp = portmap::dump(ip, &udp_opts).expect("DUMP over udp");
    assert_eq!(tcp, udp);
}

#[test]
fn getport_unregistered_program_is_not_registered() {
    let Some(ip) = host_ip() else { return };
    // 0x3fffffff is outside any range servers register.
    match portmap::getport(ip, 0x3fff_ffff, 1, Proto::Tcp, &RpcOptions::default()) {
        Err(Error::NotRegistered { prog, vers }) => {
            assert_eq!((prog, vers), (0x3fff_ffff, 1));
        }
        other => panic!("expected NotRegistered, got {other:?}"),
    }
}
