//! Live sanity check against a real portmapper. Gated on NFSC_TEST_HOST; skipped when unset.

use std::net::ToSocketAddrs;
use std::time::Duration;

use nfsc::rpc::{Auth, PortMode, Proto, RpcClient, RpcOptions};

#[test]
fn portmap_null_over_tcp_and_udp() {
    let Ok(host) = std::env::var("NFSC_TEST_HOST") else {
        eprintln!("NFSC_TEST_HOST not set; skipping");
        return;
    };
    let addr = (host.as_str(), 111)
        .to_socket_addrs()
        .expect("resolve NFSC_TEST_HOST")
        .next()
        .expect("no address");
    for proto in [Proto::Tcp, Proto::Udp] {
        let opts = RpcOptions {
            proto,
            port_mode: PortMode::Unprivileged,
            timeout: Duration::from_secs(5),
            auth: Auth::None,
        };
        let mut c = RpcClient::connect(addr, 100000, 2, &opts).expect("connect");
        c.null().unwrap_or_else(|e| panic!("NULL over {}: {e}", proto.name()));
    }
}
