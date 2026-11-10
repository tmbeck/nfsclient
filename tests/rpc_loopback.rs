//! RPC client against an in-process fake server on 127.0.0.1.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nfsc::error::{AcceptError, Error};
use nfsc::rpc::{Auth, PortMode, Proto, RpcClient, RpcOptions};
use nfsc::xdr::{Opaque, to_bytes};

const PROG: u32 = 0x2000_0001;
const VERS: u32 = 3;

/// Handler: (xid, procedure, args) -> replies to send, in order. Empty = drop the call.
type Handler = Box<dyn FnMut(u32, u32, &[u8]) -> Vec<Vec<u8>> + Send>;

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// Parse a CALL message into (xid, procedure, args bytes).
fn parse_call(msg: &[u8]) -> (u32, u32, Vec<u8>) {
    assert_eq!(u32_at(msg, 4), 0, "CALL msg_type");
    assert_eq!(u32_at(msg, 8), 2, "rpcvers");
    assert_eq!(u32_at(msg, 12), PROG);
    assert_eq!(u32_at(msg, 16), VERS);
    let proc_ = u32_at(msg, 20);
    // credential, then verifier: each is flavor + opaque body
    let mut off = 24;
    for _ in 0..2 {
        off += 4;
        let len = u32_at(msg, off) as usize;
        off += 4 + len.div_ceil(4) * 4;
    }
    (u32_at(msg, 0), proc_, msg[off..].to_vec())
}

/// Accepted/SUCCESS reply carrying `body`.
fn reply_ok(xid: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&xid.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes()); // REPLY
    v.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
    v.extend_from_slice(&[0; 8]); // verifier AUTH_NONE, empty
    v.extend_from_slice(&0u32.to_be_bytes()); // SUCCESS
    v.extend_from_slice(body);
    v
}

fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).ok()?;
        let w = u32::from_be_bytes(hdr);
        let mut frag = vec![0u8; (w & 0x7fff_ffff) as usize];
        s.read_exact(&mut frag).ok()?;
        out.extend_from_slice(&frag);
        if w & 0x8000_0000 != 0 {
            return Some(out);
        }
    }
}

/// Send `data` as `frags` fragments, each written separately.
fn write_record(s: &mut TcpStream, data: &[u8], frags: usize) {
    let frags = frags.max(1);
    let chunk = data.len().div_ceil(frags).max(1);
    let pieces: Vec<&[u8]> = data.chunks(chunk).collect();
    for (i, piece) in pieces.iter().enumerate() {
        let last = if i + 1 == pieces.len() {
            0x8000_0000u32
        } else {
            0
        };
        let hdr = last | piece.len() as u32;
        s.write_all(&hdr.to_be_bytes()).unwrap();
        s.write_all(piece).unwrap();
    }
}

fn spawn_tcp(frags: usize, mut handler: Handler) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        while let Some(call) = read_record(&mut s) {
            let (xid, proc_, args) = parse_call(&call);
            for reply in handler(xid, proc_, &args) {
                write_record(&mut s, &reply, frags);
            }
        }
    });
    addr
}

fn spawn_udp(mut handler: Handler) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    thread::spawn(move || {
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                return;
            };
            let (xid, proc_, args) = parse_call(&buf[..n]);
            for reply in handler(xid, proc_, &args) {
                sock.send_to(&reply, peer).unwrap();
            }
        }
    });
    addr
}

fn opts(proto: Proto, timeout: Duration) -> RpcOptions {
    RpcOptions {
        proto,
        port_mode: PortMode::Unprivileged,
        timeout,
        auth: Auth::None,
        ..RpcOptions::default()
    }
}

/// Procedure 0 = NULL; procedure 1 = double a u32; procedure 2 = opaque of N bytes (N from args).
fn standard_handler() -> Handler {
    Box::new(|xid, proc_, args| match proc_ {
        0 => vec![reply_ok(xid, &[])],
        1 => {
            let n = u32::from_be_bytes(args[..4].try_into().unwrap());
            vec![reply_ok(xid, &(n * 2).to_be_bytes())]
        }
        2 => {
            let n = u32::from_be_bytes(args[..4].try_into().unwrap()) as usize;
            let big: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            vec![reply_ok(xid, &to_bytes(&Opaque(big)))]
        }
        _ => unreachable!("unexpected proc {proc_}"),
    })
}

fn connect(addr: SocketAddr, o: &RpcOptions) -> RpcClient {
    RpcClient::connect(addr, PROG, VERS, o).expect("connect")
}

#[test]
fn tcp_multi_fragment_reply_is_reassembled() {
    let addr = spawn_tcp(3, standard_handler());
    let mut c = connect(addr, &opts(Proto::Tcp, Duration::from_secs(5)));
    let Opaque(data): Opaque = c.call(2, &10_000u32).unwrap();
    assert_eq!(data.len(), 10_000);
    assert!(data.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
}

#[test]
fn tcp_skips_stale_xid_replies() {
    let handler: Handler = Box::new(|xid, _p, _a| {
        vec![
            reply_ok(xid.wrapping_add(1000), &[0, 0, 0, 1]),
            reply_ok(xid, &[0, 0, 0, 84]),
        ]
    });
    let addr = spawn_tcp(1, handler);
    let mut c = connect(addr, &opts(Proto::Tcp, Duration::from_secs(5)));
    assert_eq!(c.call::<u32, u32>(1, &42).unwrap(), 84);
    // Next call on the same connection also works.
    assert_eq!(c.call::<u32, u32>(1, &42).unwrap(), 84);
}

#[test]
fn udp_skips_stale_xid_datagrams() {
    let handler: Handler = Box::new(|xid, _p, _a| {
        vec![
            reply_ok(xid.wrapping_add(1000), &[0, 0, 0, 1]),
            reply_ok(xid, &[0, 0, 0, 84]),
        ]
    });
    let addr = spawn_udp(handler);
    let mut c = connect(addr, &opts(Proto::Udp, Duration::from_secs(5)));
    assert_eq!(c.call::<u32, u32>(1, &42).unwrap(), 84);
}

#[test]
fn udp_retransmits_when_first_datagram_is_dropped() {
    let seen: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = Arc::clone(&seen);
    let handler: Handler = Box::new(move |xid, _p, _a| {
        let mut s = seen2.lock().unwrap();
        s.push(xid);
        if s.len() == 1 {
            vec![] // drop the first datagram
        } else {
            vec![reply_ok(xid, &[0, 0, 0, 6])]
        }
    });
    let addr = spawn_udp(handler);
    let mut c = connect(addr, &opts(Proto::Udp, Duration::from_secs(10)));
    let start = Instant::now();
    assert_eq!(c.call::<u32, u32>(1, &3).unwrap(), 6);
    assert!(
        start.elapsed() >= Duration::from_millis(900),
        "retransmit should wait ~1s"
    );
    let seen = seen.lock().unwrap();
    assert!(seen.len() >= 2);
    assert!(
        seen.iter().all(|&x| x == seen[0]),
        "retransmits reuse the xid"
    );
}

#[test]
fn tcp_timeout_when_server_silent() {
    let addr = spawn_tcp(1, Box::new(|_, _, _| vec![]));
    let mut c = connect(addr, &opts(Proto::Tcp, Duration::from_millis(300)));
    let start = Instant::now();
    assert!(matches!(c.null(), Err(Error::Timeout)));
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn udp_timeout_when_server_silent() {
    let addr = spawn_udp(Box::new(|_, _, _| vec![]));
    let mut c = connect(addr, &opts(Proto::Udp, Duration::from_millis(1500)));
    let start = Instant::now();
    assert!(matches!(c.null(), Err(Error::Timeout)));
    let el = start.elapsed();
    assert!(
        el >= Duration::from_millis(1400) && el < Duration::from_secs(5),
        "{el:?}"
    );
}

#[test]
fn tcp_unprivileged_end_to_end() {
    let addr = spawn_tcp(1, standard_handler());
    let mut c = connect(addr, &opts(Proto::Tcp, Duration::from_secs(5)));
    assert!(!c.is_privileged());
    assert_eq!(c.proto(), Proto::Tcp);
    assert_eq!(c.peer_addr(), addr);
    c.null().unwrap();
    assert_eq!(c.call::<u32, u32>(1, &21).unwrap(), 42);
}

#[test]
fn udp_unprivileged_end_to_end() {
    let addr = spawn_udp(standard_handler());
    let mut c = connect(addr, &opts(Proto::Udp, Duration::from_secs(5)));
    assert!(!c.is_privileged());
    assert_eq!(c.proto(), Proto::Udp);
    c.null().unwrap();
    assert_eq!(c.call::<u32, u32>(1, &21).unwrap(), 42);
}

#[test]
fn accept_error_is_surfaced() {
    // Reply PROG_UNAVAIL to everything.
    let handler: Handler = Box::new(|xid, _, _| {
        let mut v = Vec::new();
        v.extend_from_slice(&xid.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&1u32.to_be_bytes()); // PROG_UNAVAIL
        vec![v]
    });
    let addr = spawn_udp(handler);
    let mut c = connect(addr, &opts(Proto::Udp, Duration::from_secs(5)));
    assert!(matches!(
        c.null(),
        Err(Error::Accept(AcceptError::ProgUnavail))
    ));
}

#[test]
fn tcp_privileged_binds_or_errors() {
    let addr = spawn_tcp(1, standard_handler());
    let o = RpcOptions {
        port_mode: PortMode::Privileged,
        ..opts(Proto::Tcp, Duration::from_secs(5))
    };
    match RpcClient::connect(addr, PROG, VERS, &o) {
        Ok(mut c) => {
            assert!(c.is_privileged());
            c.null().unwrap();
            assert_eq!(c.call::<u32, u32>(1, &4).unwrap(), 8);
        }
        Err(Error::Invalid(msg)) => assert!(msg.contains("reserved"), "{msg}"), // not root: expected
        Err(e) => panic!("unexpected error {e:?}"),
    }
}

#[test]
fn tcp_auto_mode_connects_and_calls() {
    let addr = spawn_tcp(1, standard_handler());
    let o = RpcOptions {
        port_mode: PortMode::Auto,
        ..opts(Proto::Tcp, Duration::from_secs(5))
    };
    let mut c = RpcClient::connect(addr, PROG, VERS, &o).unwrap();
    c.null().unwrap();
    assert_eq!(c.call::<u32, u32>(1, &5).unwrap(), 10);
}

#[test]
fn udp_auto_mode_connects_either_way() {
    let addr = spawn_udp(standard_handler());
    let o = RpcOptions {
        port_mode: PortMode::Auto,
        ..opts(Proto::Udp, Duration::from_secs(5))
    };
    let mut c = RpcClient::connect(addr, PROG, VERS, &o).unwrap();
    c.null().unwrap();
}

#[test]
fn udp_privileged_mode_either_binds_or_errors() {
    let addr = spawn_udp(standard_handler());
    let o = RpcOptions {
        port_mode: PortMode::Privileged,
        ..opts(Proto::Udp, Duration::from_secs(5))
    };
    match RpcClient::connect(addr, PROG, VERS, &o) {
        Ok(mut c) => {
            assert!(c.is_privileged());
            c.null().unwrap();
        }
        Err(Error::Invalid(_)) => {} // not root: expected
        Err(e) => panic!("unexpected error {e:?}"),
    }
}

#[test]
fn set_auth_sys_is_accepted_by_fake_server() {
    let addr = spawn_tcp(1, standard_handler());
    let mut c = connect(addr, &opts(Proto::Tcp, Duration::from_secs(5)));
    c.set_auth(Auth::sys_from_process());
    assert_eq!(c.call::<u32, u32>(1, &5).unwrap(), 10);
}
