//! Pipelined RPC (send_call / recv_reply) against fake servers on 127.0.0.1.
//!
//! The fake server answers in an order the client does not expect, drops the
//! connection, or stays silent, to check xid matching and recovery.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use nfsc::error::Error;
use nfsc::rpc::{Auth, PortMode, Proto, RpcClient, RpcOptions};

const PROG: u32 = 0x2000_0042;
const VERS: u32 = 3;
/// Procedure that doubles a u32 argument.
const DOUBLE: u32 = 1;

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// (xid, procedure, argument) from a CALL record with AUTH_NONE credentials.
fn parse_call(msg: &[u8]) -> (u32, u32, u32) {
    assert_eq!(u32_at(msg, 4), 0, "CALL");
    assert_eq!(u32_at(msg, 12), PROG);
    let proc_ = u32_at(msg, 20);
    // credential and verifier: flavor, length, body (empty for AUTH_NONE)
    let mut off = 24;
    for _ in 0..2 {
        off += 4;
        let len = u32_at(msg, off) as usize;
        off += 4 + len.div_ceil(4) * 4;
    }
    (u32_at(msg, 0), proc_, u32_at(msg, off))
}

fn reply(xid: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&xid.to_be_bytes());
    v.extend_from_slice(&1u32.to_be_bytes()); // REPLY
    v.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
    v.extend_from_slice(&[0; 8]); // verifier: AUTH_NONE, empty
    v.extend_from_slice(&0u32.to_be_bytes()); // SUCCESS
    v.extend_from_slice(body);
    v
}

fn double_reply(xid: u32, arg: u32) -> Vec<u8> {
    reply(xid, &(arg * 2).to_be_bytes())
}

fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).ok()?;
    let len = (u32::from_be_bytes(hdr) & 0x7fff_ffff) as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).ok()?;
    Some(body)
}

fn write_record(s: &mut TcpStream, body: &[u8]) {
    s.write_all(&(0x8000_0000u32 | body.len() as u32).to_be_bytes())
        .unwrap();
    s.write_all(body).unwrap();
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

/// Accepts connections in a loop. Each connection is handled by `per_conn(stream, conn_index)`.
fn spawn_tcp<F>(per_conn: F) -> SocketAddr
where
    F: Fn(TcpStream, usize) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let per_conn = std::sync::Arc::new(per_conn);
        for (i, conn) in listener.incoming().enumerate() {
            let Ok(s) = conn else { return };
            let f = per_conn.clone();
            thread::spawn(move || f(s, i));
        }
    });
    addr
}

/// Read `n` calls, then answer them in reverse order.
fn reverse_batches(n: usize) -> SocketAddr {
    spawn_tcp(move |mut s, _| {
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        loop {
            let mut batch = Vec::new();
            for _ in 0..n {
                let Some(rec) = read_record(&mut s) else {
                    return;
                };
                batch.push(parse_call(&rec));
            }
            for (xid, _proc, arg) in batch.into_iter().rev() {
                write_record(&mut s, &double_reply(xid, arg));
            }
        }
    })
}

fn pipelined_client(addr: SocketAddr, timeout: Duration) -> RpcClient {
    RpcClient::connect(addr, PROG, VERS, &opts(Proto::Tcp, timeout)).unwrap()
}

#[test]
fn out_of_order_replies_are_matched_by_xid() {
    let addr = reverse_batches(8);
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    assert!(c.pipelined());
    let xids: Vec<u32> = (0..8)
        .map(|i| c.send_call(DOUBLE, &(i as u32 + 1)).unwrap())
        .collect();
    assert_eq!(c.outstanding(), 8);
    for (i, xid) in xids.iter().enumerate() {
        let got: u32 = c.recv_reply(*xid).unwrap();
        assert_eq!(got, (i as u32 + 1) * 2, "reply for call {i}");
    }
    assert_eq!(c.outstanding(), 0);
}

#[test]
fn replies_can_be_claimed_in_any_order() {
    let addr = reverse_batches(4);
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let xids: Vec<u32> = (10..14).map(|a| c.send_call(DOUBLE, &a).unwrap()).collect();
    // The reverse-order server means the last call's reply arrives first and is buffered.
    let last: u32 = c.recv_reply(xids[3]).unwrap();
    assert_eq!(last, 26);
    let first: u32 = c.recv_reply(xids[0]).unwrap();
    assert_eq!(first, 20);
    let second: u32 = c.recv_reply(xids[1]).unwrap();
    assert_eq!(second, 22);
    let third: u32 = c.recv_reply(xids[2]).unwrap();
    assert_eq!(third, 24);
}

#[test]
fn blocking_call_works_alongside_outstanding_calls() {
    let addr = spawn_tcp(|mut s, _| {
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        // Answer every call immediately, in arrival order.
        while let Some(rec) = read_record(&mut s) {
            let (xid, _, arg) = parse_call(&rec);
            write_record(&mut s, &double_reply(xid, arg));
        }
    });
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let a = c.send_call(DOUBLE, &5u32).unwrap();
    let b: u32 = c.call(DOUBLE, &7u32).unwrap();
    assert_eq!(b, 14);
    let a_reply: u32 = c.recv_reply(a).unwrap();
    assert_eq!(a_reply, 10);
}

#[test]
fn stale_and_unknown_replies_are_ignored() {
    let addr = spawn_tcp(|mut s, _| {
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        while let Some(rec) = read_record(&mut s) {
            let (xid, _, arg) = parse_call(&rec);
            // Garbage first: a reply to an xid nobody sent, then the real reply.
            write_record(&mut s, &double_reply(xid.wrapping_add(1_000_000), 1));
            write_record(&mut s, &double_reply(xid, arg));
        }
    });
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let x1 = c.send_call(DOUBLE, &3u32).unwrap();
    let x2 = c.send_call(DOUBLE, &4u32).unwrap();
    assert_eq!(c.recv_reply::<u32>(x2).unwrap(), 8);
    assert_eq!(c.recv_reply::<u32>(x1).unwrap(), 6);
}

#[test]
fn unknown_xid_is_an_error_not_a_hang() {
    let addr = reverse_batches(1);
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let started = Instant::now();
    let r: Result<u32, Error> = c.recv_reply(0xdead_beef);
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn discard_outstanding_drops_calls_and_connection_still_works() {
    let addr = reverse_batches(1);
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let abandoned = c.send_call(DOUBLE, &1u32).unwrap();
    c.discard_outstanding();
    assert_eq!(c.outstanding(), 0);
    assert!(c.recv_reply::<u32>(abandoned).is_err());
    // The late reply to the abandoned call is skipped; the next call is answered.
    let v: u32 = c.call(DOUBLE, &21u32).unwrap();
    assert_eq!(v, 42);
}

#[test]
fn dropped_connection_fails_outstanding_calls_and_reconnects() {
    // Connection 0 reads two calls and closes without answering. Later connections answer normally.
    let addr = spawn_tcp(|mut s, conn| {
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        if conn == 0 {
            let _ = read_record(&mut s);
            let _ = read_record(&mut s);
            return;
        }
        while let Some(rec) = read_record(&mut s) {
            let (xid, _, arg) = parse_call(&rec);
            write_record(&mut s, &double_reply(xid, arg));
        }
    });
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let a = c.send_call(DOUBLE, &1u32).unwrap();
    let b = c.send_call(DOUBLE, &2u32).unwrap();
    assert!(
        c.recv_reply::<u32>(a).is_err(),
        "connection closed under pending calls"
    );
    assert!(c.recv_reply::<u32>(b).is_err());
    assert_eq!(c.outstanding(), 0);
    // A new call reconnects (the server accepts a second connection).
    let v: u32 = c.call(DOUBLE, &50u32).unwrap();
    assert_eq!(v, 100);
}

#[test]
fn silent_server_times_out_then_client_is_usable() {
    let addr = spawn_tcp(|mut s, conn| {
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        if conn == 0 {
            // Never answer; hold the connection open until the client gives up.
            let _ = read_record(&mut s);
            thread::sleep(Duration::from_millis(600));
            return;
        }
        while let Some(rec) = read_record(&mut s) {
            let (xid, _, arg) = parse_call(&rec);
            write_record(&mut s, &double_reply(xid, arg));
        }
    });
    let mut c = pipelined_client(addr, Duration::from_millis(300));
    let x = c.send_call(DOUBLE, &9u32).unwrap();
    let r: Result<u32, Error> = c.recv_reply(x);
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert_eq!(c.outstanding(), 0);
    let v: u32 = c.call(DOUBLE, &4u32).unwrap();
    assert_eq!(v, 8);
}

#[test]
fn large_window_of_pipelined_calls() {
    let addr = reverse_batches(16);
    let mut c = pipelined_client(addr, Duration::from_secs(20));
    for round in 0..4u32 {
        let xids: Vec<u32> = (0..16)
            .map(|i| c.send_call(DOUBLE, &(round * 100 + i)).unwrap())
            .collect();
        for (i, x) in xids.iter().enumerate() {
            let v: u32 = c.recv_reply(*x).unwrap();
            assert_eq!(v, (round * 100 + i as u32) * 2);
        }
    }
}

#[test]
fn udp_send_call_completes_synchronously_and_recv_returns_reply() {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = sock.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf) else {
                return;
            };
            let (xid, _, arg) = parse_call(&buf[..n]);
            sock.send_to(&double_reply(xid, arg), peer).unwrap();
        }
    });
    let mut c =
        RpcClient::connect(addr, PROG, VERS, &opts(Proto::Udp, Duration::from_secs(5))).unwrap();
    assert!(!c.pipelined());
    let a = c.send_call(DOUBLE, &6u32).unwrap();
    let b = c.send_call(DOUBLE, &7u32).unwrap();
    assert_eq!(c.recv_reply::<u32>(b).unwrap(), 14);
    assert_eq!(c.recv_reply::<u32>(a).unwrap(), 12);
}

#[test]
fn send_call_on_a_dead_port_reports_an_error() {
    // Nothing listens here: the connect (inside send_call) must fail, not hang.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let r = RpcClient::connect(addr, PROG, VERS, &opts(Proto::Tcp, Duration::from_secs(2)));
    assert!(r.is_err());
}

#[test]
fn replies_received_before_a_drop_stay_claimable() {
    // Connection 0 reads three calls, answers the last two (newest first) and
    // closes without answering the first.
    let addr = spawn_tcp(|mut s, conn| {
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        if conn == 0 {
            let calls: Vec<_> = (0..3).filter_map(|_| read_record(&mut s)).collect();
            for rec in calls.iter().skip(1).rev() {
                let (xid, _, arg) = parse_call(rec);
                write_record(&mut s, &double_reply(xid, arg));
            }
            return;
        }
        while let Some(rec) = read_record(&mut s) {
            let (xid, _, arg) = parse_call(&rec);
            write_record(&mut s, &double_reply(xid, arg));
        }
    });
    let mut c = pipelined_client(addr, Duration::from_secs(10));
    let a = c.send_call(DOUBLE, &1u32).unwrap();
    let b = c.send_call(DOUBLE, &2u32).unwrap();
    let d = c.send_call(DOUBLE, &3u32).unwrap();
    // Waiting for `a` buffers the replies to `d` and `b`, then hits the close.
    assert!(c.recv_reply::<u32>(a).is_err());
    assert_eq!(c.outstanding(), 0);
    // The replies that did arrive are not thrown away with the connection.
    assert_eq!(c.recv_reply::<u32>(b).unwrap(), 4);
    assert_eq!(c.recv_reply::<u32>(d).unwrap(), 6);
    assert_eq!(c.call::<u32, u32>(DOUBLE, &50).unwrap(), 100);
}
