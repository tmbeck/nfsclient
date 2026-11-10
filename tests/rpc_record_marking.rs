//! TCP record marking (RFC 5531 section 11) edge cases against a fake server
//! on 127.0.0.1: oversized records, headers and fragments split across reads,
//! and a server that closes the connection in the middle of a record.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nfsc::error::Error;
use nfsc::rpc::{Auth, PortMode, Proto, RpcClient, RpcOptions};

const PROG: u32 = 0x2000_0043;
const VERS: u32 = 1;
/// Procedure that doubles a u32 argument.
const DOUBLE: u32 = 1;
const LAST: u32 = 0x8000_0000;

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
}

/// (xid, argument) from a CALL record with AUTH_NONE credentials.
fn parse_call(msg: &[u8]) -> (u32, u32) {
    let mut off = 24;
    for _ in 0..2 {
        off += 4;
        off += 4 + (u32_at(msg, off) as usize).div_ceil(4) * 4;
    }
    (u32_at(msg, 0), u32_at(msg, off))
}

/// Accepted/SUCCESS reply with `arg * 2` as the body.
fn double_reply(xid: u32, arg: u32) -> Vec<u8> {
    let mut v = Vec::new();
    for w in [xid, 1, 0, 0, 0, 0, arg.wrapping_mul(2)] {
        v.extend_from_slice(&w.to_be_bytes());
    }
    v
}

fn read_record(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).ok()?;
        let w = u32::from_be_bytes(hdr);
        let mut frag = vec![0u8; (w & !LAST) as usize];
        s.read_exact(&mut frag).ok()?;
        out.extend_from_slice(&frag);
        if w & LAST != 0 {
            return Some(out);
        }
    }
}

/// Write `body` as one last-fragment record.
fn write_record(s: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let mut rec = (LAST | body.len() as u32).to_be_bytes().to_vec();
    rec.extend_from_slice(body);
    s.write_all(&rec)
}

/// Answer every call on `s` normally.
fn serve_normally(mut s: TcpStream) {
    while let Some(call) = read_record(&mut s) {
        let (xid, arg) = parse_call(&call);
        if write_record(&mut s, &double_reply(xid, arg)).is_err() {
            return;
        }
    }
}

/// Accept connections; connection `i` is handled by `per_conn(stream, i)`.
fn spawn_tcp<F>(per_conn: F) -> SocketAddr
where
    F: Fn(TcpStream, usize) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let per_conn = Arc::new(per_conn);
    thread::spawn(move || {
        for (i, conn) in listener.incoming().enumerate() {
            let Ok(s) = conn else { return };
            s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
            let f = Arc::clone(&per_conn);
            thread::spawn(move || f(s, i));
        }
    });
    addr
}

fn client(addr: SocketAddr, timeout: Duration) -> RpcClient {
    let opts = RpcOptions {
        proto: Proto::Tcp,
        port_mode: PortMode::Unprivileged,
        timeout,
        auth: Auth::None,
        ..RpcOptions::default()
    };
    RpcClient::connect(addr, PROG, VERS, &opts).unwrap()
}

/// On connection 0, read one call and run `misbehave`; later connections are normal.
fn first_conn_misbehaves<F>(misbehave: F) -> SocketAddr
where
    F: Fn(&mut TcpStream, u32, u32) + Send + Sync + 'static,
{
    spawn_tcp(move |mut s, i| {
        if i == 0 {
            if let Some(call) = read_record(&mut s) {
                let (xid, arg) = parse_call(&call);
                misbehave(&mut s, xid, arg);
            }
            return;
        }
        serve_normally(s);
    })
}

#[test]
fn oversized_record_header_is_rejected_without_waiting() {
    let addr = first_conn_misbehaves(|s, _, _| {
        // Claims a 2 GiB last fragment, then sends nothing more.
        s.write_all(&(LAST | 0x7fff_ffff).to_be_bytes()).unwrap();
        thread::sleep(Duration::from_secs(5));
    });
    let mut c = client(addr, Duration::from_secs(10));
    let started = Instant::now();
    let r = c.call::<u32, u32>(DOUBLE, &1);
    assert!(
        matches!(r, Err(Error::Protocol(ref m)) if m.contains("exceeds")),
        "{r:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    // The bad stream was dropped; the next call reconnects.
    assert_eq!(c.call::<u32, u32>(DOUBLE, &21).unwrap(), 42);
}

#[test]
fn oversized_record_across_fragments_is_rejected() {
    let addr = first_conn_misbehaves(|s, _, _| {
        // A 48 MiB non-last fragment (allowed), then a 32 MiB one that takes
        // the record past the limit.
        let first = 48usize << 20;
        if s.write_all(&(first as u32).to_be_bytes()).is_err() {
            return;
        }
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..first >> 20 {
            if s.write_all(&zeros).is_err() {
                return;
            }
        }
        let _ = s.write_all(&(LAST | (32 << 20)).to_be_bytes());
        thread::sleep(Duration::from_secs(5));
    });
    let mut c = client(addr, Duration::from_secs(10));
    let r = c.call::<u32, u32>(DOUBLE, &1);
    assert!(
        matches!(r, Err(Error::Protocol(ref m)) if m.contains("exceeds")),
        "{r:?}"
    );
    assert_eq!(c.call::<u32, u32>(DOUBLE, &5).unwrap(), 10);
}

#[test]
fn header_and_fragments_split_across_reads() {
    let addr = spawn_tcp(|mut s, _| {
        s.set_nodelay(true).unwrap();
        while let Some(call) = read_record(&mut s) {
            let (xid, arg) = parse_call(&call);
            let body = double_reply(xid, arg);
            // Three fragments (one of them empty), every header and payload
            // byte written separately with a pause, so each read sees a piece.
            let (a, b) = body.split_at(10);
            let mut wire = Vec::new();
            for (frag, last) in [(a, false), (&[][..], false), (b, true)] {
                let hdr = if last { LAST } else { 0 } | frag.len() as u32;
                wire.extend_from_slice(&hdr.to_be_bytes());
                wire.extend_from_slice(frag);
            }
            for byte in wire {
                if s.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(2));
            }
        }
    });
    let mut c = client(addr, Duration::from_secs(10));
    for arg in [1u32, 1000, 7] {
        assert_eq!(c.call::<u32, u32>(DOUBLE, &arg).unwrap(), arg * 2);
    }
}

#[test]
fn server_closes_mid_fragment() {
    let addr = first_conn_misbehaves(|s, xid, arg| {
        let body = double_reply(xid, arg);
        // The header promises the whole reply; only part of it is sent.
        s.write_all(&(LAST | body.len() as u32).to_be_bytes())
            .unwrap();
        s.write_all(&body[..10]).unwrap();
        // Returning closes the connection.
    });
    let mut c = client(addr, Duration::from_secs(10));
    let started = Instant::now();
    let r = c.call::<u32, u32>(DOUBLE, &1);
    match &r {
        Err(e @ Error::Io(io)) => {
            assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof, "{e:?}");
            assert!(e.is_retryable());
        }
        other => panic!("expected an EOF error, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "no wait for the timeout"
    );
    assert_eq!(c.call::<u32, u32>(DOUBLE, &4).unwrap(), 8);
}

#[test]
fn server_closes_mid_header() {
    let addr = first_conn_misbehaves(|s, _, _| {
        s.write_all(&[0x80, 0x00]).unwrap();
    });
    let mut c = client(addr, Duration::from_secs(10));
    let r = c.call::<u32, u32>(DOUBLE, &1);
    assert!(r.as_ref().is_err_and(Error::is_retryable), "{r:?}");
    assert_eq!(c.call::<u32, u32>(DOUBLE, &9).unwrap(), 18);
}

#[test]
fn reply_split_into_many_fragments_is_reassembled() {
    let addr = spawn_tcp(|mut s, _| {
        while let Some(call) = read_record(&mut s) {
            let (xid, arg) = parse_call(&call);
            let body = double_reply(xid, arg);
            for (i, piece) in body.chunks(1).enumerate() {
                let last = if i + 1 == body.len() { LAST } else { 0 };
                let _ = s.write_all(&(last | 1).to_be_bytes());
                let _ = s.write_all(piece);
            }
        }
    });
    let mut c = client(addr, Duration::from_secs(10));
    assert_eq!(c.call::<u32, u32>(DOUBLE, &123).unwrap(), 246);
}
