//! TCP (record marking, RFC 5531 section 11) and UDP (retransmit) transports,
//! plus local source-port selection. (rpc agent owns this file.)
//!
//! Reserved source ports: Privileged and Auto modes try local ports 1023 down
//! to 512 for both transports. TCP uses socket2 for bind-before-connect; UDP
//! uses std's UdpSocket::bind followed by connect.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{PortMode, Proto, RpcOptions};
use crate::error::{Error, Result};
use crate::xdr::MAX_ITEM_LEN;

/// Largest reassembled TCP reply we accept (payload plus slack for headers).
const MAX_RECORD: usize = MAX_ITEM_LEN + 64 * 1024;
/// High bit of a record-marking header: last fragment of the record.
const LAST_FRAGMENT: u32 = 0x8000_0000;
/// Big enough for any UDP datagram (max 65507 bytes of payload over IPv4).
const UDP_BUF: usize = 65536;
const UDP_FIRST_INTERVAL: Duration = Duration::from_secs(1);
const UDP_MAX_INTERVAL: Duration = Duration::from_secs(8);
const RESERVED_LO: u16 = 512;
const RESERVED_HI: u16 = 1023;

const WARN_RESERVED: &str = "cannot bind a reserved port (need root or CAP_NET_BIND_SERVICE)";

/// Set once the fallback warning has been printed.
static WARNED: AtomicBool = AtomicBool::new(false);

/// Print the unprivileged-fallback warning, at most once per process.
fn warn_fallback(reason: &str) {
    if !WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "nfsc: warning: {reason}; using an unprivileged port, \
             servers exporting with 'secure' may reject requests"
        );
    }
}

/// A random-ish starting xid, from the clock, pid and std's per-process hash seed.
pub fn initial_xid() -> u32 {
    let mut h = RandomState::new().build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h.write_u128(nanos);
    h.write_u32(std::process::id());
    h.finish() as u32
}

enum Conn {
    /// `None` means the stream was lost; it is re-established on the next call.
    Tcp(Option<TcpStream>),
    Udp(UdpSocket),
}

pub struct Transport {
    addr: SocketAddr,
    timeout: Duration,
    port_mode: PortMode,
    conn: Conn,
}

fn map_io(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Error::Timeout,
        _ => Error::Io(e),
    }
}

/// Time left until `end`, or `None` if it has passed.
fn remaining_until(end: Instant) -> Option<Duration> {
    end.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}

/// Outcome of trying to connect from a reserved TCP source port.
enum Reserved {
    Connected(TcpStream),
    /// Every port in 512..=1023 was in use.
    Exhausted,
    /// bind(2) failed for a reason other than EADDRINUSE (EACCES/EPERM, ...).
    BindFailed(io::Error),
}

fn unspecified(peer: SocketAddr) -> IpAddr {
    match peer {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn new_tcp_socket(peer: SocketAddr) -> io::Result<Socket> {
    Socket::new(Domain::for_address(peer), Type::STREAM, Some(Protocol::TCP))
}

fn finish_tcp(stream: TcpStream) -> Result<TcpStream> {
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Bind-before-connect from ports 1023 down to 512. A port that is in use
/// (EADDRINUSE at bind, or at connect when a TIME_WAIT 4-tuple collides)
/// is skipped and the next one is tried. Each attempt gets a fresh socket,
/// since a failed connect leaves the old one unusable.
fn connect_reserved(peer: SocketAddr, timeout: Duration) -> Result<Reserved> {
    for port in (RESERVED_LO..=RESERVED_HI).rev() {
        let sock = new_tcp_socket(peer)?;
        match sock.bind(&SockAddr::from(SocketAddr::new(unspecified(peer), port))) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Ok(Reserved::BindFailed(e)),
        }
        match sock.connect_timeout(&SockAddr::from(peer), timeout) {
            Ok(()) => return Ok(Reserved::Connected(sock.into())),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::AddrNotAvailable
                ) =>
            {
                continue;
            }
            Err(e) => return Err(map_io(e)),
        }
    }
    Ok(Reserved::Exhausted)
}

/// Connect to `peer` according to `mode`. Returns (stream, privileged).
fn connect_tcp(peer: SocketAddr, timeout: Duration, mode: PortMode) -> Result<(TcpStream, bool)> {
    if mode != PortMode::Unprivileged {
        match connect_reserved(peer, timeout)? {
            Reserved::Connected(stream) => return Ok((finish_tcp(stream)?, true)),
            Reserved::Exhausted => {
                if mode == PortMode::Privileged {
                    return Err(Error::Invalid(format!(
                        "no free reserved source port in {RESERVED_LO}..={RESERVED_HI}"
                    )));
                }
                warn_fallback(WARN_RESERVED);
            }
            Reserved::BindFailed(e) => {
                if mode == PortMode::Privileged {
                    return Err(Error::Invalid(format!(
                        "cannot bind a reserved source port (need root or CAP_NET_BIND_SERVICE): {e}"
                    )));
                }
                if e.kind() != io::ErrorKind::PermissionDenied {
                    return Err(Error::Io(e));
                }
                warn_fallback(WARN_RESERVED);
            }
        }
    }
    let sock = new_tcp_socket(peer)?;
    sock.connect_timeout(&SockAddr::from(peer), timeout).map_err(map_io)?;
    Ok((finish_tcp(sock.into())?, false))
}

impl Transport {
    /// Returns the transport and whether the local port is privileged.
    ///
    /// TCP: `Privileged` is an error (no reserved TCP source ports in std).
    /// `Auto` connects from an ephemeral port and warns once. `Unprivileged`
    /// connects from an ephemeral port silently.
    pub fn connect(addr: SocketAddr, opts: &RpcOptions) -> Result<(Self, bool)> {
        if opts.timeout.is_zero() {
            return Err(Error::Invalid("RPC timeout must be non-zero".to_string()));
        }
        let (conn, privileged) = match opts.proto {
            Proto::Tcp => {
                let (stream, privileged) = connect_tcp(addr, opts.timeout, opts.port_mode)?;
                (Conn::Tcp(Some(stream)), privileged)
            }
            Proto::Udp => {
                let (sock, privileged) = bind_udp(addr, opts.port_mode)?;
                sock.connect(addr)?;
                (Conn::Udp(sock), privileged)
            }
        };
        Ok((Transport { addr, timeout: opts.timeout, port_mode: opts.port_mode, conn }, privileged))
    }

    /// UDP only: send one call and return the raw bytes of the reply whose xid
    /// matches, retransmitting with backoff (other xids are skipped).
    pub fn round_trip(&mut self, xid: u32, msg: &[u8]) -> Result<Vec<u8>> {
        match &mut self.conn {
            Conn::Udp(sock) => udp_round_trip(sock, self.timeout, xid, msg),
            Conn::Tcp(_) => Err(Error::Invalid("round_trip is UDP-only; use send_record".into())),
        }
    }

    /// TCP only: write one call record, reconnecting first if the stream was
    /// lost. Does not wait for a reply. Any failure drops the stream.
    pub fn send_record(&mut self, msg: &[u8]) -> Result<()> {
        let (addr, timeout, mode) = (self.addr, self.timeout, self.port_mode);
        let Conn::Tcp(slot) = &mut self.conn else {
            return Err(Error::Invalid("send_record is TCP-only".into()));
        };
        if slot.is_none() {
            // A reconnect may land on a different privilege level; the
            // `privileged` flag reported at connect time is not updated.
            *slot = Some(connect_tcp(addr, timeout, mode)?.0);
        }
        let stream = slot.as_mut().expect("stream was just ensured");
        let result = tcp_send(stream, timeout, msg);
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// TCP only: the next reply record on the stream, whatever its xid, read
    /// before `deadline`. Any failure drops the stream.
    pub fn recv_record(&mut self, deadline: Instant) -> Result<Vec<u8>> {
        let Conn::Tcp(slot) = &mut self.conn else {
            return Err(Error::Invalid("recv_record is TCP-only".into()));
        };
        let Some(stream) = slot.as_mut() else {
            return Err(Error::Io(io::Error::new(io::ErrorKind::NotConnected, "connection was lost")));
        };
        let result = read_record(stream, deadline);
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// Drop the TCP stream, if any, so the next send reconnects. Replies still
    /// in flight on the old stream are lost.
    pub fn reset(&mut self) {
        if let Conn::Tcp(slot) = &mut self.conn {
            *slot = None;
        }
    }

    pub fn proto(&self) -> Proto {
        match self.conn {
            Conn::Tcp(_) => Proto::Tcp,
            Conn::Udp(_) => Proto::Udp,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Bind a UDP socket for `peer` according to `mode`. Returns (socket, privileged).
fn bind_udp(peer: SocketAddr, mode: PortMode) -> Result<(UdpSocket, bool)> {
    let any = if peer.is_ipv4() { "0.0.0.0" } else { "::" };
    if mode != PortMode::Unprivileged {
        match bind_reserved(any) {
            Ok(Some(sock)) => return Ok((sock, true)),
            Ok(None) => {
                if mode == PortMode::Privileged {
                    return Err(Error::Invalid(format!(
                        "no free reserved source port in {RESERVED_LO}..={RESERVED_HI}"
                    )));
                }
                warn_fallback(WARN_RESERVED);
            }
            Err(e) => {
                if mode == PortMode::Privileged {
                    return Err(Error::Invalid(format!(
                        "cannot bind a reserved source port (need root or CAP_NET_BIND_SERVICE): {e}"
                    )));
                }
                if e.kind() != io::ErrorKind::PermissionDenied {
                    return Err(Error::Io(e));
                }
                warn_fallback(WARN_RESERVED);
            }
        }
    }
    Ok((UdpSocket::bind(format!("{any}:0"))?, false))
}

/// Try reserved ports from 1023 down to 512. `Ok(None)` if all are in use.
fn bind_reserved(ip: &str) -> io::Result<Option<UdpSocket>> {
    for port in (RESERVED_LO..=RESERVED_HI).rev() {
        match UdpSocket::bind((ip, port)) {
            Ok(sock) => return Ok(Some(sock)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Write one call message as a single last-fragment record.
fn tcp_send(stream: &mut TcpStream, timeout: Duration, msg: &[u8]) -> Result<()> {
    let len = u32::try_from(msg.len())
        .ok()
        .filter(|&n| n & LAST_FRAGMENT == 0)
        .ok_or_else(|| Error::Invalid("RPC message too large".to_string()))?;
    let mut frame = Vec::with_capacity(4 + msg.len());
    frame.extend_from_slice(&(LAST_FRAGMENT | len).to_be_bytes());
    frame.extend_from_slice(msg);
    stream.set_write_timeout(Some(timeout)).map_err(map_io)?;
    stream.write_all(&frame).map_err(map_io)
}

/// Read one record, reassembling fragments, under the overall `deadline`.
fn read_record(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut record = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        read_full(stream, &mut hdr, deadline)?;
        let word = u32::from_be_bytes(hdr);
        let last = word & LAST_FRAGMENT != 0;
        let len = (word & !LAST_FRAGMENT) as usize;
        if record.len() + len > MAX_RECORD {
            return Err(Error::Protocol(format!("reply record exceeds {MAX_RECORD} bytes")));
        }
        let start = record.len();
        record.resize(start + len, 0);
        read_full(stream, &mut record[start..], deadline)?;
        if last {
            return Ok(record);
        }
    }
}

fn read_full(stream: &mut TcpStream, mut buf: &mut [u8], deadline: Instant) -> Result<()> {
    while !buf.is_empty() {
        let left = remaining_until(deadline).ok_or(Error::Timeout)?;
        stream.set_read_timeout(Some(left)).map_err(map_io)?;
        match stream.read(buf) {
            Ok(0) => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed by peer",
                )));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(map_io(e)),
        }
    }
    Ok(())
}

/// Send, then wait for the matching reply; retransmit the same message with
/// exponential backoff until `timeout` has elapsed overall.
fn udp_round_trip(sock: &UdpSocket, timeout: Duration, xid: u32, msg: &[u8]) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let want = xid.to_be_bytes();
    let mut buf = vec![0u8; UDP_BUF];
    let mut interval = UDP_FIRST_INTERVAL;
    loop {
        match sock.send(msg) {
            Ok(_) => {}
            // A pending ICMP error from an earlier datagram; the wait below covers it.
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
            Err(e) => return Err(map_io(e)),
        }
        let attempt_end = (Instant::now() + interval).min(deadline);
        while let Some(left) = remaining_until(attempt_end) {
            sock.set_read_timeout(Some(left)).map_err(map_io)?;
            match sock.recv(&mut buf) {
                Ok(n) => {
                    if n >= 4 && buf[..4] == want {
                        buf.truncate(n);
                        return Ok(buf);
                    }
                    // Datagram for another call: ignore.
                }
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(map_io(e)),
            }
        }
        if remaining_until(deadline).is_none() {
            return Err(Error::Timeout);
        }
        interval = (interval * 2).min(UDP_MAX_INTERVAL);
    }
}
