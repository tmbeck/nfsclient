//! Windowed pipelining for bulk READ and WRITE transfers.
//!
//! The engines here are protocol-agnostic. A backend implements [`ReadIo`] or
//! [`WriteIo`] on top of its own RPC calls (NFSv3 procedures, or NFSv4 COMPOUNDs
//! with a session slot), and the engine keeps up to `window` requests in
//! flight, consumes replies in order and handles the hard cases:
//!
//! - READ: a short reply that is not at EOF is re-requested from the first
//!   missing byte, so the sink never sees a hole or a duplicate.
//! - WRITE: UNSTABLE writes are retained until a COMMIT covers them. If the
//!   write verifier at COMMIT differs from the one a write was acknowledged
//!   under, the server lost that data and it is sent again. Retained data is
//!   bounded by [`COMMIT_INTERVAL`] plus the window.
//! - Any failed request ends the pipeline: outstanding replies are drained, and
//!   READ continues with blocking reads (which carry the backend's retry and
//!   session recovery). WRITE reports the error.

use std::collections::VecDeque;

use crate::error::{Error, Result};

/// Requests kept in flight by default.
pub const DEFAULT_WINDOW: usize = 8;
/// Unstable write data is committed once this many bytes await a COMMIT.
pub const COMMIT_INTERVAL: u64 = 64 << 20;
/// Consecutive COMMIT rounds that may end with a verifier mismatch before giving up.
const MAX_COMMIT_ROUNDS: u32 = 8;

/// One READ request/reply pipeline on a backend.
pub(crate) trait ReadIo {
    /// Identifies one outstanding request.
    type Tag: Copy;

    /// Send a READ of `count` bytes at `offset` without waiting for the reply.
    fn issue(&mut self, offset: u64, count: u32) -> Result<Self::Tag>;

    /// Wait for the reply to `tag`: returns (data, eof).
    fn complete(&mut self, tag: Self::Tag) -> Result<(Vec<u8>, bool)>;

    /// A blocking READ with the backend's usual retry and recovery.
    fn read_sync(&mut self, offset: u64, count: u32) -> Result<(Vec<u8>, bool)>;
}

/// One WRITE pipeline on a backend. Writes are UNSTABLE.
pub(crate) trait WriteIo {
    type Tag: Copy;

    /// Send an UNSTABLE WRITE of `data` at `offset` without waiting.
    fn issue(&mut self, offset: u64, data: &[u8]) -> Result<Self::Tag>;

    /// Wait for the reply to `tag`.
    fn complete(&mut self, tag: Self::Tag) -> Result<WriteAck>;

    /// COMMIT the byte range `offset..offset+count` (count 0 means to the end
    /// of the file). Returns the server's write verifier.
    fn commit(&mut self, offset: u64, count: u32) -> Result<[u8; 8]>;
}

/// The part of a WRITE reply the engine needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriteAck {
    /// Bytes the server accepted from the start of the request.
    pub count: u32,
    /// True when the server stored the data stably (FILE_SYNC); no COMMIT is needed.
    pub durable: bool,
    pub verf: [u8; 8],
}

/// Stream `len` bytes (or to EOF) from `offset` into `sink`, in order, using up
/// to `window` READs of at most `chunk` bytes in flight. Returns the bytes
/// delivered. A sink error stops the transfer after the outstanding replies are
/// drained, and that error is returned.
pub(crate) fn read_pipelined<I: ReadIo>(
    io: &mut I,
    offset: u64,
    len: Option<u64>,
    chunk: u32,
    window: usize,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let chunk = chunk.max(1);
    let window = window.max(1);
    let end = len.map(|l| offset.saturating_add(l));
    // Next byte to hand to the sink.
    let mut delivered = offset;
    // Next byte to request.
    let mut next = offset;
    let mut inflight: VecDeque<(I::Tag, u64, u32)> = VecDeque::new();
    let mut issuing = true;
    // Set after a pipelined request failed; the rest is read with blocking calls.
    let mut fell_back = false;

    loop {
        while issuing && !fell_back && inflight.len() < window {
            let want = match end {
                Some(e) if next >= e => {
                    issuing = false;
                    break;
                }
                Some(e) => (e - next).min(u64::from(chunk)) as u32,
                None => chunk,
            };
            match io.issue(next, want) {
                Ok(tag) => {
                    inflight.push_back((tag, next, want));
                    next += u64::from(want);
                }
                Err(_) => {
                    fell_back = true;
                    break;
                }
            }
        }

        let (data, eof, want, off) = if let Some((tag, off, want)) = inflight.pop_front() {
            match io.complete(tag) {
                Ok((data, eof)) => (data, eof, want, off),
                Err(_) => {
                    drain_reads(io, &mut inflight);
                    fell_back = true;
                    continue;
                }
            }
        } else if fell_back {
            let want = match end {
                Some(e) if delivered >= e => break,
                Some(e) => (e - delivered).min(u64::from(chunk)) as u32,
                None => chunk,
            };
            let (data, eof) = io.read_sync(delivered, want)?;
            (data, eof, want, delivered)
        } else {
            break;
        };

        if data.len() > want as usize {
            drain_reads(io, &mut inflight);
            return Err(Error::Protocol(format!(
                "READ at {off} returned {} bytes for {want} requested",
                data.len()
            )));
        }
        if off != delivered {
            drain_reads(io, &mut inflight);
            return Err(Error::Protocol(format!(
                "READ reply for offset {off}, expected {delivered}"
            )));
        }
        if !data.is_empty() {
            if let Err(e) = sink(&data) {
                drain_reads(io, &mut inflight);
                return Err(e);
            }
            delivered += data.len() as u64;
        }

        let at_end = end.is_some_and(|e| delivered >= e);
        if at_end || eof || data.is_empty() {
            // Nothing past this point is wanted; outstanding replies are drained.
            drain_reads(io, &mut inflight);
            break;
        }
        if data.len() < want as usize && !fell_back {
            // Short read before EOF: refetch from the first missing byte. Requests
            // already sent past the gap are drained and dropped.
            drain_reads(io, &mut inflight);
            next = delivered;
            issuing = true;
        }
    }
    Ok(delivered - offset)
}

/// Wait for every outstanding READ and discard its reply.
fn drain_reads<I: ReadIo>(io: &mut I, inflight: &mut VecDeque<(I::Tag, u64, u32)>) {
    while let Some((tag, _, _)) = inflight.pop_front() {
        let _ = io.complete(tag);
    }
}

/// Keep one chunk of unstable data until a COMMIT covers it.
struct Retained {
    offset: u64,
    data: Vec<u8>,
    verf: [u8; 8],
}

struct Flight<T> {
    tag: T,
    offset: u64,
    data: Vec<u8>,
}

/// Write everything `source` produces, starting at `offset`, using up to
/// `window` unstable WRITEs of at most `chunk` bytes in flight. Data is durable
/// when this returns Ok (COMMIT done and its verifier matched). Returns the
/// bytes written.
pub(crate) fn write_pipelined<I: WriteIo>(
    io: &mut I,
    offset: u64,
    chunk: usize,
    window: usize,
    source: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
) -> Result<u64> {
    let chunk = chunk.max(1);
    let window = window.max(1);
    let mut inflight: VecDeque<Flight<I::Tag>> = VecDeque::new();
    let mut inflight_bytes: u64 = 0;
    // Chunks that must be (re)sent, from short writes or a verifier change.
    let mut resend: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut retained: Vec<Retained> = Vec::new();
    let mut retained_bytes: u64 = 0;
    let mut pos = offset;
    let mut source_done = false;
    let mut commit_rounds = 0u32;

    loop {
        while inflight.len() < window {
            let (off, data) = if let Some(r) = resend.pop_front() {
                r
            } else if !source_done && retained_bytes + inflight_bytes < COMMIT_INTERVAL {
                let mut buf = vec![0u8; chunk];
                let n = match fill(source, &mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        drain_writes(io, &mut inflight);
                        return Err(e);
                    }
                };
                if n == 0 {
                    source_done = true;
                    break;
                }
                buf.truncate(n);
                let off = pos;
                pos += n as u64;
                (off, buf)
            } else {
                break;
            };
            match io.issue(off, &data) {
                Ok(tag) => {
                    inflight_bytes += data.len() as u64;
                    inflight.push_back(Flight {
                        tag,
                        offset: off,
                        data,
                    });
                }
                Err(e) => {
                    drain_writes(io, &mut inflight);
                    return Err(e);
                }
            }
        }

        let Some(flight) = inflight.pop_front() else {
            if source_done && resend.is_empty() && retained.is_empty() {
                break;
            }
            if source_done || retained_bytes >= COMMIT_INTERVAL || !resend.is_empty() {
                if !retained.is_empty() {
                    let mismatched =
                        commit_round(io, &mut retained, &mut retained_bytes, &mut resend)?;
                    commit_rounds = if mismatched { commit_rounds + 1 } else { 0 };
                    if commit_rounds > MAX_COMMIT_ROUNDS {
                        return Err(Error::Protocol(
                            "server write verifier kept changing; giving up on unstable writes"
                                .into(),
                        ));
                    }
                }
                continue;
            }
            // Unreachable: the issue loop above always has work when nothing is in flight.
            return Err(Error::Protocol("write pipeline stalled".into()));
        };
        inflight_bytes -= flight.data.len() as u64;
        let ack = match io.complete(flight.tag) {
            Ok(ack) => ack,
            Err(e) => {
                drain_writes(io, &mut inflight);
                return Err(e);
            }
        };
        let n = ack.count as usize;
        if n == 0 || n > flight.data.len() {
            drain_writes(io, &mut inflight);
            return Err(Error::Protocol(format!(
                "server accepted {n} of {} bytes at offset {}",
                flight.data.len(),
                flight.offset
            )));
        }
        let mut data = flight.data;
        if n < data.len() {
            let rest = data.split_off(n);
            resend.push_back((flight.offset + n as u64, rest));
        }
        if !ack.durable {
            retained_bytes += n as u64;
            retained.push(Retained {
                offset: flight.offset,
                data,
                verf: ack.verf,
            });
        }
    }
    Ok(pos - offset)
}

/// Fill `buf` from `source` until it is full or the source reports end (0).
fn fill(source: &mut dyn FnMut(&mut [u8]) -> Result<usize>, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = source(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// COMMIT everything retained. Chunks acknowledged under the returned verifier
/// are durable. The rest are moved to `resend`. Returns whether any were moved.
fn commit_round<I: WriteIo>(
    io: &mut I,
    retained: &mut Vec<Retained>,
    retained_bytes: &mut u64,
    resend: &mut VecDeque<(u64, Vec<u8>)>,
) -> Result<bool> {
    let lo = retained.iter().map(|r| r.offset).min().unwrap_or(0);
    let hi = retained
        .iter()
        .map(|r| r.offset + r.data.len() as u64)
        .max()
        .unwrap_or(lo);
    // COMMIT count 0 means "to end of file", which covers the range too.
    let count = u32::try_from(hi - lo).unwrap_or(0);
    let verf = io.commit(lo, count)?;
    let mut mismatched = false;
    for r in retained.drain(..) {
        if r.verf == verf {
            continue;
        }
        mismatched = true;
        resend.push_back((r.offset, r.data));
    }
    *retained_bytes = 0;
    Ok(mismatched)
}

fn drain_writes<I: WriteIo>(io: &mut I, inflight: &mut VecDeque<Flight<I::Tag>>) {
    while let Some(f) = inflight.pop_front() {
        let _ = io.complete(f.tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory READ server. `short_every` makes every n-th reply return half the bytes.
    struct FakeReads {
        data: Vec<u8>,
        short_every: usize,
        served: usize,
        pending: VecDeque<(u64, u32, usize)>,
        next_tag: usize,
        max_outstanding: usize,
        fail_issue_at: Option<usize>,
        fail_complete_at: Option<usize>,
        issued: usize,
        sync_calls: usize,
    }

    impl FakeReads {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                short_every: 0,
                served: 0,
                pending: VecDeque::new(),
                next_tag: 0,
                max_outstanding: 0,
                fail_issue_at: None,
                fail_complete_at: None,
                issued: 0,
                sync_calls: 0,
            }
        }

        fn serve(&mut self, offset: u64, count: u32) -> (Vec<u8>, bool) {
            self.served += 1;
            let size = self.data.len() as u64;
            let start = offset.min(size) as usize;
            let mut n = (count as usize).min(self.data.len() - start);
            if self.short_every > 0 && self.served.is_multiple_of(self.short_every) && n > 1 {
                n /= 2;
            }
            let data = self.data[start..start + n].to_vec();
            let eof = offset + n as u64 >= size;
            (data, eof)
        }
    }

    impl ReadIo for FakeReads {
        type Tag = usize;

        fn issue(&mut self, offset: u64, count: u32) -> Result<usize> {
            self.issued += 1;
            if self.fail_issue_at == Some(self.issued) {
                return Err(Error::Timeout);
            }
            let tag = self.next_tag;
            self.next_tag += 1;
            self.pending.push_back((offset, count, tag));
            self.max_outstanding = self.max_outstanding.max(self.pending.len());
            Ok(tag)
        }

        fn complete(&mut self, tag: usize) -> Result<(Vec<u8>, bool)> {
            let (offset, count, t) = self.pending.pop_front().expect("reply without request");
            assert_eq!(t, tag, "replies must come back in request order here");
            if self.fail_complete_at == Some(t + 1) {
                return Err(Error::Timeout);
            }
            Ok(self.serve(offset, count))
        }

        fn read_sync(&mut self, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
            self.sync_calls += 1;
            Ok(self.serve(offset, count))
        }
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    fn run_read(
        fake: &mut FakeReads,
        offset: u64,
        len: Option<u64>,
        chunk: u32,
        window: usize,
    ) -> (Result<u64>, Vec<u8>) {
        let mut out = Vec::new();
        let r = read_pipelined(fake, offset, len, chunk, window, &mut |b: &[u8]| {
            out.extend_from_slice(b);
            Ok(())
        });
        (r, out)
    }

    #[test]
    fn read_round_trips_at_boundaries() {
        let data = pattern(1000);
        for &size in &[0usize, 1, 99, 100, 101, 999, 1000] {
            for &window in &[1usize, 3, 8] {
                for &chunk in &[1u32, 100, 1000, 4096] {
                    for &(offset, len) in &[
                        (0u64, None),
                        (0, Some(size as u64)),
                        (7, None),
                        (13, Some(50)),
                    ] {
                        let mut fake = FakeReads::new(data[..size].to_vec());
                        let (r, out) = run_read(&mut fake, offset, len, chunk, window);
                        let start = offset.min(size as u64);
                        let end = match len {
                            Some(l) => (offset + l).min(size as u64),
                            None => size as u64,
                        }
                        .max(start);
                        let expect: Vec<u8> = data[start as usize..end as usize].to_vec();
                        assert_eq!(
                            r.unwrap(),
                            expect.len() as u64,
                            "size {size} w{window} c{chunk} off {offset} len {len:?}"
                        );
                        assert_eq!(
                            out, expect,
                            "size {size} w{window} c{chunk} off {offset} len {len:?}"
                        );
                        assert_eq!(fake.pending.len(), 0, "all replies consumed");
                        assert!(fake.max_outstanding <= window);
                    }
                }
            }
        }
    }

    #[test]
    fn read_keeps_window_requests_in_flight() {
        let data = pattern(64 * 1024);
        let mut fake = FakeReads::new(data.clone());
        let (r, out) = run_read(&mut fake, 0, None, 1024, 8);
        assert_eq!(r.unwrap(), data.len() as u64);
        assert_eq!(out, data);
        assert_eq!(fake.max_outstanding, 8);
    }

    #[test]
    fn short_reads_in_the_middle_leave_no_holes() {
        let data = pattern(50_000);
        for window in [1usize, 2, 5, 8] {
            let mut fake = FakeReads::new(data.clone());
            fake.short_every = 3;
            let (r, out) = run_read(&mut fake, 0, None, 4096, window);
            assert_eq!(r.unwrap(), data.len() as u64);
            assert_eq!(out, data, "window {window}");
        }
    }

    #[test]
    fn short_read_with_limit_and_unaligned_offset() {
        let data = pattern(30_000);
        let mut fake = FakeReads::new(data.clone());
        fake.short_every = 2;
        let (r, out) = run_read(&mut fake, 1234, Some(20_000), 4000, 8);
        assert_eq!(r.unwrap(), 20_000);
        assert_eq!(out, data[1234..21_234]);
    }

    #[test]
    fn sink_error_aborts_and_drains() {
        let data = pattern(100_000);
        let mut fake = FakeReads::new(data);
        let mut calls = 0;
        let r = read_pipelined(&mut fake, 0, None, 1000, 8, &mut |_b: &[u8]| {
            calls += 1;
            if calls == 3 {
                Err(Error::Invalid("sink full".into()))
            } else {
                Ok(())
            }
        });
        assert!(matches!(r, Err(Error::Invalid(ref m)) if m == "sink full"));
        assert_eq!(calls, 3, "no sink calls after the error");
        assert_eq!(fake.pending.len(), 0, "outstanding replies were drained");
    }

    #[test]
    fn failed_request_falls_back_to_blocking_reads() {
        let data = pattern(20_000);
        let mut fake = FakeReads::new(data.clone());
        fake.fail_complete_at = Some(4);
        let (r, out) = run_read(&mut fake, 0, None, 1000, 8);
        assert_eq!(r.unwrap(), data.len() as u64);
        assert_eq!(out, data);
        assert!(fake.sync_calls > 0);
    }

    #[test]
    fn failed_issue_falls_back_too() {
        let data = pattern(9_000);
        let mut fake = FakeReads::new(data.clone());
        fake.fail_issue_at = Some(3);
        let (r, out) = run_read(&mut fake, 0, Some(9_000), 1000, 8);
        assert_eq!(r.unwrap(), 9_000);
        assert_eq!(out, data);
    }

    /// In-memory WRITE server with a volatile cache that a reboot discards.
    struct FakeWrites {
        disk: Vec<u8>,
        cache: Vec<(u64, Vec<u8>)>,
        verf: [u8; 8],
        writes_acked: usize,
        /// Reboot (drop the cache, change the verifier) after this many acks.
        reboot_after: Option<usize>,
        reboots: usize,
        /// Short-write every n-th request (accept half).
        short_every: usize,
        file_sync: bool,
        commits: usize,
        pending: VecDeque<usize>,
        datas: Vec<Vec<u8>>,
        max_outstanding: usize,
    }

    impl FakeWrites {
        fn new() -> Self {
            Self {
                disk: Vec::new(),
                cache: Vec::new(),
                verf: [1; 8],
                writes_acked: 0,
                reboot_after: None,
                reboots: 0,
                short_every: 0,
                file_sync: false,
                commits: 0,
                pending: VecDeque::new(),
                datas: Vec::new(),
                max_outstanding: 0,
            }
        }

        fn reboot(&mut self) {
            self.cache.clear();
            self.verf[0] = self.verf[0].wrapping_add(1);
            self.reboots += 1;
        }
    }

    impl WriteIo for FakeWrites {
        type Tag = usize;

        fn issue(&mut self, offset: u64, data: &[u8]) -> Result<usize> {
            let tag = self.datas.len();
            self.datas.push(data.to_vec());
            self.pending.push_back(offset as usize);
            self.max_outstanding = self.max_outstanding.max(self.pending.len());
            Ok(tag)
        }

        fn complete(&mut self, tag: usize) -> Result<WriteAck> {
            let offset = self.pending.pop_front().expect("reply without request") as u64;
            // Replies in request order: tags were issued in order, so the front matches.
            let _ = tag;
            let mut data = self.datas[tag].clone();
            if self.short_every > 0 && (tag + 1).is_multiple_of(self.short_every) && data.len() > 1
            {
                data.truncate(data.len() / 2);
            }
            let n = data.len();
            self.cache.push((offset, data));
            self.writes_acked += 1;
            let ack = WriteAck {
                count: n as u32,
                durable: self.file_sync,
                verf: self.verf,
            };
            if self.file_sync {
                self.flush_cache();
            }
            if Some(self.writes_acked) == self.reboot_after {
                self.reboot_after = None;
                self.reboot();
            }
            Ok(ack)
        }

        fn commit(&mut self, _offset: u64, _count: u32) -> Result<[u8; 8]> {
            self.commits += 1;
            self.flush_cache();
            Ok(self.verf)
        }
    }

    impl FakeWrites {
        fn flush_cache(&mut self) {
            for (off, d) in self.cache.drain(..) {
                let end = off as usize + d.len();
                if self.disk.len() < end {
                    self.disk.resize(end, 0);
                }
                self.disk[off as usize..end].copy_from_slice(&d);
            }
        }
    }

    fn run_write(
        fake: &mut FakeWrites,
        offset: u64,
        data: &[u8],
        chunk: usize,
        window: usize,
    ) -> Result<u64> {
        let mut rest = data;
        write_pipelined(fake, offset, chunk, window, &mut |buf: &mut [u8]| {
            let n = buf.len().min(rest.len());
            buf[..n].copy_from_slice(&rest[..n]);
            rest = &rest[n..];
            Ok(n)
        })
    }

    #[test]
    fn write_round_trips_and_commits() {
        for &size in &[0usize, 1, 999, 1000, 1001, 5000] {
            for &window in &[1usize, 4, 8] {
                let data = pattern(size);
                let mut fake = FakeWrites::new();
                let n = run_write(&mut fake, 0, &data, 1000, window).unwrap();
                assert_eq!(n, size as u64);
                assert_eq!(fake.disk, data, "size {size} window {window}");
                assert!(fake.max_outstanding <= window);
                if size > 0 {
                    assert_eq!(fake.commits, 1, "one COMMIT covers all unstable writes");
                } else {
                    assert_eq!(fake.commits, 0);
                }
            }
        }
    }

    #[test]
    fn write_at_unaligned_offset() {
        let data = pattern(7777);
        let mut fake = FakeWrites::new();
        run_write(&mut fake, 4321, &data, 1024, 8).unwrap();
        assert_eq!(&fake.disk[4321..4321 + data.len()], &data[..]);
    }

    #[test]
    fn short_writes_are_resent_from_the_gap() {
        let data = pattern(20_000);
        let mut fake = FakeWrites::new();
        fake.short_every = 3;
        let n = run_write(&mut fake, 0, &data, 1000, 8).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(fake.disk, data);
    }

    #[test]
    fn verifier_change_before_commit_resends_data() {
        let data = pattern(10_000);
        let mut fake = FakeWrites::new();
        // The server reboots after 4 acknowledged writes: their cached data is lost.
        fake.reboot_after = Some(4);
        let n = run_write(&mut fake, 0, &data, 1000, 2).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(fake.reboots, 1);
        assert_eq!(fake.disk, data, "lost unstable data was resent");
        assert!(
            fake.commits >= 2,
            "a second COMMIT confirmed the resent data"
        );
    }

    #[test]
    fn file_sync_replies_skip_commit() {
        let data = pattern(4000);
        let mut fake = FakeWrites::new();
        fake.file_sync = true;
        run_write(&mut fake, 0, &data, 1000, 4).unwrap();
        assert_eq!(fake.disk, data);
        assert_eq!(fake.commits, 0);
    }

    #[test]
    fn write_source_error_aborts_after_draining() {
        let mut fake = FakeWrites::new();
        let mut calls = 0;
        let r = write_pipelined(&mut fake, 0, 100, 4, &mut |buf: &mut [u8]| {
            calls += 1;
            if calls == 5 {
                return Err(Error::Invalid("source broke".into()));
            }
            buf.fill(9);
            Ok(buf.len())
        });
        assert!(matches!(r, Err(Error::Invalid(_))));
        assert!(fake.pending.is_empty(), "outstanding writes were drained");
    }

    #[test]
    fn stuck_verifier_gives_up() {
        struct Stuck(FakeWrites);
        impl WriteIo for Stuck {
            type Tag = usize;
            fn issue(&mut self, o: u64, d: &[u8]) -> Result<usize> {
                self.0.issue(o, d)
            }
            fn complete(&mut self, t: usize) -> Result<WriteAck> {
                let mut ack = self.0.complete(t)?;
                ack.verf = [9; 8];
                Ok(ack)
            }
            fn commit(&mut self, o: u64, c: u32) -> Result<[u8; 8]> {
                self.0.commit(o, c)?;
                // Every COMMIT reports a different verifier from the writes.
                let mut v = [0u8; 8];
                v[0] = self.0.commits as u8;
                Ok(v)
            }
        }
        let mut s = Stuck(FakeWrites::new());
        let data = pattern(3000);
        let mut rest = &data[..];
        let r = write_pipelined(&mut s, 0, 1000, 4, &mut |buf: &mut [u8]| {
            let n = buf.len().min(rest.len());
            buf[..n].copy_from_slice(&rest[..n]);
            rest = &rest[n..];
            Ok(n)
        });
        assert!(matches!(r, Err(Error::Protocol(_))));
    }
}
