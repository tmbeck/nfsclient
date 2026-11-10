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
//! - A failed READ request pauses the pipeline: outstanding replies are
//!   drained and the transfer continues with blocking reads (which carry the
//!   backend's retry and session recovery). After a few blocking reads succeed
//!   the pipeline is tried again; each further failure doubles that count. If
//!   a blocking read fails too, the transfer ends with an error.
//! - A WRITE request that fails with a retryable error (timeout, lost
//!   connection, JUKEBOX) pauses the pipeline: outstanding replies are
//!   drained, the failed and drained requests are sent again as blocking
//!   writes (which carry the backend's retry policy), and pipelining resumes.
//!   Writes at a fixed offset are idempotent, and the COMMIT verifier check
//!   still catches data a restarted server lost. Other WRITE errors, or a
//!   blocking write that fails too, end the transfer with the error.
//! - READ never returns a silently short result: fewer bytes than asked
//!   means the server reported EOF. A reply with no data and no EOF is
//!   retried with blocking reads and is otherwise an error, with or without
//!   a length.

use std::collections::VecDeque;

use crate::error::{Error, Result};

/// Requests kept in flight by default.
pub const DEFAULT_WINDOW: usize = 8;
/// Unstable write data is committed once this many bytes await a COMMIT.
pub const COMMIT_INTERVAL: u64 = 64 << 20;
/// Consecutive COMMIT rounds that may end with a verifier mismatch before giving up.
const MAX_COMMIT_ROUNDS: u32 = 8;
/// Upper bound on the blocking READs done before pipelining is tried again
/// (the count starts at 2 and doubles with each fallback in one transfer).
const MAX_RECOVER_AFTER: u32 = 256;

/// One READ request/reply pipeline on a backend.
pub(crate) trait ReadIo {
    /// Identifies one outstanding request.
    type Tag: Copy;

    /// Send a READ of `count` bytes at `offset` without waiting for the reply.
    fn issue(&mut self, offset: u64, count: u32) -> Result<Self::Tag>;

    /// Wait for the reply to `tag`: returns (data, eof).
    fn complete(&mut self, tag: Self::Tag) -> Result<(Vec<u8>, bool)>;

    /// A blocking READ with the backend's usual retry and recovery. It
    /// should not return an empty reply without EOF (see
    /// [`read_with_progress`]); the engine treats one as an error.
    fn read_sync(&mut self, offset: u64, count: u32) -> Result<(Vec<u8>, bool)>;
}

/// Run a blocking READ of `count` bytes at `offset` until it makes progress:
/// a reply with no data and no EOF is retried under `policy` like a
/// retryable error, and once the budget is spent it fails ([`Error::GaveUp`]
/// wrapping a protocol error), so callers never mistake it for the end of
/// the file. Other errors are returned as `read` reports them (it does its
/// own retrying).
pub(crate) fn read_with_progress(
    policy: &crate::rpc::RetryPolicy,
    offset: u64,
    count: u32,
    mut read: impl FnMut() -> Result<(Vec<u8>, bool)>,
) -> Result<(Vec<u8>, bool)> {
    let mut retry = crate::rpc::retry::Retrier::new(policy, "READ");
    loop {
        let (data, eof) = read()?;
        if !data.is_empty() || eof || count == 0 {
            retry.succeeded();
            return Ok((data, eof));
        }
        retry.backoff(Error::Protocol(format!(
            "READ at {offset} returned no data and no EOF"
        )))?;
    }
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

    /// A blocking UNSTABLE WRITE, used to resend data after a pipelined
    /// request failed. Backends override it to add their retry policy; the
    /// default is one plain attempt.
    fn write_sync(&mut self, offset: u64, data: &[u8]) -> Result<WriteAck> {
        let tag = self.issue(offset, data)?;
        self.complete(tag)
    }
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
///
/// When `len` is given, a return value below it means the server reported EOF.
/// A reply with no data and no EOF before `len` is reached is an error.
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
    let mut fb = Fallback::default();

    loop {
        while issuing && !fb.active && inflight.len() < window {
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
                Err(e) => {
                    fb.enter(e);
                    break;
                }
            }
        }

        let (data, eof, want, off, synced) = if let Some((tag, off, want)) = inflight.pop_front() {
            match io.complete(tag) {
                Ok((data, eof)) => (data, eof, want, off, false),
                Err(e) => {
                    drain_reads(io, &mut inflight);
                    fb.enter(e);
                    continue;
                }
            }
        } else if fb.active {
            let want = match end {
                Some(e) if delivered >= e => break,
                Some(e) => (e - delivered).min(u64::from(chunk)) as u32,
                None => chunk,
            };
            match io.read_sync(delivered, want) {
                Ok((data, eof)) => (data, eof, want, delivered, true),
                Err(e) => return Err(fb.final_error(e)),
            }
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
        if at_end || eof {
            // Nothing past this point is wanted; outstanding replies are drained.
            drain_reads(io, &mut inflight);
            break;
        }
        if data.is_empty() {
            // No data and no EOF: the server makes no progress here. Stopping
            // would hand back a silently short result, with or without a
            // length. A pipelined reply falls back to blocking reads, which
            // retry it under the backend's policy; a blocking read that still
            // makes no progress is an error.
            drain_reads(io, &mut inflight);
            let err = Error::Protocol(format!(
                "READ at {off} returned no data before EOF ({} bytes read{})",
                delivered - offset,
                len.map(|l| format!(" of {l}")).unwrap_or_default()
            ));
            if synced {
                return Err(err);
            }
            fb.enter(err);
            continue;
        }
        if synced {
            if fb.sync_succeeded() {
                // Blocking reads work again: resume pipelining where they left off.
                next = delivered;
                issuing = true;
            }
        } else if data.len() < want as usize {
            // Short read before EOF: refetch from the first missing byte. Requests
            // already sent past the gap are drained and dropped. (In fallback
            // mode the blocking reads continue from `delivered`.)
            drain_reads(io, &mut inflight);
            next = delivered;
            issuing = true;
        }
    }
    Ok(delivered - offset)
}

/// Blocking-read fallback state for [`read_pipelined`].
#[derive(Default)]
struct Fallback {
    /// A pipelined request failed; reads are blocking for now.
    active: bool,
    /// Blocking reads that must succeed in a row before pipelining resumes.
    /// Doubles on every fallback within one transfer, so a pipeline that keeps
    /// failing costs less and less.
    recover_after: u32,
    /// Blocking reads that succeeded since the fallback.
    ok: u32,
    /// The error that started the fallback.
    err: Option<Error>,
}

impl Fallback {
    /// A pipelined request failed with `e`.
    fn enter(&mut self, e: Error) {
        if !self.active {
            self.active = true;
            self.ok = 0;
            self.recover_after = (self.recover_after.max(1) * 2).min(MAX_RECOVER_AFTER);
        }
        // Keep the first error: later ones are usually its consequences.
        self.err.get_or_insert(e);
    }

    /// A blocking read delivered data. Returns true (and leaves fallback mode)
    /// when enough have succeeded to try pipelining again.
    fn sync_succeeded(&mut self) -> bool {
        self.ok += 1;
        if self.ok < self.recover_after {
            return false;
        }
        self.active = false;
        self.err = None;
        true
    }

    /// The blocking read failed with `sync` as well. Return the error that
    /// says more: the blocking read's when it is definitive (not retryable, so
    /// the backend's retries did not help and the server gave a real answer),
    /// otherwise the pipelined error that started it all.
    ///
    /// A blocking read that gave up after retrying ([`Error::GaveUp`]) or
    /// was interrupted is definitive too: it says why the transfer ended.
    fn final_error(&mut self, sync: Error) -> Error {
        let interrupted =
            matches!(&sync, Error::Io(e) if e.kind() == std::io::ErrorKind::Interrupted);
        match self.err.take() {
            Some(first) if sync.is_retryable() && !interrupted => first,
            _ => sync,
        }
    }
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
                    recover_writes(
                        io,
                        e,
                        vec![(off, data)],
                        &mut inflight,
                        &mut inflight_bytes,
                        &mut retained,
                        &mut retained_bytes,
                    )?;
                    continue;
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
                recover_writes(
                    io,
                    e,
                    vec![(flight.offset, flight.data)],
                    &mut inflight,
                    &mut inflight_bytes,
                    &mut retained,
                    &mut retained_bytes,
                )?;
                continue;
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

/// A pipelined WRITE failed with `e`. Drain the other outstanding writes
/// (their replies are discarded), then, if `e` is retryable, send the failed
/// and drained chunks again as blocking writes, which carry the backend's
/// retry policy. Rewriting the same bytes at the same offsets is harmless,
/// and unstable acks are retained for the COMMIT verifier check as usual.
/// Returns `e` (after draining) when it is not retryable, or the blocking
/// write's error when that fails too.
fn recover_writes<I: WriteIo>(
    io: &mut I,
    e: Error,
    mut lost: Vec<(u64, Vec<u8>)>,
    inflight: &mut VecDeque<Flight<I::Tag>>,
    inflight_bytes: &mut u64,
    retained: &mut Vec<Retained>,
    retained_bytes: &mut u64,
) -> Result<()> {
    while let Some(f) = inflight.pop_front() {
        let _ = io.complete(f.tag);
        lost.push((f.offset, f.data));
    }
    *inflight_bytes = 0;
    if !e.is_retryable() {
        return Err(e);
    }
    for (off, data) in lost {
        write_blocking(io, off, data, retained, retained_bytes)?;
    }
    Ok(())
}

/// Write all of `data` at `off` with blocking writes, following short writes.
fn write_blocking<I: WriteIo>(
    io: &mut I,
    mut off: u64,
    mut data: Vec<u8>,
    retained: &mut Vec<Retained>,
    retained_bytes: &mut u64,
) -> Result<()> {
    while !data.is_empty() {
        let ack = io.write_sync(off, &data)?;
        let n = ack.count as usize;
        if n == 0 || n > data.len() {
            return Err(Error::Protocol(format!(
                "server accepted {n} of {} bytes at offset {off}",
                data.len()
            )));
        }
        let rest = data.split_off(n);
        if !ack.durable {
            *retained_bytes += n as u64;
            retained.push(Retained {
                offset: off,
                data,
                verf: ack.verf,
            });
        }
        off += n as u64;
        data = rest;
    }
    Ok(())
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
        /// Fail every n-th pipelined reply (by tag).
        fail_complete_every: usize,
        /// The error a failing `issue`/`complete` returns.
        pipe_err: fn() -> Error,
        /// When set, every blocking read fails with this error.
        sync_err: Option<fn() -> Error>,
        /// A READ at this offset returns no data and no EOF.
        stall_at: Option<u64>,
        /// How many READs at `stall_at` stall (0 = all of them).
        stall_times: usize,
        /// Requests issued (pipelined) after the first blocking read.
        issued_after_sync: usize,
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
                fail_complete_every: 0,
                pipe_err: || Error::Timeout,
                sync_err: None,
                stall_at: None,
                stall_times: 0,
                issued_after_sync: 0,
            }
        }

        fn serve(&mut self, offset: u64, count: u32) -> (Vec<u8>, bool) {
            self.served += 1;
            if self.stall_at == Some(offset) {
                if self.stall_times == 1 {
                    self.stall_at = None;
                }
                self.stall_times = self.stall_times.saturating_sub(1);
                return (Vec::new(), false);
            }
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
            if self.sync_calls > 0 {
                self.issued_after_sync += 1;
            }
            if self.fail_issue_at == Some(self.issued) {
                return Err((self.pipe_err)());
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
            if self.fail_complete_at == Some(t + 1)
                || (self.fail_complete_every > 0
                    && (t + 1).is_multiple_of(self.fail_complete_every))
            {
                return Err((self.pipe_err)());
            }
            Ok(self.serve(offset, count))
        }

        fn read_sync(&mut self, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
            self.sync_calls += 1;
            if let Some(err) = self.sync_err {
                return Err(err());
            }
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

    #[test]
    fn pipelining_resumes_after_a_fallback() {
        let data = pattern(100_000);
        let mut fake = FakeReads::new(data.clone());
        fake.fail_complete_at = Some(4);
        let (r, out) = run_read(&mut fake, 0, None, 1000, 8);
        assert_eq!(r.unwrap(), data.len() as u64);
        assert_eq!(out, data);
        // Two blocking reads, then the rest is pipelined again (not ~96 blocking reads).
        assert_eq!(fake.sync_calls, 2);
        assert!(fake.issued_after_sync > 50, "{}", fake.issued_after_sync);
    }

    #[test]
    fn repeated_pipeline_failures_back_off_and_still_complete() {
        let data = pattern(300_000);
        let mut fake = FakeReads::new(data.clone());
        fake.fail_complete_every = 7;
        let (r, out) = run_read(&mut fake, 0, Some(300_000), 1000, 8);
        assert_eq!(r.unwrap(), data.len() as u64);
        assert_eq!(out, data);
        // Fallback lengths double (2, 4, 8, ...), so most chunks are still pipelined
        // at first and blocking reads dominate only once failures keep recurring.
        assert!(fake.sync_calls < 300, "{}", fake.sync_calls);
        assert!(fake.issued_after_sync > 0);
    }

    #[test]
    fn short_pipelined_reply_during_fallback_is_refetched() {
        // An issue fails while earlier requests are in flight; one of those replies
        // is short. The gap must be read, not reported as an offset mismatch.
        let data = pattern(20_000);
        let mut fake = FakeReads::new(data.clone());
        fake.fail_issue_at = Some(5);
        fake.short_every = 2;
        let (r, out) = run_read(&mut fake, 0, Some(20_000), 1000, 8);
        assert_eq!(r.unwrap(), 20_000);
        assert_eq!(out, data);
    }

    #[test]
    fn original_error_is_kept_when_fallback_fails_transiently() {
        let mut fake = FakeReads::new(pattern(20_000));
        fake.fail_complete_at = Some(2);
        fake.pipe_err = || Error::Nfs(crate::fs::Status::Stale);
        fake.sync_err = Some(|| Error::Timeout);
        let (r, out) = run_read(&mut fake, 0, Some(20_000), 1000, 8);
        assert!(
            matches!(r, Err(Error::Nfs(crate::fs::Status::Stale))),
            "{r:?}"
        );
        assert_eq!(out, pattern(1000), "only the first chunk was delivered");
    }

    #[test]
    fn definitive_fallback_error_wins() {
        let mut fake = FakeReads::new(pattern(20_000));
        fake.fail_complete_at = Some(1);
        fake.pipe_err = || Error::Timeout;
        fake.sync_err = Some(|| Error::Nfs(crate::fs::Status::Access));
        let (r, _) = run_read(&mut fake, 0, None, 1000, 8);
        assert!(
            matches!(r, Err(Error::Nfs(crate::fs::Status::Access))),
            "{r:?}"
        );
    }

    #[test]
    fn empty_reply_before_eof_with_length_is_an_error() {
        let data = pattern(10_000);
        for window in [1usize, 8] {
            let mut fake = FakeReads::new(data.clone());
            fake.stall_at = Some(4000);
            let (r, out) = run_read(&mut fake, 0, Some(10_000), 1000, window);
            assert!(
                matches!(r, Err(Error::Protocol(_))),
                "window {window}: {r:?}"
            );
            assert_eq!(out, data[..4000], "window {window}");
            assert!(fake.pending.is_empty());
        }
        // Without a length it is an error too, never a silently short Ok.
        for window in [1usize, 8] {
            let mut fake = FakeReads::new(data.clone());
            fake.stall_at = Some(4000);
            let (r, out) = run_read(&mut fake, 0, None, 1000, window);
            assert!(
                matches!(r, Err(Error::Protocol(_))),
                "window {window}: {r:?}"
            );
            assert_eq!(out, data[..4000], "window {window}");
            assert!(fake.pending.is_empty());
        }
    }

    #[test]
    fn empty_reply_is_retried_by_blocking_reads() {
        let data = pattern(10_000);
        for len in [None, Some(10_000)] {
            let mut fake = FakeReads::new(data.clone());
            fake.stall_at = Some(4000);
            fake.stall_times = 1;
            let (r, out) = run_read(&mut fake, 0, len, 1000, 8);
            assert_eq!(r.unwrap(), 10_000, "len {len:?}");
            assert_eq!(out, data);
        }
    }

    #[test]
    fn read_with_progress_retries_then_gives_up() {
        let policy = crate::rpc::RetryPolicy {
            budget: std::time::Duration::from_millis(200),
            initial_backoff: std::time::Duration::from_millis(10),
            ..crate::rpc::RetryPolicy::default()
        };
        let mut n = 0;
        let r = read_with_progress(&policy, 7, 100, || {
            n += 1;
            Ok(if n < 3 {
                (Vec::new(), false)
            } else {
                (vec![1], false)
            })
        });
        assert_eq!(r.unwrap(), (vec![1], false));
        assert_eq!(n, 3);
        let r = read_with_progress(&policy, 7, 100, || Ok((Vec::new(), false)));
        match r {
            Err(Error::GaveUp { last, .. }) => assert!(matches!(*last, Error::Protocol(_))),
            other => panic!("expected GaveUp, got {other:?}"),
        }
        // EOF with no data is a normal end, not a stall.
        let r = read_with_progress(&policy, 7, 100, || Ok((Vec::new(), true)));
        assert_eq!(r.unwrap(), (Vec::new(), true));
    }

    /// READ over a real RPC client against a loopback TCP server that drops
    /// connections. Procedure 1 takes (offset u64, count u32) and returns
    /// (opaque data, bool eof).
    mod loopback {
        use super::super::*;
        use super::pattern;
        use crate::rpc::{Auth, PortMode, Proto, RpcClient, RpcOptions};
        use crate::xdr::Opaque;
        use std::io::{Read, Write};
        use std::net::{SocketAddr, TcpListener, TcpStream};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        const PROG: u32 = 0x2000_0042;

        fn be32(b: &[u8], off: usize) -> u32 {
            u32::from_be_bytes(b[off..off + 4].try_into().unwrap())
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

        fn answer(file: &[u8], call: &[u8]) -> Vec<u8> {
            let xid = be32(call, 0);
            let mut off = 24;
            for _ in 0..2 {
                off += 4;
                off += 4 + (be32(call, off) as usize).div_ceil(4) * 4;
            }
            let offset = u64::from_be_bytes(call[off..off + 8].try_into().unwrap()) as usize;
            let count = be32(call, off + 8) as usize;
            let start = offset.min(file.len());
            let end = (start + count).min(file.len());
            let mut e = crate::xdr::Encoder::new();
            e.put_u32(xid).put_u32(1).put_u32(0).put_u32(0).put_u32(0);
            e.put_u32(0);
            e.put_opaque(&file[start..end]).put_bool(end >= file.len());
            let body = e.as_bytes();
            let mut rec = (0x8000_0000u32 | body.len() as u32).to_be_bytes().to_vec();
            rec.extend_from_slice(body);
            rec
        }

        /// Serve `file`. Connection `i` answers `limit(i)` calls (None: all) and
        /// then closes. At most `max_conns` connections are accepted.
        fn spawn(
            file: Arc<Vec<u8>>,
            limit: fn(usize) -> Option<usize>,
            max_conns: usize,
        ) -> SocketAddr {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            thread::spawn(move || {
                for i in 0..max_conns {
                    let Ok((mut s, _)) = listener.accept() else {
                        return;
                    };
                    let file = Arc::clone(&file);
                    thread::spawn(move || {
                        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
                        let mut answered = 0;
                        while limit(i).is_none_or(|l| answered < l) {
                            let Some(call) = read_record(&mut s) else {
                                return;
                            };
                            if s.write_all(&answer(&file, &call)).is_err() {
                                return;
                            }
                            answered += 1;
                        }
                        // Drop the stream with calls possibly still unread.
                    });
                }
                // The listener closes here: further connects are refused.
            });
            addr
        }

        struct RpcReads(RpcClient);

        impl ReadIo for RpcReads {
            type Tag = u32;
            fn issue(&mut self, offset: u64, count: u32) -> Result<u32> {
                self.0.send_call(1, &(offset, count))
            }
            fn complete(&mut self, xid: u32) -> Result<(Vec<u8>, bool)> {
                let (Opaque(d), eof): (Opaque, bool) = self.0.recv_reply(xid)?;
                Ok((d, eof))
            }
            fn read_sync(&mut self, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
                // One retry on a transient error, like the backends' blocking READ.
                let mut once = || -> Result<(Vec<u8>, bool)> {
                    let (Opaque(d), eof): (Opaque, bool) = self.0.call(1, &(offset, count))?;
                    Ok((d, eof))
                };
                match once() {
                    Err(e) if e.is_retryable() => once(),
                    r => r,
                }
            }
        }

        fn run(addr: SocketAddr, len: usize) -> (Result<u64>, Vec<u8>) {
            let opts = RpcOptions {
                proto: Proto::Tcp,
                port_mode: PortMode::Unprivileged,
                timeout: Duration::from_secs(5),
                auth: Auth::None,
                ..RpcOptions::default()
            };
            let mut io = RpcReads(RpcClient::connect(addr, PROG, 1, &opts).unwrap());
            let mut out = Vec::new();
            let r = read_pipelined(&mut io, 0, Some(len as u64), 4096, 8, &mut |b: &[u8]| {
                out.extend_from_slice(b);
                Ok(())
            });
            (r, out)
        }

        #[test]
        fn connection_drop_mid_transfer_recovers_with_correct_data() {
            let file = Arc::new(pattern(200_000));
            let addr = spawn(Arc::clone(&file), |i| (i == 0).then_some(10), 16);
            let (r, out) = run(addr, file.len());
            assert_eq!(r.unwrap(), file.len() as u64);
            assert_eq!(out, *file);
        }

        #[test]
        fn flapping_connection_gives_correct_data_or_a_clear_error() {
            let file = Arc::new(pattern(200_000));
            let addr = spawn(Arc::clone(&file), |_| Some(5), 1000);
            let (r, out) = run(addr, file.len());
            match r {
                Ok(n) => {
                    assert_eq!(n, file.len() as u64, "never a silently short result");
                    assert_eq!(out, *file);
                }
                Err(e) => {
                    assert!(e.is_retryable(), "a connection-level error: {e:?}");
                    assert!(out.len() < file.len());
                    assert_eq!(out, file[..out.len()], "delivered data is a correct prefix");
                }
            }
        }

        #[test]
        fn server_gone_mid_transfer_is_an_error_not_short_data() {
            let file = Arc::new(pattern(200_000));
            // One connection that answers 10 calls; then nothing listens.
            let addr = spawn(Arc::clone(&file), |_| Some(10), 1);
            let (r, out) = run(addr, file.len());
            let e = r.expect_err("the transfer cannot complete");
            assert!(e.is_retryable(), "{e:?}");
            assert!(out.len() < file.len());
            assert_eq!(out, file[..out.len()]);
        }
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
        /// Requests (by tag) whose reply is this error instead of an ack.
        fail_tags: Vec<(usize, fn() -> Error)>,
        /// Inside `write_sync`: injected failures apply to pipelined writes only.
        in_sync: bool,
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
                fail_tags: Vec::new(),
                in_sync: false,
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
            if let Some((_, err)) = self
                .fail_tags
                .iter()
                .find(|(t, _)| *t == tag && !self.in_sync)
            {
                return Err(err());
            }
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

        fn write_sync(&mut self, offset: u64, data: &[u8]) -> Result<WriteAck> {
            self.in_sync = true;
            let r = self.issue(offset, data).and_then(|t| self.complete(t));
            self.in_sync = false;
            r
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
    fn failed_writes_are_resent_with_blocking_writes() {
        let data = pattern(20_000);
        for window in [1usize, 4, 8] {
            let mut fake = FakeWrites::new();
            fake.fail_tags = vec![
                (3, || Error::Timeout),
                (4, || Error::Nfs(crate::fs::Status::Jukebox)),
                (9, || Error::Io(std::io::ErrorKind::ConnectionReset.into())),
            ];
            let n = run_write(&mut fake, 0, &data, 1000, window).unwrap();
            assert_eq!(n, data.len() as u64);
            assert_eq!(fake.disk, data, "window {window}");
            assert!(fake.pending.is_empty());
        }
    }

    #[test]
    fn permanent_write_error_ends_the_transfer() {
        let mut fake = FakeWrites::new();
        fake.fail_tags = vec![(3, || Error::Nfs(crate::fs::Status::NoSpc))];
        let r = run_write(&mut fake, 0, &pattern(20_000), 1000, 4);
        assert!(
            matches!(r, Err(Error::Nfs(crate::fs::Status::NoSpc))),
            "{r:?}"
        );
        assert!(fake.pending.is_empty(), "outstanding writes were drained");
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
