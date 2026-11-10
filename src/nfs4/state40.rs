//! Open state and NFSv4.0 client ID handling.
//!
//! - SETCLIENTID / SETCLIENTID_CONFIRM for NFSv4.0 (4.1+ uses session.rs).
//! - A small LRU cache of open stateids per file handle. Reads and writes use a
//!   cached open when one exists, open on first use, and fall back to the
//!   anonymous stateid if the server refuses the open.
//! - OPEN / OPEN_CONFIRM / CLOSE helpers shared by create and I/O.

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::fs::FileHandle;

use super::backend::{body, fh_at, Nfs4Backend, CB_PROGRAM};
use super::ops::{Claim, Op, OpenArgs, OpenHow, Res, ResOp};
use super::types::{code, StateId, ANON_STATEID, OPEN4_RESULT_CONFIRM, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_ACCESS_READ};

/// Open-owner string sent with every OPEN. One owner per client ID.
const OPEN_OWNER: &[u8] = b"nfsc-open-owner";
const OPEN_CACHE_CAP: usize = 16;

struct Entry {
    stateid: StateId,
    access: u32,
    last: u64,
}

/// LRU cache of open stateids, keyed by file handle.
#[derive(Default)]
pub(crate) struct OpenCache {
    entries: HashMap<FileHandle, Entry>,
    tick: u64,
}

impl OpenCache {
    /// Cached stateid usable for a read (any access) or write (BOTH access only).
    pub fn get(&mut self, fh: &FileHandle, write: bool) -> Option<StateId> {
        self.tick += 1;
        let tick = self.tick;
        let e = self.entries.get_mut(fh)?;
        if write && e.access != OPEN4_SHARE_ACCESS_BOTH {
            return None;
        }
        e.last = tick;
        Some(e.stateid)
    }

    /// Insert, returning stateids that must now be CLOSEd (a replaced entry or an evicted one).
    pub fn insert(&mut self, fh: FileHandle, stateid: StateId, access: u32) -> Vec<StateId> {
        self.tick += 1;
        let mut to_close = Vec::new();
        if let Some(old) = self.entries.remove(&fh) {
            to_close.push(old.stateid);
        }
        if self.entries.len() >= OPEN_CACHE_CAP {
            let victim = self.entries.iter().min_by_key(|(_, e)| e.last).map(|(k, _)| k.clone());
            if let Some(v) = victim {
                if let Some(e) = self.entries.remove(&v) {
                    to_close.push(e.stateid);
                }
            }
        }
        self.entries.insert(fh, Entry { stateid, access, last: self.tick });
        to_close
    }

    pub fn remove(&mut self, fh: &FileHandle) -> Option<StateId> {
        self.entries.remove(fh).map(|e| e.stateid)
    }

    /// Drop the entry without CLOSE (the stateid is already known to be invalid).
    pub fn forget(&mut self, fh: &FileHandle) {
        self.entries.remove(fh);
    }

    pub fn drain(&mut self) -> Vec<StateId> {
        self.entries.drain().map(|(_, e)| e.stateid).collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Build OPEN arguments for the current open owner.
pub(super) fn open_args(s: &Nfs4Backend, share_access: u32, how: OpenHow, claim: Claim) -> OpenArgs {
    OpenArgs {
        seqid: s.open_seqid,
        share_access,
        clientid: s.clientid,
        owner: OPEN_OWNER.to_vec(),
        how,
        claim,
    }
}

fn open_body(res: &[ResOp], i: usize) -> Result<(StateId, u32, Option<StateId>)> {
    match body(res, i)? {
        Res::Open { stateid, rflags, deleg } => Ok((*stateid, *rflags, *deleg)),
        _ => Err(Error::Xdr("expected OPEN result".into())),
    }
}

impl Nfs4Backend {
    /// SETCLIENTID then SETCLIENTID_CONFIRM (NFSv4.0).
    pub(super) fn establish_40(&mut self) -> Result<()> {
        let verifier = self.new_verifier();
        let id = self.owner_id.clone();
        let res = self.send(
            vec![Op::Setclientid {
                verifier,
                id,
                cb_program: CB_PROGRAM,
                // Callbacks are never served; the server records an address it will fail to reach.
                cb_addr: "0.0.0.0.0.0".into(),
                cb_ident: 1,
            }],
            false,
        )?;
        let res = self.check(res)?;
        let (clientid, confirm) = match body(&res, 0)? {
            Res::Setclientid { clientid, verifier } => (*clientid, *verifier),
            _ => return Err(Error::Xdr("expected SETCLIENTID result".into())),
        };
        let res = self.send(vec![Op::SetclientidConfirm { clientid, verifier: confirm }], false)?;
        self.check(res)?;
        self.clientid = clientid;
        self.open_seqid = 0;
        Ok(())
    }

    /// OPEN_CONFIRM when the server asks for it (NFSv4.0 only).
    fn maybe_confirm(&mut self, sid: StateId, rflags: u32) -> Result<StateId> {
        if self.minor != 0 || rflags & OPEN4_RESULT_CONFIRM == 0 {
            return Ok(sid);
        }
        let res = self.exec(|s| vec![Op::OpenConfirm { stateid: sid, seqid: s.open_seqid }])?;
        match body(&res, 0)? {
            Res::Stateid(n) => Ok(*n),
            _ => Err(Error::Xdr("expected OPEN_CONFIRM result".into())),
        }
    }

    /// Ask the server to release a delegation we were handed. Best effort.
    fn return_delegation(&mut self, deleg: Option<StateId>) {
        if let Some(d) = deleg {
            let _ = self.exec(|_| vec![Op::DelegReturn(d)]);
        }
    }

    /// Finish an OPEN that created the file: confirm, release any delegation,
    /// and cache the stateid.
    pub(super) fn finish_open(
        &mut self,
        fh: &FileHandle,
        sid: StateId,
        rflags: u32,
        deleg: Option<StateId>,
        access: u32,
    ) -> Result<()> {
        self.return_delegation(deleg);
        let sid = self.maybe_confirm(sid, rflags)?;
        self.cache_open(fh, sid, access);
        Ok(())
    }

    /// Open `fh` for read or write and return the new stateid. The caller caches it.
    fn open_file(&mut self, fh: &FileHandle, write: bool) -> Result<StateId> {
        let access = if write { OPEN4_SHARE_ACCESS_BOTH } else { OPEN4_SHARE_ACCESS_READ };
        if self.minor >= 1 {
            // NFSv4.1+: open the filehandle itself (CLAIM_FH).
            let res = self.exec(|s| {
                vec![
                    Op::Putfh(fh.0.clone()),
                    Op::Open(open_args(s, access, OpenHow::NoCreate, Claim::Fh)),
                ]
            })?;
            let (sid, _rflags, deleg) = open_body(&res, 1)?;
            self.return_delegation(deleg);
            Ok(sid)
        } else {
            // NFSv4.0: open by name in the parent directory. The name is taken from
            // our own lookups; GETFH verifies the name still refers to this handle.
            let (dir, name) = self
                .names
                .get(fh)
                .cloned()
                .ok_or_else(|| Error::Invalid("no known parent name for this handle".into()))?;
            let res = self.exec(|s| {
                vec![
                    Op::Putfh(dir.0.clone()),
                    Op::Open(open_args(s, access, OpenHow::NoCreate, Claim::Null(name.clone()))),
                    Op::Getfh,
                ]
            })?;
            let (sid, rflags, deleg) = open_body(&res, 1)?;
            let got = fh_at(&res, 2)?;
            if got != *fh {
                self.close_stateid(sid);
                self.names.remove(fh);
                return Err(Error::Invalid("cached name no longer refers to this handle".into()));
            }
            self.return_delegation(deleg);
            self.maybe_confirm(sid, rflags)
        }
    }

    /// Stateid for READ (write = false) or WRITE/SETATTR-size (write = true) on
    /// `fh`: a cached open when possible, otherwise a new open, otherwise the
    /// anonymous stateid.
    pub(super) fn stateid_for_io(&mut self, fh: &FileHandle, write: bool) -> StateId {
        if let Some(sid) = self.opens.get(fh, write) {
            return sid;
        }
        if write {
            // Upgrading a read-only open: close it before reopening for write.
            self.close_entry(fh);
        }
        let access = if write { OPEN4_SHARE_ACCESS_BOTH } else { OPEN4_SHARE_ACCESS_READ };
        match self.open_file(fh, write) {
            Ok(sid) => {
                self.cache_open(fh, sid, access);
                sid
            }
            Err(_) => ANON_STATEID,
        }
    }

    /// Cache an open stateid; CLOSE whatever it displaced.
    pub(super) fn cache_open(&mut self, fh: &FileHandle, sid: StateId, access: u32) {
        for old in self.opens.insert(fh.clone(), sid, access) {
            self.close_stateid(old);
        }
    }

    /// Remove and CLOSE the cached open for `fh`, if any.
    pub(super) fn close_entry(&mut self, fh: &FileHandle) {
        if let Some(sid) = self.opens.remove(fh) {
            self.close_stateid(sid);
        }
    }

    /// CLOSE an open stateid. Errors are ignored: the state is going away either way.
    pub(super) fn close_stateid(&mut self, sid: StateId) {
        let _ = self.exec(|s| vec![Op::Close { seqid: s.open_seqid, stateid: sid }]);
    }

    /// Whether `code` means the stateid itself is unusable.
    pub(super) fn is_stateid_error(c: u32) -> bool {
        matches!(c, code::BAD_STATEID | code::OLD_STATEID | code::STALE_STATEID | code::ADMIN_REVOKED | code::EXPIRED)
    }
}
