//! NFSv4 operations: argument encoding (`Op`, a `nfs_argop4`) and result
//! decoding (`ResOp`, a `nfs_resop4`) for the subset the backend uses.

use crate::error::{Error, Result};
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

use super::types::{AttrSet, Fattr, StateId, bitmap, code, get_session_id, get_verf};

pub const OP_CLOSE: u32 = 4;
pub const OP_COMMIT: u32 = 5;
pub const OP_CREATE: u32 = 6;
pub const OP_DELEGRETURN: u32 = 8;
pub const OP_GETATTR: u32 = 9;
pub const OP_GETFH: u32 = 10;
pub const OP_LINK: u32 = 11;
pub const OP_LOOKUP: u32 = 15;
pub const OP_LOOKUPP: u32 = 16;
pub const OP_OPEN: u32 = 18;
pub const OP_OPEN_CONFIRM: u32 = 20;
pub const OP_PUTFH: u32 = 22;
pub const OP_PUTROOTFH: u32 = 24;
pub const OP_READ: u32 = 25;
pub const OP_READDIR: u32 = 26;
pub const OP_READLINK: u32 = 27;
pub const OP_REMOVE: u32 = 28;
pub const OP_RENAME: u32 = 29;
pub const OP_RENEW: u32 = 30;
pub const OP_SAVEFH: u32 = 32;
pub const OP_SETATTR: u32 = 34;
pub const OP_SETCLIENTID: u32 = 35;
pub const OP_SETCLIENTID_CONFIRM: u32 = 36;
pub const OP_WRITE: u32 = 38;
pub const OP_BIND_CONN_TO_SESSION: u32 = 41;
pub const OP_EXCHANGE_ID: u32 = 42;
pub const OP_CREATE_SESSION: u32 = 43;
pub const OP_DESTROY_SESSION: u32 = 44;
pub const OP_SEQUENCE: u32 = 53;
pub const OP_DESTROY_CLIENTID: u32 = 57;
pub const OP_RECLAIM_COMPLETE: u32 = 58;

/// stable_how4 FILE_SYNC: data and metadata are on stable storage on return.
pub const UNSTABLE4: u32 = 0;
pub const FILE_SYNC4: u32 = 2;

/// Channel attributes (channel_attrs4), used for both directions of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelAttrs {
    pub headerpadsize: u32,
    pub maxrequestsize: u32,
    pub maxresponsesize: u32,
    pub maxresponsesize_cached: u32,
    pub maxoperations: u32,
    pub maxrequests: u32,
}

impl Pack for ChannelAttrs {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.headerpadsize)
            .put_u32(self.maxrequestsize)
            .put_u32(self.maxresponsesize)
            .put_u32(self.maxresponsesize_cached)
            .put_u32(self.maxoperations)
            .put_u32(self.maxrequests);
        // ca_rdma_ird<1>: no RDMA.
        e.put_u32(0);
    }
}

impl Unpack for ChannelAttrs {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let c = ChannelAttrs {
            headerpadsize: d.get_u32()?,
            maxrequestsize: d.get_u32()?,
            maxresponsesize: d.get_u32()?,
            maxresponsesize_cached: d.get_u32()?,
            maxoperations: d.get_u32()?,
            maxrequests: d.get_u32()?,
        };
        let _ird: Vec<u32> = d.get_array()?;
        Ok(c)
    }
}

/// Claim type of an OPEN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// CLAIM_NULL: open `name` inside the current filehandle (a directory).
    Null(Vec<u8>),
    /// CLAIM_FH (NFSv4.1+): open the current filehandle itself.
    Fh,
}

/// How an OPEN creates (or doesn't) the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenHow {
    NoCreate,
    /// createmode4: 0 UNCHECKED4, 1 GUARDED4, 2 EXCLUSIVE4, 3 EXCLUSIVE4_1.
    Create {
        mode: u32,
        verf: [u8; 8],
        attrs: Fattr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenArgs {
    pub seqid: u32,
    pub share_access: u32,
    pub clientid: u64,
    pub owner: Vec<u8>,
    pub how: OpenHow,
    pub claim: Claim,
}

/// createtype4 for CREATE: only directories and symlinks are used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateKind {
    Dir,
    Symlink(Vec<u8>),
}

/// One request operation (nfs_argop4). The SEQUENCE op is added by the
/// backend, not by callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Sequence {
        session: [u8; 16],
        seqid: u32,
        slot: u32,
        highest: u32,
    },
    ExchangeId {
        verifier: [u8; 8],
        owner: Vec<u8>,
    },
    CreateSession {
        clientid: u64,
        sequence: u32,
        fore: ChannelAttrs,
        back: ChannelAttrs,
        cb_program: u32,
    },
    DestroySession([u8; 16]),
    /// BIND_CONN_TO_SESSION for the fore channel (CDFC4_FORE), no RDMA.
    BindConnToSession([u8; 16]),
    DestroyClientid(u64),
    ReclaimComplete,
    Setclientid {
        verifier: [u8; 8],
        id: Vec<u8>,
        cb_program: u32,
        cb_addr: String,
        cb_ident: u32,
    },
    SetclientidConfirm {
        clientid: u64,
        verifier: [u8; 8],
    },
    Renew(u64),
    Putrootfh,
    Putfh(Vec<u8>),
    Getfh,
    Savefh,
    Lookup(Vec<u8>),
    Lookupp,
    Getattr(Vec<u32>),
    Setattr {
        stateid: StateId,
        attrs: Fattr,
    },
    Readlink,
    Read {
        stateid: StateId,
        offset: u64,
        count: u32,
    },
    /// `stable` is UNSTABLE4 or FILE_SYNC4.
    Write {
        stateid: StateId,
        offset: u64,
        data: Vec<u8>,
        stable: u32,
    },
    Commit {
        offset: u64,
        count: u32,
    },
    Open(OpenArgs),
    OpenConfirm {
        stateid: StateId,
        seqid: u32,
    },
    Close {
        seqid: u32,
        stateid: StateId,
    },
    DelegReturn(StateId),
    Create {
        kind: CreateKind,
        name: Vec<u8>,
        attrs: Fattr,
    },
    Remove(Vec<u8>),
    Rename {
        from: Vec<u8>,
        to: Vec<u8>,
    },
    Link(Vec<u8>),
    Readdir {
        cookie: u64,
        verifier: [u8; 8],
        dircount: u32,
        maxcount: u32,
        attrs: Vec<u32>,
    },
}

fn put_name(e: &mut Encoder, name: &[u8]) {
    e.put_string(name);
}

impl Pack for OpenArgs {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.seqid)
            .put_u32(self.share_access)
            .put_u32(0) // share_deny: OPEN4_SHARE_DENY_NONE
            .put_u64(self.clientid)
            .put_opaque(&self.owner);
        match &self.how {
            OpenHow::NoCreate => {
                e.put_u32(0);
            }
            OpenHow::Create { mode, verf, attrs } => {
                e.put_u32(1).put_u32(*mode);
                match mode {
                    0 | 1 => {
                        attrs.pack(e);
                    }
                    2 => {
                        e.put_opaque_fixed(verf);
                    }
                    _ => {
                        e.put_opaque_fixed(verf);
                        attrs.pack(e);
                    }
                }
            }
        }
        match &self.claim {
            Claim::Null(name) => {
                e.put_u32(0);
                put_name(e, name);
            }
            Claim::Fh => {
                e.put_u32(4);
            }
        }
    }
}

impl Pack for Op {
    fn pack(&self, e: &mut Encoder) {
        match self {
            Op::Sequence {
                session,
                seqid,
                slot,
                highest,
            } => {
                e.put_u32(OP_SEQUENCE)
                    .put_opaque_fixed(session)
                    .put_u32(*seqid)
                    .put_u32(*slot)
                    .put_u32(*highest)
                    .put_bool(false);
            }
            Op::ExchangeId { verifier, owner } => {
                e.put_u32(OP_EXCHANGE_ID)
                    .put_opaque_fixed(verifier)
                    .put_opaque(owner);
                e.put_u32(0x0001_0000); // EXCHGID4_FLAG_USE_NON_PNFS
                e.put_u32(0); // state_protect: SP4_NONE
                e.put_u32(0); // client_impl_id<1>: empty
            }
            Op::CreateSession {
                clientid,
                sequence,
                fore,
                back,
                cb_program,
            } => {
                e.put_u32(OP_CREATE_SESSION)
                    .put_u64(*clientid)
                    .put_u32(*sequence)
                    .put_u32(0);
                fore.pack(e);
                back.pack(e);
                e.put_u32(*cb_program);
                // csa_sec_parms<>: one entry, AUTH_NONE.
                e.put_u32(1).put_u32(0);
            }
            Op::DestroySession(id) => {
                e.put_u32(OP_DESTROY_SESSION).put_opaque_fixed(id);
            }
            Op::BindConnToSession(id) => {
                e.put_u32(OP_BIND_CONN_TO_SESSION)
                    .put_opaque_fixed(id)
                    .put_u32(1) // CDFC4_FORE
                    .put_bool(false); // bctsa_use_conn_in_rdma_mode
            }
            Op::DestroyClientid(id) => {
                e.put_u32(OP_DESTROY_CLIENTID).put_u64(*id);
            }
            Op::ReclaimComplete => {
                e.put_u32(OP_RECLAIM_COMPLETE).put_bool(false);
            }
            Op::Setclientid {
                verifier,
                id,
                cb_program,
                cb_addr,
                cb_ident,
            } => {
                e.put_u32(OP_SETCLIENTID)
                    .put_opaque_fixed(verifier)
                    .put_opaque(id);
                e.put_u32(*cb_program);
                e.put_string(b"tcp");
                e.put_string(cb_addr.as_bytes());
                e.put_u32(*cb_ident);
            }
            Op::SetclientidConfirm { clientid, verifier } => {
                e.put_u32(OP_SETCLIENTID_CONFIRM)
                    .put_u64(*clientid)
                    .put_opaque_fixed(verifier);
            }
            Op::Renew(id) => {
                e.put_u32(OP_RENEW).put_u64(*id);
            }
            Op::Putrootfh => {
                e.put_u32(OP_PUTROOTFH);
            }
            Op::Putfh(fh) => {
                e.put_u32(OP_PUTFH).put_opaque(fh);
            }
            Op::Getfh => {
                e.put_u32(OP_GETFH);
            }
            Op::Savefh => {
                e.put_u32(OP_SAVEFH);
            }
            Op::Lookup(name) => {
                e.put_u32(OP_LOOKUP);
                put_name(e, name);
            }
            Op::Lookupp => {
                e.put_u32(OP_LOOKUPP);
            }
            Op::Getattr(attrs) => {
                e.put_u32(OP_GETATTR).put_array(bitmap(attrs).as_slice());
            }
            Op::Setattr { stateid, attrs } => {
                e.put_u32(OP_SETATTR).put(stateid).put(attrs);
            }
            Op::Readlink => {
                e.put_u32(OP_READLINK);
            }
            Op::Read {
                stateid,
                offset,
                count,
            } => {
                e.put_u32(OP_READ)
                    .put(stateid)
                    .put_u64(*offset)
                    .put_u32(*count);
            }
            Op::Write {
                stateid,
                offset,
                data,
                stable,
            } => {
                e.put_u32(OP_WRITE)
                    .put(stateid)
                    .put_u64(*offset)
                    .put_u32(*stable)
                    .put_opaque(data);
            }
            Op::Commit { offset, count } => {
                e.put_u32(OP_COMMIT).put_u64(*offset).put_u32(*count);
            }
            Op::Open(args) => {
                e.put_u32(OP_OPEN).put(args);
            }
            Op::OpenConfirm { stateid, seqid } => {
                e.put_u32(OP_OPEN_CONFIRM).put(stateid).put_u32(*seqid);
            }
            Op::Close { seqid, stateid } => {
                e.put_u32(OP_CLOSE).put_u32(*seqid).put(stateid);
            }
            Op::DelegReturn(sid) => {
                e.put_u32(OP_DELEGRETURN).put(sid);
            }
            Op::Create { kind, name, attrs } => {
                e.put_u32(OP_CREATE);
                match kind {
                    CreateKind::Dir => {
                        e.put_u32(2); // NF4DIR
                    }
                    CreateKind::Symlink(target) => {
                        e.put_u32(5).put_string(target); // NF4LNK
                    }
                }
                put_name(e, name);
                attrs.pack(e);
            }
            Op::Remove(name) => {
                e.put_u32(OP_REMOVE);
                put_name(e, name);
            }
            Op::Rename { from, to } => {
                e.put_u32(OP_RENAME);
                put_name(e, from);
                put_name(e, to);
            }
            Op::Link(name) => {
                e.put_u32(OP_LINK);
                put_name(e, name);
            }
            Op::Readdir {
                cookie,
                verifier,
                dircount,
                maxcount,
                attrs,
            } => {
                e.put_u32(OP_READDIR)
                    .put_u64(*cookie)
                    .put_opaque_fixed(verifier)
                    .put_u32(*dircount)
                    .put_u32(*maxcount)
                    .put_array(bitmap(attrs).as_slice());
            }
        }
    }
}

/// One entry of a READDIR reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEnt {
    pub cookie: u64,
    pub name: Vec<u8>,
    pub attrs: AttrSet,
}

impl Unpack for DirEnt {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(DirEnt {
            cookie: d.get_u64()?,
            name: d.get_string()?,
            attrs: AttrSet::unpack(d)?,
        })
    }
}

/// Decoded result body of one operation. Operations that fail carry no body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Res {
    /// Status-only success (PUTFH, LOOKUP, RENEW, ...), or an op whose body we ignore.
    Empty,
    Stateid(StateId),
    Open {
        stateid: StateId,
        rflags: u32,
        deleg: Option<StateId>,
    },
    Fh(Vec<u8>),
    Attr(Box<AttrSet>),
    Read {
        eof: bool,
        data: Vec<u8>,
    },
    Write {
        count: u32,
        committed: u32,
        verf: [u8; 8],
    },
    Verf([u8; 8]),
    Readdir {
        verifier: [u8; 8],
        entries: Vec<DirEnt>,
        eof: bool,
    },
    Readlink(Vec<u8>),
    ExchangeId {
        clientid: u64,
        sequence: u32,
    },
    CreateSession {
        session: [u8; 16],
        sequence: u32,
        fore: ChannelAttrs,
    },
    Setclientid {
        clientid: u64,
        verifier: [u8; 8],
    },
}

/// One result: the opcode, its status, and the decoded body (if status is OK).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResOp {
    pub opcode: u32,
    pub status: u32,
    pub body: Res,
}

/// change_info4 (discarded).
fn skip_change_info(d: &mut Decoder<'_>) -> Result<()> {
    d.get_bool()?;
    d.get_u64()?;
    d.get_u64()?;
    Ok(())
}

fn skip_nfsace4(d: &mut Decoder<'_>) -> Result<()> {
    d.get_u32()?; // type
    d.get_u32()?; // flag
    d.get_u32()?; // access_mask
    d.get_string()?; // who
    Ok(())
}

fn decode_open_delegation(d: &mut Decoder<'_>) -> Result<Option<StateId>> {
    match d.get_u32()? {
        0 => Ok(None),
        1 => {
            // OPEN_DELEGATE_READ: stateid, recall, nfsace4
            let sid = d.get::<StateId>()?;
            d.get_bool()?;
            skip_nfsace4(d)?;
            Ok(Some(sid))
        }
        2 => {
            // OPEN_DELEGATE_WRITE: stateid, recall, space_limit, nfsace4
            let sid = d.get::<StateId>()?;
            d.get_bool()?;
            match d.get_u32()? {
                1 => {
                    d.get_u64()?;
                }
                2 => {
                    d.get_u32()?;
                    d.get_u32()?;
                }
                other => return Err(Error::Xdr(format!("bad limitby {other}"))),
            }
            skip_nfsace4(d)?;
            Ok(Some(sid))
        }
        3 => {
            // OPEN_DELEGATE_NONE_EXT (NFSv4.1, RFC 8881 §18.16.2): why_no_delegation4,
            // plus a boolean for WND4_CONTENTION (7) and WND4_RESOURCE (8).
            match d.get_u32()? {
                WND4_CONTENTION | WND4_RESOURCE => {
                    d.get_bool()?;
                }
                _ => {}
            }
            Ok(None)
        }
        other => Err(Error::Xdr(format!("unsupported delegation type {other}"))),
    }
}

/// why_no_delegation4 values that carry an extra boolean.
const WND4_CONTENTION: u32 = 7;
const WND4_RESOURCE: u32 = 8;

impl Unpack for ResOp {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let opcode = d.get_u32()?;
        let status = d.get_u32()?;
        // SETATTR's result always carries attrsset, even on failure.
        if opcode == OP_SETATTR {
            let _attrsset: Vec<u32> = d.get_array()?;
            return Ok(ResOp {
                opcode,
                status,
                body: Res::Empty,
            });
        }
        if status != code::OK {
            return Ok(ResOp {
                opcode,
                status,
                body: Res::Empty,
            });
        }
        let body = match opcode {
            OP_CLOSE | OP_OPEN_CONFIRM => Res::Stateid(d.get()?),
            OP_OPEN => {
                let stateid: StateId = d.get()?;
                skip_change_info(d)?;
                let rflags = d.get_u32()?;
                let _attrset: Vec<u32> = d.get_array()?;
                let deleg = decode_open_delegation(d)?;
                Res::Open {
                    stateid,
                    rflags,
                    deleg,
                }
            }
            OP_COMMIT => Res::Verf(get_verf(d)?),
            OP_CREATE => {
                skip_change_info(d)?;
                let _attrset: Vec<u32> = d.get_array()?;
                Res::Empty
            }
            OP_LINK | OP_REMOVE => {
                skip_change_info(d)?;
                Res::Empty
            }
            OP_RENAME => {
                skip_change_info(d)?;
                skip_change_info(d)?;
                Res::Empty
            }
            OP_GETATTR => Res::Attr(Box::new(d.get()?)),
            OP_GETFH => Res::Fh(d.get_opaque_vec()?),
            OP_READ => {
                let eof = d.get_bool()?;
                Res::Read {
                    eof,
                    data: d.get_opaque_vec()?,
                }
            }
            OP_WRITE => {
                let count = d.get_u32()?;
                let committed = d.get_u32()?;
                let verf = get_verf(d)?;
                Res::Write {
                    count,
                    committed,
                    verf,
                }
            }
            OP_READDIR => {
                let verifier = get_verf(d)?;
                let entries = d.get_list::<DirEnt>()?;
                let eof = d.get_bool()?;
                Res::Readdir {
                    verifier,
                    entries,
                    eof,
                }
            }
            OP_READLINK => Res::Readlink(d.get_string()?),
            OP_EXCHANGE_ID => {
                let clientid = d.get_u64()?;
                let sequence = d.get_u32()?;
                let _flags = d.get_u32()?;
                // state_protect4_r: only SP4_NONE is ever requested.
                let how = d.get_u32()?;
                if how != 0 {
                    return Err(Error::Xdr(format!("unexpected state protect {how}")));
                }
                let _minor_id = d.get_u64()?;
                let _major = d.get_opaque_vec()?;
                let _scope = d.get_opaque_vec()?;
                let _impl: Vec<SkipImplId> = d.get_array()?;
                Res::ExchangeId { clientid, sequence }
            }
            OP_CREATE_SESSION => {
                let session = get_session_id(d)?;
                let sequence = d.get_u32()?;
                let _flags = d.get_u32()?;
                let fore = ChannelAttrs::unpack(d)?;
                let _back = ChannelAttrs::unpack(d)?;
                Res::CreateSession {
                    session,
                    sequence,
                    fore,
                }
            }
            OP_SEQUENCE => {
                let _session = get_session_id(d)?;
                let _seq = d.get_u32()?;
                let _slot = d.get_u32()?;
                let _highest = d.get_u32()?;
                let _target = d.get_u32()?;
                let _flags = d.get_u32()?;
                Res::Empty
            }
            OP_BIND_CONN_TO_SESSION => {
                let _session = get_session_id(d)?;
                let _dir = d.get_u32()?;
                let _rdma = d.get_bool()?;
                Res::Empty
            }
            OP_SETCLIENTID => {
                let clientid = d.get_u64()?;
                let verifier = get_verf(d)?;
                Res::Setclientid { clientid, verifier }
            }
            OP_PUTFH
            | OP_PUTROOTFH
            | OP_SAVEFH
            | OP_LOOKUP
            | OP_LOOKUPP
            | OP_RENEW
            | OP_SETCLIENTID_CONFIRM
            | OP_DELEGRETURN
            | OP_DESTROY_SESSION
            | OP_DESTROY_CLIENTID
            | OP_RECLAIM_COMPLETE => Res::Empty,
            other => return Err(Error::Xdr(format!("unexpected result for opcode {other}"))),
        };
        Ok(ResOp {
            opcode,
            status,
            body,
        })
    }
}

/// nfs_impl_id4, decoded and dropped.
struct SkipImplId;

impl Unpack for SkipImplId {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        d.get_string()?;
        d.get_string()?;
        d.get_i64()?;
        d.get_u32()?;
        Ok(SkipImplId)
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{StateId, attr};
    use super::*;
    use crate::xdr::from_bytes;

    #[test]
    fn putfh_and_getattr_bytes() {
        let mut e = Encoder::new();
        e.put(&Op::Putfh(vec![1, 2, 3]));
        assert_eq!(e.as_bytes(), &[0, 0, 0, 22, 0, 0, 0, 3, 1, 2, 3, 0]);
        let mut e = Encoder::new();
        e.put(&Op::Getattr(vec![attr::TYPE]));
        // opcode 9, bitmap len 1, word 0x2 (bit 1), attr_vals empty? no: getattr args are bitmap only
        assert_eq!(e.as_bytes(), &[0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 2]);
    }

    #[test]
    fn resop_status_only_and_error_setattr() {
        // PUTROOTFH OK
        let r: ResOp = from_bytes(&[0, 0, 0, 24, 0, 0, 0, 0]).unwrap();
        assert_eq!(r.body, Res::Empty);
        // SETATTR NFS4ERR_PERM with attrsset bitmap of one word
        let r: ResOp = from_bytes(&[0, 0, 0, 34, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0]).unwrap();
        assert_eq!(r.status, 1);
        assert_eq!(r.body, Res::Empty);
    }

    #[test]
    fn close_roundtrip_bytes() {
        let sid = StateId {
            seqid: 7,
            other: [9; 12],
        };
        let mut e = Encoder::new();
        e.put(&Op::Close {
            seqid: 3,
            stateid: sid,
        });
        let mut want = vec![0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, 7];
        want.extend_from_slice(&[9; 12]);
        assert_eq!(e.as_bytes(), want.as_slice());
        // Reply: opcode 4, OK, stateid
        let mut reply = vec![0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 8];
        reply.extend_from_slice(&[1; 12]);
        let r: ResOp = from_bytes(&reply).unwrap();
        assert_eq!(
            r.body,
            Res::Stateid(StateId {
                seqid: 8,
                other: [1; 12]
            })
        );
    }
}
