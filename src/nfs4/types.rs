//! NFSv4 wire types shared by the COMPOUND codec and the backend: bitmap4,
//! fattr4 attribute sets, stateids, nfs status codes and attribute conversion
//! into the normalized [`crate::fs`] types.

use crate::error::{Error, Result};
use crate::fs::{Attr, FileType, FsStat, SetAttr, SetTime, Time};
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

/// nfsstat4 values the backend reacts to. Anything else goes through
/// [`crate::fs::Status::from_v4`].
pub mod code {
    pub const OK: u32 = 0;
    pub const BAD_COOKIE: u32 = 10003;
    pub const DELAY: u32 = 10008;
    pub const EXPIRED: u32 = 10011;
    pub const GRACE: u32 = 10013;
    pub const RESOURCE: u32 = 10018;
    pub const MOVED: u32 = 10019;
    pub const NOFILEHANDLE: u32 = 10020;
    pub const MINOR_VERS_MISMATCH: u32 = 10021;
    pub const STALE_CLIENTID: u32 = 10022;
    pub const STALE_STATEID: u32 = 10023;
    pub const OLD_STATEID: u32 = 10024;
    pub const BAD_STATEID: u32 = 10025;
    pub const BAD_SEQID: u32 = 10026;
    pub const BADXDR: u32 = 10036;
    pub const ADMIN_REVOKED: u32 = 10047;
    pub const BADSESSION: u32 = 10052;
    pub const BADSLOT: u32 = 10053;
    pub const COMPLETE_ALREADY: u32 = 10054;
    pub const SEQ_MISORDERED: u32 = 10063;
    pub const BAD_HIGH_SLOT: u32 = 10077;
    pub const DEADSESSION: u32 = 10078;
    pub const CONN_NOT_BOUND_TO_SESSION: u32 = 10055;
    pub const RETRY_UNCACHED_REP: u32 = 10068;
    pub const SEQ_FALSE_RETRY: u32 = 10076;
    pub const CB_PATH_DOWN: u32 = 10048;
}

/// Share access bits for OPEN.
pub const OPEN4_SHARE_ACCESS_READ: u32 = 1;
pub const OPEN4_SHARE_ACCESS_BOTH: u32 = 3;
/// OPEN result flag: the open must be confirmed with OPEN_CONFIRM (NFSv4.0).
pub const OPEN4_RESULT_CONFIRM: u32 = 0x2;

/// Attribute numbers (RFC 8881 section 5.8 / table in 14.2).
pub mod attr {
    pub const SUPPORTED_ATTRS: u32 = 0;
    pub const TYPE: u32 = 1;
    pub const SIZE: u32 = 4;
    pub const FSID: u32 = 8;
    pub const LEASE_TIME: u32 = 10;
    pub const RDATTR_ERROR: u32 = 11;
    pub const FILEHANDLE: u32 = 19;
    pub const FILEID: u32 = 20;
    pub const FILES_AVAIL: u32 = 21;
    pub const FILES_FREE: u32 = 22;
    pub const FILES_TOTAL: u32 = 23;
    pub const MAXREAD: u32 = 30;
    pub const MAXWRITE: u32 = 31;
    pub const MODE: u32 = 33;
    pub const NUMLINKS: u32 = 35;
    pub const OWNER: u32 = 36;
    pub const OWNER_GROUP: u32 = 37;
    pub const RAWDEV: u32 = 41;
    pub const SPACE_AVAIL: u32 = 42;
    pub const SPACE_FREE: u32 = 43;
    pub const SPACE_TOTAL: u32 = 44;
    pub const SPACE_USED: u32 = 45;
    pub const TIME_ACCESS: u32 = 47;
    pub const TIME_ACCESS_SET: u32 = 48;
    pub const TIME_METADATA: u32 = 52;
    pub const TIME_MODIFY: u32 = 53;
    pub const TIME_MODIFY_SET: u32 = 54;
}

/// Attributes requested for GETATTR / LOOKUP / CREATE results.
pub const BASIC_ATTRS: &[u32] = &[
    attr::TYPE,
    attr::SIZE,
    attr::FSID,
    attr::FILEID,
    attr::MODE,
    attr::NUMLINKS,
    attr::OWNER,
    attr::OWNER_GROUP,
    attr::RAWDEV,
    attr::SPACE_USED,
    attr::TIME_ACCESS,
    attr::TIME_METADATA,
    attr::TIME_MODIFY,
];

/// Attributes requested per entry in READDIR.
pub const READDIR_ATTRS: &[u32] = &[
    attr::TYPE,
    attr::SIZE,
    attr::FSID,
    attr::FILEID,
    attr::MODE,
    attr::NUMLINKS,
    attr::OWNER,
    attr::OWNER_GROUP,
    attr::RAWDEV,
    attr::SPACE_USED,
    attr::TIME_ACCESS,
    attr::TIME_METADATA,
    attr::TIME_MODIFY,
    attr::RDATTR_ERROR,
    attr::FILEHANDLE,
];

/// Attributes requested for fsstat.
pub const FSSTAT_ATTRS: &[u32] = &[
    attr::SPACE_AVAIL,
    attr::SPACE_FREE,
    attr::SPACE_TOTAL,
    attr::FILES_AVAIL,
    attr::FILES_FREE,
    attr::FILES_TOTAL,
];

/// Build a bitmap4 (array of 32-bit words; attribute n is bit n%32 of word n/32).
pub fn bitmap(attrs: &[u32]) -> Vec<u32> {
    let mut words: Vec<u32> = Vec::new();
    for &a in attrs {
        let w = (a / 32) as usize;
        if words.len() <= w {
            words.resize(w + 1, 0);
        }
        words[w] |= 1 << (a % 32);
    }
    words
}

/// fattr4 as sent on the wire: attribute bitmap plus the packed values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fattr {
    pub bitmap: Vec<u32>,
    pub vals: Vec<u8>,
}

impl Fattr {
    pub fn is_empty(&self) -> bool {
        self.bitmap.iter().all(|w| *w == 0)
    }
}

impl Pack for Fattr {
    fn pack(&self, e: &mut Encoder) {
        e.put_array(self.bitmap.as_slice());
        e.put_opaque(&self.vals);
    }
}

fn put_settime(e: &mut Encoder, t: SetTime) {
    match t {
        SetTime::ServerNow => {
            e.put_u32(0);
        }
        SetTime::Client(t) => {
            e.put_u32(1);
            put_nfstime(e, t);
        }
    }
}

pub fn put_nfstime(e: &mut Encoder, t: Time) {
    e.put_i64(t.seconds).put_u32(t.nseconds);
}

fn get_nfstime(d: &mut Decoder<'_>) -> Result<Time> {
    Ok(Time {
        seconds: d.get_i64()?,
        nseconds: d.get_u32()?,
    })
}

/// Encode the settable subset of `a`. `default_mode` applies when `a.mode` is
/// None (CREATE needs a mode; SETATTR passes None). Owner / group strings take
/// precedence over uid / gid, which are sent in decimal form.
pub fn encode_setattr(a: &SetAttr, default_mode: Option<u32>) -> Fattr {
    let mut attrs = Vec::new();
    let mut v = Encoder::new();
    if let Some(sz) = a.size {
        attrs.push(attr::SIZE);
        v.put_u64(sz);
    }
    if let Some(m) = a.mode.or(default_mode) {
        attrs.push(attr::MODE);
        v.put_u32(m & 0o7777);
    }
    if let Some(o) = a.owner.clone().or_else(|| a.uid.map(|u| u.to_string())) {
        attrs.push(attr::OWNER);
        v.put_string(o.as_bytes());
    }
    if let Some(g) = a.group.clone().or_else(|| a.gid.map(|u| u.to_string())) {
        attrs.push(attr::OWNER_GROUP);
        v.put_string(g.as_bytes());
    }
    if let Some(t) = a.atime {
        attrs.push(attr::TIME_ACCESS_SET);
        put_settime(&mut v, t);
    }
    if let Some(t) = a.mtime {
        attrs.push(attr::TIME_MODIFY_SET);
        put_settime(&mut v, t);
    }
    Fattr {
        bitmap: bitmap(&attrs),
        vals: v.into_inner(),
    }
}

/// Decoded fattr4. Only attributes the backend requests can appear; an
/// unrequested attribute bit is a protocol error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttrSet {
    pub supported: Option<Vec<u32>>,
    pub ftype: Option<u32>,
    pub size: Option<u64>,
    pub fsid: Option<(u64, u64)>,
    pub lease_time: Option<u32>,
    pub rdattr_error: Option<u32>,
    pub filehandle: Option<Vec<u8>>,
    pub fileid: Option<u64>,
    pub files_avail: Option<u64>,
    pub files_free: Option<u64>,
    pub files_total: Option<u64>,
    pub maxread: Option<u64>,
    pub maxwrite: Option<u64>,
    pub mode: Option<u32>,
    pub numlinks: Option<u32>,
    pub owner: Option<String>,
    pub owner_group: Option<String>,
    pub rawdev: Option<(u32, u32)>,
    pub space_avail: Option<u64>,
    pub space_free: Option<u64>,
    pub space_total: Option<u64>,
    pub space_used: Option<u64>,
    pub time_access: Option<Time>,
    pub time_metadata: Option<Time>,
    pub time_modify: Option<Time>,
}

impl AttrSet {
    fn decode_one(&mut self, a: u32, v: &mut Decoder<'_>) -> Result<()> {
        match a {
            attr::SUPPORTED_ATTRS => self.supported = Some(v.get_array::<u32>()?),
            attr::TYPE => self.ftype = Some(v.get_u32()?),
            attr::SIZE => self.size = Some(v.get_u64()?),
            attr::FSID => self.fsid = Some((v.get_u64()?, v.get_u64()?)),
            attr::LEASE_TIME => self.lease_time = Some(v.get_u32()?),
            attr::RDATTR_ERROR => self.rdattr_error = Some(v.get_u32()?),
            attr::FILEHANDLE => self.filehandle = Some(v.get_opaque_vec()?),
            attr::FILEID => self.fileid = Some(v.get_u64()?),
            attr::FILES_AVAIL => self.files_avail = Some(v.get_u64()?),
            attr::FILES_FREE => self.files_free = Some(v.get_u64()?),
            attr::FILES_TOTAL => self.files_total = Some(v.get_u64()?),
            attr::MAXREAD => self.maxread = Some(v.get_u64()?),
            attr::MAXWRITE => self.maxwrite = Some(v.get_u64()?),
            attr::MODE => self.mode = Some(v.get_u32()?),
            attr::NUMLINKS => self.numlinks = Some(v.get_u32()?),
            attr::OWNER => self.owner = Some(v.get_string_lossy()?),
            attr::OWNER_GROUP => self.owner_group = Some(v.get_string_lossy()?),
            attr::RAWDEV => self.rawdev = Some((v.get_u32()?, v.get_u32()?)),
            attr::SPACE_AVAIL => self.space_avail = Some(v.get_u64()?),
            attr::SPACE_FREE => self.space_free = Some(v.get_u64()?),
            attr::SPACE_TOTAL => self.space_total = Some(v.get_u64()?),
            attr::SPACE_USED => self.space_used = Some(v.get_u64()?),
            attr::TIME_ACCESS => self.time_access = Some(get_nfstime(v)?),
            attr::TIME_METADATA => self.time_metadata = Some(get_nfstime(v)?),
            attr::TIME_MODIFY => self.time_modify = Some(get_nfstime(v)?),
            other => {
                return Err(Error::Xdr(format!(
                    "unrequested attribute {other} in reply"
                )));
            }
        }
        Ok(())
    }

    /// Convert to the normalized attribute record; missing fields default to zero.
    pub fn to_attr(&self) -> Attr {
        let uid = self.owner.as_deref().map(id_of).unwrap_or(u32::MAX);
        let gid = self.owner_group.as_deref().map(id_of).unwrap_or(u32::MAX);
        Attr {
            ftype: ftype_of(self.ftype.unwrap_or(0)),
            mode: self.mode.unwrap_or(0) & 0o7777,
            nlink: self.numlinks.unwrap_or(0),
            uid,
            gid,
            owner: self.owner.clone(),
            group: self.owner_group.clone(),
            size: self.size.unwrap_or(0),
            used: self.space_used.unwrap_or(0),
            rdev: self.rawdev.unwrap_or((0, 0)),
            fsid: self
                .fsid
                .map(|(major, minor)| major ^ minor.rotate_left(32))
                .unwrap_or(0),
            fileid: self.fileid.unwrap_or(0),
            atime: self.time_access.unwrap_or_default(),
            mtime: self.time_modify.unwrap_or_default(),
            ctime: self.time_metadata.unwrap_or_default(),
        }
    }

    pub fn to_fsstat(&self) -> FsStat {
        FsStat {
            total_bytes: self.space_total.unwrap_or(0),
            free_bytes: self.space_free.unwrap_or(0),
            avail_bytes: self.space_avail.unwrap_or(0),
            total_files: self.files_total.unwrap_or(0),
            free_files: self.files_free.unwrap_or(0),
            avail_files: self.files_avail.unwrap_or(0),
        }
    }
}

impl Unpack for AttrSet {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let bm: Vec<u32> = d.get_array()?;
        let vals = d.get_opaque()?;
        let mut v = Decoder::new(vals);
        let mut s = AttrSet::default();
        for (wi, w) in bm.iter().enumerate() {
            for b in 0..32u32 {
                if w & (1 << b) != 0 {
                    s.decode_one(wi as u32 * 32 + b, &mut v)?;
                }
            }
        }
        v.finish()?;
        Ok(s)
    }
}

/// Owner/group conversion: a decimal string maps to that id; anything else
/// (`user@domain`) maps to `u32::MAX`. The string itself is kept in
/// `Attr::owner` / `Attr::group`.
pub fn id_of(s: &str) -> u32 {
    s.parse::<u32>().unwrap_or(u32::MAX)
}

pub fn ftype_of(t: u32) -> FileType {
    match t {
        1 => FileType::Regular,
        2 => FileType::Directory,
        3 => FileType::BlockDevice,
        4 => FileType::CharDevice,
        5 => FileType::Symlink,
        6 => FileType::Socket,
        7 => FileType::Fifo,
        other => FileType::Other(other),
    }
}

/// stateid4: a sequence number plus a 12-byte opaque tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StateId {
    pub seqid: u32,
    pub other: [u8; 12],
}

/// The anonymous stateid (all zero): used for READ/WRITE/SETATTR when no open exists.
pub const ANON_STATEID: StateId = StateId {
    seqid: 0,
    other: [0; 12],
};

/// The READ-bypass stateid (all ones).
pub const BYPASS_STATEID: StateId = StateId {
    seqid: u32::MAX,
    other: [0xff; 12],
};

impl StateId {
    /// Whether this is one of the special stateids (anonymous or READ bypass),
    /// which carry no client state.
    pub fn is_special(&self) -> bool {
        *self == ANON_STATEID || *self == BYPASS_STATEID
    }
}

impl Pack for StateId {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.seqid);
        e.put_opaque_fixed(&self.other);
    }
}

impl Unpack for StateId {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let seqid = d.get_u32()?;
        let mut other = [0u8; 12];
        other.copy_from_slice(d.get_opaque_fixed(12)?);
        Ok(StateId { seqid, other })
    }
}

/// Fixed 8-byte verifier4 / cookieverf4.
pub fn get_verf(d: &mut Decoder<'_>) -> Result<[u8; 8]> {
    let mut v = [0u8; 8];
    v.copy_from_slice(d.get_opaque_fixed(8)?);
    Ok(v)
}

/// Fixed 16-byte sessionid4.
pub fn get_session_id(d: &mut Decoder<'_>) -> Result<[u8; 16]> {
    let mut v = [0u8; 16];
    v.copy_from_slice(d.get_opaque_fixed(16)?);
    Ok(v)
}
