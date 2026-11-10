//! NFSv3 wire types (RFC 1813 sections 2 and 3): attributes, sattr, wcc data,
//! and the small helpers the procedure codecs share.

use crate::error::{Error, Result};
use crate::fs::{Attr, FileHandle, FileType, SetAttr, SetTime, Status, Time};
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

/// Maximum file handle size in NFSv3.
pub const FHSIZE: usize = 64;

/// stable_how
pub const UNSTABLE: u32 = 0;
pub const FILE_SYNC: u32 = 2;

/// createmode3
pub const CREATE_UNCHECKED: u32 = 0;
pub const CREATE_GUARDED: u32 = 1;
pub const CREATE_EXCLUSIVE: u32 = 2;

/// ftype3
pub const NF3REG: u32 = 1;
pub const NF3DIR: u32 = 2;
pub const NF3BLK: u32 = 3;
pub const NF3CHR: u32 = 4;
pub const NF3LNK: u32 = 5;
pub const NF3SOCK: u32 = 6;
pub const NF3FIFO: u32 = 7;

/// ACCESS bits (RFC 1813 section 3.3.4).
pub const ACCESS3_READ: u32 = 0x0001;
pub const ACCESS3_LOOKUP: u32 = 0x0002;
pub const ACCESS3_MODIFY: u32 = 0x0004;
pub const ACCESS3_EXTEND: u32 = 0x0008;
pub const ACCESS3_DELETE: u32 = 0x0010;
pub const ACCESS3_EXECUTE: u32 = 0x0020;

/// Write verifier, cookie verifier and create verifier are all 8 opaque bytes.
pub type Verf = [u8; 8];

/// Check a leading nfsstat3. Success returns Ok; any other value becomes `Error::Nfs`.
pub fn check_status(d: &mut Decoder<'_>) -> Result<()> {
    match d.get_u32()? {
        0 => Ok(()),
        code => Err(Error::Nfs(Status::from_v3(code))),
    }
}

/// nfs_fh3: variable opaque up to 64 bytes.
pub fn put_fh(e: &mut Encoder, fh: &FileHandle) {
    e.put_opaque(&fh.0);
}

pub fn get_fh(d: &mut Decoder<'_>) -> Result<FileHandle> {
    Ok(FileHandle(d.get_opaque_max(FHSIZE)?.to_vec()))
}

/// post_op_fh3: optional nfs_fh3.
pub fn get_opt_fh(d: &mut Decoder<'_>) -> Result<Option<FileHandle>> {
    if d.get_bool()? {
        Ok(Some(get_fh(d)?))
    } else {
        Ok(None)
    }
}

pub fn put_verf(e: &mut Encoder, v: &Verf) {
    e.put_opaque_fixed(v);
}

pub fn get_verf(d: &mut Decoder<'_>) -> Result<Verf> {
    let mut v = [0u8; 8];
    v.copy_from_slice(d.get_opaque_fixed(8)?);
    Ok(v)
}

/// nfstime3 (seconds and nanoseconds, both unsigned 32-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NfsTime {
    pub seconds: u32,
    pub nseconds: u32,
}

impl NfsTime {
    pub fn to_time(self) -> Time {
        Time {
            seconds: i64::from(self.seconds),
            nseconds: self.nseconds,
        }
    }

    /// Clamp a normalized time into the NFSv3 range.
    pub fn from_time(t: Time) -> Self {
        NfsTime {
            seconds: u32::try_from(t.seconds.clamp(0, i64::from(u32::MAX))).unwrap_or(u32::MAX),
            nseconds: t.nseconds,
        }
    }
}

impl Pack for NfsTime {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.seconds).put_u32(self.nseconds);
    }
}

impl Unpack for NfsTime {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(NfsTime {
            seconds: d.get_u32()?,
            nseconds: d.get_u32()?,
        })
    }
}

/// fattr3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fattr3 {
    pub ftype: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub used: u64,
    /// specdata3 (major, minor).
    pub rdev: (u32, u32),
    pub fsid: u64,
    pub fileid: u64,
    pub atime: NfsTime,
    pub mtime: NfsTime,
    pub ctime: NfsTime,
}

impl Unpack for Fattr3 {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Fattr3 {
            ftype: d.get_u32()?,
            mode: d.get_u32()?,
            nlink: d.get_u32()?,
            uid: d.get_u32()?,
            gid: d.get_u32()?,
            size: d.get_u64()?,
            used: d.get_u64()?,
            rdev: (d.get_u32()?, d.get_u32()?),
            fsid: d.get_u64()?,
            fileid: d.get_u64()?,
            atime: NfsTime::unpack(d)?,
            mtime: NfsTime::unpack(d)?,
            ctime: NfsTime::unpack(d)?,
        })
    }
}

fn map_ftype(t: u32) -> FileType {
    match t {
        NF3REG => FileType::Regular,
        NF3DIR => FileType::Directory,
        NF3BLK => FileType::BlockDevice,
        NF3CHR => FileType::CharDevice,
        NF3LNK => FileType::Symlink,
        NF3SOCK => FileType::Socket,
        NF3FIFO => FileType::Fifo,
        other => FileType::Other(other),
    }
}

impl Fattr3 {
    /// Normalize to the version-agnostic [`Attr`].
    pub fn to_attr(&self) -> Attr {
        Attr {
            ftype: map_ftype(self.ftype),
            mode: self.mode & 0o7777,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            owner: None,
            group: None,
            size: self.size,
            used: self.used,
            rdev: self.rdev,
            fsid: self.fsid,
            fileid: self.fileid,
            atime: self.atime.to_time(),
            mtime: self.mtime.to_time(),
            ctime: self.ctime.to_time(),
        }
    }
}

/// post_op_attr: optional fattr3.
pub fn get_opt_attr(d: &mut Decoder<'_>) -> Result<Option<Fattr3>> {
    d.get_option::<Fattr3>()
}

/// wcc_attr: the pre-operation attributes that clients compare for cache validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WccAttr {
    pub size: u64,
    pub mtime: NfsTime,
    pub ctime: NfsTime,
}

impl Unpack for WccAttr {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(WccAttr {
            size: d.get_u64()?,
            mtime: NfsTime::unpack(d)?,
            ctime: NfsTime::unpack(d)?,
        })
    }
}

/// wcc_data: pre_op_attr then post_op_attr.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WccData {
    pub before: Option<WccAttr>,
    pub after: Option<Fattr3>,
}

impl Unpack for WccData {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let before = d.get_option::<WccAttr>()?;
        let after = get_opt_attr(d)?;
        Ok(WccData { before, after })
    }
}

/// How a SET_TO_*_TIME value is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeSet {
    #[default]
    DontChange,
    ServerTime,
    Client(NfsTime),
}

/// sattr3: each field is optional on the wire (set_mode3 etc.).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sattr3 {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: TimeSet,
    pub mtime: TimeSet,
}

fn put_time_set(e: &mut Encoder, t: &TimeSet) {
    match t {
        TimeSet::DontChange => {
            e.put_u32(0);
        }
        TimeSet::ServerTime => {
            e.put_u32(1);
        }
        TimeSet::Client(t) => {
            e.put_u32(2);
            t.pack(e);
        }
    }
}

impl Pack for Sattr3 {
    fn pack(&self, e: &mut Encoder) {
        e.put_option(self.mode.as_ref());
        e.put_option(self.uid.as_ref());
        e.put_option(self.gid.as_ref());
        e.put_option(self.size.as_ref());
        put_time_set(e, &self.atime);
        put_time_set(e, &self.mtime);
    }
}

fn map_set_time(t: Option<SetTime>) -> TimeSet {
    match t {
        None => TimeSet::DontChange,
        Some(SetTime::ServerNow) => TimeSet::ServerTime,
        Some(SetTime::Client(t)) => TimeSet::Client(NfsTime::from_time(t)),
    }
}

impl Sattr3 {
    /// Convert the version-agnostic attributes. v3 has no owner/group strings, so
    /// those fields of [`SetAttr`] are ignored.
    pub fn from_fs(a: &SetAttr) -> Self {
        Sattr3 {
            mode: a.mode.map(|m| m & 0o7777),
            uid: a.uid,
            gid: a.gid,
            size: a.size,
            atime: map_set_time(a.atime),
            mtime: map_set_time(a.mtime),
        }
    }
}

/// createhow3 for CREATE: UNCHECKED and GUARDED carry attributes, EXCLUSIVE a verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateHow {
    Unchecked(Sattr3),
    Guarded(Sattr3),
    Exclusive(Verf),
}

impl Pack for CreateHow {
    fn pack(&self, e: &mut Encoder) {
        match self {
            CreateHow::Unchecked(s) => {
                e.put_u32(CREATE_UNCHECKED);
                s.pack(e);
            }
            CreateHow::Guarded(s) => {
                e.put_u32(CREATE_GUARDED);
                s.pack(e);
            }
            CreateHow::Exclusive(v) => {
                e.put_u32(CREATE_EXCLUSIVE);
                put_verf(e, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::{from_bytes, to_bytes};

    #[test]
    fn sattr_all_unset_is_six_zero_words() {
        // 4 absent optionals (4 bytes each) + 2 DONT_CHANGE time_how discriminants.
        assert_eq!(to_bytes(&Sattr3::default()), [0u8; 24]);
    }

    #[test]
    fn sattr_mode_and_times_byte_exact() {
        let s = Sattr3 {
            mode: Some(0o644),
            uid: None,
            gid: Some(100),
            size: Some(0x1_0000_0002),
            atime: TimeSet::ServerTime,
            mtime: TimeSet::Client(NfsTime {
                seconds: 7,
                nseconds: 9,
            }),
        };
        let want: &[u8] = &[
            0, 0, 0, 1, 0, 0, 0x01, 0xa4, // mode = 0644
            0, 0, 0, 0, // uid absent
            0, 0, 0, 1, 0, 0, 0, 100, // gid = 100
            0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, // size = 2^32+2
            0, 0, 0, 1, // atime: SET_TO_SERVER_TIME
            0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 9, // mtime: SET_TO_CLIENT_TIME 7.9
        ];
        assert_eq!(to_bytes(&s), want);
    }

    #[test]
    fn create_how_exclusive_has_verifier_only() {
        let b = to_bytes(&CreateHow::Exclusive([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(b, [0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn create_how_guarded_carries_sattr() {
        let b = to_bytes(&CreateHow::Guarded(Sattr3::default()));
        assert_eq!(b.len(), 4 + 24);
        assert_eq!(&b[..4], [0, 0, 0, 1]);
    }

    fn sample_fattr_bytes() -> Vec<u8> {
        let mut e = Encoder::new();
        e.put_u32(NF3REG) // type
            .put_u32(0o100644) // mode
            .put_u32(1) // nlink
            .put_u32(1000) // uid
            .put_u32(100) // gid
            .put_u64(12345) // size
            .put_u64(16384) // used
            .put_u32(8) // rdev major
            .put_u32(1) // rdev minor
            .put_u64(0xabcd) // fsid
            .put_u64(42) // fileid
            .put_u32(1_700_000_000)
            .put_u32(1)
            .put_u32(1_700_000_001)
            .put_u32(2)
            .put_u32(1_700_000_002)
            .put_u32(3);
        e.into_inner()
    }

    #[test]
    fn fattr3_decodes_and_converts() {
        let f: Fattr3 = from_bytes(&sample_fattr_bytes()).unwrap();
        assert_eq!(f.size, 12345);
        assert_eq!(f.rdev, (8, 1));
        let a = f.to_attr();
        assert_eq!(a.ftype, FileType::Regular);
        assert_eq!(a.mode, 0o644, "file type bits must be stripped");
        assert_eq!(a.fileid, 42);
        assert_eq!(
            a.mtime,
            Time {
                seconds: 1_700_000_001,
                nseconds: 2
            }
        );
        assert_eq!(a.owner, None);
    }

    #[test]
    fn ftype_mapping() {
        let mut f = from_bytes::<Fattr3>(&sample_fattr_bytes()).unwrap();
        for (raw, want) in [
            (NF3DIR, FileType::Directory),
            (NF3LNK, FileType::Symlink),
            (NF3BLK, FileType::BlockDevice),
            (NF3CHR, FileType::CharDevice),
            (NF3SOCK, FileType::Socket),
            (NF3FIFO, FileType::Fifo),
            (99, FileType::Other(99)),
        ] {
            f.ftype = raw;
            assert_eq!(f.to_attr().ftype, want);
        }
    }

    #[test]
    fn fattr3_truncated_is_error() {
        let b = sample_fattr_bytes();
        assert!(from_bytes::<Fattr3>(&b[..b.len() - 4]).is_err());
    }

    #[test]
    fn wcc_data_with_both_present() {
        let mut e = Encoder::new();
        e.put_bool(true)
            .put_u64(5)
            .put_u32(1)
            .put_u32(2)
            .put_u32(3)
            .put_u32(4);
        e.put_bool(true).put_opaque_fixed(&sample_fattr_bytes());
        let w: WccData = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(w.before.unwrap().size, 5);
        assert_eq!(w.after.unwrap().fileid, 42);
    }

    #[test]
    fn wcc_data_both_absent() {
        let w: WccData = from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(w, WccData::default());
    }

    #[test]
    fn verifier_and_handle_helpers() {
        let mut e = Encoder::new();
        put_fh(&mut e, &FileHandle(vec![9, 8, 7]));
        assert_eq!(e.as_bytes(), [0, 0, 0, 3, 9, 8, 7, 0]);
        let mut d = Decoder::new(e.as_bytes());
        assert_eq!(get_fh(&mut d).unwrap(), FileHandle(vec![9, 8, 7]));
        d.finish().unwrap();

        let too_long = [0, 0, 0, 65, 0, 0, 0, 0];
        assert!(get_fh(&mut Decoder::new(&too_long)).is_err());

        let mut e = Encoder::new();
        put_verf(&mut e, &[1; 8]);
        assert_eq!(get_verf(&mut Decoder::new(e.as_bytes())).unwrap(), [1; 8]);
    }

    #[test]
    fn check_status_maps_errors() {
        assert!(check_status(&mut Decoder::new(&[0, 0, 0, 0])).is_ok());
        assert!(matches!(
            check_status(&mut Decoder::new(&[0, 0, 0, 17])),
            Err(Error::Nfs(Status::Exist))
        ));
        assert!(matches!(
            check_status(&mut Decoder::new(&[0, 0, 0x27, 0x13])),
            Err(Error::Nfs(Status::BadCookie))
        ));
    }

    #[test]
    fn set_time_clamps() {
        assert_eq!(
            NfsTime::from_time(Time {
                seconds: -5,
                nseconds: 0
            })
            .seconds,
            0
        );
        assert_eq!(
            NfsTime::from_time(Time {
                seconds: 1 << 40,
                nseconds: 0
            })
            .seconds,
            u32::MAX
        );
    }
}
