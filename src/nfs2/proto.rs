//! NFSv2 wire types and procedure numbers (RFC 1094, section 2 and appendix).
//!
//! Pure codec, no I/O. Field order follows the RFC's XDR definitions. Every
//! type implements both [`Pack`] and [`Unpack`] so the same definitions serve
//! the client backend and the in-tests server.

use crate::error::{Error, Result};
use crate::fs::{FileHandle, NfsVersion, Status};
use crate::xdr::{Decoder, Encoder, Opaque, Pack, Unpack};

/// Size of the fixed-length `fhandle`.
pub const FHSIZE: usize = 32;
/// Maximum data bytes in one READ or WRITE (`MAXDATA`).
pub const MAXDATA: u32 = 8192;
/// Maximum filename length (`MAXNAMLEN`).
pub const MAXNAMLEN: usize = 255;
/// Maximum symlink target length (`MAXPATHLEN`).
pub const MAXPATHLEN: usize = 1024;
/// Value of an unset `sattr` field (RFC 1094 section 2.3.5: "-1").
pub const UNSET: u32 = u32::MAX;

pub const PROC_NULL: u32 = 0;
pub const PROC_GETATTR: u32 = 1;
pub const PROC_SETATTR: u32 = 2;
// 3 = ROOT (obsolete, not implemented).
pub const PROC_LOOKUP: u32 = 4;
pub const PROC_READLINK: u32 = 5;
pub const PROC_READ: u32 = 6;
// 7 = WRITECACHE (obsolete, not implemented).
pub const PROC_WRITE: u32 = 8;
pub const PROC_CREATE: u32 = 9;
pub const PROC_REMOVE: u32 = 10;
pub const PROC_RENAME: u32 = 11;
pub const PROC_LINK: u32 = 12;
pub const PROC_SYMLINK: u32 = 13;
pub const PROC_MKDIR: u32 = 14;
pub const PROC_RMDIR: u32 = 15;
pub const PROC_READDIR: u32 = 16;
pub const PROC_STATFS: u32 = 17;

/// `ftype` values.
pub const NFNON: u32 = 0;
pub const NFREG: u32 = 1;
pub const NFDIR: u32 = 2;
pub const NFBLK: u32 = 3;
pub const NFCHR: u32 = 4;
pub const NFLNK: u32 = 5;

/// `fhandle`: 32 opaque bytes, no length prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFh(pub [u8; FHSIZE]);

impl WireFh {
    /// Returns `None` unless the handle is exactly 32 bytes.
    pub fn from_fs(fh: &FileHandle) -> Option<Self> {
        <[u8; FHSIZE]>::try_from(fh.0.as_slice()).ok().map(WireFh)
    }

    pub fn to_fs(&self) -> FileHandle {
        FileHandle(self.0.to_vec())
    }
}

impl Pack for WireFh {
    fn pack(&self, e: &mut Encoder) {
        e.put_opaque_fixed(&self.0);
    }
}

impl Unpack for WireFh {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let bytes = d.get_opaque_fixed(FHSIZE)?;
        let arr: [u8; FHSIZE] = bytes
            .try_into()
            .map_err(|_| Error::Xdr("fhandle is not 32 bytes".into()))?;
        Ok(WireFh(arr))
    }
}

/// `cookie`: opaque[4] used by READDIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cookie(pub [u8; 4]);

impl Pack for Cookie {
    fn pack(&self, e: &mut Encoder) {
        e.put_opaque_fixed(&self.0);
    }
}

impl Unpack for Cookie {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let bytes = d.get_opaque_fixed(4)?;
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| Error::Xdr("cookie is not 4 bytes".into()))?;
        Ok(Cookie(arr))
    }
}

/// `timeval`: seconds and microseconds, both unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeVal {
    pub seconds: u32,
    pub useconds: u32,
}

impl TimeVal {
    /// Both fields "-1": leave the time untouched in a `sattr`.
    pub const UNSET: TimeVal = TimeVal {
        seconds: UNSET,
        useconds: UNSET,
    };
}

impl Pack for TimeVal {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.seconds).put_u32(self.useconds);
    }
}

impl Unpack for TimeVal {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(TimeVal {
            seconds: d.get_u32()?,
            useconds: d.get_u32()?,
        })
    }
}

/// `fattr`: file attributes (68 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fattr {
    /// One of the `NF*` constants.
    pub ftype: u32,
    /// Mode including the file-type bits (`st_mode`).
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub blocksize: u32,
    pub rdev: u32,
    /// Number of `blocksize`-byte blocks allocated.
    pub blocks: u32,
    pub fsid: u32,
    pub fileid: u32,
    pub atime: TimeVal,
    pub mtime: TimeVal,
    pub ctime: TimeVal,
}

impl Pack for Fattr {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.ftype)
            .put_u32(self.mode)
            .put_u32(self.nlink)
            .put_u32(self.uid)
            .put_u32(self.gid)
            .put_u32(self.size)
            .put_u32(self.blocksize)
            .put_u32(self.rdev)
            .put_u32(self.blocks)
            .put_u32(self.fsid)
            .put_u32(self.fileid);
        e.put(&self.atime).put(&self.mtime).put(&self.ctime);
    }
}

impl Unpack for Fattr {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Fattr {
            ftype: d.get_u32()?,
            mode: d.get_u32()?,
            nlink: d.get_u32()?,
            uid: d.get_u32()?,
            gid: d.get_u32()?,
            size: d.get_u32()?,
            blocksize: d.get_u32()?,
            rdev: d.get_u32()?,
            blocks: d.get_u32()?,
            fsid: d.get_u32()?,
            fileid: d.get_u32()?,
            atime: d.get()?,
            mtime: d.get()?,
            ctime: d.get()?,
        })
    }
}

/// `sattr`: settable attributes. [`UNSET`] (or [`TimeVal::UNSET`]) means "leave alone".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sattr {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u32,
    pub atime: TimeVal,
    pub mtime: TimeVal,
}

impl Sattr {
    /// Every field unset.
    pub fn unset() -> Self {
        Sattr {
            mode: UNSET,
            uid: UNSET,
            gid: UNSET,
            size: UNSET,
            atime: TimeVal::UNSET,
            mtime: TimeVal::UNSET,
        }
    }
}

impl Pack for Sattr {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.mode)
            .put_u32(self.uid)
            .put_u32(self.gid)
            .put_u32(self.size);
        e.put(&self.atime).put(&self.mtime);
    }
}

impl Unpack for Sattr {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Sattr {
            mode: d.get_u32()?,
            uid: d.get_u32()?,
            gid: d.get_u32()?,
            size: d.get_u32()?,
            atime: d.get()?,
            mtime: d.get()?,
        })
    }
}

/// `stat` discriminated union: `Ok` carries the success arm, `Err` the status
/// (only the status is on the wire for failures, per the RFC's `default: void`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Res<T> {
    Ok(T),
    Err(u32),
}

impl<T> Res<T> {
    /// Converts to a crate `Result`, mapping the status through [`status`].
    pub fn into_result(self) -> Result<T> {
        match self {
            Res::Ok(v) => Ok(v),
            Res::Err(s) => Err(Error::Nfs(status(s))),
        }
    }
}

impl<T: Pack> Pack for Res<T> {
    fn pack(&self, e: &mut Encoder) {
        match self {
            Res::Ok(v) => {
                e.put_u32(0);
                v.pack(e);
            }
            Res::Err(s) => {
                e.put_u32(*s);
            }
        }
    }
}

impl<T: Unpack> Unpack for Res<T> {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        match d.get_u32()? {
            0 => Ok(Res::Ok(T::unpack(d)?)),
            s => Ok(Res::Err(s)),
        }
    }
}

/// Map a v2 `stat` value to the crate status. v2 codes are a subset of nfsstat3,
/// so [`Status::from_v3`] does the work; codes it does not know (including
/// NFSERR_WFLUSH = 99) become `Status::Other(NfsVersion::V2, code)`.
pub fn status(code: u32) -> Status {
    match Status::from_v3(code) {
        Status::Other(_, c) => Status::Other(NfsVersion::V2, c),
        s => s,
    }
}

/// `writeargs`. `beginoffset` and `totalcount` are unused by the protocol and sent as zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteArgs {
    pub fh: WireFh,
    pub beginoffset: u32,
    pub offset: u32,
    pub totalcount: u32,
    pub data: Opaque,
}

impl Pack for WriteArgs {
    fn pack(&self, e: &mut Encoder) {
        e.put(&self.fh)
            .put_u32(self.beginoffset)
            .put_u32(self.offset)
            .put_u32(self.totalcount);
        e.put(&self.data);
    }
}

impl Unpack for WriteArgs {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(WriteArgs {
            fh: d.get()?,
            beginoffset: d.get_u32()?,
            offset: d.get_u32()?,
            totalcount: d.get_u32()?,
            data: d.get()?,
        })
    }
}

/// One `entry` of a READDIR reply (the list link is written by [`DirList`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub fileid: u32,
    pub name: Opaque,
    pub cookie: Cookie,
}

impl Pack for Entry {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.fileid);
        e.put(&self.name).put(&self.cookie);
    }
}

impl Unpack for Entry {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Entry {
            fileid: d.get_u32()?,
            name: d.get()?,
            cookie: d.get()?,
        })
    }
}

/// `dirlist` success arm of READDIR: an XDR linked list of entries, then `eof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirList {
    pub entries: Vec<Entry>,
    pub eof: bool,
}

impl Pack for DirList {
    fn pack(&self, e: &mut Encoder) {
        for entry in &self.entries {
            e.put_bool(true);
            e.put(entry);
        }
        e.put_bool(false);
        e.put_bool(self.eof);
    }
}

impl Unpack for DirList {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let entries = d.get_list::<Entry>()?;
        Ok(DirList {
            entries,
            eof: d.get_bool()?,
        })
    }
}

/// `statfsok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatfsOk {
    /// Optimum transfer size.
    pub tsize: u32,
    pub bsize: u32,
    pub blocks: u32,
    pub bfree: u32,
    pub bavail: u32,
}

impl Pack for StatfsOk {
    fn pack(&self, e: &mut Encoder) {
        e.put_u32(self.tsize)
            .put_u32(self.bsize)
            .put_u32(self.blocks)
            .put_u32(self.bfree)
            .put_u32(self.bavail);
    }
}

impl Unpack for StatfsOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(StatfsOk {
            tsize: d.get_u32()?,
            bsize: d.get_u32()?,
            blocks: d.get_u32()?,
            bfree: d.get_u32()?,
            bavail: d.get_u32()?,
        })
    }
}

#[cfg(test)]
mod tests {
    //! Expected bytes are built from the RFC layouts with the helpers below,
    //! not by calling the codec, so the tests check the codec against the spec.

    use super::*;
    use crate::xdr::{from_bytes, to_bytes};

    /// Big-endian u32 words.
    fn w(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|x| x.to_be_bytes()).collect()
    }

    /// Variable-length opaque: length, bytes, zero padding to 4.
    fn op(data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(data);
        v.resize(v.len() + (4 - data.len() % 4) % 4, 0);
        v
    }

    /// A 32-byte handle: seed, seed+1, ...
    fn fh(seed: u8) -> Vec<u8> {
        (0..32u8).map(|i| seed.wrapping_add(i)).collect()
    }

    fn wfh(seed: u8) -> WireFh {
        WireFh(fh(seed).try_into().unwrap())
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    fn sample_fattr() -> Fattr {
        Fattr {
            ftype: NFDIR,
            mode: 0o40755,
            nlink: 3,
            uid: 1000,
            gid: 100,
            size: 4096,
            blocksize: 1024,
            rdev: 0,
            blocks: 8,
            fsid: 42,
            fileid: 77,
            atime: TimeVal {
                seconds: 1,
                useconds: 2,
            },
            mtime: TimeVal {
                seconds: 3,
                useconds: 4,
            },
            ctime: TimeVal {
                seconds: 5,
                useconds: 6,
            },
        }
    }

    fn fattr_bytes() -> Vec<u8> {
        w(&[
            2, 0o40755, 3, 1000, 100, 4096, 1024, 0, 8, 42, 77, 1, 2, 3, 4, 5, 6,
        ])
    }

    #[test]
    fn fhandle_is_fixed_32_bytes_without_prefix() {
        assert_eq!(to_bytes(&wfh(0x10)), fh(0x10));
        assert_eq!(from_bytes::<WireFh>(&fh(0x10)).unwrap(), wfh(0x10));
        assert!(from_bytes::<WireFh>(&fh(0)[..31]).is_err());
    }

    #[test]
    fn fhandle_from_fs_requires_32_bytes() {
        assert!(WireFh::from_fs(&FileHandle(fh(1))).is_some());
        assert!(WireFh::from_fs(&FileHandle(vec![0; 16])).is_none());
        assert!(WireFh::from_fs(&FileHandle(vec![0; 64])).is_none());
        assert_eq!(
            WireFh::from_fs(&FileHandle(fh(9))).unwrap().to_fs(),
            FileHandle(fh(9))
        );
    }

    #[test]
    fn cookie_is_four_opaque_bytes() {
        assert_eq!(to_bytes(&Cookie([0, 0, 1, 2])), [0, 0, 1, 2]);
        assert_eq!(
            from_bytes::<Cookie>(&[9, 8, 7, 6]).unwrap(),
            Cookie([9, 8, 7, 6])
        );
    }

    #[test]
    fn fattr_layout_is_68_bytes_in_rfc_order() {
        let bytes = to_bytes(&sample_fattr());
        assert_eq!(bytes, fattr_bytes());
        assert_eq!(bytes.len(), 68);
        assert_eq!(from_bytes::<Fattr>(&bytes).unwrap(), sample_fattr());
    }

    #[test]
    fn sattr_unset_is_all_ones() {
        assert_eq!(to_bytes(&Sattr::unset()), w(&[UNSET; 8]));
    }

    #[test]
    fn sattr_partially_set() {
        let s = Sattr {
            mode: 0o644,
            uid: UNSET,
            gid: UNSET,
            size: 0,
            atime: TimeVal::UNSET,
            mtime: TimeVal {
                seconds: 100,
                useconds: 500_000,
            },
        };
        let want = w(&[0o644, UNSET, UNSET, 0, UNSET, UNSET, 100, 500_000]);
        assert_eq!(to_bytes(&s), want);
        assert_eq!(from_bytes::<Sattr>(&want).unwrap(), s);
    }

    #[test]
    fn diropargs_dir_and_name() {
        let args = (wfh(1), Opaque(b"abc".to_vec()));
        assert_eq!(to_bytes(&args), cat(&[&fh(1), &op(b"abc")]));
        // A 4-byte name has no padding.
        let args = (wfh(1), Opaque(b"abcd".to_vec()));
        assert_eq!(to_bytes(&args), cat(&[&fh(1), &w(&[4]), b"abcd"]));
    }

    #[test]
    fn getattr_and_statfs_args_are_just_the_handle() {
        assert_eq!(to_bytes(&wfh(5)), fh(5));
    }

    #[test]
    fn setattr_args() {
        let args = (wfh(2), Sattr::unset());
        assert_eq!(to_bytes(&args), cat(&[&fh(2), &w(&[UNSET; 8])]));
    }

    #[test]
    fn attrstat_replies() {
        assert_eq!(
            to_bytes(&Res::Ok(sample_fattr())),
            cat(&[&w(&[0]), &fattr_bytes()])
        );
        assert_eq!(to_bytes(&Res::<Fattr>::Err(70)), w(&[70]));
        assert_eq!(from_bytes::<Res<Fattr>>(&w(&[2])).unwrap(), Res::Err(2));
    }

    #[test]
    fn diropres_replies() {
        let ok = Res::Ok((wfh(3), sample_fattr()));
        assert_eq!(to_bytes(&ok), cat(&[&w(&[0]), &fh(3), &fattr_bytes()]));
        assert_eq!(to_bytes(&Res::<(WireFh, Fattr)>::Err(2)), w(&[2]));
        assert_eq!(
            from_bytes::<Res<(WireFh, Fattr)>>(&to_bytes(&ok)).unwrap(),
            ok
        );
    }

    #[test]
    fn void_results_are_status_only() {
        assert_eq!(to_bytes(&Res::Ok(())), w(&[0]));
        assert_eq!(to_bytes(&Res::<()>::Err(13)), w(&[13]));
        assert_eq!(from_bytes::<Res<()>>(&w(&[0])).unwrap(), Res::Ok(()));
    }

    #[test]
    fn readlink_reply() {
        let r = Res::Ok(Opaque(b"/tgt".to_vec()));
        assert_eq!(to_bytes(&r), cat(&[&w(&[0]), &op(b"/tgt")]));
    }

    #[test]
    fn read_args_and_reply() {
        let args = (wfh(4), 4096u32, 512u32, 0u32);
        assert_eq!(to_bytes(&args), cat(&[&fh(4), &w(&[4096, 512, 0])]));
        let reply = Res::Ok((sample_fattr(), Opaque(b"hello".to_vec())));
        assert_eq!(
            to_bytes(&reply),
            cat(&[&w(&[0]), &fattr_bytes(), &op(b"hello")])
        );
        assert_eq!(
            from_bytes::<Res<(Fattr, Opaque)>>(&to_bytes(&reply)).unwrap(),
            reply
        );
    }

    #[test]
    fn write_args() {
        let args = WriteArgs {
            fh: wfh(6),
            beginoffset: 0,
            offset: 100,
            totalcount: 0,
            data: Opaque(b"xy".to_vec()),
        };
        assert_eq!(
            to_bytes(&args),
            cat(&[&fh(6), &w(&[0, 100, 0]), &op(b"xy")])
        );
        assert_eq!(from_bytes::<WriteArgs>(&to_bytes(&args)).unwrap(), args);
    }

    #[test]
    fn create_and_mkdir_args() {
        let args = ((wfh(7), Opaque(b"f".to_vec())), Sattr::unset());
        assert_eq!(to_bytes(&args), cat(&[&fh(7), &op(b"f"), &w(&[UNSET; 8])]));
        let mk = (wfh(7), Opaque(b"dir".to_vec()), Sattr::unset());
        assert_eq!(to_bytes(&mk), cat(&[&fh(7), &op(b"dir"), &w(&[UNSET; 8])]));
    }

    #[test]
    fn rename_args() {
        let args = (
            (wfh(1), Opaque(b"a".to_vec())),
            (wfh(2), Opaque(b"bb".to_vec())),
        );
        assert_eq!(
            to_bytes(&args),
            cat(&[&fh(1), &op(b"a"), &fh(2), &op(b"bb")])
        );
    }

    #[test]
    fn link_args() {
        let args = (wfh(1), (wfh(2), Opaque(b"l".to_vec())));
        assert_eq!(to_bytes(&args), cat(&[&fh(1), &fh(2), &op(b"l")]));
    }

    #[test]
    fn symlink_args() {
        let args = (
            (wfh(1), Opaque(b"s".to_vec())),
            Opaque(b"/etc/x".to_vec()),
            Sattr::unset(),
        );
        assert_eq!(
            to_bytes(&args),
            cat(&[&fh(1), &op(b"s"), &op(b"/etc/x"), &w(&[UNSET; 8])])
        );
    }

    #[test]
    fn readdir_args() {
        let args = (wfh(8), Cookie([0, 0, 0, 7]), 8192u32);
        assert_eq!(to_bytes(&args), cat(&[&fh(8), &[0, 0, 0, 7], &w(&[8192])]));
    }

    #[test]
    fn readdir_reply_linked_list() {
        let list = DirList {
            entries: vec![
                Entry {
                    fileid: 2,
                    name: Opaque(b"a".to_vec()),
                    cookie: Cookie([0, 0, 0, 1]),
                },
                Entry {
                    fileid: 3,
                    name: Opaque(b"bcde".to_vec()),
                    cookie: Cookie([0, 0, 0, 2]),
                },
            ],
            eof: true,
        };
        let want = cat(&[
            &w(&[0]),      // NFS_OK
            &w(&[1, 2]),   // entry present, fileid 2
            &op(b"a"),     // name
            &[0, 0, 0, 1], // cookie
            &w(&[1, 3]),   // entry present, fileid 3
            &op(b"bcde"),
            &[0, 0, 0, 2],
            &w(&[0]), // no more entries
            &w(&[1]), // eof
        ]);
        assert_eq!(to_bytes(&Res::Ok(list.clone())), want);
        assert_eq!(from_bytes::<Res<DirList>>(&want).unwrap(), Res::Ok(list));
    }

    #[test]
    fn readdir_reply_empty_not_eof() {
        let list = DirList {
            entries: vec![],
            eof: false,
        };
        assert_eq!(to_bytes(&Res::Ok(list)), w(&[0, 0, 0]));
    }

    #[test]
    fn readdir_list_missing_terminator_is_error() {
        // Entry present, but the stream ends before the terminating FALSE.
        let bytes = cat(&[&w(&[0, 1, 2]), &op(b"a"), &[0, 0, 0, 1]]);
        assert!(from_bytes::<Res<DirList>>(&bytes).is_err());
    }

    #[test]
    fn statfs_reply() {
        let s = StatfsOk {
            tsize: 8192,
            bsize: 1024,
            blocks: 1000,
            bfree: 500,
            bavail: 400,
        };
        assert_eq!(to_bytes(&Res::Ok(s)), w(&[0, 8192, 1024, 1000, 500, 400]));
        assert_eq!(
            from_bytes::<Res<StatfsOk>>(&w(&[0, 8192, 1024, 1000, 500, 400])).unwrap(),
            Res::Ok(s)
        );
    }

    #[test]
    fn truncated_success_arm_is_error() {
        assert!(from_bytes::<Res<Fattr>>(&w(&[0, 1])).is_err());
        assert!(from_bytes::<Res<WireFh>>(&w(&[0])).is_err());
    }

    #[test]
    fn trailing_bytes_after_error_status_are_error() {
        assert!(from_bytes::<Res<()>>(&w(&[2, 0])).is_err());
    }

    #[test]
    fn status_mapping() {
        assert_eq!(status(2), Status::NoEnt);
        assert_eq!(status(17), Status::Exist);
        assert_eq!(status(66), Status::NotEmpty);
        assert_eq!(status(70), Status::Stale);
        assert_eq!(status(99), Status::Other(NfsVersion::V2, 99));
        assert_eq!(status(9999), Status::Other(NfsVersion::V2, 9999));
        match (Res::<()>::Err(13)).into_result() {
            Err(Error::Nfs(Status::Access)) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
}
