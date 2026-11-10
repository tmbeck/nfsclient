//! NFSv3 procedure argument and result codecs (RFC 1813 section 3).
//!
//! Result types decode the success arm only. A non-OK status is turned into
//! `Error::Nfs(Status)` by [`Reply`] before the arm is read, so the failure arm
//! (which carries wcc_data for some procedures) is never consumed.

use crate::error::Result;
use crate::fs::FileHandle;
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

use super::types::{
    CreateHow, Fattr3, NfsTime, Sattr3, Verf, WccData, check_status, get_fh, get_opt_attr,
    get_opt_fh, get_verf, put_fh, put_verf,
};

pub const NULL: u32 = 0;
pub const GETATTR: u32 = 1;
pub const SETATTR: u32 = 2;
pub const LOOKUP: u32 = 3;
pub const ACCESS: u32 = 4;
pub const READLINK: u32 = 5;
pub const READ: u32 = 6;
pub const WRITE: u32 = 7;
pub const CREATE: u32 = 8;
pub const MKDIR: u32 = 9;
pub const SYMLINK: u32 = 10;
pub const REMOVE: u32 = 12;
pub const RMDIR: u32 = 13;
pub const RENAME: u32 = 14;
pub const LINK: u32 = 15;
pub const READDIR: u32 = 16;
pub const READDIRPLUS: u32 = 17;
pub const FSSTAT: u32 = 18;
pub const FSINFO: u32 = 19;
pub const PATHCONF: u32 = 20;
pub const COMMIT: u32 = 21;

/// A procedure result: nfsstat3, then the success arm `T` when status is NFS3_OK.
#[derive(Debug)]
pub struct Reply<T>(pub T);

impl<T: Unpack> Unpack for Reply<T> {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        check_status(d)?;
        Ok(Reply(T::unpack(d)?))
    }
}

// ---------------------------------------------------------------- arguments

/// A bare nfs_fh3 argument (GETATTR, READLINK, FSSTAT, FSINFO, PATHCONF).
pub struct FhArg<'a>(pub &'a FileHandle);

impl Pack for FhArg<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.0);
    }
}

/// diropargs3: directory handle plus one name.
pub struct DiropArgs<'a> {
    pub dir: &'a FileHandle,
    pub name: &'a [u8],
}

impl Pack for DiropArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.dir);
        e.put_string(self.name);
    }
}

pub struct SetattrArgs<'a> {
    pub fh: &'a FileHandle,
    pub attrs: &'a Sattr3,
    /// sattrguard3: `Some(ctime)` only when the caller wants the change conditional.
    pub guard: Option<NfsTime>,
}

impl Pack for SetattrArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.fh);
        self.attrs.pack(e);
        e.put_option(self.guard.as_ref());
    }
}

pub struct AccessArgs<'a> {
    pub fh: &'a FileHandle,
    pub access: u32,
}

impl Pack for AccessArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.fh);
        e.put_u32(self.access);
    }
}

pub struct ReadArgs<'a> {
    pub fh: &'a FileHandle,
    pub offset: u64,
    pub count: u32,
}

impl Pack for ReadArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.fh);
        e.put_u64(self.offset).put_u32(self.count);
    }
}

pub struct WriteArgs<'a> {
    pub fh: &'a FileHandle,
    pub offset: u64,
    pub stable: u32,
    pub data: &'a [u8],
}

impl Pack for WriteArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.fh);
        e.put_u64(self.offset);
        e.put_u32(self.data.len() as u32);
        e.put_u32(self.stable);
        e.put_opaque(self.data);
    }
}

pub struct CreateArgs<'a> {
    pub dir: DiropArgs<'a>,
    pub how: &'a CreateHow,
}

impl Pack for CreateArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        self.dir.pack(e);
        self.how.pack(e);
    }
}

pub struct MkdirArgs<'a> {
    pub dir: DiropArgs<'a>,
    pub attrs: &'a Sattr3,
}

impl Pack for MkdirArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        self.dir.pack(e);
        self.attrs.pack(e);
    }
}

pub struct SymlinkArgs<'a> {
    pub dir: DiropArgs<'a>,
    pub attrs: &'a Sattr3,
    pub target: &'a [u8],
}

impl Pack for SymlinkArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        self.dir.pack(e);
        self.attrs.pack(e);
        e.put_string(self.target);
    }
}

pub struct LinkArgs<'a> {
    pub file: &'a FileHandle,
    pub dir: DiropArgs<'a>,
}

impl Pack for LinkArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.file);
        self.dir.pack(e);
    }
}

pub struct RenameArgs<'a> {
    pub from: DiropArgs<'a>,
    pub to: DiropArgs<'a>,
}

impl Pack for RenameArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        self.from.pack(e);
        self.to.pack(e);
    }
}

pub struct ReaddirArgs<'a> {
    pub dir: &'a FileHandle,
    pub cookie: u64,
    pub verf: Verf,
    /// Maximum bytes of reply (READDIR `count`).
    pub count: u32,
}

impl Pack for ReaddirArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.dir);
        e.put_u64(self.cookie);
        put_verf(e, &self.verf);
        e.put_u32(self.count);
    }
}

pub struct ReaddirPlusArgs<'a> {
    pub dir: &'a FileHandle,
    pub cookie: u64,
    pub verf: Verf,
    /// Soft limit on the directory information bytes (`dircount`).
    pub dircount: u32,
    /// Hard limit on the whole reply (`maxcount`).
    pub maxcount: u32,
}

impl Pack for ReaddirPlusArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.dir);
        e.put_u64(self.cookie);
        put_verf(e, &self.verf);
        e.put_u32(self.dircount).put_u32(self.maxcount);
    }
}

pub struct CommitArgs<'a> {
    pub fh: &'a FileHandle,
    pub offset: u64,
    pub count: u32,
}

impl Pack for CommitArgs<'_> {
    fn pack(&self, e: &mut Encoder) {
        put_fh(e, self.fh);
        e.put_u64(self.offset).put_u32(self.count);
    }
}

// ------------------------------------------------------------------ results

/// LOOKUP success arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupOk {
    pub fh: FileHandle,
    pub obj_attr: Option<Fattr3>,
    pub dir_attr: Option<Fattr3>,
}

impl Unpack for LookupOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let fh = get_fh(d)?;
        let obj_attr = get_opt_attr(d)?;
        let dir_attr = get_opt_attr(d)?;
        Ok(LookupOk {
            fh,
            obj_attr,
            dir_attr,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessOk {
    pub attr: Option<Fattr3>,
    pub access: u32,
}

impl Unpack for AccessOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let attr = get_opt_attr(d)?;
        let access = d.get_u32()?;
        Ok(AccessOk { attr, access })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadlinkOk {
    pub attr: Option<Fattr3>,
    pub target: Vec<u8>,
}

impl Unpack for ReadlinkOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let attr = get_opt_attr(d)?;
        let target = d.get_opaque_vec()?;
        Ok(ReadlinkOk { attr, target })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOk {
    pub attr: Option<Fattr3>,
    pub count: u32,
    pub eof: bool,
    pub data: Vec<u8>,
}

impl Unpack for ReadOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let attr = get_opt_attr(d)?;
        let count = d.get_u32()?;
        let eof = d.get_bool()?;
        let data = d.get_opaque_vec()?;
        if count as usize > data.len() {
            return Err(crate::error::Error::Protocol(format!(
                "READ reply count {count} exceeds the {} data bytes returned",
                data.len()
            )));
        }
        Ok(ReadOk {
            attr,
            count,
            eof,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOk {
    pub wcc: WccData,
    pub count: u32,
    /// stable_how the server actually committed at.
    pub committed: u32,
    pub verf: Verf,
}

impl Unpack for WriteOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let wcc = WccData::unpack(d)?;
        let count = d.get_u32()?;
        let committed = d.get_u32()?;
        let verf = get_verf(d)?;
        Ok(WriteOk {
            wcc,
            count,
            committed,
            verf,
        })
    }
}

/// CREATE, MKDIR and SYMLINK success arm (post_op_fh3, post_op_attr, dir wcc_data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOk {
    pub fh: Option<FileHandle>,
    pub attr: Option<Fattr3>,
    pub dir_wcc: WccData,
}

impl Unpack for CreateOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let fh = get_opt_fh(d)?;
        let attr = get_opt_attr(d)?;
        let dir_wcc = WccData::unpack(d)?;
        Ok(CreateOk { fh, attr, dir_wcc })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameOk {
    pub from_wcc: WccData,
    pub to_wcc: WccData,
}

impl Unpack for RenameOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(RenameOk {
            from_wcc: WccData::unpack(d)?,
            to_wcc: WccData::unpack(d)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkOk {
    pub attr: Option<Fattr3>,
    pub dir_wcc: WccData,
}

impl Unpack for LinkOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let attr = get_opt_attr(d)?;
        let dir_wcc = WccData::unpack(d)?;
        Ok(LinkOk { attr, dir_wcc })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOk {
    pub wcc: WccData,
    pub verf: Verf,
}

impl Unpack for CommitOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let wcc = WccData::unpack(d)?;
        let verf = get_verf(d)?;
        Ok(CommitOk { wcc, verf })
    }
}

/// One entry of a READDIR (`PLUS = false`) or READDIRPLUS (`PLUS = true`) reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry3 {
    pub fileid: u64,
    pub name: Vec<u8>,
    pub cookie: u64,
    /// READDIRPLUS only.
    pub attr: Option<Fattr3>,
    /// READDIRPLUS only.
    pub fh: Option<FileHandle>,
}

/// READDIR (`PLUS = false`) or READDIRPLUS (`PLUS = true`) success arm. Entries
/// form an XDR linked list, terminated by `FALSE`, followed by the `eof` flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaddirOk<const PLUS: bool> {
    pub dir_attr: Option<Fattr3>,
    pub verf: Verf,
    pub entries: Vec<DirEntry3>,
    pub eof: bool,
}

impl<const PLUS: bool> Unpack for ReaddirOk<PLUS> {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let dir_attr = get_opt_attr(d)?;
        let verf = get_verf(d)?;
        let mut entries = Vec::new();
        while d.get_bool()? {
            let fileid = d.get_u64()?;
            let name = d.get_opaque_vec()?;
            let cookie = d.get_u64()?;
            let (attr, fh) = if PLUS {
                (get_opt_attr(d)?, get_opt_fh(d)?)
            } else {
                (None, None)
            };
            entries.push(DirEntry3 {
                fileid,
                name,
                cookie,
                attr,
                fh,
            });
        }
        let eof = d.get_bool()?;
        Ok(ReaddirOk {
            dir_attr,
            verf,
            entries,
            eof,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsstatOk {
    pub attr: Option<Fattr3>,
    pub tbytes: u64,
    pub fbytes: u64,
    pub abytes: u64,
    pub tfiles: u64,
    pub ffiles: u64,
    pub afiles: u64,
    pub invarsec: u32,
}

impl Unpack for FsstatOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(FsstatOk {
            attr: get_opt_attr(d)?,
            tbytes: d.get_u64()?,
            fbytes: d.get_u64()?,
            abytes: d.get_u64()?,
            tfiles: d.get_u64()?,
            ffiles: d.get_u64()?,
            afiles: d.get_u64()?,
            invarsec: d.get_u32()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsinfoOk {
    pub attr: Option<Fattr3>,
    pub rtmax: u32,
    pub rtpref: u32,
    pub rtmult: u32,
    pub wtmax: u32,
    pub wtpref: u32,
    pub wtmult: u32,
    pub dtpref: u32,
    pub maxfilesize: u64,
    pub time_delta: NfsTime,
    pub properties: u32,
}

impl Unpack for FsinfoOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(FsinfoOk {
            attr: get_opt_attr(d)?,
            rtmax: d.get_u32()?,
            rtpref: d.get_u32()?,
            rtmult: d.get_u32()?,
            wtmax: d.get_u32()?,
            wtpref: d.get_u32()?,
            wtmult: d.get_u32()?,
            dtpref: d.get_u32()?,
            maxfilesize: d.get_u64()?,
            time_delta: NfsTime::unpack(d)?,
            properties: d.get_u32()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathconfOk {
    pub attr: Option<Fattr3>,
    pub linkmax: u32,
    pub name_max: u32,
    pub no_trunc: bool,
    pub chown_restricted: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
}

impl Unpack for PathconfOk {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(PathconfOk {
            attr: get_opt_attr(d)?,
            linkmax: d.get_u32()?,
            name_max: d.get_u32()?,
            no_trunc: d.get_bool()?,
            chown_restricted: d.get_bool()?,
            case_insensitive: d.get_bool()?,
            case_preserving: d.get_bool()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs3::types::FILE_SYNC;
    use crate::xdr::{from_bytes, to_bytes};

    fn fh(bytes: &[u8]) -> FileHandle {
        FileHandle(bytes.to_vec())
    }

    fn read_reply(count: u32, data: &[u8]) -> Vec<u8> {
        let mut b = vec![0, 0, 0, 0]; // no post-op attributes
        b.extend_from_slice(&count.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 1]); // eof
        b.extend_from_slice(&(data.len() as u32).to_be_bytes());
        b.extend_from_slice(data);
        b.resize(b.len() + (4 - data.len() % 4) % 4, 0);
        b
    }

    #[test]
    fn read_count_must_not_exceed_data() {
        let ok: ReadOk = from_bytes(&read_reply(3, b"abc")).unwrap();
        assert_eq!(ok.data, b"abc");
        let err = from_bytes::<ReadOk>(&read_reply(10, b"abc")).unwrap_err();
        assert!(matches!(err, crate::error::Error::Protocol(_)), "{err}");
    }

    #[test]
    fn fh_arg_byte_exact() {
        let f = fh(&[1, 2, 3, 4, 5]);
        assert_eq!(to_bytes(&FhArg(&f)), [0, 0, 0, 5, 1, 2, 3, 4, 5, 0, 0, 0]);
    }

    #[test]
    fn diropargs_byte_exact() {
        let f = fh(&[0xaa, 0xbb]);
        let a = DiropArgs {
            dir: &f,
            name: b"abc",
        };
        assert_eq!(
            to_bytes(&a),
            [
                0, 0, 0, 2, 0xaa, 0xbb, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c', 0
            ]
        );
    }

    #[test]
    fn setattr_guard_none_and_some() {
        let f = fh(&[9]);
        let s = Sattr3 {
            size: Some(0),
            ..Sattr3::default()
        };
        let none = to_bytes(&SetattrArgs {
            fh: &f,
            attrs: &s,
            guard: None,
        });
        // fh(4+4) + sattr(mode 4, uid 4, gid 4, size 4+8, atime 4, mtime 4) + guard FALSE 4
        assert_eq!(none.len(), 8 + 4 + 4 + 4 + 12 + 4 + 4 + 4);
        assert_eq!(&none[none.len() - 4..], [0, 0, 0, 0]);
        let some = to_bytes(&SetattrArgs {
            fh: &f,
            attrs: &s,
            guard: Some(NfsTime {
                seconds: 5,
                nseconds: 6,
            }),
        });
        assert_eq!(
            &some[some.len() - 12..],
            [0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 6]
        );
    }

    #[test]
    fn read_args_byte_exact() {
        let f = fh(&[7, 7, 7, 7]);
        let a = ReadArgs {
            fh: &f,
            offset: 0x0102,
            count: 4096,
        };
        assert_eq!(
            to_bytes(&a),
            [
                0, 0, 0, 4, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0x10, 0
            ]
        );
    }

    #[test]
    fn write_args_byte_exact_with_padding() {
        let f = fh(&[1]);
        let a = WriteArgs {
            fh: &f,
            offset: 8,
            stable: FILE_SYNC,
            data: b"hello",
        };
        assert_eq!(
            to_bytes(&a),
            [
                0, 0, 0, 1, 1, 0, 0, 0, // fh
                0, 0, 0, 0, 0, 0, 0, 8, // offset
                0, 0, 0, 5, // count (opaque length)
                0, 0, 0, 2, // FILE_SYNC
                0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', 0, 0, 0, // data + pad
            ]
        );
    }

    #[test]
    fn create_args_exclusive_byte_exact() {
        let f = fh(&[1]);
        let how = CreateHow::Exclusive([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1]);
        let a = CreateArgs {
            dir: DiropArgs {
                dir: &f,
                name: b"x",
            },
            how: &how,
        };
        assert_eq!(
            to_bytes(&a),
            [
                0, 0, 0, 1, 1, 0, 0, 0, // dir fh
                0, 0, 0, 1, b'x', 0, 0, 0, // name
                0, 0, 0, 2, // EXCLUSIVE
                0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1, // verifier
            ]
        );
    }

    #[test]
    fn symlink_args_order() {
        let f = fh(&[1]);
        let attrs = Sattr3::default();
        let a = SymlinkArgs {
            dir: DiropArgs {
                dir: &f,
                name: b"l",
            },
            attrs: &attrs,
            target: b"/t",
        };
        let b = to_bytes(&a);
        // dir(8) name(8) sattr(24) target(4+4)
        assert_eq!(b.len(), 8 + 8 + 24 + 8);
        assert_eq!(&b[b.len() - 8..], [0, 0, 0, 2, b'/', b't', 0, 0]);
    }

    #[test]
    fn rename_and_link_args() {
        let a = fh(&[1]);
        let b = fh(&[2]);
        let r = RenameArgs {
            from: DiropArgs {
                dir: &a,
                name: b"f",
            },
            to: DiropArgs {
                dir: &b,
                name: b"g",
            },
        };
        assert_eq!(
            to_bytes(&r),
            [
                0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, b'f', 0, 0, 0, //
                0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 1, b'g', 0, 0, 0,
            ]
        );
        let l = LinkArgs {
            file: &a,
            dir: DiropArgs {
                dir: &b,
                name: b"h",
            },
        };
        assert_eq!(to_bytes(&l).len(), 8 + 8 + 8);
    }

    #[test]
    fn readdirplus_args_byte_exact() {
        let f = fh(&[3]);
        let a = ReaddirPlusArgs {
            dir: &f,
            cookie: 0,
            verf: [0; 8],
            dircount: 8192,
            maxcount: 65536,
        };
        assert_eq!(
            to_bytes(&a),
            [
                0, 0, 0, 1, 3, 0, 0, 0, // fh
                0, 0, 0, 0, 0, 0, 0, 0, // cookie
                0, 0, 0, 0, 0, 0, 0, 0, // cookieverf
                0, 0, 0x20, 0, 0, 1, 0, 0, // dircount, maxcount
            ]
        );
    }

    #[test]
    fn commit_args_byte_exact() {
        let f = fh(&[1]);
        let a = CommitArgs {
            fh: &f,
            offset: 0,
            count: 0,
        };
        assert_eq!(
            to_bytes(&a),
            [0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn reply_status_error_is_surfaced() {
        let r: Result<Reply<Fattr3>> = from_bytes(&[0, 0, 0, 70]);
        assert!(matches!(
            r,
            Err(crate::error::Error::Nfs(crate::fs::Status::Stale))
        ));
        let r: Result<Reply<WccData>> = from_bytes(&10001u32.to_be_bytes());
        assert!(matches!(
            r,
            Err(crate::error::Error::Nfs(crate::fs::Status::BadHandle))
        ));
    }

    fn attr_bytes(fileid: u64) -> Vec<u8> {
        let mut e = Encoder::new();
        e.put_u32(2)
            .put_u32(0o40755)
            .put_u32(2)
            .put_u32(0)
            .put_u32(0);
        e.put_u64(4096)
            .put_u64(4096)
            .put_u32(0)
            .put_u32(0)
            .put_u64(1)
            .put_u64(fileid);
        for _ in 0..3 {
            e.put_u32(1).put_u32(0);
        }
        e.into_inner()
    }

    #[test]
    fn lookup_ok_with_attrs() {
        let mut e = Encoder::new();
        e.put_u32(0); // NFS3_OK
        e.put_opaque(&[0xaa; 4]);
        e.put_bool(true).put_opaque_fixed(&attr_bytes(77));
        e.put_bool(false);
        let r: Reply<LookupOk> = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(r.0.fh, fh(&[0xaa; 4]));
        assert_eq!(r.0.obj_attr.unwrap().fileid, 77);
        assert!(r.0.dir_attr.is_none());
    }

    #[test]
    fn lookup_noent_is_error_even_with_failure_arm() {
        // NOENT followed by dir_attributes post_op_attr FALSE.
        let r: Result<Reply<LookupOk>> = from_bytes(&[0, 0, 0, 2, 0, 0, 0, 0]);
        assert!(matches!(
            r,
            Err(crate::error::Error::Nfs(crate::fs::Status::NoEnt))
        ));
    }

    #[test]
    fn readdir_entries_linked_list_plain() {
        let mut e = Encoder::new();
        e.put_u32(0); // OK
        e.put_bool(false); // no dir attrs
        e.put_opaque_fixed(&[0; 8]); // cookieverf
        // entry "a" fileid 10 cookie 1
        e.put_bool(true).put_u64(10).put_opaque(b"a").put_u64(1);
        // entry "bc" fileid 11 cookie 2
        e.put_bool(true).put_u64(11).put_opaque(b"bc").put_u64(2);
        e.put_bool(false); // end of list
        e.put_bool(true); // eof
        let r: Reply<ReaddirOk<false>> = from_bytes(e.as_bytes()).unwrap();
        assert!(r.0.eof);
        assert_eq!(r.0.entries.len(), 2);
        assert_eq!(r.0.entries[1].name, b"bc");
        assert_eq!(r.0.entries[1].cookie, 2);
        assert!(r.0.entries[0].attr.is_none() && r.0.entries[0].fh.is_none());
    }

    #[test]
    fn readdirplus_entries_with_attrs_and_handles() {
        let mut e = Encoder::new();
        e.put_u32(0);
        e.put_bool(false);
        e.put_opaque_fixed(&[1, 2, 3, 4, 5, 6, 7, 8]);
        e.put_bool(true).put_u64(5).put_opaque(b"file").put_u64(9);
        e.put_bool(true).put_opaque_fixed(&attr_bytes(5)); // name_attributes
        e.put_bool(true).put_opaque(&[0x11, 0x22]); // name_handle
        e.put_bool(false);
        e.put_bool(false); // not eof
        let r: Reply<ReaddirOk<true>> = from_bytes(e.as_bytes()).unwrap();
        assert!(!r.0.eof);
        assert_eq!(r.0.verf, [1, 2, 3, 4, 5, 6, 7, 8]);
        let ent = &r.0.entries[0];
        assert_eq!(ent.name, b"file");
        assert_eq!(ent.attr.as_ref().unwrap().fileid, 5);
        assert_eq!(ent.fh, Some(fh(&[0x11, 0x22])));
    }

    #[test]
    fn readdir_empty_eof() {
        let mut e = Encoder::new();
        e.put_u32(0)
            .put_bool(false)
            .put_opaque_fixed(&[0; 8])
            .put_bool(false)
            .put_bool(true);
        let r: Reply<ReaddirOk<false>> = from_bytes(e.as_bytes()).unwrap();
        assert!(r.0.entries.is_empty() && r.0.eof);
    }

    #[test]
    fn readdir_truncated_is_error() {
        let mut e = Encoder::new();
        e.put_u32(0).put_bool(false).put_opaque_fixed(&[0; 8]);
        e.put_bool(true).put_u64(10).put_opaque(b"a"); // missing cookie and the rest
        assert!(from_bytes::<Reply<ReaddirOk<false>>>(e.as_bytes()).is_err());
    }

    #[test]
    fn read_ok_decodes_data_and_eof() {
        let mut e = Encoder::new();
        e.put_u32(0)
            .put_bool(false)
            .put_u32(3)
            .put_bool(true)
            .put_opaque(b"abc");
        let r: Reply<ReadOk> = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(r.0.data, b"abc");
        assert_eq!(r.0.count, 3);
        assert!(r.0.eof);
    }

    #[test]
    fn write_ok_decodes_committed_and_verf() {
        let mut e = Encoder::new();
        e.put_u32(0);
        e.put_bool(false).put_bool(false); // wcc empty
        e.put_u32(4096).put_u32(FILE_SYNC).put_opaque_fixed(&[9; 8]);
        let r: Reply<WriteOk> = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(r.0.count, 4096);
        assert_eq!(r.0.committed, FILE_SYNC);
        assert_eq!(r.0.verf, [9; 8]);
    }

    #[test]
    fn create_ok_without_handle_or_attrs() {
        let mut e = Encoder::new();
        e.put_u32(0)
            .put_bool(false)
            .put_bool(false)
            .put_bool(false)
            .put_bool(false);
        let r: Reply<CreateOk> = from_bytes(e.as_bytes()).unwrap();
        assert!(r.0.fh.is_none() && r.0.attr.is_none());
    }

    #[test]
    fn fsstat_and_fsinfo_decode() {
        let mut e = Encoder::new();
        e.put_u32(0).put_bool(false);
        for v in [1000u64, 400, 300, 50, 20, 10] {
            e.put_u64(v);
        }
        e.put_u32(5);
        let r: Reply<FsstatOk> = from_bytes(e.as_bytes()).unwrap();
        assert_eq!((r.0.tbytes, r.0.fbytes, r.0.abytes), (1000, 400, 300));
        assert_eq!((r.0.tfiles, r.0.ffiles, r.0.afiles), (50, 20, 10));
        assert_eq!(r.0.invarsec, 5);

        let mut e = Encoder::new();
        e.put_u32(0).put_bool(false);
        for v in [1 << 20, 1 << 19, 4, 1 << 20, 1 << 19, 4, 8] {
            e.put_u32(v);
        }
        e.put_u64(1 << 62).put_u32(1).put_u32(0).put_u32(0x1b);
        let r: Reply<FsinfoOk> = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(r.0.rtpref, 1 << 19);
        assert_eq!(r.0.wtmax, 1 << 20);
        assert_eq!(r.0.maxfilesize, 1 << 62);
        assert_eq!(r.0.properties, 0x1b);
    }

    #[test]
    fn commit_and_rename_decode() {
        let mut e = Encoder::new();
        e.put_u32(0)
            .put_bool(false)
            .put_bool(false)
            .put_opaque_fixed(&[3; 8]);
        let r: Reply<CommitOk> = from_bytes(e.as_bytes()).unwrap();
        assert_eq!(r.0.verf, [3; 8]);

        let mut e = Encoder::new();
        e.put_u32(0);
        e.put_bool(false)
            .put_bool(false)
            .put_bool(false)
            .put_bool(false);
        let r: Reply<RenameOk> = from_bytes(e.as_bytes()).unwrap();
        assert!(r.0.from_wcc.after.is_none());
    }
}
