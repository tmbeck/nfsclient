//! [`Filesystem`] implementation over NFSv2 (RFC 1094).

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use super::proto::{
    self, Cookie, DirList, Fattr, Res, Sattr, StatfsOk, TimeVal, WireFh, WriteArgs, MAXDATA,
    MAXNAMLEN, MAXPATHLEN, NFBLK, NFCHR, NFDIR, NFLNK, NFNON, NFREG, PROC_CREATE, PROC_GETATTR,
    PROC_LINK, PROC_LOOKUP, PROC_MKDIR, PROC_READ, PROC_READDIR, PROC_READLINK, PROC_REMOVE,
    PROC_RENAME, PROC_RMDIR, PROC_SETATTR, PROC_STATFS, PROC_SYMLINK, PROC_WRITE, UNSET,
};
use super::{PROGRAM, VERSION};
use crate::error::{Error, Result};
use crate::fs::{
    Attr, CreateMode, DirEntry, FileHandle, FileType, Filesystem, FsStat, NfsVersion, SetAttr,
    SetTime, Status, Time,
};
use crate::mount;
use crate::rpc::{RpcClient, RpcOptions};
use crate::xdr::Opaque;

/// Bytes requested per READDIR call (the reply size limit).
const READDIR_COUNT: u32 = MAXDATA;
/// S_IFMT type bits used to recover socket/fifo types when ftype is NFNON.
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;
const S_IFIFO: u32 = 0o010000;

/// MOUNT state to undo on disconnect.
pub(super) struct Umount {
    pub host: IpAddr,
    pub mount_port: Option<u16>,
    pub export: Vec<u8>,
}

pub(super) struct Nfs2 {
    rpc: RpcClient,
    root: FileHandle,
    umount: Option<Umount>,
    opts: RpcOptions,
}

impl Nfs2 {
    pub(super) fn new(
        addr: SocketAddr,
        opts: &RpcOptions,
        root: FileHandle,
        umount: Option<Umount>,
    ) -> Result<Self> {
        let rpc = RpcClient::connect(addr, PROGRAM, VERSION, opts)?;
        Ok(Nfs2 {
            rpc,
            root,
            umount,
            opts: opts.clone(),
        })
    }

    fn call<A, R>(&mut self, procedure: u32, args: &A) -> Result<R>
    where
        A: crate::xdr::Pack + ?Sized,
        R: crate::xdr::Unpack,
    {
        self.rpc.call(procedure, args)
    }
}

/// Check a name against MAXNAMLEN before it goes on the wire.
fn check_name(name: &[u8]) -> Result<()> {
    if name.len() > MAXNAMLEN {
        return Err(Error::Nfs(Status::NameTooLong));
    }
    Ok(())
}

fn wire(fh: &FileHandle) -> Result<WireFh> {
    WireFh::from_fs(fh).ok_or(Error::Nfs(Status::BadHandle))
}

fn diropargs(dir: &FileHandle, name: &[u8]) -> Result<(WireFh, Opaque)> {
    check_name(name)?;
    Ok((wire(dir)?, Opaque(name.to_vec())))
}

/// v2 offsets are u32; anything larger cannot be expressed.
fn wire_offset(offset: u64) -> Result<u32> {
    u32::try_from(offset).map_err(|_| Error::Nfs(Status::FBig))
}

fn now_timeval() -> TimeVal {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    TimeVal {
        seconds: d.as_secs() as u32,
        useconds: d.subsec_micros(),
    }
}

fn time_to_timeval(t: Time) -> Result<TimeVal> {
    let seconds = u32::try_from(t.seconds)
        .map_err(|_| Error::Invalid(format!("time {} is outside the NFSv2 range", t.seconds)))?;
    Ok(TimeVal {
        seconds,
        useconds: t.nseconds / 1000,
    })
}

/// Build a `sattr` from the normalized request. Unset fields are sent as -1.
/// v4-only `owner`/`group` strings are ignored.
fn to_sattr(a: &SetAttr) -> Result<Sattr> {
    let size = match a.size {
        None => UNSET,
        Some(s) => wire_offset(s)?,
    };
    let time = |t: Option<SetTime>| -> Result<TimeVal> {
        Ok(match t {
            None => TimeVal::UNSET,
            // v2 has no "server time" setting; the client clock is the best available.
            Some(SetTime::ServerNow) => now_timeval(),
            Some(SetTime::Client(t)) => time_to_timeval(t)?,
        })
    };
    Ok(Sattr {
        mode: a.mode.unwrap_or(UNSET),
        uid: a.uid.unwrap_or(UNSET),
        gid: a.gid.unwrap_or(UNSET),
        size,
        atime: time(a.atime)?,
        mtime: time(a.mtime)?,
    })
}

fn file_type(ftype: u32, mode: u32) -> FileType {
    match ftype {
        NFREG => FileType::Regular,
        NFDIR => FileType::Directory,
        NFBLK => FileType::BlockDevice,
        NFCHR => FileType::CharDevice,
        NFLNK => FileType::Symlink,
        // NFNON has no socket/fifo values in v2; servers commonly leave the type
        // bits in `mode`, so use them when present.
        NFNON => match mode & S_IFMT {
            S_IFSOCK => FileType::Socket,
            S_IFIFO => FileType::Fifo,
            _ => FileType::Other(NFNON),
        },
        other => FileType::Other(other),
    }
}

fn to_time(t: proto::TimeVal) -> Time {
    Time {
        seconds: i64::from(t.seconds),
        // Clamp so a bogus usec value cannot push nseconds past 999_999_999.
        nseconds: t.useconds.min(999_999) * 1000,
    }
}

/// Normalize v2 `fattr` into [`Attr`].
pub(super) fn to_attr(f: Fattr) -> Attr {
    Attr {
        ftype: file_type(f.ftype, f.mode),
        mode: f.mode & 0o7777,
        nlink: f.nlink,
        uid: f.uid,
        gid: f.gid,
        owner: None,
        group: None,
        size: u64::from(f.size),
        used: u64::from(f.blocks) * u64::from(f.blocksize),
        // Linux old encoding: 8-bit major, 8-bit minor.
        rdev: ((f.rdev >> 8) & 0xff, f.rdev & 0xff),
        fsid: u64::from(f.fsid),
        fileid: u64::from(f.fileid),
        atime: to_time(f.atime),
        mtime: to_time(f.mtime),
        ctime: to_time(f.ctime),
    }
}

impl Filesystem for Nfs2 {
    fn version(&self) -> NfsVersion {
        NfsVersion::V2
    }

    fn root(&self) -> FileHandle {
        self.root.clone()
    }

    fn max_read(&self) -> u32 {
        MAXDATA
    }

    fn max_write(&self) -> u32 {
        MAXDATA
    }

    fn getattr(&mut self, fh: &FileHandle) -> Result<Attr> {
        let r: Res<Fattr> = self.call(PROC_GETATTR, &wire(fh)?)?;
        Ok(to_attr(r.into_result()?))
    }

    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr> {
        let args = (wire(fh)?, to_sattr(attrs)?);
        let r: Res<Fattr> = self.call(PROC_SETATTR, &args)?;
        Ok(to_attr(r.into_result()?))
    }

    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> Result<(FileHandle, Attr)> {
        let r: Res<(WireFh, Fattr)> = self.call(PROC_LOOKUP, &diropargs(dir, name)?)?;
        let (fh, attr) = r.into_result()?;
        Ok((fh.to_fs(), to_attr(attr)))
    }

    fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<DirEntry>> {
        let fh = wire(dir)?;
        let mut cookie = Cookie::default();
        let mut out = Vec::new();
        loop {
            let r: Res<DirList> = self.call(PROC_READDIR, &(fh.clone(), cookie, READDIR_COUNT))?;
            let page = r.into_result()?;
            let last = page.entries.last().map(|e| e.cookie);
            for e in page.entries {
                if e.name.0 == b"." || e.name.0 == b".." {
                    continue;
                }
                out.push(DirEntry {
                    name: e.name.0,
                    fileid: u64::from(e.fileid),
                    attr: None,
                    handle: None,
                });
            }
            if out.len() > crate::fs::MAX_DIR_ENTRIES {
                return Err(Error::Protocol(format!(
                    "directory listing exceeds {} entries",
                    crate::fs::MAX_DIR_ENTRIES
                )));
            }
            if page.eof {
                break;
            }
            match last {
                // A page with no entries and no eof gives us no cookie to continue from.
                None => {
                    return Err(Error::Protocol(
                        "READDIR returned no entries and no eof".into(),
                    ));
                }
                Some(c) if c == cookie => {
                    return Err(Error::Protocol("READDIR cookie did not advance".into()));
                }
                Some(c) => cookie = c,
            }
        }
        Ok(out)
    }

    fn readlink(&mut self, fh: &FileHandle) -> Result<Vec<u8>> {
        let r: Res<Opaque> = self.call(PROC_READLINK, &wire(fh)?)?;
        let target = r.into_result()?.0;
        if target.len() > MAXPATHLEN {
            return Err(Error::Protocol("READLINK target exceeds MAXPATHLEN".into()));
        }
        Ok(target)
    }

    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        let off = wire_offset(offset)?;
        if count == 0 {
            return Ok((Vec::new(), false));
        }
        // Clamp to the protocol limit and to what the u32 offset can address.
        let room = u64::from(u32::MAX) + 1 - u64::from(off);
        let count = u64::from(count).min(u64::from(MAXDATA)).min(room) as u32;
        if count == 0 {
            // Offset is at the 4 GiB limit: nothing addressable remains.
            return Ok((Vec::new(), true));
        }
        let args = (wire(fh)?, off, count, 0u32);
        let r: Res<(Fattr, Opaque)> = self.call(PROC_READ, &args)?;
        let (attr, data) = r.into_result()?;
        let data = data.0;
        let end = offset + data.len() as u64;
        let eof = data.is_empty() || end >= u64::from(attr.size);
        Ok((data, eof))
    }

    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> Result<u32> {
        let off = wire_offset(offset)?;
        if data.is_empty() {
            return Ok(0);
        }
        // Largest chunk that fits both MAXDATA and the u32 offset space. Returning
        // fewer bytes than given is allowed by the Filesystem contract.
        let room = u64::from(u32::MAX) + 1 - u64::from(off);
        let n = (data.len() as u64).min(u64::from(MAXDATA)).min(room) as usize;
        if n == 0 {
            return Err(Error::Nfs(Status::FBig));
        }
        let args = WriteArgs {
            fh: wire(fh)?,
            beginoffset: 0,
            offset: off,
            totalcount: 0,
            data: Opaque(data[..n].to_vec()),
        };
        // v2 WRITE is always synchronous: success means the data is stable.
        let r: Res<Fattr> = self.call(PROC_WRITE, &args)?;
        r.into_result()?;
        Ok(n as u32)
    }

    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_FILE_MODE);
        if matches!(mode, CreateMode::Guarded | CreateMode::Exclusive) {
            // v2 has no GUARDED or EXCLUSIVE create, so this check races with
            // other clients. Exclusive is only as strong as Guarded here.
            match self.lookup(dir, name) {
                Ok(_) => return Err(Error::Nfs(Status::Exist)),
                Err(Error::Nfs(Status::NoEnt)) => {}
                Err(e) => return Err(e),
            }
        }
        let args = (diropargs(dir, name)?, to_sattr(attrs)?);
        let r: Res<(WireFh, Fattr)> = self.call(PROC_CREATE, &args)?;
        let (fh, attr) = r.into_result()?;
        Ok((fh.to_fs(), to_attr(attr)))
    }

    fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_DIR_MODE);
        let args = (diropargs(dir, name)?, to_sattr(attrs)?);
        let r: Res<(WireFh, Fattr)> = self.call(PROC_MKDIR, &args)?;
        let (fh, attr) = r.into_result()?;
        Ok((fh.to_fs(), to_attr(attr)))
    }

    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_SYMLINK_MODE);
        if target.len() > MAXPATHLEN {
            return Err(Error::Nfs(Status::NameTooLong));
        }
        let args = (
            diropargs(dir, name)?,
            Opaque(target.to_vec()),
            to_sattr(attrs)?,
        );
        // SYMLINK replies with status only, so look the new entry up.
        let r: Res<()> = self.call(PROC_SYMLINK, &args)?;
        r.into_result()?;
        self.lookup(dir, name)
    }

    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let args = (wire(target)?, diropargs(dir, name)?);
        let r: Res<()> = self.call(PROC_LINK, &args)?;
        r.into_result()
    }

    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let r: Res<()> = self.call(PROC_REMOVE, &diropargs(dir, name)?)?;
        r.into_result()
    }

    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let r: Res<()> = self.call(PROC_RMDIR, &diropargs(dir, name)?)?;
        r.into_result()
    }

    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> Result<()> {
        let args = (diropargs(from_dir, from_name)?, diropargs(to_dir, to_name)?);
        let r: Res<()> = self.call(PROC_RENAME, &args)?;
        r.into_result()
    }

    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat> {
        let r: Res<StatfsOk> = self.call(PROC_STATFS, &wire(fh)?)?;
        let s = r.into_result()?;
        let bsize = u64::from(s.bsize);
        Ok(FsStat {
            total_bytes: u64::from(s.blocks) * bsize,
            free_bytes: u64::from(s.bfree) * bsize,
            avail_bytes: u64::from(s.bavail) * bsize,
            // v2 STATFS has no inode counts.
            total_files: 0,
            free_files: 0,
            avail_files: 0,
        })
    }

    fn disconnect(&mut self) -> Result<()> {
        // Best effort: a failed UMNT must not fail the disconnect.
        if let Some(u) = self.umount.take() {
            let _ = mount::umnt(u.host, u.mount_port, 1, &u.export, &self.opts);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdev_uses_linux_old_encoding() {
        let f = Fattr {
            rdev: 0x0801,
            ..Fattr::default()
        };
        assert_eq!(to_attr(f).rdev, (8, 1));
        let f = Fattr {
            rdev: 0x1234,
            ..Fattr::default()
        };
        assert_eq!(to_attr(f).rdev, (0x12, 0x34));
    }

    #[test]
    fn mode_strips_type_bits_and_used_is_blocks_times_bsize() {
        let f = Fattr {
            ftype: NFREG,
            mode: 0o100644 | 0o4000,
            blocks: 3,
            blocksize: 1024,
            fsid: 9,
            fileid: 1234,
            ..Fattr::default()
        };
        let a = to_attr(f);
        assert_eq!(a.mode, 0o4644);
        assert_eq!(a.used, 3072);
        assert_eq!(a.fsid, 9);
        assert_eq!(a.fileid, 1234);
        assert_eq!(a.ftype, FileType::Regular);
        assert_eq!(a.owner, None);
    }

    #[test]
    fn times_convert_usec_to_nsec() {
        let f = Fattr {
            atime: TimeVal { seconds: 10, useconds: 250_000 },
            mtime: TimeVal { seconds: 11, useconds: 999_999 },
            ..Fattr::default()
        };
        let a = to_attr(f);
        assert_eq!(a.atime, Time { seconds: 10, nseconds: 250_000_000 });
        assert_eq!(a.mtime, Time { seconds: 11, nseconds: 999_999_000 });
    }

    #[test]
    fn ftype_mapping() {
        assert_eq!(file_type(NFDIR, 0), FileType::Directory);
        assert_eq!(file_type(NFLNK, 0), FileType::Symlink);
        assert_eq!(file_type(NFBLK, 0), FileType::BlockDevice);
        assert_eq!(file_type(NFCHR, 0), FileType::CharDevice);
        assert_eq!(file_type(NFNON, S_IFSOCK | 0o600), FileType::Socket);
        assert_eq!(file_type(NFNON, S_IFIFO | 0o600), FileType::Fifo);
        assert_eq!(file_type(NFNON, 0), FileType::Other(NFNON));
        assert_eq!(file_type(7, 0), FileType::Other(7));
    }

    #[test]
    fn sattr_from_setattr() {
        let s = to_sattr(&SetAttr {
            mode: Some(0o600),
            size: Some(5),
            mtime: Some(SetTime::Client(Time { seconds: 42, nseconds: 7_000_000 })),
            ..SetAttr::default()
        })
        .unwrap();
        assert_eq!(s.mode, 0o600);
        assert_eq!(s.uid, UNSET);
        assert_eq!(s.gid, UNSET);
        assert_eq!(s.size, 5);
        assert_eq!(s.atime, TimeVal::UNSET);
        assert_eq!(s.mtime, TimeVal { seconds: 42, useconds: 7000 });
    }

    #[test]
    fn sattr_size_beyond_u32_is_fbig() {
        let err = to_sattr(&SetAttr {
            size: Some(u64::from(u32::MAX) + 1),
            ..SetAttr::default()
        })
        .unwrap_err();
        assert!(matches!(err, Error::Nfs(Status::FBig)));
    }

    #[test]
    fn server_now_uses_client_clock() {
        let s = to_sattr(&SetAttr {
            mtime: Some(SetTime::ServerNow),
            ..SetAttr::default()
        })
        .unwrap();
        assert_ne!(s.mtime, TimeVal::UNSET);
        assert!(s.mtime.seconds > 1_600_000_000);
    }

    #[test]
    fn negative_time_is_invalid() {
        let err = to_sattr(&SetAttr {
            atime: Some(SetTime::Client(Time { seconds: -1, nseconds: 0 })),
            ..SetAttr::default()
        })
        .unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn offsets_beyond_u32_are_fbig() {
        assert_eq!(wire_offset(u64::from(u32::MAX)).unwrap(), u32::MAX);
        assert!(matches!(
            wire_offset(u64::from(u32::MAX) + 1),
            Err(Error::Nfs(Status::FBig))
        ));
    }

    #[test]
    fn long_names_are_rejected_locally() {
        assert!(check_name(&[b'a'; 255]).is_ok());
        assert!(matches!(
            check_name(&[b'a'; 256]),
            Err(Error::Nfs(Status::NameTooLong))
        ));
    }

    #[test]
    fn v2_wflush_maps_to_other() {
        assert_eq!(proto::status(99), Status::Other(NfsVersion::V2, 99));
    }
}
