//! NFSv3 [`Filesystem`] backend over one RPC connection.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{AcceptError, Error, Result};
use crate::fs::{self, Attr, CreateMode, FileHandle, Filesystem, FsStat, NfsVersion, SetAttr, Status};
use crate::mount;
use crate::rpc::{Proto, RpcClient, RpcOptions};
use crate::xdr::Pack;

use super::proto::{
    self, CommitArgs, CommitOk, CreateArgs, CreateOk, DiropArgs, DirEntry3, FhArg, FsinfoOk, FsstatOk, LinkArgs,
    LinkOk, LookupOk, MkdirArgs, ReadArgs, ReadOk, ReadlinkOk, ReaddirArgs, ReaddirOk, ReaddirPlusArgs,
    RenameArgs, RenameOk, Reply, SetattrArgs, SymlinkArgs, WriteArgs, WriteOk,
};
use super::types::{CreateHow, Fattr3, Sattr3, TimeSet, Verf, WccData, FILE_SYNC};

/// Largest READ/WRITE transfer we will use, whatever FSINFO advertises.
pub const MAX_TRANSFER: u32 = 1 << 20;
/// Largest transfer over UDP (keeps replies under the datagram limit).
pub const UDP_MAX_TRANSFER: u32 = 32 << 10;
/// READDIRPLUS `dircount` and `maxcount`.
pub const READDIRPLUS_DIRCOUNT: u32 = 8 << 10;
pub const READDIRPLUS_MAXCOUNT: u32 = 64 << 10;
/// READDIR `count`.
pub const READDIR_COUNT: u32 = 32 << 10;

/// An NFSv3 connection to one export.
pub struct Nfs3 {
    client: RpcClient,
    root: FileHandle,
    max_read: u32,
    max_write: u32,
    /// False once the server rejects READDIRPLUS with NOTSUPP.
    readdirplus: bool,
    host: IpAddr,
    mount_port: Option<u16>,
    mount_opts: RpcOptions,
    export: Vec<u8>,
}

/// Build the backend from a connected NFS client and a mounted root handle.
/// Asks FSINFO for the transfer sizes.
pub(crate) fn open(
    mut client: RpcClient,
    host: IpAddr,
    mount_port: Option<u16>,
    mount_opts: RpcOptions,
    export: Vec<u8>,
    root: FileHandle,
) -> Result<Nfs3> {
    let info: Reply<FsinfoOk> = client.call(proto::FSINFO, &FhArg(&root))?;
    let proto = mount_opts.proto;
    let max_read = transfer_size(info.0.rtpref, info.0.rtmax, proto);
    let max_write = transfer_size(info.0.wtpref, info.0.wtmax, proto);
    Ok(Nfs3 {
        client,
        root,
        max_read,
        max_write,
        readdirplus: true,
        host,
        mount_port,
        mount_opts,
        export,
    })
}

/// Pick a transfer size from FSINFO's preferred and maximum values.
pub fn transfer_size(pref: u32, max: u32, proto: Proto) -> u32 {
    let s = match (pref, max) {
        (0, 0) => 64 << 10,
        (0, m) => m,
        (p, _) => p,
    };
    let s = s.min(MAX_TRANSFER);
    match proto {
        Proto::Udp => s.min(UDP_MAX_TRANSFER),
        Proto::Tcp => s,
    }
}

/// Verifier for EXCLUSIVE create: unique enough per call (clock, pid, counter).
fn new_verifier() -> Verf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    (nanos ^ (u64::from(std::process::id()) << 32) ^ n.rotate_left(17)).to_be_bytes()
}

fn is_dot(name: &[u8]) -> bool {
    name == b"." || name == b".."
}

/// One READDIR/READDIRPLUS page: entries paired with their cookies.
pub(crate) struct Page {
    pub verf: Verf,
    pub entries: Vec<(u64, fs::DirEntry)>,
    pub eof: bool,
}

/// Collect a whole directory. `fetch(cookie, verf)` returns one page. Entries "."
/// and ".." are dropped. A BAD_COOKIE restarts the listing from the beginning once.
pub(crate) fn list_all<F>(mut fetch: F) -> Result<Vec<fs::DirEntry>>
where
    F: FnMut(u64, Verf) -> Result<Page>,
{
    let mut restarted = false;
    loop {
        match list_once(&mut fetch) {
            Err(Error::Nfs(Status::BadCookie)) if !restarted => restarted = true,
            r => return r,
        }
    }
}

fn list_once<F>(fetch: &mut F) -> Result<Vec<fs::DirEntry>>
where
    F: FnMut(u64, Verf) -> Result<Page>,
{
    let mut out = Vec::new();
    let mut cookie = 0u64;
    let mut verf = [0u8; 8];
    loop {
        let page = fetch(cookie, verf)?;
        let got_any = !page.entries.is_empty();
        for (c, ent) in page.entries {
            cookie = c;
            if !is_dot(&ent.name) {
                out.push(ent);
            }
        }
        if page.eof {
            return Ok(out);
        }
        if !got_any {
            return Err(Error::Protocol("READDIR returned no entries before eof".into()));
        }
        verf = page.verf;
    }
}

fn page_from(verf: Verf, eof: bool, entries: Vec<DirEntry3>) -> Page {
    Page {
        verf,
        eof,
        entries: entries
            .into_iter()
            .map(|e| {
                let cookie = e.cookie;
                (
                    cookie,
                    fs::DirEntry {
                        name: e.name,
                        fileid: e.fileid,
                        attr: e.attr.map(|a| a.to_attr()),
                        handle: e.fh,
                    },
                )
            })
            .collect(),
    }
}

impl Nfs3 {
    fn call<A: Pack + ?Sized, R: crate::xdr::Unpack>(&mut self, procedure: u32, args: &A) -> Result<R> {
        self.client.call(procedure, args)
    }

    /// The object created by CREATE/MKDIR/SYMLINK, with its attributes. The server
    /// may omit the handle or attributes; those are then fetched with LOOKUP/GETATTR.
    fn new_object(&mut self, dir: &FileHandle, name: &[u8], ok: CreateOk) -> Result<(FileHandle, Attr)> {
        match ok.fh {
            Some(fh) => {
                let attr = match ok.attr {
                    Some(a) => a.to_attr(),
                    None => self.getattr(&fh)?,
                };
                Ok((fh, attr))
            }
            None => self.lookup(dir, name),
        }
    }

    fn fsstat_from(f: FsstatOk) -> FsStat {
        FsStat {
            total_bytes: f.tbytes,
            free_bytes: f.fbytes,
            avail_bytes: f.abytes,
            total_files: f.tfiles,
            free_files: f.ffiles,
            avail_files: f.afiles,
        }
    }

    fn readdirplus_page(&mut self, dir: &FileHandle, cookie: u64, verf: Verf) -> Result<Page> {
        let r: Reply<ReaddirOk<true>> = self.call(
            proto::READDIRPLUS,
            &ReaddirPlusArgs {
                dir,
                cookie,
                verf,
                dircount: READDIRPLUS_DIRCOUNT,
                maxcount: READDIRPLUS_MAXCOUNT,
            },
        )?;
        let ok = r.0;
        Ok(page_from(ok.verf, ok.eof, ok.entries))
    }

    fn readdir_page(&mut self, dir: &FileHandle, cookie: u64, verf: Verf) -> Result<Page> {
        let r: Reply<ReaddirOk<false>> = self.call(
            proto::READDIR,
            &ReaddirArgs {
                dir,
                cookie,
                verf,
                count: READDIR_COUNT,
            },
        )?;
        let ok = r.0;
        Ok(page_from(ok.verf, ok.eof, ok.entries))
    }
}

impl Filesystem for Nfs3 {
    fn version(&self) -> NfsVersion {
        NfsVersion::V3
    }

    fn root(&self) -> FileHandle {
        self.root.clone()
    }

    fn max_read(&self) -> u32 {
        self.max_read
    }

    fn max_write(&self) -> u32 {
        self.max_write
    }

    fn getattr(&mut self, fh: &FileHandle) -> Result<Attr> {
        let r: Reply<Fattr3> = self.call(proto::GETATTR, &FhArg(fh))?;
        Ok(r.0.to_attr())
    }

    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr> {
        let s = Sattr3::from_fs(attrs);
        let r: Reply<WccData> = self.call(
            proto::SETATTR,
            &SetattrArgs {
                fh,
                attrs: &s,
                guard: None,
            },
        )?;
        match r.0.after {
            Some(a) => Ok(a.to_attr()),
            None => self.getattr(fh),
        }
    }

    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> Result<(FileHandle, Attr)> {
        let r: Reply<LookupOk> = self.call(proto::LOOKUP, &DiropArgs { dir, name })?;
        let LookupOk { fh, obj_attr, .. } = r.0;
        let attr = match obj_attr {
            Some(a) => a.to_attr(),
            None => self.getattr(&fh)?,
        };
        Ok((fh, attr))
    }

    fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<fs::DirEntry>> {
        if self.readdirplus {
            match list_all(|cookie, verf| self.readdirplus_page(dir, cookie, verf)) {
                Err(Error::Nfs(Status::NotSupp)) | Err(Error::Accept(AcceptError::ProcUnavail)) => {
                    self.readdirplus = false;
                }
                r => return r,
            }
        }
        list_all(|cookie, verf| self.readdir_page(dir, cookie, verf))
    }

    fn readlink(&mut self, fh: &FileHandle) -> Result<Vec<u8>> {
        let r: Reply<ReadlinkOk> = self.call(proto::READLINK, &FhArg(fh))?;
        Ok(r.0.target)
    }

    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        let count = count.min(self.max_read);
        let r: Reply<ReadOk> = self.call(proto::READ, &ReadArgs { fh, offset, count })?;
        Ok((r.0.data, r.0.eof))
    }

    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> Result<u32> {
        let n = data.len().min(self.max_write as usize);
        let chunk = &data[..n];
        let r: Reply<WriteOk> = self.call(
            proto::WRITE,
            &WriteArgs {
                fh,
                offset,
                stable: FILE_SYNC,
                data: chunk,
            },
        )?;
        let w = r.0;
        if w.committed != FILE_SYNC {
            // The server wrote unstably despite FILE_SYNC; force it to stable storage.
            let c: Reply<CommitOk> = self.call(
                proto::COMMIT,
                &CommitArgs {
                    fh,
                    offset,
                    count: n as u32,
                },
            )?;
            if c.0.verf != w.verf {
                return Err(Error::Protocol(
                    "server write verifier changed during commit; data may be lost".into(),
                ));
            }
        }
        Ok((w.count as usize).min(n) as u32)
    }

    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_FILE_MODE);
        let how = match mode {
            CreateMode::Unchecked => CreateHow::Unchecked(Sattr3::from_fs(attrs)),
            CreateMode::Guarded => CreateHow::Guarded(Sattr3::from_fs(attrs)),
            CreateMode::Exclusive => CreateHow::Exclusive(new_verifier()),
        };
        let r: Reply<CreateOk> = self.call(
            proto::CREATE,
            &CreateArgs {
                dir: DiropArgs { dir, name },
                how: &how,
            },
        )?;
        let (fh, attr) = self.new_object(dir, name, r.0)?;
        if mode != CreateMode::Exclusive {
            return Ok((fh, attr));
        }
        // RFC 1813: EXCLUSIVE create ignores the attributes, and the verifier is
        // stored in atime/mtime. Apply the requested attributes and set both times
        // (to the server clock unless given) so the verifier is overwritten.
        let mut s = Sattr3::from_fs(attrs);
        if s.atime == TimeSet::DontChange {
            s.atime = TimeSet::ServerTime;
        }
        if s.mtime == TimeSet::DontChange {
            s.mtime = TimeSet::ServerTime;
        }
        let r: Reply<WccData> = self.call(
            proto::SETATTR,
            &SetattrArgs {
                fh: &fh,
                attrs: &s,
                guard: None,
            },
        )?;
        let attr = match r.0.after {
            Some(a) => a.to_attr(),
            None => self.getattr(&fh)?,
        };
        Ok((fh, attr))
    }

    fn mkdir(&mut self, dir: &FileHandle, name: &[u8], attrs: &SetAttr) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_DIR_MODE);
        let s = Sattr3::from_fs(attrs);
        let r: Reply<CreateOk> = self.call(
            proto::MKDIR,
            &MkdirArgs {
                dir: DiropArgs { dir, name },
                attrs: &s,
            },
        )?;
        self.new_object(dir, name, r.0)
    }

    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        let attrs = &attrs.with_default_mode(SetAttr::DEFAULT_SYMLINK_MODE);
        let s = Sattr3::from_fs(attrs);
        let r: Reply<CreateOk> = self.call(
            proto::SYMLINK,
            &SymlinkArgs {
                dir: DiropArgs { dir, name },
                attrs: &s,
                target,
            },
        )?;
        self.new_object(dir, name, r.0)
    }

    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let _: Reply<LinkOk> = self.call(
            proto::LINK,
            &LinkArgs {
                file: target,
                dir: DiropArgs { dir, name },
            },
        )?;
        Ok(())
    }

    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let _: Reply<WccData> = self.call(proto::REMOVE, &DiropArgs { dir, name })?;
        Ok(())
    }

    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let _: Reply<WccData> = self.call(proto::RMDIR, &DiropArgs { dir, name })?;
        Ok(())
    }

    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> Result<()> {
        let _: Reply<RenameOk> = self.call(
            proto::RENAME,
            &RenameArgs {
                from: DiropArgs {
                    dir: from_dir,
                    name: from_name,
                },
                to: DiropArgs {
                    dir: to_dir,
                    name: to_name,
                },
            },
        )?;
        Ok(())
    }

    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat> {
        let r: Reply<FsstatOk> = self.call(proto::FSSTAT, &FhArg(fh))?;
        Ok(Self::fsstat_from(r.0))
    }

    fn disconnect(&mut self) -> Result<()> {
        // UMNT is advisory: the server may already have forgotten the mount.
        let _ = mount::umnt(self.host, self.mount_port, 3, &self.export, &self.mount_opts);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn entry(name: &str, cookie: u64) -> (u64, fs::DirEntry) {
        (
            cookie,
            fs::DirEntry {
                name: name.as_bytes().to_vec(),
                fileid: cookie,
                attr: None,
                handle: None,
            },
        )
    }

    fn page(verf: u8, entries: Vec<(u64, fs::DirEntry)>, eof: bool) -> Page {
        Page {
            verf: [verf; 8],
            entries,
            eof,
        }
    }

    fn names(v: &[fs::DirEntry]) -> Vec<String> {
        v.iter().map(|e| String::from_utf8_lossy(&e.name).into_owned()).collect()
    }

    #[test]
    fn listing_single_page_filters_dots() {
        let out = list_all(|cookie, verf| {
            assert_eq!((cookie, verf), (0, [0; 8]));
            Ok(page(0, vec![entry(".", 1), entry("..", 2), entry("a", 3), entry("b", 4)], true))
        })
        .unwrap();
        assert_eq!(names(&out), ["a", "b"]);
    }

    #[test]
    fn listing_paginates_with_cookies_and_verifier() {
        let calls = RefCell::new(Vec::new());
        let out = list_all(|cookie, verf| {
            calls.borrow_mut().push((cookie, verf));
            Ok(match cookie {
                0 => page(7, vec![entry(".", 1), entry("f1", 10), entry("f2", 11)], false),
                11 => page(7, vec![entry("f3", 12)], false),
                12 => page(8, vec![entry("f4", 13)], true),
                c => panic!("unexpected cookie {c}"),
            })
        })
        .unwrap();
        assert_eq!(names(&out), ["f1", "f2", "f3", "f4"]);
        assert_eq!(
            *calls.borrow(),
            vec![(0, [0; 8]), (11, [7; 8]), (12, [7; 8])],
            "each call uses the cookie of the last entry and the verifier of the previous reply"
        );
    }

    #[test]
    fn listing_restarts_once_on_bad_cookie() {
        let attempts = RefCell::new(0);
        let out = list_all(|cookie, _| {
            if cookie == 0 {
                *attempts.borrow_mut() += 1;
            }
            match (cookie, *attempts.borrow()) {
                (0, 1) => Ok(page(0, vec![entry("x", 5)], false)),
                (5, 1) => Err(Error::Nfs(Status::BadCookie)),
                (0, 2) => Ok(page(0, vec![entry("x", 5), entry("y", 6)], true)),
                other => panic!("unexpected {other:?}"),
            }
        })
        .unwrap();
        // The restarted listing starts over, so "x" is not duplicated.
        assert_eq!(names(&out), ["x", "y"]);
        assert_eq!(*attempts.borrow(), 2);
    }

    #[test]
    fn listing_second_bad_cookie_is_an_error() {
        let r = list_all(|_, _| Err(Error::Nfs(Status::BadCookie)));
        assert!(matches!(r, Err(Error::Nfs(Status::BadCookie))));
    }

    #[test]
    fn listing_other_errors_are_not_retried() {
        let n = RefCell::new(0);
        let r = list_all(|_, _| {
            *n.borrow_mut() += 1;
            Err(Error::Nfs(Status::Access))
        });
        assert!(matches!(r, Err(Error::Nfs(Status::Access))));
        assert_eq!(*n.borrow(), 1);
    }

    #[test]
    fn listing_detects_no_progress() {
        let r = list_all(|_, _| Ok(page(0, vec![], false)));
        assert!(matches!(r, Err(Error::Protocol(_))));
    }

    #[test]
    fn empty_directory_with_eof() {
        let out = list_all(|_, _| Ok(page(0, vec![], true))).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn transfer_sizes() {
        assert_eq!(transfer_size(0, 0, Proto::Tcp), 64 << 10);
        assert_eq!(transfer_size(0, 32768, Proto::Tcp), 32768);
        assert_eq!(transfer_size(1 << 19, 1 << 20, Proto::Tcp), 1 << 19);
        // Advertised 4 MiB is capped at 1 MiB.
        assert_eq!(transfer_size(4 << 20, 4 << 20, Proto::Tcp), MAX_TRANSFER);
        // UDP is capped lower.
        assert_eq!(transfer_size(1 << 20, 1 << 20, Proto::Udp), UDP_MAX_TRANSFER);
    }

    #[test]
    fn verifiers_differ_between_calls() {
        assert_ne!(new_verifier(), new_verifier());
    }

    #[test]
    fn page_conversion_keeps_handles_and_attrs() {
        let p = page_from(
            [9; 8],
            true,
            vec![DirEntry3 {
                fileid: 42,
                name: b"n".to_vec(),
                cookie: 3,
                attr: None,
                fh: Some(FileHandle(vec![1, 2])),
            }],
        );
        assert!(p.eof);
        assert_eq!(p.verf, [9; 8]);
        let (c, e) = &p.entries[0];
        assert_eq!(*c, 3);
        assert_eq!(e.fileid, 42);
        assert_eq!(e.handle, Some(FileHandle(vec![1, 2])));
    }

    #[test]
    fn fsstat_conversion() {
        let f = FsstatOk {
            attr: None,
            tbytes: 1,
            fbytes: 2,
            abytes: 3,
            tfiles: 4,
            ffiles: 5,
            afiles: 6,
            invarsec: 0,
        };
        let s = Nfs3::fsstat_from(f);
        assert_eq!(
            (s.total_bytes, s.free_bytes, s.avail_bytes, s.total_files, s.free_files, s.avail_files),
            (1, 2, 3, 4, 5, 6)
        );
    }
}
