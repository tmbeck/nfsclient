//! In-memory [`Filesystem`] backend for tests, and for downstream code that
//! wants to exercise facade consumers without a server.
//!
//! File handles are the 8-byte big-endian node id; the export root is id 1.
//! Timestamps come from [`MemFs::clock`] (unix seconds), so tests can pin them.
//! The backend is not a faithful server: directories always report `nlink` 2,
//! owner/group strings are never set, and only mode/uid/gid/size/times can be
//! changed by `setattr`.
//!
//! [`MemFs::add_sparse_file`] creates a file of any size (up to `u64::MAX`)
//! that stores only the bytes written to it and reads back a fill byte
//! elsewhere, so tests can exercise offsets beyond 4 GiB cheaply.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::fs::{
    Attr, CreateMode, DirEntry, FileHandle, FileType, Filesystem, FsStat, NfsVersion, SetAttr,
    SetTime, Status, Time,
};

const ROOT: u64 = 1;

#[derive(Debug, Clone)]
enum Body {
    Dir {
        parent: u64,
        entries: BTreeMap<Vec<u8>, u64>,
    },
    File(Vec<u8>),
    /// Sparse regular file: `size` bytes, `fill` where nothing was written,
    /// and `extents` (offset -> bytes) holding the written data.
    Sparse {
        size: u64,
        fill: u8,
        extents: BTreeMap<u64, Vec<u8>>,
    },
    Symlink(Vec<u8>),
}

#[derive(Debug, Clone)]
struct Node {
    attr: Attr,
    body: Body,
}

/// An in-memory export. Clone it to fork a snapshot.
#[derive(Debug, Clone)]
pub struct MemFs {
    nodes: BTreeMap<u64, Node>,
    next_id: u64,
    /// Unix seconds stamped on new and modified objects.
    pub clock: i64,
    /// Version reported by [`Filesystem::version`].
    pub version: NfsVersion,
    /// Limits reported by [`Filesystem::max_read`] / [`Filesystem::max_write`].
    pub max_read: u32,
    pub max_write: u32,
    /// When set, `write` accepts at most this many bytes per call, like a
    /// server that returns short counts. Used to test client write loops.
    pub write_call_limit: Option<usize>,
}

fn handle(id: u64) -> FileHandle {
    FileHandle(id.to_be_bytes().to_vec())
}

fn id_of(fh: &FileHandle) -> Result<u64> {
    let bytes: [u8; 8] =
        fh.0.as_slice()
            .try_into()
            .map_err(|_| Error::Nfs(Status::BadHandle))?;
    Ok(u64::from_be_bytes(bytes))
}

fn time(seconds: i64) -> Time {
    Time {
        seconds,
        nseconds: 0,
    }
}

fn new_attr(ftype: FileType, mode: u32, fileid: u64, size: u64, now: i64, nlink: u32) -> Attr {
    let t = time(now);
    Attr {
        ftype,
        mode,
        nlink,
        uid: 0,
        gid: 0,
        owner: None,
        group: None,
        size,
        used: size,
        rdev: (0, 0),
        fsid: 1,
        fileid,
        atime: t,
        mtime: t,
        ctime: t,
    }
}

fn check_name(name: &[u8]) -> Result<()> {
    if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
        return Err(Error::Nfs(Status::Inval));
    }
    Ok(())
}

fn split_path(path: &str) -> (&str, &str) {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some((dir, name)) => (dir, name),
        None => ("", path.trim_end_matches('/')),
    }
}

/// Reads `count` bytes at `offset` from a byte slice; returns (data, eof).
fn slice_read(data: &[u8], offset: u64, count: u32) -> (Vec<u8>, bool) {
    let len = data.len() as u64;
    let start = offset.min(len);
    let end = offset.saturating_add(u64::from(count)).min(len);
    let (start, end) = (start as usize, end as usize);
    (data[start..end].to_vec(), end == len as usize)
}

/// Reads from a sparse file, filling holes with `fill`.
fn sparse_read(
    size: u64,
    fill: u8,
    extents: &BTreeMap<u64, Vec<u8>>,
    offset: u64,
    count: u32,
) -> (Vec<u8>, bool) {
    if offset >= size {
        return (Vec::new(), true);
    }
    let end = offset.saturating_add(u64::from(count)).min(size);
    let mut out = vec![fill; (end - offset) as usize];
    for (&k, v) in extents.range(..end) {
        let vend = k + v.len() as u64;
        if vend <= offset {
            continue;
        }
        let (from, to) = (k.max(offset), vend.min(end));
        out[(from - offset) as usize..(to - offset) as usize]
            .copy_from_slice(&v[(from - k) as usize..(to - k) as usize]);
    }
    (out, end == size)
}

/// Stores `data` at `offset`, replacing whatever extents it overlaps.
fn sparse_write(extents: &mut BTreeMap<u64, Vec<u8>>, size: &mut u64, offset: u64, data: &[u8]) {
    let start = offset;
    let end = offset + data.len() as u64;
    let hit: Vec<u64> = extents
        .range(..end)
        .filter(|(k, v)| **k + v.len() as u64 > start)
        .map(|(k, _)| *k)
        .collect();
    for k in hit {
        let Some(v) = extents.remove(&k) else {
            continue;
        };
        let vend = k + v.len() as u64;
        if k < start {
            extents.insert(k, v[..(start - k) as usize].to_vec());
        }
        if vend > end {
            extents.insert(end, v[(end - k) as usize..].to_vec());
        }
    }
    if !data.is_empty() {
        extents.insert(start, data.to_vec());
    }
    *size = (*size).max(end);
}

/// Drops data at or beyond `size`.
fn sparse_truncate(extents: &mut BTreeMap<u64, Vec<u8>>, size: u64) {
    let gone: Vec<u64> = extents.range(size..).map(|(k, _)| *k).collect();
    for k in gone {
        extents.remove(&k);
    }
    if let Some((k, v)) = extents.range_mut(..size).next_back()
        && *k + v.len() as u64 > size
    {
        v.truncate((size - *k) as usize);
    }
}

impl Default for MemFs {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFs {
    /// An empty export containing only the root directory (mode 0755).
    pub fn new() -> Self {
        let clock = 1_700_000_000;
        let mut nodes = BTreeMap::new();
        nodes.insert(
            ROOT,
            Node {
                attr: new_attr(FileType::Directory, 0o755, ROOT, 4096, clock, 2),
                body: Body::Dir {
                    parent: ROOT,
                    entries: BTreeMap::new(),
                },
            },
        );
        MemFs {
            nodes,
            next_id: ROOT + 1,
            clock,
            version: NfsVersion::V3,
            max_read: 64 * 1024,
            max_write: 64 * 1024,
            write_call_limit: None,
        }
    }

    /// Creates a directory and any missing parents (`mkdir -p`).
    pub fn add_dir(&mut self, path: &str) -> Result<()> {
        self.mkdir_p(path).map(|_| ())
    }

    /// Creates or overwrites a regular file, creating parent directories.
    pub fn add_file(&mut self, path: &str, data: &[u8]) -> Result<()> {
        let (dir, name) = split_path(path);
        let parent = self.mkdir_p(dir)?;
        match self.child(parent, name.as_bytes()) {
            Some(id) => {
                let now = self.clock;
                let node = self.node_mut(id)?;
                let Body::File(contents) = &mut node.body else {
                    return Err(Error::Nfs(Status::Exist));
                };
                *contents = data.to_vec();
                node.attr.size = data.len() as u64;
                node.attr.used = data.len() as u64;
                node.attr.mtime = time(now);
                node.attr.ctime = time(now);
            }
            None => {
                self.add_entry(
                    parent,
                    name.as_bytes(),
                    Body::File(data.to_vec()),
                    0o644,
                    0,
                    0,
                )?;
            }
        }
        Ok(())
    }

    /// Creates a symbolic link; fails with `Exist` if the name is taken.
    pub fn add_symlink(&mut self, path: &str, target: &str) -> Result<()> {
        let (dir, name) = split_path(path);
        let parent = self.mkdir_p(dir)?;
        if self.child(parent, name.as_bytes()).is_some() {
            return Err(Error::Nfs(Status::Exist));
        }
        self.add_entry(
            parent,
            name.as_bytes(),
            Body::Symlink(target.as_bytes().to_vec()),
            0o777,
            0,
            0,
        )?;
        Ok(())
    }

    /// Creates a sparse regular file of `size` bytes whose unwritten bytes read as `fill`.
    /// Fails with `Exist` if the name is taken.
    pub fn add_sparse_file(&mut self, path: &str, size: u64, fill: u8) -> Result<()> {
        let (dir, name) = split_path(path);
        let parent = self.mkdir_p(dir)?;
        if self.child(parent, name.as_bytes()).is_some() {
            return Err(Error::Nfs(Status::Exist));
        }
        let body = Body::Sparse {
            size,
            fill,
            extents: BTreeMap::new(),
        };
        self.add_entry(parent, name.as_bytes(), body, 0o644, 0, 0)?;
        Ok(())
    }

    /// Contents of the regular file at `path`, if there is one. Sparse files
    /// are not materialized; use [`MemFs::read_at`] for those.
    pub fn read_file(&self, path: &str) -> Option<Vec<u8>> {
        match &self.nodes.get(&self.walk(path)?)?.body {
            Body::File(data) => Some(data.clone()),
            _ => None,
        }
    }

    /// Up to `len` bytes of the regular file at `path` starting at `offset`
    /// (regular or sparse), or `None` if there is no such file.
    pub fn read_at(&self, path: &str, offset: u64, len: u32) -> Option<Vec<u8>> {
        match &self.nodes.get(&self.walk(path)?)?.body {
            Body::File(data) => Some(slice_read(data, offset, len).0),
            Body::Sparse {
                size,
                fill,
                extents,
            } => Some(sparse_read(*size, *fill, extents, offset, len).0),
            _ => None,
        }
    }

    /// Attributes of the object at `path` (symlinks are not followed).
    pub fn attr_at(&self, path: &str) -> Option<Attr> {
        Some(self.nodes.get(&self.walk(path)?)?.attr.clone())
    }

    fn node(&self, id: u64) -> Result<&Node> {
        self.nodes.get(&id).ok_or(Error::Nfs(Status::Stale))
    }

    fn node_mut(&mut self, id: u64) -> Result<&mut Node> {
        self.nodes.get_mut(&id).ok_or(Error::Nfs(Status::Stale))
    }

    fn is_dir(&self, id: u64) -> bool {
        matches!(self.nodes.get(&id).map(|n| &n.body), Some(Body::Dir { .. }))
    }

    fn entries(&self, id: u64) -> Result<&BTreeMap<Vec<u8>, u64>> {
        match &self.node(id)?.body {
            Body::Dir { entries, .. } => Ok(entries),
            _ => Err(Error::Nfs(Status::NotDir)),
        }
    }

    fn entries_mut(&mut self, id: u64) -> Result<&mut BTreeMap<Vec<u8>, u64>> {
        match &mut self.node_mut(id)?.body {
            Body::Dir { entries, .. } => Ok(entries),
            _ => Err(Error::Nfs(Status::NotDir)),
        }
    }

    fn parent_of(&self, id: u64) -> Option<u64> {
        match self.nodes.get(&id)?.body {
            Body::Dir { parent, .. } => Some(parent),
            _ => None,
        }
    }

    fn child(&self, dir: u64, name: &[u8]) -> Option<u64> {
        self.entries(dir).ok()?.get(name).copied()
    }

    fn walk(&self, path: &str) -> Option<u64> {
        let mut cur = ROOT;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            cur = match comp {
                "." => cur,
                ".." => self.parent_of(cur)?,
                c => self.child(cur, c.as_bytes())?,
            };
        }
        Some(cur)
    }

    fn mkdir_p(&mut self, path: &str) -> Result<u64> {
        let mut cur = ROOT;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            cur = match self.child(cur, comp.as_bytes()) {
                Some(id) if self.is_dir(id) => id,
                Some(_) => return Err(Error::Nfs(Status::NotDir)),
                None => self.add_entry(
                    cur,
                    comp.as_bytes(),
                    Body::Dir {
                        parent: cur,
                        entries: BTreeMap::new(),
                    },
                    0o755,
                    0,
                    0,
                )?,
            };
        }
        Ok(cur)
    }

    fn touch(&mut self, id: u64) {
        let now = self.clock;
        if let Some(n) = self.nodes.get_mut(&id) {
            n.attr.mtime = time(now);
            n.attr.ctime = time(now);
        }
    }

    /// Inserts a new object under `dir`. The caller has checked that `name` is free.
    fn add_entry(
        &mut self,
        dir: u64,
        name: &[u8],
        mut body: Body,
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        if let Body::Dir { parent, .. } = &mut body {
            *parent = dir;
        }
        let (ftype, size, nlink) = match &body {
            Body::Dir { .. } => (FileType::Directory, 4096, 2),
            Body::File(data) => (FileType::Regular, data.len() as u64, 1),
            Body::Sparse { size, .. } => (FileType::Regular, *size, 1),
            Body::Symlink(target) => (FileType::Symlink, target.len() as u64, 1),
        };
        let mut attr = new_attr(ftype, mode, id, size, self.clock, nlink);
        attr.uid = uid;
        attr.gid = gid;
        self.nodes.insert(id, Node { attr, body });
        self.entries_mut(dir)?.insert(name.to_vec(), id);
        self.touch(dir);
        Ok(id)
    }

    /// Test helper for hostile servers: adds a child named by arbitrary bytes
    /// under the directory `dir`, pointing at the existing object `target`.
    /// Nothing is checked, so the name may contain '/', "..", NUL or control
    /// bytes, and a directory may be linked back into its own tree.
    pub fn add_raw_child(&mut self, dir: &str, name: &[u8], target: &str) -> Result<()> {
        let dir_id = self.id_of_path(dir)?;
        let target_id = self.id_of_path(target)?;
        self.entries_mut(dir_id)?.insert(name.to_vec(), target_id);
        self.node_mut(target_id)?.attr.nlink += 1;
        self.touch(dir_id);
        Ok(())
    }

    fn id_of_path(&self, path: &str) -> Result<u64> {
        let mut cur = ROOT;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            cur = self
                .child(cur, part.as_bytes())
                .ok_or(Error::Nfs(Status::NoEnt))?;
        }
        Ok(cur)
    }

    fn drop_link(&mut self, id: u64) {
        let gone = match self.nodes.get_mut(&id) {
            Some(n) => {
                n.attr.nlink = n.attr.nlink.saturating_sub(1);
                n.attr.nlink == 0
            }
            None => false,
        };
        if gone {
            self.nodes.remove(&id);
        }
    }
}

impl Filesystem for MemFs {
    fn version(&self) -> NfsVersion {
        self.version
    }

    fn root(&self) -> FileHandle {
        handle(ROOT)
    }

    fn max_read(&self) -> u32 {
        self.max_read
    }

    fn max_write(&self) -> u32 {
        self.max_write
    }

    fn getattr(&mut self, fh: &FileHandle) -> Result<Attr> {
        Ok(self.node(id_of(fh)?)?.attr.clone())
    }

    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr> {
        let id = id_of(fh)?;
        let now = self.clock;
        let node = self.node_mut(id)?;
        if let Some(mode) = attrs.mode {
            node.attr.mode = mode & 0o7777;
        }
        if let Some(uid) = attrs.uid {
            node.attr.uid = uid;
        }
        if let Some(gid) = attrs.gid {
            node.attr.gid = gid;
        }
        if let Some(size) = attrs.size {
            match &mut node.body {
                Body::File(data) => {
                    data.resize(size as usize, 0);
                    node.attr.size = size;
                    node.attr.used = size;
                }
                Body::Sparse {
                    size: total,
                    extents,
                    ..
                } => {
                    sparse_truncate(extents, size);
                    *total = size;
                    node.attr.size = size;
                    node.attr.used = size;
                }
                Body::Dir { .. } => return Err(Error::Nfs(Status::IsDir)),
                Body::Symlink(_) => return Err(Error::Nfs(Status::Inval)),
            }
            node.attr.mtime = time(now);
        }
        if let Some(t) = attrs.atime {
            node.attr.atime = match t {
                SetTime::ServerNow => time(now),
                SetTime::Client(c) => c,
            };
        }
        if let Some(t) = attrs.mtime {
            node.attr.mtime = match t {
                SetTime::ServerNow => time(now),
                SetTime::Client(c) => c,
            };
        }
        node.attr.ctime = time(now);
        Ok(node.attr.clone())
    }

    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> Result<(FileHandle, Attr)> {
        let did = id_of(dir)?;
        let id = match name {
            b"." => did,
            b".." => self.parent_of(did).ok_or(Error::Nfs(Status::NotDir))?,
            _ => self
                .entries(did)?
                .get(name)
                .copied()
                .ok_or(Error::Nfs(Status::NoEnt))?,
        };
        Ok((handle(id), self.node(id)?.attr.clone()))
    }

    fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<DirEntry>> {
        let entries = self.entries(id_of(dir)?)?;
        let mut out = Vec::with_capacity(entries.len());
        for (name, &id) in entries {
            out.push(DirEntry {
                name: name.clone(),
                fileid: id,
                attr: Some(self.node(id)?.attr.clone()),
                handle: Some(handle(id)),
            });
        }
        Ok(out)
    }

    fn readlink(&mut self, fh: &FileHandle) -> Result<Vec<u8>> {
        match &self.node(id_of(fh)?)?.body {
            Body::Symlink(target) => Ok(target.clone()),
            _ => Err(Error::Nfs(Status::Inval)),
        }
    }

    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        match &self.node(id_of(fh)?)?.body {
            Body::File(data) => Ok(slice_read(data, offset, count)),
            Body::Sparse {
                size,
                fill,
                extents,
            } => Ok(sparse_read(*size, *fill, extents, offset, count)),
            Body::Dir { .. } => Err(Error::Nfs(Status::IsDir)),
            Body::Symlink(_) => Err(Error::Nfs(Status::Inval)),
        }
    }

    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> Result<u32> {
        let id = id_of(fh)?;
        let now = self.clock;
        let take = self
            .write_call_limit
            .map_or(data.len(), |cap| data.len().min(cap));
        let data = &data[..take];
        let node = self.node_mut(id)?;
        match &mut node.body {
            Body::File(contents) => {
                let start = offset as usize;
                let end = start + data.len();
                if contents.len() < end {
                    contents.resize(end, 0);
                }
                contents[start..end].copy_from_slice(data);
                node.attr.size = contents.len() as u64;
            }
            Body::Sparse { size, extents, .. } => {
                sparse_write(extents, size, offset, data);
                node.attr.size = *size;
            }
            Body::Dir { .. } => return Err(Error::Nfs(Status::IsDir)),
            Body::Symlink(_) => return Err(Error::Nfs(Status::Inval)),
        }
        node.attr.used = node.attr.size;
        node.attr.mtime = time(now);
        node.attr.ctime = time(now);
        Ok(data.len() as u32)
    }

    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        check_name(name)?;
        let did = id_of(dir)?;
        if let Some(id) = self.entries(did)?.get(name).copied() {
            if mode != CreateMode::Unchecked {
                return Err(Error::Nfs(Status::Exist));
            }
            if self.is_dir(id) {
                return Err(Error::Nfs(Status::IsDir));
            }
            return Ok((handle(id), self.node(id)?.attr.clone()));
        }
        let id = self.add_entry(did, name, Body::File(Vec::new()), 0o644, 0, 0)?;
        let attr = self.setattr(&handle(id), attrs)?;
        Ok((handle(id), attr))
    }

    fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        check_name(name)?;
        let did = id_of(dir)?;
        if self.entries(did)?.contains_key(name) {
            return Err(Error::Nfs(Status::Exist));
        }
        let body = Body::Dir {
            parent: did,
            entries: BTreeMap::new(),
        };
        let id = self.add_entry(did, name, body, 0o755, 0, 0)?;
        let attr = self.setattr(&handle(id), attrs)?;
        Ok((handle(id), attr))
    }

    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        _attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        check_name(name)?;
        let did = id_of(dir)?;
        if self.entries(did)?.contains_key(name) {
            return Err(Error::Nfs(Status::Exist));
        }
        let id = self.add_entry(did, name, Body::Symlink(target.to_vec()), 0o777, 0, 0)?;
        Ok((handle(id), self.node(id)?.attr.clone()))
    }

    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> Result<()> {
        check_name(name)?;
        let tid = id_of(target)?;
        let did = id_of(dir)?;
        if self.is_dir(tid) {
            return Err(Error::Nfs(Status::Perm));
        }
        if self.entries(did)?.contains_key(name) {
            return Err(Error::Nfs(Status::Exist));
        }
        self.node_mut(tid)?.attr.nlink += 1;
        self.entries_mut(did)?.insert(name.to_vec(), tid);
        self.touch(tid);
        self.touch(did);
        Ok(())
    }

    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let did = id_of(dir)?;
        let id = self
            .entries(did)?
            .get(name)
            .copied()
            .ok_or(Error::Nfs(Status::NoEnt))?;
        if self.is_dir(id) {
            return Err(Error::Nfs(Status::IsDir));
        }
        self.entries_mut(did)?.remove(name);
        self.drop_link(id);
        self.touch(did);
        Ok(())
    }

    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        let did = id_of(dir)?;
        let id = self
            .entries(did)?
            .get(name)
            .copied()
            .ok_or(Error::Nfs(Status::NoEnt))?;
        match self.node(id)?.body {
            Body::Dir { ref entries, .. } if entries.is_empty() => {}
            Body::Dir { .. } => return Err(Error::Nfs(Status::NotEmpty)),
            _ => return Err(Error::Nfs(Status::NotDir)),
        }
        self.entries_mut(did)?.remove(name);
        self.nodes.remove(&id);
        self.touch(did);
        Ok(())
    }

    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> Result<()> {
        check_name(from_name)?;
        check_name(to_name)?;
        let fdid = id_of(from_dir)?;
        let tdid = id_of(to_dir)?;
        let cid = self
            .entries(fdid)?
            .get(from_name)
            .copied()
            .ok_or(Error::Nfs(Status::NoEnt))?;
        let existing = self.entries(tdid)?.get(to_name).copied();
        if existing == Some(cid) {
            // Same object under both names: POSIX says drop the source name only.
            self.entries_mut(fdid)?.remove(from_name);
            self.drop_link(cid);
            return Ok(());
        }
        let src_is_dir = self.is_dir(cid);
        if let Some(eid) = existing {
            match (src_is_dir, self.is_dir(eid)) {
                (true, false) => return Err(Error::Nfs(Status::NotDir)),
                (false, true) => return Err(Error::Nfs(Status::IsDir)),
                (true, true) if !self.entries(eid)?.is_empty() => {
                    return Err(Error::Nfs(Status::NotEmpty));
                }
                _ => {}
            }
        }
        if src_is_dir {
            // Refuse to move a directory into its own subtree.
            let mut cur = tdid;
            loop {
                if cur == cid {
                    return Err(Error::Nfs(Status::Inval));
                }
                if cur == ROOT {
                    break;
                }
                cur = self.parent_of(cur).ok_or(Error::Nfs(Status::Stale))?;
            }
        }
        self.entries_mut(fdid)?.remove(from_name);
        if let Some(eid) = existing {
            self.entries_mut(tdid)?.remove(to_name);
            if self.is_dir(eid) {
                self.nodes.remove(&eid);
            } else {
                self.drop_link(eid);
            }
        }
        self.entries_mut(tdid)?.insert(to_name.to_vec(), cid);
        if let Some(Node {
            body: Body::Dir { parent, .. },
            ..
        }) = self.nodes.get_mut(&cid)
        {
            *parent = tdid;
        }
        self.touch(fdid);
        self.touch(tdid);
        Ok(())
    }

    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat> {
        let _ = self.node(id_of(fh)?)?;
        Ok(FsStat {
            total_bytes: 1 << 30,
            free_bytes: 1 << 29,
            avail_bytes: 1 << 29,
            total_files: 1 << 20,
            free_files: 1 << 19,
            avail_files: 1 << 19,
        })
    }

    fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(fs: &MemFs) -> FileHandle {
        fs.root()
    }

    #[test]
    fn lookup_walks_and_reports_missing_names() {
        let mut fs = MemFs::new();
        fs.add_file("a/b/c.txt", b"hi").unwrap();
        let (a, _) = fs.lookup(&root(&fs), b"a").unwrap();
        let (b, _) = fs.lookup(&a, b"b").unwrap();
        let (c, attr) = fs.lookup(&b, b"c.txt").unwrap();
        assert_eq!(attr.size, 2);
        assert_eq!(fs.read(&c, 0, 10).unwrap(), (b"hi".to_vec(), true));
        assert_eq!(
            fs.lookup(&b, b"nope").unwrap_err().to_string(),
            "no such file or directory"
        );
        assert_eq!(
            fs.lookup(&c, b"x").unwrap_err().to_string(),
            "not a directory"
        );
        // ".." from a child returns to its parent; ".." at the root stays there.
        let (up, _) = fs.lookup(&b, b"..").unwrap();
        assert_eq!(up, a);
        let (top, _) = fs.lookup(&root(&fs), b"..").unwrap();
        assert_eq!(top, root(&fs));
    }

    #[test]
    fn short_writes_are_reported_and_loopable() {
        let mut fs = MemFs::new();
        fs.write_call_limit = Some(3);
        let (fh, _) = fs
            .create(&root(&fs), b"f", CreateMode::Unchecked, &SetAttr::default())
            .unwrap();
        let n = fs.write(&fh, 0, b"hello").unwrap();
        assert_eq!(n, 3, "the cap must produce a short count");
        assert_eq!(fs.read_file("f").unwrap(), b"hel");
        fs.write_call_limit = None;
        fs.write(&fh, 3, b"lo").unwrap();
        assert_eq!(fs.read_file("f").unwrap(), b"hello");
    }

    #[test]
    fn rename_refuses_to_move_a_directory_into_itself() {
        let mut fs = MemFs::new();
        fs.add_dir("d/sub").unwrap();
        let r = root(&fs);
        let (d, _) = fs.lookup(&r, b"d").unwrap();
        let (sub, _) = fs.lookup(&d, b"sub").unwrap();
        assert_eq!(
            fs.rename(&r, b"d", &sub, b"x").unwrap_err().to_string(),
            "invalid argument"
        );
    }

    #[test]
    fn hard_links_count_and_free_the_node_on_last_remove() {
        let mut fs = MemFs::new();
        fs.add_file("a", b"data").unwrap();
        let r = root(&fs);
        let (a, _) = fs.lookup(&r, b"a").unwrap();
        fs.link(&a, &r, b"b").unwrap();
        assert_eq!(fs.attr_at("a").unwrap().nlink, 2);
        fs.remove(&r, b"a").unwrap();
        assert_eq!(fs.read_file("b").unwrap(), b"data");
        fs.remove(&r, b"b").unwrap();
        assert!(fs.getattr(&a).is_err());
    }

    #[test]
    fn rmdir_requires_an_empty_directory() {
        let mut fs = MemFs::new();
        fs.add_file("d/f", b"").unwrap();
        let r = root(&fs);
        assert_eq!(
            fs.rmdir(&r, b"d").unwrap_err().to_string(),
            "directory not empty"
        );
    }
}
