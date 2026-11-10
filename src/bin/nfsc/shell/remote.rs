//! Shared access to the connected filesystem, the path resolver, and the
//! directory cache used by tab completion.
//!
//! The session and the line editor's completer both need the connection.
//! Readline runs while the session is idle, so both can hold a [`SharedFs`]
//! clone; each call borrows the connection only for its own duration.

use std::cell::RefCell;
use std::rc::Rc;

use nfsc::fs::{
    Attr, CreateMode, DirEntry, FileHandle, FileType, Filesystem, FsStat, NfsVersion, SetAttr,
};
use nfsc::{Error, Result};

use super::session::{Node, components, last_node};

/// Symlinks followed while resolving one path before giving up.
const MAX_SYMLINKS: usize = 40;

/// Directories remembered by [`DirCache`].
const CACHE_DIRS: usize = 16;

/// A cloneable handle to one backend connection.
#[derive(Clone)]
pub struct SharedFs(Rc<RefCell<Box<dyn Filesystem>>>);

impl SharedFs {
    pub fn new(fs: Box<dyn Filesystem>) -> Self {
        SharedFs(Rc::new(RefCell::new(fs)))
    }
}

/// Delegates every call, including the bulk transfer methods, so a backend's
/// pipelined overrides are used.
impl Filesystem for SharedFs {
    fn version(&self) -> NfsVersion {
        self.0.borrow().version()
    }
    fn root(&self) -> FileHandle {
        self.0.borrow().root()
    }
    fn max_read(&self) -> u32 {
        self.0.borrow().max_read()
    }
    fn max_write(&self) -> u32 {
        self.0.borrow().max_write()
    }
    fn getattr(&mut self, fh: &FileHandle) -> Result<Attr> {
        self.0.borrow_mut().getattr(fh)
    }
    fn setattr(&mut self, fh: &FileHandle, attrs: &SetAttr) -> Result<Attr> {
        self.0.borrow_mut().setattr(fh, attrs)
    }
    fn lookup(&mut self, dir: &FileHandle, name: &[u8]) -> Result<(FileHandle, Attr)> {
        self.0.borrow_mut().lookup(dir, name)
    }
    fn readdir(&mut self, dir: &FileHandle) -> Result<Vec<DirEntry>> {
        self.0.borrow_mut().readdir(dir)
    }
    fn readlink(&mut self, fh: &FileHandle) -> Result<Vec<u8>> {
        self.0.borrow_mut().readlink(fh)
    }
    fn read(&mut self, fh: &FileHandle, offset: u64, count: u32) -> Result<(Vec<u8>, bool)> {
        self.0.borrow_mut().read(fh, offset, count)
    }
    fn write(&mut self, fh: &FileHandle, offset: u64, data: &[u8]) -> Result<u32> {
        self.0.borrow_mut().write(fh, offset, data)
    }
    fn create(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        mode: CreateMode,
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        self.0.borrow_mut().create(dir, name, mode, attrs)
    }
    fn mkdir(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        self.0.borrow_mut().mkdir(dir, name, attrs)
    }
    fn symlink(
        &mut self,
        dir: &FileHandle,
        name: &[u8],
        target: &[u8],
        attrs: &SetAttr,
    ) -> Result<(FileHandle, Attr)> {
        self.0.borrow_mut().symlink(dir, name, target, attrs)
    }
    fn link(&mut self, target: &FileHandle, dir: &FileHandle, name: &[u8]) -> Result<()> {
        self.0.borrow_mut().link(target, dir, name)
    }
    fn remove(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        self.0.borrow_mut().remove(dir, name)
    }
    fn rmdir(&mut self, dir: &FileHandle, name: &[u8]) -> Result<()> {
        self.0.borrow_mut().rmdir(dir, name)
    }
    fn rename(
        &mut self,
        from_dir: &FileHandle,
        from_name: &[u8],
        to_dir: &FileHandle,
        to_name: &[u8],
    ) -> Result<()> {
        self.0
            .borrow_mut()
            .rename(from_dir, from_name, to_dir, to_name)
    }
    fn fsstat(&mut self, fh: &FileHandle) -> Result<FsStat> {
        self.0.borrow_mut().fsstat(fh)
    }
    fn disconnect(&mut self) -> Result<()> {
        self.0.borrow_mut().disconnect()
    }
    fn read_stream(
        &mut self,
        fh: &FileHandle,
        offset: u64,
        len: Option<u64>,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        self.0.borrow_mut().read_stream(fh, offset, len, sink)
    }
    fn write_stream(
        &mut self,
        fh: &FileHandle,
        offset: u64,
        source: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
    ) -> Result<u64> {
        self.0.borrow_mut().write_stream(fh, offset, source)
    }
}

/// One directory entry as completion sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: Vec<u8>,
    pub is_dir: bool,
}

/// Directory listings kept for completion. Cleared after any command that can
/// change the remote tree, and after `cd`.
#[derive(Default)]
pub struct DirCache {
    lists: Vec<(Vec<u8>, Vec<Listed>)>,
}

impl DirCache {
    pub fn clear(&mut self) {
        self.lists.clear();
    }

    /// The listing of `dir`, read from the server on a cache miss.
    pub fn listing(&mut self, fs: &mut dyn Filesystem, dir: &FileHandle) -> Result<Vec<Listed>> {
        if let Some((_, hit)) = self.lists.iter().find(|(key, _)| *key == dir.0) {
            return Ok(hit.clone());
        }
        let listed: Vec<Listed> = fs
            .readdir(dir)?
            .into_iter()
            .map(|e| Listed {
                is_dir: e
                    .attr
                    .as_ref()
                    .is_some_and(|a| a.ftype == FileType::Directory),
                name: e.name,
            })
            .collect();
        if self.lists.len() == CACHE_DIRS {
            self.lists.remove(0);
        }
        self.lists.push((dir.0.clone(), listed.clone()));
        Ok(listed)
    }
}

/// What tab completion needs from the session, captured before each prompt.
pub struct RemoteCtx {
    pub fs: SharedFs,
    pub root: Node,
    pub export: Vec<u8>,
    pub cwd: Vec<Node>,
    pub cache: Rc<RefCell<DirCache>>,
}

/// Resolves `path` to the chain of nodes from the export root to its target.
///
/// Absolute paths start at the export root (`/` is the root), others at `cwd`.
/// `.` is skipped and `..` pops one level, staying at the root. Symlinks are
/// followed for every component, and for the last one only when `follow_last`
/// is set. Absolute symlink targets must lie inside the export; relative ones
/// are resolved from the link's directory.
pub fn resolve_path(
    fs: &mut dyn Filesystem,
    root: &Node,
    export: &[u8],
    cwd: &[Node],
    path: &str,
    follow_last: bool,
) -> Result<Vec<Node>> {
    let mut stack = if path.starts_with('/') {
        vec![root.clone()]
    } else {
        cwd.to_vec()
    };
    let mut pending = components(path.as_bytes());
    let mut links = 0;
    while let Some(name) = pending.pop_front() {
        if name.as_slice() == b"." {
            continue;
        }
        if name.as_slice() == b".." {
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }
        let is_last = pending.is_empty();
        let dir = last_node(&stack).fh.clone();
        let (fh, attr) = fs.lookup(&dir, &name)?;
        if attr.ftype == FileType::Symlink && (follow_last || !is_last) {
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(Error::Invalid("too many levels of symbolic links".into()));
            }
            let target = fs.readlink(&fh)?;
            let mut next = if target.first() == Some(&b'/') {
                stack.truncate(1);
                components(&within_export(export, &target)?)
            } else {
                components(&target)
            };
            next.extend(pending.drain(..));
            pending = next;
            continue;
        }
        stack.push(Node { name, fh, attr });
    }
    Ok(stack)
}

/// Maps an absolute symlink target onto the export root, or refuses it.
pub fn within_export(export: &[u8], target: &[u8]) -> Result<Vec<u8>> {
    let end = export.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
    let export = &export[..end];
    if export.is_empty() {
        // The export is "/": every absolute target is already inside it.
        return Ok(target.to_vec());
    }
    if target == export {
        return Ok(Vec::new());
    }
    if target.len() > export.len() && target.starts_with(export) && target[export.len()] == b'/' {
        return Ok(target[export.len()..].to_vec());
    }
    Err(Error::Invalid(format!(
        "symbolic link target '{}' is outside the export",
        String::from_utf8_lossy(target)
    )))
}
