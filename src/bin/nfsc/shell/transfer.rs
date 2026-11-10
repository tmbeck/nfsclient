//! get and put, and the transfer loops behind them.
//!
//! Downloads and uploads go through the backend's `read_stream` and
//! `write_stream`, so backends that pipeline keep several transfers in flight.
//! Every chunk passes a closure that checks the Ctrl-C flag and feeds the
//! progress meter. An interrupt ends the transfer with an error that the
//! session reports as "interrupted".
//!
//! Resume (`-c`): `get -c` continues a local file from its current size and
//! `put -c` continues a remote file from its current size. Only sizes are
//! compared; contents are not checked.

use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nfsc::fs::{Attr, CreateMode, FileHandle, FileType, Filesystem, SetAttr, Status, Time};
use nfsc::{Error, Result};

use super::format;
use super::interrupt;
use super::line::parse_args;
use super::progress::{LineWriter, Meter, TreeProgress};
use super::session::{
    CmdFailure, CmdResult, Ctx, Session, io_text, is_plain_name, last_node, split_last, usage,
};
use crate::text::{display_name, display_path, display_str};

/// Directory levels a recursive get descends. Deeper subtrees are skipped with a
/// note, so a server cannot make the recursion (or local paths) unbounded.
const MAX_TREE_DEPTH: usize = 256;

/// `O_NOFOLLOW`, so a local symbolic link at a download target is refused
/// instead of followed. The value differs by platform.
#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const O_NOFOLLOW: i32 = 0x0100;

fn local_err(e: std::io::Error) -> Error {
    Error::Invalid(io_text(&e))
}

fn rate(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(0.001);
    format!("{}/s", format::human((bytes as f64 / secs) as u64))
}

/// " (resumed at N)" and friends for summary lines.
fn resumed_note(start: u64, size: u64) -> String {
    match start {
        0 => String::new(),
        s if s >= size => ", already complete".to_string(),
        s => format!(", resumed at {s}"),
    }
}

/// A file's remote mtime as a local time, or `None` if it is out of range.
fn system_time(t: Time) -> Option<SystemTime> {
    let base = if t.seconds >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(t.seconds.unsigned_abs()))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(t.seconds.unsigned_abs()))?
    };
    base.checked_add(Duration::from_nanos(u64::from(t.nseconds.min(999_999_999))))
}

/// Opens a local download target. Without `resume` the file is truncated. With
/// `resume` an existing file is kept and its size returned, and a missing file
/// is created with size 0. `nofollow` refuses a symbolic link at `path`; it is
/// set for files inside a downloaded tree, whose names come from the server.
/// The size comes from the open descriptor, so it cannot change under us.
fn open_local(path: &Path, resume: bool, nofollow: bool) -> Result<(File, u64)> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(!resume);
    if nofollow {
        opts.custom_flags(O_NOFOLLOW);
    }
    let file = opts.open(path).map_err(|e| {
        let link = nofollow && fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink());
        if link {
            Error::Invalid(format!(
                "{} is a symbolic link; not writing through it",
                display_path(path)
            ))
        } else {
            Error::Invalid(format!("{}: {}", display_path(path), io_text(&e)))
        }
    })?;
    let meta = file.metadata().map_err(local_err)?;
    if !meta.is_file() {
        return Err(Error::Invalid(format!(
            "{} is not a regular file",
            display_path(path)
        )));
    }
    let start = if resume { meta.len() } else { 0 };
    Ok((file, start))
}

impl Session {
    pub(super) fn cmd_get(
        &mut self,
        args: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> CmdResult<()> {
        const CMD: &str = "get";
        let flags = parse_args(args, "rc").map_err(|m| usage(CMD, m))?;
        let (recursive, resume) = (flags.has('r'), flags.has('c'));
        let (remote, local) = match flags.positional.as_slice() {
            [r] => (r.as_str(), None),
            [r, l] => (r.as_str(), Some(l.as_str())),
            _ => return Err(usage(CMD, "usage: get [-r] [-c] remote [local]")),
        };
        let sources = self.expand(CMD, remote)?;
        let several = sources.len() > 1 || super::line::is_pattern(remote);
        let to_stdout = local == Some("-");
        if to_stdout && (recursive || several) {
            return Err(CmdFailure::new(
                CMD,
                Some(remote),
                "only one file can be written to stdout",
            ));
        }
        if to_stdout && resume {
            return Err(usage(CMD, "-c needs a local file, not stdout"));
        }
        let explicit = match local {
            Some("-") | None => None,
            Some(l) => Some(self.local_path(l)),
        };
        if several && explicit.as_ref().is_some_and(|p| !p.is_dir()) {
            return Err(CmdFailure::new(
                CMD,
                Some(remote),
                "several files need a local directory as destination",
            ));
        }
        for src in &sources {
            let stack = self.resolve(src, true).ctx(CMD, src)?;
            let node = last_node(&stack).clone();
            let (_, base) = split_last(src);
            if node.attr.ftype == FileType::Directory && !recursive {
                if several {
                    writeln!(
                        err,
                        "nfsc: get: skipping directory {} (use -r)",
                        display_str(src)
                    )
                    .map_err(|e| CmdFailure::new(CMD, None, e.to_string()))?;
                    continue;
                }
                return Err(CmdFailure::new(CMD, Some(src), "is a directory (use -r)"));
            }
            if to_stdout {
                let start = Instant::now();
                let n = self.stream_to(&node.fh, 0, out).ctx(CMD, src)?;
                writeln!(
                    err,
                    "getting file {} of size {n} as - ({})",
                    display_str(src),
                    rate(n, start.elapsed())
                )
                .map_err(|e| CmdFailure::new(CMD, None, e.to_string()))?;
                continue;
            }
            // The local name is the last component of the remote path. "." and
            // ".." would name the destination itself or its parent.
            if !is_plain_name(base.as_bytes()) {
                return Err(usage(
                    CMD,
                    format!("cannot name a local file for '{}'", display_str(src)),
                ));
            }
            let dest = match &explicit {
                None => self.local_cwd().join(base),
                Some(p) if p.is_dir() => p.join(base),
                Some(p) => p.clone(),
            };
            let label = display_str(base);
            if node.attr.ftype == FileType::Directory {
                let key = (node.attr.fsid, node.attr.fileid);
                let totals = if self.progress {
                    Some(
                        self.scan_remote_tree(&node.fh, key, &mut Vec::new())
                            .ctx(CMD, src)?,
                    )
                } else {
                    None
                };
                let tree = TreeProgress::new(totals);
                let mut lines = LineWriter::new(err, tree.multi());
                self.tree = Some(tree);
                let result =
                    self.get_tree(&node.fh, key, &dest, resume, &mut lines, &mut Vec::new());
                drop(lines);
                self.scan_cache.clear();
                let tree = self.tree.take();
                let summary = tree.map(|t| t.finish("got"));
                result.ctx(CMD, src)?;
                if let Some(line) = summary {
                    writeln!(err, "{line}")
                        .map_err(|e| CmdFailure::new(CMD, None, e.to_string()))?;
                }
            } else {
                self.fetch_to_path(&label, &node.fh, &node.attr, &dest, resume, false, err)
                    .ctx(CMD, src)?;
            }
        }
        Ok(())
    }

    pub(super) fn cmd_put(&mut self, args: &[String], err: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "put";
        let flags = parse_args(args, "rc").map_err(|m| usage(CMD, m))?;
        let (recursive, resume) = (flags.has('r'), flags.has('c'));
        let (local, remote) = match flags.positional.as_slice() {
            [l] => (l.as_str(), None),
            [l, r] => (l.as_str(), Some(r.as_str())),
            _ => return Err(usage(CMD, "usage: put [-r] [-c] local [remote]")),
        };
        let path = self.local_path(local);
        let meta =
            fs::metadata(&path).map_err(|e| CmdFailure::new(CMD, Some(local), io_text(&e)))?;
        let (_, base) = split_last(local);
        if base.is_empty() {
            return Err(usage(
                CMD,
                format!("cannot name a remote file for '{local}'"),
            ));
        }
        let dst = remote.unwrap_or(base);
        let (dir, name) = self.destination(dst, local).ctx(CMD, local)?;
        if meta.is_dir() {
            if !recursive {
                return Err(CmdFailure::new(CMD, Some(local), "is a directory (use -r)"));
            }
            let totals = self.progress.then(|| scan_local_tree(&path, 0));
            let tree = TreeProgress::new(totals);
            let mut lines = LineWriter::new(err, tree.multi());
            self.tree = Some(tree);
            let result = self.put_tree(&path, &dir, &name, resume, &mut lines);
            drop(lines);
            let tree = self.tree.take();
            let summary = tree.map(|t| t.finish("put"));
            result.ctx(CMD, local)?;
            if let Some(line) = summary {
                writeln!(err, "{line}").map_err(|e| CmdFailure::new(CMD, None, e.to_string()))?;
            }
            Ok(())
        } else {
            self.put_file(&path, &meta, &dir, &name, resume, err)
                .ctx(CMD, local)
        }
    }

    /// Streams `fh` from `start` for `len` bytes (or to EOF when `None`),
    /// checking for Ctrl-C before each chunk. Returns the bytes delivered.
    pub(super) fn download(
        &mut self,
        fh: &FileHandle,
        start: u64,
        len: Option<u64>,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        let flag = Arc::clone(&self.interrupt);
        let mut checked = |chunk: &[u8]| -> Result<()> {
            interrupt::check(&flag)?;
            sink(chunk)
        };
        self.fs.read_stream(fh, start, len, &mut checked)
    }

    /// Writes the file `fh` from `start` to `out`. Returns the bytes written.
    pub(super) fn stream_to(
        &mut self,
        fh: &FileHandle,
        start: u64,
        out: &mut dyn Write,
    ) -> Result<u64> {
        self.download(fh, start, None, &mut |chunk: &[u8]| -> Result<()> {
            out.write_all(chunk).map_err(local_err)
        })
    }

    /// Downloads one file to `path`, overwriting it unless `resume` is set.
    /// Restores the remote mode and modification time on success. Only the
    /// size the server reported is written; more data is not stored. `nofollow`
    /// is set for files inside a downloaded tree (see [`open_local`]).
    #[allow(clippy::too_many_arguments)]
    fn fetch_to_path(
        &mut self,
        label: &str,
        fh: &FileHandle,
        attr: &Attr,
        path: &Path,
        resume: bool,
        nofollow: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        let (mut file, start) = open_local(path, resume, nofollow)?;
        let size = attr.size;
        if start > size {
            return Err(Error::Invalid(format!(
                "local file is larger than the remote file ({start} > {size} bytes), not resuming"
            )));
        }
        let started = Instant::now();
        let mut tree = self.tree.take();
        let mut meter = Meter::new(self.progress, label, size, start, tree.as_mut());
        let mut done = start;
        let result = if start < size {
            file.seek(SeekFrom::Start(start)).map_err(local_err)?;
            self.download(
                fh,
                start,
                Some(size - start),
                &mut |chunk: &[u8]| -> Result<()> {
                    file.write_all(chunk).map_err(local_err)?;
                    done += chunk.len() as u64;
                    meter.tick(done);
                    Ok(())
                },
            )
        } else {
            Ok(0)
        };
        let complete = matches!(result, Ok(n) if start + n >= size);
        meter.finish(complete);
        self.tree = tree;
        let delivered = match result {
            Ok(n) => n,
            Err(e) => {
                drop(file);
                if interrupt::is_interrupt(&e) && !resume {
                    let _ = fs::remove_file(path);
                    let _ = writeln!(
                        err,
                        "nfsc: get: removed partial file {}",
                        display_path(path)
                    );
                }
                return Err(e);
            }
        };
        if start + delivered < size {
            return Err(Error::Invalid(format!(
                "transfer of {label} stopped at {} of {size} bytes",
                start + delivered
            )));
        }
        file.sync_all().map_err(local_err)?;
        // Best effort: a failed chmod or utime does not undo a successful download.
        // Setuid, setgid and sticky bits from the server are dropped: a root
        // download must not create a set-id local file. The chmod goes through the
        // descriptor, so it cannot land on a symlink target.
        let _ = file.set_permissions(fs::Permissions::from_mode(attr.mode & 0o777));
        if let Some(t) = system_time(attr.mtime)
            && let Err(e) = file.set_modified(t)
        {
            let _ = writeln!(
                err,
                "nfsc: get: cannot set the time of {}: {}",
                display_path(path),
                io_text(&e)
            );
        }
        drop(file);
        writeln!(
            err,
            "getting file {label} of size {size} as {} ({}{})",
            display_path(path),
            rate(delivered, started.elapsed()),
            resumed_note(start, size)
        )
        .map_err(local_err)
    }

    /// Counts the regular files and bytes that [`Self::get_tree`] would
    /// download, applying the same skip rules (unsafe names, loops, depth).
    /// Listings (with handles and attributes filled in) are kept in
    /// `scan_cache` so the download does not list each directory twice.
    fn scan_remote_tree(
        &mut self,
        fh: &FileHandle,
        key: (u64, u64),
        ancestors: &mut Vec<(u64, u64)>,
    ) -> Result<(u64, u64)> {
        ancestors.push(key);
        let mut entries = self.fs.readdir(fh)?;
        let (mut files, mut bytes) = (0u64, 0u64);
        let mut subdirs = Vec::new();
        for entry in &mut entries {
            if !is_plain_name(&entry.name) {
                continue;
            }
            if entry.handle.is_none() || entry.attr.is_none() {
                let (h, a) = self.fs.lookup(fh, &entry.name)?;
                entry.handle = Some(h);
                entry.attr = Some(a);
            }
            let attr = entry.attr.as_ref().expect("filled above");
            match attr.ftype {
                FileType::Regular => {
                    files += 1;
                    bytes = bytes.saturating_add(attr.size);
                }
                FileType::Directory => {
                    let k = (attr.fsid, attr.fileid);
                    if !(k.1 != 0 && ancestors.contains(&k)) && ancestors.len() < MAX_TREE_DEPTH {
                        subdirs.push((entry.handle.clone().expect("filled above"), k));
                    }
                }
                _ => {}
            }
        }
        self.scan_cache.insert(fh.clone(), entries);
        for (h, k) in subdirs {
            let (f, b) = self.scan_remote_tree(&h, k, ancestors)?;
            files += f;
            bytes = bytes.saturating_add(b);
        }
        ancestors.pop();
        Ok((files, bytes))
    }

    /// Downloads a directory tree. Entries are skipped with a note when they are
    /// symlinks or special files, when their name is not one plain component, when
    /// the directory is already one of its ancestors (a loop, detected by
    /// fsid/fileid), or when the tree is deeper than [`MAX_TREE_DEPTH`]. Files
    /// are written with `nofollow`, and subdirectories are never entered through
    /// a symbolic link, so a local link under `dir` is not followed.
    /// `ancestors` holds the (fsid, fileid) keys of the directories above `dir`.
    fn get_tree(
        &mut self,
        fh: &FileHandle,
        key: (u64, u64),
        dir: &Path,
        resume: bool,
        err: &mut dyn Write,
        ancestors: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        ancestors.push(key);
        let result = self.get_tree_entries(fh, dir, resume, err, ancestors);
        ancestors.pop();
        result
    }

    fn get_tree_entries(
        &mut self,
        fh: &FileHandle,
        dir: &Path,
        resume: bool,
        err: &mut dyn Write,
        ancestors: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        fs::create_dir_all(dir).map_err(local_err)?;
        let mut entries = match self.scan_cache.remove(fh) {
            Some(e) => e,
            None => self.fs.readdir(fh)?,
        };
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in entries {
            let label = display_name(&entry.name);
            if !is_plain_name(&entry.name) {
                writeln!(err, "nfsc: get: skipping unsafe name {label}").map_err(local_err)?;
                continue;
            }
            let child = dir.join(OsStr::from_bytes(&entry.name));
            let (cfh, attr) = match (entry.handle, entry.attr) {
                (Some(h), Some(a)) => (h, a),
                _ => self.fs.lookup(fh, &entry.name)?,
            };
            match attr.ftype {
                FileType::Directory => {
                    let key = (attr.fsid, attr.fileid);
                    if key.1 != 0 && ancestors.contains(&key) {
                        writeln!(err, "nfsc: get: skipping directory loop {label}")
                            .map_err(local_err)?;
                    } else if ancestors.len() >= MAX_TREE_DEPTH {
                        writeln!(
                            err,
                            "nfsc: get: skipping {label}: directory tree is too deep"
                        )
                        .map_err(local_err)?;
                    } else if fs::symlink_metadata(&child).is_ok_and(|m| m.file_type().is_symlink())
                    {
                        writeln!(
                            err,
                            "nfsc: get: skipping {label}: a symbolic link is in the way"
                        )
                        .map_err(local_err)?;
                    } else {
                        self.get_tree(&cfh, key, &child, resume, err, ancestors)?;
                    }
                }
                FileType::Regular => {
                    self.fetch_to_path(&label, &cfh, &attr, &child, resume, true, err)?
                }
                FileType::Symlink => {
                    writeln!(err, "nfsc: get: skipping symbolic link {label}")
                        .map_err(local_err)?;
                }
                _ => {
                    writeln!(err, "nfsc: get: skipping special file {label}").map_err(local_err)?;
                }
            }
        }
        Ok(())
    }

    /// Uploads one local file as `name` in `dir`, replacing any existing file
    /// unless `resume` is set, in which case the remote file is continued from
    /// its current size.
    fn put_file(
        &mut self,
        local: &Path,
        meta: &Metadata,
        dir: &FileHandle,
        name: &[u8],
        resume: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        let mut file = File::open(local).map_err(local_err)?;
        let size = meta.len();
        let mode = meta.permissions().mode() & 0o7777;
        let label = display_name(name);
        let existing = match self.fs.lookup(dir, name) {
            Ok(found) => Some(found),
            Err(Error::Nfs(Status::NoEnt)) => None,
            Err(e) => return Err(e),
        };
        let (fh, start, attrs) = match existing {
            Some((fh, attr)) => {
                if attr.ftype == FileType::Directory {
                    return Err(Error::Nfs(Status::IsDir));
                }
                if resume {
                    if attr.size > size {
                        return Err(Error::Invalid(format!(
                            "remote file is larger than the local file ({} > {size} bytes), not resuming",
                            attr.size
                        )));
                    }
                    let attrs = SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    };
                    (fh, attr.size, attrs)
                } else {
                    let attrs = SetAttr {
                        mode: Some(mode),
                        size: Some(0),
                        ..SetAttr::default()
                    };
                    (fh, 0, attrs)
                }
            }
            None => {
                let (fh, _) =
                    self.fs
                        .create(dir, name, CreateMode::Unchecked, &SetAttr::default())?;
                let attrs = SetAttr {
                    mode: Some(mode),
                    ..SetAttr::default()
                };
                (fh, 0, attrs)
            }
        };
        self.fs.setattr(&fh, &attrs)?;

        let started = Instant::now();
        let mut tree = self.tree.take();
        let mut meter = Meter::new(self.progress, &label, size, start, tree.as_mut());
        let mut sent = start;
        if start >= size {
            meter.finish(true);
        } else {
            file.seek(SeekFrom::Start(start)).map_err(local_err)?;
            let flag = Arc::clone(&self.interrupt);
            let result = self
                .fs
                .write_stream(&fh, start, &mut |buf: &mut [u8]| -> Result<usize> {
                    interrupt::check(&flag)?;
                    let n = file.read(buf).map_err(local_err)?;
                    sent += n as u64;
                    meter.tick(sent);
                    Ok(n)
                });
            meter.finish(result.is_ok());
            if let Err(e) = result {
                self.tree = tree;
                if interrupt::is_interrupt(&e) {
                    let _ = writeln!(
                        err,
                        "nfsc: put: remote file {label} is partial ({sent} of {size} bytes); put -c continues it"
                    );
                }
                return Err(e);
            }
        }
        self.tree = tree;
        writeln!(
            err,
            "putting file {} as {label} ({}{})",
            display_path(local),
            rate(sent - start, started.elapsed()),
            resumed_note(start, size)
        )
        .map_err(local_err)
    }

    /// Uploads a local directory tree. Symlinks and special files are skipped.
    fn put_tree(
        &mut self,
        local: &Path,
        dir: &FileHandle,
        name: &[u8],
        resume: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        let attrs = SetAttr {
            mode: Some(0o755),
            ..SetAttr::default()
        };
        let dir_fh = match self.fs.mkdir(dir, name, &attrs) {
            Ok((fh, _)) => fh,
            Err(Error::Nfs(Status::Exist)) => {
                let (fh, attr) = self.fs.lookup(dir, name)?;
                if attr.ftype != FileType::Directory {
                    return Err(Error::Nfs(Status::NotDir));
                }
                fh
            }
            Err(e) => return Err(e),
        };
        let mut entries = fs::read_dir(local)
            .map_err(local_err)?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(local_err)?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let child = entry.file_name();
            let meta = entry.metadata().map_err(local_err)?;
            if meta.is_dir() {
                self.put_tree(&path, &dir_fh, child.as_bytes(), resume, err)?;
            } else if meta.is_file() {
                self.put_file(&path, &meta, &dir_fh, child.as_bytes(), resume, err)?;
            } else {
                writeln!(
                    err,
                    "nfsc: put: skipping {} (not a regular file or directory)",
                    display_path(&path)
                )
                .map_err(local_err)?;
            }
        }
        Ok(())
    }
}

/// Counts the regular files and bytes under `dir` the way `put_tree` walks
/// it (symlinks and special files skipped). Unreadable entries are ignored;
/// the upload itself reports them.
fn scan_local_tree(dir: &Path, depth: usize) -> (u64, u64) {
    let (mut files, mut bytes) = (0u64, 0u64);
    let Ok(rd) = fs::read_dir(dir) else {
        return (0, 0);
    };
    for entry in rd.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() && depth < MAX_TREE_DEPTH {
            let (f, b) = scan_local_tree(&entry.path(), depth + 1);
            files += f;
            bytes = bytes.saturating_add(b);
        } else if meta.is_file() {
            files += 1;
            bytes = bytes.saturating_add(meta.len());
        }
    }
    (files, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_times_convert_to_system_time() {
        let t = Time {
            seconds: 1_700_000_000,
            nseconds: 500,
        };
        let st = system_time(t).unwrap();
        let d = st.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!((d.as_secs(), d.subsec_nanos()), (1_700_000_000, 500));
        let before = system_time(Time {
            seconds: -10,
            nseconds: 0,
        })
        .unwrap();
        assert_eq!(UNIX_EPOCH.duration_since(before).unwrap().as_secs(), 10);
    }

    #[test]
    fn resume_notes() {
        assert_eq!(resumed_note(0, 10), "");
        assert_eq!(resumed_note(4, 10), ", resumed at 4");
        assert_eq!(resumed_note(10, 10), ", already complete");
    }
}
