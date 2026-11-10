//! get and put, and the transfer loops behind them.
//!
//! Downloads and uploads go through the backend's `read_stream` and
//! `write_stream`, so backends that pipeline keep several transfers in flight.
//! Every chunk passes a closure that checks the Ctrl-C flag and feeds the
//! progress meter. An interrupt ends the transfer with an error that the
//! session reports as "interrupted".
//!
//! Downloads are atomic: data goes to `NAME.nfsc-part` next to the target,
//! which is synced and renamed over `NAME` only once complete. A failed get
//! therefore never leaves a truncated file under the final name, nor damages
//! a good file that was already there.
//!
//! Resume (`-c`): `get -c` continues `NAME.nfsc-part` (or, for files from
//! older versions, a partial `NAME` in place) from its current size, and
//! `put -c` continues a remote file from its current size. Only sizes are
//! compared; contents are not checked.

use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nfsc::fs::{
    Attr, CreateMode, DirEntry, FileHandle, FileType, Filesystem, SetAttr, Status, Time,
};
use nfsc::{Error, Result};

use super::format;
use super::interrupt;
use super::line::parse_args;
use super::progress::{LineWriter, Meter, TreeProgress};
use super::session::{
    CmdFailure, CmdResult, Ctx, Session, io_fail, io_text, is_plain_name, last_node, split_last,
    usage,
};
use crate::text::{display_name, display_path, display_str};

/// Directory levels a recursive get descends. Deeper subtrees are skipped with a
/// note, so a server cannot make the recursion (or local paths) unbounded.
const MAX_TREE_DEPTH: usize = 256;

/// Suffix of the file a download is written to before it is renamed into place.
pub(super) const PART_SUFFIX: &str = ".nfsc-part";

/// `O_NOFOLLOW`, so a local symbolic link at a download target is refused
/// instead of followed. The value differs by platform.
#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const O_NOFOLLOW: i32 = 0x0100;

const GET_USAGE: &str = "usage: get [-rckn] remote [local]";

fn local_err(e: std::io::Error) -> Error {
    Error::Invalid(io_text(&e))
}

/// A local I/O error on `path`, in plain words for the cases a user can act
/// on (disk full, quota, permissions) rather than raw OS text.
fn local_io(action: &str, path: &Path, e: &std::io::Error) -> Error {
    let why = match e.kind() {
        ErrorKind::StorageFull => "the local disk is full (no space left on device)".to_string(),
        ErrorKind::QuotaExceeded => "the local disk quota is exceeded".to_string(),
        ErrorKind::PermissionDenied => {
            "permission denied by the local file system (check the directory's owner and mode)"
                .to_string()
        }
        ErrorKind::ReadOnlyFilesystem => "the local file system is read-only".to_string(),
        _ => io_text(e),
    };
    Error::Invalid(format!("cannot {action} {}: {why}", display_path(path)))
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

/// `NAME.nfsc-part` next to `path`.
fn part_path(path: &Path) -> Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Invalid(format!("{} does not name a file", display_path(path))))?;
    let mut part = name.to_os_string();
    part.push(PART_SUFFIX);
    Ok(path.with_file_name(part))
}

/// Opens a local download target, never through a symbolic link. Without
/// `resume` the file is truncated. With `resume` an existing file is kept and
/// its size returned, and a missing file is created with size 0. The size
/// comes from the open descriptor, so it cannot change under us.
fn open_local(path: &Path, resume: bool) -> Result<(File, u64)> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(!resume)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
                Error::Invalid(format!(
                    "{} is a symbolic link; not writing through it",
                    display_path(path)
                ))
            } else {
                local_io("create", path, &e)
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

/// Syncs the directory holding `path`, so a rename into it survives a crash.
/// Best effort.
fn sync_parent(path: &Path) {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// Makes sure we can write into `dir` (a directory left read-only by an
/// earlier `get -r` that restored a server mode such as 0555). The server
/// mode is put back once the directory's contents are written.
fn ensure_writable(dir: &Path) {
    if let Ok(m) = fs::symlink_metadata(dir)
        && m.is_dir()
    {
        let mode = m.permissions().mode();
        if mode & 0o700 != 0o700 {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode((mode | 0o700) & 0o7777));
        }
    }
}

/// Sets a downloaded directory's mode (without setuid/setgid/sticky) and
/// mtime from the server, after its contents are written (writing entries
/// would change the mtime again). Best effort; a failure is noted on `err`.
fn restore_dir(dir: &Path, attr: &Attr, err: &mut dyn Write) {
    let note = |err: &mut dyn Write, e: &std::io::Error| {
        let _ = writeln!(
            err,
            "nfsc: get: cannot set the mode or time of {}: {}",
            display_path(dir),
            io_text(e)
        );
    };
    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(dir);
    let handle = match handle {
        Ok(h) => h,
        Err(e) => return note(err, &e),
    };
    if let Some(t) = system_time(attr.mtime)
        && let Err(e) = handle.set_modified(t)
    {
        note(err, &e);
    }
    if let Err(e) = handle.set_permissions(fs::Permissions::from_mode(attr.mode & 0o777)) {
        note(err, &e);
    }
}

/// Options of one `get`.
#[derive(Debug, Clone, Copy, Default)]
struct GetOpts {
    /// `-c`: continue partial files.
    resume: bool,
    /// `-n`: skip files that exist locally.
    no_clobber: bool,
    /// `-k`: report errors and continue; fail at the end.
    keep_going: bool,
}

/// What one `get` was asked to do, shared by its sources.
struct GetPlan {
    explicit: Option<PathBuf>,
    several: bool,
    to_stdout: bool,
    recursive: bool,
    opts: GetOpts,
}

/// Rewrites the long options get accepts into their letters.
fn long_options(args: &[String]) -> Vec<String> {
    let mut done = false;
    args.iter()
        .map(|a| {
            if done {
                return a.clone();
            }
            match a.as_str() {
                "--" => {
                    done = true;
                    a.clone()
                }
                "--keep-going" => "-k".to_string(),
                "--no-clobber" => "-n".to_string(),
                "--continue" => "-c".to_string(),
                "--recursive" => "-r".to_string(),
                _ => a.clone(),
            }
        })
        .collect()
}

impl Session {
    pub(super) fn cmd_get(
        &mut self,
        args: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> CmdResult<()> {
        const CMD: &str = "get";
        let args = long_options(args);
        let flags = parse_args(&args, "rcnk").map_err(|m| usage(CMD, m))?;
        let opts = GetOpts {
            resume: flags.has('c'),
            no_clobber: flags.has('n'),
            keep_going: flags.has('k'),
        };
        let (remote, local) = match flags.positional.as_slice() {
            [r] => (r.as_str(), None),
            [r, l] => (r.as_str(), Some(l.as_str())),
            _ => return Err(usage(CMD, GET_USAGE)),
        };
        let recursive = flags.has('r');
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
        if to_stdout && opts.resume {
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
        let plan = GetPlan {
            explicit,
            several,
            to_stdout,
            recursive,
            opts,
        };
        let mut failures = Vec::new();
        for src in &sources {
            match self.get_source(&plan, src, out, err, &mut failures) {
                Ok(()) => {}
                Err(f) if opts.keep_going && !f.is_interrupted() && !f.is_pipe_closed() => {
                    writeln!(err, "{f}").map_err(|e| io_fail(CMD, e))?;
                    let text = f.to_string();
                    let text = text.strip_prefix("nfsc: get: ").unwrap_or(&text);
                    failures.push(text.to_string());
                }
                Err(f) => return Err(f),
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        writeln!(err, "nfsc: get: failed:").map_err(|e| io_fail(CMD, e))?;
        for f in &failures {
            writeln!(err, "  {}", display_str(f)).map_err(|e| io_fail(CMD, e))?;
        }
        let n = failures.len();
        Err(CmdFailure::new(
            CMD,
            None,
            format!(
                "{n} {} failed (listed above)",
                if n == 1 { "item" } else { "items" }
            ),
        ))
    }

    /// One source of a get: a file, a tree, or a file to stdout. With
    /// `keep_going`, errors inside a tree are added to `failures` and the
    /// tree continues.
    fn get_source(
        &mut self,
        plan: &GetPlan,
        src: &str,
        out: &mut dyn Write,
        err: &mut dyn Write,
        failures: &mut Vec<String>,
    ) -> CmdResult<()> {
        const CMD: &str = "get";
        let opts = plan.opts;
        let stack = self.resolve(src, true).ctx(CMD, src)?;
        let node = last_node(&stack).clone();
        let (_, base) = split_last(src);
        if node.attr.ftype == FileType::Directory && !plan.recursive {
            if plan.several {
                writeln!(
                    err,
                    "nfsc: get: skipping directory {} (use -r)",
                    display_str(src)
                )
                .map_err(|e| io_fail(CMD, e))?;
                return Ok(());
            }
            return Err(CmdFailure::new(CMD, Some(src), "is a directory (use -r)"));
        }
        if plan.to_stdout {
            let start = Instant::now();
            let n = self.stream_to(CMD, src, &node.fh, out)?;
            writeln!(
                err,
                "getting file {} of size {n} as - ({})",
                display_str(src),
                rate(n, start.elapsed())
            )
            .map_err(|e| io_fail(CMD, e))?;
            return Ok(());
        }
        // The local name is the last component of the remote path. "." and
        // ".." would name the destination itself or its parent.
        if !is_plain_name(base.as_bytes()) {
            return Err(usage(
                CMD,
                format!("cannot name a local file for '{}'", display_str(src)),
            ));
        }
        let dest = match &plan.explicit {
            None => self.local_cwd().join(base),
            Some(p) if p.is_dir() => p.join(base),
            Some(p) => p.clone(),
        };
        let label = display_str(base);
        if node.attr.ftype != FileType::Directory {
            return self
                .fetch_to_path(&label, &node.fh, &node.attr, &dest, opts, false, err)
                .ctx(CMD, src);
        }
        let key = (node.attr.fsid, node.attr.fileid);
        let totals = if self.progress {
            match self.scan_remote_tree(&node.fh, key, &mut Vec::new()) {
                Ok(t) => Some(t),
                // The download reports the problem where it occurs.
                Err(e) if opts.keep_going && !interrupt::is_interrupt(&e) => {
                    self.scan_cache.clear();
                    None
                }
                Err(e) => return Err(CmdFailure::from_error(CMD, src, e)),
            }
        } else {
            None
        };
        let tree = TreeProgress::new(totals);
        let mut lines = LineWriter::new(err, tree.multi());
        self.tree = Some(tree);
        let result = self.get_tree(
            &node.fh,
            &node.attr,
            &dest,
            opts,
            &mut lines,
            &mut Vec::new(),
            failures,
        );
        drop(lines);
        self.scan_cache.clear();
        let tree = self.tree.take();
        let summary = tree.map(|t| t.finish("got"));
        result.ctx(CMD, src)?;
        if let Some(line) = summary {
            writeln!(err, "{line}").map_err(|e| io_fail(CMD, e))?;
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

    /// Writes the file `fh` to `out` (stdout for `cat` and `get x -`).
    /// Returns the bytes written. When the reader of `out` goes away
    /// (`| head`), the command ends with a quiet pipe-closed failure.
    pub(super) fn stream_to(
        &mut self,
        cmd: &str,
        path: &str,
        fh: &FileHandle,
        out: &mut dyn Write,
    ) -> CmdResult<u64> {
        let mut closed = false;
        let result = self.download(fh, 0, None, &mut |chunk: &[u8]| -> Result<()> {
            out.write_all(chunk).map_err(|e| {
                closed |= e.kind() == ErrorKind::BrokenPipe;
                local_err(e)
            })
        });
        let flushed = if result.is_ok() { out.flush() } else { Ok(()) };
        if closed
            || flushed
                .as_ref()
                .is_err_and(|e| e.kind() == ErrorKind::BrokenPipe)
        {
            return Err(CmdFailure::pipe_closed(cmd));
        }
        let n = result.ctx(cmd, path)?;
        flushed.map_err(|e| io_fail(cmd, e))?;
        Ok(n)
    }

    /// Downloads one file to `path` through `path.nfsc-part` (see the module
    /// docs), restoring the remote mode and modification time. Only the size
    /// the server reported is written; more data is not stored. `nofollow` is
    /// set for files inside a downloaded tree, whose names come from the
    /// server: a local symbolic link at `path` is then refused. For a single
    /// file, a symbolic link the user points at is followed, as before.
    #[allow(clippy::too_many_arguments)]
    fn fetch_to_path(
        &mut self,
        label: &str,
        fh: &FileHandle,
        attr: &Attr,
        path: &Path,
        opts: GetOpts,
        nofollow: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        let existing = fs::symlink_metadata(path).ok();
        if opts.no_clobber && existing.is_some() {
            return writeln!(
                err,
                "nfsc: get: skipping {}: it exists (-n)",
                display_path(path)
            )
            .map_err(local_err);
        }
        let dest = match &existing {
            Some(m) if m.file_type().is_symlink() => {
                if nofollow {
                    return Err(Error::Invalid(format!(
                        "{} is a symbolic link; not writing through it",
                        display_path(path)
                    )));
                }
                fs::canonicalize(path)
                    .map_err(|e| local_io("follow the symbolic link", path, &e))?
            }
            _ => path.to_path_buf(),
        };
        let dest_meta = fs::symlink_metadata(&dest).ok();
        if dest_meta.as_ref().is_some_and(|m| !m.is_file()) {
            return Err(Error::Invalid(format!(
                "{} is not a regular file",
                display_path(&dest)
            )));
        }
        let part = part_path(&dest)?;
        // `get -c` on a partial file from before .nfsc-part existed (or one
        // made by another tool) continues it under its own name.
        let in_place = opts.resume && dest_meta.is_some() && fs::symlink_metadata(&part).is_err();
        let target: &Path = if in_place { &dest } else { &part };
        let (mut file, start) = open_local(target, opts.resume)?;
        let size = attr.size;
        if start > size {
            return Err(Error::Invalid(format!(
                "local file {} is larger than the remote file ({start} > {size} bytes), not resuming",
                display_path(target)
            )));
        }
        let started = Instant::now();
        let delivered = match self.receive(label, fh, &mut file, target, start, size) {
            Ok(n) => n,
            Err(e) => {
                drop(file);
                if opts.resume {
                    let _ = writeln!(
                        err,
                        "nfsc: get: partial file kept as {}; get -c continues it",
                        display_path(target)
                    );
                } else if fs::remove_file(target).is_ok() {
                    let _ = writeln!(
                        err,
                        "nfsc: get: removed partial file {}",
                        display_path(target)
                    );
                }
                return Err(e);
            }
        };
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
                display_path(&dest),
                io_text(&e)
            );
        }
        drop(file);
        if !in_place {
            if let Err(e) = fs::rename(&part, &dest) {
                if !opts.resume {
                    let _ = fs::remove_file(&part);
                }
                return Err(local_io(
                    &format!("rename {} to", display_path(&part)),
                    &dest,
                    &e,
                ));
            }
            sync_parent(&dest);
        }
        writeln!(
            err,
            "getting file {label} of size {size} as {} ({}{})",
            display_path(path),
            rate(delivered, started.elapsed()),
            resumed_note(start, size)
        )
        .map_err(local_err)
    }

    /// Fills `file` (opened at `target`) from `start` up to `size` bytes and
    /// syncs it. Returns the bytes received.
    fn receive(
        &mut self,
        label: &str,
        fh: &FileHandle,
        file: &mut File,
        target: &Path,
        start: u64,
        size: u64,
    ) -> Result<u64> {
        let mut tree = self.tree.take();
        let mut meter = Meter::new(self.progress, label, size, start, tree.as_mut());
        let mut done = start;
        let result = if start >= size {
            Ok(0)
        } else if let Err(e) = file.seek(SeekFrom::Start(start)) {
            Err(local_io("write", target, &e))
        } else {
            self.download(
                fh,
                start,
                Some(size - start),
                &mut |chunk: &[u8]| -> Result<()> {
                    file.write_all(chunk)
                        .map_err(|e| local_io("write", target, &e))?;
                    done += chunk.len() as u64;
                    meter.tick(done);
                    Ok(())
                },
            )
        };
        let complete = matches!(result, Ok(n) if start + n >= size);
        meter.finish(complete);
        self.tree = tree;
        let n = result?;
        if start + n < size {
            return Err(Error::Invalid(format!(
                "transfer of {label} stopped at {} of {size} bytes",
                start + n
            )));
        }
        file.sync_all().map_err(|e| local_io("write", target, &e))?;
        Ok(n)
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
    /// Once the entries are written, the directory gets the remote mode and
    /// mtime. With `keep_going`, a failed entry is reported, added to
    /// `failures`, and the walk continues; Ctrl-C still stops it.
    #[allow(clippy::too_many_arguments)]
    fn get_tree(
        &mut self,
        fh: &FileHandle,
        attr: &Attr,
        dir: &Path,
        opts: GetOpts,
        err: &mut dyn Write,
        ancestors: &mut Vec<(u64, u64)>,
        failures: &mut Vec<String>,
    ) -> Result<()> {
        ancestors.push((attr.fsid, attr.fileid));
        let result = self.get_tree_entries(fh, dir, opts, err, ancestors, failures);
        ancestors.pop();
        result?;
        restore_dir(dir, attr, err);
        Ok(())
    }

    fn get_tree_entries(
        &mut self,
        fh: &FileHandle,
        dir: &Path,
        opts: GetOpts,
        err: &mut dyn Write,
        ancestors: &mut Vec<(u64, u64)>,
        failures: &mut Vec<String>,
    ) -> Result<()> {
        fs::create_dir_all(dir).map_err(|e| local_io("create directory", dir, &e))?;
        ensure_writable(dir);
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
            let result =
                self.get_tree_entry(fh, entry, &label, &child, opts, err, ancestors, failures);
            if let Err(e) = result {
                if !opts.keep_going || interrupt::is_interrupt(&e) {
                    return Err(e);
                }
                let what = format!("{}: {}", display_path(&child), display_str(&e.to_string()));
                writeln!(err, "nfsc: get: {what}").map_err(local_err)?;
                failures.push(what);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn get_tree_entry(
        &mut self,
        dir_fh: &FileHandle,
        entry: DirEntry,
        label: &str,
        child: &Path,
        opts: GetOpts,
        err: &mut dyn Write,
        ancestors: &mut Vec<(u64, u64)>,
        failures: &mut Vec<String>,
    ) -> Result<()> {
        let (cfh, attr) = match (entry.handle, entry.attr) {
            (Some(h), Some(a)) => (h, a),
            _ => self.fs.lookup(dir_fh, &entry.name)?,
        };
        match attr.ftype {
            FileType::Directory => {
                let key = (attr.fsid, attr.fileid);
                if key.1 != 0 && ancestors.contains(&key) {
                    writeln!(err, "nfsc: get: skipping directory loop {label}").map_err(local_err)
                } else if ancestors.len() >= MAX_TREE_DEPTH {
                    writeln!(
                        err,
                        "nfsc: get: skipping {label}: directory tree is too deep"
                    )
                    .map_err(local_err)
                } else if fs::symlink_metadata(child).is_ok_and(|m| m.file_type().is_symlink()) {
                    writeln!(
                        err,
                        "nfsc: get: skipping {label}: a symbolic link is in the way"
                    )
                    .map_err(local_err)
                } else {
                    self.get_tree(&cfh, &attr, child, opts, err, ancestors, failures)
                }
            }
            FileType::Regular => self.fetch_to_path(label, &cfh, &attr, child, opts, true, err),
            FileType::Symlink => {
                writeln!(err, "nfsc: get: skipping symbolic link {label}").map_err(local_err)
            }
            _ => writeln!(err, "nfsc: get: skipping special file {label}").map_err(local_err),
        }
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
    fn local_errors_are_explained() {
        let p = Path::new("/backup/disk.img.nfsc-part");
        let full = local_io("write", p, &std::io::ErrorKind::StorageFull.into()).to_string();
        assert!(
            full.contains("cannot write /backup/disk.img.nfsc-part: the local disk is full"),
            "{full}"
        );
        let denied =
            local_io("create", p, &std::io::ErrorKind::PermissionDenied.into()).to_string();
        assert!(
            denied.contains("permission denied by the local file system"),
            "{denied}"
        );
        // ENOSPC as the OS reports it.
        let os = local_io("write", p, &std::io::Error::from_raw_os_error(28)).to_string();
        assert!(os.contains("the local disk is full"), "{os}");
    }

    #[test]
    fn part_files_sit_next_to_the_target() {
        assert_eq!(
            part_path(Path::new("/d/x.img")).unwrap(),
            Path::new("/d/x.img.nfsc-part")
        );
    }

    #[test]
    fn long_options_map_to_letters() {
        let args: Vec<String> = ["--keep-going", "x", "--", "--no-clobber"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(long_options(&args), ["-k", "x", "--", "--no-clobber"]);
    }

    #[test]
    fn resume_notes() {
        assert_eq!(resumed_note(0, 10), "");
        assert_eq!(resumed_note(4, 10), ", resumed at 4");
        assert_eq!(resumed_note(10, 10), ", already complete");
    }
}
