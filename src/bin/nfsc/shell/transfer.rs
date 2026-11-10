//! get, put and sum, and the transfer loops behind them.
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
//! Uploads are atomic the same way on the server: data goes to the remote
//! `NAME.nfsc-part`, which is renamed over `NAME` (NFS RENAME replaces the
//! target atomically) once complete. A failed put never truncates or replaces
//! a good remote file.
//!
//! Resume (`-c`): `get -c` continues `NAME.nfsc-part` (or, for files from
//! older versions, a partial `NAME` in place) from its current size, and
//! `put -c` does the same with the remote `NAME.nfsc-part` (or a partial
//! remote `NAME`). Before either appends, the last [`TAIL_CHECK`] bytes
//! before the resume point are compared between the local and the remote
//! file; a mismatch (one side was replaced or is something else) refuses the
//! resume.
//!
//! Verify (`-V`): the bytes are hashed (SHA-256) as they are transferred,
//! after hashing the prefix that a resume keeps. Once the file is complete,
//! the remote file is read (again) and hashed; the `.nfsc-part` is renamed
//! into place only when both digests agree. This costs a full extra read of
//! the remote file, so it is off by default.
//!
//! Modes: `get` applies the server's mode without setuid/setgid/sticky and,
//! like `cp`, minus the process umask; `get -p` keeps the server's bits.
//! `put` sends the local mode bits as they are (like `scp`).

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

use super::checksum::{Algo, Hasher};
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
pub(super) const MAX_TREE_DEPTH: usize = 256;

/// Suffix of the file a download is written to before it is renamed into place.
pub(super) const PART_SUFFIX: &str = ".nfsc-part";

/// `O_NOFOLLOW`, so a local symbolic link at a download target is refused
/// instead of followed. The value differs by platform.
#[cfg(any(target_os = "linux", target_os = "android"))]
const O_NOFOLLOW: i32 = 0o400_000;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const O_NOFOLLOW: i32 = 0x0100;

/// Bytes before the resume offset that `get -c` compares with the server.
const TAIL_CHECK: u64 = 1 << 20;

/// How far back `get -c` keeps comparing while both sides are all zeros.
const ZERO_SCAN_MAX: u64 = 64 << 20;

/// Read size when hashing a local file.
const LOCAL_CHUNK: usize = 1 << 20;

const GET_USAGE: &str = "usage: get [-rcknpV] remote... [local]";
const PUT_USAGE: &str = "usage: put [-rcknV] local... [remote]";

/// The process umask, read once. On Linux it comes from `/proc/self/status`;
/// elsewhere (or without /proc) from umask(2), which has to set a mask to read
/// one: the stricter 077 is in place for that instant, then the old one is back.
pub(super) fn process_umask() -> u32 {
    static UMASK: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *UMASK.get_or_init(|| proc_umask().unwrap_or_else(syscall_umask) & 0o777)
}

fn proc_umask() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let value = status.lines().find_map(|l| l.strip_prefix("Umask:"))?;
    u32::from_str_radix(value.trim(), 8).ok()
}

fn syscall_umask() -> u32 {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    ))]
    type ModeT = u16;
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly"
    )))]
    type ModeT = u32;
    unsafe extern "C" {
        fn umask(mask: ModeT) -> ModeT;
    }
    // SAFETY: umask(2) takes a plain integer, cannot fail and touches no
    // memory; the previous mask is restored right away.
    let old = unsafe { umask(0o077) };
    // SAFETY: as above.
    unsafe { umask(old) };
    #[allow(clippy::useless_conversion)] // mode_t is u16 on some platforms
    u32::from(old)
}

/// The local mode for a downloaded file or directory whose server mode is
/// `mode`: never setuid/setgid/sticky, and without the bits in `umask`.
fn local_mode(mode: u32, umask: u32) -> u32 {
    mode & 0o777 & !umask
}

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

/// A failure's text without the `nfsc: CMD: ` prefix, for the end summary.
fn failure_text(cmd: &str, f: &CmdFailure) -> String {
    let text = f.to_string();
    let prefix = format!("nfsc: {cmd}: ");
    text.strip_prefix(&prefix).unwrap_or(&text).to_string()
}

/// Ends a `-k` run: lists the failures and fails the command, or succeeds
/// when there were none.
fn fail_summary(cmd: &str, failures: &[String], err: &mut dyn Write) -> CmdResult<()> {
    if failures.is_empty() {
        return Ok(());
    }
    writeln!(err, "nfsc: {cmd}: failed:").map_err(|e| io_fail(cmd, e))?;
    for f in failures {
        writeln!(err, "  {}", display_str(f)).map_err(|e| io_fail(cmd, e))?;
    }
    let n = failures.len();
    Err(CmdFailure::new(
        cmd,
        None,
        format!(
            "{n} {} failed (listed above)",
            if n == 1 { "item" } else { "items" }
        ),
    ))
}

/// Reads `file` from offset 0 up to `len` bytes into `hasher`.
fn hash_local(
    file: &mut File,
    path: &Path,
    len: u64,
    hasher: &mut Hasher,
    flag: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| local_io("read", path, &e))?;
    let mut buf = vec![0u8; LOCAL_CHUNK];
    let mut left = len;
    while left > 0 {
        interrupt::check(flag)?;
        let want = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
        let n = file
            .read(&mut buf[..want])
            .map_err(|e| local_io("read", path, &e))?;
        if n == 0 {
            return Err(Error::Invalid(format!(
                "{} became shorter while it was read",
                display_path(path)
            )));
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    Ok(())
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
        .read(true)
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

/// Sets a downloaded directory's mode (see [`local_mode`]) and mtime from the
/// server, after its contents are written (writing entries would change the
/// mtime again). Best effort; a failure is noted on `err`.
fn restore_dir(dir: &Path, attr: &Attr, umask: u32, err: &mut dyn Write) {
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
    if let Err(e) = handle.set_permissions(fs::Permissions::from_mode(local_mode(attr.mode, umask)))
    {
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
    /// `-V`: hash while writing, then compare with a second read of the server.
    verify: bool,
    /// `-p`: apply the server's mode bits without the local umask.
    preserve: bool,
}

/// Why a download did not complete.
enum Failed {
    /// Reading, writing or interrupt: a partial file may be resumed.
    Transfer(Error),
    /// `-V` found different data on disk than on the server.
    Mismatch(Error),
}

/// What [`Session::scan_remote_tree`] records besides its totals.
pub(super) struct Walk {
    /// Keep the listings in `scan_cache` for the download that follows.
    pub cache: bool,
    /// Per-directory byte totals, children before parents.
    pub dirs: Option<Vec<(String, u64)>>,
}

/// Options of one `put`.
#[derive(Debug, Clone, Copy, Default)]
struct PutOpts {
    /// `-r`: upload directory trees.
    recursive: bool,
    /// `-c`: continue partial remote files.
    resume: bool,
    /// `-n`: skip names that exist on the server.
    no_clobber: bool,
    /// `-k`: report errors and continue; fail at the end.
    keep_going: bool,
    /// `-V`: hash while sending, then compare with a read of the remote file.
    verify: bool,
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
                "--verify" => "-V".to_string(),
                "--no-clobber" => "-n".to_string(),
                "--continue" => "-c".to_string(),
                "--recursive" => "-r".to_string(),
                "--preserve" => "-p".to_string(),
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
        let flags = parse_args(&args, "rcnkpV").map_err(|m| usage(CMD, m))?;
        let opts = GetOpts {
            resume: flags.has('c'),
            no_clobber: flags.has('n'),
            keep_going: flags.has('k'),
            verify: flags.has('V'),
            preserve: flags.has('p'),
        };
        let (remotes, local) = match flags.positional.as_slice() {
            [] => return Err(usage(CMD, GET_USAGE)),
            [r] => (std::slice::from_ref(r), None),
            [rs @ .., l] => (rs, Some(l.as_str())),
        };
        let recursive = flags.has('r');
        let to_stdout = local == Some("-");
        let patterns = remotes.iter().any(|r| super::line::is_pattern(r));
        if to_stdout && (recursive || remotes.len() > 1 || patterns) {
            return Err(usage(CMD, "only one file can be written to stdout"));
        }
        if to_stdout && opts.resume {
            return Err(usage(CMD, "-c needs a local file, not stdout"));
        }
        if to_stdout && opts.verify {
            return Err(usage(CMD, "-V needs a local file, not stdout"));
        }
        let explicit = match local {
            Some("-") | None => None,
            Some(l) => Some(self.local_path(l)),
        };
        // A trailing '/' says the destination is a directory; it must exist,
        // except for `get -r dir new/`, which creates it.
        if let (Some(l), Some(p)) = (local, &explicit)
            && l.ends_with('/')
            && !p.is_dir()
            && !(recursive && remotes.len() == 1 && !patterns)
        {
            return Err(CmdFailure::new(CMD, Some(l), "no such local directory"));
        }
        let mut sources = Vec::new();
        let mut failures = Vec::new();
        for remote in remotes {
            match self.expand(CMD, remote) {
                Ok(found) => sources.extend(found),
                Err(f) if opts.keep_going && !f.is_interrupted() => {
                    writeln!(err, "{f}").map_err(|e| io_fail(CMD, e))?;
                    failures.push(failure_text(CMD, &f));
                }
                Err(f) => return Err(f),
            }
        }
        let several = sources.len() > 1 || remotes.len() > 1 || patterns;
        if several && explicit.as_ref().is_some_and(|p| !p.is_dir()) {
            return Err(CmdFailure::new(
                CMD,
                local,
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
        for src in &sources {
            match self.get_source(&plan, src, out, err, &mut failures) {
                Ok(()) => {}
                Err(f) if opts.keep_going && !f.is_interrupted() && !f.is_pipe_closed() => {
                    writeln!(err, "{f}").map_err(|e| io_fail(CMD, e))?;
                    failures.push(failure_text(CMD, &f));
                }
                Err(f) => return Err(f),
            }
        }
        fail_summary(CMD, &failures, err)
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
            let mut walk = Walk {
                cache: true,
                dirs: None,
            };
            match self.scan_remote_tree(&node.fh, key, &mut Vec::new(), "", &mut walk) {
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
        self.tree_failed_at = None;
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
        // The new top directory's own entry, in its parent.
        sync_parent(&dest);
        self.scan_cache.clear();
        let tree = self.tree.take();
        let summary = tree.map(|t| t.finish("got"));
        self.tree_result(CMD, src, result)?;
        if let Some(line) = summary {
            writeln!(err, "{line}").map_err(|e| io_fail(CMD, e))?;
        }
        Ok(())
    }

    pub(super) fn cmd_put(&mut self, args: &[String], err: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "put";
        let args = long_options(args);
        let flags = parse_args(&args, "rcnkV").map_err(|m| usage(CMD, m))?;
        let opts = PutOpts {
            recursive: flags.has('r'),
            resume: flags.has('c'),
            no_clobber: flags.has('n'),
            keep_going: flags.has('k'),
            verify: flags.has('V'),
        };
        let (locals, remote) = match flags.positional.as_slice() {
            [] => return Err(usage(CMD, PUT_USAGE)),
            [l] => (std::slice::from_ref(l), None),
            [ls @ .., r] => (ls, Some(r.as_str())),
        };
        let patterns = locals.iter().any(|l| super::line::is_pattern(l));
        let mut sources = Vec::new();
        let mut failures = Vec::new();
        for local in locals {
            match self.expand_local(CMD, local) {
                Ok(found) => sources.extend(found),
                Err(f) if opts.keep_going => {
                    writeln!(err, "{f}").map_err(|e| io_fail(CMD, e))?;
                    failures.push(failure_text(CMD, &f));
                }
                Err(f) => return Err(f),
            }
        }
        let several = sources.len() > 1 || locals.len() > 1 || patterns;
        if several
            && let Some(r) = remote
            && !self
                .resolve(r, true)
                .is_ok_and(|s| last_node(&s).attr.ftype == FileType::Directory)
        {
            return Err(CmdFailure::new(
                CMD,
                Some(r),
                "several files need a remote directory as destination",
            ));
        }
        for src in &sources {
            match self.put_source(src, remote, opts, err, &mut failures) {
                Ok(()) => {}
                Err(f) if opts.keep_going && !f.is_interrupted() => {
                    writeln!(err, "{f}").map_err(|e| io_fail(CMD, e))?;
                    failures.push(failure_text(CMD, &f));
                }
                Err(f) => return Err(f),
            }
        }
        fail_summary(CMD, &failures, err)
    }

    /// Expands `*` and `?` in the last component of a local path into the
    /// matching names (sorted), as [`Session::expand`] does for remote paths.
    fn expand_local(&self, cmd: &str, pattern: &str) -> CmdResult<Vec<String>> {
        use super::line::{glob_match, is_pattern};
        if !is_pattern(pattern) {
            return Ok(vec![pattern.to_string()]);
        }
        let (dir, pat) = match pattern.rfind('/') {
            Some(i) => (&pattern[..=i], &pattern[i + 1..]),
            None => ("", pattern),
        };
        if is_pattern(dir) {
            return Err(CmdFailure::new(
                cmd,
                Some(pattern),
                "wildcards are only supported in the last path component",
            ));
        }
        let path = self.local_path(if dir.is_empty() { "." } else { dir });
        let rd =
            fs::read_dir(&path).map_err(|e| CmdFailure::new(cmd, Some(pattern), io_text(&e)))?;
        let mut names: Vec<String> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| glob_match(pat, n))
            .collect();
        if names.is_empty() {
            return Err(CmdFailure::new(cmd, Some(pattern), "no match"));
        }
        names.sort();
        Ok(names.into_iter().map(|n| format!("{dir}{n}")).collect())
    }

    /// One local source of a put: a file or (with -r) a tree.
    fn put_source(
        &mut self,
        local: &str,
        remote: Option<&str>,
        opts: PutOpts,
        err: &mut dyn Write,
        failures: &mut Vec<String>,
    ) -> CmdResult<()> {
        const CMD: &str = "put";
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
            if !opts.recursive {
                return Err(CmdFailure::new(CMD, Some(local), "is a directory (use -r)"));
            }
            let totals = self.progress.then(|| scan_local_tree(&path, 0));
            let tree = TreeProgress::new(totals);
            let mut lines = LineWriter::new(err, tree.multi());
            self.tree = Some(tree);
            self.tree_failed_at = None;
            let result = self.put_tree(&path, &dir, &name, opts, &mut lines, failures, 0);
            drop(lines);
            let tree = self.tree.take();
            let summary = tree.map(|t| t.finish("put"));
            self.tree_result(CMD, local, result)?;
            if let Some(line) = summary {
                writeln!(err, "{line}").map_err(|e| io_fail(CMD, e))?;
            }
            Ok(())
        } else {
            self.put_file(&path, &meta, &dir, &name, opts, err)
                .ctx(CMD, local)
        }
    }

    /// The failure of a recursive transfer of `src`, naming the entry that
    /// stopped it: `nfsc: get: tree: /dl/tree/x.bin: gave up on READ ...`.
    fn tree_result(&mut self, cmd: &str, src: &str, result: Result<()>) -> CmdResult<()> {
        let at = self.tree_failed_at.take();
        match (result, at) {
            (Ok(()), _) => Ok(()),
            (Err(e), Some(at)) if !interrupt::is_interrupt(&e) => Err(CmdFailure::new(
                cmd,
                Some(src),
                format!("{}: {e}", display_path(&at)),
            )),
            (Err(e), _) => Err(CmdFailure::from_error(cmd, src, e)),
        }
    }

    /// `sum [-a ALGO] path...`: prints `HEX  path` for each remote file, like
    /// sha256sum. Errors are reported and the rest are still summed.
    pub(super) fn cmd_sum(
        &mut self,
        args: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> CmdResult<()> {
        const CMD: &str = "sum";
        const USAGE: &str = "usage: sum [-a sha256|sha512] path...";
        let mut algo = Algo::default();
        let mut paths = Vec::new();
        let mut it = args.iter();
        let mut options_done = false;
        while let Some(a) = it.next() {
            let value = if options_done {
                None
            } else if a == "--" {
                options_done = true;
                continue;
            } else if a == "-a" || a == "--algorithm" {
                Some(it.next().ok_or_else(|| usage(CMD, USAGE))?.as_str())
            } else if let Some(v) = a.strip_prefix("--algorithm=") {
                Some(v)
            } else if let Some(v) = a.strip_prefix("-a").filter(|v| !v.is_empty()) {
                Some(v)
            } else if a.starts_with('-') && a != "-" {
                return Err(usage(CMD, format!("invalid option '{a}'")));
            } else {
                None
            };
            match value {
                Some(v) => {
                    algo = Algo::parse(v).ok_or_else(|| {
                        usage(
                            CMD,
                            format!("unknown algorithm '{v}' (use {})", Algo::NAMES),
                        )
                    })?;
                }
                None => paths.push(a.clone()),
            }
        }
        if paths.is_empty() {
            return Err(usage(CMD, USAGE));
        }
        let mut failures = Vec::new();
        for arg in &paths {
            let result = self.expand(CMD, arg).and_then(|found| {
                for path in found {
                    let hex = self.sum_one(&path, algo)?;
                    writeln!(out, "{hex}  {}", display_str(&path)).map_err(|e| io_fail(CMD, e))?;
                }
                Ok(())
            });
            match result {
                Ok(()) => {}
                Err(f) if !f.is_interrupted() && !f.is_pipe_closed() => {
                    writeln!(err, "{f}").map_err(|e| io_fail(CMD, e))?;
                    failures.push(failure_text(CMD, &f));
                }
                Err(f) => return Err(f),
            }
        }
        fail_summary(CMD, &failures, err)
    }

    fn sum_one(&mut self, path: &str, algo: Algo) -> CmdResult<String> {
        const CMD: &str = "sum";
        let stack = self.resolve(path, true).ctx(CMD, path)?;
        let node = last_node(&stack).clone();
        match node.attr.ftype {
            FileType::Regular => {}
            FileType::Directory => {
                return Err(CmdFailure::from_error(CMD, path, Error::Nfs(Status::IsDir)));
            }
            _ => return Err(CmdFailure::new(CMD, Some(path), "not a regular file")),
        }
        self.remote_digest(&display_str(path), &node.fh, node.attr.size, None, algo)
            .ctx(CMD, path)
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
    /// docs), restoring the remote mode (see [`local_mode`]) and modification
    /// time. Only the size the server reported is written; more data is not
    /// stored. `in_tree` is set for files inside a downloaded tree, whose
    /// names come from the server: a local symbolic link at `path` is then
    /// refused, and the directory is synced once by the tree walk instead of
    /// after every file. For a single file, a symbolic link the user points
    /// at is followed, as before.
    #[allow(clippy::too_many_arguments)]
    fn fetch_to_path(
        &mut self,
        label: &str,
        fh: &FileHandle,
        attr: &Attr,
        path: &Path,
        opts: GetOpts,
        in_tree: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        let nofollow = in_tree;
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
        if opts.resume && start > 0 {
            if in_place {
                Self::check_in_place_age(&file, target, attr)?;
            }
            self.check_tail(fh, &mut file, target, start, opts.verify)?;
        }
        let started = Instant::now();
        let received = self.receive_verified(label, fh, &mut file, target, start, size, opts);
        let (delivered, verified) = match received {
            Ok(r) => r,
            Err(Failed::Mismatch(e)) => {
                drop(file);
                // The data on disk is not what the server holds: never keep
                // it for a later -c. A partial file the user had under the
                // final name is left alone.
                if !in_place && fs::remove_file(target).is_ok() {
                    let _ = writeln!(err, "nfsc: get: removed {}", display_path(target));
                }
                return Err(e);
            }
            Err(Failed::Transfer(e)) => {
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
        // download must not create a set-id local file. The umask applies
        // unless -p. The chmod goes through the descriptor, so it cannot land
        // on a symlink target.
        let umask = if opts.preserve { 0 } else { self.umask };
        let _ = file.set_permissions(fs::Permissions::from_mode(local_mode(attr.mode, umask)));
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
            if !in_tree {
                sync_parent(&dest);
            }
        }
        let verified = verified
            .map(|hex| format!(", verified {} {hex}", Algo::Sha256.name()))
            .unwrap_or_default();
        writeln!(
            err,
            "getting file {label} of size {size} as {} ({}{}{verified})",
            display_path(path),
            rate(delivered, started.elapsed()),
            resumed_note(start, size)
        )
        .map_err(local_err)
    }

    /// Refuses a resume when the last bytes before `start` in the local file
    /// differ from the same range on the server: the remote file was replaced
    /// or the local file is another one, and appending would corrupt it.
    ///
    /// Zeros on both sides prove little (VM images and padded archives are
    /// full of them), so while the compared window is all zeros the check
    /// moves further back, up to [`ZERO_SCAN_MAX`] bytes. When that finds no
    /// data, the resume is refused unless `verify` (-V) will compare the
    /// whole file afterwards anyway.
    fn check_tail(
        &mut self,
        fh: &FileHandle,
        file: &mut File,
        target: &Path,
        start: u64,
        verify: bool,
    ) -> Result<()> {
        let mut end = start;
        let mut compared = 0u64;
        while end > 0 {
            let n = end.min(TAIL_CHECK);
            let from = end - n;
            let mut local = vec![0u8; n as usize];
            file.seek(SeekFrom::Start(from))
                .and_then(|_| file.read_exact(&mut local))
                .map_err(|e| local_io("read", target, &e))?;
            let mut remote = Vec::with_capacity(local.len());
            self.download(fh, from, Some(n), &mut |chunk: &[u8]| -> Result<()> {
                remote.extend_from_slice(chunk);
                Ok(())
            })?;
            if remote != local {
                return Err(Error::Invalid(format!(
                    "{} does not match the remote file in the {n} bytes before offset {end}; \
                     not resuming (the remote file may have changed; get without -c downloads it again)",
                    display_path(target)
                )));
            }
            if local.iter().any(|&b| b != 0) {
                return Ok(());
            }
            compared += n;
            end = from;
            if compared >= ZERO_SCAN_MAX && end > 0 && !verify {
                return Err(Error::Invalid(format!(
                    "the {compared} bytes of {} before offset {start} are all zeros, as on the \
                     server, which does not show that it is the same file; not resuming \
                     (get -cV resumes and then checks the whole file; get without -c downloads it again)",
                    display_path(target)
                )));
            }
            if compared >= ZERO_SCAN_MAX {
                break;
            }
        }
        // Everything before `start` compared equal, or -V checks it all later.
        Ok(())
    }

    /// Refuses to continue a final-named local file (not a `.nfsc-part`)
    /// whose mtime is older than the remote file's: it was written before
    /// the remote file last changed, so it is an earlier version (a finished
    /// get sets the remote mtime), not the start of this one.
    fn check_in_place_age(file: &File, target: &Path, attr: &Attr) -> Result<()> {
        let local = file.metadata().and_then(|m| m.modified()).ok();
        let remote = system_time(attr.mtime);
        if let (Some(local), Some(remote)) = (local, remote)
            && local < remote
        {
            return Err(Error::Invalid(format!(
                "{} is older than the remote file, so it is an earlier version rather than a \
                 partial download; not resuming (get without -c downloads it again)",
                display_path(target)
            )));
        }
        Ok(())
    }

    /// Compares the first `len` bytes of the local `file` (at `path`) with
    /// the remote `fh`, reading the remote range once. Returns the first
    /// offset where they differ. Used by `put -c`: a failed pipelined upload
    /// can leave a gap (zeros) well before the end of the remote file, which
    /// a tail check would not see.
    fn prefix_mismatch(
        &mut self,
        label: &str,
        fh: &FileHandle,
        file: &mut File,
        path: &Path,
        len: u64,
    ) -> Result<Option<u64>> {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| local_io("read", path, &e))?;
        let mut meter = Meter::new(self.progress, &format!("{label} (check)"), len, 0, None);
        let mut pos = 0u64;
        let mut differs = None;
        let mut local = Vec::new();
        let result = self.download(fh, 0, Some(len), &mut |chunk: &[u8]| -> Result<()> {
            local.resize(chunk.len(), 0);
            file.read_exact(&mut local)
                .map_err(|e| local_io("read", path, &e))?;
            // Slice equality first: it is a memcmp, the search is not.
            if local.as_slice() != chunk
                && let Some(i) = local.iter().zip(chunk).position(|(a, b)| a != b)
            {
                differs = Some(pos + i as u64);
                // Stop reading; the answer is known.
                return Err(Error::Invalid("differs".into()));
            }
            pos += chunk.len() as u64;
            meter.tick(pos);
            Ok(())
        });
        meter.finish(result.is_ok());
        if differs.is_some() {
            return Ok(differs);
        }
        let n = result?;
        if n < len {
            // The remote file is shorter than it claimed: treat the rest as different.
            return Ok(Some(n));
        }
        Ok(None)
    }

    /// [`Self::receive`], hashing the data when `opts.verify` is set and then
    /// comparing it with a second read of the server. Returns the bytes
    /// received and, after a successful check, the hex digest.
    #[allow(clippy::too_many_arguments)]
    fn receive_verified(
        &mut self,
        label: &str,
        fh: &FileHandle,
        file: &mut File,
        target: &Path,
        start: u64,
        size: u64,
        opts: GetOpts,
    ) -> std::result::Result<(u64, Option<String>), Failed> {
        if !opts.verify {
            let n = self
                .receive(label, fh, file, target, start, size, None)
                .map_err(Failed::Transfer)?;
            return Ok((n, None));
        }
        let mut local = Algo::Sha256.hasher();
        if start > 0 {
            hash_local(file, target, start, &mut local, &self.interrupt)
                .map_err(Failed::Transfer)?;
        }
        let n = self
            .receive(label, fh, file, target, start, size, Some(&mut local))
            .map_err(Failed::Transfer)?;
        let local = local.hex();
        let remote = self
            .remote_digest(
                &format!("{label} (verify)"),
                fh,
                size,
                Some(size),
                Algo::Sha256,
            )
            .map_err(Failed::Transfer)?;
        if remote != local {
            return Err(Failed::Mismatch(Error::Invalid(format!(
                "verification failed: the downloaded data (sha256 {local}) differs from \
                 a second read of the server (sha256 {remote})"
            ))));
        }
        Ok((n, Some(local)))
    }

    /// Hashes the first `len` bytes of a remote file (all of it when `len`
    /// is `None`), with a progress meter sized for `size` bytes. Not booked
    /// into tree totals.
    fn remote_digest(
        &mut self,
        label: &str,
        fh: &FileHandle,
        size: u64,
        len: Option<u64>,
        algo: Algo,
    ) -> Result<String> {
        let mut hasher = algo.hasher();
        let mut meter = Meter::new(self.progress, label, size, 0, None);
        let mut done = 0u64;
        let result = self.download(fh, 0, len, &mut |chunk: &[u8]| -> Result<()> {
            hasher.update(chunk);
            done += chunk.len() as u64;
            meter.tick(done);
            Ok(())
        });
        meter.finish(result.is_ok());
        let n = result?;
        if let Some(len) = len
            && n < len
        {
            return Err(Error::Invalid(format!(
                "read of {label} stopped at {n} of {len} bytes"
            )));
        }
        Ok(hasher.hex())
    }

    /// Fills `file` (opened at `target`) from `start` up to `size` bytes and
    /// syncs it. Returns the bytes received.
    #[allow(clippy::too_many_arguments)]
    fn receive(
        &mut self,
        label: &str,
        fh: &FileHandle,
        file: &mut File,
        target: &Path,
        start: u64,
        size: u64,
        mut hasher: Option<&mut Hasher>,
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
                    if let Some(h) = hasher.as_deref_mut() {
                        h.update(chunk);
                    }
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
    /// With `walk.cache`, listings (with handles and attributes filled in) are
    /// kept in `scan_cache` so the download does not list each directory
    /// twice. With `walk.dirs`, each directory's byte total is recorded under
    /// `path` (children before their parent), for `du`.
    pub(super) fn scan_remote_tree(
        &mut self,
        fh: &FileHandle,
        key: (u64, u64),
        ancestors: &mut Vec<(u64, u64)>,
        path: &str,
        walk: &mut Walk,
    ) -> Result<(u64, u64)> {
        interrupt::check(&self.interrupt)?;
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
                        let child = if walk.dirs.is_some() {
                            format!("{path}/{}", display_name(&entry.name))
                        } else {
                            String::new()
                        };
                        subdirs.push((entry.handle.clone().expect("filled above"), k, child));
                    }
                }
                _ => {}
            }
        }
        if walk.cache {
            self.scan_cache.insert(fh.clone(), entries);
        }
        for (h, k, child) in subdirs {
            let (f, b) = self.scan_remote_tree(&h, k, ancestors, &child, walk)?;
            files += f;
            bytes = bytes.saturating_add(b);
        }
        ancestors.pop();
        if let Some(dirs) = &mut walk.dirs {
            dirs.push((path.to_string(), bytes));
        }
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
        let umask = if opts.preserve { 0 } else { self.umask };
        restore_dir(dir, attr, umask, err);
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
                if interrupt::is_interrupt(&e) {
                    return Err(e);
                }
                if !opts.keep_going {
                    // The innermost directory sees the error first.
                    self.tree_failed_at.get_or_insert(child);
                    return Err(e);
                }
                let what = format!("{}: {}", display_path(&child), display_str(&e.to_string()));
                writeln!(err, "nfsc: get: {what}").map_err(local_err)?;
                failures.push(what);
            }
        }
        // Files were renamed into place without a directory sync each; one
        // sync here makes all of those renames durable.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
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

    /// LOOKUP that maps "no such name" to `None`.
    fn lookup_opt(&mut self, dir: &FileHandle, name: &[u8]) -> Result<Option<(FileHandle, Attr)>> {
        match self.fs.lookup(dir, name) {
            Ok(found) => Ok(Some(found)),
            Err(Error::Nfs(Status::NoEnt)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Uploads one local file as `name` in `dir` through the remote
    /// `NAME.nfsc-part`, which is renamed over `name` once complete (see the
    /// module docs). With `resume`, the remote part (or, when there is none,
    /// a partial remote `name` in place) is continued from its current size
    /// after a tail check. With `no_clobber` an existing remote name is
    /// skipped. The remote file gets the local mode bits; the remote mtime is
    /// the time of the upload.
    fn put_file(
        &mut self,
        local: &Path,
        meta: &Metadata,
        dir: &FileHandle,
        name: &[u8],
        opts: PutOpts,
        err: &mut dyn Write,
    ) -> Result<()> {
        let mut file = File::open(local).map_err(local_err)?;
        let size = meta.len();
        let mode = meta.permissions().mode() & 0o7777;
        let label = display_name(name);
        let existing = self.lookup_opt(dir, name)?;
        if opts.no_clobber && existing.is_some() {
            return writeln!(
                err,
                "nfsc: put: skipping {label}: it exists on the server (-n)"
            )
            .map_err(local_err);
        }
        if let Some((_, attr)) = &existing {
            match attr.ftype {
                FileType::Regular => {}
                FileType::Directory => return Err(Error::Nfs(Status::IsDir)),
                _ => {
                    return Err(Error::Invalid(format!(
                        "{label} exists on the server and is not a regular file"
                    )));
                }
            }
        }
        let mut part_name = name.to_vec();
        part_name.extend_from_slice(PART_SUFFIX.as_bytes());
        let part_label = display_name(&part_name);
        let part = self.lookup_opt(dir, &part_name)?;
        if part
            .as_ref()
            .is_some_and(|(_, a)| a.ftype != FileType::Regular)
        {
            return Err(Error::Invalid(format!(
                "{part_label} exists on the server and is not a regular file"
            )));
        }
        // The owner can write while data goes up, whatever the final mode is.
        let writable = SetAttr {
            mode: Some((mode & 0o777) | 0o600),
            ..SetAttr::default()
        };
        let (fh, in_place, start) = match (opts.resume, part, existing) {
            (true, Some((fh, attr)), _) => (fh, false, attr.size),
            // A partial file from an older nfsc (or another tool).
            (true, None, Some((fh, attr))) => (fh, true, attr.size),
            (_, Some((fh, _)), _) => {
                let truncate = SetAttr {
                    size: Some(0),
                    ..writable.clone()
                };
                self.fs.setattr(&fh, &truncate)?;
                (fh, false, 0)
            }
            (_, None, _) => {
                let (fh, _) = self
                    .fs
                    .create(dir, &part_name, CreateMode::Unchecked, &writable)?;
                (fh, false, 0)
            }
        };
        let target = if in_place { &label } else { &part_label };
        if start > size {
            return Err(Error::Invalid(format!(
                "remote file {target} is larger than the local file ({start} > {size} bytes), not resuming"
            )));
        }
        if start > 0
            && let Some(at) = self.prefix_mismatch(&label, &fh, &mut file, local, start)?
        {
            return Err(Error::Invalid(format!(
                "remote file {target} differs from {} at offset {at} (of the {start} bytes \
                 already on the server); not resuming (a failed upload can leave a gap, or one \
                 of the files changed; put without -c uploads it again)",
                display_path(local)
            )));
        }

        let started = Instant::now();
        let mut sent = start;
        let outcome = self.send_verified(
            &label,
            &fh,
            &mut file,
            local,
            start,
            size,
            opts.verify,
            &mut sent,
        );
        let verified = match outcome {
            Ok(v) => v,
            Err(Failed::Mismatch(e)) => {
                // Never keep data that differs from the local file for a
                // later -c. A partial file under the final name is left alone.
                if !in_place && self.fs.remove(dir, &part_name).is_ok() {
                    let _ = writeln!(err, "nfsc: put: removed {part_label} from the server");
                }
                return Err(e);
            }
            Err(Failed::Transfer(e)) => {
                if opts.resume {
                    let _ = writeln!(
                        err,
                        "nfsc: put: partial remote file {target} kept (up to {sent} of {size} \
                         bytes sent); put -c checks it and continues"
                    );
                } else if matches!(e, Error::GaveUp { .. }) {
                    // The server is not answering; removing would only wait again.
                    let _ = writeln!(
                        err,
                        "nfsc: put: partial remote file {part_label} left on the server \
                         (up to {sent} of {size} bytes sent); put -c checks it and continues"
                    );
                } else if self.fs.remove(dir, &part_name).is_ok() {
                    let _ = writeln!(err, "nfsc: put: removed partial remote file {part_label}");
                }
                return Err(e);
            }
        };
        // Best effort, as for get: the data is complete either way.
        let final_mode = SetAttr {
            mode: Some(mode),
            ..SetAttr::default()
        };
        if let Err(e) = self.fs.setattr(&fh, &final_mode) {
            let _ = writeln!(err, "nfsc: put: cannot set the mode of {target}: {e}");
        }
        if !in_place && let Err(e) = self.fs.rename(dir, &part_name, dir, name) {
            if !opts.resume {
                let _ = self.fs.remove(dir, &part_name);
            }
            return Err(Error::Invalid(format!(
                "cannot rename {part_label} to {label} on the server: {e}"
            )));
        }
        let verified = verified
            .map(|hex| format!(", verified {} {hex}", Algo::Sha256.name()))
            .unwrap_or_default();
        writeln!(
            err,
            "putting file {} as {label} ({}{}{verified})",
            display_path(local),
            rate(sent - start, started.elapsed()),
            resumed_note(start, size)
        )
        .map_err(local_err)
    }

    /// [`Self::send`], hashing the data when `verify` is set (after the local
    /// prefix a resume keeps) and then comparing it with a read of the remote
    /// file. Returns the hex digest after a successful check.
    #[allow(clippy::too_many_arguments)]
    fn send_verified(
        &mut self,
        label: &str,
        fh: &FileHandle,
        file: &mut File,
        local: &Path,
        start: u64,
        size: u64,
        verify: bool,
        sent: &mut u64,
    ) -> std::result::Result<Option<String>, Failed> {
        let mut hasher = verify.then(|| Algo::Sha256.hasher());
        if let Some(h) = hasher.as_mut()
            && start > 0
        {
            hash_local(file, local, start, h, &self.interrupt).map_err(Failed::Transfer)?;
        }
        self.send(label, fh, file, start, size, hasher.as_mut(), sent)
            .map_err(Failed::Transfer)?;
        let Some(hasher) = hasher else {
            return Ok(None);
        };
        let ours = hasher.hex();
        let remote = self
            .remote_digest(&format!("{label} (verify)"), fh, size, None, Algo::Sha256)
            .map_err(Failed::Transfer)?;
        if remote != ours {
            return Err(Failed::Mismatch(Error::Invalid(format!(
                "verification failed: the remote file (sha256 {remote}) differs from \
                 the uploaded data (sha256 {ours})"
            ))));
        }
        Ok(Some(ours))
    }

    /// Writes `file` from `start` to the remote `fh` until the local file
    /// ends, with a progress meter sized for `size`. `sent` ends at the
    /// offset reached, also on failure.
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        label: &str,
        fh: &FileHandle,
        file: &mut File,
        start: u64,
        size: u64,
        mut hasher: Option<&mut Hasher>,
        sent: &mut u64,
    ) -> Result<()> {
        *sent = start;
        let mut tree = self.tree.take();
        let mut meter = Meter::new(self.progress, label, size, start, tree.as_mut());
        let result = if start >= size {
            Ok(())
        } else if let Err(e) = file.seek(SeekFrom::Start(start)) {
            Err(local_err(e))
        } else {
            let flag = Arc::clone(&self.interrupt);
            let mut done = start;
            let result = self
                .fs
                .write_stream(fh, start, &mut |buf: &mut [u8]| -> Result<usize> {
                    interrupt::check(&flag)?;
                    let n = file.read(buf).map_err(local_err)?;
                    if let Some(h) = hasher.as_deref_mut() {
                        h.update(&buf[..n]);
                    }
                    done += n as u64;
                    meter.tick(done);
                    Ok(n)
                });
            *sent = done;
            result.map(|_| ())
        };
        meter.finish(result.is_ok());
        self.tree = tree;
        result
    }

    /// Uploads a local directory tree. Symlinks and special files are skipped,
    /// as are directories deeper than [`MAX_TREE_DEPTH`]. With `keep_going`, a
    /// failed entry is reported, added to `failures`, and the walk continues.
    #[allow(clippy::too_many_arguments)]
    fn put_tree(
        &mut self,
        local: &Path,
        dir: &FileHandle,
        name: &[u8],
        opts: PutOpts,
        err: &mut dyn Write,
        failures: &mut Vec<String>,
        depth: usize,
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
            let result = match entry.metadata().map_err(local_err) {
                Err(e) => Err(e),
                Ok(meta) if meta.is_dir() => {
                    if depth + 1 >= MAX_TREE_DEPTH {
                        writeln!(
                            err,
                            "nfsc: put: skipping {}: directory tree is too deep",
                            display_path(&path)
                        )
                        .map_err(local_err)
                    } else {
                        self.put_tree(
                            &path,
                            &dir_fh,
                            child.as_bytes(),
                            opts,
                            err,
                            failures,
                            depth + 1,
                        )
                    }
                }
                Ok(meta) if meta.is_file() => {
                    self.put_file(&path, &meta, &dir_fh, child.as_bytes(), opts, err)
                }
                Ok(_) => writeln!(
                    err,
                    "nfsc: put: skipping {} (not a regular file or directory)",
                    display_path(&path)
                )
                .map_err(local_err),
            };
            if let Err(e) = result {
                if interrupt::is_interrupt(&e) {
                    return Err(e);
                }
                if !opts.keep_going {
                    self.tree_failed_at.get_or_insert(path);
                    return Err(e);
                }
                let what = format!("{}: {}", display_path(&path), display_str(&e.to_string()));
                writeln!(err, "nfsc: put: {what}").map_err(local_err)?;
                failures.push(what);
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
