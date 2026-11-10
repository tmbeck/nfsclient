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
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nfsc::fs::{Attr, CreateMode, FileHandle, FileType, Filesystem, SetAttr, Status, Time};
use nfsc::{Error, Result};

use super::format;
use super::interrupt;
use super::line::parse_args;
use super::session::{CmdFailure, CmdResult, Ctx, Session, io_text, last_node, split_last, usage};
use crate::text::display_name;

/// Transfers smaller than this get no progress line.
const PROGRESS_MIN: u64 = 1 << 20;

/// Minimum time between progress redraws.
const REDRAW: Duration = Duration::from_millis(200);

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

/// Blends a new rate sample into the running estimate.
fn smooth(prev: Option<f64>, sample: f64) -> f64 {
    match prev {
        Some(p) => 0.75 * p + 0.25 * sample,
        None => sample,
    }
}

/// Completed percentage, computed in 128 bits so large files cannot overflow.
fn percent(done: u64, total: u64) -> u64 {
    if total == 0 {
        100
    } else {
        ((u128::from(done) * 100) / u128::from(total)).min(100) as u64
    }
}

/// `mm:ss`, or `h:mm:ss` from an hour up.
fn format_eta(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
    } else {
        format!("{:02}:{:02}", secs / 60, secs % 60)
    }
}

/// The progress line: name, percent, bytes, rate and ETA. `rate` is bytes per second.
fn progress_line(label: &str, done: u64, total: u64, rate: f64) -> String {
    let name: String = label.chars().take(24).collect();
    let eta = if done >= total {
        "00:00".to_string()
    } else if rate >= 1.0 {
        format_eta(((total - done) as f64 / rate) as u64)
    } else {
        "--:--".to_string()
    };
    format!(
        "{name:<24} {:>3}% {} / {}  {}/s  ETA {eta}",
        percent(done, total),
        format::human(done),
        format::human(total),
        format::human(rate as u64),
    )
}

/// One progress line on stderr, redrawn at most every 200 ms. Used only when
/// stderr is a terminal and the transfer is large enough to be worth showing.
struct Meter {
    enabled: bool,
    label: String,
    total: u64,
    last_bytes: u64,
    last_at: Instant,
    rate: Option<f64>,
    drawn: bool,
}

impl Meter {
    /// `total` is the full size of the file; `start` is the offset already present.
    fn new(enabled: bool, label: &str, total: u64, start: u64) -> Self {
        Meter {
            enabled: enabled && total >= PROGRESS_MIN,
            label: label.to_string(),
            total,
            last_bytes: start,
            last_at: Instant::now(),
            rate: None,
            drawn: false,
        }
    }

    /// `done` is the absolute offset reached so far.
    fn tick(&mut self, err: &mut dyn Write, done: u64) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_at);
        if elapsed < REDRAW {
            return;
        }
        let sample = done.saturating_sub(self.last_bytes) as f64 / elapsed.as_secs_f64();
        self.rate = Some(smooth(self.rate, sample));
        self.last_at = now;
        self.last_bytes = done;
        self.drawn = true;
        let line = progress_line(&self.label, done, self.total, self.rate.unwrap_or(0.0));
        let _ = write!(err, "\r{line}\x1b[K");
        let _ = err.flush();
    }

    fn finish(&mut self, err: &mut dyn Write) {
        if self.drawn {
            let _ = write!(err, "\r\x1b[K");
            let _ = err.flush();
            self.drawn = false;
        }
    }
}

/// Opens a local file for resuming: an existing file is kept and its size
/// returned; a missing file is created with size 0.
fn open_partial(path: &Path) -> Result<(File, u64)> {
    match fs::metadata(path) {
        Ok(m) if m.is_file() => {
            let file = fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(local_err)?;
            Ok((file, m.len()))
        }
        Ok(_) => Err(Error::Invalid(format!(
            "{} is not a regular file",
            path.display()
        ))),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            Ok((File::create(path).map_err(local_err)?, 0))
        }
        Err(e) => Err(local_err(e)),
    }
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
                    writeln!(err, "nfsc: get: skipping directory {src} (use -r)")
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
                    "getting file {src} of size {n} as - ({})",
                    rate(n, start.elapsed())
                )
                .map_err(|e| CmdFailure::new(CMD, None, e.to_string()))?;
                continue;
            }
            if base.is_empty() {
                return Err(usage(CMD, format!("cannot name a local file for '{src}'")));
            }
            let dest = match &explicit {
                None => self.local_cwd().join(base),
                Some(p) if p.is_dir() => p.join(base),
                Some(p) => p.clone(),
            };
            if node.attr.ftype == FileType::Directory {
                self.get_tree(&node.fh, &dest, resume, err).ctx(CMD, src)?;
            } else {
                self.fetch_to_path(base, &node.fh, &node.attr, &dest, resume, err)
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
            self.put_tree(&path, &dir, &name, resume, err)
                .ctx(CMD, local)
        } else {
            self.put_file(&path, &meta, &dir, &name, resume, err)
                .ctx(CMD, local)
        }
    }

    /// Streams `fh` from `start` to EOF, checking for Ctrl-C before each chunk.
    /// Returns the number of bytes delivered.
    pub(super) fn download(
        &mut self,
        fh: &FileHandle,
        start: u64,
        sink: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<u64> {
        let flag = Arc::clone(&self.interrupt);
        let mut checked = |chunk: &[u8]| -> Result<()> {
            interrupt::check(&flag)?;
            sink(chunk)
        };
        self.fs.read_stream(fh, start, None, &mut checked)
    }

    /// Writes the file `fh` from `start` to `out`. Returns the bytes written.
    pub(super) fn stream_to(
        &mut self,
        fh: &FileHandle,
        start: u64,
        out: &mut dyn Write,
    ) -> Result<u64> {
        self.download(fh, start, &mut |chunk: &[u8]| -> Result<()> {
            out.write_all(chunk).map_err(local_err)
        })
    }

    /// Downloads one file to `path`, overwriting it unless `resume` is set.
    /// Restores the remote mode and modification time on success.
    fn fetch_to_path(
        &mut self,
        label: &str,
        fh: &FileHandle,
        attr: &Attr,
        path: &Path,
        resume: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        let (mut file, start) = if resume {
            open_partial(path)?
        } else {
            (File::create(path).map_err(local_err)?, 0)
        };
        let size = attr.size;
        if start > size {
            return Err(Error::Invalid(format!(
                "local file is larger than the remote file ({start} > {size} bytes), not resuming"
            )));
        }
        let started = Instant::now();
        let mut meter = Meter::new(self.progress, label, size, start);
        let mut done = start;
        let result = if start < size {
            file.seek(SeekFrom::Start(start)).map_err(local_err)?;
            self.download(fh, start, &mut |chunk: &[u8]| -> Result<()> {
                file.write_all(chunk).map_err(local_err)?;
                done += chunk.len() as u64;
                meter.tick(err, done);
                Ok(())
            })
        } else {
            Ok(0)
        };
        meter.finish(err);
        let delivered = match result {
            Ok(n) => n,
            Err(e) => {
                drop(file);
                if interrupt::is_interrupt(&e) && !resume {
                    let _ = fs::remove_file(path);
                    let _ = writeln!(err, "nfsc: get: removed partial file {}", path.display());
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
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(attr.mode & 0o7777));
        if let Some(t) = system_time(attr.mtime)
            && let Err(e) = file.set_modified(t)
        {
            let _ = writeln!(
                err,
                "nfsc: get: cannot set the time of {}: {}",
                path.display(),
                io_text(&e)
            );
        }
        drop(file);
        writeln!(
            err,
            "getting file {label} of size {size} as {} ({}{})",
            path.display(),
            rate(delivered, started.elapsed()),
            resumed_note(start, size)
        )
        .map_err(local_err)
    }

    /// Downloads a directory tree. Symlinks inside it are skipped with a note, so
    /// a link cannot send the recursion in a loop or outside the export.
    fn get_tree(
        &mut self,
        fh: &FileHandle,
        dir: &Path,
        resume: bool,
        err: &mut dyn Write,
    ) -> Result<()> {
        fs::create_dir_all(dir).map_err(local_err)?;
        let mut entries = self.fs.readdir(fh)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for entry in entries {
            let child = dir.join(OsStr::from_bytes(&entry.name));
            let (cfh, attr) = match (entry.handle, entry.attr) {
                (Some(h), Some(a)) => (h, a),
                _ => self.fs.lookup(fh, &entry.name)?,
            };
            let label = display_name(&entry.name);
            match attr.ftype {
                FileType::Directory => self.get_tree(&cfh, &child, resume, err)?,
                FileType::Regular => {
                    self.fetch_to_path(&label, &cfh, &attr, &child, resume, err)?
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
        let mut meter = Meter::new(self.progress, &label, size, start);
        let mut sent = start;
        if start < size {
            file.seek(SeekFrom::Start(start)).map_err(local_err)?;
            let flag = Arc::clone(&self.interrupt);
            let result = self
                .fs
                .write_stream(&fh, start, &mut |buf: &mut [u8]| -> Result<usize> {
                    interrupt::check(&flag)?;
                    let n = file.read(buf).map_err(local_err)?;
                    sent += n as u64;
                    meter.tick(err, sent);
                    Ok(n)
                });
            meter.finish(err);
            if let Err(e) = result {
                if interrupt::is_interrupt(&e) {
                    let _ = writeln!(
                        err,
                        "nfsc: put: remote file {label} is partial ({sent} of {size} bytes); put -c continues it"
                    );
                }
                return Err(e);
            }
        }
        writeln!(
            err,
            "putting file {} as {label} ({}{})",
            local.display(),
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
                    path.display()
                )
                .map_err(local_err)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_percent_is_exact_past_four_gib() {
        let total = 6 << 30;
        assert_eq!(percent(0, total), 0);
        assert_eq!(percent(total / 2, total), 50);
        assert_eq!(percent((4u64 << 30) + 1, total), 66);
        assert_eq!(percent(total, total), 100);
        assert_eq!(percent(total + 1, total), 100);
        assert_eq!(percent(0, 0), 100);
    }

    #[test]
    fn eta_and_progress_line_format() {
        assert_eq!(format_eta(65), "01:05");
        assert_eq!(format_eta(3725), "1:02:05");
        let line = progress_line("backup.img", 1 << 30, 4 << 30, 100.0 * 1024.0 * 1024.0);
        assert!(line.starts_with("backup.img"), "{line}");
        assert!(line.contains(" 25%"), "{line}");
        assert!(line.contains("1.0G / 4.0G"), "{line}");
        assert!(line.contains("ETA 00:30"), "{line}");
        assert!(progress_line("x", 0, 10, 0.0).contains("ETA --:--"));
    }

    #[test]
    fn rate_smoothing_moves_toward_new_samples() {
        assert_eq!(smooth(None, 100.0), 100.0);
        assert_eq!(smooth(Some(100.0), 200.0), 125.0);
    }

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
