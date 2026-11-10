//! get and put, and the copy loops behind them.
//!
//! Reads ask for `max_read` bytes per call and writes send `max_write` bytes
//! per call. A write may be short, so the loop keeps going until every byte is
//! accepted and treats a zero-byte write as an error.

use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use nfsc::fs::{CreateMode, FileHandle, FileType, SetAttr, Status};
use nfsc::{Error, Result};

use super::line::parse_args;
use super::session::{CmdFailure, CmdResult, Ctx, Session, io_text, last_node, split_last, usage};
use crate::text::display_name;

/// Transfer size for one READ or WRITE: the server's limit, never below 512 bytes.
fn chunk(limit: u32) -> usize {
    limit.max(512) as usize
}

fn local_err(e: std::io::Error) -> Error {
    Error::Invalid(io_text(&e))
}

fn rate(bytes: u64, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(0.001);
    format!("{:.1} KiB/s", bytes as f64 / 1024.0 / secs)
}

/// Progress line on stderr, updated at most every 200 ms. Only used when
/// stderr is a terminal (see `Session::progress`).
struct Meter {
    enabled: bool,
    label: String,
    last: Instant,
}

impl Meter {
    fn new(enabled: bool, label: &str) -> Self {
        Meter {
            enabled,
            label: label.to_string(),
            last: Instant::now(),
        }
    }

    fn tick(&mut self, err: &mut dyn Write, done: u64) {
        if self.enabled && self.last.elapsed() >= Duration::from_millis(200) {
            self.last = Instant::now();
            let _ = write!(err, "\r{}: {} bytes", self.label, done);
            let _ = err.flush();
        }
    }

    fn finish(&self, err: &mut dyn Write) {
        if self.enabled {
            let _ = write!(err, "\r{:79}\r", "");
            let _ = err.flush();
        }
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
        let flags = parse_args(args, "r").map_err(|m| usage(CMD, m))?;
        let recursive = flags.has('r');
        let (remote, local) = match flags.positional.as_slice() {
            [r] => (r.as_str(), None),
            [r, l] => (r.as_str(), Some(l.as_str())),
            _ => return Err(usage(CMD, "usage: get [-r] remote [local]")),
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
                let n = self.stream_file(&node.fh, out, |_| {}).ctx(CMD, src)?;
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
                None => self.local_cwd.join(base),
                Some(p) if p.is_dir() => p.join(base),
                Some(p) => p.clone(),
            };
            if node.attr.ftype == FileType::Directory {
                self.get_tree(&node.fh, &dest, err).ctx(CMD, src)?;
            } else {
                self.fetch_to_path(base, &node.fh, &node.attr, &dest, err)
                    .ctx(CMD, src)?;
            }
        }
        Ok(())
    }

    pub(super) fn cmd_put(&mut self, args: &[String], err: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "put";
        let flags = parse_args(args, "r").map_err(|m| usage(CMD, m))?;
        let recursive = flags.has('r');
        let (local, remote) = match flags.positional.as_slice() {
            [l] => (l.as_str(), None),
            [l, r] => (l.as_str(), Some(r.as_str())),
            _ => return Err(usage(CMD, "usage: put [-r] local [remote]")),
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
            self.put_tree(&path, &dir, &name, err).ctx(CMD, local)
        } else {
            self.put_file(&path, &meta, &dir, &name, err)
                .ctx(CMD, local)
        }
    }

    /// Reads `fh` to the end, passing each chunk to `sink`. `on_chunk` gets the
    /// running byte count. Returns the total.
    pub(super) fn stream_file(
        &mut self,
        fh: &FileHandle,
        sink: &mut dyn Write,
        mut on_chunk: impl FnMut(u64),
    ) -> Result<u64> {
        let count = chunk(self.fs.max_read()) as u32;
        let mut offset = 0u64;
        loop {
            let (data, eof) = self.fs.read(fh, offset, count)?;
            sink.write_all(&data).map_err(local_err)?;
            offset += data.len() as u64;
            on_chunk(offset);
            if eof || data.is_empty() {
                break;
            }
        }
        Ok(offset)
    }

    /// Downloads one file to `path`, overwriting it, and restores its mode bits.
    fn fetch_to_path(
        &mut self,
        label: &str,
        fh: &FileHandle,
        attr: &nfsc::fs::Attr,
        path: &Path,
        err: &mut dyn Write,
    ) -> Result<()> {
        let mut file = File::create(path).map_err(local_err)?;
        let mut meter = Meter::new(self.progress, label);
        let start = Instant::now();
        let n = self.stream_file(fh, &mut file, |done| meter.tick(err, done))?;
        meter.finish(err);
        drop(file);
        // Best effort: a failed chmod does not undo a successful download.
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(attr.mode & 0o7777));
        writeln!(
            err,
            "getting file {label} of size {n} as {} ({})",
            path.display(),
            rate(n, start.elapsed())
        )
        .map_err(local_err)
    }

    /// Downloads a directory tree. Symlinks inside it are skipped with a note, so
    /// a link cannot send the recursion in a loop or outside the export.
    fn get_tree(&mut self, fh: &FileHandle, dir: &Path, err: &mut dyn Write) -> Result<()> {
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
                FileType::Directory => self.get_tree(&cfh, &child, err)?,
                FileType::Regular => self.fetch_to_path(&label, &cfh, &attr, &child, err)?,
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

    /// Uploads one local file as `name` in `dir`, replacing any existing file.
    fn put_file(
        &mut self,
        local: &Path,
        meta: &Metadata,
        dir: &FileHandle,
        name: &[u8],
        err: &mut dyn Write,
    ) -> Result<()> {
        let mut file = File::open(local).map_err(local_err)?;
        let mode = meta.permissions().mode() & 0o7777;
        let existing = match self.fs.lookup(dir, name) {
            Ok(found) => Some(found),
            Err(Error::Nfs(Status::NoEnt)) => None,
            Err(e) => return Err(e),
        };
        let fh = match existing {
            Some((fh, attr)) => {
                if attr.ftype == FileType::Directory {
                    return Err(Error::Nfs(Status::IsDir));
                }
                fh
            }
            None => {
                self.fs
                    .create(dir, name, CreateMode::Unchecked, &SetAttr::default())?
                    .0
            }
        };
        let truncate = SetAttr {
            mode: Some(mode),
            size: Some(0),
            ..SetAttr::default()
        };
        self.fs.setattr(&fh, &truncate)?;

        let label = display_name(name);
        let mut meter = Meter::new(self.progress, &label);
        let start = Instant::now();
        let mut buf = vec![0u8; chunk(self.fs.max_write())];
        let mut offset = 0u64;
        loop {
            let n = file.read(&mut buf).map_err(local_err)?;
            if n == 0 {
                break;
            }
            // The server may accept fewer bytes than offered; keep writing the rest.
            let mut sent = 0;
            while sent < n {
                let written = self.fs.write(&fh, offset, &buf[sent..n])? as usize;
                if written == 0 {
                    return Err(Error::Invalid(format!(
                        "server accepted no data for {label} at offset {offset}"
                    )));
                }
                sent += written;
                offset += written as u64;
            }
            meter.tick(err, offset);
        }
        meter.finish(err);
        writeln!(
            err,
            "putting file {} as {label} ({})",
            local.display(),
            rate(offset, start.elapsed())
        )
        .map_err(local_err)
    }

    /// Uploads a local directory tree. Symlinks and special files are skipped.
    fn put_tree(
        &mut self,
        local: &Path,
        dir: &FileHandle,
        name: &[u8],
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
                self.put_tree(&path, &dir_fh, child.as_bytes(), err)?;
            } else if meta.is_file() {
                self.put_file(&path, &meta, &dir_fh, child.as_bytes(), err)?;
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
