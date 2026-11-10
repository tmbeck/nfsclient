//! The shell session: the connected filesystem, the remote working directory
//! and the path resolver. Command bodies live in `ops` and `transfer`.
//!
//! The working directory is a stack of nodes from the export root down to the
//! current directory, so `..` never needs a server round trip and can never
//! climb above the root.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nfsc::fs::{Attr, FileHandle, FileType, Filesystem, NfsVersion, Status};
use nfsc::{Error, Result};

use super::complete::ShellHelper;
use super::format;
use super::interrupt;
use super::remote::{DirCache, RemoteCtx, SharedFs, resolve_path};

/// Commands accepted by the shell, including aliases.
pub const COMMANDS: &[&str] = &[
    "ls", "dir", "cd", "pwd", "lcd", "stat", "get", "put", "cat", "mkdir", "rm", "rmdir", "mv",
    "ln", "chmod", "chown", "df", "help", "exit", "quit",
];

/// One component of the working-directory stack.
#[derive(Debug, Clone)]
pub struct Node {
    pub name: Vec<u8>,
    pub fh: FileHandle,
    pub attr: Attr,
}

/// What the caller should do after a command ran.
#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Exit,
}

/// A failed command, printed as `nfsc: <cmd>: <path>: <error>`.
#[derive(Debug)]
pub struct CmdFailure {
    cmd: String,
    path: Option<String>,
    msg: String,
    interrupted: bool,
}

impl CmdFailure {
    pub fn new(cmd: &str, path: Option<&str>, msg: impl Into<String>) -> Self {
        CmdFailure {
            cmd: cmd.to_string(),
            path: path.map(str::to_string),
            msg: msg.into(),
            interrupted: false,
        }
    }

    /// Maps a protocol or local error. An interrupt becomes an "interrupted" failure.
    pub fn from_error(cmd: &str, path: &str, e: Error) -> Self {
        if interrupt::is_interrupt(&e) {
            return CmdFailure {
                interrupted: true,
                ..Self::new(cmd, Some(path), "interrupted")
            };
        }
        Self::new(cmd, Some(path), e.to_string())
    }

    /// True when the command stopped because of Ctrl-C.
    pub fn is_interrupted(&self) -> bool {
        self.interrupted
    }
}

impl fmt::Display for CmdFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(p) => write!(f, "nfsc: {}: {}: {}", self.cmd, p, self.msg),
            None => write!(f, "nfsc: {}: {}", self.cmd, self.msg),
        }
    }
}

pub type CmdResult<T> = std::result::Result<T, CmdFailure>;

/// Attaches the command name and the user's path to a protocol or local error.
pub trait Ctx<T> {
    fn ctx(self, cmd: &str, path: &str) -> CmdResult<T>;
}

impl<T> Ctx<T> for Result<T> {
    fn ctx(self, cmd: &str, path: &str) -> CmdResult<T> {
        self.map_err(|e| CmdFailure::from_error(cmd, path, e))
    }
}

/// A usage error for `cmd`.
pub fn usage(cmd: &str, msg: impl Into<String>) -> CmdFailure {
    CmdFailure::new(cmd, None, msg)
}

/// Failure to write command output.
pub fn io_fail(cmd: &str, e: std::io::Error) -> CmdFailure {
    CmdFailure::new(cmd, None, format!("write failed: {e}"))
}

/// The last node of a non-empty stack: the object the stack points at.
pub fn last_node(stack: &[Node]) -> &Node {
    stack
        .last()
        .expect("a path stack always holds the export root")
}

/// Splits `path` into its directory part (with the separator) and final name.
/// Trailing slashes are ignored; `"/x"` gives `("/", "x")`, `"x"` gives `("", "x")`.
pub fn split_last(path: &str) -> (&str, &str) {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    }
}

/// Rejects names that cannot be created, renamed or removed: empty, `.` and `..`.
pub fn check_name(name: &str) -> Result<()> {
    match name {
        "" | "." | ".." => Err(Error::Invalid(format!("invalid name '{name}'"))),
        _ => Ok(()),
    }
}

pub(super) fn components(path: &[u8]) -> VecDeque<Vec<u8>> {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn display_path(export: &[u8], stack: &[Node]) -> String {
    let mut s = String::from_utf8_lossy(export)
        .trim_end_matches('/')
        .to_string();
    for node in &stack[1..] {
        s.push('/');
        s.push_str(&format::name(&node.name));
    }
    if s.is_empty() { "/".to_string() } else { s }
}

/// Lexically normalizes a local path (no filesystem access).
pub fn normalize_local(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // ".." at the filesystem root stays at the root.
                Some(Component::RootDir) => {}
                _ => out.push(".."),
            },
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Message for an I/O error without the "(os error N)" suffix.
pub fn io_text(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn default_term_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .filter(|&w| w >= 20)
        .unwrap_or(80)
}

/// A connected shell session.
pub struct Session {
    pub(super) fs: SharedFs,
    /// Host as shown in the prompt.
    pub(super) host: String,
    pub(super) version: NfsVersion,
    /// Export (v2/v3) or pseudo-fs path (v4) that the root node corresponds to.
    pub(super) export: Vec<u8>,
    pub(super) root: Node,
    /// `cwd[0]` is always the export root.
    pub(super) cwd: Vec<Node>,
    pub(super) local_cwd: PathBuf,
    /// Unix seconds used to choose `ls -l` date formats. Tests pin it.
    pub clock: i64,
    /// Columns for short `ls` output.
    pub term_width: usize,
    /// Show a transfer progress line on stderr.
    pub progress: bool,
    /// Set by Ctrl-C. Transfers check it between chunks.
    pub interrupt: Arc<AtomicBool>,
    /// Directory listings for tab completion.
    pub(super) cache: Rc<RefCell<DirCache>>,
}

impl Session {
    /// Starts a session at `remainder` below the export root, the path that
    /// `fs::connect` resolved. Fails if a component is missing or not a directory.
    pub fn new(
        mut fs: Box<dyn Filesystem>,
        host: String,
        export: Vec<u8>,
        remainder: &[Vec<u8>],
    ) -> Result<Self> {
        let version = fs.version();
        let fh = fs.root();
        let attr = fs.getattr(&fh)?;
        let root = Node {
            name: Vec::new(),
            fh,
            attr,
        };
        let mut session = Session {
            fs: SharedFs::new(fs),
            host,
            version,
            export,
            root: root.clone(),
            cwd: vec![root],
            local_cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            clock: now_secs(),
            term_width: default_term_width(),
            progress: false,
            interrupt: Arc::new(AtomicBool::new(false)),
            cache: Rc::new(RefCell::new(DirCache::default())),
        };
        for name in remainder {
            let parent = last_node(&session.cwd).fh.clone();
            let (fh, attr) = session.fs.lookup(&parent, name)?;
            if attr.ftype != FileType::Directory {
                return Err(Error::Nfs(Status::NotDir));
            }
            session.cwd.push(Node {
                name: name.clone(),
                fh,
                attr,
            });
        }
        Ok(session)
    }

    /// One-line "connected" message for interactive use.
    pub fn banner(&self) -> String {
        format!(
            "Connected to {}:{} ({})",
            self.host,
            String::from_utf8_lossy(&self.export),
            self.version
        )
    }

    pub fn prompt(&self) -> String {
        format!("nfs {}:{}> ", self.host, self.cwd_path())
    }

    /// The remote working directory as a server path.
    pub fn cwd_path(&self) -> String {
        display_path(&self.export, &self.cwd)
    }

    /// Resolves `path` relative to the working directory (see [`resolve_path`]).
    pub(super) fn resolve(&mut self, path: &str, follow_last: bool) -> Result<Vec<Node>> {
        resolve_path(
            &mut self.fs,
            &self.root,
            &self.export,
            &self.cwd,
            path,
            follow_last,
        )
    }

    /// Resolves the directory that will hold `path` and returns it with the final name.
    pub(super) fn resolve_parent(&mut self, path: &str) -> Result<(FileHandle, Vec<u8>)> {
        let (dir, name) = split_last(path);
        check_name(name)?;
        let stack = self.resolve(dir, true)?;
        let node = last_node(&stack);
        if node.attr.ftype != FileType::Directory {
            return Err(Error::Nfs(Status::NotDir));
        }
        Ok((node.fh.clone(), name.as_bytes().to_vec()))
    }

    /// Where a copy, move or link named `dst` lands: inside `dst` when it is an
    /// existing directory (keeping the base name of `src`), otherwise `dst` itself.
    pub(super) fn destination(&mut self, dst: &str, src: &str) -> Result<(FileHandle, Vec<u8>)> {
        match self.resolve(dst, true) {
            Ok(stack) if last_node(&stack).attr.ftype == FileType::Directory => Ok((
                last_node(&stack).fh.clone(),
                split_last(src).1.as_bytes().to_vec(),
            )),
            _ => self.resolve_parent(dst),
        }
    }

    /// Expands `*` and `?` in the final component into the matching names
    /// (sorted). Patterns with no match are an error; names that are not valid
    /// UTF-8 cannot be typed back in, so they are skipped.
    pub(super) fn expand(&mut self, cmd: &str, pattern: &str) -> CmdResult<Vec<String>> {
        if !super::line::is_pattern(pattern) {
            return Ok(vec![pattern.to_string()]);
        }
        let (dir, pat) = match pattern.rfind('/') {
            Some(i) => (&pattern[..=i], &pattern[i + 1..]),
            None => ("", pattern),
        };
        if super::line::is_pattern(dir) {
            return Err(CmdFailure::new(
                cmd,
                Some(pattern),
                "wildcards are only supported in the last path component",
            ));
        }
        let stack = self.resolve(dir, true).ctx(cmd, pattern)?;
        let fh = last_node(&stack).fh.clone();
        let entries = self.fs.readdir(&fh).ctx(cmd, pattern)?;
        let mut names: Vec<String> = entries
            .into_iter()
            .filter_map(|e| String::from_utf8(e.name).ok())
            .filter(|n| super::line::glob_match(pat, n))
            .collect();
        if names.is_empty() {
            return Err(CmdFailure::new(cmd, Some(pattern), "no match"));
        }
        names.sort();
        Ok(names.into_iter().map(|n| format!("{dir}{n}")).collect())
    }

    /// A local path from user input: relative paths start at the local working directory.
    pub(super) fn local_path(&self, p: &str) -> PathBuf {
        normalize_local(&self.local_cwd.join(p))
    }

    /// Whether Ctrl-C has been pressed since the flag was last cleared.
    pub fn interrupt_requested(&self) -> bool {
        self.interrupt.load(Ordering::SeqCst)
    }

    /// Clears the Ctrl-C flag before a new command line.
    pub fn clear_interrupt(&self) {
        self.interrupt.store(false, Ordering::SeqCst);
    }

    pub fn local_cwd(&self) -> &Path {
        &self.local_cwd
    }

    /// Hands the completer what it needs for the next prompt.
    pub fn sync_completer(&self, helper: &mut ShellHelper) {
        helper.sync(
            RemoteCtx {
                fs: self.fs.clone(),
                root: self.root.clone(),
                export: self.export.clone(),
                cwd: self.cwd.clone(),
                cache: self.cache.clone(),
            },
            self.local_cwd.clone(),
        );
    }

    /// Runs one command. Output goes to `out`; progress and per-file summaries to `err`.
    pub fn execute(
        &mut self,
        words: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> CmdResult<Flow> {
        let Some((cmd, args)) = words.split_first() else {
            return Ok(Flow::Continue);
        };
        // Commands that can change names on the server, and `cd`, drop the
        // completion cache once they have run, whether or not they succeeded.
        let invalidates = matches!(
            cmd.as_str(),
            "cd" | "put" | "mkdir" | "rm" | "rmdir" | "mv" | "ln" | "chmod" | "chown"
        );
        let result = self.dispatch(cmd, args, out, err);
        if invalidates {
            self.cache.borrow_mut().clear();
        }
        result
    }

    fn dispatch(
        &mut self,
        cmd: &str,
        args: &[String],
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> CmdResult<Flow> {
        match cmd {
            "ls" | "dir" => self.cmd_ls(args, out)?,
            "cd" => self.cmd_cd(args)?,
            "pwd" => {
                writeln!(out, "{}", self.cwd_path()).map_err(|e| io_fail("pwd", e))?;
            }
            "lcd" => self.cmd_lcd(args)?,
            "stat" => self.cmd_stat(args, out)?,
            "get" => self.cmd_get(args, out, err)?,
            "put" => self.cmd_put(args, err)?,
            "cat" => self.cmd_cat(args, out)?,
            "mkdir" => self.cmd_mkdir(args)?,
            "rm" => self.cmd_rm(args)?,
            "rmdir" => self.cmd_rmdir(args)?,
            "mv" => self.cmd_mv(args)?,
            "ln" => self.cmd_ln(args)?,
            "chmod" => self.cmd_chmod(args)?,
            "chown" => self.cmd_chown(args)?,
            "df" => self.cmd_df(args, out)?,
            "help" => super::ops::write_help(out).map_err(|e| io_fail("help", e))?,
            "exit" | "quit" => return Ok(Flow::Exit),
            other => {
                return Err(CmdFailure::new(other, None, "unknown command (try help)"));
            }
        }
        Ok(Flow::Continue)
    }
}

/// Checks a parsed command's name before anything is sent to the server.
pub fn check_command(words: &[String]) -> std::result::Result<(), String> {
    match words.first() {
        Some(c) if !COMMANDS.contains(&c.as_str()) => {
            Err(format!("unknown command '{c}' (try help)"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_last_handles_roots_and_trailing_slashes() {
        assert_eq!(split_last("a/b/c"), ("a/b", "c"));
        assert_eq!(split_last("/x"), ("/", "x"));
        assert_eq!(split_last("x"), ("", "x"));
        assert_eq!(split_last("a/b/"), ("a", "b"));
        assert_eq!(split_last("/"), ("", ""));
    }

    #[test]
    fn local_paths_normalize_lexically() {
        assert_eq!(
            normalize_local(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(normalize_local(Path::new("/../x")), PathBuf::from("/x"));
        assert_eq!(normalize_local(Path::new("")), PathBuf::from("."));
    }

    #[test]
    fn check_command_accepts_known_names_only() {
        assert!(check_command(&["ls".to_string()]).is_ok());
        assert!(check_command(&["dir".to_string()]).is_ok());
        assert_eq!(
            check_command(&["frobnicate".to_string()]).unwrap_err(),
            "unknown command 'frobnicate' (try help)"
        );
    }

    #[test]
    fn display_path_shows_export_and_components() {
        let node = |name: &str| Node {
            name: name.as_bytes().to_vec(),
            fh: FileHandle::default(),
            attr: Attr {
                ftype: FileType::Directory,
                mode: 0,
                nlink: 1,
                uid: 0,
                gid: 0,
                owner: None,
                group: None,
                size: 0,
                used: 0,
                rdev: (0, 0),
                fsid: 0,
                fileid: 0,
                atime: Default::default(),
                mtime: Default::default(),
                ctime: Default::default(),
            },
        };
        let root = node("");
        assert_eq!(
            display_path(b"/export", std::slice::from_ref(&root)),
            "/export"
        );
        assert_eq!(display_path(b"/", std::slice::from_ref(&root)), "/");
        let stack = vec![root, node("a"), node("b")];
        assert_eq!(display_path(b"/export/", &stack), "/export/a/b");
    }
}
