//! Command bodies for everything except get/put (see `transfer`).
//! Each takes the arguments after the command name.

use std::io::Write;

use nfsc::Error;
use nfsc::fs::{Attr, DirEntry, FileHandle, FileType, Filesystem, SetAttr, Status};

use super::format::{self, LongEntry};
use super::line::parse_args;
use super::session::{
    CmdFailure, CmdResult, Ctx, Node, Session, io_fail, io_text, last_node, usage,
};
use crate::text::display_name;

/// One entry of a listing. `attr` is only filled for `ls -l`.
struct Row {
    name: String,
    attr: Option<Attr>,
    link: Option<String>,
}

impl Row {
    fn label(&self, long: bool) -> String {
        match (&self.link, long) {
            (Some(target), true) => format!("{} -> {target}", self.name),
            _ => self.name.clone(),
        }
    }
}

/// Parses an octal permission argument such as `755`.
pub fn parse_mode(s: &str) -> Option<u32> {
    u32::from_str_radix(s, 8).ok().filter(|m| *m <= 0o7777)
}

/// Parses `uid`, `uid:gid`, `uid:` or `:gid`. Missing parts are left alone.
pub fn parse_owner(spec: &str) -> std::result::Result<(Option<u32>, Option<u32>), String> {
    let bad = || format!("invalid owner '{spec}' (use uid, uid:gid or :gid)");
    let parse = |s: &str| -> std::result::Result<Option<u32>, String> {
        if s.is_empty() {
            Ok(None)
        } else {
            s.parse::<u32>().map(Some).map_err(|_| bad())
        }
    };
    let (uid_part, gid_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let uid = parse(uid_part)?;
    let gid = match gid_part {
        Some(g) => parse(g)?,
        None => None,
    };
    if uid.is_none() && gid.is_none() {
        return Err(bad());
    }
    Ok((uid, gid))
}

/// Command summary shared by `nfsc shell --help` and the in-shell `help`.
const SUMMARY: &str = shell_summary!();

/// Per-command details for `help CMD`.
const DETAILS: &[(&[&str], &str)] = &[
    (
        &["ls", "dir"],
        "ls [-l] [path]\n  List a directory or show a file. -l: long format with mode, owner, size,\n  mtime and link targets. * and ? match in the last path component.",
    ),
    (
        &["cd"],
        "cd [path]\n  Change the remote directory; no argument returns to the export root.\n  Symbolic links are followed; .. never leaves the export root.",
    ),
    (&["pwd"], "pwd\n  Print the remote working directory."),
    (
        &["lcd"],
        "lcd [path]\n  Change the local directory used by get and put (no argument: $HOME).",
    ),
    (
        &["stat"],
        "stat path...\n  Show all attributes. Symbolic links are shown, not followed.",
    ),
    (&["cat"], "cat path\n  Write a remote file to stdout."),
    (
        &["get"],
        "get [-r] [-c] remote [local]\n  Download. local defaults to the local directory; - writes to stdout.\n  -r  download a directory tree (symlinks and special files are skipped)\n  -c  resume a partial local file from its current size\n  Keeps the remote mtime and mode (without setuid/setgid/sticky). Ctrl-C\n  removes a partial download unless -c is given.",
    ),
    (
        &["put"],
        "put [-r] [-c] local [remote]\n  Upload. remote defaults to the local file name in the remote directory.\n  -r  upload a directory tree\n  -c  resume a partial remote file from its current size\n  Ctrl-C leaves the partial remote file; put -c continues it.",
    ),
    (
        &["mkdir"],
        "mkdir path...\n  Create directories (mode 755).",
    ),
    (
        &["rm"],
        "rm path...\n  Remove files and symbolic links (not directories; see rmdir).",
    ),
    (&["rmdir"], "rmdir path...\n  Remove empty directories."),
    (
        &["mv"],
        "mv src dst\n  Rename or move; into dst if dst is a directory.",
    ),
    (
        &["ln"],
        "ln [-s] target name\n  Hard link, or symbolic link with -s (target is stored as given).",
    ),
    (
        &["chmod"],
        "chmod mode path...\n  Change permissions; mode is octal (e.g. 644).",
    ),
    (
        &["chown"],
        "chown uid[:gid] path...\n  Change owner and group (numeric ids).",
    ),
    (
        &["df"],
        "df [path]\n  Show size, used and available space of the file system.",
    ),
    (
        &["help"],
        "help [cmd]\n  Command summary, or details for one command.",
    ),
    (
        &["exit", "quit"],
        "exit | quit\n  Leave the shell (Ctrl-D also works).",
    ),
];

/// `help` and `help CMD`.
pub fn write_help(args: &[String], out: &mut dyn Write) -> std::result::Result<(), String> {
    let text = match args {
        [] => format!(
            "{SUMMARY}\nQuote names with spaces; ';' separates commands. Ctrl-C stops a transfer.\n\
             Details: help <cmd>\n"
        ),
        [cmd] => match DETAILS
            .iter()
            .find(|(names, _)| names.contains(&cmd.as_str()))
        {
            Some((_, d)) => format!("{d}\n"),
            None => return Err(format!("no such command: {cmd} (try help)")),
        },
        _ => return Err("usage: help [cmd]".to_string()),
    };
    out.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

impl Session {
    pub(super) fn cmd_ls(&mut self, args: &[String], out: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "ls";
        let flags = parse_args(args, "l").map_err(|m| usage(CMD, m))?;
        if flags.positional.len() > 1 {
            return Err(usage(CMD, "usage: ls [-l] [path]"));
        }
        let long = flags.has('l');
        let arg = flags.positional.first().map_or(".", String::as_str);
        let paths = self.expand(CMD, arg)?;
        let many = paths.len() > 1;
        for (i, path) in paths.iter().enumerate() {
            let stack = self.resolve(path, false).ctx(CMD, path)?;
            let node = last_node(&stack).clone();
            // A directory, or a symlink that leads to one, is listed; anything else is one entry.
            let dir = match node.attr.ftype {
                FileType::Directory => Some(stack),
                FileType::Symlink => match self.resolve(path, true) {
                    Ok(s) if last_node(&s).attr.ftype == FileType::Directory => Some(s),
                    _ => None,
                },
                _ => None,
            };
            let rows = match dir {
                Some(dir) => {
                    if many {
                        if i > 0 {
                            writeln!(out).map_err(|e| io_fail(CMD, e))?;
                        }
                        writeln!(out, "{path}:").map_err(|e| io_fail(CMD, e))?;
                    }
                    self.list_dir(path, &dir, long)?
                }
                None => {
                    let link = if node.attr.ftype == FileType::Symlink {
                        Some(self.read_link(&node.fh, path)?)
                    } else {
                        None
                    };
                    vec![Row {
                        name: display_name(path.as_bytes()),
                        attr: long.then(|| node.attr.clone()),
                        link,
                    }]
                }
            };
            let text = self.render(&rows, long);
            out.write_all(text.as_bytes())
                .map_err(|e| io_fail(CMD, e))?;
        }
        Ok(())
    }

    fn read_link(&mut self, fh: &FileHandle, path: &str) -> CmdResult<String> {
        let target = self.fs.readlink(fh).ctx("ls", path)?;
        Ok(display_name(&target))
    }

    /// Reads a directory into rows, sorted by raw name. Attributes and link
    /// targets are fetched only for `ls -l`.
    fn list_dir(&mut self, path: &str, dir: &[Node], long: bool) -> CmdResult<Vec<Row>> {
        let dir_fh = last_node(dir).fh.clone();
        let mut entries = self.fs.readdir(&dir_fh).ctx("ls", path)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let mut rows = Vec::with_capacity(entries.len());
        for DirEntry {
            name, attr, handle, ..
        } in entries
        {
            let (attr, link) = if long {
                let (fh, attr) = match (handle, attr) {
                    (Some(fh), Some(attr)) => (fh, attr),
                    _ => self.fs.lookup(&dir_fh, &name).ctx("ls", path)?,
                };
                let link = if attr.ftype == FileType::Symlink {
                    Some(self.read_link(&fh, path)?)
                } else {
                    None
                };
                (Some(attr), link)
            } else {
                (None, None)
            };
            rows.push(Row {
                name: display_name(&name),
                attr,
                link,
            });
        }
        Ok(rows)
    }

    fn render(&self, rows: &[Row], long: bool) -> String {
        if !long {
            let names: Vec<String> = rows.iter().map(|r| r.label(false)).collect();
            return format::columns(&names, self.term_width);
        }
        let entries: Vec<LongEntry> = rows
            .iter()
            .filter_map(|r| {
                let a = r.attr.as_ref()?;
                Some(LongEntry {
                    mode: format::mode_string(a.ftype, a.mode),
                    nlink: a.nlink,
                    owner: format::owner_of(a),
                    group: format::group_of(a),
                    size: a.size,
                    date: format::ls_time(a.mtime.seconds, self.clock),
                    name: r.label(true),
                })
            })
            .collect();
        format::long_listing(&entries)
    }

    pub(super) fn cmd_cd(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "cd";
        let path = match args {
            [] => "/".to_string(),
            [p] => p.clone(),
            _ => return Err(usage(CMD, "usage: cd [path]")),
        };
        let stack = self.resolve(&path, true).ctx(CMD, &path)?;
        if last_node(&stack).attr.ftype != FileType::Directory {
            return Err(CmdFailure::from_error(
                CMD,
                &path,
                Error::Nfs(Status::NotDir),
            ));
        }
        self.cwd = stack;
        Ok(())
    }

    pub(super) fn cmd_lcd(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "lcd";
        let target = match args {
            [] => std::env::var("HOME").map_err(|_| usage(CMD, "HOME is not set"))?,
            [p] => p.clone(),
            _ => return Err(usage(CMD, "usage: lcd [path]")),
        };
        let path = self.local_path(&target);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_dir() => {
                self.local_cwd = path;
                Ok(())
            }
            Ok(_) => Err(CmdFailure::new(CMD, Some(&target), "not a directory")),
            Err(e) => Err(CmdFailure::new(CMD, Some(&target), io_text(&e))),
        }
    }

    pub(super) fn cmd_stat(&mut self, args: &[String], out: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "stat";
        if args.is_empty() {
            return Err(usage(CMD, "usage: stat path..."));
        }
        let io_size = self.fs.max_read();
        for arg in args {
            for path in self.expand(CMD, arg)? {
                let stack = self.resolve(&path, false).ctx(CMD, &path)?;
                let node = last_node(&stack).clone();
                let link = if node.attr.ftype == FileType::Symlink {
                    Some(self.read_link(&node.fh, &path)?)
                } else {
                    None
                };
                let text = format::stat_text(
                    &display_name(path.as_bytes()),
                    &node.attr,
                    link.as_deref(),
                    io_size,
                );
                out.write_all(text.as_bytes())
                    .map_err(|e| io_fail(CMD, e))?;
            }
        }
        Ok(())
    }

    pub(super) fn cmd_cat(&mut self, args: &[String], out: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "cat";
        let [path] = args else {
            return Err(usage(CMD, "usage: cat path"));
        };
        let stack = self.resolve(path, true).ctx(CMD, path)?;
        let node = last_node(&stack).clone();
        if node.attr.ftype == FileType::Directory {
            return Err(CmdFailure::from_error(CMD, path, Error::Nfs(Status::IsDir)));
        }
        self.stream_to(&node.fh, 0, out).ctx(CMD, path).map(|_| ())
    }

    pub(super) fn cmd_mkdir(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "mkdir";
        if args.is_empty() {
            return Err(usage(CMD, "usage: mkdir path..."));
        }
        for path in args {
            let (dir, name) = self.resolve_parent(path).ctx(CMD, path)?;
            let attrs = SetAttr {
                mode: Some(0o755),
                ..SetAttr::default()
            };
            self.fs.mkdir(&dir, &name, &attrs).ctx(CMD, path)?;
        }
        Ok(())
    }

    pub(super) fn cmd_rm(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "rm";
        if args.is_empty() {
            return Err(usage(CMD, "usage: rm path..."));
        }
        for arg in args {
            for path in self.expand(CMD, arg)? {
                let (dir, name) = self.resolve_parent(&path).ctx(CMD, &path)?;
                self.fs.remove(&dir, &name).ctx(CMD, &path)?;
            }
        }
        Ok(())
    }

    pub(super) fn cmd_rmdir(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "rmdir";
        if args.is_empty() {
            return Err(usage(CMD, "usage: rmdir path..."));
        }
        for path in args {
            let (dir, name) = self.resolve_parent(path).ctx(CMD, path)?;
            self.fs.rmdir(&dir, &name).ctx(CMD, path)?;
        }
        Ok(())
    }

    pub(super) fn cmd_mv(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "mv";
        let [src, dst] = args else {
            return Err(usage(CMD, "usage: mv src dst"));
        };
        let (from_dir, from_name) = self.resolve_parent(src).ctx(CMD, src)?;
        let (to_dir, to_name) = self.destination(dst, src).ctx(CMD, dst)?;
        self.fs
            .rename(&from_dir, &from_name, &to_dir, &to_name)
            .ctx(CMD, src)
    }

    pub(super) fn cmd_ln(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "ln";
        let flags = parse_args(args, "s").map_err(|m| usage(CMD, m))?;
        let [target, dst] = flags.positional.as_slice() else {
            return Err(usage(CMD, "usage: ln [-s] target name"));
        };
        let (dir, name) = self.destination(dst, target).ctx(CMD, dst)?;
        if flags.has('s') {
            self.fs
                .symlink(&dir, &name, target.as_bytes(), &SetAttr::default())
                .ctx(CMD, dst)?;
        } else {
            let stack = self.resolve(target, true).ctx(CMD, target)?;
            let fh = last_node(&stack).fh.clone();
            self.fs.link(&fh, &dir, &name).ctx(CMD, dst)?;
        }
        Ok(())
    }

    pub(super) fn cmd_chmod(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "chmod";
        let [mode, paths @ ..] = args else {
            return Err(usage(CMD, "usage: chmod mode path..."));
        };
        let mode = parse_mode(mode).ok_or_else(|| usage(CMD, format!("invalid mode '{mode}'")))?;
        if paths.is_empty() {
            return Err(usage(CMD, "usage: chmod mode path..."));
        }
        for path in paths {
            let stack = self.resolve(path, true).ctx(CMD, path)?;
            let fh = last_node(&stack).fh.clone();
            let attrs = SetAttr {
                mode: Some(mode),
                ..SetAttr::default()
            };
            self.fs.setattr(&fh, &attrs).ctx(CMD, path)?;
        }
        Ok(())
    }

    pub(super) fn cmd_chown(&mut self, args: &[String]) -> CmdResult<()> {
        const CMD: &str = "chown";
        let [spec, paths @ ..] = args else {
            return Err(usage(CMD, "usage: chown uid[:gid] path..."));
        };
        let (uid, gid) = parse_owner(spec).map_err(|m| usage(CMD, m))?;
        if paths.is_empty() {
            return Err(usage(CMD, "usage: chown uid[:gid] path..."));
        }
        for path in paths {
            let stack = self.resolve(path, true).ctx(CMD, path)?;
            let fh = last_node(&stack).fh.clone();
            let attrs = SetAttr {
                uid,
                gid,
                ..SetAttr::default()
            };
            self.fs.setattr(&fh, &attrs).ctx(CMD, path)?;
        }
        Ok(())
    }

    pub(super) fn cmd_df(&mut self, args: &[String], out: &mut dyn Write) -> CmdResult<()> {
        const CMD: &str = "df";
        let arg = match args {
            [] => "",
            [p] => p.as_str(),
            _ => return Err(usage(CMD, "usage: df [path]")),
        };
        let stack = self.resolve(arg, true).ctx(CMD, arg)?;
        let fh = last_node(&stack).fh.clone();
        let st = self.fs.fsstat(&fh).ctx(CMD, arg)?;
        let used = st.total_bytes.saturating_sub(st.free_bytes);
        let denom = used + st.avail_bytes;
        let pct = if denom == 0 {
            0
        } else {
            (used * 100).div_ceil(denom)
        };
        let source = format!("{}:{}", self.host, String::from_utf8_lossy(&self.export));
        let text = format!(
            "{:<24}{:>8}{:>8}{:>8}{:>6}\n{:<24}{:>8}{:>8}{:>8}{:>5}%\n",
            "Filesystem",
            "Size",
            "Used",
            "Avail",
            "Use%",
            source,
            format::human(st.total_bytes),
            format::human(used),
            format::human(st.avail_bytes),
            pct
        );
        out.write_all(text.as_bytes()).map_err(|e| io_fail(CMD, e))
    }
}
