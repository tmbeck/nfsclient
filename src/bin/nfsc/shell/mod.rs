//! `nfsc shell`: connect to an export path, then run commands interactively,
//! from `-c`, or from a pipe.
//!
//! - Interactive (stdin is a terminal, no `-c`): rustyline with history. An
//!   error in one command is printed and the shell continues.
//! - `-c 'cmd; cmd'` and piped stdin: commands run in order and the process
//!   stops at the first failure (like `set -e`), exiting with status 1. `exit`
//!   or `quit` ends early with status 0. Unknown command names in `-c` are
//!   rejected before connecting.

mod format;
mod line;
mod ops;
mod session;
#[cfg(test)]
mod tests;
mod transfer;

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use nfsc::fs::ConnectOptions;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use crate::cli::{self, CmdError, Globals, ShellArgs};
use crate::target;
use session::{Flow, Session, check_command};

pub fn run(g: &Globals, args: &ShellArgs) -> Result<(), CmdError> {
    let target = target::parse_target(&args.target).map_err(CmdError::Failed)?;
    let script = match &args.command {
        Some(text) => Some(line::parse_script(text).map_err(CmdError::Failed)?),
        None => None,
    };
    if let Some(cmds) = &script {
        for words in cmds {
            check_command(words).map_err(CmdError::Failed)?;
        }
    }
    let nfs_port = match (target.port, g.nfs_port) {
        (Some(a), Some(b)) if a != b => {
            return Err(CmdError::Failed(format!(
                "conflicting ports: {a} in the target and {b} from --nfs-port"
            )));
        }
        (a, b) => a.or(b),
    };
    let ip = cli::resolve(&target.host)?;
    let opts = ConnectOptions {
        rpc: cli::rpc_options(g, cli::sys_auth(g)?),
        nfs_port,
        mount_port: g.mount_port,
        version: args.nfs_version.into(),
    };
    let located = |e: nfsc::Error| CmdError::Failed(format!("{}: {e}", target.path));
    let conn = nfsc::fs::connect(ip, target.path.as_bytes(), &opts).map_err(located)?;
    let label = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    let mut sess = Session::new(conn.fs, label, conn.export, &conn.remainder).map_err(located)?;
    sess.progress = io::stderr().is_terminal();

    if let Some(cmds) = script {
        return run_script(&mut sess, &cmds).map(|_| ());
    }
    if io::stdin().is_terminal() {
        eprintln!("{}", sess.banner());
        return interactive(&mut sess);
    }
    run_piped(&mut sess)
}

/// Runs parsed commands in order on the process's stdout and stderr.
fn run_script(sess: &mut Session, cmds: &[Vec<String>]) -> Result<Flow, CmdError> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let (mut out, mut err) = (stdout.lock(), stderr.lock());
    run_script_to(sess, cmds, &mut out, &mut err)
}

/// Runs parsed commands in order. Returns `Ok(Flow::Exit)` on `exit`, and
/// `Err(Reported(1))` after writing the first failure to `err`.
fn run_script_to(
    sess: &mut Session,
    cmds: &[Vec<String>],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Flow, CmdError> {
    for words in cmds {
        match sess.execute(words, out, err) {
            Ok(Flow::Continue) => {}
            Ok(Flow::Exit) => return Ok(Flow::Exit),
            Err(failure) => {
                let _ = writeln!(err, "{failure}");
                return Err(CmdError::Reported(1));
            }
        }
    }
    Ok(Flow::Continue)
}

/// Reads script lines from stdin with the same stop-at-first-failure rule as `-c`.
fn run_piped(sess: &mut Session) -> Result<(), CmdError> {
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| CmdError::Failed(e.to_string()))?;
        let cmds = line::parse_script(&line).map_err(CmdError::Failed)?;
        if run_script(sess, &cmds)? == Flow::Exit {
            break;
        }
    }
    Ok(())
}

fn interactive(sess: &mut Session) -> Result<(), CmdError> {
    let mut editor = DefaultEditor::new().map_err(|e| CmdError::Failed(e.to_string()))?;
    let history = history_path();
    if let Some(path) = &history {
        let _ = editor.load_history(path);
    }
    let result = interactive_loop(sess, &mut editor);
    if let Some(path) = &history {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = editor.save_history(path);
    }
    result
}

fn interactive_loop(sess: &mut Session, editor: &mut DefaultEditor) -> Result<(), CmdError> {
    loop {
        let line = match editor.readline(&sess.prompt()) {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => return Ok(()),
            Err(e) => return Err(CmdError::Failed(e.to_string())),
        };
        if !line.trim().is_empty() {
            let _ = editor.add_history_entry(line.as_str());
        }
        let cmds = match line::parse_script(&line) {
            Ok(cmds) => cmds,
            Err(msg) => {
                eprintln!("nfsc: {msg}");
                continue;
            }
        };
        for words in &cmds {
            let stdout = io::stdout();
            let stderr = io::stderr();
            match sess.execute(words, &mut stdout.lock(), &mut stderr.lock()) {
                Ok(Flow::Continue) => {}
                Ok(Flow::Exit) => return Ok(()),
                Err(failure) => eprintln!("{failure}"),
            }
        }
    }
}

/// `$XDG_STATE_HOME/nfsc/history`, or `~/.local/state/nfsc/history`.
fn history_path() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(state.join("nfsc").join("history"))
}
