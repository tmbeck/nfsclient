//! Argument definitions, option building and subcommand dispatch.

use std::io::{self, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use nfsc::fs::{NfsVersion, VersionPref};
use nfsc::portmap;
use nfsc::rpc::{Auth, PortMode, Proto, RpcOptions};

use crate::exports;
use crate::rpcinfo::{self, ServiceNames};
use crate::shell;

/// Unix AUTH_SYS limit on supplementary groups.
const MAX_GIDS: usize = 16;

#[derive(Parser, Debug)]
#[command(
    name = "nfsc",
    version,
    about = "Userspace NFS client: browse and transfer files without mounting",
    after_help = "\
Examples:
  nfsc shell nas:/srv/backups                       open an interactive shell
  nfsc shell nfs://nas/srv/backups -c 'get -c vm.img ./vm.img'
  nfsc exports nas                                  list exports (showmount -e)
  nfsc rpcinfo nas                                  list portmapper services (rpcinfo -p)

Exit status: 0 success; 1 a command failed; 2 bad command line;
130 interrupted with Ctrl-C.

Run 'nfsc <command> --help' for the options of each command."
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Globals,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
pub struct Globals {
    /// AUTH_SYS uid (default: the current user)
    #[arg(long, global = true, value_name = "UID")]
    pub uid: Option<u32>,

    /// AUTH_SYS gid (default: the current user's primary group)
    #[arg(long, global = true, value_name = "GID")]
    pub gid: Option<u32>,

    /// AUTH_SYS supplementary gids, comma separated (default: the current user's groups)
    #[arg(long, global = true, value_name = "GID,...", value_delimiter = ',')]
    pub gids: Option<Vec<u32>>,

    /// Source port selection: auto (reserved, falling back to ephemeral), priv, unpriv
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "MODE",
        default_value = "auto"
    )]
    pub port_mode: PortModeArg,

    /// Transport for RPC calls
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "PROTO",
        default_value = "tcp"
    )]
    pub proto: ProtoArg,

    /// Seconds to wait for each reply (UDP: across all retransmits)
    #[arg(long, global = true, value_name = "SECS", default_value = "10", value_parser = parse_timeout)]
    pub timeout: Duration,

    /// NFS server port; skips portmap for NFS (a port in an nfs:// target wins if equal)
    #[arg(long, global = true, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub nfs_port: Option<u16>,

    /// MOUNT server port; skips portmap for MOUNT (used by `exports` and `shell`)
    #[arg(long, global = true, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub mount_port: Option<u16>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Interactive shell on a path below an export, or run -c commands and exit
    #[command(after_long_help = "\
Interactive use: Tab completes command names, remote and local paths, and
flags. Ctrl-C stops a running transfer (a partial download is removed unless
-c is given) and returns to the prompt; at the prompt it clears the line.
Ctrl-D leaves the shell. Type 'help' at the prompt for the command list.

Scripted use: -c, or commands piped on stdin, stop at the first failure.

Exit status: 0 success, or 'exit' / 'quit'; 1 a command failed; 130 Ctrl-C.

Examples:
  nfsc shell nas:/srv/backups
  nfsc shell nfs://nas/srv/backups -c 'get -c vm.img ./vm.img; ls -l'
  nfsc shell nas:/srv/iso -v 4.1 -c 'ls'")]
    Shell(ShellArgs),
    /// List the exports of a server (MOUNT EXPORT, like showmount -e)
    Exports(HostArgs),
    /// List the RPC services registered with the portmapper (rpcinfo -p)
    Rpcinfo(HostArgs),
}

#[derive(Args, Debug)]
pub struct ShellArgs {
    /// nfs://host[:port]/path or host:/path (the full server path, e.g. /srv/data/x)
    pub target: String,

    /// Run these commands separated by ';' and exit. Stops at the first failure
    /// (status 1), or at Ctrl-C (status 130). 'exit' or 'quit' ends early with status 0.
    #[arg(short = 'c', long = "command", value_name = "CMDS")]
    pub command: Option<String>,

    /// NFS protocol version to use
    #[arg(
        short = 'v',
        long = "nfs-version",
        value_enum,
        value_name = "VERS",
        default_value = "auto"
    )]
    pub nfs_version: NfsVersionArg,
}

#[derive(Args, Debug)]
pub struct HostArgs {
    /// Server name or address
    pub host: String,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortModeArg {
    Auto,
    Priv,
    Unpriv,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoArg {
    Tcp,
    Udp,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfsVersionArg {
    #[value(name = "2")]
    V2,
    #[value(name = "3")]
    V3,
    /// Any NFSv4 minor version, highest first
    #[value(name = "4")]
    V4,
    #[value(name = "4.0")]
    V40,
    #[value(name = "4.1")]
    V41,
    #[value(name = "4.2")]
    V42,
    #[value(name = "auto")]
    Auto,
}

impl From<NfsVersionArg> for VersionPref {
    fn from(v: NfsVersionArg) -> Self {
        match v {
            NfsVersionArg::V2 => VersionPref::Exact(NfsVersion::V2),
            NfsVersionArg::V3 => VersionPref::Exact(NfsVersion::V3),
            NfsVersionArg::V4 => VersionPref::AnyV4,
            NfsVersionArg::V40 => VersionPref::Exact(NfsVersion::V4(0)),
            NfsVersionArg::V41 => VersionPref::Exact(NfsVersion::V4(1)),
            NfsVersionArg::V42 => VersionPref::Exact(NfsVersion::V4(2)),
            NfsVersionArg::Auto => VersionPref::Auto,
        }
    }
}

/// Failure of a subcommand, mapped to the process exit status in `main`.
#[derive(Debug)]
pub enum CmdError {
    /// Printed as `nfsc: <message>`, exit 1.
    Failed(String),
    /// Already reported on stderr; exit with this status and print nothing more.
    Reported(u8),
}

impl From<nfsc::Error> for CmdError {
    fn from(e: nfsc::Error) -> Self {
        CmdError::Failed(e.to_string())
    }
}

fn parse_timeout(s: &str) -> Result<Duration, String> {
    let secs: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a number of seconds"))?;
    Duration::try_from_secs_f64(secs)
        .ok()
        .filter(|d| !d.is_zero())
        .ok_or_else(|| format!("timeout must be a positive number of seconds, got '{s}'"))
}

impl From<PortModeArg> for PortMode {
    fn from(p: PortModeArg) -> Self {
        match p {
            PortModeArg::Auto => PortMode::Auto,
            PortModeArg::Priv => PortMode::Privileged,
            PortModeArg::Unpriv => PortMode::Unprivileged,
        }
    }
}

impl From<ProtoArg> for Proto {
    fn from(p: ProtoArg) -> Self {
        match p {
            ProtoArg::Tcp => Proto::Tcp,
            ProtoArg::Udp => Proto::Udp,
        }
    }
}

/// Transport, port mode and timeout from the global options, with the given credentials.
pub fn rpc_options(g: &Globals, auth: Auth) -> RpcOptions {
    RpcOptions {
        proto: g.proto.into(),
        port_mode: g.port_mode.into(),
        timeout: g.timeout,
        auth,
    }
}

/// AUTH_SYS credentials: the process identity with any --uid/--gid/--gids overrides.
pub fn sys_auth(g: &Globals) -> Result<Auth, CmdError> {
    apply_overrides(Auth::sys_from_process(), g.uid, g.gid, g.gids.as_deref())
}

fn apply_overrides(
    base: Auth,
    uid: Option<u32>,
    gid: Option<u32>,
    gids: Option<&[u32]>,
) -> Result<Auth, CmdError> {
    if let Some(g) = gids.filter(|g| g.len() > MAX_GIDS) {
        return Err(CmdError::Failed(format!(
            "--gids takes at most {MAX_GIDS} groups, got {}",
            g.len()
        )));
    }
    match base {
        Auth::Sys {
            stamp,
            machine_name,
            uid: buid,
            gid: bgid,
            gids: bgids,
        } => Ok(Auth::Sys {
            stamp,
            machine_name,
            uid: uid.unwrap_or(buid),
            gid: gid.unwrap_or(bgid),
            gids: gids.map(<[u32]>::to_vec).unwrap_or(bgids),
        }),
        other => Ok(other),
    }
}

pub fn run(cli: &Cli) -> Result<(), CmdError> {
    let g = &cli.global;
    match &cli.command {
        Command::Rpcinfo(args) => rpcinfo(g, &args.host),
        Command::Exports(args) => exports::run(g, &args.host),
        Command::Shell(args) => shell::run(g, args),
    }
}

/// Resolves `host` to its first address, accepting `[v6]` brackets.
pub fn resolve(host: &str) -> Result<IpAddr, CmdError> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    (bare, portmap::PORT)
        .to_socket_addrs()
        .map_err(|e| CmdError::Failed(format!("cannot resolve '{host}': {e}")))?
        .next()
        .map(|sa| sa.ip())
        .ok_or_else(|| CmdError::Failed(format!("cannot resolve '{host}': no addresses")))
}

fn rpcinfo(g: &Globals, host: &str) -> Result<(), CmdError> {
    let ip = resolve(host)?;
    // Portmap calls always use AUTH_NONE, so no credentials are built here.
    let opts = rpc_options(g, Auth::None);
    let mappings = portmap::dump(ip, &opts)?;
    let table = rpcinfo::format_table(&mappings, &ServiceNames::load());
    io::stdout()
        .lock()
        .write_all(table.as_bytes())
        .map_err(|e| CmdError::Failed(format!("write failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("nfsc").chain(args.iter().copied()))
    }

    #[test]
    fn rpcinfo_defaults() {
        let cli = parse(&["rpcinfo", "nas"]).unwrap();
        assert!(matches!(&cli.command, Command::Rpcinfo(h) if h.host == "nas"));
        assert_eq!(cli.global.proto, ProtoArg::Tcp);
        assert_eq!(cli.global.port_mode, PortModeArg::Auto);
        assert_eq!(cli.global.timeout, Duration::from_secs(10));
        assert_eq!(cli.global.uid, None);
    }

    #[test]
    fn globals_work_before_and_after_subcommand() {
        let a = parse(&["--proto", "udp", "rpcinfo", "nas"]).unwrap();
        let b = parse(&["rpcinfo", "nas", "--proto", "udp", "--timeout", "2.5"]).unwrap();
        assert_eq!(a.global.proto, ProtoArg::Udp);
        assert_eq!(b.global.proto, ProtoArg::Udp);
        assert_eq!(b.global.timeout, Duration::from_millis(2500));
    }

    #[test]
    fn identity_flags() {
        let cli = parse(&[
            "--uid", "1000", "--gid", "100", "--gids", "4,24,27", "exports", "nas",
        ])
        .unwrap();
        assert_eq!(cli.global.uid, Some(1000));
        assert_eq!(cli.global.gid, Some(100));
        assert_eq!(cli.global.gids, Some(vec![4, 24, 27]));
        assert!(matches!(cli.command, Command::Exports(_)));
    }

    #[test]
    fn port_mode_values() {
        for (v, want) in [
            ("auto", PortModeArg::Auto),
            ("priv", PortModeArg::Priv),
            ("unpriv", PortModeArg::Unpriv),
        ] {
            let cli = parse(&["--port-mode", v, "rpcinfo", "nas"]).unwrap();
            assert_eq!(cli.global.port_mode, want);
        }
        assert!(parse(&["--port-mode", "root", "rpcinfo", "nas"]).is_err());
    }

    #[test]
    fn rejects_bad_timeouts_and_protos() {
        assert!(parse(&["--timeout", "0", "rpcinfo", "nas"]).is_err());
        assert!(parse(&["--timeout", "-1", "rpcinfo", "nas"]).is_err());
        assert!(parse(&["--timeout", "soon", "rpcinfo", "nas"]).is_err());
        assert!(parse(&["--proto", "sctp", "rpcinfo", "nas"]).is_err());
    }

    #[test]
    fn shell_args() {
        let cli = parse(&["shell", "nfs://nas/export", "-c", "ls; pwd", "-v", "3"]).unwrap();
        match cli.command {
            Command::Shell(s) => {
                assert_eq!(s.target, "nfs://nas/export");
                assert_eq!(s.command.as_deref(), Some("ls; pwd"));
                assert_eq!(s.nfs_version, NfsVersionArg::V3);
            }
            other => panic!("unexpected {other:?}"),
        }
        let cli = parse(&["shell", "nas:/export"]).unwrap();
        match cli.command {
            Command::Shell(s) => {
                assert_eq!(s.command, None);
                assert_eq!(s.nfs_version, NfsVersionArg::Auto);
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(parse(&["shell", "nas:/export", "-v", "5"]).is_err());
        assert!(parse(&["shell", "nas:/export", "-v", "4.3"]).is_err());
        assert!(parse(&["shell"]).is_err());
    }

    #[test]
    fn only_three_subcommands() {
        assert!(parse(&["mount", "nas"]).is_err());
        assert!(parse(&["ls", "nas"]).is_err());
        assert!(parse(&["exports"]).is_err());
        assert!(parse(&["rpcinfo"]).is_err());
    }

    #[test]
    fn overrides_replace_only_given_fields() {
        let base = Auth::Sys {
            stamp: 7,
            machine_name: "host".into(),
            uid: 1000,
            gid: 100,
            gids: vec![4, 24],
        };
        assert_eq!(
            apply_overrides(base.clone(), None, None, None).unwrap(),
            base
        );
        assert_eq!(
            apply_overrides(base.clone(), Some(0), None, Some(&[27])).unwrap(),
            Auth::Sys {
                stamp: 7,
                machine_name: "host".into(),
                uid: 0,
                gid: 100,
                gids: vec![27],
            }
        );
        let too_many: Vec<u32> = (0..17).collect();
        assert!(apply_overrides(base, None, None, Some(&too_many)).is_err());
    }

    #[test]
    fn overrides_leave_non_sys_untouched() {
        assert_eq!(
            apply_overrides(Auth::None, Some(1), None, None).unwrap(),
            Auth::None
        );
    }
}
