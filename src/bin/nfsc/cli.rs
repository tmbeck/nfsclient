//! Argument definitions, option building and subcommand dispatch.

use std::io::{self, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use nfsc::portmap;
use nfsc::rpc::{Auth, PortMode, Proto, RpcOptions};

use crate::rpcinfo::{self, ServiceNames};
use crate::target;

/// Unix AUTH_SYS limit on supplementary groups.
const MAX_GIDS: usize = 16;

#[derive(Parser, Debug)]
#[command(
    name = "nfsc",
    version,
    about = "Userspace NFS client: browse and transfer files without mounting"
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
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Interactive shell on an export, or run -c commands and exit
    Shell(ShellArgs),
    /// List the exports of a server (MOUNT EXPORT)
    Exports(HostArgs),
    /// List the RPC services registered with the portmapper (rpcinfo -p)
    Rpcinfo(HostArgs),
}

#[derive(Args, Debug)]
pub struct ShellArgs {
    /// nfs://host[:port]/export[/path] or host:/export[/path]
    pub target: String,

    /// Run these commands separated by ';' and exit
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
    #[value(name = "auto")]
    Auto,
}

/// Failure of a subcommand, mapped to the process exit status in `main`.
#[derive(Debug)]
pub enum CmdError {
    /// Subcommand exists but is not built yet (exit 2).
    NotImplemented(&'static str),
    /// Any other failure (exit 1).
    Failed(String),
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
#[allow(dead_code)] // used by exports and shell in later milestones
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
        Command::Exports(_) => Err(CmdError::NotImplemented("exports")),
        Command::Shell(args) => {
            // Reject a malformed target before reporting the missing feature.
            target::parse_target(&args.target).map_err(CmdError::Failed)?;
            Err(CmdError::NotImplemented("shell"))
        }
    }
}

/// Resolves `host` to its first address, accepting `[v6]` brackets.
fn resolve(host: &str) -> Result<IpAddr, CmdError> {
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
        assert!(parse(&["shell", "nas:/export", "-v", "4"]).is_err());
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
