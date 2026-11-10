//! Argument definitions, option building and subcommand dispatch.

use std::io::{self, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use nfsc::fs::{NfsVersion, VersionPref};
use nfsc::portmap;
use nfsc::rpc::{Auth, PortMode, Proto, RetryEvent, RetryPolicy, RpcOptions};
use std::sync::Arc;

use crate::exports;
use crate::rpcinfo::{self, ServiceNames};
use crate::shell;

/// Unix AUTH_SYS limit on supplementary groups.
const MAX_GIDS: usize = 16;

#[derive(Parser, Debug)]
#[command(
    name = "nfsc",
    version,
    about = "Userspace NFS client (v2/v3/v4.x): browse and transfer files without mounting",
    disable_help_subcommand = true,
    after_help = "\
Global options (before or after the command):
  --uid N, --gid N, --gids N,..  AUTH_SYS identity [current user]
  --port-mode auto|priv|unpriv   source port [auto]; see 'Permission denied' below
  --proto tcp|udp                transport [tcp]; NFSv4 is TCP only
  --timeout SECS                 per-reply timeout [10]
  --retry-time SECS              keep retrying a failed call this long [300]; 0 = off
  --nfs-port P, --mount-port P   skip portmap lookups
Each also reads NFSC_<NAME> from the environment (NFSC_UID, NFSC_TIMEOUT,
NFSC_PORT_MODE, ...); the command line wins.

Permission denied on 'secure' exports: the server wants a source port <1024.
  sudo setcap cap_net_bind_service=+ep \"$(command -v nfsc)\"   (once per install)

Exit status: 0 ok, 1 command failed, 2 usage error, 130 Ctrl-C.
More: nfsc <command> --help"
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
    #[arg(long, global = true, hide = true, value_name = "UID", env = "NFSC_UID")]
    pub uid: Option<u32>,

    /// AUTH_SYS gid (default: the current user's primary group)
    #[arg(long, global = true, hide = true, value_name = "GID", env = "NFSC_GID")]
    pub gid: Option<u32>,

    /// AUTH_SYS supplementary gids, comma separated (default: the current user's groups)
    #[arg(
        long,
        global = true,
        hide = true,
        value_name = "GID,...",
        value_delimiter = ',',
        env = "NFSC_GIDS"
    )]
    pub gids: Option<Vec<u32>>,

    /// Source port selection: auto (reserved, falling back to ephemeral), priv, unpriv
    #[arg(
        long,
        global = true,
        hide = true,
        value_enum,
        value_name = "MODE",
        default_value = "auto",
        env = "NFSC_PORT_MODE"
    )]
    pub port_mode: PortModeArg,

    /// Transport for RPC calls
    #[arg(
        long,
        global = true,
        hide = true,
        value_enum,
        value_name = "PROTO",
        default_value = "tcp",
        env = "NFSC_PROTO"
    )]
    pub proto: ProtoArg,

    /// Seconds to wait for each reply (UDP: across all retransmits)
    #[arg(long, global = true, hide = true, value_name = "SECS", default_value = "10", value_parser = parse_timeout, env = "NFSC_TIMEOUT")]
    pub timeout: Duration,

    /// Seconds to keep retrying a failed call (server down, stalled, JUKEBOX/DELAY); 0 disables
    #[arg(long, global = true, hide = true, value_name = "SECS", default_value = "300", value_parser = parse_retry_time, env = "NFSC_RETRY_TIME")]
    pub retry_time: Duration,

    /// NFS server port; skips portmap for NFS (a port in an nfs:// target wins if equal)
    #[arg(long, global = true, hide = true, value_name = "PORT", env = "NFSC_NFS_PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub nfs_port: Option<u16>,

    /// MOUNT server port; skips portmap for MOUNT (used by `exports` and `shell`)
    #[arg(long, global = true, hide = true, value_name = "PORT", env = "NFSC_MOUNT_PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub mount_port: Option<u16>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Open a shell on host:/path, or run commands with -c and exit
    #[command(after_help = crate::shell::CLI_HELP)]
    Shell(ShellArgs),
    /// List a server's exports (like showmount -e)
    #[command(after_help = "Global options: nfsc --help")]
    Exports(HostArgs),
    /// List RPC services registered with portmap (like rpcinfo -p)
    #[command(after_help = "Global options: nfsc --help")]
    Rpcinfo(HostArgs),
}

#[derive(Args, Debug)]
pub struct ShellArgs {
    /// host:/path or nfs://host[:port]/path (full server path)
    pub target: String,

    /// Run ';'-separated commands and exit; stops at the first failure
    #[arg(short = 'c', long = "command", value_name = "CMDS")]
    pub command: Option<String>,

    /// 2|3|4|4.0|4.1|4.2|auto (4: highest v4 minor; auto: 4.2 down to 2)
    #[arg(
        short = 'v',
        long = "nfs-version",
        value_enum,
        value_name = "VERS",
        default_value = "auto",
        env = "NFSC_VERS",
        hide_possible_values = true,
        hide_env_values = true
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

fn parse_retry_time(s: &str) -> Result<Duration, String> {
    let secs: f64 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a number of seconds"))?;
    Duration::try_from_secs_f64(secs)
        .map_err(|_| format!("retry time must be zero or a positive number of seconds, got '{s}'"))
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
        retry: RetryPolicy {
            budget: g.retry_time,
            on_retry: Some(Arc::new(report_retry)),
            ..RetryPolicy::default()
        },
    }
}

/// Retry notices with the same text are shown at most once per this interval,
/// so several pipelined requests failing together give one line, not dozens.
const RETRY_NOTE_INTERVAL: Duration = Duration::from_secs(2);

/// Thins out repeated retry notices; see [`RetryNotes::render`].
struct RetryNotes {
    /// What was printed last (without numbers) and when.
    last: Option<(String, Instant)>,
    /// Notices dropped since the last printed one.
    suppressed: u32,
}

static RETRY_NOTES: Mutex<RetryNotes> = Mutex::new(RetryNotes {
    last: None,
    suppressed: 0,
});

impl RetryNotes {
    /// The line to print for `ev` at `now`, or `None` when it repeats the
    /// previous notice within [`RETRY_NOTE_INTERVAL`]. Giving up is reported
    /// by the failing command itself, with the path, so it prints nothing.
    fn render(&mut self, ev: &RetryEvent<'_>, now: Instant) -> Option<String> {
        let (key, line) = match ev {
            RetryEvent::Retrying {
                op,
                error,
                delay,
                elapsed,
                budget,
                ..
            } => (
                format!("retry {op}: {error}"),
                format!(
                    "nfsc: {op}: {error}; retrying in {:.1}s ({:.0}s of {:.0}s)",
                    delay.as_secs_f64(),
                    elapsed.as_secs_f64(),
                    budget.as_secs_f64()
                ),
            ),
            RetryEvent::Recovered {
                op,
                attempts,
                elapsed,
            } => (
                format!("recovered {op}"),
                format!(
                    "nfsc: {op}: recovered after {attempts} attempts ({:.1}s)",
                    elapsed.as_secs_f64()
                ),
            ),
            RetryEvent::GaveUp { .. } => return None,
        };
        if let Some((k, at)) = &self.last
            && *k == key
            && now.saturating_duration_since(*at) < RETRY_NOTE_INTERVAL
        {
            self.suppressed += 1;
            return None;
        }
        let line = match self.suppressed {
            0 => line,
            n => format!(
                "{line} [{n} repeated notice{} not shown]",
                if n == 1 { "" } else { "s" }
            ),
        };
        self.suppressed = 0;
        self.last = Some((key, now));
        Some(line)
    }
}

/// Prints retry progress on stderr so a stalled transfer is visibly waiting,
/// not frozen. While progress bars are drawn the line goes above them;
/// otherwise (no terminal, cron) it is a plain line.
fn report_retry(ev: &RetryEvent<'_>) {
    let line = match RETRY_NOTES.lock() {
        Ok(mut notes) => notes.render(ev, Instant::now()),
        Err(_) => None,
    };
    if let Some(line) = line {
        shell::status_line(&line);
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

    #[test]
    fn retry_notices_render_and_repeats_are_thinned() {
        let mut notes = RetryNotes {
            last: None,
            suppressed: 0,
        };
        let error = nfsc::Error::Timeout;
        let retrying = RetryEvent::Retrying {
            op: "READ",
            attempt: 2,
            error: &error,
            delay: Duration::from_secs(4),
            elapsed: Duration::from_secs(1),
            budget: Duration::from_secs(120),
        };
        let t0 = Instant::now();
        assert_eq!(
            notes.render(&retrying, t0).as_deref(),
            Some("nfsc: READ: RPC timed out; retrying in 4.0s (1s of 120s)")
        );
        // The same notice from other in-flight requests is dropped and counted.
        assert!(
            notes
                .render(&retrying, t0 + Duration::from_millis(100))
                .is_none()
        );
        assert!(
            notes
                .render(&retrying, t0 + Duration::from_millis(200))
                .is_none()
        );
        let later = notes
            .render(&retrying, t0 + Duration::from_secs(3))
            .unwrap();
        assert!(later.ends_with("[2 repeated notices not shown]"), "{later}");
        let recovered = RetryEvent::Recovered {
            op: "READ",
            attempts: 3,
            elapsed: Duration::from_millis(4500),
        };
        assert_eq!(
            notes
                .render(&recovered, t0 + Duration::from_secs(3))
                .as_deref(),
            Some("nfsc: READ: recovered after 3 attempts (4.5s)")
        );
        let gave_up = RetryEvent::GaveUp {
            op: "READ",
            attempts: 9,
            error: &error,
            elapsed: Duration::from_secs(120),
        };
        assert!(
            notes
                .render(&gave_up, t0 + Duration::from_secs(9))
                .is_none()
        );
    }

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

    /// Child half of [`env_vars_set_globals`]: only does work when the parent
    /// started it with the NFSC_* variables set.
    #[test]
    fn env_child() {
        if std::env::var_os("NFSC_CLI_ENV_CHILD").is_none() {
            return;
        }
        let cli = parse(&["rpcinfo", "nas"]).unwrap();
        assert_eq!(cli.global.uid, Some(4242));
        assert_eq!(cli.global.gids, Some(vec![5, 6]));
        assert_eq!(cli.global.timeout, Duration::from_millis(2500));
        assert_eq!(cli.global.proto, ProtoArg::Udp);
        // The command line wins over the environment.
        let cli = parse(&["--uid", "7", "--timeout", "3", "rpcinfo", "nas"]).unwrap();
        assert_eq!(cli.global.uid, Some(7));
        assert_eq!(cli.global.timeout, Duration::from_secs(3));
        let cli = parse(&["shell", "nas:/x"]).unwrap();
        assert!(matches!(cli.command, Command::Shell(s) if s.nfs_version == NfsVersionArg::V3));
    }

    /// NFSC_* variables provide defaults. Setting them in this process would
    /// race with the other tests, so the check runs in a child test process.
    #[test]
    fn env_vars_set_globals() {
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args(["--exact", "cli::tests::env_child", "--nocapture"])
            .env("NFSC_CLI_ENV_CHILD", "1")
            .env("NFSC_UID", "4242")
            .env("NFSC_GIDS", "5,6")
            .env("NFSC_TIMEOUT", "2.5")
            .env("NFSC_PROTO", "udp")
            .env("NFSC_VERS", "3")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(text.contains("1 passed"), "the child test ran: {text}");

        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args(["--exact", "cli::tests::env_child"])
            .env("NFSC_CLI_ENV_CHILD", "1")
            .env("NFSC_UID", "4242")
            .env("NFSC_TIMEOUT", "0")
            .output()
            .unwrap();
        assert!(!out.status.success(), "a bad NFSC_TIMEOUT is rejected");
    }

    #[test]
    fn overrides_leave_non_sys_untouched() {
        assert_eq!(
            apply_overrides(Auth::None, Some(1), None, None).unwrap(),
            Auth::None
        );
    }
}
