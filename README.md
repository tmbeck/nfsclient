# nfsclient

`nfsclient` is a userspace NFS client for the command line, in the spirit of
`smbclient`. You browse and transfer files on NFS exports without mounting
them. It is pure Rust, runs entirely in user space, and speaks the wire
protocols itself.

## Why

I vibe coded this project to solve a problem I had (scripting the download
of files from an NFS server hosted by proxmox/zfs). I didn't want to
constantly mount and unmount nfs when I knew the path to the file I needed.

`nfsclient` was created in the spirit of `smbclient`. I didn't do an exhaustive
search for a similar solution and it was easier to vibe code one with a
prompt. This version is also portable, which is something I wanted when
using it on some of my old devices.

I didn't exhaustively test it with all versions of NFS; I focused on the
most common ones I had available (v3 and v4). I didn't test all the security
feaures of v4 to validate they work correctly.

- **No mount.** Nothing is added to the kernel's mount table, so no root is
  needed for the kernel client, no `/etc/fstab` entry, and no cleanup.
- **Works where NFS client tools are missing.** A single binary is enough.
- **Scriptable.** `-c` runs a command list, stdin accepts a script, and file
  contents go to stdout, so transfers compose with pipes.

## Features

- Browse exports (`exports`) and portmapper services (`rpcinfo`).
- An interactive shell, or non-interactive `-c` / piped scripts, on any path
  below an export.
- NFSv2, NFSv3 and NFSv4.0 / 4.1 / 4.2, chosen automatically or pinned with
  `-v`. Over TCP and UDP where the protocol allows it.
- Read and write: `ls`, `get`, `put`, `cat`, `mkdir`, `rm`, `rmdir`, `mv`,
  `ln`, `chmod`, `chown`, `stat`, `df`, with recursive `get -r` and `put -r`.
- Resumable transfers (`get -c`, `put -c`), and mtime preserved on `get`.
- Progress bars with rate and ETA; `get -r` / `put -r` add a totals bar for
  the whole tree and print a summary.
- Pipelined READ/WRITE: several requests in flight for NFSv3 and NFSv4.x.
- Concise `--help`, and `help <cmd>` inside the shell, suitable for scripts
  and agents.
- Ctrl-C interrupts a running transfer; tab completion in the interactive shell.
- Source-port control for servers that require reserved ports.
- AUTH_SYS with a chosen uid, gid and supplementary groups.

## Protocol support

| Protocol                     | TCP | UDP | Notes                                                  |
|------------------------------|-----|-----|--------------------------------------------------------|
| NFSv2 (RFC 1094)             | yes | yes | Tested against an in-process fake server only.         |
| NFSv3 (RFC 1813)             | yes | yes | UDP is exercised by the live suites when enabled.      |
| NFSv4.0 (RFC 7530)           | yes | no  | TCP only, as the protocol requires.                    |
| NFSv4.1 (RFC 8881)           | yes | no  | TCP only.                                              |
| NFSv4.2 (RFC 7862)           | yes | no  | TCP only.                                              |
| MOUNT v1 / v3, portmap v2    | yes | yes | Used for `exports`, `rpcinfo` and v2/v3 mounts.        |

`-v auto` (the default) tries NFSv4.2, 4.1, 4.0, then 3, then 2, and uses the
first one the server accepts.

Live testing used:

- Linux kernel nfsd, in a privileged container: NFSv3 and NFSv4.1 / 4.2 over
  TCP. The test host's kernel did not offer NFSv2 or NFSv4.0.
- nfs-ganesha 14, in a privileged container: NFSv3 and NFSv4.0 / 4.1 / 4.2 over
  TCP. Ganesha does not offer UDP.
- An external ZFS storage server, read-only, as a remote target.

The test environment is described in [`testenv/README.md`](testenv/README.md).

## Install

Prebuilt Linux binaries (x86_64 glibc and musl, aarch64 musl) with SHA-256
checksums are attached to each release.

Once published to crates.io, `cargo install nfsclient` works too. To build from a
checkout (requires Rust 1.100.0 or newer, edition 2024):

```sh
cargo install --path .
```

This installs `nfsclient` into `~/.cargo/bin`. To build only the library, without
the command-line dependencies, use `cargo build --no-default-features`.

With [`just`](https://github.com/casey/just), `just install-cap` installs and
also grants the binary `cap_net_bind_service`, so `secure` exports work
without root (see [Privileged source ports](#privileged-source-ports)).

## Quick start

List the exports of a server (like `showmount -e`):

```sh
nfsclient exports nas.example.net
```

List the RPC services the server registers (like `rpcinfo -p`):

```sh
nfsclient rpcinfo nas.example.net
```

Open an interactive shell on an export:

```sh
nfsclient shell nas.example.net:/export
```

Open a shell on a subdirectory with the `nfs://` form and download a file
non-interactively:

```sh
nfsclient shell nfs://nas.example.net/export/dir -c 'get big.iso'
```

Stream a file to another tool without writing it to disk:

```sh
nfsclient shell nas.example.net:/export -c 'cat big.iso' | sha256sum
```

Pin the protocol version:

```sh
nfsclient shell nas.example.net:/export -v 3
```

Read a script from stdin. The process stops at the first failing command:

```sh
printf 'cd backups\nls -l\nget -c db.dump\n' | nfsclient shell nas.example.net:/export
```

### Identity

```sh
nfsclient shell nas.example.net:/export --uid 1000 --gid 100 --gids 4,24,27
```

`--uid`, `--gid` and `--gids` set the AUTH_SYS credentials. The defaults are
the local user, the primary group, and the user's groups.

**AUTH_SYS trusts the identity the client claims.** The server never checks it.
Anyone who can reach the NFS port can send any uid. Use these options only
against servers you trust, on networks you control, or with export options
(such as `root_squash` and host restrictions) that match your threat model.
`nfsclient` does not provide RPCSEC_GSS or Kerberos authentication.

## Privileged source ports

Some exports are marked `secure`. The server then accepts requests only from a
source port below 1024. A normal user cannot bind those ports.

`--port-mode` controls this:

- `auto` (default): try a reserved port, and silently fall back to an
  ephemeral port if the bind is refused. If a server then denies access, the
  error explains that a reserved port may be required.
- `priv`: require a reserved port and fail otherwise.
- `unpriv`: always use an ephemeral port.

To use a `secure` export, choose one of these:

1. Run `nfsclient` as root. This is simple but gives the whole process root.
2. Grant the binary the capability to bind low ports:

   ```sh
   sudo setcap cap_net_bind_service=+ep "$(command -v nfsclient)"
   ```

   The capability is stored on the file. Reinstalling `nfsclient` (for example with
   `cargo install`) replaces the file and drops the capability, so run the
   `setcap` command again after each install or upgrade.

3. Ask the server administrator to add `insecure` to the export. This is
   often the right answer for a home or lab server.

None of these options change the NFS protocol. The server still sees a
normal AUTH_SYS request, only from a reserved source port.

## Shell reference

Paths starting with `/` are relative to the export root. Other paths are
relative to the remote working directory. Use `"double"` or `'single'` quotes,
or `\` to escape spaces. Separate several commands on one line with `;`.

| Command                    | Description                                                            |
|----------------------------|------------------------------------------------------------------------|
| `ls [-l] [path]`           | List a directory, or show a file. `*` and `?` match names. `-l` shows mode, owner, size, time and symlink targets. `dir` is an alias. |
| `cd [path]`                | Change remote directory. No argument goes to the export root.          |
| `pwd`                      | Print the remote working directory.                                    |
| `lcd [path]`               | Change the local working directory. No argument goes to `$HOME`.       |
| `stat path...`             | Show attributes. Symlinks are shown, not followed.                     |
| `get [-r] [-c] remote [local]` | Download. `-r` includes directories. A local name of `-` writes to stdout. `-c` resumes a partial download. The local mtime is set from the remote one. |
| `put [-r] [-c] local [remote]` | Upload. `-r` includes directories. `-c` resumes a partial upload.  |
| `cat path`                 | Write a remote file to stdout.                                         |
| `mkdir path...`            | Create directories.                                                    |
| `rm path...`               | Remove files or symlinks (not directories).                            |
| `rmdir path...`            | Remove empty directories.                                              |
| `mv src dst`               | Rename or move. Moves into `dst` if it is a directory.                 |
| `ln [-s] target name`      | Create a hard link, or a symbolic link with `-s`.                      |
| `chmod mode path...`       | Change permissions. `mode` is octal, for example `644`.                |
| `chown uid[:gid] path...`  | Change owner and group. Numeric IDs only.                              |
| `df [path]`                | Show space on the file system.                                         |
| `help [cmd]`               | Show the command summary, or details for one command.                  |
| `exit`, `quit`             | Leave the shell.                                                       |

Behavior that applies to all commands:

- Interactive: Ctrl-C cancels a running transfer or discards the current line
  and returns to the prompt. Ctrl-D exits. History is kept in
  `$XDG_STATE_HOME/nfsclient/history` (default `~/.local/state/nfsclient/history`).
- `-c 'cmd; cmd'` and piped scripts run commands in order and stop at the
  first failure. `exit` or `quit` ends early with status 0.
- Unknown command names in `-c` are rejected before connecting.
- Progress bars appear on stderr only when stderr is a terminal, so scripts
  and pipes stay clean. Recursive transfers scan the tree first and show a
  totals bar (files and bytes) below the current file's bar.
- `nfsclient shell --help` lists the shell commands, so you can discover them
  without connecting; `-c 'help get'` prints one command's details.
- File data goes to stdout only for `cat` and `get -`. Diagnostics go to stderr.

Global options, given before or after the subcommand:

| Option                              | Default       | Meaning                                              |
|-------------------------------------|---------------|------------------------------------------------------|
| `--uid UID`, `--gid GID`            | local user    | AUTH_SYS identity.                                   |
| `--gids GID,...`                    | user's groups | Supplementary groups (at most 16).                   |
| `--port-mode auto\|priv\|unpriv`    | `auto`        | Source port selection (see above).                   |
| `--proto tcp\|udp`                  | `tcp`         | Transport for the RPC calls.                         |
| `--timeout SECS`                    | `10`          | Wait per reply. For UDP, across all retransmits.     |
| `--nfs-port PORT`                   | portmap       | NFS port. Skips portmap for NFS.                     |
| `--mount-port PORT`                 | portmap       | MOUNT port. Skips portmap for MOUNT.                 |
| `--version`, `--help`               |               | Print the version or help.                           |

Exit status: 0 on success, 1 when a command fails, 2 for invalid command-line
options (clap's usage error), 130 when interrupted with Ctrl-C.

## Library

The library crate is also called `nfsclient`. Its only required dependency is
`socket2`. `fs::connect` negotiates the NFS version, and the `Filesystem`
trait gives one interface across v2, v3 and v4:

```rust
use std::net::IpAddr;

use nfsclient::fs::{self, ConnectOptions};

fn list_export() -> nfsclient::Result<()> {
    let host: IpAddr = "192.0.2.10".parse().expect("literal address");
    let mut conn = fs::connect(host, b"/srv/data", &ConnectOptions::default())?;

    // `conn.remainder` holds the path components below the export root.
    let mut dir = conn.fs.root();
    for part in &conn.remainder {
        dir = conn.fs.lookup(&dir, part)?.0;
    }
    for entry in conn.fs.readdir(&dir)? {
        println!("{}", String::from_utf8_lossy(&entry.name));
    }
    conn.fs.disconnect()
}
```

The example is compiled by `tests/readme_example.rs`. The other methods
(`getattr`, `read`, `write`, `create`, `rename`, and so on) are documented on
the trait in `src/fs.rs`. `ConnectOptions` sets the transport, port mode,
timeout, credentials and version.

## Limitations

- **Authentication:** AUTH_SYS only. No RPCSEC_GSS or Kerberos.
- **Locking:** no NLM and no NFSv4 lock operations. Files are read and written
  without locks.
- **Delegations:** no callback channel. A delegation the server hands out is
  returned at once (DELEGRETURN), so nothing is cached under one.
- **NFSv2:** tested only against an in-process fake server. Modern servers
  rarely offer it.
- **pNFS:** not supported. All I/O goes to the server that serves the path.
- **NFSv4 owner names:** an owner string of the form `user@domain` maps to the
  uid `4294967295` (`u32::MAX`). The original string is kept in the attributes.
  Numeric owner strings map to their number.
- **UDP:** NFSv2, NFSv3 and the MOUNT and portmap services. NFSv4 requires TCP.

## Development

Common tasks are in the [`justfile`](justfile); run `just` to list them.

| Recipe                      | What it does                                                   |
|-----------------------------|----------------------------------------------------------------|
| `just build` / `just release` | Debug or optimized build.                                    |
| `just test [ARGS]`          | Offline tests (`cargo test`); live suites skip themselves.     |
| `just lint`                 | `cargo fmt --check`, clippy with `-D warnings`, library-only build. |
| `just ci`                   | `lint` then `test`, as CI runs them.                           |
| `just fmt`                  | Format the code.                                               |
| `just install`              | `cargo install --path .`                                       |
| `just setcap` / `just install-cap` | Grant `cap_net_bind_service` (sudo), optionally after installing. |
| `just testenv-up [all\|knfsd\|ganesha]` | Start the podman NFS test servers.                |
| `just testenv-down [...]`   | Stop them.                                                     |
| `just live [--sudo] [--no-lease]` | Run every live suite against the test servers.           |
| `just bench host:/export/dir/file [vers] [MiB]` | Read-only throughput benchmark, sequential vs pipelined. |
| `just clean`                | `cargo clean`.                                                 |

The test-server env file defaults to `testenv/testenv.env` (gitignored);
set `NFSC_TESTENV_FILE` to use another path.

## Testing

Unit and offline tests run with `just test` (plain `cargo test`). Live tests
need servers and skip themselves unless their environment variables are set.
The `testenv/` directory starts local NFS servers in podman containers, and
`testenv/run-live.sh` runs the live suites against them:

```sh
just testenv-up          # testenv/up.sh
just live --no-lease     # testenv/run-live.sh testenv/testenv.env
```

See [`testenv/README.md`](testenv/README.md) for the servers, the environment
variables, and the `--sudo` mode for privileged-port checks.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
