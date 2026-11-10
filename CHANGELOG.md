# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - Unreleased

First release.

### Added

- `nfsc exports` (MOUNT EXPORT, like `showmount -e`) and `nfsc rpcinfo`
  (portmap DUMP, like `rpcinfo -p`).
- `nfsc shell` with an interactive REPL, `-c 'cmd; cmd'` scripts, and piped
  scripts on stdin. Targets are `host:/path` or `nfs://host[:port]/path`.
- Shell commands: `ls [-l]`, `dir`, `cd`, `pwd`, `lcd`, `stat`, `get [-r]`,
  `put [-r]`, `cat`, `mkdir`, `rm`, `rmdir`, `mv`, `ln [-s]`, `chmod`,
  `chown`, `df`, `help`, `exit`, `quit`.
- Resumable transfers with `get -c` and `put -c`, a progress line on stderr
  when it is a terminal, and the remote mtime applied on `get`.
- Ctrl-C interrupts a running transfer. Tab completion in the interactive shell.
- NFSv2, NFSv3, and NFSv4.0, 4.1 and 4.2, with `-v auto|2|3|4|4.0|4.1|4.2`
  (`auto` tries 4.2, 4.1, 4.0, 3, then 2).
- TCP and UDP transports (`--proto`), with a per-reply timeout (`--timeout`).
  NFSv4 uses TCP.
- Source-port selection (`--port-mode auto|priv|unpriv`) for `secure` exports.
- AUTH_NONE and AUTH_SYS credentials, with `--uid`, `--gid` and `--gids`.
- `--nfs-port` and `--mount-port` to skip portmap lookups.
- A library crate (`nfsc`): `fs::connect` with version negotiation, and the
  version-agnostic `fs::Filesystem` trait implemented for v2, v3 and v4.
- Live test suites gated by environment variables, a podman-based test
  environment in `testenv/`, and `testenv/run-live.sh` to run them.

### Security

- AUTH_SYS sends the identity the client claims. Servers do not verify it.
  RPCSEC_GSS and Kerberos are not implemented.

### Known limitations

- No NLM or NFSv4 locking, no delegation callbacks, no pNFS.
- NFSv2 is tested only against an in-process fake server.
