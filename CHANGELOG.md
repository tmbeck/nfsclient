# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `get -k` / `--keep-going`: `get -r` and glob gets continue past per-file
  errors, print a summary of failures, and exit non-zero.
- `get -n` / `--no-clobber`: skip files that already exist locally.
- `Error::is_retryable()` classifies transient failures (timeouts, dropped
  connections, JUKEBOX/DELAY, GRACE).
- CI: MSRV (1.85), macOS, `cargo doc -D warnings`, `cargo-deny`, Dependabot,
  and a tag-triggered release workflow building glibc and musl binaries.

### Changed

- `get` downloads into `NAME.nfsc-part` and renames on success. A failed
  download no longer leaves a truncated file under the final name or
  truncates an existing one; `get -c` resumes from the `.part` file.
- `get -r` restores directory modes (minus setuid/setgid/sticky) and mtimes.
- Local write errors (disk full, quota, permission, read-only) are reported
  in plain words.
- A closed stdout pipe (`cat x | head`) ends quietly with status 141.
- The read pipeline returns to pipelined mode after a fallback instead of
  staying one-request-at-a-time for the rest of the file, and reports the
  original error when the fallback also fails.
- NFSv4 grace-period wait follows the server lease (2x, 30s–300s); setup
  (SETCLIENTID, EXCHANGE_ID, CREATE_SESSION) retries DELAY/GRACE.
- NFSv4.1 recovers a lost session with CREATE_SESSION on the existing
  clientid, keeping open state.
- NFS port falls back to 2049 when portmap is unreachable; mountd lookup
  tries the other transport; `-v auto` reports the error from the version
  that got furthest.

### Fixed

- A read that returns no data before EOF is an error, not a silent short
  transfer.
- Decoded XDR arrays bound their preallocation in bytes; a hostile count can
  no longer force a huge allocation.
- Replies already received are kept when the connection drops.
- The privileged-port flag is updated after a reconnect, so the setcap hint
  still appears for `secure` exports.
- NFSv4.0 open-owner seqid is not advanced on errors excluded by RFC 7530
  §9.1.7; BAD_SEQID recovers with a new open-owner.
- NFSv4 OPEN_CONFIRM failure no longer leaks an open; `OPEN_DELEGATE_NONE_EXT`
  (4.1) is decoded; 4.0 lease renewal is tracked only for renewing ops; an
  internal "no free slot" error no longer forces a reconnect.
- NFSv3: FSINFO failure falls back to default sizes; transfer size is
  clamped to rtmax/wtmax; READ replies with count > data are rejected;
  READDIRPLUS falls back to READDIR on TOOSMALL.
- NFSv2 normalizes the mount path like v3.
- Three rustdoc warnings.

## [1.0.0] - 2026-11-09

First release.

### Added

- `nfsc exports` (MOUNT EXPORT, like `showmount -e`) and `nfsc rpcinfo`
  (portmap DUMP, like `rpcinfo -p`).
- `nfsc shell` with an interactive REPL, `-c 'cmd; cmd'` scripts, and piped
  scripts on stdin. Targets are `host:/path` or `nfs://host[:port]/path`.
- Shell commands: `ls [-l]`, `dir`, `cd`, `pwd`, `lcd`, `stat`, `get [-r]`,
  `put [-r]`, `cat`, `mkdir`, `rm`, `rmdir`, `mv`, `ln [-s]`, `chmod`,
  `chown`, `df`, `help`, `exit`, `quit`.
- Resumable transfers with `get -c` and `put -c`, and the remote mtime
  applied on `get`.
- Progress bars on stderr when it is a terminal (rate, ETA). `get -r` and
  `put -r` pre-scan the tree and add a totals bar (files and bytes), then
  print a summary.
- Ctrl-C interrupts a running transfer. Tab completion in the interactive shell.
- NFSv2, NFSv3, and NFSv4.0, 4.1 and 4.2, with `-v auto|2|3|4|4.0|4.1|4.2`
  (`auto` tries 4.2, 4.1, 4.0, 3, then 2).
- TCP and UDP transports (`--proto`), with a per-reply timeout (`--timeout`).
  NFSv4 uses TCP.
- Source-port selection (`--port-mode auto|priv|unpriv`) for `secure` exports.
- AUTH_NONE and AUTH_SYS credentials, with `--uid`, `--gid` and `--gids`.
- `--nfs-port` and `--mount-port` to skip portmap lookups.
- Pipelined bulk READ/WRITE (`Filesystem::read_stream` / `write_stream`) for
  NFSv3 and NFSv4.x: several requests in flight, UNSTABLE writes with COMMIT
  and write-verifier checking, and multiple NFSv4.1+ session slots.
- A library crate (`nfsc`): `fs::connect` with version negotiation, and the
  version-agnostic `fs::Filesystem` trait implemented for v2, v3 and v4.
- Live test suites gated by environment variables, a podman-based test
  environment in `testenv/`, and `testenv/run-live.sh` to run them.

### Security

- AUTH_SYS sends the identity the client claims. Servers do not verify it.
  RPCSEC_GSS and Kerberos are not implemented.
- Downloads treat the server as untrusted: server-supplied names that are
  empty, `.`, `..`, or contain `/` or NUL are skipped; `get -r` detects
  directory cycles and limits depth; local symlinks inside a downloaded tree
  are not followed; setuid/setgid/sticky bits are stripped from downloaded
  files; names, owners and errors from the server are escaped before printing.
- Decoders bound every length prefix and directory listing size, and are
  fuzz-tested against random and truncated input.

### Known limitations

- No NLM or NFSv4 locking, no delegation callbacks, no pNFS.
- NFSv2 is tested only against an in-process fake server.
- UDP and NFSv2 transfers are not pipelined.
- Downloaded file modes are taken from the server (minus setuid/setgid/sticky)
  without applying the local umask.

<!-- TODO: once a remote exists, replace REPO_URL and uncomment:
[Unreleased]: REPO_URL/compare/v1.0.0...HEAD
[1.0.0]: REPO_URL/releases/tag/v1.0.0
-->
