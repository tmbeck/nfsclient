# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.1] - 2026-11-10

### Added

- `put` is atomic: uploads go to `NAME.nfsc-part` on the server and are
  renamed over `NAME` on success. `put -c` resumes the remote part after
  comparing the whole uploaded prefix with the local file, so a hole left by
  a failed pipelined write is caught. `put -V` re-reads and compares SHA-256.
- `get -p` / `--preserve` keeps the server's mode bits.
- Connecting retries while the server is down or rebooting: the whole
  version negotiation is repeated under one retry budget, and "version not
  offered" answers still fall through immediately.
- `Connected::fs` is `Box<dyn Filesystem + Send>`.
- In-process fake NFSv4.0/4.1/4.2 server with fault injection (DELAY, GRACE,
  reboot with grace period, BADSESSION, STALE_CLIENTID, lease expiry, lost
  and truncated replies, knfsd-like and fully caching reply caches) and a
  55-test backend suite; `tests/connect_retry.rs`.
- Chaos proxy (resets, half-closes, stalls, latency, bandwidth caps,
  refused connections) and a live soak suite (`just soak [MiB]`): 1 GiB
  reads and writes over NFSv3 and NFSv4.0/4.1/4.2, CLI `get -cV`, and
  SIGINT-then-resume, verified byte for byte against kernel nfsd and
  nfs-ganesha.

### Changed

- `get` applies the local umask to downloaded files and directories (like
  `cp`); use `-p` for the previous behaviour.
- NFSv4 reconnects keep client state: the client verifier is fixed for the
  life of a connection, NFSv4.1+ keeps its session on a new TCP connection
  (BIND_CONN_TO_SESSION when asked), and NFSv4.0 renews its client ID, so
  the server keeps open files.
- Retry notices print above progress bars instead of through them, and
  repeats are thinned.
- `get -r` syncs each directory once instead of after every file.

### Fixed

- NFSv4.1: a lost reply no longer leaves its slot's sequence id stale. The
  slot is probed before reuse, so the server never replays a different
  request's reply (which could return data from another offset) or answers
  RETRY_UNCACHED_REP.
- NFSv4.0: a lease expiry or reconnect that loses client state no longer
  loops on EXPIRED until the retry budget runs out; the file is reopened for
  a fresh stateid.
- `get -c` no longer resumes onto an all-zero tail or an older file kept in
  place, which could join two versions of a file.
- NFSv4 setup waits for DELAY/GRACE honour Ctrl-C and `--retry-time 0`.
- NFSv4.1: a COMPOUND reply whose results do not match the request (a
  server replaying another request's reply) is rejected and the slot is
  re-synchronised, instead of being taken as success; a lost reply to the
  client's own slot probe keeps the slot uncertain.
- testenv: kernel nfsd serves NFSv4 on Linux 7.2 (a tmpfs `fsid=0`
  pseudo-root with bind mounts, and `nfsdcld`).

## [1.2.0] - 2026-11-10

### Added

- Retry policy (`RpcOptions::retry`, `RetryPolicy`): failed calls are
  retried with jittered exponential backoff for up to 5 minutes per
  operation (`--retry-time SECS`, `NFSC_RETRY_TIME`; 0 disables). Covers
  refused or dropped connections (nfsd/NAS restart), timeouts, NFSv3
  JUKEBOX and NFSv4 DELAY/GRACE, and NFSv4 session/clientid recovery.
  Idempotent calls retry on any transient error; non-idempotent ones
  (CREATE, REMOVE, RENAME, ...) only when the server certainly did not run
  them. Retries are reported on stderr, Ctrl-C cancels a backoff wait, and
  an exhausted budget fails with `Error::GaveUp`.
- `sum [-a sha256|sha512]`: checksum remote files like `sha256sum`.
- `get -V` / `--verify`: hash the download as it is written, re-read the
  remote file and compare before renaming into place.
- `get -c` compares the last 1 MiB before the resume point with the server
  and refuses to resume onto mismatching data.
- `get` takes several remotes (`get a b c dir/`); `put` expands local globs,
  takes several files, and gains `-k` and `-n`.
- `rm -r` (no symlink following, loop and cwd protection) and
  `du [-s] [-h]`.
- `NFSC_*` environment defaults for the global options (`NFSC_UID`,
  `NFSC_TIMEOUT`, `NFSC_PROTO`, `NFSC_VERS`, ...); the command line wins.
- In-process fake NFSv3/MOUNT/portmap server with fault injection, and an
  integration suite covering JUKEBOX, restarts, drops, short reads, verifier
  changes, >4 GiB offsets and READDIR fallbacks.
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

- A read that returns no data before EOF is retried and then an error, never
  a silent short transfer (also for `cat` and `get x -`, which read without
  a known length).
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
- testenv: the kernel nfsd container starts nfsd with `rpc.nfsd` so NFS is
  registered with the portmapper (Linux 7.2 no longer registers it when nfsd
  is started through `/proc`).

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
