# nfsc — userspace NFS client

An smbclient-style tool for browsing and transferring files on NFS exports
without mounting them. Pure Rust, no kernel involvement.

## Scope

- **Protocols:** NFSv2 (RFC 1094), NFSv3 (RFC 1813), NFSv4.0 (RFC 7530),
  NFSv4.1 (RFC 8881), NFSv4.2 (RFC 7862), MOUNT v1/v3, portmap v2 (RFC 1833),
  ONC-RPC v2 (RFC 5531), XDR (RFC 4506). All implemented in-repo.
  (NFSv1 was never publicly released.)
- **Version negotiation:** `auto` tries v4.2 → v4.1 → v4.0 → v3 → v2.
- **Transports:** TCP (record marking) and UDP (retransmit with timeout/backoff).
  NFSv4 is TCP-only.
- **Auth:** AUTH_NONE, AUTH_SYS with an arbitrary uid/gid/aux gids (defaulting
  to the local user). RPCSEC_GSS/Kerberos is out of scope for 1.0; credentials
  are an enum in `rpc` so a flavor can be added later.
- **Source ports:** `--port-mode auto|priv|unpriv`. `auto` tries a reserved
  port (<1024, needs root or CAP_NET_BIND_SERVICE) and falls back to an
  ephemeral port with a warning.
- **Runtime:** synchronous. Bulk transfers (`Filesystem::read_stream` /
  `write_stream`) keep several READ/WRITE calls in flight on one connection,
  matching replies by xid.

## Layout

One package containing a library and a thin binary.

```
src/lib.rs
  xdr.rs      encoder/decoder, Pack/Unpack traits
  rpc/        call/reply, auth flavors, tcp+udp transports, reserved-port bind
  portmap.rs  GETPORT, DUMP
  mount.rs    MNT, UMNT, EXPORT (v1 + v3), export resolution
  fs.rs       version-agnostic Filesystem trait + normalized types/status
  client.rs   version negotiation behind fs::connect
  nfs2/       v2 codec + Filesystem backend
  nfs3/       v3 codec + Filesystem backend
  nfs4/       v4.x COMPOUND codec, sessions/clientid state, Filesystem backend
  memfs.rs    in-memory Filesystem (tests, examples)
src/bin/nfsc/
  main.rs, cli.rs   clap CLI, option plumbing
  target.rs         target parsing (nfs://, host:/path)
  rpcinfo.rs        rpcinfo/exports output
  shell/            REPL (rustyline), tokenizer, commands, transfers, -c
```

Library dependencies: std plus `socket2`, which is used only to bind TCP
sockets to a reserved port before connecting (std has no bind-before-connect). Binary dependencies:
clap, rustyline.

## CLI

```
nfsc shell   nfs://host[:port]/export[/path] | host:/export  [-c 'cmd; cmd'] [-v 2|3|4|4.0|4.1|4.2|auto]
nfsc exports host     # MOUNT EXPORT  (showmount -e)
nfsc rpcinfo host     # portmap DUMP  (rpcinfo -p)

global: --uid --gid --gids --port-mode auto|priv|unpriv --proto tcp|udp --timeout
        --nfs-port --mount-port
```

Shell commands (kept deliberately small; see README for flags):
`ls`/`dir`, `cd`, `pwd`, `lcd`, `stat`, `cat`, `get`, `put`, `mkdir`, `rm`,
`rmdir`, `mv`, `ln`, `chmod`, `chown`, `df`, `help`, `exit`/`quit`.
`ls -l` and `stat` show symlink targets.

## Testing

- **Unit:** XDR/RPC/NFS codec round-trips and byte-exact vectors from the RFCs
  and from pcaps.
- **NFSv2 and UDP-NFS:** best effort. They are built from the RFC and covered by
  codec tests only, because modern servers rarely offer them (Linux kernels
  often lack CONFIG_NFSD_V2, and nfs-ganesha dropped v2). MOUNT and portmap
  over UDP can still be tested against most servers.
- **Read-only integration:** run against an externally supplied read-only
  export (discovery, browse, stat, get, privileged vs unprivileged ports,
  root squash, crossing filesystem boundaries). Never write to it.
- **Writes and v4:** run against local podman containers in `testenv/`:
  kernel nfsd (v3/v4.x, needs the host `nfsd` module and a privileged
  container) and nfs-ganesha (userspace, v3/v4.x).
- Integration tests are gated behind env vars (`NFSC_TEST_RO`, `NFSC_TEST_RW`,
  and others; `testenv/run-live.sh` maps the testenv file onto all of them)
  so `cargo test` stays offline by default. Test targets are never committed
  to the repo.

## Milestones

1. ✅ XDR + RPC (TCP/UDP, AUTH_SYS, reserved ports) + portmap → `nfsc rpcinfo`
2. ✅ MOUNT → `nfsc exports`; Filesystem facade; shell
3. ✅ NFSv3, NFSv2, NFSv4.x backends (read + write), container test env
4. 1.0.0: tab completion, pipelined READ/WRITE, Ctrl-C/resume/progress, docs
5. Later: RPCSEC_GSS, NFSv4 locking/delegation callbacks, READ_PLUS
