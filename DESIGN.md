# nfsc — userspace NFS client

An smbclient-style tool for browsing and transferring files on NFS exports
without mounting them. Pure Rust, no kernel involvement.

## Scope

- **Protocols:** NFSv2 (RFC 1094), NFSv3 (RFC 1813), MOUNT v1/v3, portmap v2
  (RFC 1833), ONC-RPC v2 (RFC 5531), XDR (RFC 4506). All implemented in-repo.
  (NFSv1 was never publicly released.)
- **Transports:** TCP (record marking) and UDP (retransmit with timeout/backoff).
- **Auth:** AUTH_NONE, AUTH_SYS with an arbitrary uid/gid/aux gids (defaulting
  to the local user). The auth layer is a trait so RPCSEC_GSS/Kerberos can be
  added later.
- **Source ports:** `--port-mode auto|priv|unpriv`. `auto` tries a reserved
  port (<1024, needs root or CAP_NET_BIND_SERVICE) and falls back to an
  ephemeral port with a warning.
- **Runtime:** synchronous, std only. Big transfers may later pipeline through
  a reader thread that matches replies by xid.

## Layout

One package containing a library and a thin binary.

```
src/lib.rs
  xdr/        encoder/decoder, Pack/Unpack traits
  rpc/        call/reply, auth flavors, tcp+udp transports, reserved-port bind
  portmap.rs  GETPORT, DUMP
  mount.rs    MNT, UMNT, EXPORT (v1 + v3)
  nfs2.rs     v2 procedures + types
  nfs3.rs     v3 procedures + types
  client.rs   version-agnostic facade (lookup/readdir/read/write/...),
              path resolution, v3→v2 negotiation
src/bin/nfsc/
  main.rs     clap CLI
  shell.rs    REPL (rustyline), command parsing, -c scripting
```

Library dependencies: std plus `socket2`, which is used only to bind TCP
sockets to a reserved port before connecting (std has no bind-before-connect). Binary dependencies:
clap, rustyline.

## CLI

```
nfsc shell   nfs://host[:port]/export[/path] | host:/export  [-c 'cmd; cmd'] [-v 2|3|auto]
nfsc exports host     # MOUNT EXPORT  (showmount -e)
nfsc rpcinfo host     # portmap DUMP  (rpcinfo -p)

global: --uid --gid --gids --port-mode auto|priv|unpriv --proto tcp|udp --timeout
```

Shell commands (kept deliberately small):
`ls [-l]`, `cd`, `pwd`, `lcd`, `stat`, `get [-r]`, `put [-r]`, `mkdir`, `rm`,
`rmdir`, `mv`, `ln -s`, `chmod`, `chown`, `df`, `help`, `exit`.
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
- **Writes:** run against a container. nfs-ganesha (userspace, no host
  module) is preferred; kernel nfsd in `--privileged` docker is the fallback.
- Integration tests are gated behind env vars (`NFSC_TEST_RO=host:/export`,
  `NFSC_TEST_RW=host:/export`) so `cargo test` stays offline by default.
  Test targets are never committed to the repo.

## Milestones

1. XDR + RPC (TCP/UDP, AUTH_SYS, reserved ports) + portmap → `nfsc rpcinfo`
2. MOUNT → `nfsc exports`, MNT/UMNT
3. NFSv3 read path + client facade + shell: ls, cd, stat, get, df
4. NFSv3 write path: put, mkdir, rm, rmdir, mv, ln, chmod, chown; ganesha container tests
5. NFSv2 behind the same facade, version negotiation
6. Polish: tab completion, recursive transfers, progress bars, pipelined READ/WRITE
