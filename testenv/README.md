# nfsc test environment

Local NFS servers for the write and NFSv4 tests, run as rootful podman
containers on a private bridge network (`nfsc-testenv`, 10.89.0.0/24). No
host ports are published; clients connect to the container IPs. Nothing here
touches a real export or any LAN host.

| server   | image                          | exports (same paths for v3 and v4)           |
|----------|--------------------------------|----------------------------------------------|
| knfsd    | `localhost/nfsc-testenv-knfsd` | `/export/rw` (tmpfs, no_root_squash), `/export/ro` (tmpfs, root_squash) |
| ganesha  | `localhost/nfsc-testenv-ganesha` | `/export/rw` (RW, No_Root_Squash), `/export/ro` (RO, Root_Squash) |

Both run `--privileged`. Both seed `/export/ro` with the same deterministic
tree (`fixtures.sh`, checked by `fixtures.sha256`).

## Usage

```
testenv/up.sh [knfsd|ganesha|all]   # build missing images, start, write env file
testenv/down.sh [knfsd|ganesha|all] # remove containers, scratch volumes, network, env file
testenv/check.sh HOST:/export/rw HOST:/export/ro [label]  # kernel-mount validation
```

`up.sh` writes `testenv.env` (default `testenv/testenv.env`, gitignored, or
`NFSC_TESTENV_FILE`) with `KEY=value` lines for each server that answers:
`NFSC_TEST_RW_<SRV>`, `NFSC_TEST_RO_<SRV>`, `NFSC_TEST_ADDR_<SRV>`, plus
`NFSC_TEST_FIXTURES_SHA256`. The file is replaced atomically.

Set `NFSC_TESTENV_REBUILD=1` to rebuild images and recreate containers.

## Fixtures (`fixtures.sh`)

`fixtures.sh DEST` writes the tree; `fixtures.sh --manifest DIR` prints the
manifest. Contents: `hello.txt`, `empty.txt`, `owned.txt` (uid/gid 1000),
`big.bin` (5 MiB, AES-CTR keystream, sha256 in manifest), `nested/dir1/dir2/deep.txt`,
`nested/dir1/sibling.txt`, `hardlink.txt` (hard link to `hello.txt`),
`link-rel.txt` (symlink to `nested/dir1/dir2/deep.txt`), `dangling.txt`
(dangling symlink), `latin1-\xe9.txt` (non-UTF-8 name), `many/` (300 files,
readdir paging), `secret/key.txt` (dir 0700, file 0600; unreadable to squashed
clients, so not in the manifest).

## Validation

`check.sh` mounts each export with the host kernel client at v3, v4.0, v4.1 and
v4.2 (`nolock`, under `$TMPDIR`), verifies the RO manifest, confirms the RO
mount refuses writes, and writes and deletes a file on the RW mount. A version
the server does not offer is reported as SKIP.

## Live test suites (`run-live.sh`)

`run-live.sh` runs every live suite against the servers in an env file:

```
testenv/run-live.sh [--sudo] [--no-lease] [ENV_FILE]
```

`ENV_FILE` defaults to `$NFSC_TESTENV`. The script parses the file (it does
not source it) and maps the keys onto each suite's variables:

| env file key                   | used as                                                        |
|--------------------------------|----------------------------------------------------------------|
| `NFSC_TEST_RW_<SRV>`           | `NFSC_TEST_RW` for `nfs3_live_rw`, one run per server; `NFSC_TEST_RW_KNFSD` / `_GANESHA` for `nfs4_live_rw` |
| `NFSC_TEST_RO_<SRV>`           | `NFSC_TEST_RO` for `mount_live`, `nfs3_live_ro`, `nfs4_live_ro`, one run per server |
| `NFSC_TEST_FIXTURES_SHA256`    | `NFSC_TEST_RO_MANIFEST`, for local servers only                |
| `NFSC_TEST_ADDR_<SRV>`         | `NFSC_TEST_HOST` for `portmap_live`, `rpc_live`, `cli_rpcinfo_live` |

The server names come from the `NFSC_TEST_ADDR_<SRV>` keys. Variables that can
also be given in the environment (environment wins):

- `NFSC_TEST_RO_EXTERNAL=host:/export`: one extra read-only export, such as a
  NAS. Only the read-only suites and the portmapper suites run against it. The
  fixture manifest is not checked, because that tree is not ours.
- `NFSC_TEST_RO_SECURE=host:/export`: an export that requires reserved source
  ports. Checked only with `--sudo`.
- `NFSC_TEST_HOST`: one more portmapper host.
- `NFSC_TEST_RO_UDP=1`, `NFSC_TEST_RW_UDP=1`: also run the UDP checks.

Other options:

- `--sudo`: build all test binaries first (`cargo test --no-run`), then run
  `ro_secure_export_port_policy` as root with `sudo`. Everything else runs as
  the current user. Without `--sudo`, that test is skipped. Reserved ports
  need root or `CAP_NET_BIND_SERVICE`.
- `--no-lease`: skip the NFSv4.0 lease test (`lease_renewal_after_idle`),
  which sleeps for 50 seconds. The default runs it, against the first
  read-write target.

Each suite is listed with its target. The script exits 0 only if every suite
passes, and prints a summary at the end.

Example, against the local containers:

```
testenv/up.sh ganesha
testenv/run-live.sh "$NFSC_TESTENV"
```

## Caveats

- knfsd needs the host `nfsd` module (`up.sh` loads it). Kernel nfsd here has
  no NFSv2 and, on this kernel, no NFSv4.0 either.
- Kernel nfsd and ganesha ownership is numeric: no idmapd runs, so v4 owner
  strings are numeric.
- Scratch data lives in tmpfs (knfsd) or podman volumes `nfsc-ganesha-rw/ro`
  (ganesha). `down.sh` removes the volumes; restarting containers resets data.
- ganesha: tmpfs export paths fail in the VFS FSAL (ENOENT on resolve), and
  overlay paths fail with ENOTSUP for file handles, so it uses named volumes
  (btrfs-backed on this host). UDP transport is not offered by ganesha 14.
- Locks (NLM, NFSv4 byte-range) are not exercised: ganesha has NLM disabled.
