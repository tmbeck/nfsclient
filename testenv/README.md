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
