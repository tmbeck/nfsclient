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

## Chaos and soak tests (`just soak`)

`tests/soak_live.rs` proves that long transfers survive network faults and
server restarts against the real servers, and never return short or wrong
data. It is skipped unless `NFSC_TEST_SOAK=1` and `NFSC_TEST_RW_<SRV>` are
set; `just soak [MiB] [FILTER]` does both from the env file and runs a release
build with one test at a time:

```
just testenv-up
just soak                 # 1024 MiB, every soak test
just soak 4096 soak_read  # 4 GiB, read test only
NFSC_TEST_SOAK_RESTART=1 just soak 1024 soak_server_restart
```

Each test writes a file with deterministic content (byte `o` is a function of
a per-file seed and `o`, so every chunk is checked on arrival) directly to the
RW export, in a `nfsc-soak-<random>` directory that is removed afterwards.
Transfers then go through `tests/support/chaos_proxy.rs`, a TCP proxy on
127.0.0.1 that injects, on a seeded random schedule triggered by bytes
forwarded: connection reset, half-close, stall (longer than the RPC timeout),
added latency, bandwidth cap, and "server down" (listener closed, connects
refused). For NFSv3 the client is pointed at 127.0.0.1 with `nfs_port` set to
the NFS proxy and `mount_port` to a second, fault-free proxy in front of
mountd; NFSv4 only needs the NFS proxy.

| test                          | what it checks |
|-------------------------------|----------------|
| `soak_read_through_chaos`     | `read_stream` to EOF under faults, v3 and v4.0/4.1/4.2 (versions the server lacks are skipped): exact length and content, retries observed, no give-up, within the time budget |
| `soak_write_through_chaos`    | `write_stream` under faults (v3, v4.1), then a clean direct read verifies size and content |
| `soak_server_restart`         | readers for every version, throttled to ~30 s, in parallel; one `sudo -n podman restart nfsc-ganesha` a quarter of the way in; all reads complete and verify. Readers go through fault-free proxies, because podman may give the restarted container a **new IP address**; the proxies are pointed at it, like a stable server name. Afterwards run `just testenv-up` to rewrite the env file. Needs `NFSC_TEST_SOAK_RESTART=1`. knfsd is skipped: its export is tmpfs, so a restart loses the file |
| `soak_cli_get_through_chaos`  | the `nfsc` binary: `shell -c 'get -cV ...'` through the proxy exits 0, and the local file is exact |
| `soak_cli_interrupt_resume`   | a bandwidth-capped `get -cV` gets SIGINT at ~30% (exit 130, `.nfsc-part` kept and correct), then `get -cV` under faults resumes ("resumed at"), verifies and exits 0 |

A transfer passes when it returns exactly the file (length and every byte),
within `NFSC_TEST_SOAK_BUDGET_SECS`, with no operation giving up, and with
evidence of recovery: a retry event (`RetryPolicy::on_retry`) or a reconnect
seen by the proxy. Pipelined transfers often recover by reconnecting and
resending without a retry event, so both count.

The knfsd RW export is a 512 MiB tmpfs: when an export has too little free
space (FSSTAT), the file is shrunk to fit and the test says so.

`soak_live.rs` also has short regression tests (64 MiB, one scripted fault):
`v3_read_survives_reset_and_down` runs whenever `NFSC_TEST_RW_<SRV>` is set;
the `bug_v4*` tests are `#[ignore]`d until the NFSv4 recovery bugs they
describe are fixed (`cargo test --test soak_live bug_ -- --ignored`).

The fault seed is printed; `NFSC_TEST_SOAK_SEED=N` replays it. Other knobs
(see the top of `tests/soak_live.rs`): `NFSC_TEST_SOAK_VERS`,
`NFSC_TEST_SOAK_WRITE_VERS`, `NFSC_TEST_SOAK_CLI_VERS`,
`NFSC_TEST_SOAK_FAULTS` (per transfer, default 8),
`NFSC_TEST_SOAK_BUDGET_SECS` (default 900), `NFSC_TEST_SOAK_TMPDIR` (local
downloads), `NFSC_TEST_SOAK_KEEP=1`, `NFSC_TEST_CHAOS_VERBOSE=1` (log each
fault). The proxy's own self-tests in the same file need no server and run
with `cargo test`.

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
