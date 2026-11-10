#!/bin/sh
# nfs-ganesha (VFS FSAL) test server. Needs --privileged only for the
# rpcbind/ganesha capabilities it manages itself; no mounts are made.
# Exports are plain directories in the container layer: ganesha's VFS FSAL
# refuses tmpfs export paths here (resolve_posix_filesystem ENOENT).
set -eu
log() { echo "[ganesha] $*" >&2; }

mkdir -p /export/rw /export/ro /run/ganesha /var/lib/nfs/ganesha /run/rpcbind
chmod 1777 /export/rw
chmod 0755 /export/ro
sh /usr/local/share/nfsc-testenv/fixtures.sh /export/ro

rpcbind -w

trap 'kill "$GPID" 2>/dev/null; exit 0' TERM INT
/usr/bin/ganesha.nfsd -F -L /dev/stderr -p /run/ganesha/ganesha.pid \
    -f /etc/ganesha/ganesha.conf -N NIV_EVENT &
GPID=$!
log "started pid $GPID"
wait "$GPID"
