#!/bin/sh
# Kernel nfsd server. Needs --privileged (mounts, nfsd filesystem).
set -eu
log() { echo "[knfsd] $*" >&2; }

mkdir -p /export/rw /export/ro
# Both exports are tmpfs: nothing from the host is ever exported.
mount -t tmpfs -o mode=1777,size=512m tmpfs /export/rw
mount -t tmpfs -o mode=0755,size=64m tmpfs /export/ro
sh /usr/local/share/nfsc-testenv/fixtures.sh /export/ro

mkdir -p /var/lib/nfs/v4recovery /var/lib/nfs/rpc_pipefs /run/rpcbind
mount -t rpc_pipefs sunrpc /var/lib/nfs/rpc_pipefs 2>/dev/null || true
mount -t nfsd nfsd /proc/fs/nfsd

# v2 is not built into the kernel. Kernels may lack some minor versions
# (4.0 is optional upstream), so enable each one and keep whatever sticks.
for v in 3 4 4.0 4.1 4.2; do
    echo "+$v" > /proc/fs/nfsd/versions 2>/dev/null || log "cannot enable nfsd version $v"
done
log "nfsd versions: $(cat /proc/fs/nfsd/versions)"

rpcbind -w
exportfs -ra
rpc.mountd
# Start nfsd with rpc.nfsd rather than writing portlist/threads directly:
# recent kernels (seen on 7.2) no longer register NFS with the portmapper
# when nfsd is started through /proc, and rpc.nfsd does the registration.
# Ask for a UDP listener too; fall back to TCP only if UDP is unavailable.
rpc.nfsd -u 8 2>/dev/null || { log "udp listener unavailable"; rpc.nfsd 8; }
rpcinfo -p 2>/dev/null | grep -q ' 100003 ' || log "warning: nfs is not registered with rpcbind"
log "ready"

trap 'exit 0' TERM INT
sleep infinity &
wait $!
