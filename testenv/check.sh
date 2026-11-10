#!/bin/bash
# Validate a test export with the host kernel NFS client, one mount per version.
#   check.sh HOST:/export/rw HOST:/export/ro [label]
# For each of v3, v4.0, v4.1, v4.2: mount RO and verify fixtures.sha256 against
# the RO export, then mount RW, write and delete a file, and unmount.
# Versions the server does not offer are reported as SKIP, not FAIL.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
MANIFEST=$HERE/fixtures.sha256
SCRATCH=${NFSC_TESTENV_SCRATCH:-${TMPDIR:-/tmp}/nfsc-testenv-check}
RW=${1:?usage: check.sh HOST:/export/rw HOST:/export/ro [label]}
RO=${2:?usage: check.sh HOST:/export/rw HOST:/export/ro [label]}
LABEL=${3:-server}
OPTS=nolock,soft,timeo=50,retrans=2
fails=0

try_mount() { # src dir vers
    sudo mount -t nfs -o "vers=$3,$OPTS" "$1" "$2" 2>/dev/null
}

for vers in 3 4.0 4.1 4.2; do
    ro_dir=$SCRATCH/$LABEL-v$vers-ro
    rw_dir=$SCRATCH/$LABEL-v$vers-rw
    mkdir -p "$ro_dir" "$rw_dir"
    if ! try_mount "$RO" "$ro_dir" "$vers"; then
        echo "SKIP $LABEL v$vers: mount of $RO failed (server may not offer it)"
        continue
    fi
    if (cd "$ro_dir" && sha256sum --quiet -c "$MANIFEST" >/dev/null 2>&1); then
        ro_res=ok
    else
        ro_res=FAIL; fails=$((fails + 1))
    fi
    # RO export must refuse writes.
    if (echo x 2>/dev/null > "$ro_dir/nfsc-ro-probe"); then
        ro_res="$ro_res,WRITABLE(FAIL)"; fails=$((fails + 1))
        rm -f "$ro_dir/nfsc-ro-probe" 2>/dev/null
    fi
    sudo umount "$ro_dir" 2>/dev/null

    if ! try_mount "$RW" "$rw_dir" "$vers"; then
        echo "FAIL $LABEL v$vers: rw mount of $RW failed"; fails=$((fails + 1))
        echo "     ro=$ro_res"
        continue
    fi
    name=nfsc-check-$$-v$vers
    rw_res=ok
    if ! (printf 'probe %s\n' "$vers" > "$rw_dir/$name" && \
          [ "$(cat "$rw_dir/$name")" = "probe $vers" ] && \
          rm -f "$rw_dir/$name" && [ ! -e "$rw_dir/$name" ]); then
        rw_res=FAIL; fails=$((fails + 1))
    fi
    sudo umount "$rw_dir" 2>/dev/null || { echo "WARN: umount $rw_dir failed"; }
    echo "$([ "$ro_res" = ok ] && [ "$rw_res" = ok ] && echo PASS || echo FAIL) $LABEL v$vers: ro=$ro_res rw=$rw_res"
done

rmdir "$SCRATCH"/$LABEL-v* 2>/dev/null
exit $((fails > 0))
