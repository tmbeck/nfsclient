#!/bin/bash
# Stop and remove the nfsc test servers, their scratch volumes and network,
# then remove the env file. Idempotent. Leaves images and the nfsd module alone.
#   down.sh [knfsd|ganesha|all]     default: all
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WHAT=${1:-all}
ENV_FILE=${NFSC_TESTENV_FILE:-$HERE/testenv.env}
NET=nfsc-testenv
P=(sudo podman)

case "$WHAT" in
    knfsd)   names=(nfsc-knfsd) ;;
    ganesha) names=(nfsc-ganesha) ;;
    all)     names=(nfsc-knfsd nfsc-ganesha) ;;
    *) echo "usage: down.sh [knfsd|ganesha|all]" >&2; exit 2 ;;
esac

for name in "${names[@]}"; do
    "${P[@]}" rm -f "$name" >/dev/null 2>&1 && echo "removed $name"
done
if [ "$WHAT" != knfsd ]; then
    "${P[@]}" volume rm -f nfsc-ganesha-rw nfsc-ganesha-ro >/dev/null 2>&1
fi
if [ "$WHAT" = all ]; then
    "${P[@]}" network rm "$NET" >/dev/null 2>&1 && echo "removed network $NET"
    rm -f "$ENV_FILE"
fi
exit 0
