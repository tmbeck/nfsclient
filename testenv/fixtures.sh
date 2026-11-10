#!/bin/sh
# Deterministic NFS test fixture tree.
#
#   fixtures.sh DEST              populate DEST (created if missing) with the fixture tree
#   fixtures.sh --manifest DIR    print "sha256  path" for every regular file under DIR
#
# Used inside the knfsd and ganesha images (DEST = the RO export) and on the
# host (to regenerate fixtures.sha256). Modes, owners and mtimes are fixed so
# the tree is identical everywhere. Requires GNU coreutils, find, sed, openssl.
set -eu

if [ "${1:-}" = "--manifest" ]; then
    cd "${2:?usage: fixtures.sh --manifest DIR}"
    # secret/ (mode 0700) is the permission-denial fixture: squashed clients
    # cannot read it, so it is left out of the manifest.
    LC_ALL=C find . -type f -not -path './secret/*' -print0 | LC_ALL=C sort -z |
        xargs -0 sha256sum |
        LC_ALL=C sed 's|^\([0-9a-f]*\)  \./|\1  |'
    exit 0
fi

DEST=${1:?usage: fixtures.sh DEST}
mkdir -p "$DEST"
cd "$DEST"
# Clear children only, so DEST itself may be a mount point.
find . -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +

printf 'hello from nfsc fixtures\n' > hello.txt
: > empty.txt
printf 'owned by uid 1000\n' > owned.txt
mkdir -p nested/dir1/dir2
printf 'deep file\n' > nested/dir1/dir2/deep.txt
printf 'sibling file\n' > nested/dir1/sibling.txt
ln -s nested/dir1/dir2/deep.txt link-rel.txt
ln -s no-such-target dangling.txt
ln hello.txt hardlink.txt
printf 'non-UTF-8 file name\n' > "$(printf 'latin1-\351.txt')"
mkdir many
i=0
while [ "$i" -lt 300 ]; do
    printf 'n=%d\n' "$i" > "$(printf 'many/f%04d' "$i")"
    i=$((i + 1))
done
mkdir secret
printf 'root only\n' > secret/key.txt
# 5 MiB pseudo-random but fixed: AES-128-CTR of zeros with an all-zero key/IV.
head -c 5242880 < /dev/zero | openssl enc -aes-128-ctr \
    -K 00000000000000000000000000000000 -iv 00000000000000000000000000000000 \
    -nosalt 2>/dev/null > big.bin

find . -type d -exec chmod 0755 {} +
find . -type f -exec chmod 0644 {} +
chmod 0700 secret
chmod 0600 secret/key.txt
chown 1000:1000 owned.txt
find . -exec touch -h -d @1700000000 {} +
