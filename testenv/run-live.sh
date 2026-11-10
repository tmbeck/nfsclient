#!/usr/bin/env bash
# Run the live test suites against the servers described by an env file.
#
#   testenv/run-live.sh [--sudo] [--no-lease] [ENV_FILE]
#
# ENV_FILE defaults to $NFSC_TESTENV. It is the KEY=value file written by
# testenv/up.sh (NFSC_TEST_RW_<SRV>, NFSC_TEST_RO_<SRV>, NFSC_TEST_ADDR_<SRV>,
# NFSC_TEST_FIXTURES_SHA256). The file is parsed, not sourced, and only
# NFSC_TEST_* keys are used. No host name is written into this script.
#
# Extra targets, read from the file or the environment (environment wins):
#   NFSC_TEST_RO_EXTERNAL=host:/export  one more read-only export. Only the
#       read-only suites run against it, and the fixture manifest is not
#       checked (that tree is not the one testenv/up.sh seeds).
#   NFSC_TEST_RO_SECURE=host:/export    an export that requires reserved
#       source ports. Checked only with --sudo.
#   NFSC_TEST_HOST=host                 an extra portmapper for the portmap suites.
#   NFSC_TEST_RO_UDP=1, NFSC_TEST_RW_UDP=1  also run the UDP checks.
#
# --sudo      Build all test binaries first (cargo test --no-run), then run the
#             reserved-port check (ro_secure_export_port_policy) as root with
#             sudo. Every other suite runs as the current user.
# --no-lease  Skip the 50-second NFSv4.0 lease idle test.
#
# Exit status: 0 if every suite passed, 1 if any failed, 2 on usage errors.

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/.." && pwd)

SUDO=0
LEASE=1
ENV_FILE=
for arg in "$@"; do
    case $arg in
        --sudo) SUDO=1 ;;
        --no-lease) LEASE=0 ;;
        -h | --help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "run-live.sh: unknown option $arg" >&2; exit 2 ;;
        *) ENV_FILE=$arg ;;
    esac
done
ENV_FILE=${ENV_FILE:-${NFSC_TESTENV:-}}
if [ -z "$ENV_FILE" ]; then
    echo "usage: run-live.sh [--sudo] [--no-lease] ENV_FILE  (or set NFSC_TESTENV)" >&2
    exit 2
fi
if [ ! -r "$ENV_FILE" ]; then
    echo "run-live.sh: cannot read env file $ENV_FILE" >&2
    exit 2
fi

# ---- read the env file ------------------------------------------------------
declare -A E=()
while IFS= read -r line || [ -n "$line" ]; do
    case $line in
        NFSC_TEST_*=*) E[${line%%=*}]=${line#*=} ;;
    esac
done < "$ENV_FILE"

for k in NFSC_TEST_RO_EXTERNAL NFSC_TEST_RO_SECURE NFSC_TEST_HOST NFSC_TEST_RO_UDP NFSC_TEST_RW_UDP; do
    if [ -n "${!k:-}" ]; then
        E[$k]=${!k}
    fi
done

# Servers are the <SRV> suffixes of the NFSC_TEST_ADDR_<SRV> keys.
servers=()
for k in "${!E[@]}"; do
    case $k in
        NFSC_TEST_ADDR_*) servers+=("${k#NFSC_TEST_ADDR_}") ;;
    esac
done
mapfile -t servers < <(printf '%s\n' "${servers[@]}" | sort)

cd "$REPO" || exit 2

# Every suite gets only the NFSC_TEST_* variables set below, never the ones
# left over in the caller's shell.
CLEAN=()
while IFS= read -r v; do
    CLEAN+=(-u "$v")
done < <(compgen -e | grep '^NFSC_TEST_' || true)

# Optional UDP switches, passed on when set.
common=()
for k in NFSC_TEST_RO_UDP NFSC_TEST_RW_UDP; do
    if [ -n "${E[$k]:-}" ]; then
        common+=("$k=${E[$k]}")
    fi
done

# ---- suites -------------------------------------------------------------------
RW_SUITES=(nfs3_live_rw)                          # NFSC_TEST_RW=<one target> per run
RW_V4_SUITES=(nfs4_live_rw)                       # reads NFSC_TEST_RW_KNFSD / _GANESHA itself
RO_SUITES=(mount_live nfs3_live_ro nfs4_live_ro)  # NFSC_TEST_RO=<one target> per run
HOST_SUITES=(portmap_live rpc_live cli_rpcinfo_live)  # NFSC_TEST_HOST=<one host> per run

# Test in nfs3_live_ro that binds a reserved source port. It runs only in the
# secure-export step, never in the ordinary runs.
SECURE_TEST=ro_secure_export_port_policy

for s in "${RW_SUITES[@]}" "${RW_V4_SUITES[@]}" "${RO_SUITES[@]}" "${HOST_SUITES[@]}"; do
    if [ ! -f "tests/$s.rs" ]; then
        echo "run-live.sh: missing tests/$s.rs" >&2
        exit 2
    fi
done

declare -A BIN=()
if [ "$SUDO" = 1 ]; then
    echo "building test binaries"
    for s in "${RW_SUITES[@]}" "${RW_V4_SUITES[@]}" "${RO_SUITES[@]}" "${HOST_SUITES[@]}"; do
        out=$(cargo test --no-run --test "$s" 2>&1) || { printf '%s\n' "$out" >&2; exit 1; }
        p=$(printf '%s\n' "$out" | sed -n "s/.*Executable tests\/$s\.rs (\(.*\))\$/\1/p" | tail -1)
        if [ -z "$p" ]; then
            echo "run-live.sh: cannot find the test binary for $s" >&2
            exit 1
        fi
        case $p in
            /*) BIN[$s]=$p ;;
            *) BIN[$s]=$REPO/$p ;;
        esac
    done
fi

RESULTS=()
FAILED=0

# run_suite SUITE LABEL [--skip NAME | --exact NAME] [KEY=VALUE...]
# Runs one suite and records the result. Without --sudo it goes through
# cargo test; with --sudo it runs the prebuilt binary (under sudo for --exact).
run_suite() {
    local suite=$1 label=$2 filter=() rc=0
    shift 2
    if [ "${1:-}" = --skip ] || [ "${1:-}" = --exact ]; then
        filter=("$1" "$2")
        shift 2
    fi
    echo
    echo "== $suite [$label]"
    if [ "$SUDO" = 1 ]; then
        if [ "${filter[0]:-}" = --exact ]; then
            sudo env "$@" "${BIN[$suite]}" --nocapture "${filter[@]}" || rc=$?
        else
            env "${CLEAN[@]}" "$@" "${BIN[$suite]}" --nocapture "${filter[@]}" || rc=$?
        fi
    else
        env "${CLEAN[@]}" "$@" cargo test --test "$suite" -- --nocapture "${filter[@]}" || rc=$?
    fi
    if [ "$rc" -eq 0 ]; then
        RESULTS+=("PASS  $suite [$label]")
    else
        RESULTS+=("FAIL  $suite [$label] (exit $rc)")
        FAILED=1
    fi
}

# run_ro LABEL TARGET [MANIFEST]: the read-only suites against one export.
run_ro() {
    local label=$1 target=$2 manifest=${3:-}
    local vars=("NFSC_TEST_RO=$target" "${common[@]}")
    if [ -n "$manifest" ]; then
        vars+=("NFSC_TEST_RO_MANIFEST=$manifest")
    fi
    local s
    for s in "${RO_SUITES[@]}"; do
        if [ "$s" = nfs3_live_ro ]; then
            run_suite "$s" "$label" --skip "$SECURE_TEST" "${vars[@]}"
        else
            run_suite "$s" "$label" "${vars[@]}"
        fi
    done
}

# ---- reserved-port check ------------------------------------------------------
secure=${E[NFSC_TEST_RO_SECURE]:-}
if [ -n "$secure" ]; then
    if [ "$SUDO" = 1 ]; then
        run_suite nfs3_live_ro "secure export" --exact "$SECURE_TEST" "NFSC_TEST_RO_SECURE=$secure"
    else
        echo
        echo "== nfs3_live_ro [secure export]: skipped, the reserved-port check needs --sudo"
    fi
fi

# ---- read-write targets -------------------------------------------------------
for srv in "${servers[@]}"; do
    rw=${E[NFSC_TEST_RW_$srv]:-}
    [ -n "$rw" ] || continue
    for s in "${RW_SUITES[@]}"; do
        run_suite "$s" "$srv" "NFSC_TEST_RW=$rw" "${common[@]}"
    done
done

rw_v4=()
for srv in "${servers[@]}"; do
    if [ -n "${E[NFSC_TEST_RW_$srv]:-}" ]; then
        rw_v4+=("NFSC_TEST_RW_$srv=${E[NFSC_TEST_RW_$srv]}")
    fi
done
if [ "${#rw_v4[@]}" -gt 0 ]; then
    lease=()
    if [ "$LEASE" = 1 ]; then
        lease=(NFSC_TEST_LEASE=1)
    fi
    for s in "${RW_V4_SUITES[@]}"; do
        run_suite "$s" "all targets" "${rw_v4[@]}" "${lease[@]}" "${common[@]}"
    done
fi

# ---- read-only targets --------------------------------------------------------
manifest=${E[NFSC_TEST_FIXTURES_SHA256]:-}
for srv in "${servers[@]}"; do
    ro=${E[NFSC_TEST_RO_$srv]:-}
    [ -n "$ro" ] || continue
    run_ro "$srv" "$ro" "$manifest"
done

ext=${E[NFSC_TEST_RO_EXTERNAL]:-}
if [ -n "$ext" ]; then
    run_ro external "$ext"
fi

# ---- portmapper ---------------------------------------------------------------
hosts=()
for srv in "${servers[@]}"; do
    hosts+=("${E[NFSC_TEST_ADDR_$srv]}")
done
if [ -n "$ext" ]; then
    hosts+=("${ext%%:*}")
fi
if [ -n "${E[NFSC_TEST_HOST]:-}" ]; then
    hosts+=("${E[NFSC_TEST_HOST]}")
fi
mapfile -t hosts < <(printf '%s\n' "${hosts[@]}" | awk 'NF && !seen[$0]++')
for h in "${hosts[@]}"; do
    for s in "${HOST_SUITES[@]}"; do
        run_suite "$s" "$h" "NFSC_TEST_HOST=$h"
    done
done

# ---- summary ------------------------------------------------------------------
echo
echo "== summary"
if [ "${#RESULTS[@]}" -eq 0 ]; then
    echo "no targets in $ENV_FILE; nothing ran"
    exit 2
fi
printf '%s\n' "${RESULTS[@]}"
exit "$FAILED"
