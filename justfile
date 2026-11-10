# nfsc development tasks. Run `just` to list them.

# Env file written by `testenv/up.sh` and read by the live suites.
testenv := env("NFSC_TESTENV_FILE", justfile_directory() / "testenv/testenv.env")

# List recipes
default:
    @just --list --unsorted

# Debug build
build:
    cargo build

# Optimized build (target/release/nfsc)
release:
    cargo build --release

# Offline tests (live suites skip themselves)
test *ARGS:
    cargo test {{ARGS}}

# Formatting check, clippy with warnings denied, and a library-only build
lint:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo build --no-default-features

# Format the code
fmt:
    cargo fmt

# Rustdoc with warnings denied
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Build and test with the minimum supported Rust version (needs rustup)
msrv:
    cargo +1.85 build --locked --all-targets
    cargo +1.85 test --locked

# Everything CI runs (except msrv and cargo-deny)
ci: lint doc test

# Install nfsc into ~/.cargo/bin
install:
    cargo install --path . --force

# Let the installed nfsc bind ports <1024 for 'secure' exports (sudo; redo after each install)
setcap:
    sudo setcap cap_net_bind_service=+ep "$(command -v nfsc)"

# install, then setcap
install-cap: install setcap

# Start the podman NFS test servers: all, knfsd, or ganesha
testenv-up which="all":
    NFSC_TESTENV_FILE={{testenv}} testenv/up.sh {{which}}

# Stop the podman NFS test servers: all, knfsd, or ganesha
testenv-down which="all":
    NFSC_TESTENV_FILE={{testenv}} testenv/down.sh {{which}}

# Live suites against the test servers (flags: --sudo, --no-lease)
live *FLAGS:
    testenv/run-live.sh {{FLAGS}} {{testenv}}

# NFSC_TEST_SOAK_* knobs pass through; NFSC_TEST_SOAK_RESTART=1 also restarts ganesha.
# Chaos + soak suite against the test servers (release), e.g. just soak 2048 soak_read
soak mib="1024" *ARGS:
    #!/usr/bin/env bash
    set -euo pipefail
    env_file={{testenv}}
    if [ ! -r "$env_file" ]; then echo "no env file $env_file; run 'just testenv-up' first" >&2; exit 2; fi
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            NFSC_TEST_RW_*=*) k=${line%%=*}; [ -n "${!k:-}" ] || export "$line" ;;
        esac
    done < "$env_file"
    export NFSC_TEST_SOAK=1 NFSC_TEST_SOAK_MIB={{mib}}
    cargo test --release --test soak_live -- --nocapture --test-threads=1 {{ARGS}}

# Read benchmark of a large file, e.g. just bench host:/export/dir/file 3,4.2 2048
bench file vers="3,4.2" mib="2048":
    NFSC_PERF_RO_FILE={{file}} NFSC_PERF_RO_VERS={{vers}} NFSC_PERF_RO_MIB={{mib}} \
        cargo test --release --test perf_stream_live bench_ro -- --ignored --nocapture

# Remove build output
clean:
    cargo clean
