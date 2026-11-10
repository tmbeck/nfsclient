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

# Everything CI runs
ci: lint test

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

# Read benchmark of a large file, e.g. just bench host:/export/dir/file 3,4.2 2048
bench file vers="3,4.2" mib="2048":
    NFSC_PERF_RO_FILE={{file}} NFSC_PERF_RO_VERS={{vers}} NFSC_PERF_RO_MIB={{mib}} \
        cargo test --release --test perf_stream_live bench_ro -- --ignored --nocapture

# Remove build output
clean:
    cargo clean
