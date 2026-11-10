//! Live check: `nfsc rpcinfo` must print the same table as the system `rpcinfo -p`.
//!
//! Gated on NFSC_TEST_HOST (a portmapper to query; only portmap calls are made).
//! Skipped when the variable is unset.

use std::process::Command;

fn host() -> Option<String> {
    match std::env::var("NFSC_TEST_HOST") {
        Ok(h) if !h.is_empty() => Some(h),
        _ => {
            eprintln!("skipping: NFSC_TEST_HOST is not set");
            None
        }
    }
}

fn run(program: &str, args: &[&str]) -> std::process::Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {program}: {e}"))
}

fn nfsc_rpcinfo(extra: &[&str], host: &str) -> String {
    let mut args = vec!["rpcinfo"];
    args.extend_from_slice(extra);
    args.push(host);
    let out = run(env!("CARGO_BIN_EXE_nfsc"), &args);
    assert!(
        out.status.success(),
        "nfsc {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("nfsc output is UTF-8")
}

fn system_rpcinfo(host: &str) -> Option<String> {
    let path = "/usr/bin/rpcinfo";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping comparison: {path} not found");
        return None;
    }
    let out = run(path, &["-p", host]);
    assert!(
        out.status.success(),
        "rpcinfo -p failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Some(String::from_utf8(out.stdout).expect("rpcinfo output is UTF-8"))
}

#[test]
fn rpcinfo_matches_system_rpcinfo_tcp() {
    let Some(host) = host() else { return };
    let Some(reference) = system_rpcinfo(&host) else {
        return;
    };
    let ours = nfsc_rpcinfo(&[], &host);
    assert_eq!(ours, reference);
}

#[test]
fn rpcinfo_matches_system_rpcinfo_udp() {
    let Some(host) = host() else { return };
    let Some(reference) = system_rpcinfo(&host) else {
        return;
    };
    let ours = nfsc_rpcinfo(&["--proto", "udp"], &host);
    assert_eq!(ours, reference);
}
