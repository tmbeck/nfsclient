//! Offline checks of the `nfsc` command line: argument parsing, target errors,
//! and `-c` validation that happens before any connection is attempted.
//! Nothing here touches the network.

use std::process::{Command, Output};

fn nfsc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nfsc"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run nfsc: {e}"))
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn exactly_three_subcommands() {
    let out = nfsc(&["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let commands: Vec<&str> = text
        .lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|c| *c != "help")
        .collect();
    assert_eq!(commands, ["shell", "exports", "rpcinfo"], "{text}");
}

#[test]
fn shell_help_documents_the_version_and_port_flags() {
    let out = nfsc(&["shell", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--nfs-version"), "{text}");
    assert!(text.contains("--nfs-port"), "global flag shown: {text}");
    assert!(text.contains("--mount-port"), "global flag shown: {text}");
}

#[test]
fn nfs_version_values_are_checked_by_the_parser() {
    // Rejected before any connection is attempted.
    for bad in ["5", "4.3", "1"] {
        let out = nfsc(&["shell", "nas:/export", "-v", bad]);
        assert!(!out.status.success(), "-v {bad} should be rejected");
        assert!(stderr(&out).contains("invalid value"), "{}", stderr(&out));
    }
}

#[test]
fn malformed_targets_fail_with_a_message() {
    let out = nfsc(&["shell", "nas"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("expected nfs://host[:port]/path or host:/path"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn unknown_commands_in_c_are_rejected_before_connecting() {
    // 203.0.113.0/24 is documentation space; the run must not get that far.
    let out = nfsc(&["shell", "nfs://203.0.113.1/export", "-c", "ls; frobnicate"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr(&out),
        "nfsc: unknown command 'frobnicate' (try help)\n"
    );
}

#[test]
fn unterminated_quote_in_c_is_rejected_before_connecting() {
    let out = nfsc(&["shell", "nfs://203.0.113.1/export", "-c", "ls 'oops"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stderr(&out), "nfsc: unterminated single quote\n");
}

#[test]
fn conflicting_ports_are_an_error() {
    let out = nfsc(&[
        "shell",
        "nfs://203.0.113.1:2049/export",
        "--nfs-port",
        "2050",
        "-c",
        "pwd",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr(&out),
        "nfsc: conflicting ports: 2049 in the target and 2050 from --nfs-port\n"
    );
}

#[test]
fn port_flags_reject_zero() {
    let out = nfsc(&["--nfs-port", "0", "exports", "nas"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("invalid value"), "{}", stderr(&out));
}
