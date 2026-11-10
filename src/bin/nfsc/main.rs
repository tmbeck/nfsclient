//! nfsc CLI entry point. (portmap/CLI agent owns this directory.)
//! Logic lives in the submodules; this file only parses arguments and maps errors to exit codes.

mod cli;
mod exports;
mod rpcinfo;
mod shell;
mod target;
mod text;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, CmdError};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli::run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CmdError::Failed(msg)) => {
            eprintln!("nfsc: {msg}");
            if msg.contains("reserved source port") {
                eprintln!("nfsc: hint: {}", setcap_command());
            }
            ExitCode::FAILURE
        }
        Err(CmdError::Reported(code)) => ExitCode::from(code),
    }
}

/// The exact command that lets this binary bind ports below 1024.
fn setcap_command() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "$(command -v nfsc)".to_string());
    format!("sudo setcap cap_net_bind_service=+ep '{exe}'  (repeat after each install)")
}
