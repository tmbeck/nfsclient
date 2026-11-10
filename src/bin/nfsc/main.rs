//! nfsc CLI entry point. (portmap/CLI agent owns this directory.)
//! Logic lives in the submodules; this file only parses arguments and maps errors to exit codes.

mod cli;
mod rpcinfo;
mod target;

use std::process::ExitCode;

use clap::Parser;

use cli::{Cli, CmdError};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli::run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CmdError::NotImplemented(what)) => {
            eprintln!("nfsc: {what} is not implemented yet");
            ExitCode::from(2)
        }
        Err(CmdError::Failed(msg)) => {
            eprintln!("nfsc: {msg}");
            ExitCode::FAILURE
        }
    }
}
