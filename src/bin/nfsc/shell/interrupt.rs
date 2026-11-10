//! Ctrl-C handling. A process-wide flag is set by the signal handler; transfer
//! loops check it between chunks and abort with an `Interrupted` I/O error.
//! Sessions hold their own `Arc` to the flag, so tests can use private flags.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use nfsc::Error;

/// The flag the Ctrl-C handler sets.
pub fn global() -> Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// Installs the SIGINT handler once per process. It only sets the flag, so
/// the process keeps running and the current command can wind down.
pub fn install_handler() -> Result<(), String> {
    let flag = global();
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst)).map_err(|e| e.to_string())
}

/// Returns the interrupt error when the flag is set. Transfer sinks call this.
pub fn check(flag: &AtomicBool) -> nfsc::Result<()> {
    if flag.load(Ordering::SeqCst) {
        Err(interrupted())
    } else {
        Ok(())
    }
}

/// The error a transfer returns after an interrupt.
pub fn interrupted() -> Error {
    Error::Io(io::Error::new(io::ErrorKind::Interrupted, "interrupted"))
}

/// True for the error produced by [`check`].
pub fn is_interrupt(e: &Error) -> bool {
    matches!(e, Error::Io(io) if io.kind() == io::ErrorKind::Interrupted)
}
