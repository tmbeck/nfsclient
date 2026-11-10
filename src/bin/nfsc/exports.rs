//! `nfsc exports host`: MOUNT EXPORT, printed like `showmount -e host`.

use std::io::Write;

use nfsc::mount::{self, Export};
use nfsc::rpc::Auth;

use crate::cli::{self, CmdError, Globals};
use crate::text::display_name;

/// The showmount layout: a header, then each directory left-justified to the
/// widest one, one space, and the comma-separated groups (`(everyone)` if none).
pub fn format(host: &str, exports: &[Export]) -> String {
    let dirs: Vec<String> = exports.iter().map(|e| display_name(&e.dir)).collect();
    let width = dirs.iter().map(|d| d.chars().count()).max().unwrap_or(0);
    let mut out = format!("Export list for {host}:\n");
    for (dir, export) in dirs.iter().zip(exports) {
        let groups = if export.groups.is_empty() {
            "(everyone)".to_string()
        } else {
            export.groups.join(",")
        };
        out.push_str(&format!("{dir:<width$} {groups}\n"));
    }
    out
}

pub fn run(g: &Globals, host: &str) -> Result<(), CmdError> {
    let ip = cli::resolve(host)?;
    // MOUNT EXPORT is normally answered without credentials.
    let opts = cli::rpc_options(g, Auth::None);
    let list = mount::exports(ip, g.mount_port, &opts)?;
    std::io::stdout()
        .lock()
        .write_all(format(host, &list).as_bytes())
        .map_err(|e| CmdError::Failed(format!("write failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(dir: &str, groups: &[&str]) -> Export {
        Export {
            dir: dir.as_bytes().to_vec(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    #[test]
    fn matches_showmount_layout() {
        let list = vec![
            export("/export", &[]),
            export("/srv/data", &["10.0.0.0/8", "192.168.1.0/24"]),
        ];
        assert_eq!(
            format("nas", &list),
            "Export list for nas:\n\
             /export   (everyone)\n\
             /srv/data 10.0.0.0/8,192.168.1.0/24\n"
        );
    }

    #[test]
    fn header_only_when_there_are_no_exports() {
        assert_eq!(format("nas", &[]), "Export list for nas:\n");
    }
}
