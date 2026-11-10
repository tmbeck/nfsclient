//! Credential encoding and process-identity helpers. (rpc agent owns this file.)

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use super::Auth;
use crate::xdr::Encoder;

pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
/// Maximum size of an opaque_auth body (RFC 5531 section 8.2).
pub const MAX_AUTH_BODY: usize = 400;
/// Maximum machinename length in AUTH_SYS (RFC 5531 appendix A, authsys_parms).
pub const MAX_MACHINE_NAME: usize = 255;
/// Maximum number of auxiliary gids in AUTH_SYS.
pub const MAX_AUX_GIDS: usize = 16;

/// Overflow id used when the process identity cannot be determined.
const NOBODY: u32 = 65534;

/// Append an `opaque_auth` (flavor + opaque body) for `auth` to `e`.
pub(crate) fn encode_cred(auth: &Auth, e: &mut Encoder) {
    match auth {
        Auth::None => {
            e.put_u32(AUTH_NONE);
            e.put_opaque(&[]);
        }
        Auth::Sys { stamp, machine_name, uid, gid, gids } => {
            let mut body = Encoder::with_capacity(MAX_AUTH_BODY);
            body.put_u32(*stamp);
            let name = machine_name.as_bytes();
            body.put_string(&name[..name.len().min(MAX_MACHINE_NAME)]);
            body.put_u32(*uid).put_u32(*gid);
            body.put_array(&gids[..gids.len().min(MAX_AUX_GIDS)]);
            e.put_u32(AUTH_SYS);
            e.put_opaque(body.as_bytes());
        }
    }
}

/// AUTH_SYS for the current process: uid/gid/groups from /proc/self/status,
/// hostname from /proc/sys/kernel/hostname, stamp from the clock.
pub fn sys_from_process() -> Auth {
    let (uid, gid, gids) = read_ids().unwrap_or((NOBODY, NOBODY, Vec::new()));
    Auth::Sys {
        stamp: now_stamp(),
        machine_name: hostname(),
        uid,
        gid,
        gids,
    }
}

fn read_ids() -> Option<(u32, u32, Vec<u32>)> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let mut uid = None;
    let mut gid = None;
    let mut gids = Vec::new();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = first_u32(rest);
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            gid = first_u32(rest);
        } else if let Some(rest) = line.strip_prefix("Groups:") {
            gids = rest.split_ascii_whitespace().filter_map(|s| s.parse().ok()).collect();
        }
    }
    // Uid/Gid lines are "real effective saved fs"; the first field is the real id.
    Some((uid?, gid?, gids))
}

fn first_u32(s: &str) -> Option<u32> {
    s.split_ascii_whitespace().next()?.parse().ok()
}

fn hostname() -> String {
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(s) = fs::read_to_string(path) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_owned();
            }
        }
    }
    "localhost".to_owned()
}

fn now_stamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_identity_is_populated() {
        match sys_from_process() {
            Auth::Sys { machine_name, .. } => assert!(!machine_name.is_empty()),
            other => panic!("expected AUTH_SYS, got {other:?}"),
        }
    }

    #[test]
    fn auth_none_cred_bytes() {
        let mut e = Encoder::new();
        encode_cred(&Auth::None, &mut e);
        assert_eq!(e.as_bytes(), &[0, 0, 0, 0, 0, 0, 0, 0]);
    }
}
