//! RPC call/reply message encoding (RFC 5531 section 9). (rpc agent owns this file.)

use super::auth::{encode_cred, MAX_AUTH_BODY};
use super::Auth;
use crate::error::{AcceptError, Error, RejectReason, Result};
use crate::xdr::{Decoder, Encoder, Pack};

const RPC_VERSION: u32 = 2;

const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;

const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;

const SUCCESS: u32 = 0;
const PROG_UNAVAIL: u32 = 1;
const PROG_MISMATCH: u32 = 2;
const PROC_UNAVAIL: u32 = 3;
const GARBAGE_ARGS: u32 = 4;
const SYSTEM_ERR: u32 = 5;

const RPC_MISMATCH: u32 = 0;
const AUTH_ERROR: u32 = 1;

/// Encode a complete CALL message (without TCP record marking).
///
/// Layout: xid, CALL, rpcvers=2, prog, vers, proc, credential, verifier
/// (always AUTH_NONE), then the procedure arguments.
pub fn encode_call<A: Pack + ?Sized>(
    xid: u32,
    prog: u32,
    vers: u32,
    procedure: u32,
    auth: &Auth,
    args: &A,
) -> Vec<u8> {
    let mut e = Encoder::with_capacity(128);
    e.put_u32(xid)
        .put_u32(MSG_CALL)
        .put_u32(RPC_VERSION)
        .put_u32(prog)
        .put_u32(vers)
        .put_u32(procedure);
    encode_cred(auth, &mut e);
    encode_cred(&Auth::None, &mut e);
    e.put(args);
    e.into_inner()
}

/// Validate a REPLY message for `xid` and return the procedure-specific result bytes,
/// mapping MSG_DENIED / non-SUCCESS accept_stat to the corresponding Error.
pub fn decode_reply(xid: u32, reply: &[u8]) -> Result<&[u8]> {
    let mut d = Decoder::new(reply);
    let got_xid = d.get_u32()?;
    if got_xid != xid {
        return Err(Error::Protocol(format!(
            "reply xid {got_xid:#010x} does not match call xid {xid:#010x}"
        )));
    }
    match d.get_u32()? {
        MSG_REPLY => {}
        other => return Err(Error::Protocol(format!("expected REPLY, got msg_type {other}"))),
    }
    match d.get_u32()? {
        MSG_ACCEPTED => {
            // Verifier: opaque_auth (flavor, body). We do not check it.
            let _flavor = d.get_u32()?;
            d.get_opaque_max(MAX_AUTH_BODY)?;
            match d.get_u32()? {
                SUCCESS => Ok(d.rest()),
                PROG_UNAVAIL => Err(Error::Accept(AcceptError::ProgUnavail)),
                PROG_MISMATCH => {
                    let low = d.get_u32()?;
                    let high = d.get_u32()?;
                    Err(Error::Accept(AcceptError::ProgMismatch { low, high }))
                }
                PROC_UNAVAIL => Err(Error::Accept(AcceptError::ProcUnavail)),
                GARBAGE_ARGS => Err(Error::Accept(AcceptError::GarbageArgs)),
                SYSTEM_ERR => Err(Error::Accept(AcceptError::SystemErr)),
                other => Err(Error::Protocol(format!("unknown accept_stat {other}"))),
            }
        }
        MSG_DENIED => match d.get_u32()? {
            RPC_MISMATCH => {
                let low = d.get_u32()?;
                let high = d.get_u32()?;
                Err(Error::Rejected(RejectReason::RpcMismatch { low, high }))
            }
            AUTH_ERROR => {
                let stat = d.get_u32()?;
                Err(Error::Rejected(RejectReason::AuthError(stat)))
            }
            other => Err(Error::Protocol(format!("unknown reject_stat {other}"))),
        },
        other => Err(Error::Protocol(format!("unknown reply_stat {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::RejectReason;

    /// Reply header for `xid` with an AUTH_NONE verifier, accepted status.
    fn accepted_header(xid: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&xid.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes()); // REPLY
        v.extend_from_slice(&0u32.to_be_bytes()); // MSG_ACCEPTED
        v.extend_from_slice(&0u32.to_be_bytes()); // verf flavor AUTH_NONE
        v.extend_from_slice(&0u32.to_be_bytes()); // verf body len 0
        v
    }

    fn with_u32(mut v: Vec<u8>, x: u32) -> Vec<u8> {
        v.extend_from_slice(&x.to_be_bytes());
        v
    }

    #[test]
    fn encode_call_auth_none_vector() {
        let msg = encode_call(0x1122_3344, 100000, 2, 0, &Auth::None, &());
        let want: Vec<u8> = [
            &[0x11, 0x22, 0x33, 0x44][..], // xid
            &[0, 0, 0, 0],                 // CALL
            &[0, 0, 0, 2],                 // rpcvers
            &[0, 0x01, 0x86, 0xA0],        // prog 100000
            &[0, 0, 0, 2],                 // vers
            &[0, 0, 0, 0],                 // proc NULL
            &[0, 0, 0, 0, 0, 0, 0, 0],     // cred AUTH_NONE, empty body
            &[0, 0, 0, 0, 0, 0, 0, 0],     // verf AUTH_NONE, empty body
        ]
        .concat();
        assert_eq!(msg, want);
    }

    #[test]
    fn encode_call_auth_sys_vector_with_args() {
        let auth = Auth::Sys {
            stamp: 0x0102_0304,
            machine_name: "h".to_string(),
            uid: 1000,
            gid: 100,
            gids: vec![4, 24],
        };
        let msg = encode_call(0x1122_3344, 100000, 2, 1, &auth, &7u32);
        let want: Vec<u8> = [
            &[0x11, 0x22, 0x33, 0x44][..],
            &[0, 0, 0, 0],
            &[0, 0, 0, 2],
            &[0, 0x01, 0x86, 0xA0],
            &[0, 0, 0, 2],
            &[0, 0, 0, 1],                 // proc 1
            &[0, 0, 0, 1],                 // cred flavor AUTH_SYS
            &[0, 0, 0, 0x20],              // body length 32
            &[1, 2, 3, 4],                 // stamp
            &[0, 0, 0, 1, b'h', 0, 0, 0],  // machinename "h" padded
            &[0, 0, 0x03, 0xE8],           // uid 1000
            &[0, 0, 0, 0x64],              // gid 100
            &[0, 0, 0, 2],                 // gids count
            &[0, 0, 0, 4, 0, 0, 0, 0x18],  // gids 4, 24
            &[0, 0, 0, 0, 0, 0, 0, 0],     // verf AUTH_NONE
            &[0, 0, 0, 7],                 // args
        ]
        .concat();
        assert_eq!(msg, want);
    }

    #[test]
    fn auth_sys_truncates_name_and_gids() {
        let auth = Auth::Sys {
            stamp: 1,
            machine_name: "a".repeat(300),
            uid: 2,
            gid: 3,
            gids: (0..20).collect(),
        };
        let msg = encode_call(9, 1, 1, 0, &auth, &());
        // header (24) + cred flavor (4) + body length (4) + body + verf (8)
        let body_len = u32::from_be_bytes(msg[28..32].try_into().unwrap()) as usize;
        // stamp 4 + name (4 + 255 + 1 pad) + uid 4 + gid 4 + gids (4 + 16*4)
        assert_eq!(body_len, 4 + 260 + 4 + 4 + 68);
        assert_eq!(body_len, 340);
        assert_eq!(msg.len(), 24 + 8 + body_len + 8);
        // machinename length field is 255
        assert_eq!(u32::from_be_bytes(msg[36..40].try_into().unwrap()), 255);
        // gids count is 16
        let gids_count_off = 32 + 4 + 260 + 4 + 4;
        assert_eq!(
            u32::from_be_bytes(msg[gids_count_off..gids_count_off + 4].try_into().unwrap()),
            16
        );
    }

    #[test]
    fn decode_success_returns_body_after_verifier() {
        let mut reply = accepted_header(5);
        reply = with_u32(reply, SUCCESS);
        reply.extend_from_slice(&[0, 0, 0, 7]);
        assert_eq!(decode_reply(5, &reply).unwrap(), &[0, 0, 0, 7]);
    }

    #[test]
    fn decode_skips_nonempty_verifier() {
        // verifier: flavor 1, body of 8 bytes
        let mut reply = Vec::new();
        reply.extend_from_slice(&5u32.to_be_bytes());
        reply.extend_from_slice(&1u32.to_be_bytes());
        reply.extend_from_slice(&0u32.to_be_bytes());
        reply.extend_from_slice(&1u32.to_be_bytes());
        reply.extend_from_slice(&8u32.to_be_bytes());
        reply.extend_from_slice(&[9; 8]);
        reply = with_u32(reply, SUCCESS);
        reply.extend_from_slice(b"ok");
        reply.extend_from_slice(&[0, 0]);
        assert_eq!(decode_reply(5, &reply).unwrap(), b"ok\0\0");
    }

    #[test]
    fn decode_empty_success_body() {
        let reply = with_u32(accepted_header(1), SUCCESS);
        assert_eq!(decode_reply(1, &reply).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn decode_accept_errors() {
        let h = |stat| with_u32(accepted_header(3), stat);
        assert!(matches!(
            decode_reply(3, &h(PROG_UNAVAIL)),
            Err(Error::Accept(AcceptError::ProgUnavail))
        ));
        let mut v = with_u32(accepted_header(3), PROG_MISMATCH);
        v = with_u32(v, 2);
        v = with_u32(v, 4);
        assert!(matches!(
            decode_reply(3, &v),
            Err(Error::Accept(AcceptError::ProgMismatch { low: 2, high: 4 }))
        ));
        assert!(matches!(
            decode_reply(3, &h(PROC_UNAVAIL)),
            Err(Error::Accept(AcceptError::ProcUnavail))
        ));
        assert!(matches!(
            decode_reply(3, &h(GARBAGE_ARGS)),
            Err(Error::Accept(AcceptError::GarbageArgs))
        ));
        assert!(matches!(
            decode_reply(3, &h(SYSTEM_ERR)),
            Err(Error::Accept(AcceptError::SystemErr))
        ));
        assert!(matches!(decode_reply(3, &h(99)), Err(Error::Protocol(_))));
    }

    #[test]
    fn decode_denied() {
        // MSG_DENIED, RPC_MISMATCH low=2 high=2
        let mut v = Vec::new();
        v.extend_from_slice(&7u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes()); // MSG_DENIED
        v.extend_from_slice(&0u32.to_be_bytes()); // RPC_MISMATCH
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            decode_reply(7, &v),
            Err(Error::Rejected(RejectReason::RpcMismatch { low: 2, high: 2 }))
        ));

        // MSG_DENIED, AUTH_ERROR AUTH_TOOWEAK (5)
        let mut v = Vec::new();
        v.extend_from_slice(&7u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes()); // AUTH_ERROR
        v.extend_from_slice(&5u32.to_be_bytes());
        assert!(matches!(
            decode_reply(7, &v),
            Err(Error::Rejected(RejectReason::AuthError(5)))
        ));

        // unknown reject_stat
        let mut v = Vec::new();
        v.extend_from_slice(&7u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&9u32.to_be_bytes());
        assert!(matches!(decode_reply(7, &v), Err(Error::Protocol(_))));
    }

    #[test]
    fn decode_header_errors() {
        // xid mismatch
        let r = with_u32(accepted_header(1), SUCCESS);
        assert!(matches!(decode_reply(2, &r), Err(Error::Protocol(_))));
        // msg_type CALL instead of REPLY
        let mut r = accepted_header(1);
        r[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(matches!(decode_reply(1, &r), Err(Error::Protocol(_))));
        // reply_stat 7
        let mut r = accepted_header(1);
        r[8..12].copy_from_slice(&7u32.to_be_bytes());
        assert!(matches!(decode_reply(1, &r), Err(Error::Protocol(_))));
        // truncated
        assert!(matches!(decode_reply(1, &[0, 0, 0]), Err(Error::Xdr(_))));
        let r = accepted_header(1);
        assert!(matches!(decode_reply(1, &r), Err(Error::Xdr(_))));
    }
}
