//! NFSv4.1+ client ID and session establishment (EXCHANGE_ID, CREATE_SESSION,
//! RECLAIM_COMPLETE). Teardown lives in backend.rs (DESTROY_SESSION /
//! DESTROY_CLIENTID).

use crate::error::{Error, Result};

use super::backend::{
    CB_PROGRAM, CHAN_REQUEST, MAX_SLOTS, Nfs4Backend, Session, back_channel_request, body,
    fore_channel_request,
};
use super::ops::{Op, Res};
use super::types::code;

impl Nfs4Backend {
    /// EXCHANGE_ID, CREATE_SESSION, then RECLAIM_COMPLETE(one_fs = false).
    /// Leaves the backend with a new clientid, session and seqid 1 on slot 0.
    /// NFS4ERR_DELAY and NFS4ERR_GRACE are retried with backoff.
    pub(super) fn establish_41(&mut self) -> Result<()> {
        let verifier = self.new_verifier();
        let owner = self.owner_id.clone();
        let res = self.send_setup(false, |_| {
            vec![Op::ExchangeId {
                verifier,
                owner: owner.clone(),
            }]
        })?;
        let res = self.check(res)?;
        let (clientid, sequence) = match body(&res, 0)? {
            Res::ExchangeId { clientid, sequence } => (*clientid, *sequence),
            _ => return Err(Error::Xdr("expected EXCHANGE_ID result".into())),
        };
        self.create_seq = sequence;
        self.create_session(clientid)?;
        self.clientid = clientid;
        self.open_seqid = 0;

        let res = self.send_setup(true, |_| vec![Op::ReclaimComplete])?;
        if res.status != code::OK && res.status != code::COMPLETE_ALREADY {
            return Err(self.status_err(res.status));
        }
        Ok(())
    }

    /// CREATE_SESSION on `clientid` with the next csa_sequence. On success the
    /// backend has a fresh session (seqid 1 on every slot). Open state held by
    /// the client ID is unaffected, so this also recovers from a lost session.
    pub(super) fn create_session(&mut self, clientid: u64) -> Result<()> {
        let sequence = self.create_seq;
        let res = self.send_setup(false, |_| {
            vec![Op::CreateSession {
                clientid,
                sequence,
                fore: fore_channel_request(),
                back: back_channel_request(),
                cb_program: CB_PROGRAM,
            }]
        })?;
        let res = self.check(res)?;
        let (id, fore) = match body(&res, 0)? {
            Res::CreateSession { session, fore, .. } => (*session, *fore),
            _ => return Err(Error::Xdr("expected CREATE_SESSION result".into())),
        };
        self.create_seq = sequence.wrapping_add(1);
        // The server grants at most `fore.maxrequests` slots; each starts at seqid 1.
        let slots = fore.maxrequests.clamp(1, MAX_SLOTS) as usize;
        self.session = Some(Session {
            id,
            slot_seq: vec![1; slots],
            busy: vec![false; slots],
            max_req: fore.maxrequestsize.min(CHAN_REQUEST),
            max_resp: fore.maxresponsesize.min(CHAN_REQUEST),
        });
        Ok(())
    }
}
