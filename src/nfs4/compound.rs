//! COMPOUND4args / COMPOUND4res (RFC 8881 section 16.2), NFSv4 procedure 1.

use crate::error::Result;
use crate::xdr::{Decoder, Encoder, Pack, Unpack};

use super::ops::{Op, ResOp};

pub const PROC_COMPOUND: u32 = 1;

/// COMPOUND4args: an empty tag, the minor version, and the operations.
pub struct CompoundArgs {
    pub minor: u32,
    pub ops: Vec<Op>,
}

impl Pack for CompoundArgs {
    fn pack(&self, e: &mut Encoder) {
        e.put_string(&[]);
        e.put_u32(self.minor);
        e.put_array(&self.ops);
    }
}

/// COMPOUND4res. `results` ends at the first failing operation; the failing
/// operation is the last element and carries `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompoundRes {
    pub status: u32,
    pub results: Vec<ResOp>,
}

impl Unpack for CompoundRes {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        let status = d.get_u32()?;
        let _tag = d.get_string()?;
        let results = d.get_array::<ResOp>()?;
        Ok(CompoundRes { status, results })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs4::ops::Op;
    use crate::xdr::{from_bytes, to_bytes};

    #[test]
    fn empty_compound_args_bytes() {
        let args = CompoundArgs {
            minor: 2,
            ops: vec![],
        };
        // tag "" , minorversion 2, zero ops
        assert_eq!(to_bytes(&args), vec![0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0]);
    }

    #[test]
    fn compound_res_with_error_stops_early() {
        // status NOENT(2), tag "", 1 result: PUTFH (22) with status NOENT
        let bytes = [0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 22, 0, 0, 0, 2];
        let res: CompoundRes = from_bytes(&bytes).unwrap();
        assert_eq!(res.status, 2);
        assert_eq!(res.results.len(), 1);
        assert_eq!(res.results[0].status, 2);
        let _ = Op::Getfh;
    }
}
