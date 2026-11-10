//! Offline NFSv4 wire tests: byte-exact COMPOUND encodings, fattr4 decoding,
//! READDIR replies and status mapping. No network access.

use nfsc::fs::{FileType, NfsVersion, SetAttr, SetTime, Status, Time};
use nfsc::nfs4::compound::{CompoundArgs, CompoundRes};
use nfsc::nfs4::ops::{ChannelAttrs, Op, Res, ResOp};
use nfsc::nfs4::types::{StateId, attr, bitmap, encode_setattr};
use nfsc::xdr::{Encoder, from_bytes, to_bytes};

/// Big-endian u32 words to bytes.
fn words(ws: &[u32]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_be_bytes()).collect()
}

#[test]
fn exchange_id_args_bytes() {
    let op = Op::ExchangeId {
        verifier: [1; 8],
        owner: b"ab".to_vec(),
    };
    let mut want = words(&[42]);
    want.extend_from_slice(&[1; 8]);
    want.extend(words(&[2]));
    want.extend_from_slice(b"ab\0\0");
    want.extend(words(&[0x0001_0000, 0, 0])); // flags USE_NON_PNFS, SP4_NONE, empty impl id list
    assert_eq!(to_bytes(&op), want);
}

#[test]
fn sequence_putrootfh_getattr_compound_bytes() {
    let args = CompoundArgs {
        minor: 1,
        ops: vec![
            Op::Sequence {
                session: [0xab; 16],
                seqid: 5,
                slot: 0,
                highest: 0,
            },
            Op::Putrootfh,
            Op::Getattr(vec![attr::TYPE]),
        ],
    };
    let mut want = words(&[0, 1, 3]); // empty tag, minorversion 1, three ops
    want.extend(words(&[53]));
    want.extend_from_slice(&[0xab; 16]);
    want.extend(words(&[5, 0, 0, 0])); // seqid, slot, highest, cachethis=false
    want.extend(words(&[24]));
    want.extend(words(&[9, 1, 2])); // GETATTR, bitmap of one word: bit 1 (TYPE)
    assert_eq!(to_bytes(&args), want);
}

#[test]
fn create_session_args_bytes() {
    let chan = ChannelAttrs {
        headerpadsize: 1,
        maxrequestsize: 2,
        maxresponsesize: 3,
        maxresponsesize_cached: 4,
        maxoperations: 5,
        maxrequests: 6,
    };
    let op = Op::CreateSession {
        clientid: 0x0102_0304_0506_0708,
        sequence: 9,
        fore: chan,
        back: chan,
        cb_program: 7,
    };
    let mut want = words(&[43]);
    want.extend(words(&[0x0102_0304, 0x0506_0708, 9, 0])); // clientid, sequence, flags
    let ch = [1, 2, 3, 4, 5, 6, 0]; // six attrs + empty rdma_ird
    want.extend(words(&ch));
    want.extend(words(&ch));
    want.extend(words(&[7, 1, 0])); // cb_program, one sec_parms entry, AUTH_NONE
    assert_eq!(to_bytes(&op), want);
}

#[test]
fn close_and_readlink_result_decode() {
    // CLOSE result: stateid
    let mut b = words(&[4, 0]);
    b.extend(words(&[3]));
    b.extend([7; 12]);
    let r: ResOp = from_bytes(&b).unwrap();
    assert_eq!(
        r.body,
        Res::Stateid(StateId {
            seqid: 3,
            other: [7; 12]
        })
    );

    // READLINK result: "target"
    let mut b = words(&[27, 0, 6]);
    b.extend_from_slice(b"target");
    b.extend_from_slice(&[0, 0]);
    let r: ResOp = from_bytes(&b).unwrap();
    assert_eq!(r.body, Res::Readlink(b"target".to_vec()));
}

#[test]
fn getattr_fattr4_decode_and_conversion() {
    // type=DIR(2), size=4096, mode=0o755 (0x1ed), owner "1000", group "alice@example.com",
    // numlinks=3, time_modify = (1700000000, 5)
    let mut vals = Encoder::new();
    vals.put_u32(2); // type
    vals.put_u64(4096); // size
    vals.put_u32(0o755); // mode
    vals.put_u32(3); // numlinks
    vals.put_string(b"1000");
    vals.put_string(b"alice@example.com");
    vals.put_i64(1_700_000_000).put_u32(5); // time_modify
    let vals = vals.into_inner();
    let bm = bitmap(&[
        attr::TYPE,
        attr::SIZE,
        attr::MODE,
        attr::NUMLINKS,
        attr::OWNER,
        attr::OWNER_GROUP,
        attr::TIME_MODIFY,
    ]);
    let mut b = words(&[9, 0]); // GETATTR, OK
    b.extend(words(&[bm.len() as u32]));
    b.extend(words(&bm));
    b.extend(words(&[vals.len() as u32]));
    b.extend_from_slice(&vals);
    let r: ResOp = from_bytes(&b).unwrap();
    let Res::Attr(a) = r.body else {
        panic!("not an attr")
    };
    let attr = a.to_attr();
    assert_eq!(attr.ftype, FileType::Directory);
    assert_eq!(attr.size, 4096);
    assert_eq!(attr.mode, 0o755);
    assert_eq!(attr.nlink, 3);
    assert_eq!(attr.uid, 1000);
    assert_eq!(attr.gid, u32::MAX, "user@domain owner maps to the sentinel");
    assert_eq!(attr.owner.as_deref(), Some("1000"));
    assert_eq!(attr.group.as_deref(), Some("alice@example.com"));
    assert_eq!(
        attr.mtime,
        Time {
            seconds: 1_700_000_000,
            nseconds: 5
        }
    );
}

#[test]
fn attr_decode_rejects_unrequested_attribute() {
    // A reply that carries attribute 2 (fh_expire_type), which we never request.
    let b = words(&[9, 0, 1, 1 << 2, 1, 0]);
    assert!(from_bytes::<ResOp>(&b).is_err());
}

#[test]
fn readdir_reply_decode() {
    // READDIR OK: verifier, two entries (one with a filehandle), eof=true.
    let mut attrs = Encoder::new();
    attrs.put_u32(1); // type = REG
    attrs.put_u64(12);
    let attrs = attrs.into_inner();
    let bm = bitmap(&[attr::TYPE, attr::SIZE]);

    let mut b = words(&[26, 0]);
    b.extend_from_slice(&[9; 8]); // cookieverf
    b.extend(words(&[1, 0, 11, 1])); // present, cookie hi/lo, name length 1
    b.extend_from_slice(b"a\0\0\0");
    b.extend(words(&[bm.len() as u32]));
    b.extend(words(&bm));
    b.extend(words(&[attrs.len() as u32]));
    b.extend_from_slice(&attrs);
    // list terminator, then eof
    b.extend(words(&[0, 1]));

    let r: ResOp = from_bytes(&b).unwrap();
    let Res::Readdir {
        verifier,
        entries,
        eof,
    } = r.body
    else {
        panic!("not readdir")
    };
    assert_eq!(verifier, [9; 8]);
    assert!(eof);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cookie, 11);
    assert_eq!(entries[0].name, b"a");
    assert_eq!(entries[0].attrs.to_attr().ftype, FileType::Regular);
    assert_eq!(entries[0].attrs.to_attr().size, 12);
}

#[test]
fn compound_res_minor_version_mismatch() {
    // status NFS4ERR_MINOR_VERS_MISMATCH (10021), no results.
    let res: CompoundRes = from_bytes(&words(&[10021, 0, 0])).unwrap();
    assert_eq!(res.status, 10021);
    assert!(res.results.is_empty());
    assert_eq!(
        Status::from_v4(10021, 2),
        Status::Other(NfsVersion::V4(2), 10021)
    );
}

#[test]
fn status_mapping() {
    assert_eq!(Status::from_v4(2, 1), Status::NoEnt);
    assert_eq!(Status::from_v4(21, 0), Status::IsDir);
    assert_eq!(Status::from_v4(10008, 0), Status::Jukebox);
    assert_eq!(Status::from_v4(10004, 1), Status::NotSupp);
    assert_eq!(
        Status::from_v4(10063, 1),
        Status::Other(NfsVersion::V4(1), 10063)
    );
}

#[test]
fn setattr_encoding_is_ascending_and_numeric_owner() {
    let a = SetAttr {
        mode: Some(0o640),
        uid: Some(1000),
        size: Some(10),
        mtime: Some(SetTime::Client(Time {
            seconds: 5,
            nseconds: 6,
        })),
        atime: Some(SetTime::ServerNow),
        ..Default::default()
    };
    let f = encode_setattr(&a, None);
    // size(4), mode(33), owner(36), time_access_set(48), time_modify_set(54)
    assert_eq!(f.bitmap, bitmap(&[4, 33, 36, 48, 54]));
    let mut want = Encoder::new();
    want.put_u64(10).put_u32(0o640).put_string(b"1000");
    want.put_u32(0); // SET_TO_SERVER_TIME4
    want.put_u32(1).put_i64(5).put_u32(6); // SET_TO_CLIENT_TIME4
    assert_eq!(f.vals, want.into_inner());
}

#[test]
fn stateid_roundtrip_and_anon() {
    let s = StateId {
        seqid: 2,
        other: [3; 12],
    };
    let b = to_bytes(&s);
    assert_eq!(b.len(), 16);
    assert_eq!(from_bytes::<StateId>(&b).unwrap(), s);
    assert_eq!(to_bytes(&nfsc::nfs4::types::ANON_STATEID), vec![0u8; 16]);
}

#[test]
fn write_args_use_file_sync() {
    let op = Op::Write {
        stateid: StateId::default(),
        offset: 0x10,
        data: b"xyz".to_vec(),
        stable: 2,
    };
    let b = to_bytes(&op);
    // opcode 38, stateid(16), offset(8), stable=2, opaque(3 + pad)
    assert_eq!(&b[..4], &words(&[38])[..]);
    assert_eq!(&b[4 + 16 + 8..4 + 16 + 8 + 4], &words(&[2])[..]);
    assert_eq!(&b[b.len() - 8..], &[0, 0, 0, 3, b'x', b'y', b'z', 0]);
}

#[test]
fn unstable_write_args_encode_stable_how_zero() {
    use nfsc::nfs4::ops::UNSTABLE4;
    let op = Op::Write {
        stateid: StateId::default(),
        offset: 0x20,
        data: b"ab".to_vec(),
        stable: UNSTABLE4,
    };
    let b = to_bytes(&op);
    // opcode 38, stateid(16), offset(8), stable_how=0 (UNSTABLE4), opaque(2 + pad)
    assert_eq!(&b[..4], &words(&[38])[..]);
    assert_eq!(&b[4 + 16 + 8..4 + 16 + 8 + 4], &words(&[0])[..]);
}

#[test]
fn unset_setattr_is_empty() {
    // A SetAttr with nothing set encodes to an empty fattr4.
    let f = encode_setattr(&SetAttr::default(), None);
    assert!(f.is_empty());
    assert!(f.vals.is_empty());
}

/// Nothing listening on the NFS port: negotiation must see "version not offered"
/// so the caller can fall back to another protocol version.
#[test]
fn connection_refused_is_version_unsupported() {
    use nfsc::fs::{ConnectOptions, VersionPref};
    use nfsc::rpc::RpcOptions;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let opts = ConnectOptions {
        rpc: RpcOptions::default(),
        nfs_port: Some(port),
        mount_port: None,
        version: VersionPref::AnyV4,
    };
    let err = nfsc::nfs4::connect("127.0.0.1".parse().unwrap(), b"/", None, &opts)
        .err()
        .unwrap();
    assert!(err.is_version_unsupported(), "got {err}");
}

/// COMPOUND reply: OPEN (with the given open_delegation4 words) followed by
/// GETFH, so a mis-sized delegation decode shows up as a broken GETFH.
fn open_then_getfh(deleg: &[u32]) -> Vec<u8> {
    let mut b = words(&[0, 0, 2]); // OK, empty tag, two results
    b.extend(words(&[18, 0, 1])); // OPEN OK, stateid.seqid
    b.extend([9; 12]);
    b.extend(words(&[1, 0, 1, 0, 2])); // change_info4: atomic, before, after
    b.extend(words(&[4, 0])); // rflags LOCKTYPE_POSIX, empty attrset
    b.extend(words(deleg));
    b.extend(words(&[10, 0, 2])); // GETFH OK, fh length 2
    b.extend([0xfe, 0xed, 0, 0]);
    b
}

#[test]
fn open_delegate_none_ext_decodes() {
    // OPEN_DELEGATE_NONE_EXT with WND4_CONTENTION (carries a bool),
    // WND4_RESOURCE (carries a bool), and WND4_NOT_WANTED (no extra field).
    for deleg in [&[3, 7, 1][..], &[3, 8, 0], &[3, 0]] {
        let res: CompoundRes = from_bytes(&open_then_getfh(deleg)).unwrap();
        assert_eq!(res.results.len(), 2, "{deleg:?}");
        assert_eq!(
            res.results[0].body,
            Res::Open {
                stateid: StateId {
                    seqid: 1,
                    other: [9; 12]
                },
                rflags: 4,
                deleg: None
            }
        );
        assert_eq!(res.results[1].body, Res::Fh(vec![0xfe, 0xed]), "{deleg:?}");
    }
}
