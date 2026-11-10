//! Deterministic fuzz-style checks: hostile bytes fed to the wire decoders must
//! produce `Err`, never a panic. No external crates; a fixed xorshift PRNG keeps
//! every run identical.

use std::panic::{self, AssertUnwindSafe};

use nfsc::nfs2::proto::Fattr as Fattr2;
use nfsc::nfs3::proto::{ReaddirOk, Reply};
use nfsc::nfs3::types::Fattr3;
use nfsc::nfs4::compound::CompoundRes;
use nfsc::nfs4::types::AttrSet;
use nfsc::rpc::message::decode_reply;
use nfsc::xdr::{Unpack, from_bytes};

const ITERATIONS: usize = 3000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Decodes `buf` with `f`, panicking with the input in hex if `f` panics.
fn must_not_panic<F: FnOnce(&[u8])>(name: &str, buf: &[u8], f: F) {
    let result = panic::catch_unwind(AssertUnwindSafe(|| f(buf)));
    if result.is_err() {
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        panic!("{name} panicked on {} bytes: {hex}", buf.len());
    }
}

/// Random buffers, every prefix of each seed, and seeds with a few bytes flipped.
fn corpus(rng: &mut Rng, seeds: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for _ in 0..ITERATIONS {
        out.push(rng.bytes(256));
    }
    for seed in seeds {
        for cut in 0..=seed.len() {
            out.push(seed[..cut].to_vec());
        }
        for _ in 0..ITERATIONS / seeds.len().max(1) {
            let mut m = seed.clone();
            for _ in 0..1 + rng.below(4) {
                if m.is_empty() {
                    break;
                }
                let i = rng.below(m.len());
                m[i] = match rng.below(3) {
                    0 => rng.next() as u8,
                    1 => 0xff,
                    _ => 0,
                };
            }
            if rng.below(4) == 0 {
                let extra = rng.bytes(16);
                m.extend(extra);
            }
            out.push(m);
        }
    }
    out
}

fn be(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_be_bytes()).collect()
}

fn fuzz<T: Unpack>(name: &str, seeds: &[Vec<u8>]) {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ name.len() as u64);
    for buf in corpus(&mut rng, seeds) {
        must_not_panic(name, &buf, |b| {
            let _ = from_bytes::<T>(b);
        });
    }
}

#[test]
fn fattr3_decoder_never_panics() {
    let valid = be(&[
        1, 0o644, 1, 0, 0, 0, 0, 100, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2,
        0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6,
    ]);
    fuzz::<Fattr3>("fattr3", &[valid]);
}

#[test]
fn readdirplus_reply_never_panics() {
    // status OK, no dir attributes, verifier, one entry (fileid, name, cookie,
    // no attributes, no handle), end of list, eof.
    let mut plus = be(&[0, 0]);
    plus.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    plus.extend(be(&[1]));
    plus.extend(be(&[0, 9]));
    plus.extend(be(&[3]));
    plus.extend_from_slice(b"abc\0");
    plus.extend(be(&[0, 1]));
    plus.extend(be(&[0, 0]));
    plus.extend(be(&[0, 1]));
    // Same shape without the READDIRPLUS attributes, and with eof set.
    let mut plain = be(&[0, 0]);
    plain.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    plain.extend(be(&[1]));
    plain.extend(be(&[0, 9]));
    plain.extend(be(&[1]));
    plain.extend_from_slice(b"x\0\0\0");
    plain.extend(be(&[0, 1]));
    plain.extend(be(&[0, 1]));
    fuzz::<Reply<ReaddirOk<true>>>("readdirplus", &[plus]);
    fuzz::<Reply<ReaddirOk<false>>>("readdir", &[plain]);
}

#[test]
fn compound_reply_never_panics() {
    // COMPOUND4res: status, tag (empty), zero results; and one with a GETFH result.
    let empty = be(&[0, 0, 0, 0, 0]);
    let with_result = be(&[
        0, 0, 0, 0, 1, 10, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    fuzz::<CompoundRes>("compound", &[empty, with_result]);
}

#[test]
fn fattr4_decoder_never_panics() {
    // bitmap4 with one word holding TYPE (bit 1) and SIZE (bit 4), then an
    // opaque block of 12 bytes: a u32 type and a u64 size.
    let mut seed = be(&[1, 0x12, 12, 1]);
    seed.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 7]);
    fuzz::<AttrSet>("fattr4", &[seed]);
}

#[test]
fn nfs2_fattr_decoder_never_panics() {
    let seed = be(&[
        2, 0o100644, 1, 0, 0, 10, 4096, 1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    fuzz::<Fattr2>("fattr2", &[seed]);
}

#[test]
fn rpc_reply_header_never_panics() {
    // xid, REPLY, MSG_ACCEPTED, null verifier, SUCCESS, then a body.
    let accepted = be(&[7, 1, 0, 0, 0, 0, 0, 0, 0]);
    let denied = be(&[7, 1, 1, 0, 0]);
    let seeds = [accepted, denied];
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for buf in corpus(&mut rng, &seeds) {
        must_not_panic("rpc reply", &buf, |b| {
            let _ = decode_reply(7, b);
            let _ = decode_reply(rng_xid(b), b);
        });
    }
}

fn rng_xid(b: &[u8]) -> u32 {
    if b.len() < 4 {
        return 0;
    }
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
