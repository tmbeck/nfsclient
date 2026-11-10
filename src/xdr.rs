//! XDR codec (RFC 4506).
//!
//! Everything is big-endian and padded to 4-byte boundaries. Protocol types
//! implement [`Pack`] / [`Unpack`]; helpers cover variable-length opaques,
//! strings, arrays, and optional-data.

use crate::error::{Error, Result};

/// Upper bound for any single variable-length item we will decode, to stop a
/// hostile length prefix from making us allocate gigabytes.
pub const MAX_ITEM_LEN: usize = 64 * 1024 * 1024;

#[inline]
fn pad_len(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

/// Serializes values into a growable buffer.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn put<T: Pack + ?Sized>(&mut self, v: &T) -> &mut Self {
        v.pack(self);
        self
    }

    pub fn put_u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn put_i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn put_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn put_i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn put_bool(&mut self, v: bool) -> &mut Self {
        self.put_u32(v as u32)
    }

    /// Fixed-length opaque: bytes then padding, no length prefix.
    pub fn put_opaque_fixed(&mut self, data: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(data);
        self.buf.resize(self.buf.len() + pad_len(data.len()), 0);
        self
    }

    /// Variable-length opaque: u32 length, bytes, padding.
    pub fn put_opaque(&mut self, data: &[u8]) -> &mut Self {
        self.put_u32(data.len() as u32);
        self.put_opaque_fixed(data)
    }

    /// String: same wire format as variable-length opaque. NFS filenames are
    /// bytes, not necessarily UTF-8, so this takes bytes.
    pub fn put_string(&mut self, s: &[u8]) -> &mut Self {
        self.put_opaque(s)
    }

    /// Variable-length array: u32 count then each element.
    pub fn put_array<T: Pack>(&mut self, items: &[T]) -> &mut Self {
        self.put_u32(items.len() as u32);
        for it in items {
            it.pack(self);
        }
        self
    }

    /// Optional-data (`*T`): bool discriminant then the value if present.
    pub fn put_option<T: Pack>(&mut self, v: Option<&T>) -> &mut Self {
        match v {
            Some(v) => {
                self.put_bool(true);
                v.pack(self);
            }
            None => {
                self.put_bool(false);
            }
        }
        self
    }
}

/// Deserializes values from a borrowed buffer.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Unconsumed bytes.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Error if any bytes remain (use after decoding a full message body).
    pub fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::Xdr(format!("{} trailing bytes", self.remaining())))
        }
    }

    pub fn get<T: Unpack>(&mut self) -> Result<T> {
        T::unpack(self)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Xdr(format!(
                "need {n} bytes at offset {}, only {} remain",
                self.pos,
                self.remaining()
            )));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn get_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn get_i32(&mut self) -> Result<i32> {
        Ok(i32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn get_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn get_i64(&mut self) -> Result<i64> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn get_bool(&mut self) -> Result<bool> {
        match self.get_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(Error::Xdr(format!("invalid bool value {v}"))),
        }
    }

    /// Fixed-length opaque of `n` bytes (plus padding).
    pub fn get_opaque_fixed(&mut self, n: usize) -> Result<&'a [u8]> {
        let data = self.take(n)?;
        self.take(pad_len(n))?;
        Ok(data)
    }

    /// Variable-length opaque with an upper bound on length.
    pub fn get_opaque_max(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.get_u32()? as usize;
        if n > max {
            return Err(Error::Xdr(format!("opaque length {n} exceeds max {max}")));
        }
        self.get_opaque_fixed(n)
    }

    pub fn get_opaque(&mut self) -> Result<&'a [u8]> {
        self.get_opaque_max(MAX_ITEM_LEN)
    }

    pub fn get_opaque_vec(&mut self) -> Result<Vec<u8>> {
        Ok(self.get_opaque()?.to_vec())
    }

    /// String as raw bytes (NFS names need not be UTF-8).
    pub fn get_string(&mut self) -> Result<Vec<u8>> {
        self.get_opaque_vec()
    }

    /// String decoded lossily into UTF-8 (for display-oriented fields).
    pub fn get_string_lossy(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.get_opaque()?).into_owned())
    }

    /// Variable-length array.
    pub fn get_array<T: Unpack>(&mut self) -> Result<Vec<T>> {
        let n = self.get_u32()? as usize;
        // Each element is at least 4 bytes on the wire; reject impossible counts early.
        if n > self.remaining() / 4 + 1 {
            return Err(Error::Xdr(format!(
                "array count {n} exceeds remaining data"
            )));
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(T::unpack(self)?);
        }
        Ok(v)
    }

    /// Optional-data (`*T`).
    pub fn get_option<T: Unpack>(&mut self) -> Result<Option<T>> {
        if self.get_bool()? {
            Ok(Some(T::unpack(self)?))
        } else {
            Ok(None)
        }
    }

    /// XDR linked list idiom (`struct entry { ...; entry *next; }` preceded by a
    /// `*entry` head): repeatedly reads `bool present` then an element.
    pub fn get_list<T: Unpack>(&mut self) -> Result<Vec<T>> {
        let mut v = Vec::new();
        while self.get_bool()? {
            v.push(T::unpack(self)?);
        }
        Ok(v)
    }
}

pub trait Pack {
    fn pack(&self, e: &mut Encoder);
}

pub trait Unpack: Sized {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self>;
}

/// Encode a value into a fresh buffer.
pub fn to_bytes<T: Pack + ?Sized>(v: &T) -> Vec<u8> {
    let mut e = Encoder::new();
    v.pack(&mut e);
    e.into_inner()
}

/// Decode a value, requiring that it consumes the whole buffer.
pub fn from_bytes<T: Unpack>(buf: &[u8]) -> Result<T> {
    let mut d = Decoder::new(buf);
    let v = T::unpack(&mut d)?;
    d.finish()?;
    Ok(v)
}

macro_rules! prim {
    ($t:ty, $put:ident, $get:ident) => {
        impl Pack for $t {
            fn pack(&self, e: &mut Encoder) {
                e.$put(*self);
            }
        }
        impl Unpack for $t {
            fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
                d.$get()
            }
        }
    };
}
prim!(u32, put_u32, get_u32);
prim!(i32, put_i32, get_i32);
prim!(u64, put_u64, get_u64);
prim!(i64, put_i64, get_i64);
prim!(bool, put_bool, get_bool);

/// `void`.
impl Pack for () {
    fn pack(&self, _: &mut Encoder) {}
}
impl Unpack for () {
    fn unpack(_: &mut Decoder<'_>) -> Result<Self> {
        Ok(())
    }
}

/// Variable-length opaque / string as owned bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Opaque(pub Vec<u8>);

impl Pack for Opaque {
    fn pack(&self, e: &mut Encoder) {
        e.put_opaque(&self.0);
    }
}
impl Unpack for Opaque {
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        Ok(Opaque(d.get_opaque_vec()?))
    }
}

impl Pack for str {
    fn pack(&self, e: &mut Encoder) {
        e.put_string(self.as_bytes());
    }
}
impl Pack for String {
    fn pack(&self, e: &mut Encoder) {
        e.put_string(self.as_bytes());
    }
}
impl Unpack for String {
    /// Lossy: invalid UTF-8 is replaced. Use [`Opaque`] for byte-exact names.
    fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
        d.get_string_lossy()
    }
}

impl<T: Pack + ?Sized> Pack for &T {
    fn pack(&self, e: &mut Encoder) {
        (**self).pack(e);
    }
}

macro_rules! tuple {
    ($($n:ident),+) => {
        impl<$($n: Pack),+> Pack for ($($n,)+) {
            #[allow(non_snake_case)]
            fn pack(&self, e: &mut Encoder) {
                let ($($n,)+) = self;
                $($n.pack(e);)+
            }
        }
        impl<$($n: Unpack),+> Unpack for ($($n,)+) {
            fn unpack(d: &mut Decoder<'_>) -> Result<Self> {
                Ok(($($n::unpack(d)?,)+))
            }
        }
    };
}
tuple!(A);
tuple!(A, B);
tuple!(A, B, C);
tuple!(A, B, C, D);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ints_big_endian() {
        let mut e = Encoder::new();
        e.put_u32(0x01020304)
            .put_i32(-1)
            .put_u64(0x0102030405060708)
            .put_bool(true);
        assert_eq!(
            e.as_bytes(),
            &[
                1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 1
            ]
        );
        let mut d = Decoder::new(e.as_bytes());
        assert_eq!(d.get_u32().unwrap(), 0x01020304);
        assert_eq!(d.get_i32().unwrap(), -1);
        assert_eq!(d.get_u64().unwrap(), 0x0102030405060708);
        assert!(d.get_bool().unwrap());
        d.finish().unwrap();
    }

    #[test]
    fn opaque_padding() {
        for n in 0..9 {
            let data: Vec<u8> = (0..n as u8).collect();
            let bytes = to_bytes(&Opaque(data.clone()));
            assert_eq!(bytes.len(), 4 + n + pad_len(n));
            assert_eq!(bytes.len() % 4, 0);
            assert_eq!(from_bytes::<Opaque>(&bytes).unwrap().0, data);
        }
    }

    #[test]
    fn string_wire_format() {
        assert_eq!(to_bytes("abcde"), b"\0\0\0\x05abcde\0\0\0");
    }

    #[test]
    fn truncated_and_bad_values() {
        assert!(from_bytes::<u32>(&[0, 0, 1]).is_err());
        assert!(from_bytes::<bool>(&[0, 0, 0, 2]).is_err());
        assert!(from_bytes::<u32>(&[0, 0, 0, 1, 0]).is_err()); // trailing
        // length claims 8 bytes, only 4 present
        assert!(from_bytes::<Opaque>(&[0, 0, 0, 8, 1, 2, 3, 4]).is_err());
        let mut d = Decoder::new(&[0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(d.get_opaque_max(8).is_err());
    }

    #[test]
    fn arrays_options_lists() {
        let mut e = Encoder::new();
        e.put_array(&[1u32, 2, 3])
            .put_option(Some(&7u32))
            .put_option::<u32>(None);
        // list of two u32s: 1,a,1,b,0
        e.put_bool(true)
            .put_u32(10)
            .put_bool(true)
            .put_u32(20)
            .put_bool(false);
        let mut d = Decoder::new(e.as_bytes());
        assert_eq!(d.get_array::<u32>().unwrap(), vec![1, 2, 3]);
        assert_eq!(d.get_option::<u32>().unwrap(), Some(7));
        assert_eq!(d.get_option::<u32>().unwrap(), None);
        assert_eq!(d.get_list::<u32>().unwrap(), vec![10, 20]);
        d.finish().unwrap();
    }

    #[test]
    fn hostile_array_count() {
        let mut d = Decoder::new(&[0xff, 0xff, 0xff, 0xff]);
        assert!(d.get_array::<u32>().is_err());
    }

    #[test]
    fn tuples() {
        let v = (1u32, Opaque(b"x".to_vec()), true);
        let b = to_bytes(&v);
        assert_eq!(from_bytes::<(u32, Opaque, bool)>(&b).unwrap(), v);
    }
}
