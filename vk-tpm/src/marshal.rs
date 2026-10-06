//! The TPM's wire format (Part 2/3): big-endian integers and size-prefixed buffers (TPM2B).
//!
//! [`Reader`] is the only thing that looks at command bytes: every read is bounds-checked and
//! fails with the code the reference implementation gives (TPM_RC_INSUFFICIENT when the bytes
//! run out, TPM_RC_SIZE for a TPM2B larger than its type allows).

use crate::rc::{Rc, Result};

/// Reads a command (or the TPM's own state) front to back.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { rest: bytes }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rest.len()
    }

    /// What is left to read.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The next `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let Some((head, rest)) = self.rest.split_at_checked(n) else {
            return Err(Rc::INSUFFICIENT);
        };
        self.rest = rest;
        Ok(head)
    }

    /// A reader over the next `n` bytes, which this one skips.
    pub fn take(&mut self, n: usize) -> Result<Reader<'a>> {
        self.bytes(n).map(Reader::new)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.bytes(N)?;
        bytes.try_into().map_err(|_| Rc::INSUFFICIENT)
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.array::<1>().map(|[b]| b)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.array().map(u16::from_be_bytes)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.array().map(u32::from_be_bytes)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.array().map(u64::from_be_bytes)
    }

    /// A TPM2B's contents, at most `max` bytes long.
    pub fn tpm2b(&mut self, max: usize) -> Result<&'a [u8]> {
        let size = usize::from(self.u16()?);
        if size > max {
            return Err(Rc::SIZE);
        }
        self.bytes(size)
    }

    /// A list's count (TPML), at most `max`.
    pub fn count(&mut self, max: usize) -> Result<usize> {
        let count = usize::try_from(self.u32()?).map_err(|_| Rc::SIZE)?;
        if count > max {
            return Err(Rc::SIZE);
        }
        Ok(count)
    }
}

/// Builds a response (or the TPM's state).
#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    /// A writer that will not reallocate until it holds `capacity` bytes: the TPM's state is
    /// written this way, so no copy of its secrets is left behind in freed memory.
    pub fn with_capacity(capacity: usize) -> Writer {
        Writer {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Writer {
        self.bytes.extend_from_slice(bytes);
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Writer {
        self.bytes.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Writer {
        self.bytes(&v.to_be_bytes())
    }

    pub fn u32(&mut self, v: u32) -> &mut Writer {
        self.bytes(&v.to_be_bytes())
    }

    pub fn u64(&mut self, v: u64) -> &mut Writer {
        self.bytes(&v.to_be_bytes())
    }

    /// A TPM2B. The TPM only writes buffers it sized itself (digests, its own state), all far
    /// below 64 KiB.
    pub fn tpm2b(&mut self, data: &[u8]) -> &mut Writer {
        debug_assert!(data.len() <= usize::from(u16::MAX));
        self.u16(u16::try_from(data.len()).unwrap_or(u16::MAX));
        self.bytes(data)
    }

    /// A list's count (TPML).
    pub fn count(&mut self, n: usize) -> &mut Writer {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_it_is_given_and_no_more() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x00, 0x02, 0xaa, 0xbb, 0x00]);
        assert_eq!(r.u16(), Ok(0x0102));
        assert_eq!(r.u8(), Ok(3));
        assert_eq!(r.tpm2b(2), Ok(&[0xaa, 0xbb][..]));
        assert_eq!(r.u16(), Err(Rc::INSUFFICIENT));
        assert_eq!(r.len(), 1, "a failed read consumes nothing");
    }

    #[test]
    fn a_tpm2b_larger_than_its_type_is_refused() {
        assert_eq!(Reader::new(&[0x00, 0x03, 1, 2, 3]).tpm2b(2), Err(Rc::SIZE));
        assert_eq!(
            Reader::new(&[0x00, 0x03, 1, 2]).tpm2b(8),
            Err(Rc::INSUFFICIENT)
        );
    }

    #[test]
    fn writes_big_endian() {
        let mut w = Writer::new();
        w.u16(0x8001).u32(10).tpm2b(&[9]);
        assert_eq!(w.into_bytes(), [0x80, 0x01, 0, 0, 0, 10, 0, 1, 9]);
    }
}
