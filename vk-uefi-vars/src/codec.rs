//! Little-endian fields of guest buffers, read and written within bounds: a short buffer is an
//! error, never a panic.

use crate::guid::Guid;

/// A buffer too short for what was asked of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Short;

/// Reads fields one after another from a byte slice.
pub struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes }
    }

    /// The bytes not read yet.
    pub fn rest(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Short> {
        if n > self.bytes.len() {
            return Err(Short);
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Short> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, Short> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    pub fn u16(&mut self) -> Result<u16, Short> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, Short> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, Short> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn guid(&mut self) -> Result<Guid, Short> {
        Ok(Guid(self.array()?))
    }
}

/// Little-endian fields at fixed offsets of a mutable buffer.
pub fn put(buf: &mut [u8], offset: usize, bytes: &[u8]) -> Result<(), Short> {
    let end = offset.checked_add(bytes.len()).ok_or(Short)?;
    buf.get_mut(offset..end)
        .ok_or(Short)?
        .copy_from_slice(bytes);
    Ok(())
}

pub fn get(buf: &[u8], offset: usize, len: usize) -> Result<&[u8], Short> {
    let end = offset.checked_add(len).ok_or(Short)?;
    buf.get(offset..end).ok_or(Short)
}

pub fn get_u32(buf: &[u8], offset: usize) -> Result<u32, Short> {
    Reader::new(get(buf, offset, 4)?).u32()
}

pub fn get_u64(buf: &[u8], offset: usize) -> Result<u64, Short> {
    Reader::new(get(buf, offset, 8)?).u64()
}

/// `value` rounded up to a multiple of `align`, a power of two.
pub fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    Some(value.checked_add(mask)? & !mask)
}

/// A UCS-2 name as its code units, without the terminating NUL, from `bytes` that hold it with
/// the NUL: None if they do not end with one, have an odd length or hold another NUL.
pub fn ucs2_name(bytes: &[u8]) -> Option<Vec<u16>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let (last, name) = units.split_last()?;
    if *last != 0 || name.contains(&0) {
        return None;
    }
    Some(name.to_vec())
}

/// A name's UCS-2 bytes with the terminating NUL.
pub fn ucs2_bytes(name: &[u16]) -> Vec<u8> {
    name.iter()
        .chain(std::iter::once(&0u16))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

/// A name for log lines.
pub fn display_name(name: &[u16]) -> String {
    String::from_utf16_lossy(name)
}
