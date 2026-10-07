//! The ASN.1 encodings PKCS#7 signatures and X.509 certificates arrive in: one tag-length-value
//! at a time, definite lengths (DER) and the indefinite ones BER also allows, low tag numbers
//! only. Enough for the structures `pkcs7` walks; anything else is refused.

/// One element.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The contents (for an indefinite length, without the end-of-contents octets).
    pub value: &'a [u8],
    /// The whole element as encoded.
    pub raw: &'a [u8],
}

pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
/// [0] constructed (context-specific).
pub const CTX0: u8 = 0xa0;
/// [1] constructed.
pub const CTX1: u8 = 0xa1;
/// [3] constructed.
pub const CTX3: u8 = 0xa3;
/// [0] primitive.
pub const CTX0_PRIMITIVE: u8 = 0x80;

/// Nesting deeper than any certificate or signature needs is refused.
const MAX_DEPTH: u32 = 32;

/// The element at the start of `input`, and what follows it.
pub fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    read_at(input, 0)
}

fn read_at(input: &[u8], depth: u32) -> Option<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None; // high tag numbers: none in what is parsed here
    }
    let (&first, mut rest) = rest.split_first()?;
    let header = input.len().checked_sub(rest.len())?;
    if first == 0x80 {
        // Indefinite: constructed only, its elements up to the end-of-contents octets.
        if tag & 0x20 == 0 {
            return None;
        }
        let start = rest;
        let mut len = 0usize;
        loop {
            if rest.get(..2) == Some(&[0, 0]) {
                let value = start.get(..len)?;
                let total = header.checked_add(len)?.checked_add(2)?;
                return Some((
                    Tlv {
                        tag,
                        value,
                        raw: input.get(..total)?,
                    },
                    rest.get(2..)?,
                ));
            }
            let (child, after) = read_at(rest, depth.checked_add(1)?)?;
            len = len.checked_add(child.raw.len())?;
            rest = after;
        }
    }
    let (len, header) = if first < 0x80 {
        (usize::from(first), header)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = rest.get(..n)?;
        rest = rest.get(n..)?;
        let len = bytes.iter().try_fold(0usize, |acc, b| {
            acc.checked_mul(256)?.checked_add(usize::from(*b))
        })?;
        (len, header.checked_add(n)?)
    };
    let value = rest.get(..len)?;
    let total = header.checked_add(len)?;
    Some((
        Tlv {
            tag,
            value,
            raw: input.get(..total)?,
        },
        rest.get(len..)?,
    ))
}

/// The element at the start of `input`, which must have tag `tag`.
pub fn expect(input: &[u8], tag: u8) -> Option<(Tlv<'_>, &[u8])> {
    let (tlv, rest) = read(input)?;
    (tlv.tag == tag).then_some((tlv, rest))
}

/// The elements of a constructed value, in order.
pub fn children(value: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (tlv, after) = read(rest)?;
        out.push(tlv);
        rest = after;
    }
    Some(out)
}

/// An INTEGER's magnitude, without the leading zero of a positive value.
pub fn unsigned(value: &[u8]) -> &[u8] {
    match value.split_first() {
        Some((0, rest)) if !rest.is_empty() => rest,
        _ => value,
    }
}

/// Encoded OBJECT IDENTIFIER contents (without tag and length).
pub mod oids {
    pub const SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    pub const MESSAGE_DIGEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    pub const SHA1_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    pub const SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
    pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    pub const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
}
