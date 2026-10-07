//! EFI_SIGNATURE_LIST sequences, the data of PK, KEK, db, dbx, dbt and dbr.

use crate::codec::{Reader, Short};
use crate::guid::{self, Guid};

/// EFI_SIGNATURE_LIST's header: type, list size, header size, signature size.
const LIST_HEADER: usize = 28;
/// EFI_SIGNATURE_DATA's owner GUID, ahead of each signature.
const OWNER: usize = 16;

/// One signature list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List<'a> {
    pub kind: Guid,
    /// SignatureHeader, opaque.
    pub header: &'a [u8],
    pub signature_size: usize,
    /// Each EFI_SIGNATURE_DATA: owner GUID, then the signature.
    pub entries: Vec<&'a [u8]>,
}

impl<'a> List<'a> {
    /// The signatures without their owners.
    pub fn signatures(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.entries.iter().filter_map(|e| e.get(OWNER..))
    }
}

/// The size a signature of `kind` has, for the kinds whose size is fixed (owner included).
fn fixed_size(kind: &Guid) -> Option<usize> {
    let data = match *kind {
        guid::CERT_SHA1 => 20,
        guid::CERT_SHA256 => 32,
        guid::CERT_SHA384 => 48,
        guid::CERT_SHA512 => 64,
        guid::CERT_RSA2048 => 256,
        guid::CERT_X509_SHA256 => 32 + 16,
        guid::CERT_X509_SHA384 => 48 + 16,
        guid::CERT_X509_SHA512 => 64 + 16,
        _ => return None,
    };
    OWNER.checked_add(data)
}

/// Parse `data` as signature lists, each well formed (edk2's CheckSignatureListFormat):
/// sizes consistent, known fixed-size kinds at their size. An empty `data` is no lists.
pub fn parse(data: &[u8]) -> Option<Vec<List<'_>>> {
    let mut lists = Vec::new();
    let mut r = Reader::new(data);
    while !r.rest().is_empty() {
        let list = (|| -> Result<List<'_>, Short> {
            let kind = r.guid()?;
            let list_size = usize::try_from(r.u32()?).map_err(|_| Short)?;
            let header_size = usize::try_from(r.u32()?).map_err(|_| Short)?;
            let signature_size = usize::try_from(r.u32()?).map_err(|_| Short)?;
            let body = list_size.checked_sub(LIST_HEADER).ok_or(Short)?;
            let header = r.take(header_size)?;
            let signatures = body.checked_sub(header_size).ok_or(Short)?;
            if signature_size <= OWNER
                || signatures == 0
                || !signatures.is_multiple_of(signature_size)
            {
                return Err(Short);
            }
            let mut entries = Vec::new();
            for _ in 0..signatures.checked_div(signature_size).ok_or(Short)? {
                entries.push(r.take(signature_size)?);
            }
            Ok(List {
                kind,
                header,
                signature_size,
                entries,
            })
        })()
        .ok()?;
        if fixed_size(&list.kind).is_some_and(|size| size != list.signature_size) {
            return None;
        }
        if list.kind == guid::CERT_X509 && !list.header.is_empty() {
            return None;
        }
        lists.push(list);
    }
    Some(lists)
}

/// The certificates the X.509 lists of `data` hold.
pub fn certificates(data: &[u8]) -> Vec<&[u8]> {
    parse(data)
        .unwrap_or_default()
        .into_iter()
        .filter(|l| l.kind == guid::CERT_X509)
        .flat_map(|l| l.signatures().collect::<Vec<_>>())
        .collect()
}

/// `old` with the signatures of `new` it lacks appended, list by list, as an APPEND_WRITE to a
/// signature database does (edk2's FilterSignatureList): a signature already there, same kind
/// and same bytes owner included, is dropped, and so is a list left empty.
pub fn append(old: &[u8], new: &[u8]) -> Option<Vec<u8>> {
    let existing = parse(old)?;
    let mut out = old.to_vec();
    for list in parse(new)? {
        let fresh: Vec<&[u8]> = list
            .entries
            .iter()
            .copied()
            .filter(|entry| {
                !existing.iter().any(|e| {
                    e.kind == list.kind
                        && e.signature_size == list.signature_size
                        && e.entries.contains(entry)
                })
            })
            .collect();
        if fresh.is_empty() {
            continue;
        }
        let body = list
            .signature_size
            .checked_mul(fresh.len())?
            .checked_add(list.header.len())?;
        let list_size = u32::try_from(body.checked_add(LIST_HEADER)?).ok()?;
        out.extend_from_slice(&list.kind.0);
        out.extend_from_slice(&list_size.to_le_bytes());
        out.extend_from_slice(&u32::try_from(list.header.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&u32::try_from(list.signature_size).ok()?.to_le_bytes());
        out.extend_from_slice(list.header);
        for entry in fresh {
            out.extend_from_slice(entry);
        }
    }
    Some(out)
}
