//! Time-based authenticated variable writes (UEFI 2.10 §8.2.2), as edk2's AuthVariableLib
//! checks them without SMM's help: the Secure Boot keys and databases against the keys above
//! them, any other time-based authenticated variable against the signer that created it.

use crate::codec::{Reader, Short, ucs2_bytes};
use crate::guid::{self, Guid};
use crate::pkcs7::{Certificate, SignedData};
use crate::siglist;
use crate::store::{EfiTime, Status, Variable};

/// WIN_CERTIFICATE's own header: dwLength, wRevision, wCertificateType.
const WIN_CERT_HEADER: usize = 8;
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0ef1;

/// What a Secure Boot variable is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// PK: by the current PK.
    Pk,
    /// KEK: by the PK.
    Kek,
    /// db, dbx, dbt, dbr: by a KEK, or the PK.
    Db,
}

/// The kind of the variable `name` in `guid`, given that it is written with time-based
/// authentication (or is a Secure Boot variable, which must be).
pub fn kind(guid: &Guid, name: &[u16]) -> Option<Kind> {
    let is = |s: &str| name.iter().copied().eq(s.encode_utf16());
    if *guid == guid::GLOBAL_VARIABLE && is("PK") {
        Some(Kind::Pk)
    } else if *guid == guid::GLOBAL_VARIABLE && is("KEK") {
        Some(Kind::Kek)
    } else if *guid == guid::IMAGE_SECURITY_DATABASE
        && (is("db") || is("dbx") || is("dbt") || is("dbr"))
    {
        Some(Kind::Db)
    } else {
        None
    }
}

/// A parsed EFI_VARIABLE_AUTHENTICATION_2 and what follows it.
pub struct Authenticated<'a> {
    pub timestamp: EfiTime,
    pub signature: &'a [u8],
    pub payload: &'a [u8],
}

/// Split `data` into its EFI_VARIABLE_AUTHENTICATION_2 and payload: SECURITY_VIOLATION if
/// it is not one (as edk2 answers).
pub fn split(data: &[u8]) -> Result<Authenticated<'_>, Status> {
    let parse = || -> Result<Authenticated<'_>, Short> {
        let mut r = Reader::new(data);
        let mut ts = [0u8; 16];
        ts.copy_from_slice(r.take(16)?);
        let length = usize::try_from(r.u32()?).map_err(|_| Short)?;
        r.u16()?; // wRevision
        let cert_type = r.u16()?;
        let kind = r.guid()?;
        if cert_type != WIN_CERT_TYPE_EFI_GUID || kind != guid::CERT_PKCS7 {
            return Err(Short);
        }
        let sig_len = length
            .checked_sub(WIN_CERT_HEADER)
            .and_then(|l| l.checked_sub(16))
            .ok_or(Short)?;
        let signature = r.take(sig_len)?;
        Ok(Authenticated {
            timestamp: EfiTime(ts),
            signature,
            payload: r.rest(),
        })
    };
    let auth = parse().map_err(|_| Status::SECURITY_VIOLATION)?;
    if !auth.timestamp.is_clean() {
        return Err(Status::SECURITY_VIOLATION);
    }
    Ok(auth)
}

/// What a signature covers: the name (no NUL), the vendor GUID, the attributes as written,
/// the timestamp, the payload.
pub fn signed_content(
    name: &[u16],
    guid: &Guid,
    attributes: u32,
    auth: &Authenticated<'_>,
) -> Vec<u8> {
    let mut name_bytes = ucs2_bytes(name);
    name_bytes.truncate(name_bytes.len().saturating_sub(2));
    let mut out = name_bytes;
    out.extend_from_slice(&guid.0);
    out.extend_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&auth.timestamp.0);
    out.extend_from_slice(auth.payload);
    out
}

/// Whether `signature` signs `content` and chains to one of the certificates of the X.509
/// lists in `keys` (PK's or KEK's data).
pub fn signed_by_any(signature: &[u8], content: &[u8], keys: &[&[u8]]) -> bool {
    let Some(signed) = SignedData::parse(signature) else {
        return false;
    };
    keys.iter()
        .flat_map(|data| siglist::certificates(data))
        .filter_map(Certificate::parse)
        .any(|trusted| signed.verify(content, &trusted))
}

/// The identity of a private authenticated variable's signer: SHA-256 of the to-be-signed
/// part of the top of its chain, once the signature checks against it. None if it does not.
pub fn private_signer(signature: &[u8], content: &[u8]) -> Option<[u8; 32]> {
    let signed = SignedData::parse(signature)?;
    let top = signed.top_level()?.clone();
    signed.verify(content, &top).then(|| top.tbs_sha256())
}

/// Whether a payload is fit for a Secure Boot variable of `kind`: well-formed signature lists,
/// and for the PK a single X.509 certificate (or RSA-2048 key).
pub fn payload_fits(kind: Kind, payload: &[u8]) -> bool {
    if payload.is_empty() {
        return true;
    }
    let Some(lists) = siglist::parse(payload) else {
        return false;
    };
    match kind {
        Kind::Pk => matches!(lists.as_slice(), [list]
            if (list.kind == guid::CERT_X509 || list.kind == guid::CERT_RSA2048)
                && list.entries.len() == 1),
        Kind::Kek => lists
            .iter()
            .all(|l| l.kind == guid::CERT_X509 || l.kind == guid::CERT_RSA2048),
        Kind::Db => true,
    }
}

/// Whether a write may replace `existing`'s timestamp with `new`: it must be later, unless the
/// write appends.
pub fn timestamp_ok(existing: Option<&Variable>, new: &EfiTime, append: bool) -> bool {
    append || existing.is_none_or(|v| new.later_than(&v.timestamp))
}
