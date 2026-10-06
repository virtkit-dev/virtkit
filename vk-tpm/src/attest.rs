//! Attestation (Part 3, "Attestation Commands"; the reference's `Attest_spt.c`): the TPM signs a
//! TPMS_ATTEST about an object (TPM2_Certify, TPM2_CertifyCreation), the PCRs (TPM2_Quote), an
//! NV index (TPM2_NV_Certify), TPM time (TPM2_GetTime) or an audit session
//! (TPM2_GetSessionAuditDigest). And credentials (Part 3, "Object Commands"):
//! TPM2_MakeCredential wraps a secret for an object's Name to a restricted decryption key (an
//! EK), TPM2_ActivateCredential unwraps it only with that key and the object both loaded.
//!
//! An attestation by a key outside the endorsement and platform hierarchies (or by no key)
//! obfuscates the reset counters and the firmware version, so that they cannot tell TPMs apart,
//! as the reference does (FillInAttestInfo).

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST, TPM_ALG_NULL};
use crate::capability::FIRMWARE_VERSION;
use crate::commands::{end, first};
use crate::crypt;
use crate::entity::{MAX_NAME, TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_PLATFORM};
use crate::key::{Key, MAX_DATA, MAX_ENCRYPTED_SECRET, TPM_ST_CREATION, outer_unwrap, outer_wrap};
use crate::marshal::{Reader, Writer};
use crate::nv::{self, MAX_NV_BUFFER_SIZE};
use crate::object::read_hierarchy;
use crate::pcr;
use crate::public::{Scheme, Type, attr};
use crate::rc::{Rc, Result};
use crate::signing::{select_sign_scheme, write_signature};
use crate::{Out, Tpm};

/// TPM_GENERATED_VALUE: what every structure the TPM signs starts with.
const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
const TPM_ST_ATTEST_NV: u16 = 0x8014;
const TPM_ST_ATTEST_SESSION_AUDIT: u16 = 0x8016;
const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
const TPM_ST_ATTEST_TIME: u16 = 0x8019;
const TPM_ST_ATTEST_CREATION: u16 = 0x801a;
const TPM_ST_ATTEST_NV_DIGEST: u16 = 0x801c;
/// TPM2B_ID_OBJECT: sizeof(TPMS_ID_OBJECT), two TPM2B_DIGESTs.
const MAX_ID_OBJECT: usize = 2 * (2 + MAX_DIGEST);
/// The label a credential's seed is encrypted with (IDENTITY_STRING).
const IDENTITY: &[u8] = b"IDENTITY\0";

/// What signs an attestation: a key (by handle) and its scheme, or TPM_RH_NULL (None): the
/// attestation is then not signed.
#[derive(Clone, Copy)]
struct Signer {
    handle: Option<u32>,
    scheme: Scheme,
}

/// IsSigningObject and CryptSelectSignScheme: `handle` (handle number `n`) names a key that
/// signs, or is TPM_RH_NULL; the scheme it signs with (`requested` is parameter `p`).
fn signer(tpm: &Tpm, handle: u32, n: u32, requested: Scheme, p: u32) -> Result<Signer> {
    if handle == TPM_RH_NULL {
        return Ok(Signer {
            handle: None,
            scheme: Scheme::NULL,
        });
    }
    let key = tpm.key(handle).ok_or(Rc::KEY.handle(n))?;
    if !key.public.has(attr::SIGN) || key.public.kind() == Type::SymCipher {
        return Err(Rc::KEY.handle(n));
    }
    let scheme = select_sign_scheme(key, requested).ok_or(Rc::SCHEME.param(p))?;
    Ok(Signer {
        handle: Some(handle),
        scheme,
    })
}

impl Tpm {
    /// FillInAttestInfo and SignAttestInfo: a TPMS_ATTEST of `kind` whose last field is
    /// `attested`, signed by `signer`: the response's TPM2B_ATTEST and TPMT_SIGNATURE.
    fn attest(
        &mut self,
        signer: Signer,
        extra: &[u8],
        kind: u16,
        attested: &[u8],
        w: &mut Out,
    ) -> Result<()> {
        let key = signer.handle.and_then(|h| self.key(h));
        let signer_name = match key {
            Some(key) => key.qualified_name.clone(),
            None => TPM_RH_NULL.to_be_bytes().to_vec(),
        };
        let mut firmware = FIRMWARE_VERSION;
        let mut reset_count = self.permanent.reset_count;
        let mut restart_count = self.volatile.restart_count;
        let identified =
            key.is_some_and(|k| matches!(k.hierarchy, TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM));
        if !identified {
            // KDFa(SHA-512, shProof, "OBFUSCATE", qualifiedSigner): two 64-bit numbers, which the
            // reference reads in the host's order, little-endian wherever it runs.
            let proof = self.permanent.hierarchies.sh_proof.as_slice();
            let mask = crypt::kdfa(Hash::Sha512, proof, b"OBFUSCATE", &signer_name, &[], 16);
            let word = |at: usize| {
                let bytes = mask.get(at..at.saturating_add(8));
                u64::from_le_bytes(bytes.and_then(|b| b.try_into().ok()).unwrap_or_default())
            };
            let (low, high) = (word(0), word(8));
            firmware = firmware.wrapping_add(low);
            reset_count = reset_count.wrapping_add((high >> 32) as u32);
            restart_count = restart_count.wrapping_add(high as u32);
        }
        let p = &self.permanent;
        let mut a = Writer::new();
        a.u32(TPM_GENERATED_VALUE)
            .u16(kind)
            .tpm2b(&signer_name)
            .tpm2b(extra)
            .u64(p.clock)
            .u32(reset_count)
            .u32(restart_count)
            .u8(p.clock_safe.into())
            .u64(firmware)
            .bytes(attested);
        let attest = a.into_bytes();
        w.tpm2b(&attest);
        let Some(key) = key else {
            w.u16(TPM_ALG_NULL);
            return Ok(());
        };
        let hash = signer.scheme.hash.ok_or(Rc::SCHEME)?;
        write_signature(key, signer.scheme, hash, &hash.digest(&[&attest]), w)?;
        // The response tells Clock: a recorded orderly shutdown no longer is one (NvClearOrderly).
        self.clear_orderly();
        Ok(())
    }
}

/// qualifyingData and inScheme, which every attestation command takes first.
fn read_common(r: &mut Reader) -> Result<(Vec<u8>, Scheme)> {
    let extra = r.tpm2b(MAX_DATA).map_err(|rc| rc.param(1))?.to_vec();
    let scheme = Scheme::read_sig(r, true).map_err(|rc| rc.param(2))?;
    Ok((extra, scheme))
}

fn second(handles: &[u32]) -> Result<u32> {
    handles.get(1).copied().ok_or(Rc::FAILURE)
}

/// TPM2_Certify: an object (its ADMIN role) is loaded in this TPM, with these Names.
pub fn certify(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let (extra, requested) = read_common(r)?;
    end(r)?;
    let signer = signer(tpm, second(handles)?, 2, requested, 2)?;
    // A sequence has neither Name.
    let object = first(handles)?;
    let qualified_name = tpm.key(object).map(|k| k.qualified_name.clone());
    let mut attested = Writer::new();
    attested
        .tpm2b(&tpm.entity_name(object))
        .tpm2b(&qualified_name.unwrap_or_default());
    tpm.attest(
        signer,
        &extra,
        TPM_ST_ATTEST_CERTIFY,
        &attested.into_bytes(),
        w,
    )
}

/// TPM2_CertifyCreation: this TPM created the object, with this creation data (its digest and
/// the ticket TPM2_Create or TPM2_CreatePrimary gave).
pub fn certify_creation(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let extra = r.tpm2b(MAX_DATA).map_err(|rc| rc.param(1))?.to_vec();
    let creation_hash = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(2))?.to_vec();
    let requested = Scheme::read_sig(r, true).map_err(|rc| rc.param(3))?;
    let (hierarchy, ticket) = read_creation_ticket(r).map_err(|rc| rc.param(4))?;
    end(r)?;
    let signer = signer(tpm, first(handles)?, 1, requested, 3)?;
    let name = tpm.entity_name(second(handles)?);
    let expected = tpm.creation_ticket_digest(hierarchy, &name, &creation_hash);
    if !bool::from(expected.ct_eq(&ticket)) {
        return Err(Rc::TICKET.param(4));
    }
    let mut attested = Writer::new();
    attested.tpm2b(&name).tpm2b(&creation_hash);
    tpm.attest(
        signer,
        &extra,
        TPM_ST_ATTEST_CREATION,
        &attested.into_bytes(),
        w,
    )
}

/// A TPMT_TK_CREATION: its hierarchy and digest.
fn read_creation_ticket(r: &mut Reader) -> Result<(u32, Vec<u8>)> {
    let tag = r.u16()?;
    if !crate::is_structure_tag(tag) {
        return Err(Rc::VALUE);
    }
    if tag != TPM_ST_CREATION {
        return Err(Rc::TAG);
    }
    let hierarchy = read_hierarchy(r)?;
    Ok((hierarchy, r.tpm2b(MAX_DIGEST)?.to_vec()))
}

/// TPM2_Quote: the digest of the selected PCRs, with the scheme's hash.
pub fn quote(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let (extra, requested) = read_common(r)?;
    let mut selections = pcr::read_selections(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let signer = signer(tpm, first(handles)?, 1, requested, 2)?;
    // TPM_RH_NULL signs with no scheme, so has no hash to quote with.
    let hash = signer.scheme.hash.ok_or(Rc::SCHEME.param(2))?;
    // The PCR allocation from the next power on, as the reference's (gp.pcrAllocated).
    let allocation = &tpm.permanent.allocation;
    let digest = tpm.volatile.pcrs.digest(allocation, &mut selections, hash);
    let mut attested = Writer::new();
    pcr::write_selections(&mut attested, &selections);
    attested.tpm2b(&digest);
    tpm.attest(
        signer,
        &extra,
        TPM_ST_ATTEST_QUOTE,
        &attested.into_bytes(),
        w,
    )
}

/// TPM2_GetSessionAuditDigest: an audit session's digest (the privacy administrator, the
/// endorsement hierarchy, authorizing).
pub fn get_session_audit_digest(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let (extra, requested) = read_common(r)?;
    end(r)?;
    let signer = signer(tpm, second(handles)?, 2, requested, 2)?;
    let handle = handles.get(2).copied().ok_or(Rc::FAILURE)?;
    let session = tpm.session(handle).ok_or(Rc::FAILURE)?;
    let digest = session.audit.clone().ok_or(Rc::TYPE.handle(3))?;
    let exclusive = tpm.volatile.exclusive_audit == Some(handle);
    let mut attested = Writer::new();
    attested.u8(exclusive.into()).tpm2b(&digest);
    let kind = TPM_ST_ATTEST_SESSION_AUDIT;
    tpm.attest(signer, &extra, kind, &attested.into_bytes(), w)
}

/// TPM2_GetTime: TPM time, Clock and the firmware version, none of them obfuscated (the privacy
/// administrator, the endorsement hierarchy, authorizing).
pub fn get_time(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let (extra, requested) = read_common(r)?;
    end(r)?;
    let signer = signer(tpm, second(handles)?, 2, requested, 2)?;
    let mut attested = Writer::new();
    attested.u64(tpm.volatile.time);
    tpm.write_clock_info(&mut attested);
    attested.u64(FIRMWARE_VERSION);
    tpm.attest(
        signer,
        &extra,
        TPM_ST_ATTEST_TIME,
        &attested.into_bytes(),
        w,
    )
}

/// TPM2_NV_Certify: an NV index's Name and part of its data, or, asked for none, the digest of
/// all of it.
pub fn nv_certify(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let (extra, requested) = read_common(r)?;
    let size = usize::from(r.u16().map_err(|rc| rc.param(3))?);
    let offset = usize::from(r.u16().map_err(|rc| rc.param(4))?);
    end(r)?;
    let signer = signer(tpm, first(handles)?, 1, requested, 2)?;
    let (auth, index) = (
        second(handles)?,
        handles.get(2).copied().ok_or(Rc::FAILURE)?,
    );
    let public = tpm.nv_public(index).ok_or(Rc::FAILURE)?;
    nv::read_access(auth, index, &public)?;
    if size.saturating_add(offset) > public.size() {
        return Err(Rc::NV_RANGE);
    }
    if size > MAX_NV_BUFFER_SIZE {
        return Err(Rc::VALUE.param(3));
    }
    let data = tpm.nv_data(index).unwrap_or_default();
    let mut attested = Writer::new();
    attested.tpm2b(&public.name());
    let kind = if size != 0 || offset != 0 {
        let end = offset.saturating_add(size);
        let part = data.get(offset..end).ok_or(Rc::FAILURE)?;
        attested.u16(u16::try_from(offset).map_err(|_| Rc::FAILURE)?);
        attested.tpm2b(part);
        TPM_ST_ATTEST_NV
    } else {
        // No hash without a key: an empty digest.
        let digest = signer.scheme.hash.map(|h| h.digest(&[data]));
        attested.tpm2b(&digest.unwrap_or_default());
        TPM_ST_ATTEST_NV_DIGEST
    };
    tpm.attest(signer, &extra, kind, &attested.into_bytes(), w)
}

/// A restricted decryption key with an asymmetric secret: what a credential is made for (an
/// EK). TPM_RC_TYPE (handle `n`) for any other.
fn credential_key(tpm: &Tpm, handle: u32, n: u32) -> Result<&Key> {
    let key = tpm.key(handle).ok_or(Rc::TYPE.handle(n))?;
    let p = &key.public;
    if !p.kind().is_asymmetric() || !p.has(attr::DECRYPT) || !p.has(attr::RESTRICTED) {
        return Err(Rc::TYPE.handle(n));
    }
    Ok(key)
}

/// TPM2_MakeCredential: `credential` wrapped for the object named `name`, under a seed encrypted
/// to the key (which needs only its public area): what TPM2_ActivateCredential unwraps.
pub fn make_credential(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let credential = Zeroizing::new(r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?.to_vec());
    let name = r.tpm2b(MAX_NAME).map_err(|rc| rc.param(2))?;
    end(r)?;
    let key = credential_key(tpm, first(handles)?, 1)?;
    if credential.len() > key.public.digest_size() {
        return Err(Rc::SIZE.param(1));
    }
    let (seed, secret) = key.encrypt_secret(IDENTITY)?;
    // SecretToCredential: the TPM2B_DIGEST, wrapped as a duplicate's outside is.
    let mut identity = Writer::new();
    identity.tpm2b(&credential);
    let blob = outer_wrap(key, &seed, name, &Zeroizing::new(identity.into_bytes()))?;
    w.tpm2b(&blob).tpm2b(&secret);
    Ok(())
}

/// TPM2_ActivateCredential: the credential TPM2_MakeCredential wrapped for the object
/// `activateHandle` (its ADMIN role), with the seed only `keyHandle` decrypts.
pub fn activate_credential(
    tpm: &mut Tpm,
    handles: &[u32],
    r: &mut Reader,
    w: &mut Out,
) -> Result<()> {
    let blob = r.tpm2b(MAX_ID_OBJECT).map_err(|rc| rc.param(1))?;
    let secret = r.tpm2b(MAX_ENCRYPTED_SECRET).map_err(|rc| rc.param(2))?;
    end(r)?;
    let key = credential_key(tpm, second(handles)?, 2)?;
    let seed = key
        .decrypt_secret(IDENTITY, secret)
        .map_err(|rc| match rc {
            Rc::KEY => Rc::FAILURE,
            rc => rc.param(2),
        })?;
    let name = tpm.entity_name(first(handles)?);
    let credential = unwrap_credential(key, &seed, &name, blob).map_err(|rc| rc.param(1))?;
    w.tpm2b(&credential);
    Ok(())
}

/// CredentialToSecret: the TPM2B_DIGEST the blob holds once unwrapped, which must use it up.
fn unwrap_credential(
    key: &Key,
    seed: &[u8],
    name: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let identity = outer_unwrap(key, seed, name, blob)?;
    let mut r = Reader::new(&identity);
    let credential = Zeroizing::new(r.tpm2b(MAX_DIGEST)?.to_vec());
    if !r.is_empty() {
        return Err(Rc::SIZE);
    }
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::rsa_storage_key;

    #[test]
    fn a_credential_unwraps_only_for_its_name_and_seed() {
        let ek = rsa_storage_key(2048);
        let (seed, secret) = ek.encrypt_secret(IDENTITY).unwrap();
        assert_eq!(*ek.decrypt_secret(IDENTITY, &secret).unwrap(), *seed);
        let mut identity = Writer::new();
        identity.tpm2b(b"the credential");
        let blob = outer_wrap(&ek, &seed, b"name", &identity.into_bytes()).unwrap();
        let credential = unwrap_credential(&ek, &seed, b"name", &blob).unwrap();
        assert_eq!(*credential, b"the credential");
        assert_eq!(
            unwrap_credential(&ek, &seed, b"other", &blob),
            Err(Rc::INTEGRITY)
        );
        assert_eq!(
            unwrap_credential(&ek, &[0; 64], b"name", &blob),
            Err(Rc::INTEGRITY)
        );
    }
}
