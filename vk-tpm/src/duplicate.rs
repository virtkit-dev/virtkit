//! Duplication (Part 3, "Duplication Commands"; the reference's `Duplicate.c`, `Import.c` and
//! `Object_spt.c`): TPM2_Duplicate exports an object that is not fixedParent for another parent,
//! perhaps another TPM's; TPM2_Import takes such a duplicate in under one of this TPM's parents.
//!
//! A duplicate is the object's sensitive area (a TPM2B_SENSITIVE), wrapped up to twice: inside,
//! with an integrity digest and a symmetric key the caller chooses (or the TPM, which then
//! returns it); outside, as a credential is, under a seed encrypted to the new parent with the
//! label "DUPLICATE". TPM2_Rewrap is not implemented.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST};
use crate::commands::{end, first};
use crate::crypt;
use crate::entity::TPM_RH_NULL;
use crate::key::{Key, MAX_DATA, MAX_ENCRYPTED_SECRET, MAX_PRIVATE};
use crate::marshal::{Reader, Writer};
use crate::protection::{load_checked, outer_unwrap, outer_wrap, wrap};
use crate::public::{Public, Sensitive, SymDef, Type, attr};
use crate::rc::{Rc, Result};
use crate::{Out, Tpm};

/// The label a duplicate's seed is encrypted with (DUPLICATE_STRING).
const DUPLICATE: &[u8] = b"DUPLICATE\0";

/// ObjectIsStorage: a duplicate's destination key (restricted, decrypts, does not sign; RSA
/// or ECC). Only its public area is required.
fn is_storage(key: &Key) -> bool {
    let p = &key.public;
    p.has(attr::RESTRICTED)
        && p.has(attr::DECRYPT)
        && !p.has(attr::SIGN)
        && matches!(p.kind(), Type::Rsa | Type::Ecc)
}

/// The inner wrap (ProduceInnerIntegrity): H(data ‖ Name) with the object's nameAlg, then the
/// data, all encrypted with AES-CFB (a zero IV) under `key`.
fn inner_wrap(hash: Hash, key: &[u8], name: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut w = Writer::with_capacity(data.len().saturating_add(2 + MAX_DIGEST));
    w.tpm2b(&hash.digest(&[data, name])).bytes(data);
    let mut wrapped = Zeroizing::new(w.into_bytes());
    crypt::aes_cfb(key, &[0; crypt::AES_BLOCK], &mut wrapped, true)?;
    Ok(wrapped)
}

/// Undo [`inner_wrap`] (CheckInnerIntegrity): TPM_RC_INTEGRITY unless the digest matches.
fn inner_unwrap(hash: Hash, key: &[u8], name: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(data.to_vec());
    crypt::aes_cfb(key, &[0; crypt::AES_BLOCK], &mut data, false)?;
    let mut r = Reader::new(&data);
    let integrity = r.tpm2b(MAX_DIGEST)?;
    if !bool::from(hash.digest(&[r.rest(), name]).ct_eq(integrity)) {
        return Err(Rc::INTEGRITY);
    }
    Ok(Zeroizing::new(r.rest().to_vec()))
}

/// DuplicateToSensitive: unwrap a duplicate for `parent` to its sensitive area:
/// outer wrap with `seed` unless empty, inner wrap with `inner` if given.
fn duplicate_to_sensitive(
    parent: &Key,
    seed: &[u8],
    name: &[u8],
    hash: Hash,
    inner: Option<&[u8]>,
    duplicate: &[u8],
) -> Result<Sensitive> {
    let mut data = Zeroizing::new(duplicate.to_vec());
    if !seed.is_empty() {
        data = outer_unwrap(parent, seed, name, &data)?;
    }
    if let Some(key) = inner {
        data = inner_unwrap(hash, key, name, &data)?;
    }
    let mut r = Reader::new(&data);
    let size = usize::from(r.u16()?);
    if size != r.len() {
        return Err(Rc::SIZE);
    }
    let sensitive = Sensitive::read(&mut r)?;
    if !r.is_empty() {
        return Err(Rc::SIZE);
    }
    Ok(sensitive)
}

/// TPM2_Duplicate: the object (its DUP role: a policy that allows TPM2_Duplicate) wrapped for
/// `newParentHandle`, or TPM_RH_NULL (no outer wrap); inside too if `symmetricAlg` says so.
pub fn duplicate(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let key_in = Zeroizing::new(r.tpm2b(MAX_DATA).map_err(|rc| rc.param(1))?.to_vec());
    let symmetric = SymDef::read(r, true).map_err(|rc| rc.param(2))?;
    end(r)?;
    let object = tpm.key(first(handles)?).ok_or(Rc::TYPE.handle(1))?;
    if object.public.has(attr::FIXED_PARENT) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    let hash = object.public.name_alg.ok_or(Rc::TYPE.handle(1))?;
    let new_parent_handle = handles.get(1).copied().ok_or(Rc::FAILURE)?;
    let new_parent = if new_parent_handle == TPM_RH_NULL {
        None
    } else {
        let key = tpm.key(new_parent_handle).filter(|k| is_storage(k));
        Some(key.ok_or(Rc::TYPE.handle(2))?)
    };
    if object.public.has(attr::ENCRYPTED_DUPLICATION) {
        if symmetric.is_none() {
            return Err(Rc::SYMMETRIC.param(2));
        }
        if new_parent.is_none() {
            return Err(Rc::HIERARCHY.handle(2));
        }
    }
    match symmetric {
        None if !key_in.is_empty() => return Err(Rc::SIZE.param(1)),
        Some(def) if !key_in.is_empty() && key_in.len() != def.key_bytes() => {
            return Err(Rc::SIZE.param(1));
        }
        _ => {}
    }
    let (seed, out_seed) = match new_parent {
        Some(parent) => parent.encrypt_secret(DUPLICATE)?,
        None => (Zeroizing::new(Vec::new()), Vec::new()),
    };
    // The DUP role takes a policy, which an object loaded without its sensitive area does not
    // have: authorization refuses one before this runs.
    let sensitive = object.sensitive.as_ref().ok_or(Rc::AUTH_UNAVAILABLE)?;
    // SensitiveToDuplicate: the TPM2B_SENSITIVE, its authValue padded to the nameAlg's digest.
    let sensitive = sensitive.to_bytes(hash.size());
    let mut data = Writer::with_capacity(sensitive.len().saturating_add(2));
    data.tpm2b(&sensitive);
    let mut data = Zeroizing::new(data.into_bytes());
    // A key the TPM picks is returned; the caller's is not.
    let mut key_out = Zeroizing::new(Vec::new());
    if let Some(def) = symmetric {
        let key = if key_in.is_empty() {
            let mut key = Zeroizing::new(vec![0; def.key_bytes()]);
            getrandom::fill(&mut key).map_err(|_| Rc::FAILURE)?;
            key_out = key.clone();
            key
        } else {
            key_in
        };
        data = inner_wrap(hash, &key, &object.name, &data)?;
    }
    if let Some(parent) = new_parent {
        data = Zeroizing::new(outer_wrap(parent, &seed, &object.name, &data)?);
    }
    w.tpm2b(&key_out).tpm2b(&data).tpm2b(&out_seed);
    Ok(())
}

/// TPM2_Import: rewrap a duplicate made for `parentHandle` under it as TPM2_Create would,
/// for loading with TPM2_Load.
pub fn import(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let key = Zeroizing::new(r.tpm2b(MAX_DATA).map_err(|rc| rc.param(1))?.to_vec());
    let public = Public::read_sized(r, false).map_err(|rc| rc.param(2))?;
    let duplicate = r.tpm2b(MAX_PRIVATE).map_err(|rc| rc.param(3))?;
    let seed_in = r.tpm2b(MAX_ENCRYPTED_SECRET).map_err(|rc| rc.param(4))?;
    let symmetric = SymDef::read(r, true).map_err(|rc| rc.param(5))?;
    end(r)?;
    if public.has(attr::FIXED_TPM) || public.has(attr::FIXED_PARENT) {
        return Err(Rc::ATTRIBUTES.param(2));
    }
    let parent_handle = first(handles)?;
    let parent = tpm.key(parent_handle).filter(|k| k.is_parent());
    let parent = parent.ok_or(Rc::TYPE.handle(1))?;
    let encrypted_duplication = public.has(attr::ENCRYPTED_DUPLICATION);
    match symmetric {
        Some(def) if key.len() != def.key_bytes() => return Err(Rc::SIZE.param(1)),
        None if !key.is_empty() => return Err(Rc::SIZE.param(1)),
        None if encrypted_duplication => return Err(Rc::ATTRIBUTES.param(1)),
        _ => {}
    }
    let seed = if seed_in.is_empty() {
        if encrypted_duplication {
            return Err(Rc::ATTRIBUTES.param(4));
        }
        Zeroizing::new(Vec::new())
    } else {
        if parent.public.kind() == Type::SymCipher {
            return Err(Rc::TYPE.handle(1));
        }
        parent
            .decrypt_secret(DUPLICATE, seed_in)
            .map_err(|rc| rc.param(4))?
    };
    let name = public.name();
    let hash = public.name_alg.ok_or(Rc::HASH.param(2))?;
    let inner = symmetric.map(|_| key.as_slice());
    let sensitive = duplicate_to_sensitive(parent, &seed, &name, hash, inner, duplicate)
        .map_err(|rc| rc.param(3))?;
    // Under a fixedTPM parent the object is checked now, as TPM2_Load will not.
    if parent.public.has(attr::FIXED_TPM) {
        load_checked(None, public.clone(), Some(sensitive.clone()), (2, 3))?;
    }
    let private = wrap(parent, &name, public.name_alg, &sensitive)?;
    w.tpm2b(&private);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sensitive() -> Zeroizing<Vec<u8>> {
        let s = Sensitive {
            kind: Type::KeyedHash,
            auth: Zeroizing::new(b"pw".to_vec()),
            seed: Zeroizing::new(vec![1; 32]),
            secret: Zeroizing::new(b"secret".to_vec()),
        };
        let mut w = Writer::new();
        w.tpm2b(&s.to_bytes(32));
        Zeroizing::new(w.into_bytes())
    }

    #[test]
    fn an_inner_wrap_unwraps_only_for_its_key_and_name() {
        let key = [7u8; 16];
        let data = sensitive();
        let wrapped = inner_wrap(Hash::Sha256, &key, b"name", &data).unwrap();
        assert_eq!(
            *inner_unwrap(Hash::Sha256, &key, b"name", &wrapped).unwrap(),
            *data
        );
        assert_eq!(
            inner_unwrap(Hash::Sha256, &key, b"other", &wrapped),
            Err(Rc::INTEGRITY)
        );
        // Another key decrypts to garbage: whatever its digest's size says, no match.
        assert!(inner_unwrap(Hash::Sha256, &[8; 16], b"name", &wrapped).is_err());
    }

    #[test]
    fn a_duplicate_reads_back_its_sensitive_area() {
        let parent = crate::key::tests::rsa_storage_key(2048);
        let data = sensitive();
        let s = duplicate_to_sensitive(&parent, &[], b"n", Hash::Sha256, None, &data).unwrap();
        assert_eq!(*s.secret, b"secret");
        let (seed, _) = parent.encrypt_secret(DUPLICATE).unwrap();
        let outer = outer_wrap(&parent, &seed, b"n", &data).unwrap();
        let back = duplicate_to_sensitive(&parent, &seed, b"n", Hash::Sha256, None, &outer);
        assert_eq!(back.unwrap(), s);
        // A size that does not cover it exactly, and trailing bytes.
        let mut short = data.to_vec();
        short.pop();
        let r = duplicate_to_sensitive(&parent, &[], b"n", Hash::Sha256, None, &short);
        assert_eq!(r.err(), Some(Rc::SIZE));
    }
}
