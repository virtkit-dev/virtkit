//! Object protection (Part 1, "Protected Storage"; `Object_spt.c`): a child's sensitive area
//! wrapped under its parent's seed for storage outside the TPM, and the checks an object passes
//! before it is loaded (ObjectLoad, CryptValidateKeys).

use zeroize::Zeroizing;

use crate::alg::{Hash, MAX_DIGEST};
use crate::asym;
use crate::crypt;
use crate::key::{Key, hash_block_size, symmetric_unique};
use crate::marshal::{Reader, Writer};
use crate::public::{self, MAX_SYM_DATA, Params, Parent, Public, Sensitive, Unique, attr};
use crate::rc::{Rc, Result};

/// The AES block: the IV of a wrapped sensitive area.
const IV_SIZE: usize = crypt::AES_BLOCK;

/// The parent's nameAlg, and the symmetric key and HMAC key that protect a child.
type Protection = (Hash, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

/// The keys that protect a child of `parent` named `name` (ComputeProtectionKeyParms,
/// ComputeOuterIntegrity).
fn protection(parent: &Key, name: &[u8]) -> Result<Protection> {
    let hash = parent.public.name_alg.ok_or(Rc::FAILURE)?;
    let def = parent.public.params.symmetric().ok_or(Rc::FAILURE)?;
    let seed = parent.seed();
    let sym = crypt::kdfa(hash, seed, b"STORAGE", name, &[], def.key_bytes());
    let hmac = crypt::kdfa(hash, seed, b"INTEGRITY", &[], &[], hash.size());
    Ok((hash, sym, hmac))
}

/// SensitiveToPrivate: the TPM2B_PRIVATE of a child of `parent`: integrity ‖ IV ‖ the
/// sensitive area (its authValue padded to the digest of `name_alg`) encrypted with AES-CFB.
pub fn wrap(parent: &Key, name: &[u8], name_alg: Option<Hash>, s: &Sensitive) -> Result<Vec<u8>> {
    let (hash, sym, hmac) = protection(parent, name)?;
    let mut iv = [0u8; IV_SIZE];
    getrandom::fill(&mut iv).map_err(|_| Rc::FAILURE)?;
    let inner = s.to_bytes(name_alg.map_or(0, Hash::size));
    let mut data = Writer::with_capacity(inner.len().saturating_add(4 + IV_SIZE));
    data.tpm2b(&iv).tpm2b(&inner);
    let mut data = Zeroizing::new(data.into_bytes());
    crypt::aes_cfb(
        &sym,
        &iv,
        data.get_mut(2 + IV_SIZE..).unwrap_or_default(),
        true,
    )?;
    let integrity = crypt::hmac(hash, &hmac, &[&data, name]);
    let mut out = Writer::new();
    out.tpm2b(&integrity).bytes(&data);
    Ok(out.into_bytes())
}

/// PrivateToSensitive: check a TPM2B_PRIVATE's integrity, decrypt it, and read the sensitive
/// area it holds. TPM_RC_INTEGRITY if it was not made for `name` under `parent`.
pub fn unwrap(parent: &Key, name: &[u8], private: &[u8]) -> Result<Sensitive> {
    let (hash, sym, hmac) = protection(parent, name)?;
    let mut r = Reader::new(private);
    let integrity = r.tpm2b(MAX_DIGEST)?;
    let rest = r.rest();
    let expected = crypt::hmac(hash, &hmac, &[rest, name]);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(integrity, &expected[..])) {
        return Err(Rc::INTEGRITY);
    }
    let iv = r.tpm2b(IV_SIZE)?;
    if iv.len() != IV_SIZE {
        return Err(Rc::VALUE);
    }
    let mut data = Zeroizing::new(r.rest().to_vec());
    crypt::aes_cfb(&sym, iv, &mut data, false)?;
    let mut r = Reader::new(&data);
    let size = r.u16().map_err(|_| Rc::SENSITIVE)?;
    if usize::from(size) != r.len() {
        return Err(Rc::SENSITIVE);
    }
    let sensitive = Sensitive::read(&mut r).map_err(|_| Rc::SENSITIVE)?;
    if !r.is_empty() {
        return Err(Rc::SENSITIVE);
    }
    Ok(sensitive)
}

/// CryptValidateKeys: the public and sensitive areas agree. Errors identify parameters
/// `blame_public` and `blame_sensitive`.
fn validate_keys(
    public: &Public,
    sensitive: Option<&Sensitive>,
    blame_public: u32,
    blame_sensitive: u32,
) -> Result<()> {
    let digest_size = public.digest_size();
    if let Some(s) = sensitive {
        if s.kind != public.kind() {
            return Err(Rc::TYPE.param(blame_sensitive));
        }
        if digest_size > 0 && s.auth.len() > digest_size {
            return Err(Rc::SIZE.param(blame_sensitive));
        }
    }
    match (&public.params, &public.unique) {
        (Params::Rsa { bits, exponent, .. }, Unique::Rsa(n)) => {
            let bytes = usize::from(bits / 8);
            if n.len() != bytes || n.first().is_none_or(|&b| b < 0x80) {
                return Err(Rc::KEY.param(blame_public));
            }
            if *exponent != 0 && *exponent < 7 {
                return Err(Rc::VALUE.param(blame_public));
            }
            if let Some(s) = sensitive
                && (s.secret.len().saturating_mul(2) != bytes
                    || s.secret.first().is_none_or(|&b| b < 0x80))
            {
                return Err(Rc::KEY_SIZE.param(blame_sensitive));
            }
        }
        (Params::Ecc { .. }, Unique::Ecc { x, y }) => match sensitive {
            None => {
                if x.len() != asym::P256_BYTES || y.len() != asym::P256_BYTES {
                    return Err(Rc::KEY.param(blame_public));
                }
                if public.name_alg.is_some() && asym::point(x, y).is_none() {
                    return Err(Rc::ECC_POINT.param(blame_public));
                }
            }
            Some(s) => {
                // As the reference: this one is not numbered.
                if asym::scalar(&s.secret).is_none() {
                    return Err(Rc::KEY_SIZE);
                }
                if public.name_alg.is_some() {
                    let (qx, qy) = asym::ecc_public(&s.secret).map_err(|_| Rc::BINDING)?;
                    if !same_number(&qx, x) || !same_number(&qy, y) {
                        return Err(Rc::BINDING);
                    }
                }
            }
        },
        (params, Unique::Digest(unique)) => match sensitive {
            None => {
                if unique.len() != digest_size {
                    return Err(Rc::KEY.param(blame_public));
                }
            }
            Some(s) => {
                match params {
                    Params::SymCipher(def) => {
                        if s.secret.len() != def.key_bytes() {
                            return Err(Rc::KEY_SIZE.param(blame_sensitive));
                        }
                    }
                    Params::KeyedHash(scheme) => {
                        let max = match scheme.hash {
                            Some(hash) => hash_block_size(hash),
                            None => MAX_SYM_DATA,
                        };
                        if s.secret.len() > max {
                            return Err(Rc::KEY_SIZE.param(blame_sensitive));
                        }
                    }
                    _ => return Err(Rc::FAILURE),
                }
                if public.name_alg.is_some() {
                    if s.seed.len() != digest_size {
                        return Err(Rc::KEY_SIZE.param(blame_sensitive));
                    }
                    if *unique != symmetric_unique(public, &s.seed, &s.secret) {
                        return Err(Rc::BINDING);
                    }
                }
            }
        },
        _ => return Err(Rc::FAILURE),
    }
    // A parent's seed is at least half its nameAlg's digest.
    if let Some(s) = sensitive
        && public.has(attr::RESTRICTED)
        && public.has(attr::DECRYPT)
        && public.name_alg.is_some()
        && (s.seed.len() < digest_size / 2 || s.seed.len() > digest_size)
    {
        return Err(Rc::SIZE.param(blame_sensitive));
    }
    Ok(())
}

/// Two big-endian numbers are equal, leading zeros aside (AdjustNumberB).
fn same_number(a: &[u8], b: &[u8]) -> bool {
    let strip = |v: &[u8]| -> Vec<u8> { v.iter().copied().skip_while(|&x| x == 0).collect() };
    strip(a) == strip(b)
}

/// ObjectLoad: check an object before loading it under `parent` (None: external), then build it.
pub fn load_checked(
    parent: Option<&Key>,
    public: Public,
    sensitive: Option<Sensitive>,
    (blame_public, blame_sensitive): (u32, u32),
) -> Result<Key> {
    let checks = match (&sensitive, public.name_alg) {
        (None, _) | (_, None) => public::scheme_checks(None, &public),
        (Some(s), Some(hash)) => {
            if s.seed.len() > hash.size() {
                return Err(Rc::KEY_SIZE.param(blame_sensitive));
            }
            let parent = parent.map(|p| Parent { public: &p.public });
            public::attributes_validation(parent.as_ref(), &public)
        }
    };
    checks.map_err(|rc| rc.param(blame_public))?;
    // Under a fixedTPM parent the TPM made the sensitive area itself: no need to check it.
    if parent.is_none_or(|p| !p.public.has(attr::FIXED_TPM)) {
        validate_keys(&public, sensitive.as_ref(), blame_public, blame_sensitive)?;
    }
    Key::new(public, sensitive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::ecc_srk;
    use crate::public::Type;

    #[test]
    fn a_wrapped_object_loads_only_under_its_parent_and_name() {
        let srk = ecc_srk();
        assert!(srk.is_parent());
        let s = Sensitive {
            kind: Type::KeyedHash,
            auth: Zeroizing::new(b"pw".to_vec()),
            seed: Zeroizing::new(vec![3; 32]),
            secret: Zeroizing::new(b"sealed".to_vec()),
        };
        let private = wrap(&srk, b"name", Some(Hash::Sha256), &s).unwrap();
        let back = unwrap(&srk, b"name", &private).unwrap();
        assert_eq!(*back.secret, b"sealed");
        assert_eq!(back.auth.len(), 32, "padded to the digest");
        assert_eq!(unwrap(&srk, b"other", &private).err(), Some(Rc::INTEGRITY));
        let mut tampered = private.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(unwrap(&srk, b"name", &tampered).err(), Some(Rc::INTEGRITY));
    }

    #[test]
    fn loading_checks_that_public_and_sensitive_agree() {
        let srk = ecc_srk();
        let (public, sensitive) = (srk.public.clone(), srk.sensitive.clone().unwrap());
        assert!(load_checked(None, public.clone(), Some(sensitive.clone()), (2, 1)).is_ok());
        let mut other = sensitive.clone();
        other.secret = Zeroizing::new(vec![1; 32]);
        assert_eq!(
            load_checked(None, public.clone(), Some(other), (2, 1)).err(),
            Some(Rc::BINDING)
        );
        let mut short_seed = sensitive;
        short_seed.seed.truncate(8);
        assert_eq!(
            load_checked(None, public, Some(short_seed), (2, 1)).err(),
            Some(Rc::SIZE.param(1))
        );
    }
}
