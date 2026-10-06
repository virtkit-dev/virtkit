//! The commands that use a key's secret, or its public half, on the caller's data (Part 3,
//! "Signing and Signature Verification", "Asymmetric Primitives"): TPM2_Sign,
//! TPM2_VerifySignature, TPM2_RSA_Encrypt, TPM2_RSA_Decrypt, TPM2_ECDH_KeyGen, TPM2_ECDH_ZGen
//! and TPM2_ECC_Parameters.
//!
//! Signing schemes vk-tpm does not implement (ECDAA, EC-Schnorr, SM2) are refused with
//! TPM_RC_SCHEME where libtpms would sign or verify.

use crate::alg::{Hash, MAX_DIGEST, TPM_ALG_NULL};
use crate::asym;
use crate::commands::{end, first};
use crate::crypt;
use crate::key::{Key, MAX_DATA};
use crate::marshal::{Reader, Writer};
use crate::object::{TPM_ST_HASHCHECK, read_hierarchy};
use crate::public::{
    self, MAX_ECC_KEY_BYTES, MAX_RSA_KEY_BYTES, Params, Scheme, TPM_ALG_ECDH, TPM_ALG_ECDSA,
    TPM_ALG_HMAC, TPM_ALG_KDF1_SP800_56A, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, Type, Unique, attr,
};
use crate::rc::{Rc, Result};
use crate::{Out, Tpm};

/// TPM_ST_VERIFIED, the tag of a TPMT_TK_VERIFIED.
pub const TPM_ST_VERIFIED: u16 = 0x8022;

/// CryptSelectSignScheme: the scheme a key signs with, from its own and the caller's.
fn select_sign_scheme(key: &Key, requested: Scheme) -> Option<Scheme> {
    let kind = key.public.kind();
    let own = match kind {
        Type::Rsa | Type::Ecc | Type::KeyedHash => key.public.params.scheme(),
        Type::SymCipher => return None,
    };
    let scheme = if own.is_null() {
        (!requested.is_null()).then_some(requested)?
    } else if requested.is_null() {
        // ECDAA signs in two steps (TPM2_Commit): never by default.
        (own.alg != public::TPM_ALG_ECDAA).then_some(own)?
    } else {
        (own.alg == requested.alg && own.hash == requested.hash).then_some(requested)?
    };
    let valid = match kind {
        Type::Rsa | Type::Ecc => public::is_asym_sign_scheme(kind, scheme.alg),
        _ => scheme.alg == TPM_ALG_HMAC,
    };
    (valid && scheme.hash.is_some()).then_some(scheme)
}

/// A TPMT_TK_HASHCHECK, as a command takes it: the hierarchy and the digest.
fn read_hash_check(r: &mut Reader) -> Result<(u32, Vec<u8>)> {
    let tag = r.u16()?;
    if !crate::is_structure_tag(tag) {
        return Err(Rc::VALUE);
    }
    if tag != TPM_ST_HASHCHECK {
        return Err(Rc::TAG);
    }
    let hierarchy = read_hierarchy(r)?;
    Ok((hierarchy, r.tpm2b(MAX_DIGEST)?.to_vec()))
}

/// TPM2_Sign: a signature of a digest. A restricted key signs only what the TPM hashed itself
/// (a ticket from TPM2_Hash or a hash sequence says so), so that it cannot be made to sign
/// something that looks like an attestation.
pub fn sign(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let digest = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?.to_vec();
    let requested = Scheme::read_sig(r, true).map_err(|rc| rc.param(2))?;
    let (hierarchy, ticket) = read_hash_check(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let key = tpm.key(first(handles)?).ok_or(Rc::KEY.handle(1))?;
    if !key.public.has(attr::SIGN) || key.public.kind() == Type::SymCipher {
        return Err(Rc::KEY.handle(1));
    }
    if key.public.has(attr::X509_SIGN) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    let scheme = select_sign_scheme(key, requested).ok_or(Rc::SCHEME.param(2))?;
    let hash = scheme.hash.ok_or(Rc::SCHEME.param(2))?;
    if !ticket.is_empty() || key.public.has(attr::RESTRICTED) {
        let expected = tpm.hash_check(hierarchy, hash, &digest);
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&ticket[..], &expected[..])) {
            return Err(Rc::TICKET.param(3));
        }
    } else if digest.len() != hash.size() {
        return Err(Rc::SIZE.param(1));
    }
    write_signature(key, scheme, hash, &digest, w)
}

/// CryptSign: the TPMT_SIGNATURE.
fn write_signature(
    key: &Key,
    scheme: Scheme,
    hash: Hash,
    digest: &[u8],
    w: &mut Writer,
) -> Result<()> {
    match (&key.public.params, scheme.alg) {
        (Params::Rsa { .. }, TPM_ALG_RSASSA | TPM_ALG_RSAPSS) => {
            let signature = asym::rsa_sign(key.rsa()?, scheme.alg, hash, digest)?;
            w.u16(scheme.alg).u16(hash.id()).tpm2b(&signature);
        }
        (Params::Ecc { .. }, TPM_ALG_ECDSA) => {
            let (r, s) = asym::ecdsa_sign(key.ecc_secret()?, digest)?;
            w.u16(scheme.alg).u16(hash.id()).tpm2b(&r).tpm2b(&s);
        }
        (Params::KeyedHash(_), TPM_ALG_HMAC) => {
            let secret = key.sensitive.as_ref().map_or(&[][..], |s| &s.secret);
            let mac = crypt::hmac(hash, secret, &[digest]);
            w.u16(scheme.alg).u16(hash.id()).bytes(&mac);
        }
        _ => return Err(Rc::SCHEME),
    }
    Ok(())
}

/// A TPMT_SIGNATURE: its scheme and hash, and the signature's parts (one for RSA and HMAC, r
/// and s for ECC).
pub struct Signature {
    pub alg: u16,
    pub hash: Hash,
    parts: Vec<Vec<u8>>,
}

pub fn read_signature(r: &mut Reader) -> Result<Signature> {
    // A TPMT_SIGNATURE, not a TPMT_SIGNATURE+: TPM_ALG_NULL is no scheme.
    let alg = r.u16()?;
    if !public::is_sig_scheme(alg) {
        return Err(Rc::SCHEME);
    }
    let hash = Hash::read(r)?;
    let parts = match alg {
        TPM_ALG_RSASSA | TPM_ALG_RSAPSS => vec![r.tpm2b(MAX_RSA_KEY_BYTES)?.to_vec()],
        TPM_ALG_HMAC => vec![r.bytes(hash.size())?.to_vec()],
        // ECDSA, ECDAA, SM2, EC-Schnorr: r and s.
        _ => vec![
            r.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec(),
            r.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec(),
        ],
    };
    Ok(Signature { alg, hash, parts })
}

/// CryptValidateSignature.
pub fn verify(key: &Key, digest: &[u8], sig: &Signature) -> Result<()> {
    let hash = sig.hash;
    let part = |i: usize| sig.parts.get(i).map_or(&[][..], Vec::as_slice);
    match (&key.public.params, &key.public.unique) {
        (Params::Rsa { exponent, .. }, Unique::Rsa(n)) => {
            if !matches!(sig.alg, TPM_ALG_RSASSA | TPM_ALG_RSAPSS) {
                return Err(Rc::SCHEME);
            }
            let public = asym::rsa_public(n, *exponent).map_err(|_| Rc::SIGNATURE)?;
            asym::rsa_verify(&public, sig.alg, hash, digest, part(0))
        }
        (Params::Ecc { .. }, Unique::Ecc { x, y }) => match sig.alg {
            TPM_ALG_ECDSA => asym::ecdsa_verify(x, y, digest, part(0), part(1)),
            // EC-Schnorr and SM2 are not implemented.
            _ => Err(Rc::SCHEME),
        },
        (Params::KeyedHash(own), _) => {
            let Some(secret) = key.sensitive.as_ref().map(|s| &s.secret) else {
                return Err(Rc::HANDLE);
            };
            if sig.alg != TPM_ALG_HMAC {
                return Err(Rc::SCHEME);
            }
            if !own.is_null() && (own.alg != sig.alg || own.hash != Some(hash)) {
                return Err(Rc::SIGNATURE);
            }
            let mac = crypt::hmac(hash, secret, &[digest]);
            if bool::from(subtle::ConstantTimeEq::ct_eq(&mac[..], part(0))) {
                Ok(())
            } else {
                Err(Rc::SIGNATURE)
            }
        }
        _ => Err(Rc::SCHEME),
    }
}

/// TPM2_VerifySignature: check a signature, and give a ticket that the TPM did.
pub fn verify_signature(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let digest = r.tpm2b(MAX_DIGEST).map_err(|rc| rc.param(1))?.to_vec();
    let signature = read_signature(r).map_err(|rc| rc.param(2))?;
    end(r)?;
    let handle = first(handles)?;
    let key = tpm.key(handle).ok_or(Rc::ATTRIBUTES.handle(1))?;
    if !key.public.has(attr::SIGN) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    verify(key, &digest, &signature).map_err(|rc| rc.param(2))?;
    let hierarchy = key.hierarchy;
    if hierarchy == crate::entity::TPM_RH_NULL || key.public.name_alg.is_none() {
        w.u16(TPM_ST_VERIFIED)
            .u32(crate::entity::TPM_RH_NULL)
            .tpm2b(&[]);
    } else {
        let ticket = tpm.verified_ticket(hierarchy, &digest, &key.name);
        w.u16(TPM_ST_VERIFIED).u32(hierarchy).tpm2b(&ticket);
    }
    Ok(())
}

impl Tpm {
    /// TicketComputeVerified: HMAC(proof, TPM_ST_VERIFIED ‖ digest ‖ Name).
    pub fn verified_ticket(&self, hierarchy: u32, digest: &[u8], name: &[u8]) -> Vec<u8> {
        let tag = TPM_ST_VERIFIED.to_be_bytes();
        let proof = self.proof(hierarchy);
        crypt::hmac(Hash::Sha512, proof.as_slice(), &[&tag, digest, name])
    }
}

/// IsLabelProperlyFormatted: an OAEP label is empty or ends with its terminating zero.
fn read_label(r: &mut Reader) -> Result<Vec<u8>> {
    Ok(r.tpm2b(MAX_DATA)?.to_vec())
}

fn check_label(label: &[u8], n: u32) -> Result<()> {
    if label.last().is_none_or(|&b| b == 0) {
        Ok(())
    } else {
        Err(Rc::VALUE.param(n))
    }
}

/// CryptRsaSelectScheme: the key's scheme, the caller's, or both if they agree.
fn select_rsa_scheme(key: &Key, requested: Scheme) -> Option<Scheme> {
    let own = key.public.params.scheme();
    if own.is_null() {
        Some(requested)
    } else if requested.is_null() {
        Some(own)
    } else {
        (own.alg == requested.alg && own.hash == requested.hash).then_some(requested)
    }
}

/// The RSA key of a command, checked as RSA_Encrypt and RSA_Decrypt check it.
fn rsa_key(tpm: &Tpm, handle: u32) -> Result<&Key> {
    let key = tpm.key(handle).ok_or(Rc::KEY.handle(1))?;
    if key.public.kind() != Type::Rsa {
        return Err(Rc::KEY.handle(1));
    }
    Ok(key)
}

/// TPM2_RSA_Encrypt: RSAES, OAEP or raw RSA with a key's public half.
pub fn rsa_encrypt(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let message = r
        .tpm2b(MAX_RSA_KEY_BYTES)
        .map_err(|rc| rc.param(1))?
        .to_vec();
    let requested = Scheme::read_rsa_decrypt(r).map_err(|rc| rc.param(2))?;
    let label = read_label(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let key = rsa_key(tpm, first(handles)?)?;
    if !key.public.has(attr::DECRYPT) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    check_label(&label, 3)?;
    let scheme = select_rsa_scheme(key, requested).ok_or(Rc::SCHEME.param(2))?;
    let (Params::Rsa { exponent, .. }, Unique::Rsa(n)) = (&key.public.params, &key.public.unique)
    else {
        return Err(Rc::FAILURE);
    };
    let public = asym::rsa_public(n, *exponent).map_err(|_| Rc::FAILURE)?;
    let out = match scheme.alg {
        TPM_ALG_NULL => asym::rsa_encrypt(&public, scheme.alg, None, &label, &message)?,
        // OpenSSL's failure (a message too long for the padding) is TPM_RC_FAILURE in libtpms.
        public::TPM_ALG_RSAES | public::TPM_ALG_OAEP => {
            asym::rsa_encrypt(&public, scheme.alg, scheme.hash, &label, &message)
                .map_err(|_| Rc::FAILURE)?
        }
        _ => return Err(Rc::SCHEME),
    };
    w.tpm2b(&out);
    Ok(())
}

/// TPM2_RSA_Decrypt: with an unrestricted decryption key only (a restricted one, an EK or a
/// storage key, decrypts nothing a caller chooses but salts and credentials, as OAEP).
pub fn rsa_decrypt(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let ciphertext = r
        .tpm2b(MAX_RSA_KEY_BYTES)
        .map_err(|rc| rc.param(1))?
        .to_vec();
    let requested = Scheme::read_rsa_decrypt(r).map_err(|rc| rc.param(2))?;
    let label = read_label(r).map_err(|rc| rc.param(3))?;
    end(r)?;
    let key = rsa_key(tpm, first(handles)?)?;
    if key.public.has(attr::RESTRICTED) || !key.public.has(attr::DECRYPT) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    check_label(&label, 3)?;
    let scheme = select_rsa_scheme(key, requested).ok_or(Rc::SCHEME.param(2))?;
    if !matches!(
        scheme.alg,
        TPM_ALG_NULL | public::TPM_ALG_RSAES | public::TPM_ALG_OAEP
    ) {
        return Err(Rc::SCHEME);
    }
    let message = asym::rsa_decrypt(key.rsa()?, scheme.alg, scheme.hash, &label, &ciphertext)?;
    w.tpm2b(&message);
    Ok(())
}

/// A TPM2B_ECC_POINT.
fn read_sized_point(r: &mut Reader) -> Result<(Vec<u8>, Vec<u8>)> {
    let size = usize::from(r.u16()?);
    if size == 0 {
        return Err(Rc::SIZE);
    }
    let before = r.len();
    let point = public::read_point(r)?;
    if before.saturating_sub(r.len()) != size {
        return Err(Rc::SIZE);
    }
    Ok(point)
}

fn write_sized_point(w: &mut Writer, (x, y): &(Vec<u8>, Vec<u8>)) {
    let mut p = Writer::new();
    p.tpm2b(x).tpm2b(y);
    w.tpm2b(&p.into_bytes());
}

/// The ECC key of a command (TPM_RC_KEY for another).
fn ecc_key(tpm: &Tpm, handle: u32) -> Result<&Key> {
    let key = tpm.key(handle).ok_or(Rc::KEY.handle(1))?;
    if key.public.kind() != Type::Ecc {
        return Err(Rc::KEY.handle(1));
    }
    Ok(key)
}

/// TPM2_ECDH_KeyGen: an ephemeral key pair, and the shared point it makes with the key's
/// public point (what a caller needs to send the key a secret).
pub fn ecdh_key_gen(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    let key = ecc_key(tpm, first(handles)?)?;
    let Unique::Ecc { x, y } = &key.public.unique else {
        return Err(Rc::FAILURE);
    };
    loop {
        let d = asym::ecc_random()?;
        let public = asym::ecc_public(d.as_slice())?;
        match asym::ecc_multiply(d.as_slice(), x, y) {
            Ok(z) => {
                write_sized_point(w, &z);
                write_sized_point(w, &public);
                return Ok(());
            }
            Err(rc) if rc == Rc::NO_RESULT => continue,
            Err(_) => return Err(Rc::KEY.handle(1)),
        }
    }
}

/// TPM2_ECDH_ZGen: [d]P with the key's private scalar.
pub fn ecdh_z_gen(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let (px, py) = read_sized_point(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let key = ecc_key(tpm, first(handles)?)?;
    if key.public.has(attr::RESTRICTED) || !key.public.has(attr::DECRYPT) {
        return Err(Rc::ATTRIBUTES.handle(1));
    }
    let scheme = key.public.params.scheme();
    if !scheme.is_null() && scheme.alg != TPM_ALG_ECDH {
        return Err(Rc::SCHEME.handle(1));
    }
    let z = asym::ecc_multiply(key.ecc_secret()?, &px, &py).map_err(|rc| rc.param(1))?;
    write_sized_point(w, &z);
    Ok(())
}

// NIST P-256 (SEC 2): the prime, a, b, the base point and the order.
const P256_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
const P256_A: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
];
const P256_B: [u8; 32] = [
    0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc,
    0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];
const P256_GX: [u8; 32] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
];
const P256_GY: [u8; 32] = [
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// TPM2_ECC_Parameters: NIST P-256's parameters, as the reference gives them.
pub fn ecc_parameters(_: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let curve = public::read_curve(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    w.u16(curve).u16(256);
    // kdf: KDF1_SP800_56A with SHA-256; sign: none.
    w.u16(TPM_ALG_KDF1_SP800_56A)
        .u16(Hash::Sha256.id())
        .u16(TPM_ALG_NULL);
    for value in [P256_P, P256_A, P256_B, P256_GX, P256_GY, P256_N] {
        w.tpm2b(&value);
    }
    // The cofactor.
    w.tpm2b(&[1]);
    Ok(())
}
