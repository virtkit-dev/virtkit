//! The asymmetric keys: RSA (1024, 2048, 3072) and ECC on NIST P-256, over RustCrypto's `rsa`,
//! `p256` and `ecdsa`. This module only shapes inputs and outputs the way the TPM's wire format
//! has them (big-endian, fixed size) and draws key material the way the TPM must.
//!
//! RSA private operations always blind (rsa's `rsa_decrypt_and_check` with an RNG), on top of
//! crypto-bigint's constant-time exponentiation, and the decryption paddings are removed in
//! constant time; every decryption failure is one error (TPM_RC_VALUE), so a caller learns only
//! that it failed. See "RSA and the Marvin attack" in docs/tpm-design.md.

use crypto_bigint::{BoxedUint, Limb, NonZero, Resize, U384};
use crypto_primes::hazmat::SmallFactorsSieve;
use crypto_primes::{Flavor, is_prime};
use ecdsa::hazmat::verify_prehashed;
use getrandom::SysRng;
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint};
use rsa::traits::{PaddingScheme, PublicKeyParts, SignatureScheme};
use rsa::{Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey};
use zeroize::{Zeroize, Zeroizing};

use crate::alg::Hash;
use crate::drbg::Drbg;
use crate::public::{TPM_ALG_OAEP, TPM_ALG_RSAES, TPM_ALG_RSAPSS, TPM_ALG_RSASSA};
use crate::rc::{Rc, Result};

/// Run `$body` with `$d` the RustCrypto digest type of `$hash`.
macro_rules! with_digest {
    ($hash:expr, $d:ident => $body:expr) => {
        match $hash {
            Hash::Sha1 => {
                type $d = sha1::Sha1;
                $body
            }
            Hash::Sha256 => {
                type $d = sha2::Sha256;
                $body
            }
            Hash::Sha384 => {
                type $d = sha2::Sha384;
                $body
            }
            Hash::Sha512 => {
                type $d = sha2::Sha512;
                $body
            }
        }
    };
}

/// The public exponent a key says 0 for.
pub const RSA_DEFAULT_EXPONENT: u32 = 65537;

pub fn rsa_exponent(exponent: u32) -> u32 {
    if exponent == 0 {
        RSA_DEFAULT_EXPONENT
    } else {
        exponent
    }
}

/// The exponent of a key to generate: the default, or a prime from 65537 up (TPM_RC_RANGE).
fn generation_exponent(exponent: u32) -> Result<u32> {
    let e = rsa_exponent(exponent);
    if e < RSA_DEFAULT_EXPONENT || !is_prime(Flavor::Any, &crypto_bigint::U64::from(e)) {
        return Err(Rc::RANGE);
    }
    Ok(e)
}

/// `value` as `len` big-endian bytes, left-padded with zeros.
fn be_padded(value: &BoxedUint, len: usize) -> Zeroizing<Vec<u8>> {
    let bytes = Zeroizing::new(value.to_be_bytes().into_vec());
    let skip = bytes.len().saturating_sub(len);
    let mut out = Zeroizing::new(vec![0; len.saturating_sub(bytes.len())]);
    out.extend_from_slice(bytes.get(skip..).unwrap_or_default());
    out
}

/// A new RSA key: (modulus, the prime the sensitive area keeps, the key).
///
/// Each prime is the first one at or above a candidate drawn from `drbg` (its top two bits and
/// its low bit set, so the modulus has exactly `bits` bits) that is not 1 modulo the exponent:
/// a search of our own, defined by the arithmetic alone, so a primary key stays the same key
/// across crate upgrades. The reference implementation sieves differently; its RSA primaries
/// are not ours (docs/tpm-design.md).
pub fn rsa_generate(
    bits: u16,
    exponent: u32,
    drbg: &mut Drbg,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>, RsaPrivateKey)> {
    let e = generation_exponent(exponent)?;
    let half = u32::from(bits / 2);
    let modulus_bytes = usize::from(bits / 8);
    for _ in 0..100 {
        let q = rsa_prime(drbg, half, e)?;
        let p = rsa_prime(drbg, half, e)?;
        // FIPS 186-5: |p - q| > 2^(bits/2 - 100).
        let diff = if p > q {
            p.wrapping_sub(&q)
        } else {
            q.wrapping_sub(&p)
        };
        if diff.bits() <= half.saturating_sub(100) {
            continue;
        }
        let secret = be_padded(&p, modulus_bytes / 2);
        let Ok(mut key) = RsaPrivateKey::from_p_q(p, q, BoxedUint::from(e)) else {
            continue;
        };
        key.precompute().map_err(|_| Rc::FAILURE)?;
        let n = be_padded(key.n().as_ref(), modulus_bytes);
        if n.first().is_none_or(|b| b & 0x80 == 0) {
            return Err(Rc::FAILURE);
        }
        return Ok((n.to_vec(), secret, key));
    }
    Err(Rc::NO_RESULT)
}

/// One RSA prime of `bits` bits, (p - 1) prime to `e` (see [`rsa_generate`]).
fn rsa_prime(drbg: &mut Drbg, bits: u32, e: u32) -> Result<BoxedUint> {
    let bytes = usize::try_from(bits / 8).map_err(|_| Rc::FAILURE)?;
    let max_bits = std::num::NonZeroU32::new(bits).ok_or(Rc::FAILURE)?;
    let e = NonZero::new(Limb::from(e))
        .into_option()
        .ok_or(Rc::FAILURE)?;
    for _ in 0..1000 {
        let mut candidate = drbg.bytes(bytes);
        if let Some(top) = candidate.first_mut() {
            *top |= 0xc0;
        }
        if let Some(low) = candidate.last_mut() {
            *low |= 1;
        }
        let start = BoxedUint::from_be_slice(&candidate, bits).map_err(|_| Rc::FAILURE)?;
        let sieve = SmallFactorsSieve::new(start, max_bits, false).map_err(|_| Rc::FAILURE)?;
        for mut c in sieve {
            if c.rem_limb(e) != Limb::ONE && is_prime(Flavor::Any, &c) {
                return Ok(c);
            }
            c.zeroize();
        }
    }
    Err(Rc::NO_RESULT)
}

/// The private key whose modulus is `n` and one of whose primes is `p` (CryptRsaLoadPrivateExponent):
/// TPM_RC_BINDING if `p` does not divide `n`.
pub fn rsa_private(n: &[u8], p: &[u8], exponent: u32) -> Result<RsaPrivateKey> {
    let bits = u32::try_from(n.len().saturating_mul(8)).map_err(|_| Rc::FAILURE)?;
    let n = BoxedUint::from_be_slice(n, bits).map_err(|_| Rc::BINDING)?;
    let p = BoxedUint::from_be_slice(p, bits).map_err(|_| Rc::BINDING)?;
    let divisor = NonZero::new(p.clone()).into_option().ok_or(Rc::BINDING)?;
    let (q, remainder) = n.div_rem(&divisor);
    if !bool::from(remainder.is_zero()) {
        return Err(Rc::BINDING);
    }
    let half = bits / 2;
    let (Some(p_half), Some(q_half)) = (p.try_resize(half), q.try_resize(half)) else {
        return Err(Rc::BINDING);
    };
    let e = BoxedUint::from(rsa_exponent(exponent));
    let mut key = RsaPrivateKey::from_p_q(p_half, q_half, e).map_err(|_| Rc::BINDING)?;
    key.precompute().map_err(|_| Rc::BINDING)?;
    Ok(key)
}

/// A public key, as OpenSSL takes one: any exponent (the TPM refused those below 7 when the
/// key was loaded), an odd modulus. rsa's own encryption paddings still refuse an even
/// exponent (a deviation: no TPM key has one).
pub fn rsa_public(n: &[u8], exponent: u32) -> Result<RsaPublicKey> {
    let bits = u32::try_from(n.len().saturating_mul(8)).map_err(|_| Rc::FAILURE)?;
    let n = BoxedUint::from_be_slice(n, bits).map_err(|_| Rc::KEY)?;
    if n.as_limbs().first().is_none_or(|l| l.0 & 1 == 0) || n.bits() < 2 {
        return Err(Rc::KEY);
    }
    let e = BoxedUint::from(rsa_exponent(exponent));
    Ok(RsaPublicKey::new_unchecked(n, e))
}

/// The salt of an RSAPSS signature: the digest's size, unless the modulus is too small for it
/// (as libtpms asks OpenSSL for).
fn pss_salt(hash: Hash, modulus_bytes: usize) -> usize {
    let h = hash.size();
    if h.saturating_mul(2).saturating_add(2) <= modulus_bytes {
        h
    } else {
        modulus_bytes.saturating_sub(h).saturating_sub(2)
    }
}

/// An RSASSA or RSAPSS signature of `digest` (blinded).
pub fn rsa_sign(key: &RsaPrivateKey, scheme: u16, hash: Hash, digest: &[u8]) -> Result<Vec<u8>> {
    let mut rng = SysRng;
    let signature = match scheme {
        TPM_ALG_RSASSA => {
            with_digest!(hash, D => Pkcs1v15Sign::new::<D>().sign(Some(&mut rng), key, digest))
        }
        TPM_ALG_RSAPSS => {
            let salt_len = Some(pss_salt(hash, key.size()));
            with_digest!(hash, D => Pss::<D> { blinded: true, digest: <D as sha2::Digest>::new(), salt_len }
                .sign(Some(&mut rng), key, digest))
        }
        _ => return Err(Rc::SCHEME),
    };
    signature.map_err(|_| Rc::FAILURE)
}

/// Verify an RSASSA or RSAPSS signature (any salt length): TPM_RC_SIGNATURE if it is not one.
pub fn rsa_verify(
    key: &RsaPublicKey,
    scheme: u16,
    hash: Hash,
    digest: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != key.size() {
        return Err(Rc::SIGNATURE);
    }
    let verified = match scheme {
        TPM_ALG_RSASSA => {
            with_digest!(hash, D => Pkcs1v15Sign::new::<D>().verify(key, digest, signature))
        }
        TPM_ALG_RSAPSS => {
            with_digest!(hash, D => Pss::<D> { blinded: false, digest: <D as sha2::Digest>::new(), salt_len: None }
                .verify(key, digest, signature))
        }
        _ => return Err(Rc::SCHEME),
    };
    verified.map_err(|_| Rc::SIGNATURE)
}

/// RSA encryption with `scheme` (RSAES, OAEP with its hash and `label`, or with TPM_ALG_NULL
/// none: `message` is then the integer, at most the modulus' size once its leading zeros go).
pub fn rsa_encrypt(
    key: &RsaPublicKey,
    scheme: u16,
    hash: Option<Hash>,
    label: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut rng = SysRng;
    let k = key.size();
    let out = match (scheme, hash) {
        (TPM_ALG_RSAES, _) => Pkcs1v15Encrypt.encrypt(&mut rng, key, message),
        (TPM_ALG_OAEP, Some(hash)) => {
            with_digest!(hash, D => oaep::<D>(label).encrypt(&mut rng, key, message))
        }
        (crate::alg::TPM_ALG_NULL, _) => {
            let significant = message
                .iter()
                .position(|&b| b != 0)
                .map_or(&[][..], |i| message.get(i..).unwrap_or_default());
            if significant.len() > k {
                return Err(Rc::VALUE);
            }
            let bits = u32::try_from(k.saturating_mul(8)).map_err(|_| Rc::FAILURE)?;
            let m = BoxedUint::from_be_slice(significant, bits).map_err(|_| Rc::FAILURE)?;
            // OpenSSL refuses a message that is not below the modulus.
            if m >= *key.n().as_ref() {
                return Err(Rc::FAILURE);
            }
            let c = rsa::hazmat::rsa_encrypt(key, &m).map_err(|_| Rc::FAILURE)?;
            return Ok(be_padded(&c, k).to_vec());
        }
        _ => return Err(Rc::SCHEME),
    };
    out.map_err(|_| Rc::VALUE)
}

fn oaep<D: sha2::Digest + sha2::digest::FixedOutputReset>(label: &[u8]) -> Oaep<D> {
    if label.is_empty() {
        Oaep::<D>::new()
    } else {
        Oaep::<D>::new_with_label(label.to_vec())
    }
}

/// RSA decryption, blinded, its padding removed in constant time: OAEP's failures, whatever made
/// the padding wrong, are all TPM_RC_VALUE; RSAES has none (implicit rejection, see
/// [`rsaes_unpad`]).
pub fn rsa_decrypt(
    key: &RsaPrivateKey,
    scheme: u16,
    hash: Option<Hash>,
    label: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut rng = SysRng;
    let k = key.size();
    if ciphertext.len() != k {
        return Err(Rc::SIZE);
    }
    let out = match (scheme, hash) {
        (TPM_ALG_RSAES, _) => {
            let bits = u32::try_from(k.saturating_mul(8)).map_err(|_| Rc::FAILURE)?;
            let c = BoxedUint::from_be_slice(ciphertext, bits).map_err(|_| Rc::VALUE)?;
            let m = rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut rng), &c)
                .map_err(|_| Rc::VALUE)?;
            return rsaes_unpad(key, ciphertext, &be_padded(&m, k));
        }
        (TPM_ALG_OAEP, Some(hash)) => {
            with_digest!(hash, D => oaep::<D>(label).decrypt(Some(&mut rng), key, ciphertext))
        }
        (crate::alg::TPM_ALG_NULL, _) => {
            let bits = u32::try_from(k.saturating_mul(8)).map_err(|_| Rc::FAILURE)?;
            let c = BoxedUint::from_be_slice(ciphertext, bits).map_err(|_| Rc::VALUE)?;
            let m = rsa::hazmat::rsa_decrypt_and_check(key, Some(&mut rng), &c)
                .map_err(|_| Rc::VALUE)?;
            return Ok(be_padded(&m, k));
        }
        _ => return Err(Rc::SCHEME),
    };
    out.map(Zeroizing::new).map_err(|_| Rc::VALUE)
}

/// The private exponent libtpms gives OpenSSL, which keys implicit rejection: as OpenSSL
/// computes it, inverse of e modulo λ(n) from 2048 bits with e above 2^16 (unless that one is
/// suspiciously small), modulo φ(n) otherwise.
fn libtpms_exponent(key: &RsaPrivateKey) -> Result<BoxedUint> {
    use rsa::traits::PrivateKeyParts;
    let n = key.n().as_ref();
    let bits = n.bits();
    if bits >= 2048 && key.e().bits() > 16 && key.d().bits() > bits / 2 {
        return Ok(key.d().clone());
    }
    let precision = n.bits_precision();
    let (Some(p), Some(q)) = (key.primes().first(), key.primes().get(1)) else {
        return Err(Rc::FAILURE);
    };
    let widen = |v: &BoxedUint| v.resize_unchecked(precision);
    let phi = n
        .wrapping_sub(widen(p))
        .wrapping_sub(widen(q))
        .wrapping_add(BoxedUint::one_with_precision(precision));
    let phi = NonZero::new(phi).into_option().ok_or(Rc::FAILURE)?;
    widen(key.e())
        .invert_mod(&phi)
        .into_option()
        .ok_or(Rc::FAILURE)
}

/// The PRF of implicit rejection: HMAC-SHA256(kdk, i ‖ label ‖ bits) for i = 0, 1, ...
fn rejection_prf(kdk: &[u8], label: &[u8], bytes: usize) -> Zeroizing<Vec<u8>> {
    let bits = u16::try_from(bytes.saturating_mul(8))
        .unwrap_or(u16::MAX)
        .to_be_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.saturating_add(32)));
    let mut i = 0u16;
    while out.len() < bytes {
        out.extend_from_slice(&crate::crypt::hmac(
            Hash::Sha256,
            kdk,
            &[&i.to_be_bytes(), label, &bits],
        ));
        i = i.wrapping_add(1);
    }
    out.truncate(bytes);
    out
}

/// RSAES-PKCS1-v1_5 decoding with implicit rejection, as OpenSSL 3.2+ (so libtpms) does it: a
/// malformed `em` decodes to a message derived from the private key and the ciphertext, the same
/// every time, so that whether the padding was right never shows, not even in the result (the
/// Bleichenbacher and Marvin oracles). Constant time but for the returned length.
fn rsaes_unpad(key: &RsaPrivateKey, ciphertext: &[u8], em: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess};
    let k = em.len();
    let mut d = libtpms_exponent(key)?;
    let d_bytes = be_padded(&d, k);
    d.zeroize();
    let d_hash = Zeroizing::new(Hash::Sha256.digest(&[&d_bytes]));
    let kdk = Zeroizing::new(crate::crypt::hmac(Hash::Sha256, &d_hash, &[ciphertext]));
    let synthetic = rejection_prf(&kdk, b"message", k);
    // A synthetic length: the last of 128 candidates below the largest a message can be.
    const TRIES: usize = 128;
    let candidates = rejection_prf(&kdk, b"length", TRIES * 2);
    let max = u16::try_from(k.saturating_sub(10)).map_err(|_| Rc::FAILURE)?;
    let mut mask = max;
    for shift in [1, 2, 4, 8] {
        mask |= mask >> shift;
    }
    let mut synthetic_len = 0u16;
    for pair in candidates.as_chunks::<2>().0 {
        let candidate = u16::from_be_bytes(*pair) & mask;
        synthetic_len.conditional_assign(&candidate, candidate.ct_lt(&max));
    }
    // The real message: 00 02, at least 8 nonzero bytes, 00, the message.
    let (first, second) = (
        em.first().copied().unwrap_or(1),
        em.get(1).copied().unwrap_or(0),
    );
    let mut good = first.ct_eq(&0) & second.ct_eq(&2);
    let mut zero_index = 0u32;
    let mut found = subtle::Choice::from(0);
    for (i, b) in (0u32..).zip(em).skip(2) {
        let is_zero = b.ct_eq(&0);
        zero_index.conditional_assign(&i, !found & is_zero);
        found |= is_zero;
    }
    good &= zero_index.ct_gt(&9);
    let real_index = zero_index.wrapping_add(1);
    let synthetic_index = u32::try_from(k)
        .unwrap_or(0)
        .saturating_sub(u32::from(synthetic_len));
    let index = u32::conditional_select(&synthetic_index, &real_index, good);
    let index = usize::try_from(index).unwrap_or(k).min(k);
    let mut out = Zeroizing::new(vec![0u8; k.saturating_sub(index)]);
    let (real, fake) = (em.get(index..), synthetic.get(index..));
    let (real, fake) = (real.unwrap_or_default(), fake.unwrap_or_default());
    for ((o, real), fake) in out.iter_mut().zip(real).zip(fake) {
        *o = u8::conditional_select(fake, real, good);
    }
    Ok(out)
}

/// P-256's group order less one, n - 1, as wide as the number reduced modulo it.
const P256_ORDER_MINUS_1: NonZero<U384> = NonZero::<U384>::new_unwrap(U384::from_be_hex(concat!(
    "00000000000000000000000000000000",
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550"
)));
/// The size of a P-256 coordinate or scalar.
pub const P256_BYTES: usize = 32;

/// TpmEcc_GenPrivateScalar: a P-256 private key from `drbg`, as the reference derives it (FIPS
/// 186-4 B.4.1, "extra random bits"): 64 bits more than the order's size, reduced modulo n - 1,
/// plus one. Constant time.
pub fn ecc_derive(drbg: &mut Drbg) -> Zeroizing<[u8; P256_BYTES]> {
    let extra = drbg.bytes(P256_BYTES + 8);
    let mut wide = Zeroizing::new([0u8; 48]);
    if let Some(dst) = wide.get_mut(48usize.saturating_sub(extra.len())..) {
        dst.copy_from_slice(&extra);
    }
    let mut c = U384::from_be_slice(wide.as_slice());
    let mut d = c.rem(&P256_ORDER_MINUS_1).wrapping_add(&U384::ONE);
    c.zeroize();
    let mut bytes = d.to_be_bytes();
    d.zeroize();
    let mut out = Zeroizing::new([0u8; P256_BYTES]);
    if let Some(src) = bytes.as_ref().get(48 - P256_BYTES..) {
        out.copy_from_slice(src);
    }
    bytes.as_mut().zeroize();
    out
}

/// A random P-256 private key, from the host's entropy.
pub fn ecc_random() -> Result<Zeroizing<[u8; P256_BYTES]>> {
    loop {
        let mut d = Zeroizing::new([0u8; P256_BYTES]);
        getrandom::fill(d.as_mut_slice()).map_err(|_| Rc::FAILURE)?;
        if scalar(d.as_slice()).is_some() {
            return Ok(d);
        }
    }
}

/// A private key: 0 < d < n (CryptEccIsValidPrivateKey); leading zeros are fine.
pub fn scalar(d: &[u8]) -> Option<NonZeroScalar> {
    let bytes = Zeroizing::new(field_bytes(d)?);
    NonZeroScalar::from_repr(*bytes).into_option()
}

/// A big-endian number of any length as a P-256 field element's 32 bytes, if it fits.
fn field_bytes(v: &[u8]) -> Option<FieldBytes> {
    let start = v.iter().position(|&b| b != 0).unwrap_or(v.len());
    let significant = v.get(start..)?;
    if significant.len() > P256_BYTES {
        return None;
    }
    let mut out = FieldBytes::default();
    out.get_mut(P256_BYTES.saturating_sub(significant.len())..)?
        .copy_from_slice(significant);
    Some(out)
}

/// A point on P-256 (CryptEccIsPointOnCurve), from its coordinates.
pub fn point(x: &[u8], y: &[u8]) -> Option<AffinePoint> {
    let (x, y) = (field_bytes(x)?, field_bytes(y)?);
    AffinePoint::from_coordinates(&x, &y).into_option()
}

/// A point's coordinates, each 32 bytes; None for the point at infinity.
fn coordinates(p: &AffinePoint) -> Option<(Vec<u8>, Vec<u8>)> {
    if bool::from(p.is_identity()) {
        return None;
    }
    let encoded = p.to_sec1_point(false);
    Some((encoded.x()?.to_vec(), encoded.y()?.to_vec()))
}

/// The public point of private key `d`.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "group arithmetic, not integers"
)]
pub fn ecc_public(d: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let d = scalar(d).ok_or(Rc::KEY_SIZE)?;
    let q = (ProjectivePoint::GENERATOR * *d).to_affine();
    coordinates(&q).ok_or(Rc::NO_RESULT)
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "group arithmetic, not integers"
)]
/// [d]P (CryptEccPointMultiply): TPM_RC_ECC_POINT if P is not on the curve, TPM_RC_NO_RESULT
/// for the point at infinity.
pub fn ecc_multiply(d: &[u8], x: &[u8], y: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let p = point(x, y).ok_or(Rc::ECC_POINT)?;
    let d = scalar(d).ok_or(Rc::VALUE)?;
    let r = (ProjectivePoint::from(p) * *d).to_affine();
    coordinates(&r).ok_or(Rc::NO_RESULT)
}

/// An ECDSA signature (r, s) of `digest`, each 32 bytes, with a hedged RFC 6979 nonce.
pub fn ecdsa_sign(d: &[u8], digest: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use ecdsa::signature::hazmat::RandomizedPrehashSigner;
    let key = p256::ecdsa::SigningKey::from(scalar(d).ok_or(Rc::KEY)?);
    let signature: p256::ecdsa::Signature = key
        .sign_prehash_with_rng(&mut SysRng, digest)
        .map_err(|_| Rc::FAILURE)?;
    let (r, s) = signature.split_bytes();
    Ok((r.to_vec(), s.to_vec()))
}

/// Verify an ECDSA signature: TPM_RC_SIGNATURE if it is not one (r or s zero or not below n
/// included).
pub fn ecdsa_verify(x: &[u8], y: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> Result<()> {
    let q = point(x, y).ok_or(Rc::SIGNATURE)?;
    let (r, s) = (
        field_bytes(r).ok_or(Rc::SIGNATURE)?,
        field_bytes(s).ok_or(Rc::SIGNATURE)?,
    );
    let signature = p256::ecdsa::Signature::from_scalars(r, s).map_err(|_| Rc::SIGNATURE)?;
    verify_prehashed::<p256::NistP256>(&ProjectivePoint::from(q), digest, &signature)
        .map_err(|_| Rc::SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drbg::PRIMARY_OBJECT_CREATION;

    fn drbg(n: u8) -> Drbg {
        Drbg::seeded(&[n; 64], PRIMARY_OBJECT_CREATION, b"test", b"")
    }

    #[test]
    fn rsa_keys_are_deterministic_and_work() {
        let (n, p, key) = rsa_generate(1024, 0, &mut drbg(1)).unwrap();
        let (n2, p2, _) = rsa_generate(1024, 0, &mut drbg(1)).unwrap();
        assert_eq!((&n, &p), (&n2, &p2));
        assert_eq!(n.len(), 128);
        assert!(n[0] & 0x80 != 0);
        let again = rsa_private(&n, &p, 0).unwrap();
        assert_eq!(again.n(), key.n());
        let mut q = n.clone();
        q[127] ^= 2;
        assert!(rsa_private(&q, &p, 0).is_err(), "p must divide n");
        assert_eq!(rsa_generate(1024, 3, &mut drbg(1)).err(), Some(Rc::RANGE));

        let public = rsa_public(&n, 0).unwrap();
        let digest = Hash::Sha256.digest(&[b"abc"]);
        for scheme in [TPM_ALG_RSASSA, TPM_ALG_RSAPSS] {
            let sig = rsa_sign(&key, scheme, Hash::Sha256, &digest).unwrap();
            assert_eq!(
                rsa_verify(&public, scheme, Hash::Sha256, &digest, &sig),
                Ok(())
            );
            let mut bad = sig.clone();
            bad[5] ^= 1;
            assert_eq!(
                rsa_verify(&public, scheme, Hash::Sha256, &digest, &bad),
                Err(Rc::SIGNATURE)
            );
        }
        // RSA-1024 with SHA-512 PSS: the salt shrinks to fit.
        let digest = Hash::Sha512.digest(&[b"abc"]);
        let sig = rsa_sign(&key, TPM_ALG_RSAPSS, Hash::Sha512, &digest).unwrap();
        assert_eq!(
            rsa_verify(&public, TPM_ALG_RSAPSS, Hash::Sha512, &digest, &sig),
            Ok(())
        );

        for (scheme, hash) in [
            (TPM_ALG_RSAES, None),
            (TPM_ALG_OAEP, Some(Hash::Sha256)),
            (crate::alg::TPM_ALG_NULL, None),
        ] {
            let c = rsa_encrypt(&public, scheme, hash, b"label\0", b"\0\0secret").unwrap();
            let m = rsa_decrypt(&key, scheme, hash, b"label\0", &c).unwrap();
            assert!(m.ends_with(b"secret"), "scheme {scheme:#x}");
            let mut bad = c.clone();
            bad[10] ^= 0x40;
            let wrong = rsa_decrypt(&key, scheme, hash, b"label\0", &bad);
            match scheme {
                TPM_ALG_OAEP => assert_eq!(wrong, Err(Rc::VALUE)),
                // Implicit rejection: a message, always the same one for this ciphertext.
                TPM_ALG_RSAES => {
                    let again = rsa_decrypt(&key, scheme, hash, b"label\0", &bad).unwrap();
                    assert_eq!(wrong.unwrap(), again);
                    assert!(!again.ends_with(b"secret"));
                }
                _ => {}
            }
        }
        let c = rsa_encrypt(&public, TPM_ALG_OAEP, Some(Hash::Sha256), b"a\0", b"x").unwrap();
        assert_eq!(
            rsa_decrypt(&key, TPM_ALG_OAEP, Some(Hash::Sha256), b"b\0", &c),
            Err(Rc::VALUE),
            "the label is checked"
        );
    }

    #[test]
    fn rsaes_implicit_rejection_gives_what_openssl_gives() {
        use crate::crypt::tests::unhex;
        // The differential harness's fixed RSA-2048 key (n, p), and a ciphertext whose padding
        // is wrong: the synthetic message libtpms (OpenSSL 3.2+) answers with.
        let n = unhex(
            "e27d4c39369bf37ac6d7d4c7f05c8ac4eddf943a726a2de1a0302c5a946f10c0facbceaf4b5815ca40d6\
             61b21fcacde5ebd1b8336a6014cc338275608b0f0ae2eca68bc74b1ffee1b6adc4d7fe169b69fc7e240a\
             5eefef8b0f4c6ef372889bc3f91511b200a9c1bf8a5308a43b04d38aff3b22abe710b2ef5b4beeb70e48\
             433370375358ce3505eb0878847fb107fe7e3010d7d363c6b12d6104b6d340776f299e7676afe2441c49\
             528fe573e6e1b0b007b85ff514c6ff09959bce18c6f361fc20e5dc57da4608a56a7c3242a7280dbf49e0\
             8539b2a2a13ae5d4a7622b2fce901e4e6a532bea8452a6f7e56e46ada0d3b9f8300a29e216d6b72b3d55\
             72733cd9",
        );
        let p = unhex(
            "fb4fe6639d7b897c4c5159fe7a3e3414fab8d64dfd13e551472d941a3174b495610c25e5758d323ebf97\
             318f30c5b835651f8dd16f2ea26e958a11f83c4224e065bc323dfcf31b0dc033ba7d629d72290e82bdec\
             0a43d12df81861e009a9ce04eeb8736fa1ff111104a81dcd8848165fa03cb88c114fb6f5813e39bd6bf0\
             f5f9",
        );
        let key = rsa_private(&n, &p, 0).unwrap();
        let m = rsa_decrypt(&key, TPM_ALG_RSAES, None, b"", &[0x55; 256]).unwrap();
        assert_eq!(
            m[..],
            unhex(
                "e0b89bb1e467daea8f61a0620118a244769ef00fb3e97680933c258c5ffc332a2462c5af12e1d5fe\
                 069b42ac80d996b042b800b8b08850d4a682a666d0f2800e3d35a1d551b06cf6da7531c0aa144609\
                 73d4a8d754f047091ef8650096934b4de6d8819089a4723ec9"
            )
        );
    }

    /// Decryption takes as long whether the padding is right or not: medians over interleaved
    /// samples of valid and invalid ciphertexts. Timing is noisy; run it alone, optimized:
    /// `cargo test --release -p vk-tpm --lib -- --ignored decryption_time`.
    #[test]
    #[ignore = "timing: run alone with --release"]
    fn decryption_time_does_not_depend_on_the_padding() {
        let (n, _, key) = rsa_generate(2048, 0, &mut drbg(3)).unwrap();
        let public = rsa_public(&n, 0).unwrap();
        for (scheme, hash) in [(TPM_ALG_OAEP, Some(Hash::Sha256)), (TPM_ALG_RSAES, None)] {
            let good = rsa_encrypt(&public, scheme, hash, b"", &[7; 32]).unwrap();
            // A ciphertext of random padding: invalid (all but certainly).
            let bad =
                rsa_encrypt(&public, crate::alg::TPM_ALG_NULL, None, b"", &[0x55; 255]).unwrap();
            let mut times = [Vec::new(), Vec::new()];
            for i in 0..4000usize {
                let which = (i.wrapping_mul(0x9e37_79b9) >> 7) & 1;
                let c = if which == 0 { &good } else { &bad };
                let start = std::time::Instant::now();
                let _ = std::hint::black_box(rsa_decrypt(&key, scheme, hash, b"", c));
                times[which].push(start.elapsed().as_nanos());
            }
            let median = |v: &mut Vec<u128>| {
                v.sort_unstable();
                v[v.len() / 2] as f64
            };
            let (g, b) = (median(&mut times[0]), median(&mut times[1]));
            let difference = (g - b).abs() / g;
            eprintln!(
                "scheme {scheme:#x}: valid {g:.0} ns, invalid {b:.0} ns ({:.2}%)",
                difference * 100.0
            );
            assert!(
                difference < 0.02,
                "scheme {scheme:#x}: {:.2}%",
                difference * 100.0
            );
        }
    }

    #[test]
    fn ecc_keys_are_deterministic_and_work() {
        let d = ecc_derive(&mut drbg(2));
        assert_eq!(d, ecc_derive(&mut drbg(2)));
        let (x, y) = ecc_public(d.as_slice()).unwrap();
        assert!(point(&x, &y).is_some());
        assert!(point(&x, &[0; 32]).is_none());
        // d = (extra mod (n - 1)) + 1, checked with plain big-integer arithmetic.
        let extra = drbg(2).bytes(40);
        let mut wide = [0u8; 48];
        wide[8..].copy_from_slice(&extra);
        let expected = U384::from_be_slice(&wide)
            .rem_vartime(&P256_ORDER_MINUS_1)
            .wrapping_add(&U384::ONE);
        assert_eq!(d[..], expected.to_be_bytes().as_ref()[16..]);

        let digest = Hash::Sha384.digest(&[b"abc"]);
        let (r, s) = ecdsa_sign(d.as_slice(), &digest).unwrap();
        assert_eq!(ecdsa_verify(&x, &y, &digest, &r, &s), Ok(()));
        assert_eq!(
            ecdsa_verify(&x, &y, &digest[..20], &r, &s),
            Err(Rc::SIGNATURE)
        );
        assert_eq!(ecdsa_verify(&x, &y, &digest, &[0], &s), Err(Rc::SIGNATURE));

        // ECDH: [a]([b]G) = [b]([a]G).
        let e = ecc_random().unwrap();
        let (ex, ey) = ecc_public(e.as_slice()).unwrap();
        assert_eq!(
            ecc_multiply(d.as_slice(), &ex, &ey).unwrap(),
            ecc_multiply(e.as_slice(), &x, &y).unwrap()
        );
        assert_eq!(ecc_multiply(d.as_slice(), &ex, &x), Err(Rc::ECC_POINT));
    }
}
