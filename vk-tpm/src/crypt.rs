//! The TPM's keyed primitives (Part 1, "Cryptographic Functions"): HMAC, the two key derivation
//! functions, and the symmetric transforms parameter encryption uses. All of it is RustCrypto's;
//! this module only frames the inputs the way the specification does.
//!
//! Every derived key comes back [`Zeroizing`].

use aes::{Aes128, Aes192, Aes256};
use cfb_mode::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyIvInit};
use hmac::digest::block_api::EagerHash;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use zeroize::Zeroizing;

use crate::alg::Hash;
use crate::rc::{Rc, Result};

/// The AES block size, which is also the size of a CFB IV.
pub const AES_BLOCK: usize = 16;

/// HMAC(`key`, the concatenation of `parts`), with `hash`.
pub fn hmac(hash: Hash, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    fn run<D: EagerHash>(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        // HMAC takes a key of any length (a long one is hashed first): this cannot fail.
        let Ok(mut mac) = <Hmac<D> as KeyInit>::new_from_slice(key) else {
            return Vec::new();
        };
        for part in parts {
            mac.update(part);
        }
        mac.finalize().into_bytes().to_vec()
    }
    match hash {
        Hash::Sha1 => run::<Sha1>(key, parts),
        Hash::Sha256 => run::<Sha256>(key, parts),
        Hash::Sha384 => run::<Sha384>(key, parts),
        Hash::Sha512 => run::<Sha512>(key, parts),
    }
}

/// KDFa (SP 800-108 counter mode, HMAC as the PRF): `bytes` bytes of key stream from `key`.
///
/// Each block is HMAC(key, counter ‖ label ‖ 0 ‖ contextU ‖ contextV ‖ bits). `label` is the
/// specification's string ("ATH", "CFB", ...); the 0 that terminates it is added unless it already
/// ends in one, as the reference implementation does.
pub fn kdfa(
    hash: Hash,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    bytes: usize,
) -> Zeroizing<Vec<u8>> {
    let terminator: &[u8] = if label.last() == Some(&0) { &[] } else { &[0] };
    let bits = bits(bytes);
    counter_mode(hash.size(), bytes, |counter| {
        hmac(
            hash,
            key,
            &[&counter, label, terminator, context_u, context_v, &bits],
        )
    })
}

/// KDFe (SP 800-56A concatenation, the hash itself as the PRF): `bytes` bytes of key stream from
/// the shared secret `z`. Each block is H(counter ‖ Z ‖ label ‖ partyUInfo ‖ partyVInfo), with
/// `label` hashed as given: its terminating 0 included.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "ECC salts and credentials come with ECC keys")
)]
pub fn kdfe(
    hash: Hash,
    z: &[u8],
    label: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    bytes: usize,
) -> Zeroizing<Vec<u8>> {
    counter_mode(hash.size(), bytes, |counter| {
        hash.digest(&[&counter, z, label, party_u, party_v])
    })
}

/// The 32-bit big-endian bit count the KDFs take; a TPM never asks for 512 MiB of key.
fn bits(bytes: usize) -> [u8; 4] {
    u32::try_from(bytes.saturating_mul(8))
        .unwrap_or(u32::MAX)
        .to_be_bytes()
}

/// Concatenate `block(1)`, `block(2)`, ... (each `size` bytes, the counter big-endian) up to
/// `bytes`, the last one truncated.
fn counter_mode(
    size: usize,
    bytes: usize,
    mut block: impl FnMut([u8; 4]) -> Vec<u8>,
) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.saturating_add(size)));
    let mut counter = 0u32;
    while out.len() < bytes {
        counter = counter.wrapping_add(1);
        let mut b = Zeroizing::new(block(counter.to_be_bytes()));
        if b.is_empty() {
            break;
        }
        b.truncate(bytes.saturating_sub(out.len()));
        out.extend_from_slice(&b);
    }
    out
}

/// XOR obfuscation (Part 1, "XOR parameter obfuscation"): `data` ^= KDFa(hash, key, "XOR", U, V).
/// Its own inverse.
pub fn xor_obfuscate(hash: Hash, key: &[u8], context_u: &[u8], context_v: &[u8], data: &mut [u8]) {
    let mask = kdfa(hash, key, b"XOR", context_u, context_v, data.len());
    for (d, m) in data.iter_mut().zip(mask.iter()) {
        *d ^= m;
    }
}

/// AES in CFB mode (full-block feedback), in place; the key's length picks AES-128, -192 or -256.
pub fn aes_cfb(key: &[u8], iv: &[u8], data: &mut [u8], encrypt: bool) -> Result<()> {
    fn run<C>(key: &[u8], iv: &[u8], data: &mut [u8], encrypt: bool) -> Result<()>
    where
        C: BlockCipherEncrypt + BlockCipherDecrypt + KeyInit,
    {
        if encrypt {
            cfb_mode::Encryptor::<C>::new_from_slices(key, iv)
                .map_err(|_| Rc::FAILURE)?
                .encrypt(data);
        } else {
            cfb_mode::Decryptor::<C>::new_from_slices(key, iv)
                .map_err(|_| Rc::FAILURE)?
                .decrypt(data);
        }
        Ok(())
    }
    match key.len() {
        16 => run::<Aes128>(key, iv, data, encrypt),
        24 => run::<Aes192>(key, iv, data, encrypt),
        32 => run::<Aes256>(key, iv, data, encrypt),
        _ => Err(Rc::FAILURE),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        // RFC 4231 test case 2, split into parts.
        let mac = hmac(
            Hash::Sha256,
            b"Jefe",
            &[b"what do ya want ", b"for nothing?"],
        );
        assert_eq!(
            mac,
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        let mac = hmac(Hash::Sha512, b"Jefe", &[b"what do ya want for nothing?"]);
        assert_eq!(mac[..8], unhex("164b7a7bfcf819e2"));
    }

    #[test]
    fn kdfa_is_hmac_counter_mode() {
        let (key, u, v) = (b"key", b"nonce-newer", b"nonce-older");
        // 40 bytes of SHA-256: two blocks, the second one truncated.
        let out = kdfa(Hash::Sha256, key, b"ATH", u, v, 40);
        let block = |i: u32| {
            hmac(
                Hash::Sha256,
                key,
                &[&i.to_be_bytes(), b"ATH\0", u, v, &320u32.to_be_bytes()],
            )
        };
        assert_eq!(out[..32], block(1)[..]);
        assert_eq!(out[32..], block(2)[..8]);
        // A label that already ends in its 0 gets no second one.
        assert_eq!(kdfa(Hash::Sha256, key, b"ATH\0", u, v, 40), out);
        assert!(kdfa(Hash::Sha1, key, b"", u, v, 0).is_empty());
    }

    #[test]
    fn kdfe_is_hash_counter_mode() {
        let out = kdfe(Hash::Sha384, b"z", b"SECRET\0", b"u", b"v", 50);
        let block =
            |i: u32| Hash::Sha384.digest(&[&i.to_be_bytes(), b"z", b"SECRET\0", b"u", b"v"]);
        assert_eq!(out[..48], block(1)[..]);
        assert_eq!(out[48..], block(2)[..2]);
    }

    #[test]
    fn xor_obfuscation_is_its_own_inverse() {
        let mut data = b"some parameter".to_vec();
        xor_obfuscate(Hash::Sha1, b"k", b"u", b"v", &mut data);
        assert_ne!(data, b"some parameter");
        xor_obfuscate(Hash::Sha1, b"k", b"u", b"v", &mut data);
        assert_eq!(data, b"some parameter");
    }

    #[test]
    fn aes_cfb_matches_sp_800_38a() {
        // SP 800-38A F.3.13, CFB128-AES128, two blocks and a partial third.
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let plain = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let mut data = plain.clone();
        aes_cfb(&key, &iv, &mut data, true).unwrap();
        assert_eq!(
            data,
            unhex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b")
        );
        aes_cfb(&key, &iv, &mut data, false).unwrap();
        assert_eq!(data, plain);
        let mut short = plain[..5].to_vec();
        aes_cfb(&key, &iv, &mut short, true).unwrap();
        assert_eq!(short, unhex("3b3f d92eb7".replace(' ', "").as_str()));
        assert_eq!(aes_cfb(&key[..15], &iv, &mut data, true), Err(Rc::FAILURE));
    }
}
