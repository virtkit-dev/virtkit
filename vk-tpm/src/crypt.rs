//! The TPM's keyed primitives (Part 1, "Cryptographic Functions"). All of it is RustCrypto's;
//! this module only frames the inputs the way the specification does.

use hmac::digest::block_api::EagerHash;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::alg::Hash;

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

#[cfg(test)]
mod tests {
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
}
