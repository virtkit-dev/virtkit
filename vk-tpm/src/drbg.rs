//! The deterministic random bit generator primary keys are derived with: the reference
//! implementation's CTR_DRBG (SP 800-90A, AES-256, no prediction resistance), instantiated from a
//! hierarchy seed through its own derivation function (`CryptRand.c`, DRBG_InstantiateSeeded).
//!
//! A TPM must recreate the same primary key from the same seed and template, every boot. Doing
//! it exactly as the reference does makes vk-tpm's ECC, keyed-hash and symmetric primaries the
//! very keys libtpms derives from the same seeds, which the differential tests check byte for
//! byte. RSA primaries also draw from it, but their prime search is vk-tpm's (see `rsa.rs`).

use aes::Aes256;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use zeroize::{Zeroize, Zeroizing};

const KEY: usize = 32;
const BLOCK: usize = 16;
/// The DRBG state, and what (re)seeds it: a key and a counter block (DRBG_SEED).
const SEED: usize = KEY + BLOCK;
/// The derivation function's parallel CBC-MAC chains: enough blocks for a seed.
const DF_CHAINS: usize = KEY / BLOCK + 1;

/// "Primary Object Creation", with its terminating zero, as the reference's TPM2B_STRING has it.
pub const PRIMARY_OBJECT_CREATION: &[u8] = b"Primary Object Creation\0";

fn cipher(key: &[u8]) -> Option<Aes256> {
    Aes256::new_from_slice(key).ok()
}

fn encrypt(cipher: &Aes256, block: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut b = Array::from(*block);
    cipher.encrypt_block(&mut b);
    let out: [u8; BLOCK] = b.into();
    b.zeroize();
    out
}

/// A CTR_DRBG. Its state is wiped when dropped.
pub struct Drbg {
    /// Key ‖ V.
    seed: Zeroizing<[u8; SEED]>,
}

impl Drbg {
    /// DRBG_InstantiateSeeded: the generator for a primary key of the hierarchy whose seed is
    /// `seed`, for the template whose Name is `name` and the caller's sensitive `data`.
    pub fn seeded(seed: &[u8], purpose: &[u8], name: &[u8], data: &[u8]) -> Drbg {
        let parts = [seed, purpose, name, data];
        let total = parts.iter().map(|p| p.len()).sum();
        let mut df = Df::start(total);
        for part in parts {
            df.update(part);
        }
        let entropy = df.end();
        let mut drbg = Drbg {
            seed: Zeroizing::new([0; SEED]),
        };
        drbg.reseed(&entropy);
        drbg
    }

    /// A generator seeded with 48 bytes of `entropy` and no personalization (DRBG_Instantiate),
    /// as the NIST test vectors give it.
    #[cfg(test)]
    fn from_entropy(entropy: &[u8; SEED]) -> Drbg {
        let mut drbg = Drbg {
            seed: Zeroizing::new([0; SEED]),
        };
        drbg.reseed(entropy);
        drbg
    }

    /// DRBG_AdditionalData: mix `data` (through the derivation function) into the state.
    pub fn additional_data(&mut self, data: &[u8]) {
        let mut df = Df::start(data.len());
        df.update(data);
        let entropy = df.end();
        self.reseed(&entropy);
    }

    /// DRBG_Reseed with no additional input.
    fn reseed(&mut self, entropy: &[u8; SEED]) {
        self.update(Some(entropy));
    }

    /// CTR_DRBG_Update: the state becomes the next three counter blocks, XORed with `provided`.
    fn update(&mut self, provided: Option<&[u8; SEED]>) {
        let Some(c) = self.cipher() else {
            return;
        };
        let mut next = Zeroizing::new([0u8; SEED]);
        self.counter_blocks(&c, next.as_mut_slice());
        if let Some(p) = provided {
            for (n, p) in next.iter_mut().zip(p) {
                *n ^= p;
            }
        }
        *self.seed = *next;
    }

    /// Fill `out` with E(++V), E(++V), ... (the last block truncated).
    fn counter_blocks(&mut self, c: &Aes256, out: &mut [u8]) {
        for chunk in out.chunks_mut(BLOCK) {
            let v = self.v_mut();
            for b in v.iter_mut().rev() {
                *b = b.wrapping_add(1);
                if *b != 0 {
                    break;
                }
            }
            let mut v_block = [0u8; BLOCK];
            v_block.copy_from_slice(self.v_mut());
            let mut block = encrypt(c, &v_block);
            for (o, b) in chunk.iter_mut().zip(block.iter()) {
                *o = *b;
            }
            block.zeroize();
        }
    }

    /// AES-256 with the state's key.
    fn cipher(&self) -> Option<Aes256> {
        cipher(self.seed.first_chunk::<KEY>()?)
    }

    fn v_mut(&mut self) -> &mut [u8] {
        self.seed.get_mut(KEY..).unwrap_or_default()
    }

    /// DRBG_Generate: `out.len()` bytes, then a key update. The reference caps one request at
    /// 64 KiB; no TPM caller comes near.
    pub fn generate(&mut self, out: &mut [u8]) {
        let Some(c) = self.cipher() else {
            return;
        };
        self.counter_blocks(&c, out);
        // The update keeps using the key the bytes were generated with (as the reference).
        let mut next = Zeroizing::new([0u8; SEED]);
        self.counter_blocks(&c, next.as_mut_slice());
        *self.seed = *next;
    }

    /// `n` bytes from the generator.
    pub fn bytes(&mut self, n: usize) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0; n]);
        self.generate(&mut out);
        out
    }
}

/// The reference's derivation function (DfStart/DfUpdate/DfEnd): parallel AES CBC-MACs keyed
/// with 00 01 .. 1f, over the input length, the seed length and the input. It is not quite SP
/// 800-90A's Block_Cipher_df (the chains share one running XOR); what matters is that it is the
/// reference's, bit for bit.
struct Df {
    cipher: Option<Aes256>,
    chains: Zeroizing<[[u8; BLOCK]; DF_CHAINS]>,
    buf: Zeroizing<[u8; BLOCK]>,
    contents: usize,
}

impl Df {
    fn start(input_len: usize) -> Df {
        let key: [u8; KEY] = std::array::from_fn(|i| i as u8);
        let mut df = Df {
            cipher: cipher(&key),
            chains: Zeroizing::new([[0; BLOCK]; DF_CHAINS]),
            buf: Zeroizing::new([0; BLOCK]),
            contents: 0,
        };
        for (i, chain) in df.chains.iter_mut().enumerate() {
            chain[3] = i as u8;
        }
        df.compute();
        let len = u32::try_from(input_len).unwrap_or(u32::MAX).to_be_bytes();
        let seed_len = (SEED as u32).to_be_bytes();
        if let Some(first) = df.chains.first_mut() {
            for (dst, src) in first.iter_mut().zip(len.iter().chain(&seed_len)) {
                *dst = *src;
            }
        }
        df.contents = 4;
        df
    }

    /// DfCompute: one block of input into every chain.
    fn compute(&mut self) {
        let Some(c) = &self.cipher else { return };
        let mut temp = Zeroizing::new([0u8; BLOCK]);
        for chain in self.chains.iter_mut() {
            for ((t, ch), b) in temp.iter_mut().zip(chain.iter()).zip(self.buf.iter()) {
                *t ^= ch ^ b;
            }
            *chain = encrypt(c, &temp);
        }
        *self.buf = [0; BLOCK];
        self.contents = 0;
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let room = BLOCK.saturating_sub(self.contents).min(data.len());
            let (head, rest) = data.split_at(room);
            let end = self.contents.saturating_add(room);
            if let Some(dst) = self.buf.get_mut(self.contents..end) {
                dst.copy_from_slice(head);
            }
            self.contents = end;
            data = rest;
            if self.contents == BLOCK {
                self.compute();
            }
        }
    }

    fn end(mut self) -> Zeroizing<[u8; SEED]> {
        if let Some(b) = self.buf.get_mut(self.contents) {
            *b = 0x80;
        }
        self.compute();
        let mut out = Zeroizing::new([0u8; SEED]);
        for (dst, chain) in out.chunks_mut(BLOCK).zip(self.chains.iter()) {
            dst.copy_from_slice(chain);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypt::tests::unhex;

    #[test]
    fn matches_the_nist_ctr_drbg_vector() {
        // [AES-256 no df], COUNT = 0: the reference's own self-test.
        let entropy = unhex(
            "0d15aa80b16c3a10906cfedb795dae0b5b81041c5c5bfacb373d4440d9120f7e\
             3d6cf90986cf52d85d3e947d8c061f91",
        );
        let mut drbg = Drbg::from_entropy(&entropy.try_into().unwrap());
        let mut out = [0u8; 16];
        drbg.generate(&mut out);
        assert_eq!(out[..], unhex("28e0ebb8210166508c8f65f2207bd0a3"));
        let reseed = unhex(
            "6ee793a33955d72ad12fd80a8a3fcf95ed3b4dac5795fe25cf869f7c27573bbc\
             56f1acae13a65042b340093c464a7a22",
        );
        drbg.reseed(&reseed.try_into().unwrap());
        drbg.generate(&mut out);
        assert_eq!(out[..], unhex("946f5182d54510b9461248f571ca06c9"));
    }

    #[test]
    fn a_seeded_generator_depends_on_every_input() {
        let a = Drbg::seeded(&[1; 64], PRIMARY_OBJECT_CREATION, b"name", b"").bytes(40);
        let b = Drbg::seeded(&[1; 64], PRIMARY_OBJECT_CREATION, b"name", b"").bytes(40);
        assert_eq!(a, b);
        for other in [
            Drbg::seeded(&[2; 64], PRIMARY_OBJECT_CREATION, b"name", b"").bytes(40),
            Drbg::seeded(&[1; 64], PRIMARY_OBJECT_CREATION, b"nane", b"").bytes(40),
            Drbg::seeded(&[1; 64], PRIMARY_OBJECT_CREATION, b"name", b"x").bytes(40),
        ] {
            assert_ne!(a, other);
        }
        // Successive requests continue the stream only through the key update.
        let mut d = Drbg::seeded(&[1; 64], PRIMARY_OBJECT_CREATION, b"name", b"");
        let (first, second) = (d.bytes(16), d.bytes(16));
        assert_eq!(first[..], a[..16]);
        assert_ne!(second[..], a[16..32]);
        // Additional data changes what follows.
        let mut e = Drbg::seeded(&[1; 64], PRIMARY_OBJECT_CREATION, b"name", b"");
        e.additional_data(b"proof");
        assert_ne!(e.bytes(16)[..], a[..16]);
    }
}
