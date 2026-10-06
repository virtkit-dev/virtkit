//! Algorithms (TPM_ALG_ID) the TPM implements, and what TPM2_GetCapability(TPM_CAP_ALGS) says
//! of them.

use sha1::Sha1;
use sha2::digest::common::hazmat::{SerializableState, SerializedState};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::marshal::Reader;
use crate::rc::{Rc, Result};

pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_SHA256: u16 = 0x000b;
pub const TPM_ALG_SHA384: u16 = 0x000c;
pub const TPM_ALG_SHA512: u16 = 0x000d;

/// The largest digest the TPM computes (sizeof(TPMU_HA)).
pub const MAX_DIGEST: usize = 64;

/// A hash algorithm the TPM implements, each a PCR bank.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    /// Every one, in TPM_ALG_ID order.
    pub const ALL: [Hash; 4] = [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512];

    pub fn id(self) -> u16 {
        match self {
            Hash::Sha1 => TPM_ALG_SHA1,
            Hash::Sha256 => TPM_ALG_SHA256,
            Hash::Sha384 => TPM_ALG_SHA384,
            Hash::Sha512 => TPM_ALG_SHA512,
        }
    }

    pub fn from_id(id: u16) -> Option<Hash> {
        Hash::ALL.into_iter().find(|h| h.id() == id)
    }

    /// A TPMI_ALG_HASH (without TPM_ALG_NULL): TPM_RC_HASH for anything else.
    pub fn read(r: &mut Reader) -> Result<Hash> {
        Hash::from_id(r.u16()?).ok_or(Rc::HASH)
    }

    /// A TPMI_ALG_HASH+: None for TPM_ALG_NULL.
    pub fn read_or_null(r: &mut Reader) -> Result<Option<Hash>> {
        match r.u16()? {
            TPM_ALG_NULL => Ok(None),
            id => Hash::from_id(id).map(Some).ok_or(Rc::HASH),
        }
    }

    pub fn size(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    /// The digest of the concatenation of `parts`.
    pub fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        let mut h = Hasher::new(self);
        for part in parts {
            h.update(part);
        }
        h.finish()
    }
}

/// A hash sequence's in-progress digest state, saved and restored with the TPM's volatile state.
#[derive(Clone)]
pub enum Hasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(hash: Hash) -> Hasher {
        match hash {
            Hash::Sha1 => Hasher::Sha1(Sha1::new()),
            Hash::Sha256 => Hasher::Sha256(Sha256::new()),
            Hash::Sha384 => Hasher::Sha384(Sha384::new()),
            Hash::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    pub fn hash(&self) -> Hash {
        match self {
            Hasher::Sha1(_) => Hash::Sha1,
            Hasher::Sha256(_) => Hash::Sha256,
            Hasher::Sha384(_) => Hash::Sha384,
            Hasher::Sha512(_) => Hash::Sha512,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha1(d) => d.update(data),
            Hasher::Sha256(d) => d.update(data),
            Hasher::Sha384(d) => d.update(data),
            Hasher::Sha512(d) => d.update(data),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Sha1(d) => d.finalize().to_vec(),
            Hasher::Sha256(d) => d.finalize().to_vec(),
            Hasher::Sha384(d) => d.finalize().to_vec(),
            Hasher::Sha512(d) => d.finalize().to_vec(),
        }
    }

    /// Its internal state, in RustCrypto's serialization: the block state, the length so far
    /// and the bytes buffered.
    pub fn save(&self) -> Vec<u8> {
        match self {
            Hasher::Sha1(d) => d.serialize().to_vec(),
            Hasher::Sha256(d) => d.serialize().to_vec(),
            Hasher::Sha384(d) => d.serialize().to_vec(),
            Hasher::Sha512(d) => d.serialize().to_vec(),
        }
    }

    /// Restore [`Hasher::save`]'s output if `state` is valid for `hash`.
    pub fn load(hash: Hash, state: &[u8]) -> Option<Hasher> {
        fn load<D: SerializableState>(state: &[u8]) -> Option<D> {
            let state = SerializedState::<D>::try_from(state).ok()?;
            D::deserialize(&state).ok()
        }
        Some(match hash {
            Hash::Sha1 => Hasher::Sha1(load(state)?),
            Hash::Sha256 => Hasher::Sha256(load(state)?),
            Hash::Sha384 => Hasher::Sha384(load(state)?),
            Hash::Sha512 => Hasher::Sha512(load(state)?),
        })
    }
}

// TPMA_ALGORITHM bits.
const SYMMETRIC: u32 = 1 << 1;
const HASH: u32 = 1 << 2;
const SIGNING: u32 = 1 << 8;
const ENCRYPTING: u32 = 1 << 9;
const METHOD: u32 = 1 << 10;

/// TPM_CAP_ALGS: each implemented algorithm and its TPMA_ALGORITHM, in TPM_ALG_ID order. Only
/// what the TPM actually implements: a client picks from this list. HMAC, AES (in CFB mode),
/// XOR and KDFa (SP 800-108) are those of the sessions.
pub const IMPLEMENTED: [(u16, u32); 9] = [
    (TPM_ALG_SHA1, HASH),
    (0x0005, HASH | SIGNING),   // TPM_ALG_HMAC
    (0x0006, SYMMETRIC),        // TPM_ALG_AES
    (0x000a, SYMMETRIC | HASH), // TPM_ALG_XOR
    (TPM_ALG_SHA256, HASH),
    (TPM_ALG_SHA384, HASH),
    (TPM_ALG_SHA512, HASH),
    (0x0022, HASH | METHOD),          // TPM_ALG_KDF1_SP800_108
    (0x0043, SYMMETRIC | ENCRYPTING), // TPM_ALG_CFB
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_their_size_and_known_values() {
        for h in Hash::ALL {
            assert_eq!(h.digest(&[b"abc"]).len(), h.size());
            assert_eq!(Hash::from_id(h.id()), Some(h));
        }
        assert_eq!(
            Hash::Sha256.digest(&[b"a", b"bc"])[..4],
            [0xba, 0x78, 0x16, 0xbf]
        );
        assert!(IMPLEMENTED.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn a_saved_hasher_goes_on_where_it_stopped() {
        for hash in Hash::ALL {
            let mut h = Hasher::new(hash);
            h.update(&[7; 200]);
            let state = h.save();
            let mut loaded = Hasher::load(hash, &state).unwrap();
            loaded.update(b"tail");
            assert_eq!(loaded.finish(), hash.digest(&[&[7; 200], b"tail"]));
            assert!(Hasher::load(hash, &state[1..]).is_none());
        }
    }
}
