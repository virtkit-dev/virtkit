//! Algorithms (TPM_ALG_ID) the TPM implements, and what TPM2_GetCapability(TPM_CAP_ALGS) says
//! of them.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::marshal::Reader;
use crate::rc::{Rc, Result};

pub const TPM_ALG_SHA1: u16 = 0x0004;
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
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for part in parts {
                d.update(part);
            }
            d.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => run::<Sha1>(parts),
            Hash::Sha256 => run::<Sha256>(parts),
            Hash::Sha384 => run::<Sha384>(parts),
            Hash::Sha512 => run::<Sha512>(parts),
        }
    }
}

// TPMA_ALGORITHM bits.
const HASH: u32 = 1 << 2;

/// TPM_CAP_ALGS: each implemented algorithm and its TPMA_ALGORITHM, in TPM_ALG_ID order. Only
/// what the TPM actually implements: a client picks from this list.
pub const IMPLEMENTED: [(u16, u32); 4] = [
    (TPM_ALG_SHA1, HASH),
    (TPM_ALG_SHA256, HASH),
    (TPM_ALG_SHA384, HASH),
    (TPM_ALG_SHA512, HASH),
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
}
