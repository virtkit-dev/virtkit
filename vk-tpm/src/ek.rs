//! Endorsement keys as a TPM manufacturer provisions them (TCG EK Credential Profile 2.x): the EK
//! the profile's default template makes in the endorsement hierarchy (the one a guest makes
//! with TPM2_CreatePrimary, Windows included), made persistent, and its certificate in NV.
//! The persistent handles are those the TCG Provisioning Guidance reserves (Table 2); the
//! certificate index's attributes are those swtpm_setup gives QEMU's TPMs.
//!
//! Nothing is provisioned by [`Tpm::manufacture`]: the device decides, and which CA signs a
//! certificate is the host's business (see the design's "EK certificate").

use zeroize::Zeroizing;

use crate::Tpm;
use crate::alg::Hash;
use crate::entity::TPM_RH_ENDORSEMENT;
use crate::key::{Key, MAX_PERSISTENT};
use crate::nv::{self, MAX_NV_INDEX_SIZE, NvPublic};
use crate::public::{
    Params, Public, Scheme, SensitiveCreate, SymDef, TPM_ALG_CFB, TPM_ECC_NIST_P256, Unique, attr,
};
use crate::rc::Rc;

/// The default EK authPolicy: TPM2_PolicySecret(TPM_RH_ENDORSEMENT), with SHA-256.
const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// An EK certificate's index: written by the platform only, read by the owner or with its
/// empty authValue, never by policy; write-locked until it is deleted (TPMA_NV_WRITEDEFINE).
const CERTIFICATE_ATTRIBUTES: u32 = nv::attr::PLATFORMCREATE
    | nv::attr::PPWRITE
    | nv::attr::PPREAD
    | nv::attr::OWNERREAD
    | nv::attr::AUTHREAD
    | nv::attr::NO_DA
    | nv::attr::WRITEDEFINE
    | nv::attr::WRITTEN
    | nv::attr::WRITELOCKED;

/// Low-range EKs from the profile's default templates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EkKind {
    /// RSA 2048, template L-1: what Windows uses.
    Rsa2048,
    /// ECC NIST P-256, template L-2.
    EccNistP256,
}

impl EkKind {
    /// Where the EK is made persistent.
    pub fn handle(self) -> u32 {
        match self {
            EkKind::Rsa2048 => 0x8101_0001,
            EkKind::EccNistP256 => 0x8101_0002,
        }
    }

    /// The NV index of its certificate.
    pub fn certificate_index(self) -> u32 {
        match self {
            EkKind::Rsa2048 => 0x01c0_0002,
            EkKind::EccNistP256 => 0x01c0_000a,
        }
    }

    /// The default template: a restricted decryption key with AES-128-CFB for its children,
    /// whose ADMIN and USER roles take the endorsement hierarchy's authorization (its policy);
    /// the unique field zeros.
    fn template(self) -> Public {
        let symmetric = Some(SymDef {
            bits: 128,
            mode: TPM_ALG_CFB,
        });
        let (params, unique) = match self {
            EkKind::Rsa2048 => (
                Params::Rsa {
                    symmetric,
                    scheme: Scheme::NULL,
                    bits: 2048,
                    exponent: 0,
                },
                Unique::Rsa(vec![0; 256]),
            ),
            EkKind::EccNistP256 => (
                Params::Ecc {
                    symmetric,
                    scheme: Scheme::NULL,
                    curve: TPM_ECC_NIST_P256,
                    kdf: Scheme::NULL,
                },
                Unique::Ecc {
                    x: vec![0; 32],
                    y: vec![0; 32],
                },
            ),
        };
        Public {
            name_alg: Some(Hash::Sha256),
            attributes: attr::FIXED_TPM
                | attr::FIXED_PARENT
                | attr::SENSITIVE_DATA_ORIGIN
                | attr::ADMIN_WITH_POLICY
                | attr::RESTRICTED
                | attr::DECRYPT,
            auth_policy: EK_POLICY.to_vec(),
            params,
            unique,
        }
    }
}

impl Tpm {
    /// The EK of `kind` (a TPMT_PUBLIC): what a certificate certifies. It is the same until the
    /// endorsement seed changes (TPM2_ChangeEPS).
    pub fn endorsement_key(&self, kind: EkKind) -> Result<Vec<u8>, Rc> {
        Ok(self.ek(kind)?.public.to_bytes())
    }

    /// Provision the EK of `kind` as a manufacturer would: persistent at its handle, and
    /// `certificate` (DER) at its index, or no certificate there if `None`; either replaces what
    /// was there. The permanent state changes: store it. TPM_RC_NV_SPACE if there is no room.
    pub fn provision_endorsement_key(
        &mut self,
        kind: EkKind,
        certificate: Option<&[u8]>,
    ) -> Result<(), Rc> {
        let key = self.ek(kind)?;
        let handle = kind.handle();
        let persistent = &self.permanent.persistent;
        if persistent.len() >= MAX_PERSISTENT && !persistent.iter().any(|(h, _)| *h == handle) {
            return Err(Rc::NV_SPACE);
        }
        let index = kind.certificate_index();
        match certificate {
            Some(der) => {
                if der.len() > MAX_NV_INDEX_SIZE {
                    return Err(Rc::SIZE);
                }
                let public = NvPublic {
                    index,
                    name_alg: Hash::Sha256,
                    attributes: CERTIFICATE_ATTRIBUTES,
                    auth_policy: Vec::new(),
                    data_size: u16::try_from(der.len()).map_err(|_| Rc::SIZE)?,
                };
                self.nv_provision(public, der)?;
            }
            None => self.nv_delete(index),
        }
        let list = &mut self.permanent.persistent;
        list.retain(|(h, _)| *h != handle);
        let at = list.partition_point(|(h, _)| *h < handle);
        list.insert(at, (handle, key));
        self.permanent_changed = true;
        Ok(())
    }

    /// The EK of `kind`, as TPM2_CreatePrimary makes it.
    fn ek(&self, kind: EkKind) -> Result<Key, Rc> {
        let empty = SensitiveCreate {
            auth: Zeroizing::new(Vec::new()),
            data: Zeroizing::new(Vec::new()),
        };
        self.primary_key(TPM_RH_ENDORSEMENT, kind.template(), &empty)
    }
}
