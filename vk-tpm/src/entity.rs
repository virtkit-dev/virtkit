//! Handles (Part 2, TPM_HANDLE) and what they name: a hierarchy, a PCR, a session, an object.
//!
//! A command's handle area is checked twice, as the reference implementation does: each handle
//! against the interface type the command declares ([`HandleKind`]), then, once all are read,
//! that each names something present ([`Tpm::check_loaded`]). The entity functions give the
//! Name, authValue and authPolicy that authorization needs.

use zeroize::Zeroizing;

use crate::Tpm;
use crate::hierarchy::Policy;
use crate::pcr;
use crate::rc::{Rc, Result};

pub const TPM_RH_OWNER: u32 = 0x4000_0001;
pub const TPM_RH_NULL: u32 = 0x4000_0007;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const TPM_RH_LOCKOUT: u32 = 0x4000_000a;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
pub const TPM_RH_PLATFORM: u32 = 0x4000_000c;
pub const TPM_RH_PLATFORM_NV: u32 = 0x4000_000d;
/// TPM_RH_AUTH_00..FF: vendor authorization values, none of which this TPM has.
const VENDOR_AUTH: std::ops::RangeInclusive<u32> = 0x4000_0010..=0x4000_010f;

pub const TPM_HT_PCR: u8 = 0x00;
pub const TPM_HT_NV_INDEX: u8 = 0x01;
pub const TPM_HT_HMAC_SESSION: u8 = 0x02;
pub const TPM_HT_POLICY_SESSION: u8 = 0x03;
pub const TPM_HT_PERMANENT: u8 = 0x40;
pub const TPM_HT_TRANSIENT: u8 = 0x80;
pub const TPM_HT_PERSISTENT: u8 = 0x81;

/// The handle's type: its top byte.
pub fn handle_type(handle: u32) -> u8 {
    handle.to_be_bytes()[0]
}

/// What a handle in a command's handle area may be: a TPMI_ interface type (`+`: TPM_RH_NULL
/// allowed). Anything else is TPM_RC_VALUE.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandleKind {
    /// TPMI_DH_PCR, or with `true` TPMI_DH_PCR+.
    Pcr(bool),
    /// TPMI_RH_HIERARCHY: owner, endorsement or platform.
    Hierarchy,
    /// TPMI_RH_HIERARCHY_AUTH: a hierarchy, or lockout.
    HierarchyAuth,
    /// TPMI_RH_HIERARCHY_POLICY: as TPMI_RH_HIERARCHY_AUTH (and the ACT handles, which this TPM
    /// does not have: those fail the load check with the same TPM_RC_VALUE).
    HierarchyPolicy,
    /// TPMI_RH_PLATFORM.
    Platform,
    /// TPMI_RH_LOCKOUT.
    Lockout,
    /// TPMI_RH_CLEAR: lockout or platform.
    Clear,
}

impl HandleKind {
    pub fn check(self, handle: u32) -> Result<()> {
        let hierarchy = matches!(handle, TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM);
        let ok = match self {
            HandleKind::Pcr(null) => is_pcr(handle) || (null && handle == TPM_RH_NULL),
            HandleKind::Hierarchy => hierarchy,
            HandleKind::HierarchyAuth | HandleKind::HierarchyPolicy => {
                hierarchy || handle == TPM_RH_LOCKOUT
            }
            HandleKind::Platform => handle == TPM_RH_PLATFORM,
            HandleKind::Lockout => handle == TPM_RH_LOCKOUT,
            HandleKind::Clear => matches!(handle, TPM_RH_LOCKOUT | TPM_RH_PLATFORM),
        };
        if ok { Ok(()) } else { Err(Rc::VALUE) }
    }
}

pub fn is_pcr(handle: u32) -> bool {
    usize::try_from(handle).is_ok_and(|h| h < pcr::PCR_COUNT)
}

impl Tpm {
    /// EntityGetLoadStatus: every handle names something the TPM has, in an enabled hierarchy.
    pub fn check_loaded(&self, handles: &[u32]) -> Result<()> {
        for (n, &handle) in (1..).zip(handles) {
            let status = match handle_type(handle) {
                TPM_HT_PERMANENT => match handle {
                    TPM_RS_PW | TPM_RH_LOCKOUT => Ok(()),
                    h if VENDOR_AUTH.contains(&h) => Err(Rc::VALUE),
                    h => self.hierarchy_enabled(h),
                },
                // A PCR handle that passed its kind check names a PCR.
                _ => Ok(()),
            };
            status.map_err(|rc| rc.handle(n))?;
        }
        Ok(())
    }

    /// ValidateHierarchy: TPM_RC_HIERARCHY for a disabled hierarchy, TPM_RC_VALUE for a handle
    /// that is none.
    pub fn hierarchy_enabled(&self, handle: u32) -> Result<()> {
        let enabled = match handle {
            TPM_RH_PLATFORM => self.volatile.ph_enable,
            TPM_RH_OWNER => self.volatile.clear.sh_enable,
            TPM_RH_ENDORSEMENT => self.volatile.clear.eh_enable,
            TPM_RH_NULL => true,
            _ => return Err(Rc::VALUE),
        };
        if enabled { Ok(()) } else { Err(Rc::HIERARCHY) }
    }

    /// The entity's Name: for a hierarchy or a PCR, its handle.
    pub fn entity_name(&self, handle: u32) -> Vec<u8> {
        handle.to_be_bytes().to_vec()
    }

    /// The entity's authValue, trailing zeros removed (they never count).
    pub fn entity_auth(&self, handle: u32) -> Zeroizing<Vec<u8>> {
        let h = &self.permanent.hierarchies;
        let auth = match handle {
            TPM_RH_OWNER => &h.owner_auth,
            TPM_RH_ENDORSEMENT => &h.endorsement_auth,
            TPM_RH_LOCKOUT => &h.lockout_auth,
            TPM_RH_PLATFORM => &self.volatile.clear.platform_auth,
            // TPM_RH_NULL and the PCRs: the empty authValue.
            _ => return Zeroizing::new(Vec::new()),
        };
        Zeroizing::new(strip_zeros(auth).to_vec())
    }

    /// The entity's authPolicy, if it has one a policy session can satisfy.
    pub fn entity_policy(&self, handle: u32) -> Option<&Policy> {
        let h = &self.permanent.hierarchies;
        let policy = match handle {
            TPM_RH_OWNER => &h.owner_policy,
            TPM_RH_ENDORSEMENT => &h.endorsement_policy,
            TPM_RH_LOCKOUT => &h.lockout_policy,
            TPM_RH_PLATFORM => &self.volatile.clear.platform_policy,
            // No PCR belongs to a policy group.
            _ => return None,
        };
        policy.hash.is_some().then_some(policy)
    }
}

/// IsDAExempted: an authorization failure on the entity does not count against the dictionary
/// attack protection. Every permanent handle but lockout (which has its own) and every PCR is.
pub fn is_da_exempt(handle: u32) -> bool {
    match handle_type(handle) {
        TPM_HT_PERMANENT => handle != TPM_RH_LOCKOUT,
        TPM_HT_PCR => true,
        _ => false,
    }
}

/// `bytes` without its trailing zeros (MemoryRemoveTrailingZeros).
pub fn strip_zeros(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    bytes.get(..end).unwrap_or_default()
}
