//! Handles (Part 2, TPM_HANDLE) and what they name: a hierarchy, a PCR, a session, an object.
//!
//! A command's handle area is checked twice, as the reference implementation does: each handle
//! against the interface type the command declares ([`HandleKind`]), then, once all are read,
//! that each names something present ([`Tpm::check_loaded`]). The entity functions give the
//! Name, authValue and authPolicy that authorization needs.

use zeroize::Zeroizing;

use crate::Tpm;
use crate::hierarchy::Policy;
use crate::object::{MAX_OBJECTS, TRANSIENT_FIRST};
use crate::pcr;
use crate::public::attr;
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
    /// TPMI_RH_HIERARCHY+: a hierarchy or TPM_RH_NULL.
    HierarchyOrNull,
    /// TPMI_RH_PROVISION: owner or platform.
    Provision,
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
    /// TPMI_DH_OBJECT, or with `true` TPMI_DH_OBJECT+: a transient or persistent object.
    Object(bool),
    /// TPMI_DH_ENTITY, or with `true` TPMI_DH_ENTITY+: anything with an authorization.
    Entity(bool),
}

impl HandleKind {
    pub fn check(self, handle: u32) -> Result<()> {
        let hierarchy = matches!(handle, TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM);
        let ok = match self {
            HandleKind::Pcr(null) => is_pcr(handle) || (null && handle == TPM_RH_NULL),
            HandleKind::Hierarchy => hierarchy,
            HandleKind::HierarchyOrNull => hierarchy || handle == TPM_RH_NULL,
            HandleKind::Provision => matches!(handle, TPM_RH_OWNER | TPM_RH_PLATFORM),
            HandleKind::HierarchyAuth | HandleKind::HierarchyPolicy => {
                hierarchy || handle == TPM_RH_LOCKOUT
            }
            HandleKind::Platform => handle == TPM_RH_PLATFORM,
            HandleKind::Lockout => handle == TPM_RH_LOCKOUT,
            HandleKind::Clear => matches!(handle, TPM_RH_LOCKOUT | TPM_RH_PLATFORM),
            HandleKind::Object(null) => {
                TRANSIENT.contains(&handle)
                    || handle_type(handle) == TPM_HT_PERSISTENT
                    || (null && handle == TPM_RH_NULL)
            }
            HandleKind::Entity(null) => {
                hierarchy
                    || handle == TPM_RH_LOCKOUT
                    || TRANSIENT.contains(&handle)
                    || matches!(handle_type(handle), TPM_HT_PERSISTENT | TPM_HT_NV_INDEX)
                    || is_pcr(handle)
                    || VENDOR_AUTH.contains(&handle)
                    || (null && handle == TPM_RH_NULL)
            }
        };
        if ok { Ok(()) } else { Err(Rc::VALUE) }
    }
}

/// The handles of the object slots (TRANSIENT_FIRST..=TRANSIENT_LAST).
const TRANSIENT: std::ops::RangeInclusive<u32> =
    TRANSIENT_FIRST..=TRANSIENT_FIRST + (MAX_OBJECTS as u32 - 1);
const HMAC_SESSIONS: std::ops::RangeInclusive<u32> = 0x0200_0000..=0x0200_003f;
const POLICY_SESSIONS: std::ops::RangeInclusive<u32> = 0x0300_0000..=0x0300_003f;

/// An HMAC or policy session handle, whether or not one is loaded.
pub fn is_session(handle: u32) -> bool {
    HMAC_SESSIONS.contains(&handle) || POLICY_SESSIONS.contains(&handle)
}

pub fn is_pcr(handle: u32) -> bool {
    usize::try_from(handle).is_ok_and(|h| h < pcr::PCR_COUNT)
}

impl Tpm {
    /// EntityGetLoadStatus: every handle names something the TPM has, in an enabled hierarchy.
    /// A persistent object is copied into a free slot for the command, and its handle replaced
    /// with the slot's (ObjectLoadEvict).
    pub fn check_loaded(&mut self, code: u32, handles: &mut [u32]) -> Result<()> {
        for (n, handle) in (1usize..).zip(handles.iter_mut()) {
            let n32 = u32::try_from(n).unwrap_or(0);
            let status = match handle_type(*handle) {
                TPM_HT_PERMANENT => match *handle {
                    TPM_RS_PW | TPM_RH_LOCKOUT => Ok(()),
                    h if VENDOR_AUTH.contains(&h) => Err(Rc::VALUE),
                    h => self.hierarchy_enabled(h),
                },
                TPM_HT_TRANSIENT if self.object(*handle).is_none() => {
                    return Err(Rc::REFERENCE_H0.nth(n.saturating_sub(1)));
                }
                TPM_HT_PERSISTENT => self.load_evict(*handle, code).map(|slot| *handle = slot),
                // No NV index exists yet.
                TPM_HT_NV_INDEX => Err(Rc::HANDLE),
                TPM_HT_HMAC_SESSION | TPM_HT_POLICY_SESSION => match self.session(*handle) {
                    None => return Err(Rc::REFERENCE_H0.nth(n.saturating_sub(1))),
                    Some(_) if self.loaded_session(*handle).is_none() => Err(Rc::HANDLE),
                    Some(_) => Ok(()),
                },
                // A PCR handle that passed its kind check names a PCR.
                _ => Ok(()),
            };
            status.map_err(|rc| rc.handle(n32))?;
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

    /// The entity's Name: an object's own (a sequence has none); for a hierarchy or a PCR, its
    /// handle.
    pub fn entity_name(&self, handle: u32) -> Vec<u8> {
        if handle_type(handle) == TPM_HT_TRANSIENT {
            return self.key(handle).map_or_else(Vec::new, |k| k.name.clone());
        }
        handle.to_be_bytes().to_vec()
    }

    /// The entity's authValue, trailing zeros removed (they never count).
    pub fn entity_auth(&self, handle: u32) -> Zeroizing<Vec<u8>> {
        let h = &self.permanent.hierarchies;
        let auth: &[u8] = match handle {
            TPM_RH_OWNER => &h.owner_auth,
            TPM_RH_ENDORSEMENT => &h.endorsement_auth,
            TPM_RH_LOCKOUT => &h.lockout_auth,
            TPM_RH_PLATFORM => &self.volatile.clear.platform_auth,
            h => match self.object(h) {
                Some(object) => object.auth(),
                // TPM_RH_NULL and the PCRs: the empty authValue.
                None => &[],
            },
        };
        Zeroizing::new(strip_zeros(auth).to_vec())
    }

    /// The entity's authPolicy, if it has one a policy session can satisfy
    /// (IsAuthPolicyAvailable): a hierarchy's if set, any key's (with its sensitive area).
    pub fn entity_policy(&self, handle: u32) -> Option<Policy> {
        let h = &self.permanent.hierarchies;
        let policy = match handle {
            TPM_RH_OWNER => &h.owner_policy,
            TPM_RH_ENDORSEMENT => &h.endorsement_policy,
            TPM_RH_LOCKOUT => &h.lockout_policy,
            TPM_RH_PLATFORM => &self.volatile.clear.platform_policy,
            h if handle_type(h) == TPM_HT_TRANSIENT => {
                let key = self.key(h).filter(|k| !k.public_only())?;
                return Some(Policy {
                    hash: key.public.name_alg,
                    digest: key.public.auth_policy.clone(),
                });
            }
            // No PCR belongs to a policy group.
            _ => return None,
        };
        policy.hash.is_some().then(|| policy.clone())
    }

    /// IsAuthValueAvailable: whether a password or HMAC session may authorize the entity,
    /// `admin` for the ADMIN role. A key's authValue serves the USER role if userWithAuth is
    /// set, the ADMIN role unless adminWithPolicy is; a public key alone has none.
    pub fn auth_value_available(&self, handle: u32, admin: bool) -> bool {
        match self.key(handle) {
            Some(key) => {
                let has = |a| key.public.has(a);
                !key.public_only()
                    && (has(attr::USER_WITH_AUTH) || (admin && !has(attr::ADMIN_WITH_POLICY)))
            }
            None => true,
        }
    }

    /// IsPolicySessionRequired: the ADMIN role of a key with adminWithPolicy, or of anything
    /// that is not an object, takes a policy session.
    pub fn policy_required(&self, handle: u32, admin: bool) -> bool {
        admin
            && (handle_type(handle) != TPM_HT_TRANSIENT
                || self
                    .key(handle)
                    .is_some_and(|k| k.public.has(attr::ADMIN_WITH_POLICY)))
    }

    /// IsDAExempted: an authorization failure on the entity does not count against the
    /// dictionary-attack protection. Every permanent handle but lockout (which has its own),
    /// every PCR, every sequence and every key with noDA is.
    pub fn is_da_exempt(&self, handle: u32) -> bool {
        match handle_type(handle) {
            TPM_HT_PERMANENT => handle != TPM_RH_LOCKOUT,
            TPM_HT_PCR => true,
            TPM_HT_TRANSIENT => self.key(handle).is_none_or(|k| k.public.has(attr::NO_DA)),
            _ => false,
        }
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
