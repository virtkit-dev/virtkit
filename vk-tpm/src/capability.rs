//! TPM2_GetCapability: what the TPM is, implements and holds.
//!
//! Each capability is a list sorted by property; a request asks for at most `count` entries
//! from `property` on, and the answer says whether more follow. Values describing the TPM's
//! shape (buffer sizes, slot counts, the PC Client profile) are libtpms', so a guest sees the
//! TPM it knew; what identifies the implementation (manufacturer, vendor, firmware) is ours.

use crate::alg::{self, Hash};
use crate::commands::{COMMANDS, end};
use crate::entity::{
    TPM_HT_HMAC_SESSION, TPM_HT_NV_INDEX, TPM_HT_PCR, TPM_HT_PERMANENT, TPM_HT_PERSISTENT,
    TPM_HT_POLICY_SESSION, TPM_HT_TRANSIENT, TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL,
    TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_PLATFORM_NV, TPM_RS_PW, handle_type,
};
use crate::marshal::{Reader, Writer};
use crate::object::MAX_OBJECTS;
use crate::pcr::{self, PCR_COUNT};
use crate::rc::{Rc, Result};
use crate::session::{MAX_ACTIVE, MAX_LOADED};
use crate::{MAX_COMMAND_SIZE, Out, Tpm};

const TPM_CAP_ALGS: u32 = 0;
const TPM_CAP_HANDLES: u32 = 1;
const TPM_CAP_COMMANDS: u32 = 2;
const TPM_CAP_PP_COMMANDS: u32 = 3;
const TPM_CAP_AUDIT_COMMANDS: u32 = 4;
const TPM_CAP_PCRS: u32 = 5;
const TPM_CAP_TPM_PROPERTIES: u32 = 6;
const TPM_CAP_PCR_PROPERTIES: u32 = 7;
const TPM_CAP_ECC_CURVES: u32 = 8;

/// The capability data must fit MAX_CAP_BUFFER (1024) with its TPM_CAP and count: these are
/// the entries that fit, per kind (MAX_CAP_ALGS, MAX_CAP_HANDLES, ...).
const MAX_CAP_BUFFER: u32 = 1024;
const MAX_CAP_DATA: usize = MAX_CAP_BUFFER as usize - 8;
const MAX_CAP_ALGS: usize = MAX_CAP_DATA / 6;
const MAX_CAP_HANDLES: usize = MAX_CAP_DATA / 4;
const MAX_CAP_CC: usize = MAX_CAP_DATA / 4;
const MAX_TPM_PROPERTIES: usize = MAX_CAP_DATA / 8;
const MAX_PCR_PROPERTIES: usize = MAX_CAP_DATA / 8;

/// The permanent handles (hierarchies, TPM_RS_PW, ...), in order.
const PERMANENT_HANDLES: [u32; 7] = [
    TPM_RH_OWNER,
    TPM_RH_NULL,
    TPM_RS_PW,
    TPM_RH_LOCKOUT,
    TPM_RH_ENDORSEMENT,
    TPM_RH_PLATFORM,
    TPM_RH_PLATFORM_NV,
];

const PT_FIXED: u32 = 0x100;
const PT_VAR: u32 = 0x200;
const PT_GROUP: u32 = 0x100;

/// Up to `count` of `entries` (sorted by key) from key `from` on, and whether more follow.
fn page<T: Copy>(entries: &[(u32, T)], from: u32, count: usize) -> (Vec<(u32, T)>, bool) {
    let mut rest = entries.iter().filter(|(key, _)| *key >= from).copied();
    let page = rest.by_ref().take(count).collect();
    (page, rest.next().is_some())
}

pub fn get_capability(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let capability = r.u32().map_err(|rc| rc.param(1))?;
    let property = r.u32().map_err(|rc| rc.param(2))?;
    let count = usize::try_from(r.u32().map_err(|rc| rc.param(3))?).unwrap_or(usize::MAX);
    end(r)?;

    let mut data = Writer::new();
    let more = match capability {
        TPM_CAP_ALGS => {
            // The property is a TPM_ALG_ID: only its low 16 bits count.
            let from = property & 0xffff;
            let algs: Vec<_> = (alg::IMPLEMENTED.iter())
                .map(|&(alg, attributes)| (u32::from(alg), attributes))
                .collect();
            let (algs, more) = page(&algs, from, count.min(MAX_CAP_ALGS));
            data.count(algs.len());
            for (alg, attributes) in algs {
                data.u16(u16::try_from(alg).unwrap_or(0)).u32(attributes);
            }
            more
        }
        TPM_CAP_HANDLES => {
            // The handles listed, and the one to list from.
            let (handles, from): (Vec<u32>, u32) = match handle_type(property) {
                TPM_HT_PCR => {
                    let pcrs = (0..PCR_COUNT).filter_map(|p| u32::try_from(p).ok());
                    (pcrs.collect(), property)
                }
                TPM_HT_PERMANENT => (PERMANENT_HANDLES.to_vec(), property),
                TPM_HT_TRANSIENT => (tpm.loaded_objects(), property),
                // TPM_HT_LOADED_SESSION: the loaded sessions from that index on, whatever their
                // type (so a policy session's handle may sort before the one asked for).
                TPM_HT_HMAC_SESSION => (tpm.loaded_sessions(property), 0),
                // No NV index, saved session (TPM_HT_SAVED_SESSION) or persistent object yet.
                TPM_HT_NV_INDEX | TPM_HT_POLICY_SESSION | TPM_HT_PERSISTENT => (Vec::new(), 0),
                _ => return Err(Rc::HANDLE.param(2)),
            };
            let keyed: Vec<_> = handles.iter().map(|&h| (h, ())).collect();
            let (handles, more) = page(&keyed, from, count.min(MAX_CAP_HANDLES));
            data.count(handles.len());
            for (h, ()) in handles {
                data.u32(h);
            }
            more
        }
        TPM_CAP_COMMANDS => {
            let ccs: Vec<_> = COMMANDS.iter().map(|c| (c.code, c.attributes())).collect();
            let (ccs, more) = page(&ccs, property, count.min(MAX_CAP_CC));
            data.count(ccs.len());
            for (_, attributes) in ccs {
                data.u32(attributes);
            }
            more
        }
        // No command needs physical presence, and none is audited.
        TPM_CAP_PP_COMMANDS | TPM_CAP_AUDIT_COMMANDS => {
            data.count(0);
            false
        }
        TPM_CAP_PCRS => {
            if property != 0 {
                return Err(Rc::VALUE.param(2));
            }
            // As the reference implementation: no room asked for, "more" answered.
            if count == 0 {
                data.count(0);
                true
            } else {
                pcr::write_selections(&mut data, &tpm.volatile.allocation);
                false
            }
        }
        TPM_CAP_TPM_PROPERTIES => {
            let (props, more) = tpm_properties(tpm, property, count.min(MAX_TPM_PROPERTIES));
            data.count(props.len());
            for (p, v) in props {
                data.u32(p).u32(v);
            }
            more
        }
        TPM_CAP_PCR_PROPERTIES => {
            let props = pcr::properties();
            let (props, more) = page(&props, property, count.min(MAX_PCR_PROPERTIES));
            data.count(props.len());
            // TPMS_TAGGED_PCR_SELECT: the property, then a bitmap of the PCRs that have it.
            for (tag, pcrs) in props {
                data.u32(tag).u8(pcr::PCR_SELECT as u8).bytes(&pcrs);
            }
            more
        }
        TPM_CAP_ECC_CURVES => {
            // No ECC yet.
            data.count(0);
            false
        }
        _ => return Err(Rc::VALUE.param(1)),
    };
    w.u8(more.into()).u32(capability).bytes(&data.into_bytes());
    Ok(())
}

/// TPM_CAP_TPM_PROPERTIES: from `property` to the end of its group (fixed or variable) only.
fn tpm_properties(tpm: &Tpm, property: u32, count: usize) -> (Vec<(u32, u32)>, bool) {
    let from = property.max(PT_FIXED);
    if from >= PT_VAR.saturating_add(PT_GROUP) {
        return (Vec::new(), false);
    }
    let group_end = (from / PT_GROUP).saturating_add(1).saturating_mul(PT_GROUP);
    let all = properties(tpm);
    let in_group: Vec<_> = all.into_iter().filter(|(p, _)| *p < group_end).collect();
    page(&in_group, from, count)
}

/// A TPMA_ bitfield: the bits that are set.
fn flags(bits: &[(u32, bool)]) -> u32 {
    bits.iter()
        .filter(|(_, set)| *set)
        .fold(0, |acc, (bit, _)| acc | (1 << bit))
}

/// Four ASCII characters as a UINT32, as TPM_PT_MANUFACTURER and the vendor strings are.
const fn chars(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

/// Every TPM_PT, in order.
fn properties(tpm: &Tpm) -> Vec<(u32, u32)> {
    let da = &tpm.permanent.dictionary_attack;
    let h = &tpm.permanent.hierarchies;
    // TPMA_PERMANENT: which authValues are set, disableClear, inLockout, and that the EPS is
    // the TPM's own.
    let permanent = flags(&[
        (0, !h.owner_auth.is_empty()),
        (1, !h.endorsement_auth.is_empty()),
        (2, !h.lockout_auth.is_empty()),
        (8, h.disable_clear),
        (9, da.in_lockout()),
        (10, true),
    ]);
    // TPMA_STARTUP_CLEAR: the enables, and whether the last shutdown was orderly.
    let clear = &tpm.volatile.clear;
    let startup_clear = flags(&[
        (0, tpm.volatile.ph_enable),
        (1, clear.sh_enable),
        (2, clear.eh_enable),
        (3, clear.ph_enable_nv),
        (31, tpm.volatile.orderly_startup),
    ]);
    let commands = u32::try_from(COMMANDS.len()).unwrap_or(0);
    let loaded = tpm.loaded_objects().len();
    let transient_avail = u32::try_from(MAX_OBJECTS.saturating_sub(loaded)).unwrap_or(0);
    let sessions = u32::try_from(tpm.session_count()).unwrap_or(0);
    let loaded_avail = (MAX_LOADED as u32).saturating_sub(sessions);
    let active_avail = (MAX_ACTIVE as u32).saturating_sub(sessions);
    let max_command = u32::try_from(MAX_COMMAND_SIZE).unwrap_or(0);
    vec![
        (0x100, chars(b"2.0\0")), // TPM_PT_FAMILY_INDICATOR
        (0x101, 0),               // TPM_PT_LEVEL
        (0x102, 183),             // TPM_PT_REVISION: 1.83
        (0x103, 25),              // TPM_PT_DAY_OF_YEAR
        (0x104, 2024),            // TPM_PT_YEAR
        (0x105, chars(b"VKIT")),  // TPM_PT_MANUFACTURER
        (0x106, chars(b"virt")),  // TPM_PT_VENDOR_STRING_1..4
        (0x107, chars(b"kit\0")),
        (0x108, 0),
        (0x109, 0),
        (0x10a, 1), // TPM_PT_VENDOR_TPM_TYPE
        (0x10b, 1), // TPM_PT_FIRMWARE_VERSION_1..2
        (0x10c, 0),
        (0x10d, 1024),                         // TPM_PT_INPUT_BUFFER
        (0x10e, 3),                            // TPM_PT_HR_TRANSIENT_MIN
        (0x10f, 7),                            // TPM_PT_HR_PERSISTENT_MIN
        (0x110, 3),                            // TPM_PT_HR_LOADED_MIN
        (0x111, 64),                           // TPM_PT_ACTIVE_SESSIONS_MAX
        (0x112, PCR_COUNT as u32),             // TPM_PT_PCR_COUNT
        (0x113, pcr::PCR_SELECT as u32),       // TPM_PT_PCR_SELECT_MIN
        (0x114, 0xffff),                       // TPM_PT_CONTEXT_GAP_MAX
        (0x116, 0),                            // TPM_PT_NV_COUNTERS_MAX
        (0x117, 2048),                         // TPM_PT_NV_INDEX_MAX
        (0x118, 6),                            // TPM_PT_MEMORY
        (0x119, 1 << 12),                      // TPM_PT_CLOCK_UPDATE
        (0x11a, u32::from(Hash::Sha512.id())), // TPM_PT_CONTEXT_HASH
        (0x11b, 0x0006),                       // TPM_PT_CONTEXT_SYM: AES
        (0x11c, 256),                          // TPM_PT_CONTEXT_SYM_SIZE
        (0x11d, 255),                          // TPM_PT_ORDERLY_COUNT
        (0x11e, max_command),                  // TPM_PT_MAX_COMMAND_SIZE
        (0x11f, max_command),                  // TPM_PT_MAX_RESPONSE_SIZE
        (0x120, alg::MAX_DIGEST as u32),       // TPM_PT_MAX_DIGEST
        (0x121, 0xd4c),                        // TPM_PT_MAX_OBJECT_CONTEXT
        (0x122, 0x194),                        // TPM_PT_MAX_SESSION_CONTEXT
        (0x123, 1),                            // TPM_PT_PS_FAMILY_INDICATOR: PC Client
        (0x124, 0),                            // TPM_PT_PS_LEVEL
        (0x125, 0x106),                        // TPM_PT_PS_REVISION
        (0x126, 25),                           // TPM_PT_PS_DAY_OF_YEAR
        (0x127, 2024),                         // TPM_PT_PS_YEAR
        (0x128, 0),                            // TPM_PT_SPLIT_MAX: no TPM2_Commit
        (0x129, commands),                     // TPM_PT_TOTAL_COMMANDS
        (0x12a, commands),                     // TPM_PT_LIBRARY_COMMANDS
        (0x12b, 0),                            // TPM_PT_VENDOR_COMMANDS
        (0x12c, 1024),                         // TPM_PT_NV_BUFFER_MAX
        (0x12d, 0),                            // TPM_PT_MODES
        (0x12e, MAX_CAP_BUFFER),               // TPM_PT_MAX_CAP_BUFFER
        (0x12f, 0),                            // TPM_PT_FIRMWARE_SVN
        (0x130, 0),                            // TPM_PT_FIRMWARE_MAX_SVN
        (0x200, permanent),                    // TPM_PT_PERMANENT
        (0x201, startup_clear),                // TPM_PT_STARTUP_CLEAR
        (0x202, 0),                            // TPM_PT_HR_NV_INDEX
        (0x203, sessions),                     // TPM_PT_HR_LOADED
        (0x204, loaded_avail),                 // TPM_PT_HR_LOADED_AVAIL
        (0x205, sessions),                     // TPM_PT_HR_ACTIVE
        (0x206, active_avail),                 // TPM_PT_HR_ACTIVE_AVAIL
        (0x207, transient_avail),              // TPM_PT_HR_TRANSIENT_AVAIL
        (0x208, 0),                            // TPM_PT_HR_PERSISTENT
        (0x209, 0x33),                         // TPM_PT_HR_PERSISTENT_AVAIL
        (0x20a, 0),                            // TPM_PT_NV_COUNTERS
        (0x20b, 0x19),                         // TPM_PT_NV_COUNTERS_AVAIL
        (0x20c, 0),                            // TPM_PT_ALGORITHM_SET
        (0x20d, 0),                            // TPM_PT_LOADED_CURVES: no ECC yet
        (0x20e, da.failed_tries),              // TPM_PT_LOCKOUT_COUNTER
        (0x20f, da.max_tries),                 // TPM_PT_MAX_AUTH_FAIL
        (0x210, da.recovery_time),             // TPM_PT_LOCKOUT_INTERVAL
        (0x211, da.lockout_recovery),          // TPM_PT_LOCKOUT_RECOVERY
        (0x212, 0),                            // TPM_PT_NV_WRITE_RECOVERY
        (0x213, 0),                            // TPM_PT_AUDIT_COUNTER_0..1
        (0x214, 0),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_say_whether_more_follow() {
        let e = [(1, 'a'), (3, 'b'), (5, 'c')];
        assert_eq!(page(&e, 2, 1), (vec![(3, 'b')], true));
        assert_eq!(page(&e, 2, 2), (vec![(3, 'b'), (5, 'c')], false));
        assert_eq!(page(&e, 6, 9), (vec![], false));
    }

    #[test]
    fn properties_are_sorted_and_grouped() {
        let tpm = Tpm::manufacture().unwrap();
        let all = properties(&tpm);
        assert!(all.windows(2).all(|w| w[0].0 < w[1].0));
        let (fixed, more) = tpm_properties(&tpm, 0, 1000);
        assert!(!more);
        assert!(fixed.iter().all(|(p, _)| (0x100..0x200).contains(p)));
        let (var, _) = tpm_properties(&tpm, 0x200, 2);
        assert_eq!(var.len(), 2);
        assert!(tpm_properties(&tpm, 0x300, 9).0.is_empty());
    }
}
