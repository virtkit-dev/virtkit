//! The commands the TPM implements (Part 3), and what TPM_CAP_COMMANDS says of each. A command
//! not in [`COMMANDS`] gets TPM_RC_COMMAND_CODE, and is not listed, so a client does not try it.
//!
//! Each command parses all of its parameters (numbering a parse error after the parameter),
//! checks none are left over ([`end`]), and only then acts: a refused command changes nothing.

use crate::alg::{Hash, MAX_DIGEST};
use crate::entity::{HandleKind, TPM_RH_NULL};
use crate::marshal::Reader;
use crate::pcr::{self, Startup};
use crate::rc::{Rc, Result};
use crate::state::{Saved, Shutdown};
use crate::{LOCALITY, Out, Tpm, capability, hierarchy};

pub const TPM_CC_HIERARCHY_CONTROL: u32 = 0x121;
pub const TPM_CC_CHANGE_EPS: u32 = 0x124;
pub const TPM_CC_CHANGE_PPS: u32 = 0x125;
pub const TPM_CC_CLEAR: u32 = 0x126;
pub const TPM_CC_CLEAR_CONTROL: u32 = 0x127;
pub const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x129;
pub const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x12e;
pub const TPM_CC_DICTIONARY_ATTACK_LOCK_RESET: u32 = 0x139;
pub const TPM_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x13a;
pub const TPM_CC_SELF_TEST: u32 = 0x143;
pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_CC_SHUTDOWN: u32 = 0x145;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x17a;
pub const TPM_CC_GET_RANDOM: u32 = 0x17b;
pub const TPM_CC_PCR_READ: u32 = 0x17e;
pub const TPM_CC_PCR_EXTEND: u32 = 0x182;

type Run = fn(&mut Tpm, &[u32], &mut Reader, &mut Out) -> Result<()>;

pub struct Command {
    pub code: u32,
    /// The handle area, in order.
    pub handles: &'static [HandleKind],
    /// How many of those handles (the first ones) need an authorization session (USER role).
    pub auth: usize,
    /// It takes an authorization area (not TPM2_Startup).
    pub sessions: bool,
    /// TPMA_CC.nv: it may write the TPM's NV memory.
    nv: bool,
    /// TPMA_CC.extensive: it may flush many objects.
    extensive: bool,
    pub run: Run,
}

impl Command {
    const fn new(code: u32, run: Run) -> Command {
        Command {
            code,
            handles: &[],
            auth: 0,
            sessions: true,
            nv: false,
            extensive: false,
            run,
        }
    }

    /// Its handle area; the first `auth` handles need an authorization.
    const fn handles(self, handles: &'static [HandleKind], auth: usize) -> Command {
        Command {
            handles,
            auth,
            ..self
        }
    }

    const fn nv(self) -> Command {
        Command { nv: true, ..self }
    }

    const fn extensive(self) -> Command {
        Command {
            extensive: true,
            ..self
        }
    }

    const fn no_sessions(self) -> Command {
        Command {
            sessions: false,
            ..self
        }
    }

    /// Its TPMA_CC, for TPM_CAP_COMMANDS.
    pub fn attributes(&self) -> u32 {
        let handles = u32::try_from(self.handles.len()).unwrap_or(0) & 0x7;
        (self.code & 0xffff)
            | (u32::from(self.nv) << 22)
            | (u32::from(self.extensive) << 23)
            | (handles << 25)
    }
}

use HandleKind as H;

/// Every implemented command, by code.
pub const COMMANDS: &[Command] = &[
    Command::new(TPM_CC_HIERARCHY_CONTROL, hierarchy::hierarchy_control)
        .handles(&[H::Hierarchy], 1)
        .nv()
        .extensive(),
    Command::new(TPM_CC_CHANGE_EPS, hierarchy::change_eps)
        .handles(&[H::Platform], 1)
        .nv()
        .extensive(),
    Command::new(TPM_CC_CHANGE_PPS, hierarchy::change_pps)
        .handles(&[H::Platform], 1)
        .nv()
        .extensive(),
    Command::new(TPM_CC_CLEAR, hierarchy::clear)
        .handles(&[H::Clear], 1)
        .nv()
        .extensive(),
    Command::new(TPM_CC_CLEAR_CONTROL, hierarchy::clear_control)
        .handles(&[H::Clear], 1)
        .nv(),
    Command::new(
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        hierarchy::hierarchy_change_auth,
    )
    .handles(&[H::HierarchyAuth], 1)
    .nv(),
    Command::new(TPM_CC_SET_PRIMARY_POLICY, hierarchy::set_primary_policy)
        .handles(&[H::HierarchyPolicy], 1)
        .nv(),
    Command::new(
        TPM_CC_DICTIONARY_ATTACK_LOCK_RESET,
        hierarchy::dictionary_attack_lock_reset,
    )
    .handles(&[H::Lockout], 1)
    .nv(),
    Command::new(
        TPM_CC_DICTIONARY_ATTACK_PARAMETERS,
        hierarchy::dictionary_attack_parameters,
    )
    .handles(&[H::Lockout], 1)
    .nv(),
    Command::new(TPM_CC_SELF_TEST, self_test).nv(),
    Command::new(TPM_CC_STARTUP, startup).nv().no_sessions(),
    Command::new(TPM_CC_SHUTDOWN, shutdown).nv(),
    Command::new(TPM_CC_GET_CAPABILITY, capability::get_capability),
    Command::new(TPM_CC_GET_RANDOM, get_random),
    Command::new(TPM_CC_PCR_READ, pcr_read),
    Command::new(TPM_CC_PCR_EXTEND, pcr_extend)
        .handles(&[H::Pcr(true)], 1)
        .nv(),
];

pub fn find(code: u32) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.code == code)
}

/// No parameter bytes may be left once a command has read its own.
pub fn end(r: &Reader) -> Result<()> {
    if r.is_empty() { Ok(()) } else { Err(Rc::SIZE) }
}

/// A TPMI_YES_NO.
pub fn read_yes_no(r: &mut Reader) -> Result<bool> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Rc::VALUE),
    }
}

const TPM_SU_CLEAR: u16 = 0;
const TPM_SU_STATE: u16 = 1;

/// A TPM_SU: CLEAR (false) or STATE (true).
fn read_su(r: &mut Reader) -> Result<bool> {
    match r.u16()? {
        TPM_SU_CLEAR => Ok(false),
        TPM_SU_STATE => Ok(true),
        _ => Err(Rc::VALUE),
    }
}

/// TPM2_Startup: a TPM Reset, Restart or Resume, according to the last shutdown.
fn startup(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let state = read_su(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let previous = &tpm.permanent.shutdown;
    let da_used = *previous == Shutdown::DaUsed;
    let orderly = previous.is_orderly();
    let saved = match previous {
        Shutdown::State(saved) => Some(saved.clone()),
        _ => None,
    };
    let kind = match (state, &saved) {
        (true, None) => return Err(Rc::VALUE.param(1)),
        (true, Some(_)) => Startup::Resume,
        (false, Some(_)) => Startup::Restart,
        (false, None) => Startup::Reset,
    };
    tpm.update_time();
    let time_reset = std::mem::take(&mut tpm.volatile.time_reset);
    tpm.da_startup(orderly, time_reset, da_used);
    // Every startup enables the platform hierarchy; all but a resume reset the rest of what
    // TPM2_Clear does not keep.
    tpm.volatile.ph_enable = true;
    tpm.volatile.clear = match (&saved, kind) {
        (Some(Saved { clear, .. }), Startup::Resume) => clear.clone(),
        _ => Default::default(),
    };
    let saved_pcrs = saved.as_ref().map(|s| &s.pcrs);
    tpm.volatile.pcrs.startup(kind, saved_pcrs);
    tpm.volatile.orderly_startup = orderly;
    tpm.volatile.da_used = false;
    tpm.volatile.started = true;
    // Until the next orderly shutdown, losing power is not orderly.
    tpm.permanent.shutdown = Shutdown::None;
    Ok(())
}

/// TPM2_Shutdown: record an orderly shutdown; STATE also saves what a resume brings back.
fn shutdown(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    let state = read_su(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    tpm.volatile.da_used = false;
    tpm.permanent.shutdown_time = tpm.volatile.time;
    tpm.permanent.shutdown = if state {
        Shutdown::State(Saved {
            pcrs: tpm.volatile.pcrs.save(),
            clear: tpm.volatile.clear.clone(),
        })
    } else {
        Shutdown::Clear
    };
    Ok(())
}

/// TPM2_SelfTest: the algorithms are RustCrypto's, tested where they are built; nothing is left
/// to test at run time, and every test has passed.
fn self_test(_: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    read_yes_no(r).map_err(|rc| rc.param(1))?;
    end(r)
}

/// TPM2_GetRandom: at most a digest's worth of bytes per call (as the specification allows).
fn get_random(_: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let wanted = usize::from(r.u16().map_err(|rc| rc.param(1))?);
    end(r)?;
    let mut bytes = vec![0; wanted.min(MAX_DIGEST)];
    getrandom::fill(&mut bytes).map_err(|_| Rc::FAILURE)?;
    w.tpm2b(&bytes);
    Ok(())
}

/// TPM2_PCR_Read.
fn pcr_read(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let selections = pcr::read_selections(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let pcrs = &tpm.volatile.pcrs;
    let (selected, digests) = pcrs.read(&tpm.permanent.allocation, &selections);
    w.u32(pcrs.counter);
    pcr::write_selections(w, &selected);
    w.count(digests.len());
    for d in &digests {
        w.tpm2b(d);
    }
    Ok(())
}

/// TPM2_PCR_Extend: each digest into its bank's PCR (a bank not allocated is skipped).
fn pcr_extend(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    // TPML_DIGEST_VALUES: TPMT_HAs, each a hash algorithm and a digest of its size.
    let digests = (|| {
        let count = r.count(Hash::ALL.len())?;
        (0..count)
            .map(|_| {
                let hash = Hash::read(r)?;
                Ok((hash, r.bytes(hash.size())?))
            })
            .collect::<Result<Vec<_>>>()
    })()
    .map_err(|rc| rc.param(1))?;
    end(r)?;
    let handle = handles.first().copied().ok_or(Rc::FAILURE)?;
    if handle == TPM_RH_NULL {
        return Ok(());
    }
    let pcr = usize::try_from(handle).map_err(|_| Rc::FAILURE)?;
    if !pcr::may_extend(pcr, LOCALITY) {
        return Err(Rc::LOCALITY);
    }
    // A change to a PCR that TPM2_Shutdown(STATE) saved voids that saved state.
    if pcr::is_state_saved(pcr) {
        tpm.clear_orderly();
    }
    for (hash, digest) in digests {
        let allocation = &tpm.permanent.allocation;
        tpm.volatile.pcrs.extend(allocation, pcr, hash, digest);
    }
    Ok(())
}
