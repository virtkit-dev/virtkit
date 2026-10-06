//! The commands the TPM implements (Part 3), and what TPM_CAP_COMMANDS says of each. A command
//! not in [`COMMANDS`] gets TPM_RC_COMMAND_CODE, and is not listed, so a client does not try it.
//!
//! Each command parses all of its parameters (numbering a parse error after the parameter),
//! checks none are left over ([`end`]), and only then acts: a refused command changes nothing.

use crate::alg::{Hash, MAX_DIGEST};
use crate::entity::{HandleKind, TPM_RH_NULL};
use crate::marshal::{Reader, Writer};
use crate::pcr::{self, Startup};
use crate::rc::{Rc, Result};
use crate::state::{Saved, Shutdown};
use crate::{LOCALITY, Out, Tpm, capability, hierarchy, object, session};

pub const TPM_CC_HIERARCHY_CONTROL: u32 = 0x121;
pub const TPM_CC_CHANGE_EPS: u32 = 0x124;
pub const TPM_CC_CHANGE_PPS: u32 = 0x125;
pub const TPM_CC_CLEAR: u32 = 0x126;
pub const TPM_CC_CLEAR_CONTROL: u32 = 0x127;
pub const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x129;
pub const TPM_CC_PCR_ALLOCATE: u32 = 0x12b;
pub const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x12e;
pub const TPM_CC_DICTIONARY_ATTACK_LOCK_RESET: u32 = 0x139;
pub const TPM_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x13a;
pub const TPM_CC_PCR_EVENT: u32 = 0x13c;
pub const TPM_CC_SEQUENCE_COMPLETE: u32 = 0x13e;
pub const TPM_CC_PCR_RESET: u32 = 0x13d;
pub const TPM_CC_SELF_TEST: u32 = 0x143;
pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_CC_SHUTDOWN: u32 = 0x145;
pub const TPM_CC_SEQUENCE_UPDATE: u32 = 0x15c;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x165;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x176;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x17a;
pub const TPM_CC_GET_RANDOM: u32 = 0x17b;
pub const TPM_CC_HASH: u32 = 0x17d;
pub const TPM_CC_PCR_READ: u32 = 0x17e;
pub const TPM_CC_PCR_EXTEND: u32 = 0x182;
pub const TPM_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x185;
pub const TPM_CC_HASH_SEQUENCE_START: u32 = 0x186;

type Run = fn(&mut Tpm, &[u32], &mut Reader, &mut Out) -> Result<()>;

pub struct Command {
    pub code: u32,
    /// The handle area, in order.
    pub handles: &'static [HandleKind],
    /// How many of those handles (the first ones) need an authorization session (USER role).
    pub auth: usize,
    /// It takes an authorization area (not TPM2_Startup).
    pub sessions: bool,
    /// A session may encrypt its first parameter, a TPM2B (DECRYPT_2).
    pub decrypt: bool,
    /// A session may encrypt the response's first parameter, a TPM2B (ENCRYPT_2).
    pub encrypt: bool,
    /// TPMA_CC.nv: it may write the TPM's NV memory.
    nv: bool,
    /// TPMA_CC.extensive: it may flush many objects.
    extensive: bool,
    /// TPMA_CC.flushed: it flushes the object it names.
    flushed: bool,
    /// TPMA_CC.rHandle: it returns a handle.
    response_handle: bool,
    pub run: Run,
}

impl Command {
    const fn new(code: u32, run: Run) -> Command {
        Command {
            code,
            handles: &[],
            auth: 0,
            sessions: true,
            decrypt: false,
            encrypt: false,
            nv: false,
            extensive: false,
            flushed: false,
            response_handle: false,
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

    const fn decrypt(self) -> Command {
        Command {
            decrypt: true,
            ..self
        }
    }

    const fn encrypt(self) -> Command {
        Command {
            encrypt: true,
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

    const fn flushed(self) -> Command {
        Command {
            flushed: true,
            ..self
        }
    }

    const fn response_handle(self) -> Command {
        Command {
            response_handle: true,
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
            | (u32::from(self.flushed) << 24)
            | (handles << 25)
            | (u32::from(self.response_handle) << 28)
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
    .nv()
    .decrypt(),
    Command::new(TPM_CC_PCR_ALLOCATE, pcr_allocate)
        .handles(&[H::Platform], 1)
        .nv(),
    Command::new(TPM_CC_SET_PRIMARY_POLICY, hierarchy::set_primary_policy)
        .handles(&[H::HierarchyPolicy], 1)
        .nv()
        .decrypt(),
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
    Command::new(TPM_CC_PCR_EVENT, pcr_event)
        .handles(&[H::Pcr(true)], 1)
        .nv()
        .decrypt(),
    Command::new(TPM_CC_PCR_RESET, pcr_reset)
        .handles(&[H::Pcr(false)], 1)
        .nv(),
    Command::new(TPM_CC_SEQUENCE_COMPLETE, object::sequence_complete)
        .handles(&[H::Object(false)], 1)
        .flushed()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_SELF_TEST, self_test).nv(),
    Command::new(TPM_CC_STARTUP, startup).nv().no_sessions(),
    Command::new(TPM_CC_SHUTDOWN, shutdown).nv(),
    Command::new(TPM_CC_SEQUENCE_UPDATE, object::sequence_update)
        .handles(&[H::Object(false)], 1)
        .decrypt(),
    Command::new(TPM_CC_FLUSH_CONTEXT, object::flush_context).no_sessions(),
    Command::new(TPM_CC_START_AUTH_SESSION, session::start_auth_session)
        .handles(&[H::Object(true), H::Entity(true)], 0)
        .response_handle()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_GET_CAPABILITY, capability::get_capability),
    Command::new(TPM_CC_GET_RANDOM, get_random).encrypt(),
    Command::new(TPM_CC_HASH, object::hash).decrypt().encrypt(),
    Command::new(TPM_CC_PCR_READ, pcr_read),
    Command::new(TPM_CC_PCR_EXTEND, pcr_extend)
        .handles(&[H::Pcr(true)], 1)
        .nv(),
    Command::new(
        TPM_CC_EVENT_SEQUENCE_COMPLETE,
        object::event_sequence_complete,
    )
    .handles(&[H::Pcr(true), H::Object(false)], 2)
    .nv()
    .flushed()
    .decrypt(),
    Command::new(TPM_CC_HASH_SEQUENCE_START, object::hash_sequence_start)
        .response_handle()
        .decrypt(),
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

/// The largest event TPM2_PCR_Event takes (TPM2B_EVENT).
const MAX_EVENT: usize = 1024;

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
    let allocation = &tpm.volatile.allocation;
    tpm.volatile.pcrs.startup(allocation, kind, saved_pcrs);
    tpm.volatile.pcr_reconfig = false;
    tpm.volatile.objects.iter_mut().for_each(|o| *o = None);
    tpm.volatile.sessions.iter_mut().for_each(|s| *s = None);
    tpm.volatile.exclusive_audit = None;
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
    if state && tpm.volatile.pcr_reconfig {
        return Err(Rc::TYPE.param(1));
    }
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
    let (selected, digests) = pcrs.read(&tpm.volatile.allocation, &selections);
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
                Ok((hash, r.bytes(hash.size())?.to_vec()))
            })
            .collect::<Result<Vec<_>>>()
    })()
    .map_err(|rc| rc.param(1))?;
    end(r)?;
    let Some(pcr) = tpm.pcr_to_extend(first(handles)?)? else {
        return Ok(());
    };
    tpm.extend(pcr, &digests);
    Ok(())
}

/// TPM2_PCR_Event: digest the event data with every bank's algorithm, and extend each into the
/// PCR (unless it is TPM_RH_NULL). The digests are the response.
fn pcr_event(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let data = r.tpm2b(MAX_EVENT).map_err(|rc| rc.param(1))?;
    end(r)?;
    let pcr = tpm.pcr_to_extend(first(handles)?)?;
    let digests: Vec<_> = (Hash::ALL.into_iter())
        .map(|hash| (hash, hash.digest(&[data])))
        .collect();
    if let Some(pcr) = pcr {
        tpm.extend(pcr, &digests);
    }
    write_digest_values(w, &digests);
    Ok(())
}

/// TPM2_PCR_Reset: a PCR the locality may reset, back to zeros in every bank.
fn pcr_reset(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    end(r)?;
    let pcr = usize::try_from(first(handles)?).map_err(|_| Rc::FAILURE)?;
    if !pcr::may_reset(pcr, LOCALITY) {
        return Err(Rc::LOCALITY);
    }
    if pcr::is_state_saved(pcr) {
        tpm.clear_orderly();
    }
    tpm.volatile.pcrs.reset(&tpm.volatile.allocation, pcr);
    Ok(())
}

/// TPM2_PCR_Allocate: the PCRs each bank will have from the next power on. Until then the TPM
/// goes on with the allocation it has, and TPM2_Shutdown(STATE) is refused.
fn pcr_allocate(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    let requested = pcr::read_selections(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    // From the allocation in use: a second TPM2_PCR_Allocate replaces the first.
    let mut allocation = tpm.volatile.allocation.clone();
    for selection in requested {
        if let Some(bank) = allocation.iter_mut().find(|s| s.hash == selection.hash) {
            *bank = selection;
        }
    }
    // A PC Client TPM keeps PCR 0 (the H-CRTM's) and 17 (the DRTM's) in some bank.
    let kept = |pcr| allocation.iter().any(|s| s.has(pcr));
    if !kept(pcr::HCRTM_PCR) || !kept(pcr::DRTM_PCR) {
        return Err(Rc::PCR);
    }
    let needed: usize = (allocation.iter())
        .map(|s| s.count().saturating_mul(s.hash.size()))
        .sum();
    tpm.permanent.allocation = allocation;
    tpm.volatile.pcr_reconfig = true;
    w.u8(1) // allocationSuccess
        .u32(pcr::PCR_COUNT as u32) // maxPCR
        .u32(u32::try_from(needed).unwrap_or(u32::MAX)) // sizeNeeded
        .u32(pcr::PCR_MEMORY); // sizeAvailable
    Ok(())
}

impl Tpm {
    /// The PCR an extend goes to, None for TPM_RH_NULL, checked against the locality. Extending
    /// a PCR that TPM2_Shutdown(STATE) saved voids that saved state.
    pub fn pcr_to_extend(&mut self, handle: u32) -> Result<Option<usize>> {
        if handle == TPM_RH_NULL {
            return Ok(None);
        }
        let pcr = usize::try_from(handle).map_err(|_| Rc::FAILURE)?;
        if !pcr::may_extend(pcr, LOCALITY) {
            return Err(Rc::LOCALITY);
        }
        if pcr::is_state_saved(pcr) {
            self.clear_orderly();
        }
        Ok(Some(pcr))
    }

    /// Extend each digest into its bank's `pcr`.
    pub fn extend(&mut self, pcr: usize, digests: &[(Hash, Vec<u8>)]) {
        for (hash, digest) in digests {
            let allocation = &self.volatile.allocation;
            self.volatile.pcrs.extend(allocation, pcr, *hash, digest);
        }
    }
}

/// A TPML_DIGEST_VALUES.
pub fn write_digest_values(w: &mut Writer, digests: &[(Hash, Vec<u8>)]) {
    w.count(digests.len());
    for (hash, digest) in digests {
        w.u16(hash.id()).bytes(digest);
    }
}

pub fn first(handles: &[u32]) -> Result<u32> {
    handles.first().copied().ok_or(Rc::FAILURE)
}
