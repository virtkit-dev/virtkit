//! The commands the TPM implements (Part 3), and what TPM_CAP_COMMANDS says of each. A command
//! not in [`COMMANDS`] gets TPM_RC_COMMAND_CODE, and is not listed, so a client does not try it.
//!
//! Each command parses all of its parameters (numbering a parse error after the parameter),
//! checks none are left over ([`end`]), and only then acts: a refused command changes nothing.

use crate::alg::{Hash, MAX_DIGEST};
use crate::marshal::{Reader, Writer};
use crate::pcr::{self, Startup};
use crate::rc::{Rc, Result};
use crate::state::Shutdown;
use crate::{LOCALITY, Tpm, capability};

pub const TPM_CC_SELF_TEST: u32 = 0x143;
pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_CC_SHUTDOWN: u32 = 0x145;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x17a;
pub const TPM_CC_GET_RANDOM: u32 = 0x17b;
pub const TPM_CC_PCR_READ: u32 = 0x17e;
pub const TPM_CC_PCR_EXTEND: u32 = 0x182;

/// What a handle in a command's handle area may be.
#[derive(Clone, Copy)]
pub enum HandleKind {
    /// TPMI_DH_PCR+: a PCR, or TPM_RH_NULL.
    PcrOrNull,
}

impl HandleKind {
    pub fn check(self, handle: u32) -> Result<()> {
        match self {
            HandleKind::PcrOrNull => {
                let is_pcr = usize::try_from(handle).is_ok_and(|h| h < pcr::PCR_COUNT);
                if is_pcr || handle == pcr::TPM_RH_NULL {
                    Ok(())
                } else {
                    Err(Rc::VALUE)
                }
            }
        }
    }
}

type Run = fn(&mut Tpm, &[u32], &mut Reader, &mut Writer) -> Result<()>;

pub struct Command {
    pub code: u32,
    /// The handle area, in order.
    pub handles: &'static [HandleKind],
    /// How many of those handles (the first ones) need an authorization session.
    pub auth: usize,
    /// It may write the TPM's NV memory (TPMA_CC.nv).
    nv: bool,
    /// It takes an authorization area (not TPM2_Startup).
    pub sessions: bool,
    pub run: Run,
}

impl Command {
    /// Its TPMA_CC, for TPM_CAP_COMMANDS.
    pub fn attributes(&self) -> u32 {
        let handles = u32::try_from(self.handles.len()).unwrap_or(0) & 0x7;
        (self.code & 0xffff) | (u32::from(self.nv) << 22) | (handles << 25)
    }
}

/// Every implemented command, by code.
pub const COMMANDS: &[Command] = &[
    Command {
        code: TPM_CC_SELF_TEST,
        handles: &[],
        auth: 0,
        nv: true,
        sessions: true,
        run: self_test,
    },
    Command {
        code: TPM_CC_STARTUP,
        handles: &[],
        auth: 0,
        nv: true,
        sessions: false,
        run: startup,
    },
    Command {
        code: TPM_CC_SHUTDOWN,
        handles: &[],
        auth: 0,
        nv: true,
        sessions: true,
        run: shutdown,
    },
    Command {
        code: TPM_CC_GET_CAPABILITY,
        handles: &[],
        auth: 0,
        nv: false,
        sessions: true,
        run: capability::get_capability,
    },
    Command {
        code: TPM_CC_GET_RANDOM,
        handles: &[],
        auth: 0,
        nv: false,
        sessions: true,
        run: get_random,
    },
    Command {
        code: TPM_CC_PCR_READ,
        handles: &[],
        auth: 0,
        nv: false,
        sessions: true,
        run: pcr_read,
    },
    Command {
        code: TPM_CC_PCR_EXTEND,
        handles: &[HandleKind::PcrOrNull],
        auth: 1,
        nv: true,
        sessions: true,
        run: pcr_extend,
    },
];

pub fn find(code: u32) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.code == code)
}

/// No parameter bytes may be left once a command has read its own.
pub fn end(r: &Reader) -> Result<()> {
    if r.is_empty() { Ok(()) } else { Err(Rc::SIZE) }
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
fn startup(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Writer) -> Result<()> {
    let state = read_su(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let saved = match &tpm.permanent.shutdown {
        Shutdown::State(saved) => Some(saved),
        _ => None,
    };
    let kind = match (state, saved) {
        (true, None) => return Err(Rc::VALUE.param(1)),
        (true, Some(_)) => Startup::Resume,
        (false, Some(_)) => Startup::Restart,
        (false, None) => Startup::Reset,
    };
    tpm.volatile.pcrs.startup(kind, saved);
    tpm.volatile.orderly_startup = tpm.permanent.shutdown != Shutdown::None;
    tpm.volatile.started = true;
    // Until the next orderly shutdown, losing power is not orderly.
    tpm.permanent.shutdown = Shutdown::None;
    tpm.mark_permanent_changed();
    Ok(())
}

/// TPM2_Shutdown: record an orderly shutdown; STATE also saves what a resume brings back.
fn shutdown(tpm: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Writer) -> Result<()> {
    let state = read_su(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    tpm.permanent.shutdown = if state {
        Shutdown::State(tpm.volatile.pcrs.save())
    } else {
        Shutdown::Clear
    };
    tpm.mark_permanent_changed();
    Ok(())
}

/// TPM2_SelfTest: the algorithms are RustCrypto's, tested where they are built; nothing is left
/// to test at run time, and every test has passed.
fn self_test(_: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Writer) -> Result<()> {
    // fullTest: a TPMI_YES_NO.
    if r.u8().map_err(|rc| rc.param(1))? > 1 {
        return Err(Rc::VALUE.param(1));
    }
    end(r)
}

/// TPM2_GetRandom: at most a digest's worth of bytes per call (as the specification allows).
fn get_random(_: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Writer) -> Result<()> {
    let wanted = usize::from(r.u16().map_err(|rc| rc.param(1))?);
    end(r)?;
    let mut bytes = vec![0; wanted.min(MAX_DIGEST)];
    getrandom::fill(&mut bytes).map_err(|_| Rc::FAILURE)?;
    w.tpm2b(&bytes);
    Ok(())
}

/// TPM2_PCR_Read.
fn pcr_read(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Writer) -> Result<()> {
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
fn pcr_extend(tpm: &mut Tpm, handles: &[u32], r: &mut Reader, _: &mut Writer) -> Result<()> {
    let digests = read_digest_values(r).map_err(|rc| rc.param(1))?;
    end(r)?;
    let handle = handles.first().copied().ok_or(Rc::FAILURE)?;
    if handle == pcr::TPM_RH_NULL {
        return Ok(());
    }
    let pcr = usize::try_from(handle).map_err(|_| Rc::FAILURE)?;
    if !pcr::may_extend(pcr, LOCALITY) {
        return Err(Rc::LOCALITY);
    }
    // A change to a PCR that TPM2_Shutdown(STATE) saved voids that saved state.
    if pcr::is_state_saved(pcr) && tpm.permanent.shutdown != Shutdown::None {
        tpm.permanent.shutdown = Shutdown::None;
        tpm.mark_permanent_changed();
    }
    for (hash, digest) in digests {
        let allocation = &tpm.permanent.allocation;
        tpm.volatile.pcrs.extend(allocation, pcr, hash, digest);
    }
    Ok(())
}

/// A TPML_DIGEST_VALUES: TPMT_HAs, each a hash algorithm and a digest of its size.
fn read_digest_values<'a>(r: &mut Reader<'a>) -> Result<Vec<(Hash, &'a [u8])>> {
    let count = r.count(Hash::ALL.len())?;
    (0..count)
        .map(|_| {
            let hash = Hash::read(r)?;
            Ok((hash, r.bytes(hash.size())?))
        })
        .collect()
}
