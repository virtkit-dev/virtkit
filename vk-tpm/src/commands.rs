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
use crate::session::SessionSlot;
use crate::state::{ResetData, Saved, Shutdown, new_seed};
use crate::{
    LOCALITY, Out, Tpm, capability, context, hierarchy, key, nv, object, session, signing,
};

pub const TPM_CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x11f;
pub const TPM_CC_EVICT_CONTROL: u32 = 0x120;
pub const TPM_CC_HIERARCHY_CONTROL: u32 = 0x121;
pub const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x122;
pub const TPM_CC_CHANGE_EPS: u32 = 0x124;
pub const TPM_CC_CHANGE_PPS: u32 = 0x125;
pub const TPM_CC_CLEAR: u32 = 0x126;
pub const TPM_CC_CLEAR_CONTROL: u32 = 0x127;
pub const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x129;
pub const TPM_CC_NV_DEFINE_SPACE: u32 = 0x12a;
pub const TPM_CC_PCR_ALLOCATE: u32 = 0x12b;
pub const TPM_CC_CREATE_PRIMARY: u32 = 0x131;
pub const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x12e;
pub const TPM_CC_NV_GLOBAL_WRITE_LOCK: u32 = 0x132;
pub const TPM_CC_NV_INCREMENT: u32 = 0x134;
pub const TPM_CC_NV_SET_BITS: u32 = 0x135;
pub const TPM_CC_NV_EXTEND: u32 = 0x136;
pub const TPM_CC_NV_WRITE: u32 = 0x137;
pub const TPM_CC_NV_WRITE_LOCK: u32 = 0x138;
pub const TPM_CC_DICTIONARY_ATTACK_LOCK_RESET: u32 = 0x139;
pub const TPM_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x13a;
pub const TPM_CC_NV_CHANGE_AUTH: u32 = 0x13b;
pub const TPM_CC_PCR_EVENT: u32 = 0x13c;
pub const TPM_CC_PCR_RESET: u32 = 0x13d;
pub const TPM_CC_SEQUENCE_COMPLETE: u32 = 0x13e;
pub const TPM_CC_SELF_TEST: u32 = 0x143;
pub const TPM_CC_STARTUP: u32 = 0x144;
pub const TPM_CC_SHUTDOWN: u32 = 0x145;
pub const TPM_CC_STIR_RANDOM: u32 = 0x146;
pub const TPM_CC_NV_READ: u32 = 0x14e;
pub const TPM_CC_NV_READ_LOCK: u32 = 0x14f;
pub const TPM_CC_OBJECT_CHANGE_AUTH: u32 = 0x150;
pub const TPM_CC_CREATE: u32 = 0x153;
pub const TPM_CC_ECDH_ZGEN: u32 = 0x154;
pub const TPM_CC_HMAC: u32 = 0x155;
pub const TPM_CC_LOAD: u32 = 0x157;
pub const TPM_CC_RSA_DECRYPT: u32 = 0x159;
pub const TPM_CC_HMAC_START: u32 = 0x15b;
pub const TPM_CC_SEQUENCE_UPDATE: u32 = 0x15c;
pub const TPM_CC_SIGN: u32 = 0x15d;
pub const TPM_CC_UNSEAL: u32 = 0x15e;
pub const TPM_CC_CONTEXT_LOAD: u32 = 0x161;
pub const TPM_CC_CONTEXT_SAVE: u32 = 0x162;
pub const TPM_CC_ECDH_KEYGEN: u32 = 0x163;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x165;
pub const TPM_CC_LOAD_EXTERNAL: u32 = 0x167;
pub const TPM_CC_NV_READ_PUBLIC: u32 = 0x169;
pub const TPM_CC_READ_PUBLIC: u32 = 0x173;
pub const TPM_CC_RSA_ENCRYPT: u32 = 0x174;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x176;
pub const TPM_CC_VERIFY_SIGNATURE: u32 = 0x177;
pub const TPM_CC_ECC_PARAMETERS: u32 = 0x178;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x17a;
pub const TPM_CC_GET_RANDOM: u32 = 0x17b;
pub const TPM_CC_GET_TEST_RESULT: u32 = 0x17c;
pub const TPM_CC_HASH: u32 = 0x17d;
pub const TPM_CC_PCR_READ: u32 = 0x17e;
pub const TPM_CC_READ_CLOCK: u32 = 0x181;
pub const TPM_CC_PCR_EXTEND: u32 = 0x182;
pub const TPM_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x185;
pub const TPM_CC_HASH_SEQUENCE_START: u32 = 0x186;
pub const TPM_CC_TEST_PARMS: u32 = 0x18a;

type Run = fn(&mut Tpm, &[u32], &mut Reader, &mut Out) -> Result<()>;

/// The authorization role a handle takes (Part 1, "Authorization Roles").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    User,
    /// Certifying, changing the authValue of, or deleting the entity: an object without
    /// adminWithPolicy may use its authValue; anything else needs its policy, and a policy
    /// session bound to the command (TPM2_PolicyCommandCode).
    Admin,
}

pub struct Command {
    pub code: u32,
    /// The handle area, in order.
    pub handles: &'static [HandleKind],
    /// Number of leading handles that need an authorization session.
    pub auth: usize,
    /// The role the first of them takes (the others take the USER role).
    pub role: Role,
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
            role: Role::User,
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

    const fn admin(self) -> Command {
        Command {
            role: Role::Admin,
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
    Command::new(TPM_CC_NV_UNDEFINE_SPACE_SPECIAL, nv::undefine_space_special)
        .handles(&[H::NvIndex, H::Platform], 2)
        .admin()
        .nv(),
    Command::new(TPM_CC_EVICT_CONTROL, key::evict_control)
        .handles(&[H::Provision, H::Object(false)], 1)
        .nv(),
    Command::new(TPM_CC_HIERARCHY_CONTROL, hierarchy::hierarchy_control)
        .handles(&[H::Hierarchy], 1)
        .nv()
        .extensive(),
    Command::new(TPM_CC_NV_UNDEFINE_SPACE, nv::undefine_space)
        .handles(&[H::Provision, H::NvIndex], 1)
        .nv(),
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
    Command::new(TPM_CC_NV_DEFINE_SPACE, nv::define_space)
        .handles(&[H::Provision], 1)
        .nv()
        .decrypt(),
    Command::new(TPM_CC_PCR_ALLOCATE, pcr_allocate)
        .handles(&[H::Platform], 1)
        .nv(),
    Command::new(TPM_CC_SET_PRIMARY_POLICY, hierarchy::set_primary_policy)
        .handles(&[H::HierarchyPolicy], 1)
        .nv()
        .decrypt(),
    Command::new(TPM_CC_CREATE_PRIMARY, key::create_primary)
        .handles(&[H::HierarchyOrNull], 1)
        .response_handle()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_NV_GLOBAL_WRITE_LOCK, nv::global_write_lock)
        .handles(&[H::Provision], 1)
        .nv(),
    Command::new(TPM_CC_NV_INCREMENT, nv::increment)
        .handles(&[H::NvAuth, H::NvIndex], 1)
        .nv(),
    Command::new(TPM_CC_NV_SET_BITS, nv::set_bits)
        .handles(&[H::NvAuth, H::NvIndex], 1)
        .nv(),
    Command::new(TPM_CC_NV_EXTEND, nv::extend)
        .handles(&[H::NvAuth, H::NvIndex], 1)
        .nv()
        .decrypt(),
    Command::new(TPM_CC_NV_WRITE, nv::write)
        .handles(&[H::NvAuth, H::NvIndex], 1)
        .nv()
        .decrypt(),
    Command::new(TPM_CC_NV_WRITE_LOCK, nv::write_lock)
        .handles(&[H::NvAuth, H::NvIndex], 1)
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
    Command::new(TPM_CC_NV_CHANGE_AUTH, nv::change_auth)
        .handles(&[H::NvIndex], 1)
        .admin()
        .nv()
        .decrypt(),
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
    Command::new(TPM_CC_STIR_RANDOM, stir_random).nv().decrypt(),
    Command::new(TPM_CC_NV_READ, nv::read)
        .handles(&[H::NvAuth, H::NvIndex], 1)
        .encrypt(),
    Command::new(TPM_CC_NV_READ_LOCK, nv::read_lock)
        .handles(&[H::NvAuth, H::NvIndex], 1)
        .nv(),
    Command::new(TPM_CC_OBJECT_CHANGE_AUTH, key::object_change_auth)
        .handles(&[H::Object(false), H::Object(false)], 1)
        .admin()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_CREATE, key::create)
        .handles(&[H::Object(false)], 1)
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_ECDH_ZGEN, signing::ecdh_z_gen)
        .handles(&[H::Object(false)], 1)
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_HMAC, object::hmac)
        .handles(&[H::Object(false)], 1)
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_LOAD, key::load)
        .handles(&[H::Object(false)], 1)
        .response_handle()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_RSA_DECRYPT, signing::rsa_decrypt)
        .handles(&[H::Object(false)], 1)
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_HMAC_START, object::hmac_start_command)
        .handles(&[H::Object(false)], 1)
        .response_handle()
        .decrypt(),
    Command::new(TPM_CC_SEQUENCE_UPDATE, object::sequence_update)
        .handles(&[H::Object(false)], 1)
        .decrypt(),
    Command::new(TPM_CC_SIGN, signing::sign)
        .handles(&[H::Object(false)], 1)
        .decrypt(),
    Command::new(TPM_CC_UNSEAL, key::unseal)
        .handles(&[H::Object(false)], 1)
        .encrypt(),
    Command::new(TPM_CC_CONTEXT_LOAD, context::context_load)
        .response_handle()
        .no_sessions(),
    Command::new(TPM_CC_CONTEXT_SAVE, context::context_save)
        .handles(&[H::Context], 0)
        .no_sessions(),
    Command::new(TPM_CC_ECDH_KEYGEN, signing::ecdh_key_gen)
        .handles(&[H::Object(false)], 0)
        .encrypt(),
    Command::new(TPM_CC_FLUSH_CONTEXT, context::flush_context).no_sessions(),
    Command::new(TPM_CC_LOAD_EXTERNAL, key::load_external)
        .response_handle()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_NV_READ_PUBLIC, nv::read_public)
        .handles(&[H::NvIndex], 0)
        .encrypt(),
    Command::new(TPM_CC_READ_PUBLIC, key::read_public)
        .handles(&[H::Object(false)], 0)
        .encrypt(),
    Command::new(TPM_CC_RSA_ENCRYPT, signing::rsa_encrypt)
        .handles(&[H::Object(false)], 0)
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_START_AUTH_SESSION, session::start_auth_session)
        .handles(&[H::Object(true), H::Entity(true)], 0)
        .response_handle()
        .decrypt()
        .encrypt(),
    Command::new(TPM_CC_VERIFY_SIGNATURE, signing::verify_signature)
        .handles(&[H::Object(false)], 0)
        .decrypt(),
    Command::new(TPM_CC_ECC_PARAMETERS, signing::ecc_parameters),
    Command::new(TPM_CC_GET_CAPABILITY, capability::get_capability),
    Command::new(TPM_CC_GET_RANDOM, get_random).encrypt(),
    Command::new(TPM_CC_GET_TEST_RESULT, get_test_result).encrypt(),
    Command::new(TPM_CC_HASH, object::hash).decrypt().encrypt(),
    Command::new(TPM_CC_PCR_READ, pcr_read),
    Command::new(TPM_CC_READ_CLOCK, read_clock),
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
    Command::new(TPM_CC_TEST_PARMS, test_parms),
];

/// IsWriteOperation: the command writes an NV index, so an index authorizes it with its
/// AUTHWRITE or POLICYWRITE (else AUTHREAD or POLICYREAD).
pub fn is_write_operation(code: u32) -> bool {
    matches!(
        code,
        TPM_CC_NV_WRITE
            | TPM_CC_NV_INCREMENT
            | TPM_CC_NV_SET_BITS
            | TPM_CC_NV_EXTEND
            | TPM_CC_NV_WRITE_LOCK
    )
}

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
    // Every Startup enables the platform hierarchy; all but a resume reset the STATE_CLEAR data
    // (enables, platform auth and policy).
    tpm.volatile.ph_enable = true;
    tpm.volatile.clear = match (&saved, kind) {
        (Some(saved), Startup::Resume) => saved.clear.clone(),
        _ => Default::default(),
    };
    let saved_pcrs = saved.as_ref().map(|s| &s.pcrs);
    let allocation = &tpm.volatile.allocation;
    tpm.volatile.pcrs.startup(allocation, kind, saved_pcrs);
    tpm.volatile.pcr_reconfig = false;
    if !orderly {
        tpm.permanent.clock_safe = false;
    }
    tpm.startup_reset_data(kind, saved.map(|s| s.reset))?;
    tpm.nv_startup(kind, orderly);
    tpm.volatile.objects.iter_mut().for_each(|o| *o = None);
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
    tpm.nv_store_orderly();
    tpm.permanent.shutdown_time = tpm.volatile.time;
    tpm.permanent.shutdown = if state {
        Shutdown::State(Box::new(Saved {
            pcrs: tpm.volatile.pcrs.save(),
            clear: tpm.volatile.clear.clone(),
            reset: tpm.volatile.reset_data(),
        }))
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

/// TPM2_StirRandom: every random byte comes straight from the host's CSPRNG, which guest data
/// cannot make better; the data is accepted and dropped (the reference mixes it into its own
/// DRBG, which vk-tpm does not keep).
fn stir_random(_: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    r.tpm2b(crate::public::MAX_SYM_DATA)
        .map_err(|rc| rc.param(1))?;
    end(r)
}

/// TPM2_GetTestResult: nothing to report, and every test passed.
fn get_test_result(_: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    w.tpm2b(&[]).u32(Rc::SUCCESS.0);
    Ok(())
}

/// TPM2_TestParms: whether the TPM takes these parameters (a TPMT_PUBLIC_PARMS): it does if
/// they unmarshal.
fn test_parms(_: &mut Tpm, _: &[u32], r: &mut Reader, _: &mut Out) -> Result<()> {
    (|| {
        let kind = crate::public::Type::read(r)?;
        crate::public::Params::read(kind, r)
    })()
    .map_err(|rc| rc.param(1))?;
    end(r)
}

/// TPM2_ReadClock: TPMS_TIME_INFO.
fn read_clock(tpm: &mut Tpm, _: &[u32], r: &mut Reader, w: &mut Out) -> Result<()> {
    end(r)?;
    w.u64(tpm.volatile.time);
    tpm.write_clock_info(w);
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
    let digests = read_digest_values(r).map_err(|rc| rc.param(1))?;
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

/// TPM2_PCR_Allocate: set each bank's PCR allocation for the next power on. Until then, keep
/// the current allocation and refuse TPM2_Shutdown(STATE).
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
    /// What each kind of Startup does to STATE_RESET_DATA: a TPM Reset draws a new null
    /// hierarchy and starts the counters and the sessions over; a Restart or a Resume brings
    /// back what TPM2_Shutdown(STATE) saved (saved sessions included), and counts itself.
    fn startup_reset_data(&mut self, kind: Startup, saved: Option<ResetData>) -> Result<()> {
        let v = &mut self.volatile;
        v.sessions.iter_mut().for_each(|s| *s = SessionSlot::Free);
        match (kind, saved) {
            (Startup::Restart | Startup::Resume, Some(saved)) => {
                v.null_proof = saved.null_proof;
                v.null_seed = saved.null_seed;
                v.clear_count = saved.clear_count;
                v.restart_count = saved.restart_count.wrapping_add(1);
                if kind == Startup::Restart {
                    v.clear_count = v.clear_count.wrapping_add(1);
                }
                v.object_context_id = saved.object_context_id;
                v.context_counter = saved.context_counter;
                for (i, sequence) in saved.saved_sessions {
                    let slot = usize::try_from(i).ok().and_then(|i| v.sessions.get_mut(i));
                    if let Some(slot) = slot {
                        *slot = SessionSlot::Saved(sequence);
                    }
                }
            }
            _ => {
                v.null_proof = new_seed().map_err(|_| Rc::FAILURE)?;
                v.null_seed = new_seed().map_err(|_| Rc::FAILURE)?;
                v.clear_count = 0;
                v.restart_count = 0;
                v.object_context_id = 0;
                v.context_counter = context::FIRST_CONTEXT;
                let p = &mut self.permanent;
                p.reset_count = p.reset_count.wrapping_add(1);
                p.total_reset_count = p.total_reset_count.wrapping_add(1);
            }
        }
        Ok(())
    }

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

/// A TPML_DIGEST_VALUES: TPMT_HAs, each a hash algorithm and a digest of its size.
fn read_digest_values(r: &mut Reader) -> Result<Vec<(Hash, Vec<u8>)>> {
    let count = r.count(Hash::ALL.len())?;
    (0..count)
        .map(|_| {
            let hash = Hash::read(r)?;
            Ok((hash, r.bytes(hash.size())?.to_vec()))
        })
        .collect()
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
