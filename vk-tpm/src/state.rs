//! The TPM's state, and its serialized forms.
//!
//! - [`Permanent`]: what a TPM keeps across power cycles (its NV memory): seeds, the hierarchies'
//!   authorizations and proofs, PCR bank allocation, dictionary-attack state, and what the last
//!   TPM2_Shutdown saved. The VMM writes it to the machine's state file each time it changes.
//! - [`Volatile`]: what is lost at power-off (PCR values, whether TPM2_Startup ran, the
//!   hierarchy enables). Only a snapshot keeps it.
//!
//! Each serializes as a magic, a format version and the fields in order, in the TPM's own wire
//! format. A reader refuses a version it does not know, rather than guess.

use zeroize::Zeroizing;

use crate::alg::Hash;
use crate::hierarchy::{ClearState, DaTimers, DictionaryAttack, Hierarchies};
use crate::key::{Key, MAX_PERSISTENT};
use crate::marshal::{Reader, Writer};
use crate::nv::{self, NvIndex, OrderlyRam};
use crate::object::{MAX_OBJECTS, Object};
use crate::pcr::{self, Bank, Banks, Pcrs, Selection};
use crate::rc::Rc;
use crate::session::{MAX_ACTIVE, Session, SessionSlot};

const PERMANENT_MAGIC: &[u8; 8] = b"VKTPM-P\0";
const VOLATILE_MAGIC: &[u8; 8] = b"VKTPM-V\0";
/// No vk-tpm state has been stored outside a test yet: the format stays at version 1, and
/// changes in place, until one is (docs/tpm-design.md).
const VERSION: u16 = 1;
pub const SEED_SIZE: usize = 64;
/// More than the serialized states can hold (the permanent one a few KiB with saved PCRs, some
/// tens with every persistent object an RSA-3072 key, and up to 64 KiB more of NV indices; the
/// volatile one some tens with every session and object slot taken), so writing one never reallocates and leaves a stray copy of
/// its secrets. Each is wiped whole when dropped.
const PERMANENT_CAPACITY: usize = 192 * 1024;
const VOLATILE_CAPACITY: usize = 64 * 1024;

/// The state could not be read: not ours, a version this build does not know, or corrupt.
#[derive(Debug, PartialEq, Eq)]
pub struct StateError(pub &'static str);

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TPM state: {}", self.0)
    }
}

impl std::error::Error for StateError {}

impl From<Rc> for StateError {
    fn from(_: Rc) -> StateError {
        StateError("truncated or malformed")
    }
}

/// A hierarchy's seed, the root every primary key of it is derived from, or a proof. Wiped when
/// dropped.
pub type Seed = Zeroizing<[u8; SEED_SIZE]>;

/// A random seed (or proof), from the host's entropy.
pub fn new_seed() -> Result<Seed, StateError> {
    let mut seed = Seed::new([0; SEED_SIZE]);
    getrandom::fill(seed.as_mut()).map_err(|_| StateError("no entropy for the seeds"))?;
    Ok(seed)
}

/// A seed of zeros, until a TPM Reset draws one.
pub fn zero_seed() -> Seed {
    Seed::new([0; SEED_SIZE])
}

pub fn read_seed(r: &mut Reader) -> Result<Seed, StateError> {
    let bytes = r.tpm2b(SEED_SIZE)?;
    let seed: [u8; SEED_SIZE] = bytes.try_into().map_err(|_| StateError("bad seed"))?;
    Ok(Seed::new(seed))
}

/// How the TPM was last shut down (its orderlyState), which decides what the next TPM2_Startup
/// may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shutdown {
    /// No orderly shutdown since the last Startup: the next one is a TPM Reset.
    None,
    /// As None, and a DA-protected authValue was used since: the TPM Reset counts one failed
    /// authorization, in case one was lost with the power.
    DaUsed,
    /// TPM2_Shutdown(CLEAR) (or a new TPM).
    Clear,
    /// TPM2_Shutdown(STATE), with what it saved.
    State(Box<Saved>),
}

impl Shutdown {
    /// The shutdown was orderly: no failure is presumed lost, and Startup may restart or
    /// resume.
    pub fn is_orderly(&self) -> bool {
        matches!(self, Shutdown::Clear | Shutdown::State(_))
    }
}

/// What TPM2_Shutdown(STATE) saves for the TPM2_Startup after it: the state-saved PCRs, the
/// enables and platform authorization a resume brings back, and what a restart or a resume
/// keeps (STATE_RESET_DATA).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub pcrs: pcr::Saved,
    pub clear: ClearState,
    pub reset: ResetData,
}

/// What only a TPM Reset starts over (STATE_RESET_DATA): the null hierarchy's proof and seed,
/// the counters that date contexts, and which session handles hold saved sessions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetData {
    pub null_proof: Seed,
    pub null_seed: Seed,
    /// TPM Restarts since the last TPM Reset: a stClear object's context is valid for one.
    pub clear_count: u32,
    /// TPM Restarts and Resumes since the last TPM Reset (TPMS_CLOCK_INFO.restartCount).
    pub restart_count: u32,
    /// The sequence number of the last object context saved.
    pub object_context_id: u64,
    /// The sequence number the next saved session context gets.
    pub context_counter: u64,
    /// (handle index, context sequence) of each saved session.
    pub saved_sessions: Vec<(u32, u64)>,
}

impl ResetData {
    pub fn write(&self, w: &mut Writer) {
        w.tpm2b(self.null_proof.as_slice())
            .tpm2b(self.null_seed.as_slice())
            .u32(self.clear_count)
            .u32(self.restart_count)
            .u64(self.object_context_id)
            .u64(self.context_counter)
            .count(self.saved_sessions.len());
        for (i, sequence) in &self.saved_sessions {
            w.u32(*i).u64(*sequence);
        }
    }

    pub fn read(r: &mut Reader) -> Result<ResetData, StateError> {
        let null_proof = read_seed(r)?;
        let null_seed = read_seed(r)?;
        let (clear_count, restart_count) = (r.u32()?, r.u32()?);
        let (object_context_id, context_counter) = (r.u64()?, r.u64()?);
        let count = r.count(MAX_ACTIVE)?;
        let saved_sessions = (0..count)
            .map(|_| Ok((r.u32()?, r.u64()?)))
            .collect::<Result<_, StateError>>()?;
        Ok(ResetData {
            null_proof,
            null_seed,
            clear_count,
            restart_count,
            object_context_id,
            context_counter,
            saved_sessions,
        })
    }
}

pub struct Permanent {
    /// Endorsement, storage (owner) and platform primary seeds.
    pub eps: Seed,
    pub sps: Seed,
    pub pps: Seed,
    pub hierarchies: Hierarchies,
    /// Which PCRs of which bank are allocated from the next power on (TPM2_PCR_Allocate), one
    /// selection per bank.
    pub allocation: Vec<Selection>,
    pub dictionary_attack: DictionaryAttack,
    pub shutdown: Shutdown,
    /// TPM time (ms) at the last TPM2_Shutdown, from which the dictionary-attack timers go on
    /// counting after an orderly power cycle.
    pub shutdown_time: u64,
    /// The persistent objects (TPM2_EvictControl), by handle.
    pub persistent: Vec<(u32, Key)>,
    /// TPM Resets since the last TPM2_Clear (resetCount), and ever (totalResetCount: object
    /// contexts of an earlier TPM Reset do not load).
    pub reset_count: u32,
    pub total_reset_count: u64,
    /// Clock (ms), which goes on across power cycles, and whether no larger value of it may
    /// have been reported (TPMS_CLOCK_INFO.safe).
    pub clock: u64,
    pub clock_safe: bool,
    /// The NV indices, by handle.
    pub nv: Vec<NvIndex>,
    /// The highest value a deleted counter index had: a new one starts above it.
    pub nv_max_counter: u64,
}

impl Permanent {
    pub fn clock_state(&self) -> (u64, bool) {
        (self.clock, self.clock_safe)
    }

    /// Put back Clock as `state` had it, and return what it was.
    pub fn set_clock_state(&mut self, (clock, safe): (u64, bool)) -> (u64, bool) {
        let was = self.clock_state();
        (self.clock, self.clock_safe) = (clock, safe);
        was
    }

    /// A newly manufactured TPM: fresh seeds and proofs, every bank allocated.
    pub fn manufacture() -> Result<Permanent, StateError> {
        Ok(Permanent {
            eps: new_seed()?,
            sps: new_seed()?,
            pps: new_seed()?,
            hierarchies: Hierarchies::manufacture()?,
            allocation: Hash::ALL
                .into_iter()
                .map(|h| Selection::all(h, true))
                .collect(),
            dictionary_attack: DictionaryAttack::default(),
            shutdown: Shutdown::Clear,
            shutdown_time: 0,
            persistent: Vec::new(),
            reset_count: 0,
            total_reset_count: 0,
            clock: 0,
            clock_safe: true,
            nv: Vec::new(),
            nv_max_counter: 0,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(PERMANENT_CAPACITY);
        w.bytes(PERMANENT_MAGIC).u16(VERSION);
        for seed in [&self.eps, &self.sps, &self.pps] {
            w.tpm2b(seed.as_slice());
        }
        self.hierarchies.write(&mut w);
        pcr::write_selections(&mut w, &self.allocation);
        self.dictionary_attack.write(&mut w);
        match &self.shutdown {
            Shutdown::None => {
                w.u8(0);
            }
            Shutdown::DaUsed => {
                w.u8(1);
            }
            Shutdown::Clear => {
                w.u8(2);
            }
            Shutdown::State(saved) => {
                w.u8(3).u32(saved.pcrs.counter);
                write_banks(&mut w, &saved.pcrs.banks);
                saved.clear.write(&mut w);
                saved.reset.write(&mut w);
            }
        }
        w.u64(self.shutdown_time);
        w.count(self.persistent.len());
        for (handle, key) in &self.persistent {
            w.u32(*handle);
            key.write(&mut w);
        }
        w.u32(self.reset_count)
            .u64(self.total_reset_count)
            .u64(self.clock)
            .u8(self.clock_safe.into());
        nv::write_nv(&mut w, &self.nv, self.nv_max_counter);
        w.into_bytes()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Permanent, StateError> {
        let mut r = Reader::new(bytes);
        expect_header(&mut r, PERMANENT_MAGIC)?;
        let (eps, sps, pps) = (read_seed(&mut r)?, read_seed(&mut r)?, read_seed(&mut r)?);
        let hierarchies = Hierarchies::read(&mut r)?;
        let allocation = pcr::read_selections(&mut r)?;
        let dictionary_attack = DictionaryAttack::read(&mut r)?;
        let shutdown = match r.u8()? {
            0 => Shutdown::None,
            1 => Shutdown::DaUsed,
            2 => Shutdown::Clear,
            3 => Shutdown::State(Box::new(Saved {
                pcrs: pcr::Saved {
                    counter: r.u32()?,
                    banks: read_banks(&mut r)?,
                },
                clear: ClearState::read(&mut r)?,
                reset: ResetData::read(&mut r)?,
            })),
            _ => return Err(StateError("bad shutdown state")),
        };
        let shutdown_time = r.u64()?;
        let count = r.count(MAX_PERSISTENT)?;
        let mut persistent: Vec<(u32, Key)> = Vec::with_capacity(count);
        for _ in 0..count {
            let handle = r.u32()?;
            if persistent.last().is_some_and(|(h, _)| *h >= handle) {
                return Err(StateError("persistent objects out of order"));
            }
            persistent.push((handle, Key::read(&mut r)?));
        }
        let reset_count = r.u32()?;
        let total_reset_count = r.u64()?;
        let clock = r.u64()?;
        let clock_safe = read_bool(&mut r)?;
        let (nv, nv_max_counter) = nv::read_nv(&mut r)?;
        expect_end(&r)?;
        Ok(Permanent {
            eps,
            sps,
            pps,
            hierarchies,
            allocation,
            dictionary_attack,
            shutdown,
            shutdown_time,
            persistent,
            reset_count,
            total_reset_count,
            clock,
            clock_safe,
            nv,
            nv_max_counter,
        })
    }
}

pub struct Volatile {
    /// TPM2_Startup ran since the TPM powered on.
    pub started: bool,
    /// The shutdown before that Startup was orderly (TPMA_STARTUP_CLEAR.orderly).
    pub orderly_startup: bool,
    /// TPM time: milliseconds since power on, as of the command being run.
    pub time: u64,
    /// TPM time restarted from zero since the last Startup (_plat__TimerWasReset).
    pub time_reset: bool,
    pub da_timers: DaTimers,
    /// A DA-protected authValue was used since Startup (g_daUsed).
    pub da_used: bool,
    /// The platform hierarchy is enabled (every Startup enables it).
    pub ph_enable: bool,
    /// The PCR allocation in use: the permanent one as of power on (TPM2_PCR_Allocate changes
    /// only the latter).
    pub allocation: Vec<Selection>,
    /// TPM2_PCR_Allocate changed the allocation since Startup (g_pcrReConfig): the PCRs no
    /// longer match it, so TPM2_Shutdown(STATE) may not save them.
    pub pcr_reconfig: bool,
    pub clear: ClearState,
    pub pcrs: Pcrs,
    /// The object slots.
    pub objects: Vec<Option<Object>>,
    /// The sessions, by handle index.
    pub sessions: Vec<SessionSlot>,
    /// The session whose audit digest covers every command since it last audited one
    /// (g_exclusiveAuditSession).
    pub exclusive_audit: Option<u32>,
    /// The null hierarchy's proof and seed, new at every TPM Reset.
    pub null_proof: Seed,
    pub null_seed: Seed,
    pub clear_count: u32,
    pub restart_count: u32,
    pub object_context_id: u64,
    pub context_counter: u64,
    /// The orderly NV indices' attributes and data (their RAM copies).
    pub nv_orderly: Vec<OrderlyRam>,
}

impl Volatile {
    /// The TPM as it powers on (_TPM_Init): waiting for TPM2_Startup.
    pub fn power_on(permanent: &Permanent) -> Volatile {
        Volatile {
            allocation: permanent.allocation.clone(),
            started: false,
            orderly_startup: false,
            time: 0,
            time_reset: true,
            da_timers: DaTimers::default(),
            da_used: false,
            ph_enable: true,
            pcr_reconfig: false,
            clear: ClearState::default(),
            pcrs: Pcrs::new(),
            objects: empty_slots(MAX_OBJECTS),
            sessions: std::iter::repeat_with(|| SessionSlot::Free)
                .take(MAX_ACTIVE)
                .collect(),
            exclusive_audit: None,
            null_proof: zero_seed(),
            null_seed: zero_seed(),
            clear_count: 0,
            restart_count: 0,
            object_context_id: 0,
            context_counter: 0,
            nv_orderly: nv::orderly_images(&permanent.nv),
        }
    }

    /// What a TPM2_Shutdown(STATE) keeps for a restart or a resume.
    pub fn reset_data(&self) -> ResetData {
        let saved_sessions = (self.sessions.iter().enumerate())
            .filter_map(|(i, s)| match s {
                SessionSlot::Saved(sequence) => Some((u32::try_from(i).ok()?, *sequence)),
                _ => None,
            })
            .collect();
        ResetData {
            null_proof: self.null_proof.clone(),
            null_seed: self.null_seed.clone(),
            clear_count: self.clear_count,
            restart_count: self.restart_count,
            object_context_id: self.object_context_id,
            context_counter: self.context_counter,
            saved_sessions,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(VOLATILE_CAPACITY);
        w.bytes(VOLATILE_MAGIC).u16(VERSION);
        w.u8(self.started.into())
            .u8(self.orderly_startup.into())
            .u64(self.time)
            .u8(self.time_reset.into())
            .u64(self.da_timers.self_heal.cast_unsigned())
            .u64(self.da_timers.lockout.cast_unsigned())
            .u8(self.da_used.into())
            .u8(self.ph_enable.into())
            .u8(self.pcr_reconfig.into());
        pcr::write_selections(&mut w, &self.allocation);
        self.clear.write(&mut w);
        w.u32(self.pcrs.counter);
        let banks: Vec<_> = (self.pcrs.banks.iter())
            .map(|b| (b.hash, b.values.clone()))
            .collect();
        write_banks(&mut w, &banks);
        write_slots(&mut w, &self.objects, Object::write);
        for slot in &self.sessions {
            match slot {
                SessionSlot::Free => {
                    w.u8(0);
                }
                SessionSlot::Loaded(s) => {
                    w.u8(1);
                    s.write(&mut w);
                }
                SessionSlot::Saved(sequence) => {
                    w.u8(2).u64(*sequence);
                }
            }
        }
        w.u32(self.exclusive_audit.unwrap_or(0));
        w.tpm2b(self.null_proof.as_slice())
            .tpm2b(self.null_seed.as_slice())
            .u32(self.clear_count)
            .u32(self.restart_count)
            .u64(self.object_context_id)
            .u64(self.context_counter);
        OrderlyRam::write_list(&mut w, &self.nv_orderly);
        w.into_bytes()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Volatile, StateError> {
        let mut r = Reader::new(bytes);
        expect_header(&mut r, VOLATILE_MAGIC)?;
        let started = read_bool(&mut r)?;
        let orderly_startup = read_bool(&mut r)?;
        let time = r.u64()?;
        let time_reset = read_bool(&mut r)?;
        let da_timers = DaTimers {
            self_heal: r.u64()?.cast_signed(),
            lockout: r.u64()?.cast_signed(),
        };
        let da_used = read_bool(&mut r)?;
        let ph_enable = read_bool(&mut r)?;
        let pcr_reconfig = read_bool(&mut r)?;
        let allocation = pcr::read_selections(&mut r)?;
        let clear = ClearState::read(&mut r)?;
        let mut pcrs = Pcrs::new();
        pcrs.counter = r.u32()?;
        for (hash, values) in read_banks(&mut r)? {
            let bank = (pcrs.banks.iter_mut())
                .find(|b| b.hash == hash)
                .ok_or(StateError("unknown bank"))?;
            if values.len() != pcr::PCR_COUNT {
                return Err(StateError("bad PCR count"));
            }
            *bank = Bank { hash, values };
        }
        let objects = read_slots(&mut r, MAX_OBJECTS, Object::read)?;
        let sessions = (0..MAX_ACTIVE)
            .map(|_| {
                Ok(match r.u8()? {
                    0 => SessionSlot::Free,
                    1 => SessionSlot::Loaded(Box::new(Session::read(&mut r)?)),
                    2 => SessionSlot::Saved(r.u64()?),
                    _ => return Err(StateError("bad session slot")),
                })
            })
            .collect::<Result<_, StateError>>()?;
        let exclusive_audit = Some(r.u32()?).filter(|&h| h != 0);
        let null_proof = read_seed(&mut r)?;
        let null_seed = read_seed(&mut r)?;
        let (clear_count, restart_count) = (r.u32()?, r.u32()?);
        let (object_context_id, context_counter) = (r.u64()?, r.u64()?);
        let nv_orderly = OrderlyRam::read_list(&mut r)?;
        expect_end(&r)?;
        Ok(Volatile {
            started,
            orderly_startup,
            time,
            time_reset,
            da_timers,
            da_used,
            ph_enable,
            allocation,
            pcr_reconfig,
            clear,
            pcrs,
            objects,
            sessions,
            exclusive_audit,
            null_proof,
            null_seed,
            clear_count,
            restart_count,
            object_context_id,
            context_counter,
            nv_orderly,
        })
    }
}

fn empty_slots<T>(n: usize) -> Vec<Option<T>> {
    std::iter::repeat_with(|| None).take(n).collect()
}

/// Object or session slots: a flag for each, then what it holds.
fn write_slots<T>(w: &mut Writer, slots: &[Option<T>], write: fn(&T, &mut Writer)) {
    for slot in slots {
        match slot {
            Some(t) => {
                w.u8(1);
                write(t, w);
            }
            None => {
                w.u8(0);
            }
        }
    }
}

fn read_slots<T>(
    r: &mut Reader,
    n: usize,
    read: fn(&mut Reader) -> Result<T, StateError>,
) -> Result<Vec<Option<T>>, StateError> {
    (0..n)
        .map(|_| Ok(if read_bool(r)? { Some(read(r)?) } else { None }))
        .collect()
}

fn expect_header(r: &mut Reader, magic: &[u8; 8]) -> Result<(), StateError> {
    if r.bytes(magic.len())? != magic {
        return Err(StateError("not a vk-tpm state"));
    }
    if r.u16()? != VERSION {
        return Err(StateError("unknown format version"));
    }
    Ok(())
}

fn expect_end(r: &Reader) -> Result<(), StateError> {
    if r.is_empty() {
        Ok(())
    } else {
        Err(StateError("trailing bytes"))
    }
}

pub fn read_bool(r: &mut Reader) -> Result<bool, StateError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StateError("bad flag")),
    }
}

/// Per bank: the algorithm, then its PCR values (each a TPM2B of that algorithm's size).
fn write_banks(w: &mut Writer, banks: &[(Hash, Vec<Vec<u8>>)]) {
    w.count(banks.len());
    for (hash, values) in banks {
        w.u16(hash.id()).count(values.len());
        for v in values {
            w.tpm2b(v);
        }
    }
}

fn read_banks(r: &mut Reader) -> Result<Banks, StateError> {
    let count = r.count(Hash::ALL.len())?;
    let mut banks: Banks = Vec::with_capacity(count);
    for _ in 0..count {
        let hash = Hash::read(r)?;
        if banks.iter().any(|(h, _)| *h == hash) {
            return Err(StateError("duplicate bank"));
        }
        let n = r.count(pcr::PCR_COUNT)?;
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            let v = r.tpm2b(hash.size())?;
            if v.len() != hash.size() {
                return Err(StateError("bad PCR size"));
            }
            values.push(v.to_vec());
        }
        banks.push((hash, values));
    }
    Ok(banks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hierarchy::Policy;
    use crate::pcr::Startup;

    #[test]
    fn permanent_state_round_trips() {
        let mut p = Permanent::manufacture().unwrap();
        assert_ne!(*p.eps, *p.sps, "seeds are random");
        let mut pcrs = Pcrs::new();
        pcrs.startup(&p.allocation, Startup::Reset, None);
        let clear = ClearState {
            platform_auth: Zeroizing::new(b"platform".to_vec()),
            ..Default::default()
        };
        p.shutdown = Shutdown::State(Box::new(Saved {
            pcrs: pcrs.save(),
            clear,
            reset: Volatile::power_on(&p).reset_data(),
        }));
        p.dictionary_attack.failed_tries = 2;
        p.hierarchies.owner_auth = Zeroizing::new(b"owner".to_vec());
        p.hierarchies.lockout_policy = Policy {
            hash: Some(Hash::Sha256),
            digest: vec![7; 32],
        };
        p.shutdown_time = 1234;
        let bytes = p.serialize();
        let q = Permanent::deserialize(&bytes).unwrap();
        assert_eq!(q.serialize(), bytes);
        assert_eq!(*q.eps, *p.eps);
        assert_eq!(q.shutdown, p.shutdown);
        assert_eq!(*q.hierarchies.owner_auth, b"owner");
    }

    #[test]
    fn volatile_state_round_trips() {
        let mut v = Volatile::power_on(&Permanent::manufacture().unwrap());
        v.started = true;
        v.time = 99;
        v.da_timers.lockout = -5;
        v.clear.sh_enable = false;
        v.pcrs.startup(&v.allocation.clone(), Startup::Reset, None);
        let bytes = v.serialize();
        let w = Volatile::deserialize(&bytes).unwrap();
        assert!(w.started);
        assert_eq!(w.pcrs, v.pcrs);
        assert_eq!(w.da_timers, v.da_timers);
        assert_eq!(w.clear, v.clear);
        assert_eq!(w.serialize(), bytes);
    }

    #[test]
    fn states_fit_their_buffer() {
        let tpm = crate::Tpm::manufacture().unwrap();
        let mut p = Permanent::manufacture().unwrap();
        let mut pcrs = Pcrs::new();
        pcrs.startup(&p.allocation, Startup::Reset, None);
        let mut v = Volatile::power_on(&p);
        for slot in v.sessions.iter_mut() {
            *slot = SessionSlot::Saved(u64::MAX);
        }
        p.shutdown = Shutdown::State(Box::new(Saved {
            pcrs: pcrs.save(),
            clear: ClearState {
                platform_auth: Zeroizing::new(vec![1; 64]),
                ..Default::default()
            },
            reset: v.reset_data(),
        }));
        // Every persistent object an RSA-3072 key, every slot one too.
        let key = crate::key::tests::rsa_storage_key(3072);
        for handle in (0x8100_0000..).take(MAX_PERSISTENT) {
            p.persistent.push((handle, key.clone()));
        }
        // And NV indices filling their memory, each with the longest authValue and policy.
        for index in (0x0100_0000..).take(29) {
            p.nv.push(nv::NvIndex {
                public: nv::NvPublic {
                    index,
                    name_alg: Hash::Sha512,
                    attributes: nv::attr::OWNERREAD | nv::attr::OWNERWRITE,
                    auth_policy: vec![1; 64],
                    data_size: 2048,
                },
                auth: Zeroizing::new(vec![2; 64]),
                data: Zeroizing::new(vec![3; 2048]),
            });
        }
        let bytes = p.serialize();
        assert!(
            bytes.len() < PERMANENT_CAPACITY / 2,
            "{} bytes",
            bytes.len()
        );
        assert_eq!(Permanent::deserialize(&bytes).unwrap().serialize(), bytes);
        let mut v = Volatile::power_on(&tpm.permanent);
        for slot in &mut v.objects {
            *slot = Some(Object::Key(Box::new(key.clone())));
        }
        for slot in &mut v.sessions {
            *slot = SessionSlot::Loaded(Box::new(crate::session::Session {
                kind: crate::session::Kind::Hmac,
                hash: Hash::Sha512,
                nonce_tpm: vec![0; 64],
                key: Zeroizing::new(vec![0; 64]),
                symmetric: crate::session::Symmetric::Aes(256),
                bound: Some(Zeroizing::new(vec![0; 66])),
                da_bound: true,
                lockout_bound: true,
                audit: Some(vec![0; 64]),
                policy_digest: vec![0; 64],
            }));
        }
        assert!(v.serialize().len() < VOLATILE_CAPACITY / 2);
    }

    #[test]
    fn foreign_old_or_damaged_state_is_refused() {
        let bytes = Permanent::manufacture().unwrap().serialize();
        let mut newer = bytes.clone();
        newer[9] = 2;
        assert!(Permanent::deserialize(&newer).is_err());
        assert!(Permanent::deserialize(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Permanent::deserialize(&longer).is_err());
        assert!(Permanent::deserialize(b"libtpms permall").is_err());
        assert!(
            Volatile::deserialize(&bytes).is_err(),
            "not a volatile state"
        );
    }
}
