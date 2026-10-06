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
use crate::marshal::{Reader, Writer};
use crate::pcr::{self, Bank, Banks, Pcrs, Selection};
use crate::rc::Rc;

const PERMANENT_MAGIC: &[u8; 8] = b"VKTPM-P\0";
const VOLATILE_MAGIC: &[u8; 8] = b"VKTPM-V\0";
/// No vk-tpm state has been stored outside a test yet: the format stays at version 1, and
/// changes in place, until one is (docs/tpm-design.md).
const VERSION: u16 = 1;
pub const SEED_SIZE: usize = 64;

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
    State(Saved),
}

impl Shutdown {
    /// The shutdown was orderly: no failure is presumed lost, and Startup may restart or
    /// resume.
    pub fn is_orderly(&self) -> bool {
        matches!(self, Shutdown::Clear | Shutdown::State(_))
    }
}

/// What TPM2_Shutdown(STATE) saves for the TPM2_Startup after it: the state-saved PCRs, and the
/// enables and platform authorization a resume brings back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Saved {
    pub pcrs: pcr::Saved,
    pub clear: ClearState,
}

pub struct Permanent {
    /// Endorsement, storage (owner) and platform primary seeds.
    pub eps: Seed,
    pub sps: Seed,
    pub pps: Seed,
    pub hierarchies: Hierarchies,
    /// Which PCRs of which bank are allocated (TPM2_PCR_Allocate), one selection per bank.
    pub allocation: Vec<Selection>,
    pub dictionary_attack: DictionaryAttack,
    pub shutdown: Shutdown,
    /// TPM time (ms) at the last TPM2_Shutdown, from which the dictionary-attack timers go on
    /// counting after an orderly power cycle.
    pub shutdown_time: u64,
}

impl Permanent {
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
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
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
            }
        }
        w.u64(self.shutdown_time);
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
            3 => Shutdown::State(Saved {
                pcrs: pcr::Saved {
                    counter: r.u32()?,
                    banks: read_banks(&mut r)?,
                },
                clear: ClearState::read(&mut r)?,
            }),
            _ => return Err(StateError("bad shutdown state")),
        };
        let shutdown_time = r.u64()?;
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
    pub clear: ClearState,
    pub pcrs: Pcrs,
}

impl Volatile {
    /// The TPM as it powers on (_TPM_Init): waiting for TPM2_Startup.
    pub fn power_on() -> Volatile {
        Volatile {
            started: false,
            orderly_startup: false,
            time: 0,
            time_reset: true,
            da_timers: DaTimers::default(),
            da_used: false,
            ph_enable: true,
            clear: ClearState::default(),
            pcrs: Pcrs::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(VOLATILE_MAGIC).u16(VERSION);
        w.u8(self.started.into())
            .u8(self.orderly_startup.into())
            .u64(self.time)
            .u8(self.time_reset.into())
            .u64(self.da_timers.self_heal.cast_unsigned())
            .u64(self.da_timers.lockout.cast_unsigned())
            .u8(self.da_used.into())
            .u8(self.ph_enable.into());
        self.clear.write(&mut w);
        w.u32(self.pcrs.counter);
        let banks: Vec<_> = (self.pcrs.banks.iter())
            .map(|b| (b.hash, b.values.clone()))
            .collect();
        write_banks(&mut w, &banks);
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
        expect_end(&r)?;
        Ok(Volatile {
            started,
            orderly_startup,
            time,
            time_reset,
            da_timers,
            da_used,
            ph_enable,
            clear,
            pcrs,
        })
    }
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
        pcrs.startup(Startup::Reset, None);
        let clear = ClearState {
            platform_auth: Zeroizing::new(b"platform".to_vec()),
            ..Default::default()
        };
        p.shutdown = Shutdown::State(Saved {
            pcrs: pcrs.save(),
            clear,
        });
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
        let mut v = Volatile::power_on();
        v.started = true;
        v.time = 99;
        v.da_timers.lockout = -5;
        v.clear.sh_enable = false;
        v.pcrs.startup(Startup::Reset, None);
        let bytes = v.serialize();
        let w = Volatile::deserialize(&bytes).unwrap();
        assert!(w.started);
        assert_eq!(w.pcrs, v.pcrs);
        assert_eq!(w.da_timers, v.da_timers);
        assert_eq!(w.clear, v.clear);
        assert_eq!(w.serialize(), bytes);
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
