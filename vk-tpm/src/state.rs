//! The TPM's state, and its serialized forms.
//!
//! - [`Permanent`]: what a TPM keeps across power cycles (its NV memory): seeds, PCR bank
//!   allocation, dictionary-attack counters, and what the last TPM2_Shutdown saved. The VMM
//!   writes it to the machine's state file each time it changes.
//! - [`Volatile`]: what is lost at power-off (PCR values, whether TPM2_Startup ran). Only a
//!   snapshot keeps it.
//!
//! Each serializes as a magic, a format version and the fields in order, in the TPM's own wire
//! format. A reader refuses a version it does not know, rather than guess.

use zeroize::Zeroizing;

use crate::alg::Hash;
use crate::marshal::{Reader, Writer};
use crate::pcr::{self, Bank, Banks, Pcrs, Saved, Selection};
use crate::rc::Rc;

const PERMANENT_MAGIC: &[u8; 8] = b"VKTPM-P\0";
const VOLATILE_MAGIC: &[u8; 8] = b"VKTPM-V\0";
const VERSION: u16 = 1;
const SEED_SIZE: usize = 64;
/// More than the serialized permanent state holds (under 3 KiB with saved PCRs), so writing it
/// never reallocates and leaves a stray copy of the seeds; [`crate::Tpm::permanent_state`]
/// wipes it whole when dropped.
const PERMANENT_CAPACITY: usize = 16 * 1024;

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

/// A hierarchy's seed: the root every primary key of it is derived from. Wiped when dropped.
pub type Seed = Zeroizing<[u8; SEED_SIZE]>;

/// How the TPM was last shut down, which decides what the next TPM2_Startup may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shutdown {
    /// No orderly shutdown since the last Startup: the next one is a TPM Reset.
    None,
    /// TPM2_Shutdown(CLEAR) (or a new TPM).
    Clear,
    /// TPM2_Shutdown(STATE), with what it saved.
    State(Saved),
}

/// The dictionary-attack parameters and counter (TPM2_DictionaryAttackParameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictionaryAttack {
    pub max_tries: u32,
    pub recovery_time: u32,
    pub lockout_recovery: u32,
    pub failed_tries: u32,
}

impl Default for DictionaryAttack {
    /// The reference implementation's (and libtpms') defaults.
    fn default() -> DictionaryAttack {
        DictionaryAttack {
            max_tries: 3,
            recovery_time: 1000,
            lockout_recovery: 1000,
            failed_tries: 0,
        }
    }
}

pub struct Permanent {
    /// Endorsement, storage (owner) and platform primary seeds.
    pub eps: Seed,
    pub sps: Seed,
    pub pps: Seed,
    /// Which PCRs of which bank are allocated (TPM2_PCR_Allocate), one selection per bank.
    pub allocation: Vec<Selection>,
    pub dictionary_attack: DictionaryAttack,
    pub shutdown: Shutdown,
}

impl Permanent {
    /// A newly manufactured TPM: fresh seeds, every bank allocated.
    pub fn manufacture() -> Result<Permanent, StateError> {
        let seed = || -> Result<Seed, StateError> {
            let mut seed = Seed::new([0; SEED_SIZE]);
            getrandom::fill(seed.as_mut()).map_err(|_| StateError("no entropy for the seeds"))?;
            Ok(seed)
        };
        Ok(Permanent {
            eps: seed()?,
            sps: seed()?,
            pps: seed()?,
            allocation: Hash::ALL
                .into_iter()
                .map(|h| Selection::all(h, true))
                .collect(),
            dictionary_attack: DictionaryAttack::default(),
            shutdown: Shutdown::Clear,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(PERMANENT_CAPACITY);
        w.bytes(PERMANENT_MAGIC).u16(VERSION);
        for seed in [&self.eps, &self.sps, &self.pps] {
            w.tpm2b(seed.as_slice());
        }
        pcr::write_selections(&mut w, &self.allocation);
        let da = &self.dictionary_attack;
        w.u32(da.max_tries)
            .u32(da.recovery_time)
            .u32(da.lockout_recovery)
            .u32(da.failed_tries);
        match &self.shutdown {
            Shutdown::None => {
                w.u8(0);
            }
            Shutdown::Clear => {
                w.u8(1);
            }
            Shutdown::State(saved) => {
                w.u8(2).u32(saved.counter);
                write_banks(&mut w, &saved.banks);
            }
        }
        w.into_bytes()
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Permanent, StateError> {
        let mut r = Reader::new(bytes);
        expect_header(&mut r, PERMANENT_MAGIC)?;
        let mut seed = || -> Result<Seed, StateError> {
            let bytes = r.tpm2b(SEED_SIZE)?;
            if bytes.len() != SEED_SIZE {
                return Err(StateError("bad seed"));
            }
            let mut seed = Seed::new([0; SEED_SIZE]);
            seed.copy_from_slice(bytes);
            Ok(seed)
        };
        let (eps, sps, pps) = (seed()?, seed()?, seed()?);
        let allocation = pcr::read_selections(&mut r)?;
        let duplicate = (allocation.iter().enumerate())
            .any(|(i, s)| allocation.iter().take(i).any(|t| t.hash == s.hash));
        if duplicate {
            return Err(StateError("duplicate bank"));
        }
        let dictionary_attack = DictionaryAttack {
            max_tries: r.u32()?,
            recovery_time: r.u32()?,
            lockout_recovery: r.u32()?,
            failed_tries: r.u32()?,
        };
        let shutdown = match r.u8()? {
            0 => Shutdown::None,
            1 => Shutdown::Clear,
            2 => Shutdown::State(Saved {
                counter: r.u32()?,
                banks: read_banks(&mut r, pcr::STATE_SAVED)?,
            }),
            _ => return Err(StateError("bad shutdown state")),
        };
        expect_end(&r)?;
        Ok(Permanent {
            eps,
            sps,
            pps,
            allocation,
            dictionary_attack,
            shutdown,
        })
    }
}

pub struct Volatile {
    /// TPM2_Startup ran since the TPM powered on.
    pub started: bool,
    /// The shutdown before that Startup was orderly (TPMA_STARTUP_CLEAR.orderly).
    pub orderly_startup: bool,
    pub pcrs: Pcrs,
}

impl Volatile {
    /// The TPM as it powers on (_TPM_Init): waiting for TPM2_Startup.
    pub fn power_on() -> Volatile {
        Volatile {
            started: false,
            orderly_startup: false,
            pcrs: Pcrs::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(VOLATILE_MAGIC).u16(VERSION);
        w.u8(self.started.into())
            .u8(self.orderly_startup.into())
            .u32(self.pcrs.counter);
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
        let counter = r.u32()?;
        let mut pcrs = Pcrs::new();
        pcrs.counter = counter;
        let banks = read_banks(&mut r, pcr::PCR_COUNT)?;
        if banks.len() != pcrs.banks.len() {
            return Err(StateError("missing bank"));
        }
        for (hash, values) in banks {
            if let Some(bank) = pcrs.banks.iter_mut().find(|b| b.hash == hash) {
                *bank = Bank { hash, values };
            }
        }
        expect_end(&r)?;
        Ok(Volatile {
            started,
            orderly_startup,
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

fn read_bool(r: &mut Reader) -> Result<bool, StateError> {
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

/// Banks as [`write_banks`] wrote them, each different and with `pcrs` values.
fn read_banks(r: &mut Reader, pcrs: usize) -> Result<Banks, StateError> {
    let count = r.count(Hash::ALL.len())?;
    let mut banks: Banks = Vec::with_capacity(count);
    for _ in 0..count {
        let hash = Hash::read(r)?;
        if banks.iter().any(|(h, _)| *h == hash) {
            return Err(StateError("duplicate bank"));
        }
        if r.count(pcr::PCR_COUNT)? != pcrs {
            return Err(StateError("bad PCR count"));
        }
        let mut values = Vec::with_capacity(pcrs);
        for _ in 0..pcrs {
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
    use crate::pcr::Startup;

    #[test]
    fn permanent_state_round_trips() {
        let mut p = Permanent::manufacture().unwrap();
        assert_ne!(*p.eps, *p.sps, "seeds are random");
        let mut pcrs = Pcrs::new();
        pcrs.startup(Startup::Reset, None);
        p.shutdown = Shutdown::State(pcrs.save());
        p.dictionary_attack.failed_tries = 2;
        let bytes = p.serialize();
        let q = Permanent::deserialize(&bytes).unwrap();
        assert_eq!(q.serialize(), bytes);
        assert_eq!(*q.eps, *p.eps);
        assert_eq!(q.shutdown, p.shutdown);
    }

    #[test]
    fn volatile_state_round_trips() {
        let mut v = Volatile::power_on();
        v.started = true;
        v.pcrs.startup(Startup::Reset, None);
        let bytes = v.serialize();
        let w = Volatile::deserialize(&bytes).unwrap();
        assert!(w.started);
        assert_eq!(w.pcrs, v.pcrs);
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

    #[test]
    fn state_of_the_wrong_shape_is_refused() {
        let mut p = Permanent::manufacture().unwrap();
        p.allocation[1] = Selection::all(Hash::Sha1, false);
        let refused = Permanent::deserialize(&p.serialize()).err();
        assert_eq!(refused, Some(StateError("duplicate bank")));

        let mut p = Permanent::manufacture().unwrap();
        let mut pcrs = Pcrs::new();
        pcrs.startup(Startup::Reset, None);
        let mut saved = pcrs.save();
        saved.banks[0].1.push(vec![0; 20]);
        p.shutdown = Shutdown::State(saved);
        let refused = Permanent::deserialize(&p.serialize()).err();
        assert_eq!(refused, Some(StateError("bad PCR count")));

        let mut v = Volatile::power_on();
        v.pcrs.banks.pop();
        let refused = Volatile::deserialize(&v.serialize()).err();
        assert_eq!(refused, Some(StateError("missing bank")));
    }
}
